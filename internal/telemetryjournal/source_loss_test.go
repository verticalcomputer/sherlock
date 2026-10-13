package telemetryjournal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func lossBody(m telemetry.SessionMessage, seq string, losses ...telemetry.SessionLoss) []byte {
	var e Envelope
	json.Unmarshal(sessionBody(m, seq), &e)
	e.Loss = losses
	body, _ := json.Marshal(e)
	return body
}
func testSourceLoss(old telemetry.SessionMessage, id, from, through string) telemetry.SessionLoss {
	return telemetry.SessionLoss{SourceID: "fixture-source", Range: telemetry.LossRange{ID: id, AffectedKey: sessionBatch(old, from).Key, ThroughSequence: through, Reason: "SPOOL_EXPIRED"}}
}
func setupLossSessions(t *testing.T) (*sessionFixture, *Queue, telemetry.SessionMessage, telemetry.SessionMessage) {
	t.Helper()
	f := newSessionFixture()
	q := mustOpen(t, filepath.Join(t.TempDir(), "queue"), f.options)
	old := f.message(t, "OPEN", 1, "boot-old", "key-a", "")
	current := f.message(t, "OPEN", 2, "boot-current", "key-b", "")
	mustRegister(t, q, old)
	mustRegister(t, q, current)
	return f, q, old, current
}
func TestGatewaySourceLossPreAckRejectsUnsupportedOrContradictoryFacts(t *testing.T) {
	for _, kind := range []string{"unknown-session", "foreign-node", "source", "future", "received", "self"} {
		t.Run(kind, func(t *testing.T) {
			_, q, old, current := setupLossSessions(t)
			loss := testSourceLoss(old, "loss-a", "3", "4")
			switch kind {
			case "unknown-session":
				loss.Range.AffectedKey.SessionEpoch = "3"
			case "foreign-node":
				loss.Range.AffectedKey.NodeID = "foreign"
			case "source":
				loss.SourceID = "unknown"
			case "future":
				at := testAt.Add(31 * time.Second)
				loss.Range.FromAt = &at
				loss.Range.ThroughAt = &at
			case "received":
				loss.Range.Reason = "SOURCE_LOSS"
				mustPut(t, q, sessionBody(old, "3"))
			case "self":
				loss.Range.AffectedKey = sessionBatch(current, "1").Key
				loss.Range.ThroughSequence = "1"
			}
			_, e := q.Put(ctx, lossBody(current, "1", loss))
			if e == nil {
				t.Fatal("unsupported/contradictory loss acknowledged")
			}
			var count int
			if q.db.QueryRow(`SELECT count(*)FROM source_loss`).Scan(&count) != nil || count != 0 {
				t.Fatal("invalid loss persisted")
			}
		})
	}
}
func TestSourceLossReceiptAtomicRestartAndLateFillHistory(t *testing.T) {
	f, q, old, current := setupLossSessions(t)
	path := q.root
	loss := testSourceLoss(old, "loss-a", "1", "4")
	body := lossBody(current, "1", loss)
	fault := errors.New("synthetic crash")
	q.opts.fault = func(stage string) error {
		if stage == "losses_inserted" {
			return fault
		}
		return nil
	}
	_, e := q.Put(ctx, body)
	if e != fault {
		t.Fatal("atomic fault not reached", e)
	}
	var count int
	q.db.QueryRow(`SELECT count(*)FROM source_loss`).Scan(&count)
	if count != 0 {
		t.Fatal("loss facts escaped rolled back receipt commit")
	}
	q.Close()
	q = mustOpen(t, path, f.options)
	r := mustPut(t, q, body)
	if r.Durability != "GATEWAY" {
		t.Fatal("wrong ownership")
	}
	var stored []byte
	if e = q.db.QueryRow(`SELECT body FROM source_loss WHERE id='loss-a'`).Scan(&stored); e != nil {
		t.Fatal(e)
	}
	var actual telemetry.SessionLoss
	if json.Unmarshal(stored, &actual) != nil || actual.Range.FromAt != nil || actual.Range.ThroughAt != nil || actual.Range.CountKnown || actual.Range.Count != "" || actual.Range.AffectedKey != loss.Range.AffectedKey {
		t.Fatal("unknown or prior-session loss facts changed")
	}
	mustPut(t, q, sessionBody(old, "2"))
	overlap := testSourceLoss(old, "loss-b", "3", "4")
	mustPut(t, q, lossBody(current, "2", overlap))
	q.db.QueryRow(`SELECT count(*)FROM source_loss`).Scan(&count)
	if count != 2 {
		t.Fatal("loss history erased by late fill/overlap")
	}
	if got := mustPut(t, q, body); !sameReceipt(got, r) {
		t.Fatal("matching loss replay receipt changed")
	}
	changed := loss
	changed.Range.ThroughSequence = "5"
	_, e = q.Put(ctx, lossBody(current, "3", changed))
	assertError(t, e, ErrConflict)
}

func TestLostGatewayResponseThenNodeExpiryDoesNotStrandCarrier(t *testing.T) {
	for _, remoteState := range []string{"OWNED", "TRANSFERRED"} {
		t.Run(remoteState, func(t *testing.T) {
			f, gw, old, current := setupLossSessions(t)
			o := f.options
			o.Role = Node
			o.Limits = NodeLimits()
			o.Limits.MinimumFree = 0
			node := mustOpen(t, filepath.Join(t.TempDir(), "node"), o)
			mustRegister(t, node, old)
			mustRegister(t, node, current)
			body := sessionBody(old, "3")
			mustPut(t, node, body)
			accepted := mustPut(t, gw, body) // response deliberately never acknowledged locally
			if remoteState == "TRANSFERRED" {
				ack := accepted
				ack.ID = "cloud-receipt"
				ack.Durability = "CLOUD"
				if e := gw.Acknowledge(ctx, ack, accepted.ID); e != nil {
					t.Fatal(e)
				}
			}
			expired := testAt.Add(24 * time.Hour)
			if e := node.Expire(ctx, expired); e != nil {
				t.Fatal(e)
			}
			local, e := node.Lookup(ctx, sessionBatch(old, "3").Key)
			if e != nil || local.State != "LOST" || local.Loss == nil || local.Loss.Reason != "NODE_EXPIRED" {
				t.Fatal("local expiry not durable", local, e)
			}
			loss := testSourceLoss(old, "expired-after-lost-response", "3", "3")
			carrier := lossBody(current, "1", loss)
			receipt := mustPut(t, gw, carrier)
			if r := mustPut(t, gw, body); !sameReceipt(r, accepted) {
				t.Fatal("local-discard fact replaced received receipt")
			}
			path := gw.root
			gw.Close()
			gw = mustOpen(t, path, f.options)
			if r := mustPut(t, gw, carrier); !sameReceipt(r, receipt) {
				t.Fatal("carrier receipt changed after restart")
			}
			if r := mustPut(t, gw, body); !sameReceipt(r, accepted) {
				t.Fatal("received evidence lost after restart")
			}
			// A source absence assertion still cannot overwrite received evidence.
			loss.Range.ID = "source-loss-conflict"
			loss.Range.Reason = "SOURCE_LOSS"
			_, e = gw.Put(ctx, lossBody(current, "2", loss))
			assertError(t, e, ErrConflict)
		})
	}
}
func TestCorruptSourceLossFactsFailClosedBeforePayloadRetirement(t *testing.T) {
	for _, kind := range []string{"digest", "body", "link"} {
		t.Run(kind, func(t *testing.T) {
			f, q, old, current := setupLossSessions(t)
			receipt := mustPut(t, q, lossBody(current, "1", testSourceLoss(old, "loss-a", "3", "4")))
			id, _ := keyID(receipt.Key)
			path := q.path(id)
			var e error
			switch kind {
			case "digest":
				_, e = q.db.Exec(`UPDATE source_loss SET digest=zeroblob(32)`)
			case "body":
				_, e = q.db.Exec(`UPDATE source_loss SET body=CAST('{}' AS BLOB)`)
			case "link":
				_, e = q.db.Exec(`DELETE FROM batch_loss`)
			}
			if e != nil {
				t.Fatal(e)
			}
			root := q.root
			q.Close()
			_, e = Open(root, f.options)
			assertError(t, e, ErrCorrupt)
			if _, e = os.Stat(path); e != nil {
				t.Fatal("corrupt loss recovery removed owned payload", e)
			}
		})
	}
}
func TestFinalizedLossHistorySurvivesLaterReceivedFill(t *testing.T) {
	f, q, old, _ := setupLossSessions(t)
	final := old
	final.Kind = "FINALIZE"
	final.LastAllocatedSequence = "4"
	final.Loss = []telemetry.SessionLoss{testSourceLoss(old, "final-gap", "1", "4")}
	if e := telemetry.SignSessionMessage(&final, f.keys[old.SigningKeyID]); e != nil {
		t.Fatal(e)
	}
	r := mustRegister(t, q, final)
	mustPut(t, q, sessionBody(old, "2"))
	path := q.root
	q.Close()
	q = mustOpen(t, path, f.options)
	if got := mustRegister(t, q, final); got.ID != r.ID {
		t.Fatal("finalization changed after historical fill")
	}
}

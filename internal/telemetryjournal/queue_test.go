package telemetryjournal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

type verifierFunc func(context.Context, []byte) (Envelope, error)

func (f verifierFunc) Verify(c context.Context, b []byte) (Envelope, error) { return f(c, b) }

var ctx = context.Background()
var testAt = time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)

func testKey(seq int) telemetry.BatchKey {
	return telemetry.BatchKey{ClusterID: "fixture-cluster", NodeID: "node-a", EnrollmentID: "enrollment-a", SessionEpoch: "1", SessionID: "session-a", Sequence: strconv.Itoa(seq)}
}
func testOptions(role Role) Options {
	limits := NodeLimits()
	if role == Gateway {
		limits = GatewayLimits()
	}
	limits.MinimumFree = 0
	return Options{Role: role, SourceIDs: []string{"fixture-source"}, Scope: Scope{"fixture-cluster", "node-a", "enrollment-a"}, Limits: limits, Now: func() time.Time { return testAt }, Verifier: verifierFunc(func(_ context.Context, body []byte) (Envelope, error) {
		var e Envelope
		if json.Unmarshal(body, &e) != nil {
			return e, ErrInvalid
		}
		return e, nil
	})}
}
func testBody(seq int, lane Lane, pad string) []byte {
	hash := sha256.Sum256([]byte(pad))
	e := Envelope{Key: testKey(seq), Digest: hex.EncodeToString(hash[:]), CreatedAt: testAt, Lane: lane, Sources: []string{"fixture-source"}}
	body, _ := json.Marshal(e)
	return body
}
func mustOpen(t *testing.T, path string, o Options) *Queue {
	t.Helper()
	q, e := Open(path, o)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = q.Close() })
	return q
}
func mustPut(t *testing.T, q *Queue, b []byte) telemetry.Receipt {
	t.Helper()
	r, e := q.Put(ctx, b)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func assertError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestOwnershipTransferRestartAndImmutableReplay(t *testing.T) {
	nodePath := filepath.Join(t.TempDir(), "node")
	gatewayPath := filepath.Join(t.TempDir(), "gateway")
	node := mustOpen(t, nodePath, testOptions(Node))
	gateway := mustOpen(t, gatewayPath, testOptions(Gateway))
	body := testBody(1, Data, "one")
	local := mustPut(t, node, body)
	gr := mustPut(t, gateway, body)
	if local.Durability != "NODE" || gr.Durability != "GATEWAY" {
		t.Fatal("wrong ownership durability")
	}
	if e := node.Acknowledge(ctx, gr, ""); e != nil {
		t.Fatal(e)
	}
	if _, e := node.Read(ctx, testKey(1)); !errors.Is(e, ErrRole) {
		t.Fatal("transferred node bytes accessible", e)
	}
	if b, e := gateway.Read(ctx, testKey(1)); e != nil || !bytes.Equal(b, body) {
		t.Fatal("gateway lost bytes before cloud acknowledgement", e)
	}
	node.Close()
	gateway.Close()
	node = mustOpen(t, nodePath, testOptions(Node))
	gateway = mustOpen(t, gatewayPath, testOptions(Gateway))
	if got := mustPut(t, node, body); !reflect.DeepEqual(got, local) {
		t.Fatal("local receipt changed")
	}
	if got := mustPut(t, gateway, body); !reflect.DeepEqual(got, gr) {
		t.Fatal("gateway receipt changed")
	}
	cloud := gr
	cloud.ID = "cloud-a"
	cloud.Durability = "CLOUD"
	cloud.StoredAt = testAt.Add(time.Minute)
	assertError(t, node.Acknowledge(ctx, cloud, ""), ErrRole)
	assertError(t, gateway.Acknowledge(ctx, cloud, "wrong-receipt"), ErrConflict)
	if e := gateway.Acknowledge(ctx, cloud, gr.ID); e != nil {
		t.Fatal(e)
	}
	if e := gateway.Acknowledge(ctx, cloud, gr.ID); e != nil {
		t.Fatal("same ack replay", e)
	}
	other := cloud
	other.ID = "cloud-b"
	assertError(t, gateway.Acknowledge(ctx, other, gr.ID), ErrConflict)
	if got := mustPut(t, gateway, body); !reflect.DeepEqual(got, gr) {
		t.Fatal("transferred immutable replay changed")
	}
}

func TestReplayConflictAndAuthorityBeforeDedupe(t *testing.T) {
	o := testOptions(Gateway)
	q := mustOpen(t, filepath.Join(t.TempDir(), "queue"), o)
	body := testBody(1, Data, "one")
	want := mustPut(t, q, body)
	_, e := q.Put(ctx, testBody(1, Data, "different"))
	assertError(t, e, ErrConflict)
	got, e := q.Read(ctx, want.Key)
	if e != nil || !bytes.Equal(got, body) {
		t.Fatal("conflict overwrote owned payload")
	}
	q.opts.Verifier = verifierFunc(func(context.Context, []byte) (Envelope, error) { return Envelope{}, ErrInvalid })
	_, e = q.Put(ctx, body)
	assertError(t, e, ErrInvalid)
}

func TestCrashBoundariesRecoverBeforeAcknowledgement(t *testing.T) {
	for _, role := range []Role{Node, Gateway} {
		for _, stage := range []string{"intent_committed", "payload_synced", "payload_published", "receipt_committed"} {
			t.Run(string(role)+"/"+stage, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "queue")
				o := testOptions(role)
				fault := errors.New("synthetic crash")
				o.fault = func(s string) error {
					if s == stage {
						return fault
					}
					return nil
				}
				q := mustOpen(t, path, o)
				body := testBody(1, Data, "one")
				if _, e := q.Put(ctx, body); e != fault {
					t.Fatal("fault stage not reached", e)
				}
				q.Close()
				o.fault = nil
				q = mustOpen(t, path, o)
				if stage == "intent_committed" && role == Node {
					loss, e := q.Losses(ctx)
					if e != nil || len(loss) != 1 || loss[0].AffectedKey != testKey(1) || loss[0].Count != nil || loss[0].FromAt != nil || loss[0].ThroughAt != nil {
						t.Fatal("interrupted intent lost silently or invented observations", loss, e)
					}
					_, e = q.Put(ctx, body)
					assertError(t, e, ErrLost)
					return
				}
				r := mustPut(t, q, body)
				if r.Key != testKey(1) {
					t.Fatal("recovery identity changed")
				}
				got, e := q.Read(ctx, r.Key)
				if e != nil || !bytes.Equal(got, body) {
					t.Fatal("recovered payload differs", e)
				}
			})
		}
	}
}

func TestCommittedAckOrLossSurvivesCrashBeforeUnlink(t *testing.T) {
	for _, stage := range []string{"ack_committed", "loss_committed"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "queue")
			o := testOptions(Node)
			q := mustOpen(t, path, o)
			body := testBody(1, Data, "one")
			r := mustPut(t, q, body)
			fault := errors.New("synthetic crash")
			q.opts.fault = func(s string) error {
				if s == stage {
					return fault
				}
				return nil
			}
			var e error
			if stage == "ack_committed" {
				r.Durability = "GATEWAY"
				r.ID = "gateway-a"
				e = q.Acknowledge(ctx, r, "")
			} else {
				e = q.RecordLoss(ctx, r.Key, "NODE_CAPACITY")
			}
			if e != fault {
				t.Fatal("fault not reached", e)
			}
			id, _ := keyID(r.Key)
			if _, e = os.Stat(q.path(id)); e != nil {
				t.Fatal("fault should preserve file until recovery")
			}
			q.Close()
			q = mustOpen(t, path, o)
			if _, e = os.Stat(q.path(id)); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("completed ownership file not retired")
			}
			s, e := q.Stats(ctx)
			if e != nil || s.Corrupt || s.Owned != 0 {
				t.Fatal("durable transition lost", s, e)
			}
		})
	}
}

func TestReservedControlAndExplicitLossAtDataCapacity(t *testing.T) {
	o := testOptions(Node)
	body := testBody(1, Data, "one")
	o.Limits.Payload = 4096
	q := mustOpen(t, filepath.Join(t.TempDir(), "queue"), o)
	mustPut(t, q, body)
	_, e := q.Put(ctx, testBody(2, Data, "two"))
	assertError(t, e, ErrCapacity)
	mustPut(t, q, testBody(3, Contact, "contact"))
	if e = q.RecordLoss(ctx, testKey(1), "NODE_CAPACITY"); e != nil {
		t.Fatal(e)
	}
	loss, e := q.Losses(ctx)
	if e != nil || len(loss) != 1 || loss[0].Count != nil || loss[0].FromAt != nil || loss[0].ThroughAt != nil {
		t.Fatal("loss facts not preserved", e)
	}
	mustPut(t, q, testBody(2, Data, "two"))
	_, e = q.Put(ctx, body)
	assertError(t, e, ErrLost)
}

func TestExpiryBoundaryAndGatewayOwnsUntilCloudAck(t *testing.T) {
	for _, role := range []Role{Node, Gateway} {
		o := testOptions(role)
		q := mustOpen(t, filepath.Join(t.TempDir(), "queue"), o)
		body := testBody(1, Data, "one")
		mustPut(t, q, body)
		if role == Gateway {
			assertError(t, q.Expire(ctx, testAt.Add(48*time.Hour)), ErrRole)
			if _, e := q.Read(ctx, testKey(1)); e != nil {
				t.Fatal(e)
			}
			assertError(t, q.RecordLoss(ctx, testKey(1), "NODE_EXPIRED"), ErrRole)
			continue
		}
		if e := q.Expire(ctx, testAt.Add(24*time.Hour-time.Nanosecond)); e != nil {
			t.Fatal(e)
		}
		next, e := q.Next(ctx, 1)
		if e != nil || len(next) != 1 {
			t.Fatal("expired before boundary")
		}
		if e = q.Expire(ctx, testAt.Add(24*time.Hour)); e != nil {
			t.Fatal(e)
		}
		_, e = q.Read(ctx, testKey(1))
		assertError(t, e, ErrLost)
	}
}

func TestCorruptOwnedPayloadFailsClosedPreservingBytes(t *testing.T) {
	for _, mode := range []string{"modified", "missing", "symlink", "orphan"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "queue")
			o := testOptions(Gateway)
			q := mustOpen(t, path, o)
			r := mustPut(t, q, testBody(1, Data, "one"))
			id, _ := keyID(r.Key)
			payload := q.path(id)
			q.Close()
			switch mode {
			case "modified":
				os.WriteFile(payload, []byte("corrupt"), 0600)
			case "missing":
				os.Remove(payload)
			case "symlink":
				os.Remove(payload)
				os.Symlink(filepath.Join(path, "metadata.sqlite"), payload)
			case "orphan":
				os.WriteFile(filepath.Join(path, "payload", "unowned.payload"), []byte("preserve"), 0600)
			}
			_, e := Open(path, o)
			assertError(t, e, ErrCorrupt)
			if mode == "modified" {
				b, _ := os.ReadFile(payload)
				if string(b) != "corrupt" {
					t.Fatal("evidence altered")
				}
			}
		})
	}
}

func TestSingleOwnerAndBoundedPhysicalAccounting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue")
	o := testOptions(Node)
	q := mustOpen(t, path, o)
	_, e := Open(path, o)
	assertError(t, e, ErrInUse)
	for i := 1; i <= 20; i++ {
		mustPut(t, q, testBody(i, Data, strconv.Itoa(i)))
	}
	s, e := q.Stats(ctx)
	if e != nil || s.PhysicalBytes <= s.PayloadBytes || s.PhysicalBytes > o.Limits.Total {
		t.Fatal("unbounded/missing allocated storage accounting", s, e)
	}
	files, e := os.ReadDir(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		i, _ := f.Info()
		if i.Mode().Perm() != 0600 {
			t.Fatalf("nonprivate journal file %s mode%o", f.Name(), i.Mode().Perm())
		}
	}
	q.Close()
	if _, e = os.Stat(filepath.Join(path, "owner.lock")); e != nil {
		t.Fatal("lock inode removed")
	}
	q = mustOpen(t, path, o)
	q.Close()
	_, e = q.Put(ctx, testBody(21, Data, "next"))
	assertError(t, e, ErrClosed)
}

func TestProtocolSignatureVerifierFeedsDurableQueue(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	frame := signedFrame()
	b := telemetry.NodeBatch{ProtocolVersion: 1, Key: testKey(1), EnrollmentRevision: 1, InventoryRevisionID: "inventory-a", BootID: "boot-a", SigningKeyID: "key-a", AgentVersion: "fixture.v1", BuildSHA256: string(bytes.Repeat([]byte("a"), 64)), CreatedAt: testAt, Sources: []telemetry.SourceFrame{frame}}
	if e := telemetry.SignBatch(&b, key); e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(b)
	o := testOptions(Gateway)
	o.Verifier = verifierFunc(func(_ context.Context, body []byte) (Envelope, error) {
		b, e := telemetry.DecodeNodeBatch(body, "identity")
		if e != nil || telemetry.ValidateNodeBatch(b) != nil || telemetry.VerifyBatchSignature(b, pub) != nil {
			return Envelope{}, ErrInvalid
		}
		return Envelope{Key: b.Key, Digest: b.Digest, CreatedAt: b.CreatedAt, Lane: Data, Sources: []string{b.Sources[0].SourceID}}, nil
	})
	q := mustOpen(t, filepath.Join(t.TempDir(), "queue"), o)
	r := mustPut(t, q, body)
	if r.Digest != b.Digest {
		t.Fatal("canonical digest lost")
	}
	b.Key.NodeID = "foreign"
	bad, _ := json.Marshal(b)
	_, e := q.Put(ctx, bad)
	assertError(t, e, ErrInvalid)
}
func signedFrame() telemetry.SourceFrame {
	s, e := telemetry.NewFixtureFrame("fixture-source", "fixture-cluster", "node-a", "sample", testAt, 18446744073709551615)
	if e != nil {
		panic(e)
	}
	return s
}

func TestBoundedIdentifiersScopeAndMetadataRejectInvalidInput(t *testing.T) {
	o := testOptions(Node)
	q := mustOpen(t, filepath.Join(t.TempDir(), "queue"), o)
	for _, change := range []func(*Envelope){func(e *Envelope) { e.Key.NodeID = "foreign" }, func(e *Envelope) { e.Key.Sequence = "01" }, func(e *Envelope) { e.Key.SessionEpoch = "0" }, func(e *Envelope) { e.Sources = []string{"duplicate", "duplicate"} }, func(e *Envelope) { e.Sources = []string{string(bytes.Repeat([]byte("a"), 129))} }, func(e *Envelope) { e.Digest = string(bytes.Repeat([]byte("A"), 64)) }} {
		var envelope Envelope
		json.Unmarshal(testBody(1, Data, "one"), &envelope)
		change(&envelope)
		body, _ := json.Marshal(envelope)
		_, err := q.Put(ctx, body)
		assertError(t, err, ErrInvalid)
	}
	r := mustPut(t, q, testBody(1, Data, "one"))
	r.Durability = "GATEWAY"
	r.ID = string(bytes.Repeat([]byte("a"), 129))
	assertError(t, q.Acknowledge(ctx, r, ""), ErrRole)
}

func TestDurableReceiptCorruptionAndSchemaRoleMismatchFailClosed(t *testing.T) {
	for _, mode := range []string{"receipt", "scope", "role"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "queue")
			o := testOptions(Node)
			q := mustOpen(t, path, o)
			r := mustPut(t, q, testBody(1, Data, "one"))
			if mode == "receipt" {
				id, _ := keyID(r.Key)
				r.Digest = string(bytes.Repeat([]byte("0"), 64))
				if _, e := q.db.Exec(`UPDATE item_rows SET receipt_id=? WHERE id=?`, "invalid receipt id", id); e != nil {
					t.Fatal(e)
				}
			}
			q.Close()
			if mode == "scope" {
				o.Scope.NodeID = "node-b"
			}
			if mode == "role" {
				o.Role = Gateway
			}
			_, e := Open(path, o)
			assertError(t, e, ErrCorrupt)
		})
	}
}

func TestGatewayStagingRetryReusesReservationAtCapacity(t *testing.T) {
	o := testOptions(Gateway)
	body := testBody(1, Data, "one")
	o.Limits.Payload = 4096
	o.Limits.MaxEntries = 1
	o.fault = func(stage string) error {
		if stage == "intent_committed" {
			return ErrCapacity
		}
		return nil
	}
	path := filepath.Join(t.TempDir(), "queue")
	q := mustOpen(t, path, o)
	_, err := q.Put(ctx, body)
	assertError(t, err, ErrCapacity)
	q.Close()
	o.fault = nil
	q = mustOpen(t, path, o)
	mustPut(t, q, body)
	s, e := q.Stats(ctx)
	if e != nil || s.Owned != 1 || s.PayloadBytes != int64(len(body)) {
		t.Fatal("retry double charged reservation", s, e)
	}
}

func TestRecoveryDoesNotExtendNodeMaximumSpoolAge(t *testing.T) {
	o := testOptions(Node)
	o.fault = func(stage string) error {
		if stage == "payload_synced" {
			return ErrCapacity
		}
		return nil
	}
	path := filepath.Join(t.TempDir(), "queue")
	q := mustOpen(t, path, o)
	_, err := q.Put(ctx, testBody(1, Data, "one"))
	assertError(t, err, ErrCapacity)
	q.Close()
	o.fault = nil
	o.Now = func() time.Time { return testAt.Add(48 * time.Hour) }
	q = mustOpen(t, path, o)
	if e := q.Expire(ctx, o.Now()); e != nil {
		t.Fatal(e)
	}
	loss, e := q.Losses(ctx)
	if e != nil || len(loss) != 1 || loss[0].Reason != "NODE_EXPIRED" {
		t.Fatal("recovery extended node retention clock", loss, e)
	}
}

func TestMissingMetadataAfterCompleteTransferCannotReinitialize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue")
	o := testOptions(Node)
	q := mustOpen(t, path, o)
	r := mustPut(t, q, testBody(1, Data, "one"))
	r.Durability = "GATEWAY"
	r.ID = "gateway-a"
	if e := q.Acknowledge(ctx, r, ""); e != nil {
		t.Fatal(e)
	}
	q.Close()
	if e := os.Remove(filepath.Join(path, "metadata.sqlite")); e != nil {
		t.Fatal(e)
	}
	_, e := Open(path, o)
	assertError(t, e, ErrCorrupt)
	if _, e = os.Stat(filepath.Join(path, "metadata.sqlite")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("missing metadata recreated")
	}
}

func TestUnsafeAncestorRejectedBeforeDirectoryMutation(t *testing.T) {
	for _, mode := range []string{"symlink", "writable"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			real := filepath.Join(base, "real")
			if e := os.Mkdir(real, 0700); e != nil {
				t.Fatal(e)
			}
			ancestor := real
			if mode == "symlink" {
				ancestor = filepath.Join(base, "link")
				if e := os.Symlink(real, ancestor); e != nil {
					t.Fatal(e)
				}
			} else {
				if e := os.Chmod(real, 0777); e != nil {
					t.Fatal(e)
				}
			}
			_, e := Open(filepath.Join(ancestor, "new", "queue"), testOptions(Node))
			assertError(t, e, ErrCorrupt)
			if _, e = os.Stat(filepath.Join(real, "new")); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("unsafe traversal created child")
			}
		})
	}
}

func TestMalformedOwnershipFactPreservesPayloadBeforeRecoveryUnlink(t *testing.T) {
	for _, state := range []string{"TRANSFERRED", "LOST"} {
		for _, fact := range []string{"missing", "foreign", "invented"} {
			t.Run(state+"/"+fact, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "queue")
				o := testOptions(Node)
				q := mustOpen(t, path, o)
				r := mustPut(t, q, testBody(1, Data, "one"))
				id, _ := keyID(r.Key)
				q.opts.fault = func(stage string) error {
					if stage == "ack_committed" || stage == "loss_committed" {
						return ErrCapacity
					}
					return nil
				}
				if state == "TRANSFERRED" {
					r.Durability = "GATEWAY"
					r.ID = "gateway-a"
					assertError(t, q.Acknowledge(ctx, r, ""), ErrCapacity)
					var body any
					if fact == "foreign" {
						r.Key.NodeID = "foreign"
						body = r
					} else if fact == "invented" {
						r.Durability = "CLOUD"
						body = r
					}
					_ = body
					var changeErr error
					switch fact {
					case "missing":
						_, changeErr = q.db.Exec(`UPDATE item_rows SET ack_id=NULL WHERE id=?`, id)
					case "foreign":
						_, changeErr = q.db.Exec(`UPDATE item_rows SET source_mask=0 WHERE id=?`, id)
					case "invented":
						_, changeErr = q.db.Exec(`UPDATE item_rows SET ack_at=0 WHERE id=?`, id)
					}
					if changeErr != nil {
						t.Fatal(changeErr)
					}
				} else {
					assertError(t, q.RecordLoss(ctx, r.Key, "NODE_CAPACITY"), ErrCapacity)
					l := LocalLoss{AffectedKey: r.Key, Sources: []string{"fixture-source"}, Reason: "NODE_CAPACITY"}
					var body any
					if fact == "foreign" {
						l.AffectedKey.SessionID = "foreign"
						body = l
					} else if fact == "invented" {
						n := uint64(100)
						l.Count = &n
						body = l
					}
					b, _ := json.Marshal(body)
					if _, e := q.db.Exec(`UPDATE items SET loss=? WHERE id=?`, b, id); e != nil {
						t.Fatal(e)
					}
				}
				payload := q.path(id)
				q.Close()
				_, e := Open(path, o)
				assertError(t, e, ErrCorrupt)
				if _, e = os.Stat(payload); e != nil {
					t.Fatal("malformed ownership caused destructive unlink", e)
				}
			})
		}
	}
}

func TestMissingIdentityAndDatabaseCannotReusePersistentLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue")
	o := testOptions(Node)
	q := mustOpen(t, path, o)
	q.Close()
	os.Remove(filepath.Join(path, "metadata.sqlite"))
	os.Remove(filepath.Join(path, "identity.json"))
	_, e := Open(path, o)
	assertError(t, e, ErrCorrupt)
	if _, e = os.Stat(filepath.Join(path, "identity.json")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("identity recreated")
	}
}

func TestOwnershipMutationCapacityRefusalPreservesOwnedPayload(t *testing.T) {
	o := testOptions(Node)
	q := mustOpen(t, filepath.Join(t.TempDir(), "queue"), o)
	r := mustPut(t, q, testBody(1, Data, "one"))
	s, e := q.Stats(ctx)
	if e != nil {
		t.Fatal(e)
	}
	q.opts.Limits.Total = s.PhysicalBytes
	r.Durability = "GATEWAY"
	r.ID = "gateway-a"
	assertError(t, q.Acknowledge(ctx, r, ""), ErrCapacity)
	assertError(t, q.RecordLoss(ctx, r.Key, "NODE_CAPACITY"), ErrCapacity)
	if _, e := q.Read(ctx, r.Key); e != nil {
		t.Fatal("failed mutation relinquished payload", e)
	}
}

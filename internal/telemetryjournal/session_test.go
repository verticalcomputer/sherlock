package telemetryjournal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

type sessionVerifierFunc func(context.Context, telemetry.SessionMessage) (SessionAuthorization, error)

func (f sessionVerifierFunc) VerifySession(c context.Context, m telemetry.SessionMessage) (SessionAuthorization, error) {
	return f(c, m)
}

type sessionFixture struct {
	options Options
	keys    map[string]ed25519.PrivateKey
	active  map[string]bool
	revoked bool
}

func newSessionFixture() *sessionFixture {
	f := &sessionFixture{options: testOptions(Gateway), keys: map[string]ed25519.PrivateKey{}, active: map[string]bool{"key-a": true, "key-b": true}}
	for _, id := range []string{"key-a", "key-b"} {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		f.keys[id] = key
	}
	f.options.RequireSessions = true
	f.options.SessionVerifier = sessionVerifierFunc(func(_ context.Context, m telemetry.SessionMessage) (SessionAuthorization, error) {
		key, ok := f.keys[m.SigningKeyID]
		if f.revoked || !ok || telemetry.VerifySessionSignature(m, key.Public().(ed25519.PublicKey)) != nil {
			return SessionAuthorization{}, ErrInvalid
		}
		return SessionAuthorization{SignerActive: f.active[m.SigningKeyID]}, nil
	})
	return f
}
func (f *sessionFixture) message(t *testing.T, kind string, epoch int, boot, key string, last string) telemetry.SessionMessage {
	t.Helper()
	m := telemetry.SessionMessage{ProtocolVersion: 1, Kind: kind, ClusterID: "fixture-cluster", NodeID: "node-a", EnrollmentID: "enrollment-a", EnrollmentRevision: 1, SessionEpoch: strconv.Itoa(epoch), SessionID: "session-" + strconv.Itoa(epoch), BootID: boot, SigningKeyID: key, CreatedAt: testAt, LastAllocatedSequence: last}
	if e := telemetry.SignSessionMessage(&m, f.keys[key]); e != nil {
		t.Fatal(e)
	}
	return m
}
func sessionBatch(m telemetry.SessionMessage, seq string) telemetry.NodeBatch {
	return telemetry.NodeBatch{Key: telemetry.BatchKey{ClusterID: m.ClusterID, NodeID: m.NodeID, EnrollmentID: m.EnrollmentID, SessionEpoch: m.SessionEpoch, SessionID: m.SessionID, Sequence: seq}, BootID: m.BootID, SigningKeyID: m.SigningKeyID, EnrollmentRevision: 1, Sources: []telemetry.SourceFrame{{SourceID: "fixture-source"}}}
}
func sessionBody(m telemetry.SessionMessage, seq string) []byte {
	var e Envelope
	json.Unmarshal(testBody(1, Data, "one"), &e)
	e.Key = sessionBatch(m, seq).Key
	e.BootID = m.BootID
	e.SigningKeyID = m.SigningKeyID
	e.EnrollmentRevision = 1
	b, _ := json.Marshal(e)
	return b
}
func mustRegister(t *testing.T, q *Queue, m telemetry.SessionMessage) telemetry.SessionReceipt {
	t.Helper()
	r, e := q.RegisterSession(ctx, m)
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func TestSessionOpenDurableImmutableReplayAndCurrentAuthority(t *testing.T) {
	f := newSessionFixture()
	path := filepath.Join(t.TempDir(), "queue")
	q := mustOpen(t, path, f.options)
	m := f.message(t, "OPEN", 1, "boot-a", "key-a", "")
	if e := q.CheckBatchSession(ctx, sessionBatch(m, "1")); !errors.Is(e, ErrInvalid) {
		t.Fatal("unknown session accepted", e)
	}
	r := mustRegister(t, q, m)
	mustPut(t, q, sessionBody(m, "1"))
	q.Close()
	q = mustOpen(t, path, f.options)
	f.active["key-a"] = false
	if got := mustRegister(t, q, m); !reflect.DeepEqual(got, r) {
		t.Fatal("known verify-only replay receipt changed")
	}
	f.revoked = true
	_, e := q.RegisterSession(ctx, m)
	assertError(t, e, ErrInvalid)
}

func TestSessionExactlyNextEpochAndSameBootKeyRotation(t *testing.T) {
	f := newSessionFixture()
	q := mustOpen(t, filepath.Join(t.TempDir(), "queue"), f.options)
	first := f.message(t, "OPEN", 1, "boot-a", "key-a", "")
	mustRegister(t, q, first)
	jump := f.message(t, "OPEN", 3, "boot-b", "key-a", "")
	_, e := q.RegisterSession(ctx, jump)
	assertError(t, e, ErrConflict)
	same := f.message(t, "OPEN", 2, "boot-a", "key-a", "")
	_, e = q.RegisterSession(ctx, same)
	assertError(t, e, ErrConflict)
	rotated := f.message(t, "OPEN", 2, "boot-a", "key-b", "")
	f.active["key-b"] = false
	_, e = q.RegisterSession(ctx, rotated)
	assertError(t, e, ErrInvalid)
	f.active["key-b"] = true
	mustRegister(t, q, rotated)
	if e = q.CheckBatchSession(ctx, sessionBatch(first, "1")); e != nil {
		t.Fatal("older signed history rejected", e)
	}
	batch := sessionBatch(first, "1")
	batch.SigningKeyID = "key-b"
	assertError(t, q.CheckBatchSession(ctx, batch), ErrConflict)
}

func TestSessionFinalizePreservesUnknownHolesAndReceipt(t *testing.T) {
	f := newSessionFixture()
	path := filepath.Join(t.TempDir(), "queue")
	q := mustOpen(t, path, f.options)
	m := f.message(t, "OPEN", 1, "boot-a", "key-a", "")
	mustRegister(t, q, m)
	mustPut(t, q, sessionBody(m, "8"))
	final := f.message(t, "FINALIZE", 1, "boot-a", "key-b", "10")
	r := mustRegister(t, q, final)
	if r.Covered || r.Retired || !r.Finalized {
		t.Fatal("finalization invented coverage/retirement")
	}
	if e := q.CheckBatchSession(ctx, sessionBatch(m, "2")); e != nil {
		t.Fatal("unaccepted hole rejected as replay", e)
	}
	assertError(t, q.CheckBatchSession(ctx, sessionBatch(m, "11")), ErrConflict)
	q.Close()
	q = mustOpen(t, path, f.options)
	if got := mustRegister(t, q, final); !reflect.DeepEqual(got, r) {
		t.Fatal("final receipt changed")
	}
}

func TestSessionFinalizationCannotContradictOwnedData(t *testing.T) {
	f := newSessionFixture()
	q := mustOpen(t, filepath.Join(t.TempDir(), "queue"), f.options)
	m := f.message(t, "OPEN", 1, "boot-a", "key-a", "")
	mustRegister(t, q, m)
	mustPut(t, q, sessionBody(m, "8"))
	bad := f.message(t, "FINALIZE", 1, "boot-a", "key-a", "7")
	_, e := q.RegisterSession(ctx, bad)
	assertError(t, e, ErrConflict)
	bad = f.message(t, "FINALIZE", 1, "boot-a", "key-a", "10")
	bad.Loss = []telemetry.SessionLoss{{SourceID: "fixture-source", Range: telemetry.LossRange{ID: "loss-a", AffectedKey: sessionBatch(m, "8").Key, ThroughSequence: "9", Reason: "SOURCE_LOSS"}}}
	telemetry.SignSessionMessage(&bad, f.keys["key-a"])
	_, e = q.RegisterSession(ctx, bad)
	assertError(t, e, ErrConflict)
	bad.Loss[0].Range.AffectedKey.Sequence = "3"
	bad.Loss[0].Range.ThroughSequence = "4"
	telemetry.SignSessionMessage(&bad, f.keys["key-a"])
	mustRegister(t, q, bad)
	if e = q.CheckBatchSession(ctx, sessionBatch(m, "3")); e != nil {
		t.Fatal("late original historical fill rejected", e)
	}
	if e = q.CheckBatchSession(ctx, sessionBatch(m, "5")); e != nil {
		t.Fatal("unaccepted unknown hole rejected", e)
	}
}

func TestSessionCapAndCommitBeforeAcknowledgement(t *testing.T) {
	f := newSessionFixture()
	path := filepath.Join(t.TempDir(), "queue")
	q := mustOpen(t, path, f.options)
	crash := errors.New("synthetic crash")
	q.opts.fault = func(stage string) error {
		if stage == "session_committed" {
			return crash
		}
		return nil
	}
	m := f.message(t, "OPEN", 1, "boot-1", "key-a", "")
	_, e := q.RegisterSession(ctx, m)
	if e != crash {
		t.Fatal("fault not reached", e)
	}
	q.Close()
	q = mustOpen(t, path, f.options)
	mustRegister(t, q, m)
	for i := 2; i <= 8; i++ {
		mustRegister(t, q, f.message(t, "OPEN", i, "boot-"+strconv.Itoa(i), "key-a", ""))
	}
	_, e = q.RegisterSession(ctx, f.message(t, "OPEN", 9, "boot-9", "key-a", ""))
	assertError(t, e, ErrCapacity)
}

func TestSessionMappingCorruptionOrMissingSchemaFailsClosed(t *testing.T) {
	for _, mode := range []string{"mapping", "receipt", "drop"} {
		t.Run(mode, func(t *testing.T) {
			f := newSessionFixture()
			path := filepath.Join(t.TempDir(), "queue")
			q := mustOpen(t, path, f.options)
			m := f.message(t, "OPEN", 1, "boot-a", "key-a", "")
			mustRegister(t, q, m)
			var e error
			switch mode {
			case "mapping":
				_, e = q.db.Exec(`UPDATE sessions SET boot='foreign'`)
			case "receipt":
				_, e = q.db.Exec(`UPDATE sessions SET open_receipt=?`, []byte(`{}`))
			case "drop":
				_, e = q.db.Exec(`DROP TABLE sessions`)
			}
			if e != nil {
				t.Fatal(e)
			}
			q.Close()
			_, e = Open(path, f.options)
			assertError(t, e, ErrCorrupt)
		})
	}
}

func TestSessionEnforcementCannotBeDisabledOnExistingJournal(t *testing.T) {
	f := newSessionFixture()
	path := filepath.Join(t.TempDir(), "queue")
	q := mustOpen(t, path, f.options)
	q.Close()
	f.options.RequireSessions = false
	_, e := Open(path, f.options)
	assertError(t, e, ErrCorrupt)
}

func TestVerifyOnlySignerCannotFinalizeAnotherKeySession(t *testing.T) {
	f := newSessionFixture()
	q := mustOpen(t, filepath.Join(t.TempDir(), "queue"), f.options)
	old := f.message(t, "OPEN", 1, "boot-a", "key-a", "")
	newer := f.message(t, "OPEN", 2, "boot-a", "key-b", "")
	mustRegister(t, q, old)
	mustRegister(t, q, newer)
	f.active["key-a"] = false
	_, err := q.RegisterSession(ctx, f.message(t, "FINALIZE", 2, "boot-a", "key-a", "0"))
	assertError(t, err, ErrInvalid)
	r := mustRegister(t, q, f.message(t, "FINALIZE", 1, "boot-a", "key-b", "0"))
	if !r.Finalized || r.Covered || r.Retired {
		t.Fatal("active-key finalize failed or invented coverage")
	}
}

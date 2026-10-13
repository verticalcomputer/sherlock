package nodetelemetry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetryjournal"
)

type fakeGateway struct {
	mu               sync.Mutex
	sessions         map[string]telemetry.SessionReceipt
	batches          map[telemetry.BatchKey]telemetry.Receipt
	wires            map[telemetry.BatchKey][]byte
	failAfterCommit  bool
	entered, release chan struct{}
}

func (g *fakeGateway) RegisterSession(_ context.Context, m telemetry.SessionMessage) (telemetry.SessionReceipt, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	id := m.SessionEpoch + "-" + m.Kind
	if r, ok := g.sessions[id]; ok {
		return r, nil
	}
	r := telemetry.SessionReceipt{ProtocolVersion: 1, ID: "gateway-session-" + id, ClusterID: m.ClusterID, NodeID: m.NodeID, EnrollmentID: m.EnrollmentID, EnrollmentRevision: 1, SessionEpoch: m.SessionEpoch, SessionID: m.SessionID, BootID: m.BootID, Kind: m.Kind, Digest: m.Digest, StoredAt: m.CreatedAt, Durability: "GATEWAY", Finalized: m.Kind == "FINALIZE"}
	g.sessions[id] = r
	return r, nil
}
func (g *fakeGateway) SubmitBatch(ctx context.Context, wire []byte) (telemetry.Receipt, error) {
	if g.entered != nil {
		select {
		case g.entered <- struct{}{}:
		default:
		}
		select {
		case <-g.release:
		case <-ctx.Done():
			return telemetry.Receipt{}, ctx.Err()
		}
	}
	b, e := telemetry.DecodeNodeBatch(wire, "")
	if e != nil {
		return telemetry.Receipt{}, e
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if r, ok := g.batches[b.Key]; ok {
		return r, nil
	}
	r := telemetry.Receipt{ProtocolVersion: 1, ID: "gateway-batch-" + b.Key.SessionEpoch + "-" + b.Key.Sequence, Key: b.Key, Digest: b.Digest, StoredAt: b.CreatedAt, Durability: "GATEWAY"}
	g.batches[b.Key] = r
	g.wires[b.Key] = append([]byte(nil), wire...)
	if g.failAfterCommit {
		g.failAfterCommit = false
		return telemetry.Receipt{}, telemetry.ErrUnavailable
	}
	return r, nil
}
func fixture(t *testing.T) (Config, *fakeGateway, *time.Time, *string) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	at := time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)
	boot := "boot-a"
	g := &fakeGateway{sessions: map[string]telemetry.SessionReceipt{}, batches: map[telemetry.BatchKey]telemetry.Receipt{}, wires: map[telemetry.BatchKey][]byte{}}
	limits := telemetryjournal.NodeLimits()
	limits.MinimumFree = 0
	return Config{Root: filepath.Join(t.TempDir(), "node"), Scope: LocalScope{ClusterID: "cluster-a", NodeID: "node-a", EnrollmentID: "enrollment-a", InventoryRevisionID: "inventory-a", SourceIDs: []string{"source-a"}, AgentVersion: "fixture-agent", BuildSHA256: strings.Repeat("a", 64), GatewaySPKISHA256: strings.Repeat("b", 64), Keys: []telemetry.NodeKey{{ID: "key-a", Epoch: "1", PublicKeyBase64: base64.RawStdEncoding.EncodeToString(pub), State: "ACTIVE"}}}, SigningKeyID: "key-a", SigningKey: key, Gateway: g, Now: func() time.Time { return at }, BootID: func() (string, error) { return boot, nil }, limits: &limits}, g, &at, &boot
}
func openRuntime(t *testing.T, c Config) *Runtime {
	t.Helper()
	r, e := Open(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}
func collect(t *testing.T, r *Runtime) {
	t.Helper()
	if e := r.CollectOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func drain(t *testing.T, r *Runtime) {
	t.Helper()
	for i := 0; i < 32; i++ {
		progress, e := r.DrainOnce(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		if !progress {
			return
		}
	}
	t.Fatal("drain bound")
}
func latestBatch(t *testing.T, r *Runtime) telemetry.NodeBatch {
	t.Helper()
	entries, e := r.q.Next(context.Background(), 128)
	if e != nil || len(entries) == 0 {
		t.Fatal(e)
	}
	wire, e := r.q.Read(context.Background(), entries[len(entries)-1].Key)
	if e != nil {
		t.Fatal(e)
	}
	b, e := telemetry.DecodeNodeBatch(wire, "")
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestInterruptedAllocationIsSignedUnknownLossAndNeverReused(t *testing.T) {
	c, g, at, _ := fixture(t)
	c.fault = func(point string) error {
		if point == "allocation_committed" {
			return errors.New("synthetic crash")
		}
		return nil
	}
	r := openRuntime(t, c)
	if e := r.CollectOnce(context.Background()); !errors.Is(e, ErrState) {
		t.Fatal(e)
	}
	lost := r.state.Pending.Key
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	c.fault = nil
	*at = at.Add(30 * time.Second)
	r = openRuntime(t, c)
	if r.state.Pending != nil || len(r.state.Gaps) != 1 || !verifyGap(r.state.Gaps[0], c.SigningKey.Public().(ed25519.PublicKey)) {
		t.Fatal("gap not durably signed")
	}
	collect(t, r)
	b := latestBatch(t, r)
	if b.Key.Sequence != "2" || len(b.Sources[0].Loss) != 1 {
		t.Fatal("sequence reused or loss absent")
	}
	l := b.Sources[0].Loss[0]
	if l.AffectedKey != lost || l.Reason != "SOURCE_LOSS" || l.CountKnown || l.Count != "" || l.FromAt != nil || l.ThroughAt != nil {
		t.Fatal("manufactured source evidence", l)
	}
	drain(t, r)
	if r.state.Gaps[0].Carrier == nil || r.state.Gaps[0].Carrier.Receipt.ID != g.batches[b.Key].ID {
		t.Fatal("missing exact gateway handoff proof")
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	*at = at.Add(30 * time.Second)
	r = openRuntime(t, c)
	collect(t, r)
	b = latestBatch(t, r)
	if b.Key.Sequence != "3" || len(b.Sources[0].Loss) != 0 {
		t.Fatal("handed-off gap redelivered or sequence reset")
	}
}
func TestSealedCrashAndLostGatewayResponseReplayOriginalBytes(t *testing.T) {
	c, g, at, _ := fixture(t)
	c.fault = func(point string) error {
		if point == "batch_sealed" {
			return errors.New("synthetic crash")
		}
		return nil
	}
	r := openRuntime(t, c)
	if e := r.CollectOnce(context.Background()); !errors.Is(e, ErrState) {
		t.Fatal(e)
	}
	original := latestBatch(t, r)
	wire, _ := json.Marshal(original)
	_ = r.Close()
	c.fault = nil
	*at = at.Add(time.Hour)
	r = openRuntime(t, c)
	if len(r.state.Gaps) != 0 || r.state.Pending != nil {
		t.Fatal("sealed batch misclassified as loss")
	}
	g.failAfterCommit = true
	if _, e := r.DrainOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e := r.DrainOnce(context.Background()); !errors.Is(e, telemetry.ErrUnavailable) {
		t.Fatal(e)
	}
	entry, e := r.q.Lookup(context.Background(), original.Key)
	if e != nil || entry.State != "OWNED" {
		t.Fatal("lost response transferred ownership")
	}
	_ = r.Close()
	r = openRuntime(t, c)
	drain(t, r)
	entry, e = r.q.Lookup(context.Background(), original.Key)
	if e != nil || entry.State != "TRANSFERRED" || string(g.wires[original.Key]) != string(wire) {
		t.Fatal("restart changed signed bytes or ownership")
	}
	if len(g.batches) != 1 {
		t.Fatal("duplicate receipt")
	}
}
func TestRebootAndSameBootKeyRotationResumeExactEpochs(t *testing.T) {
	c, _, at, boot := fixture(t)
	r := openRuntime(t, c)
	collect(t, r)
	old := r.state.Sessions[0].Open
	_ = r.Close()
	r = openRuntime(t, c)
	if len(r.state.Sessions) != 1 || r.state.Sessions[0].Open.Digest != old.Digest {
		t.Fatal("same boot restart changed session")
	}
	_ = r.Close()
	*boot = "boot-b"
	*at = at.Add(time.Minute)
	r = openRuntime(t, c)
	if len(r.state.Sessions) != 2 || r.state.Sessions[0].Final.LastAllocatedSequence != "1" {
		t.Fatal("reboot did not finalize original terminal")
	}
	collect(t, r)
	_ = r.Close()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	c.Scope.Keys[0].State = "VERIFY_ONLY"
	c.Scope.Keys = append(c.Scope.Keys, telemetry.NodeKey{ID: "key-b", Epoch: "2", PublicKeyBase64: base64.RawStdEncoding.EncodeToString(pub), State: "ACTIVE"})
	c.SigningKeyID = "key-b"
	c.SigningKey = key
	*at = at.Add(time.Minute)
	r = openRuntime(t, c)
	if len(r.state.Sessions) != 3 || r.state.Sessions[2].Open.BootID != *boot || r.state.Sessions[2].Open.SessionEpoch != "3" || r.state.Sessions[1].Final.SigningKeyID != "key-b" {
		t.Fatal("same-boot rotation changed identity")
	}
	_ = r.Close()
	r = openRuntime(t, c)
	if len(r.state.Sessions) != 3 {
		t.Fatal("rotation restart opened another session")
	}
}
func TestMissingCorruptAndForeignAllocatorFailClosed(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "symlink", "foreign"} {
		t.Run(kind, func(t *testing.T) {
			c, _, _, _ := fixture(t)
			r := openRuntime(t, c)
			collect(t, r)
			_ = r.Close()
			path := filepath.Join(c.Root, allocatorName)
			switch kind {
			case "missing":
				_ = os.Remove(path)
			case "corrupt":
				_ = os.WriteFile(path, []byte(`{"version":1}`), 0600)
			case "symlink":
				_ = os.Remove(path)
				_ = os.Symlink(filepath.Join(t.TempDir(), "missing"), path)
			case "foreign":
				c.Scope.InventoryRevisionID = "foreign-inventory"
			}
			if _, e := Open(context.Background(), c); !errors.Is(e, ErrState) {
				t.Fatal("unsafe allocator accepted", e)
			}
		})
	}
}
func TestSessionGapAndSequenceCapsAndClockRegression(t *testing.T) {
	c, _, at, boot := fixture(t)
	r := openRuntime(t, c)
	for i := 1; i < 8; i++ {
		_ = r.Close()
		*boot = "boot-" + strconv.Itoa(i)
		*at = at.Add(time.Minute)
		r = openRuntime(t, c)
	}
	_ = r.Close()
	*boot = "boot-exhausted"
	if _, e := Open(context.Background(), c); !errors.Is(e, ErrCapacity) {
		t.Fatal("session cap", e)
	}
	c, _, at, _ = fixture(t)
	r = openRuntime(t, c)
	s := clone(r.state)
	s.Sessions[0].LastAllocated = "18446744073709551615"
	if e := r.save(context.Background(), s); e != nil {
		t.Fatal(e)
	}
	if e := r.CollectOnce(context.Background()); !errors.Is(e, ErrCapacity) {
		t.Fatal("sequence overflow", e)
	}
	s = clone(r.state)
	s.Sessions[0].LastAllocated = "0"
	if e := r.save(context.Background(), s); e != nil {
		t.Fatal(e)
	}
	*at = at.Add(-time.Second)
	if e := r.CollectOnce(context.Background()); !errors.Is(e, ErrClock) {
		t.Fatal("clock regression", e)
	}
}
func TestRateWaitCancellationAndRunJoinsUpload(t *testing.T) {
	b := tokenBucket{last: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := b.wait(ctx, telemetry.MaxBatchBytes); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	c, g, _, _ := fixture(t)
	g.entered = make(chan struct{}, 1)
	g.release = make(chan struct{})
	r := openRuntime(t, c)
	ctx, cancel = context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	select {
	case <-g.entered:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("upload did not begin")
	}
	if e := r.Close(); !errors.Is(e, ErrRunning) {
		t.Fatal("closed active runtime", e)
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("upload worker not joined")
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestOfflineExpiryPreservesExactOriginalLossAndCursor(t *testing.T) {
	c, _, at, _ := fixture(t)
	r := openRuntime(t, c)
	collect(t, r)
	original := latestBatch(t, r)
	*at = at.Add(25 * time.Hour)
	collect(t, r)
	next := latestBatch(t, r)
	if next.Key.Sequence != "2" || len(next.Sources[0].Loss) != 1 {
		t.Fatal("expiry gap missing")
	}
	loss := next.Sources[0].Loss[0]
	if loss.AffectedKey != original.Key || loss.Reason != "SPOOL_EXPIRED" || loss.CountKnown || loss.FromAt != nil || loss.ThroughAt != nil {
		t.Fatal("expiry manufactured source observations")
	}
	entry, e := r.q.Lookup(context.Background(), original.Key)
	if e != nil || entry.State != "LOST" || entry.Loss == nil || entry.Loss.Reason != "NODE_EXPIRED" {
		t.Fatal("original local loss discarded", e)
	}
	if r.state.LossCursor == 0 || len(r.state.Gaps) != 1 {
		t.Fatal("loss cursor not durable")
	}
	cursor := r.state.LossCursor
	_ = r.Close()
	r = openRuntime(t, c)
	if len(r.state.Gaps) != 1 || r.state.LossCursor != cursor {
		t.Fatal("restart duplicated/forgot loss")
	}
	drain(t, r)
	if r.state.Gaps[0].Carrier == nil {
		t.Fatal("expiry loss has no gateway proof")
	}
}

func TestAllocatorPublishBoundariesNeverReuseDurableSequence(t *testing.T) {
	for _, point := range []string{"allocator_file_synced", "allocator_renamed"} {
		t.Run(point, func(t *testing.T) {
			c, _, at, _ := fixture(t)
			r := openRuntime(t, c)
			r.config.fault = func(actual string) error {
				if actual == point {
					return errors.New("synthetic allocator boundary crash")
				}
				return nil
			}
			if e := r.CollectOnce(context.Background()); !errors.Is(e, ErrState) {
				t.Fatal(e)
			}
			_ = r.Close()
			*at = at.Add(time.Minute)
			r = openRuntime(t, c)
			collect(t, r)
			b := latestBatch(t, r)
			if point == "allocator_renamed" {
				if b.Key.Sequence != "2" || len(b.Sources[0].Loss) != 1 {
					t.Fatal("durable allocation reused")
				}
			} else if b.Key.Sequence != "1" || len(b.Sources[0].Loss) != 0 {
				t.Fatal("uncommitted allocator invented sequence/loss")
			}
		})
	}
}

func TestGapFactCapacityStopsWithoutDroppingSignedEvidence(t *testing.T) {
	c, _, _, _ := fixture(t)
	r := openRuntime(t, c)
	s := clone(r.state)
	s.Sessions[0].LastAllocated = "257"
	for i := 1; i <= 256; i++ {
		k := telemetry.BatchKey{ClusterID: c.Scope.ClusterID, NodeID: c.Scope.NodeID, EnrollmentID: c.Scope.EnrollmentID, SessionEpoch: "1", SessionID: s.Sessions[0].Open.SessionID, Sequence: strconv.Itoa(i)}
		g := signedGap{Key: k, SourceIDs: c.Scope.SourceIDs, Reason: "LOCAL_COMMIT_INTERRUPTED", SigningKeyID: c.SigningKeyID}
		signGap(&g, c.SigningKey)
		s.Gaps = append(s.Gaps, g)
	}
	if e := r.save(context.Background(), s); e != nil {
		t.Fatal(e)
	}
	k := s.Gaps[0].Key
	k.Sequence = "257"
	if e := r.addGap(context.Background(), k, c.Scope.SourceIDs, "LOCAL_COMMIT_INTERRUPTED"); !errors.Is(e, ErrCapacity) {
		t.Fatal("gap capacity waived", e)
	}
	if len(r.state.Gaps) != 256 {
		t.Fatal("gap evidence dropped")
	}
	_ = r.Close()
	r = openRuntime(t, c)
	if len(r.state.Gaps) != 256 {
		t.Fatal("full evidence not retained after restart")
	}
}

func TestInFlightTransferDefersAllocationAndExpiryThenGrantsCollectionTurn(t *testing.T) {
	c, g, at, _ := fixture(t)
	r := openRuntime(t, c)
	collect(t, r)
	original := latestBatch(t, r)
	if _, e := r.DrainOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	g.entered = make(chan struct{}, 1)
	g.release = make(chan struct{})
	done := make(chan error, 1)
	go func() { _, e := r.DrainOnce(context.Background()); done <- e }()
	select {
	case <-g.entered:
	case <-time.After(time.Second):
		t.Fatal("transfer not started")
	}
	*at = at.Add(25 * time.Hour)
	if e := r.CollectOnce(context.Background()); !errors.Is(e, ErrBusy) {
		t.Fatal("in-flight allocation not deferred", e)
	}
	if r.state.Pending != nil || r.state.Sessions[0].LastAllocated != "1" {
		t.Fatal("deferred collection allocated sequence")
	}
	entry, e := r.q.Lookup(context.Background(), original.Key)
	if e != nil || entry.State != "OWNED" {
		t.Fatal("in-flight expiry lost payload", e)
	}
	close(g.release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if progress, e := r.DrainOnce(context.Background()); e != nil || progress {
		t.Fatal("drain stole pending collection turn", e)
	}
	collect(t, r)
	if len(r.state.Gaps) != 0 || r.state.Sessions[0].LastAllocated != "2" {
		t.Fatal("accepted transfer manufactured expiry gap")
	}
}

func TestLostResponseThenOfflineStartupExpiryIsLocalDiscard(t *testing.T) {
	c, g, at, _ := fixture(t)
	r := openRuntime(t, c)
	collect(t, r)
	original := latestBatch(t, r)
	if _, e := r.DrainOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	g.failAfterCommit = true
	if _, e := r.DrainOnce(context.Background()); !errors.Is(e, telemetry.ErrUnavailable) {
		t.Fatal(e)
	}
	receipt := g.batches[original.Key]
	_ = r.Close()
	*at = at.Add(25 * time.Hour)
	r = openRuntime(t, c)
	entry, e := r.q.Lookup(context.Background(), original.Key)
	if e != nil || entry.State != "LOST" {
		t.Fatal("startup did not expire before drain", e)
	}
	if progress, e := r.DrainOnce(context.Background()); e != nil || progress {
		t.Fatal("expired payload uploaded before carrier collection", e)
	}
	collect(t, r)
	carrier := latestBatch(t, r)
	if len(carrier.Sources[0].Loss) != 1 || carrier.Sources[0].Loss[0].Reason != "SPOOL_EXPIRED" {
		t.Fatal("local discard reason lost")
	}
	drain(t, r)
	if g.batches[original.Key] != receipt || r.state.Gaps[0].Carrier == nil {
		t.Fatal("lost response/expiry overwrote original receipt")
	}
}

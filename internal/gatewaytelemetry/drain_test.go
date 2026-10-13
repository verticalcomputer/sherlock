package gatewaytelemetry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetryjournal"
)

type testQueue struct {
	open     telemetry.SessionMessage
	messages []telemetry.SessionMessage
	batch    telemetry.NodeBatch
	wire     []byte
	receipt  telemetry.Receipt
	owned    bool
	ackErr   error
	ackCount int
	turns    []uint64
}

func (q *testQueue) SessionMessages(context.Context) ([]telemetry.SessionMessage, error) {
	return append([]telemetry.SessionMessage(nil), q.messages...), nil
}
func (q *testQueue) SessionOpen(context.Context, string) (telemetry.SessionMessage, error) {
	return q.open, nil
}
func (q *testQueue) NextForDrain(_ context.Context, turn uint64) (telemetryjournal.Entry, bool, error) {
	q.turns = append(q.turns, turn)
	return telemetryjournal.Entry{Key: q.batch.Key, Digest: q.batch.Digest, Receipt: q.receipt}, q.owned, nil
}
func (q *testQueue) NextForDrainExcludingSessions(ctx context.Context, turn uint64, excluded []string) (telemetryjournal.Entry, bool, error) {
	for _, epoch := range excluded {
		if q.batch.Key.SessionEpoch == epoch {
			return telemetryjournal.Entry{}, false, nil
		}
	}
	return q.NextForDrain(ctx, turn)
}
func (q *testQueue) Read(context.Context, telemetry.BatchKey) ([]byte, error) {
	return append([]byte(nil), q.wire...), nil
}
func (q *testQueue) Acknowledge(_ context.Context, r telemetry.Receipt, id string) error {
	q.ackCount++
	if q.ackErr != nil {
		return q.ackErr
	}
	if r.Key != q.batch.Key || r.Digest != q.batch.Digest || id != q.receipt.ID {
		return telemetry.ErrConflict
	}
	q.owned = false
	return nil
}
func newTestQueue(t *testing.T, id string) *testQueue {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	at := time.Now().UTC()
	m := telemetry.SessionMessage{ProtocolVersion: 1, Kind: "OPEN", ClusterID: "cluster", NodeID: "node-" + id, EnrollmentID: id, EnrollmentRevision: 1, SessionEpoch: "1", SessionID: "session-" + id, BootID: "boot-" + id, SigningKeyID: "key", CreatedAt: at}
	if e = telemetry.SignSessionMessage(&m, key); e != nil {
		t.Fatal(e)
	}
	b := telemetry.NodeBatch{ProtocolVersion: 1, Key: telemetry.BatchKey{ClusterID: m.ClusterID, NodeID: m.NodeID, EnrollmentID: id, SessionEpoch: m.SessionEpoch, SessionID: m.SessionID, Sequence: "1"}, EnrollmentRevision: 1, InventoryRevisionID: "inventory", BootID: m.BootID, SigningKeyID: "key", AgentVersion: "fixture.v1", BuildSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CreatedAt: at}
	frame, e := telemetry.NewFixtureFrame("source", m.ClusterID, m.NodeID, "sample", at, 1)
	if e != nil {
		t.Fatal(e)
	}
	b.Sources = []telemetry.SourceFrame{frame}
	if e = telemetry.SignBatch(&b, key); e != nil {
		t.Fatal(e)
	}
	wire, _ := json.Marshal(b)
	return &testQueue{open: m, messages: []telemetry.SessionMessage{m}, batch: b, wire: wire, receipt: telemetry.Receipt{ProtocolVersion: 1, ID: "gateway-" + id, Key: b.Key, Digest: b.Digest, StoredAt: at, Durability: "GATEWAY"}, owned: true}
}

type testCloud struct {
	mu            sync.Mutex
	calls         map[string]int
	receipts      map[string]telemetry.CloudReceipt
	lost          bool
	mutate        func(*telemetry.CloudReceipt)
	sessionMutate func(*telemetry.SessionReceipt)
	block         bool
	denyEpoch     string
	active        atomic.Int64
	peak          atomic.Int64
}

func (c *testCloud) RegisterSession(ctx context.Context, m telemetry.SessionMessage) (telemetry.SessionReceipt, error) {
	if m.SessionEpoch == c.denyEpoch {
		return telemetry.SessionReceipt{}, telemetry.ErrUnauthorized
	}
	if c.block {
		n := c.active.Add(1)
		defer c.active.Add(-1)
		for p := c.peak.Load(); n > p && !c.peak.CompareAndSwap(p, n); p = c.peak.Load() {
		}
		<-ctx.Done()
		return telemetry.SessionReceipt{}, ctx.Err()
	}
	r := telemetry.SessionReceipt{ProtocolVersion: 1, ID: "cloud-session", ClusterID: m.ClusterID, NodeID: m.NodeID, EnrollmentID: m.EnrollmentID, EnrollmentRevision: m.EnrollmentRevision, SessionEpoch: m.SessionEpoch, SessionID: m.SessionID, BootID: m.BootID, Kind: m.Kind, Digest: m.Digest, StoredAt: time.Now().UTC(), Durability: "CLOUD", Finalized: m.Kind == "FINALIZE"}
	if c.sessionMutate != nil {
		c.sessionMutate(&r)
	}
	return r, nil
}
func (c *testCloud) SubmitBatch(_ context.Context, b telemetry.NodeBatch, id string) (telemetry.CloudReceipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.calls == nil {
		c.calls = map[string]int{}
		c.receipts = map[string]telemetry.CloudReceipt{}
	}
	c.calls[b.Key.EnrollmentID]++
	r, ok := c.receipts[id]
	if !ok {
		r = telemetry.CloudReceipt{ProtocolVersion: 1, ID: "cloud-" + id, Key: b.Key, Digest: b.Digest, GatewayReceiptID: id, StoredAt: time.Now().UTC(), Durability: "CLOUD", HistoryOnly: true}
		c.receipts[id] = r
	}
	if c.lost {
		c.lost = false
		return telemetry.CloudReceipt{}, telemetry.ErrUnavailable
	}
	if c.mutate != nil {
		c.mutate(&r)
	}
	return r, nil
}
func TestLostCloudResponseAndLocalAckFailureRetainOwnership(t *testing.T) {
	q := newTestQueue(t, "a")
	cloud := &testCloud{lost: true}
	r, e := New(map[string]Queue{"a": q}, cloud, nil)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	r.now = func() time.Time { return now }
	if n, e := r.Pass(context.Background()); n != 1 || e != nil {
		t.Fatal("OPEN", n, e)
	}
	if n, e := r.Pass(context.Background()); n != 0 || e == nil || !q.owned || q.ackCount != 0 {
		t.Fatal("lost response released ownership", n, e)
	}
	q.ackErr = errors.New("local disk failure")
	now = now.Add(time.Minute)
	if n, e := r.Pass(context.Background()); n != 0 || e == nil || !q.owned {
		t.Fatal("failed ack released ownership", n, e)
	}
	q.ackErr = nil
	now = now.Add(time.Minute)
	if n, e := r.Pass(context.Background()); n != 1 || e != nil || q.owned || len(cloud.receipts) != 1 || cloud.calls["a"] != 3 {
		t.Fatal("immutable replay", n, e, cloud.calls)
	}
}
func TestForeignReceiptsNeverReleaseOwnership(t *testing.T) {
	for _, change := range []func(*telemetry.CloudReceipt){func(r *telemetry.CloudReceipt) { r.Key.NodeID = "foreign" }, func(r *telemetry.CloudReceipt) { r.GatewayReceiptID = "foreign" }, func(r *telemetry.CloudReceipt) { r.HistoryOnly = false }, func(r *telemetry.CloudReceipt) { r.Durability = "GATEWAY" }} {
		q := newTestQueue(t, "a")
		cloud := &testCloud{mutate: change}
		r, _ := New(map[string]Queue{"a": q}, cloud, nil)
		_, _ = r.Pass(context.Background())
		if n, e := r.Pass(context.Background()); n != 0 || e == nil || !q.owned || q.ackCount != 0 {
			t.Fatal("unbound receipt accepted", n, e)
		}
	}
	q := newTestQueue(t, "a")
	cloud := &testCloud{sessionMutate: func(r *telemetry.SessionReceipt) { r.BootID = "foreign" }}
	r, _ := New(map[string]Queue{"a": q}, cloud, nil)
	if n, e := r.Pass(context.Background()); n != 0 || e == nil || q.ackCount != 0 {
		t.Fatal("foreign lifecycle accepted", n, e)
	}
}
func TestPassCapsConcurrentNodesAndJoinsCancellation(t *testing.T) {
	queues := map[string]Queue{}
	for i := 0; i < 9; i++ {
		id := fmt.Sprintf("e%d", i)
		queues[id] = newTestQueue(t, id)
	}
	cloud := &testCloud{block: true}
	r, _ := New(queues, cloud, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := r.Pass(ctx); done <- e }()
	deadline := time.After(2 * time.Second)
	for cloud.active.Load() != 4 {
		select {
		case <-deadline:
			t.Fatal("four requests did not start")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("did not join")
	}
	if cloud.active.Load() != 0 || cloud.peak.Load() != 4 {
		t.Fatal("concurrency/join", cloud.active.Load(), cloud.peak.Load())
	}
	if n, e := r.Pass(ctx); n != 0 || !errors.Is(e, context.Canceled) {
		t.Fatal("canceled pass started work", n, e)
	}
}
func TestRoundRobinDoesNotStarveNodes(t *testing.T) {
	queues := map[string]Queue{}
	for i := 0; i < 9; i++ {
		id := fmt.Sprintf("e%d", i)
		queues[id] = newTestQueue(t, id)
	}
	cloud := &testCloud{}
	r, _ := New(queues, cloud, nil)
	for i := 0; i < 7; i++ {
		if _, e := r.Pass(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	for id, q := range queues {
		if q.(*testQueue).owned || cloud.calls[id] != 1 {
			t.Fatal("starved", id)
		}
	}
}
func TestLifecycleFinalizationReplaysAfterGatewayRestart(t *testing.T) {
	q := newTestQueue(t, "a")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	final := q.open
	final.Kind = "FINALIZE"
	final.LastAllocatedSequence = "1"
	final.Digest = ""
	final.Signature = ""
	if e := telemetry.SignSessionMessage(&final, key); e != nil {
		t.Fatal(e)
	}
	q.messages = []telemetry.SessionMessage{final, q.open}
	q.owned = false
	cloud := &testCloud{}
	r, _ := New(map[string]Queue{"a": q}, cloud, nil)
	for i := 0; i < 2; i++ {
		if n, e := r.Pass(context.Background()); n != 1 || e != nil {
			t.Fatal("lifecycle", n, e)
		}
	}
	if n, e := r.Pass(context.Background()); n != 0 || e != nil {
		t.Fatal("duplicate in-memory lifecycle", n, e)
	}
	restarted, _ := New(map[string]Queue{"a": q}, cloud, nil)
	if n, e := restarted.Pass(context.Background()); n != 1 || e != nil {
		t.Fatal("restart did not replay", n, e)
	}
}

func TestRevokedOldLifecycleDoesNotStarveActiveSession(t *testing.T) {
	q := newTestQueue(t, "a")
	old := q.open
	_, active, _ := ed25519.GenerateKey(rand.Reader)
	q.open.SessionEpoch = "2"
	q.open.SessionID = "session-new"
	q.open.SigningKeyID = "key-new"
	q.open.Digest = ""
	q.open.Signature = ""
	if e := telemetry.SignSessionMessage(&q.open, active); e != nil {
		t.Fatal(e)
	}
	q.batch.Key.SessionEpoch = "2"
	q.batch.Key.SessionID = q.open.SessionID
	q.batch.SigningKeyID = "key-new"
	q.batch.Digest = ""
	q.batch.Signature = ""
	if e := telemetry.SignBatch(&q.batch, active); e != nil {
		t.Fatal(e)
	}
	q.wire, _ = json.Marshal(q.batch)
	q.receipt.Key = q.batch.Key
	q.receipt.Digest = q.batch.Digest
	q.messages = []telemetry.SessionMessage{old, q.open}
	cloud := &testCloud{denyEpoch: "1"}
	r, _ := New(map[string]Queue{"a": q}, cloud, nil)
	now := time.Now()
	r.now = func() time.Time { return now }
	if n, e := r.Pass(context.Background()); n != 0 || e == nil {
		t.Fatal("old revoked lifecycle was accepted", n, e)
	}
	now = now.Add(3 * time.Second)
	if n, e := r.Pass(context.Background()); n != 1 || e != nil {
		t.Fatal("new ACTIVE lifecycle starved", n, e)
	}
	if n, e := r.Pass(context.Background()); n != 1 || e != nil || q.owned {
		t.Fatal("new ACTIVE payload starved", n, e)
	}
	if until := r.blocked["a"]["1"]; until.IsZero() || !now.Before(until) {
		t.Fatal("old ownership rejection not preserved")
	}
	if len(r.blocked["a"]) != 1 || cloud.calls["a"] != 1 {
		t.Fatal("unexpected old replay or unbounded dispositions")
	}
}

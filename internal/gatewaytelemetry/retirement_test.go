package gatewaytelemetry

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetryjournal"
)

type retirementTestQueue struct {
	*testQueue
	record      telemetryjournal.ReleaseRecord
	afterCommit bool
	completed   bool
	pruneLimit  int
	compactions int
	compactErr  error
}

func (q *retirementTestQueue) PendingReleases(context.Context, string, int) ([]telemetryjournal.ReleaseRecord, bool, error) {
	if q.completed {
		return nil, false, nil
	}
	return []telemetryjournal.ReleaseRecord{q.record}, false, nil
}
func (q *retirementTestQueue) PrepareCloudRelease(context.Context, telemetry.ReleaseRequest) (telemetry.ReleasePrepareEnvelope, error) {
	if q.owned {
		return telemetry.ReleasePrepareEnvelope{}, telemetry.ErrBackpressure
	}
	return telemetry.ReleasePrepareEnvelope{Release: telemetry.ReleaseEnvelope{Request: q.record.Request, Manifest: q.record.Manifest}, Admission: *q.record.Admission}, nil
}
func (q *retirementTestQueue) CommitGatewayRelease(_ context.Context, r telemetry.ReleaseRequest, p telemetry.CloudRetirementReceipt) (telemetry.GatewayReleaseCommit, error) {
	c := telemetry.GatewayReleaseCommit{ProtocolVersion: 1, ReleaseVersion: 1, ID: "gateway-commit", Binding: r.Binding(), GatewayAdmissionID: q.record.Admission.ID, PreparedReceiptID: p.ID, CreatedAt: r.CreatedAt}
	q.record.Prepared = &p
	q.record.Commit = &c
	q.record.Phase = "RELEASED"
	if q.afterCommit {
		q.afterCommit = false
		return telemetry.GatewayReleaseCommit{}, telemetry.ErrUnavailable
	}
	return c, nil
}
func (q *retirementTestQueue) ConfirmCloudRelease(_ context.Context, r telemetry.ReleaseRequest, f telemetry.CloudRetirementReceipt) (telemetry.GatewayRetirementReceipt, error) {
	id, _ := telemetry.GatewayRetirementReceiptID(f)
	receipt := telemetry.GatewayRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: id, Binding: r.Binding(), GatewayAdmissionID: q.record.Admission.ID, PreparedReceiptID: q.record.Prepared.ID, GatewayCommitID: q.record.Commit.ID, CloudFinalReceipt: f, StoredAt: r.CreatedAt, Durability: "GATEWAY"}
	q.record.Final = &receipt
	q.record.Phase = "FINAL_RECEIVED"
	return receipt, nil
}
func (q *retirementTestQueue) ConfirmNodeCompletion(_ context.Context, c telemetry.NodeReleaseCompletion, r telemetry.NodeCompletionReceipt) error {
	q.record.CompletionReceipt = &r
	q.record.Phase = "COMPLETE"
	q.completed = true
	return nil
}
func (q *retirementTestQueue) PruneRetiredReceipts(_ context.Context, _ time.Time, limit int) (int, error) {
	q.pruneLimit = limit
	if limit < 1 || limit > 128 {
		return 0, telemetryjournal.ErrInvalid
	}
	return 0, nil
}
func (q *retirementTestQueue) CompactGatewaySessions(context.Context) error {
	q.compactions++
	return q.compactErr
}

type retirementTestCloud struct {
	*testCloud
	lostPrepare, lostFinal, lostCompletion bool
	foreign                                bool
	prepared                               *telemetry.CloudRetirementReceipt
	final                                  *telemetry.CloudRetirementReceipt
	receipt                                *telemetry.NodeCompletionReceipt
	requests                               int
}

func (c *retirementTestCloud) PrepareRetirement(_ context.Context, r telemetry.ReleaseRequest, _ telemetry.ReleaseManifest, a telemetry.ReleaseAdmissionReceipt) (telemetry.CloudRetirementReceipt, error) {
	c.requests++
	if c.prepared == nil {
		c.prepared = &telemetry.CloudRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "cloud-prepared", Phase: "PREPARED", Binding: r.Binding(), GatewayAdmissionID: a.ID, StoredAt: r.CreatedAt, Durability: "CLOUD"}
	}
	if c.lostPrepare {
		c.lostPrepare = false
		return telemetry.CloudRetirementReceipt{}, telemetry.ErrUnavailable
	}
	out := *c.prepared
	if c.foreign {
		out.Binding.NodeID = "foreign"
	}
	return out, nil
}
func (c *retirementTestCloud) CommitRetirement(_ context.Context, r telemetry.ReleaseRequest, k telemetry.GatewayReleaseCommit) (telemetry.CloudRetirementReceipt, error) {
	c.requests++
	if c.final == nil {
		c.final = &telemetry.CloudRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "cloud-final", Phase: "FINAL", Binding: r.Binding(), GatewayAdmissionID: k.GatewayAdmissionID, PreparedReceiptID: k.PreparedReceiptID, GatewayCommitID: k.ID, StoredAt: r.CreatedAt, Durability: "CLOUD"}
	}
	if c.lostFinal {
		c.lostFinal = false
		return telemetry.CloudRetirementReceipt{}, telemetry.ErrUnavailable
	}
	return *c.final, nil
}
func (c *retirementTestCloud) CompleteRetirement(_ context.Context, n telemetry.NodeReleaseCompletion) (telemetry.NodeCompletionReceipt, error) {
	c.requests++
	if c.receipt == nil {
		c.receipt = &telemetry.NodeCompletionReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "cloud-completion", Binding: n.Binding, CompletionDigest: n.Digest, CloudFinalReceiptID: n.CloudFinalReceiptID, GatewayRetirementReceiptID: n.GatewayRetirementReceiptID, StoredAt: n.CreatedAt, Durability: "CLOUD"}
	}
	if c.lostCompletion {
		c.lostCompletion = false
		return telemetry.NodeCompletionReceipt{}, telemetry.ErrUnavailable
	}
	return *c.receipt, nil
}
func retirementRuntimeFixture(t *testing.T) (*retirementTestQueue, *retirementTestCloud) {
	t.Helper()
	base := newTestQueue(t, "enrollment")
	base.owned = false
	m := telemetry.ReleaseManifest{Batches: []telemetry.ReleaseBatchFact{{Sequence: "1", Digest: base.batch.Digest, GatewayReceiptID: base.receipt.ID}}}
	digest, e := telemetry.CanonicalReleaseManifestDigest(m)
	if e != nil {
		t.Fatal(e)
	}
	r := telemetry.ReleaseRequest{ProtocolVersion: 1, ReleaseVersion: 1, ReleaseID: "release", ClusterID: base.open.ClusterID, NodeID: base.open.NodeID, EnrollmentID: base.open.EnrollmentID, EnrollmentRevision: 1, SessionEpoch: "1", SessionID: base.open.SessionID, SigningKeyID: "key", CreatedAt: base.open.CreatedAt, FromSequence: "1", ThroughSequence: "1", ManifestDigest: hex.EncodeToString(digest[:])}
	if e = telemetry.SignReleaseRequest(&r, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))); e != nil {
		t.Fatal(e)
	}
	a := telemetry.ReleaseAdmissionReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "admission", Binding: r.Binding(), StoredAt: r.CreatedAt, Durability: "GATEWAY"}
	return &retirementTestQueue{testQueue: base, record: telemetryjournal.ReleaseRecord{Request: r, Manifest: m, Phase: "RELEASING", Admission: &a}}, &retirementTestCloud{testCloud: &testCloud{calls: map[string]int{}, receipts: map[string]telemetry.CloudReceipt{}}}
}
func TestRetirementDrainReplayAcrossLostCloudAndLocalCommitResponses(t *testing.T) {
	q, c := retirementRuntimeFixture(t)
	c.lostPrepare = true
	c.lostFinal = true
	c.lostCompletion = true
	q.afterCommit = true
	pass := func(wantPhase string, wantErr bool) {
		t.Helper()
		r, e := New(map[string]Queue{q.open.EnrollmentID: q}, c, nil)
		if e != nil {
			t.Fatal(e)
		}
		handled, progressed, e := r.drainRetirement(context.Background(), q.open.EnrollmentID)
		if !handled || (e != nil) != wantErr || progressed == wantErr || q.record.Phase != wantPhase {
			t.Fatal("ownership phase changed incorrectly", q.record.Phase, handled, progressed, e)
		}
	}
	pass("RELEASING", true) // Cloud prepared, response lost.
	pass("RELEASED", true)  // Local commit durable, response lost.
	pass("RELEASED", true)  // Cloud final durable, response lost.
	pass("FINAL_RECEIVED", false)
	r, e := New(map[string]Queue{q.open.EnrollmentID: q}, c, nil)
	if e != nil {
		t.Fatal(e)
	}
	if handled, _, e := r.drainRetirement(context.Background(), q.open.EnrollmentID); handled || e != nil {
		t.Fatal("waiting for node monopolized control", e)
	}
	n := telemetry.NodeReleaseCompletion{ProtocolVersion: 1, ReleaseVersion: 1, ID: "node-completion", Binding: q.record.Request.Binding(), CloudFinalReceiptID: q.record.Final.CloudFinalReceipt.ID, GatewayRetirementReceiptID: q.record.Final.ID, SigningKeyID: "key", CreatedAt: q.record.Request.CreatedAt}
	if e := telemetry.SignNodeCompletion(&n, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))); e != nil {
		t.Fatal(e)
	}
	q.record.Completion = &n
	q.record.Phase = "NODE_COMPLETION_PENDING"
	pass("NODE_COMPLETION_PENDING", true)
	pass("COMPLETE", false)
	if c.requests != 6 || q.record.CompletionReceipt.ID != c.receipt.ID {
		t.Fatal("nonimmutable completion replay", c.requests)
	}
}
func TestRetirementDrainDoesNotStarveOriginalsOrAcceptForeignPreparation(t *testing.T) {
	q, c := retirementRuntimeFixture(t)
	q.owned = true
	r, e := New(map[string]Queue{q.open.EnrollmentID: q}, c, nil)
	if e != nil {
		t.Fatal(e)
	}
	if handled, _, e := r.drainRetirement(context.Background(), q.open.EnrollmentID); handled || e != nil || c.requests != 0 {
		t.Fatal("owned original blocked behind retirement", handled, e)
	}
	q.owned = false
	c.foreign = true
	if handled, progress, e := r.drainRetirement(context.Background(), q.open.EnrollmentID); !handled || progress || e == nil || q.record.Commit != nil {
		t.Fatal("foreign preparation released ownership", handled, progress, e)
	}
}

func TestRetirementMaintenanceUsesJournalLimitAndRetriesCompaction(t *testing.T) {
	q, c := retirementRuntimeFixture(t)
	r, err := New(map[string]Queue{q.open.EnrollmentID: q}, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	q.compactErr = telemetryjournal.ErrCapacity
	if _, err := r.pruneRetirement(context.Background(), q.open.EnrollmentID); err == nil || q.pruneLimit != 0 {
		t.Fatal("failed compaction was hidden or pruning proceeded", err)
	}
	q.compactErr = nil
	if _, err := r.pruneRetirement(context.Background(), q.open.EnrollmentID); err != nil || q.pruneLimit != 128 || q.compactions != 2 {
		t.Fatal("maintenance did not retry within the journal bound", err, q.pruneLimit, q.compactions)
	}
}

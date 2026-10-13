package collectorcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type fakeTypedOperations struct {
	lease               domain.TypedWorkLease
	claims, submissions int
	ref                 LeaseRef
}

func (f *fakeTypedOperations) ClaimTypedWork(_ context.Context, cluster domain.ClusterID, collector domain.CollectorID, token string, _ time.Duration, _ []domain.SourceID) (domain.TypedWorkLease, bool, error) {
	f.claims++
	f.lease.Lease.CollectorID = collector
	f.lease.Lease.LeaseToken = token
	return f.lease, true, nil
}
func (f *fakeTypedOperations) SubmitTypedResult(_ context.Context, cluster domain.ClusterID, collector domain.CollectorID, ref LeaseRef, result domain.TypedCollectorResult, digest string) (FinalizeOutcome, error) {
	f.submissions++
	f.ref = ref
	if cluster != f.lease.Plan.ClusterID || collector != f.lease.Lease.CollectorID || ref.LeaseToken != f.lease.Lease.LeaseToken {
		return FinalizeOutcome{}, ErrWorkLeaseInvalid
	}
	if domain.ValidateTypedResultForLease(result, f.lease) != nil {
		return FinalizeOutcome{}, ErrResultConflict
	}
	return FinalizeOutcome{RunID: result.Plan.RunID, Status: result.Status, SHA256: digest, PreviouslyFinalized: f.submissions > 1}, nil
}

func typedTestLease() domain.TypedWorkLease {
	l := testLease()
	l.LeaseToken = strings.Repeat("a", 32)
	t := l.Work.Task
	p := domain.CollectionPlan{SchemaVersion: 2, RunID: t.RunID, ClusterID: t.ClusterID, SourceID: t.SourceID, SourceKind: domain.CollectionSourceSlurm, Operation: domain.OperationSlurmInventory, PayloadSchema: domain.CollectionInventorySchema,
		Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{"node-1"}}, Interval: &domain.CollectionInterval{Start: t.Range.Start, End: t.Range.End}, ScheduledFor: t.ScheduledFor, Deadline: t.Deadline, Limits: domain.CollectionLimits{MaxRecords: 10, MaxBytes: 100000}, IdempotencyKey: t.IdempotencyKey}
	return domain.TypedWorkLease{Lease: l, Plan: p}
}
func typedTestResult(l domain.TypedWorkLease) domain.TypedCollectorResult {
	p := l.Plan
	return domain.TypedCollectorResult{SchemaVersion: 2, WorkID: l.Lease.Work.WorkID, Attempt: l.Lease.Attempt, Plan: p, Status: domain.ResultNoData, StartedAt: p.ScheduledFor, CompletedAt: p.Deadline,
		Coverage: domain.SourceCoverage{SchemaVersion: 1, ClusterID: p.ClusterID, SourceID: p.SourceID, Scope: domain.CoverageInventory, State: domain.SourceCoverageUnknown, SourceAt: p.ScheduledFor, EffectiveAt: p.ScheduledFor, ObservedAt: p.Deadline},
		Payload:  domain.CollectionPayload{Kind: domain.CollectionPayloadInventory, Inventory: &domain.CollectionInventoryPayload{Revisions: []domain.InventoryRevision{}}}}
}
func serveTyped(t *Transport, method, path, body, version string, authenticated bool) *httptest.ResponseRecorder {
	r := collectorRequest(method, path, body, authenticated)
	r.Header.Set(protocolHeader, version)
	w := httptest.NewRecorder()
	t.ServeHTTP(w, r)
	return w
}

func TestTypedTransportFailsClosedAndPreservesV1(t *testing.T) {
	transport, _, _, work, _ := newTestTransport(t)
	work.lease, work.found = testLease(), true
	if w := serveTyped(transport, "GET", "/collector/v2/work/claim?wait_seconds=0", "", "2", true); w.Code != 503 {
		t.Fatalf("unconfigured: %d", w.Code)
	}
	if w := serveTyped(transport, "GET", "/collector/v2/work/claim?wait_seconds=0", "", "1", true); w.Code != 426 {
		t.Fatalf("version: %d", w.Code)
	}
	if w := serveTyped(transport, "GET", "/collector/v2/work/claim?wait_seconds=0", "", "2", false); w.Code != 401 {
		t.Fatalf("auth: %d", w.Code)
	}
	if w := serveTyped(transport, "GET", "/collector/v1/work/claim?wait_seconds=0", "", "1", true); w.Code != 200 || !strings.Contains(w.Body.String(), `"query_kind"`) {
		t.Fatalf("v1: %d %s", w.Code, w.Body.String())
	}
}

func TestTypedTransportSharesLeaseAuthorityAndBindsSubmission(t *testing.T) {
	transport, _, _, work, _ := newTestTransport(t)
	fake := &fakeTypedOperations{lease: typedTestLease()}
	if err := transport.ConfigureTypedCollection(fake); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"", "&source_id=", "&source_id=source-1&source_id=source-1"} {
		w := serveTyped(transport, "GET", "/collector/v2/work/claim?wait_seconds=0"+query, "", "2", true)
		if w.Code != 400 || fake.claims != 0 {
			t.Fatalf("unbounded or ambiguous source selection reached store: %d", w.Code)
		}
	}
	w := serveTyped(transport, "GET", "/collector/v2/work/claim?wait_seconds=0&source_id=source-1", "", "2", true)
	if w.Code != 200 || w.Header().Get(protocolHeader) != "2" {
		t.Fatalf("claim: %d %s", w.Code, w.Body.String())
	}
	var claim TypedClaimResponse
	if err := json.Unmarshal(w.Body.Bytes(), &claim); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"start", "renew"} {
		body := leaseRequestDTO{LeaseToken: claim.LeaseToken}
		if suffix == "renew" {
			body.DurationSeconds = 60
		}
		encoded, _ := json.Marshal(body)
		w = serveTyped(transport, "POST", "/collector/v2/work/work-1/attempts/2/"+suffix, string(encoded), "2", true)
		if w.Code != 204 || w.Header().Get(protocolHeader) != "2" {
			t.Fatalf("%s: %d %s", suffix, w.Code, w.Body.String())
		}
	}
	if work.startedToken != claim.LeaseToken || work.renewedToken != claim.LeaseToken {
		t.Fatal("v2 did not reuse existing lease authority")
	}
	result := typedTestResult(fake.lease)
	submit := func(result domain.TypedCollectorResult, checksum string) *httptest.ResponseRecorder {
		encoded, err := domain.EncodeTypedCollectorResult(result)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		if checksum == "" {
			checksum = hex.EncodeToString(digest[:])
		}
		body, _ := json.Marshal(TypedResultRequest{LeaseToken: claim.LeaseToken, Document: encoded, SHA256: checksum})
		return serveTyped(transport, http.MethodPost, "/collector/v2/work/work-1/attempts/2/results", string(body), "2", true)
	}
	for i := 0; i < 2; i++ {
		if w = submit(result, ""); w.Code != 200 {
			t.Fatalf("submit: %d %s", w.Code, w.Body.String())
		}
	}
	if !strings.Contains(w.Body.String(), `"previously_finalized":true`) {
		t.Fatal("replay outcome was lost")
	}
	if w = submit(result, strings.Repeat("0", 64)); w.Code != 400 || fake.submissions != 2 {
		t.Fatal("invalid checksum reached backend")
	}
	result.Plan.SourceID, result.Coverage.SourceID = "forged", "forged"
	if w = submit(result, ""); w.Code != 409 {
		t.Fatalf("forged source: %d", w.Code)
	}
	result.Plan.ClusterID, result.Coverage.ClusterID = "foreign", "foreign"
	if w = submit(result, ""); w.Code != 400 || fake.submissions != 3 {
		t.Fatal("foreign cluster reached backend")
	}
}

package investigationcontext

import (
	"context"
	"errors"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type checkpointMemory struct{ records []ContextRecord }

func (store *checkpointMemory) LoadLatestCheckpoint(_ context.Context, id string, before int) (Checkpoint, bool, error) {
	for index := len(store.records) - 1; index >= 0; index-- {
		value := store.records[index].Checkpoint
		if string(value.Projection.InvestigationID) == id && value.Projection.LedgerVersion < before {
			return value, true, nil
		}
	}
	return Checkpoint{}, false, nil
}
func (store *checkpointMemory) RecordContextCheckpoint(_ context.Context, record ContextRecord) error {
	for _, value := range store.records {
		if value.Checkpoint.Projection.InvestigationID == record.Checkpoint.Projection.InvestigationID && value.Checkpoint.Projection.LedgerVersion == record.Checkpoint.Projection.LedgerVersion {
			if value.Checkpoint.Digest != record.Checkpoint.Digest {
				return errors.New("conflict")
			}
			return nil
		}
	}
	store.records = append(store.records, record)
	return nil
}

func TestCheckpointDeterministicAcrossEvidenceOrder(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 123456000, time.UTC)
	snapshot := checkpointSnapshot(t, now)
	input := checkpointInput(now)
	first, err := ProjectCheckpoint(snapshot, input, "policy-v1", "tools-v1")
	if err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 100; iteration++ {
		shuffled := input
		shuffled.Evidence = slices.Clone(input.Evidence)
		rand.New(rand.NewSource(int64(iteration))).Shuffle(len(shuffled.Evidence), func(i, j int) {
			shuffled.Evidence[i], shuffled.Evidence[j] = shuffled.Evidence[j], shuffled.Evidence[i]
		})
		got, err := ProjectCheckpoint(snapshot, shuffled, "policy-v1", "tools-v1")
		if err != nil {
			t.Fatal(err)
		}
		if got.Digest != first.Digest || !slices.Equal(got.CanonicalJSON, first.CanonicalJSON) {
			t.Fatalf("iteration %d changed checkpoint", iteration)
		}
	}
}

func TestDeltaReconstructsNextCheckpointAndFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	parentSnapshot := checkpointSnapshot(t, now)
	parent, _ := ProjectCheckpoint(parentSnapshot, checkpointInput(now), "policy-v1", "tools-v1")
	nextInvestigation, err := parentSnapshot.Investigation.BeginPlanning(now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	nextSnapshot := parentSnapshot
	nextSnapshot.Investigation = nextInvestigation
	nextSnapshot.PriorActions = append(nextSnapshot.PriorActions, application.InvestigationActionHistory{ToolID: "gpu.snapshot.v1", Outcome: "NO_EVIDENCE", Targets: []string{"node-1"}, Start: now.Add(-time.Hour), End: now})
	nextInput := checkpointInput(now)
	nextInput.Evidence = append(nextInput.Evidence, evidenceCandidate(now, "ev-3", "source-c", false))
	next, _ := ProjectCheckpoint(nextSnapshot, nextInput, "policy-v1", "tools-v1")
	delta, err := BuildDelta(parent, next)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := Apply(parent, delta)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Digest != next.Digest || !slices.Equal(applied.CanonicalJSON, next.CanonicalJSON) {
		t.Fatal("delta did not reconstruct checkpoint")
	}
	delta.ParentDigest = "altered"
	if _, err := Apply(parent, delta); !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("error=%v", err)
	}
}

func TestRetrievalHardFiltersBeforeStableRankingAndPreservesMandatory(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	latest := evidenceCandidate(now, "ev-latest", "source-a", true)
	tieB := evidenceCandidate(now.Add(-time.Minute), "ev-b", "source-b", false)
	tieA := evidenceCandidate(now.Add(-time.Minute), "ev-a", "source-c", false)
	wrong := evidenceCandidate(now, "ev-wrong", "source-a", false)
	wrong.ClusterID = "cluster-b"
	result, err := SelectEvidence([]EvidenceInput{tieB, wrong, latest, tieA}, RetrievalQuery{ClusterID: "cluster-a", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now, CommittedBefore: now.Add(time.Minute), AllowanceTokens: 10_000, MaximumPerClass: 8, MaximumPerSource: 8})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Selected) != 3 || result.Selected[0].EvidenceID != "ev-latest" || result.Selected[1].EvidenceID != "ev-a" || result.Selected[2].EvidenceID != "ev-b" {
		t.Fatalf("selection=%v", selectedIDs(result.Selected))
	}
	if len(result.Exclusions) != 1 || result.Exclusions[0].Reason != ExcludeCluster {
		t.Fatalf("exclusions=%+v", result.Exclusions)
	}
	if _, err := SelectEvidence([]EvidenceInput{latest}, RetrievalQuery{ClusterID: "cluster-a", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now, CommittedBefore: now.Add(time.Minute), AllowanceTokens: 1}); !errors.Is(err, ErrRequiredContextTooLarge) {
		t.Fatalf("error=%v", err)
	}
}

func TestRetrievalAllowsOnlyStoreAdmittedPostRequestDiagnosticsAcrossTheRequestBoundary(t *testing.T) {
	now := time.Date(2026, 8, 26, 13, 19, 30, 0, time.UTC)
	query := RetrievalQuery{
		ClusterID: "cluster-a", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Minute), End: now,
		CommittedBefore: now, AllowanceTokens: 10_000, MaximumPerClass: 8, MaximumPerSource: 8,
	}
	postRequest := evidenceCandidate(now, "diagnostic-post-request", "diagnostic:gpu.ecc_counters", true)
	postRequest.CommittedAt = now.Add(2 * time.Minute)
	postRequest.ObservedFrom = now.Add(time.Minute)
	postRequest.ObservedTo = now.Add(90 * time.Second)
	postRequest.CollectedAt = postRequest.ObservedTo
	postRequest.ExpectedFrom = postRequest.ObservedFrom
	postRequest.ExpectedTo = postRequest.ObservedTo

	ordinary, err := SelectEvidence([]EvidenceInput{postRequest}, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(ordinary.Selected) != 0 || len(ordinary.Exclusions) != 1 || ordinary.Exclusions[0].Reason != ExcludeCommitBoundary {
		t.Fatalf("ordinary post-request evidence crossed the boundary: selected=%v exclusions=%+v", selectedIDs(ordinary.Selected), ordinary.Exclusions)
	}

	postRequest.AdmittedPostRequestDiagnostic = true
	admitted, err := SelectEvidence([]EvidenceInput{postRequest}, query)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(selectedIDs(admitted.Selected), []domain.EvidenceID{postRequest.EvidenceID}) || len(admitted.Exclusions) != 0 {
		t.Fatalf("store-admitted diagnostic was not selected: selected=%v exclusions=%+v", selectedIDs(admitted.Selected), admitted.Exclusions)
	}

	missingCommit := postRequest
	missingCommit.EvidenceID = "diagnostic-missing-commit"
	missingCommit.CommittedAt = time.Time{}
	missing, err := SelectEvidence([]EvidenceInput{missingCommit}, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing.Selected) != 0 || len(missing.Exclusions) != 1 || missing.Exclusions[0].Reason != ExcludeCommitBoundary {
		t.Fatalf("admission marker bypassed missing durable commit: selected=%v exclusions=%+v", selectedIDs(missing.Selected), missing.Exclusions)
	}
}

func TestRetrievalDiagnosticAdmissionMarkerDoesNotBypassOtherHardFilters(t *testing.T) {
	now := time.Date(2026, 8, 26, 13, 19, 30, 0, time.UTC)
	query := RetrievalQuery{
		ClusterID: "cluster-a", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Minute), End: now,
		CommittedBefore: now, AllowanceTokens: 10_000, MaximumPerClass: 8, MaximumPerSource: 8,
	}
	base := evidenceCandidate(now, "diagnostic-tamper", "diagnostic:gpu.ecc_counters", false)
	base.CommittedAt = now.Add(time.Minute)
	base.AdmittedPostRequestDiagnostic = true
	tests := []struct {
		name   string
		reason ExclusionReason
		mutate func(*EvidenceInput)
	}{
		{name: "foreign cluster", reason: ExcludeCluster, mutate: func(value *EvidenceInput) { value.ClusterID = "cluster-b" }},
		{name: "citation authority", reason: ExcludeAuthority, mutate: func(value *EvidenceInput) { value.CitationEligible = false }},
		{name: "superseded", reason: ExcludeSuperseded, mutate: func(value *EvidenceInput) { value.Superseded = true }},
		{name: "retention", reason: ExcludeRetention, mutate: func(value *EvidenceInput) { value.Retained = false }},
		{name: "artifact unavailable", reason: ExcludeArtifactAvailability, mutate: func(value *EvidenceInput) { value.Excerpt = "bounded output"; value.ArtifactAvailable = false }},
		{name: "foreign target", reason: ExcludeScope, mutate: func(value *EvidenceInput) { value.EntityIDs = []string{"node-2"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.EvidenceID = domain.EvidenceID("diagnostic-tamper-" + strings.ReplaceAll(test.name, " ", "-"))
			test.mutate(&candidate)
			result, err := SelectEvidence([]EvidenceInput{candidate}, query)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Selected) != 0 || len(result.Exclusions) != 1 || result.Exclusions[0].Reason != test.reason {
				t.Fatalf("marker bypassed %s: selected=%v exclusions=%+v", test.reason, selectedIDs(result.Selected), result.Exclusions)
			}
		})
	}
}

func TestSemanticUsabilityRejectsPresenceOnlyEvidence(t *testing.T) {
	item := EvidenceInput{EvidenceID: "ev-1", Summary: "Validated immutable evidence is available under this evidence ID."}
	if !errors.Is(ValidateSemanticUsability(item), ErrEvidenceContextUnusable) {
		t.Fatal("generic evidence summary was accepted")
	}
	item.Excerpt = `{"temperature":87}`
	if err := ValidateSemanticUsability(item); err != nil {
		t.Fatal(err)
	}
	item.Excerpt, item.Summary = "", "Envelope covers one target but contains no normalized values."
	item.SummaryQuality = "PROVENANCE_ONLY"
	if !errors.Is(ValidateSemanticUsability(item), ErrEvidenceContextUnusable) {
		t.Fatal("provenance-only summary was accepted")
	}
}

func TestStatelessRecoveryRebuildsIdenticalCheckpointAndSelection(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	store := &checkpointMemory{}
	config := DefaultEngineConfig()
	config.EvidenceAllowanceTokens = 10_000
	firstEngine, _ := NewEngine(config, store)
	prepared, first, err := firstEngine.Prepare(t.Context(), checkpointSnapshot(t, now), checkpointInput(now))
	if err != nil {
		t.Fatal(err)
	}
	secondEngine, _ := NewEngine(config, store)
	rebuilt, second, err := secondEngine.Prepare(t.Context(), checkpointSnapshot(t, now), checkpointInput(now))
	if err != nil {
		t.Fatal(err)
	}
	if first.Checkpoint.Digest != second.Checkpoint.Digest || !slices.Equal(selectedIDs(prepared.Evidence), selectedIDs(rebuilt.Evidence)) {
		t.Fatalf("first=%s second=%s", first.Checkpoint.Digest, second.Checkpoint.Digest)
	}
}

func checkpointSnapshot(t *testing.T, now time.Time) application.InvestigationSnapshot {
	t.Helper()
	request := domain.InvestigationRequest{ID: "inv-1", IncidentID: "incident-1", ClusterID: "cluster-a", Question: "why", RequestedBy: "actor", IdempotencyKey: "key", Scope: domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now}, SuccessCriteria: []string{"cite evidence"}, Budget: domain.InvestigationBudget{MaxDecisions: 10, MaxToolCalls: 10, MaxFanOut: 2, MaxModelTokens: 100000, MaxCostMicros: 1000000}, RequestedAt: now.Add(time.Minute), Deadline: now.Add(time.Hour)}
	investigation, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	return application.InvestigationSnapshot{Investigation: investigation}
}

func checkpointInput(now time.Time) Input {
	return Input{InvestigationID: "inv-1", ClusterID: "cluster-a", Question: "why", Scope: domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now}, SuccessCriteria: []string{"cite evidence"}, Evidence: []EvidenceInput{evidenceCandidate(now, "ev-2", "source-b", false), evidenceCandidate(now, "ev-1", "source-a", false)}}
}

func evidenceCandidate(now time.Time, id, source string, latest bool) EvidenceInput {
	target := domain.EvidenceTarget{Kind: domain.EvidenceTargetNode, ID: "node-1"}
	return EvidenceInput{EvidenceID: domain.EvidenceID(id), ClusterID: "cluster-a", Operation: "gpu.snapshot.v1", EvidenceClass: "GPU", Status: domain.EvidenceComplete, EntityIDs: []string{"node-1"}, ObservedFrom: now.Add(-time.Minute), ObservedTo: now, CollectedAt: now, Source: source, Summary: "Observed one GPU temperature sample with maximum 87 C; onset is not established.", SummaryVersion: "gpu-v1", SummaryQuality: "MEANINGFUL", Priority: 10, Coverage: domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{target}, Covered: []domain.EvidenceTarget{target}}, ExpectedFrom: now.Add(-time.Minute), ExpectedTo: now, Latest: latest, CommittedAt: now, Retained: true, ArtifactAvailable: true, CitationEligible: true}
}

func selectedIDs(values []EvidenceInput) []domain.EvidenceID {
	result := make([]domain.EvidenceID, len(values))
	for i := range values {
		result[i] = values[i].EvidenceID
	}
	return result
}

// Selection must price the block the builder will emit, not the raw envelope.
// A bounded XID lookup can carry a 50 KB excerpt while the builder sends at
// most 2 KB, so estimating the raw shape priced one mandatory item above the
// entire evidence allowance and failed transitions that would have fitted.
func TestSelectionPricesTheTruncatedBlockNotTheRawEnvelope(t *testing.T) {
	limits := DefaultLimits()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	item := EvidenceInput{
		EvidenceID: "xid-large", ClusterID: "pilot-cluster", EvidenceClass: "dcgm_gpu_xid",
		Status: domain.EvidenceComplete, EntityIDs: []string{"gpu-1"}, Source: "prometheus:dcgm_gpu_xid",
		ObservedFrom: now, ObservedTo: now, CollectedAt: now.Add(time.Second),
		ExpectedFrom: now, ExpectedTo: now.Add(time.Minute),
		Summary: strings.Repeat("s", 8_000),
		Excerpt: strings.Repeat("x", 50_000),
		Latest:  true,
		// hardFilter requires a citable, retained, artifact-backed candidate.
		CitationEligible: true, Retained: true, ArtifactAvailable: true, CommittedAt: now.Add(time.Second),
		SummaryQuality: "MEANINGFUL", SummaryVersion: "operation-summary-v1",
		Coverage: domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{{Kind: domain.EvidenceTargetGPU, ID: "gpu-1"}}, Covered: []domain.EvidenceTarget{{Kind: domain.EvidenceTargetGPU, ID: "gpu-1"}}},
	}
	query := RetrievalQuery{
		ClusterID: "pilot-cluster", EntityIDs: []string{"gpu-1"}, Start: now.Add(-time.Hour), End: now.Add(time.Hour),
		CommittedBefore: now.Add(time.Hour), AllowanceTokens: 4_000, MaximumPerClass: 8, MaximumPerSource: 8,
		MaxSummaryBytes: limits.MaxSummaryBytes, MaxExcerptBytes: limits.MaxExcerptBytes,
	}
	result, err := SelectEvidence([]EvidenceInput{item}, query)
	if err != nil {
		t.Fatalf("a single truncated block did not fit a 4000 token allowance: %v", err)
	}
	if len(result.Selected) != 1 {
		t.Fatalf("selected=%d exclusions=%+v", len(result.Selected), result.Exclusions)
	}
	// 58 KB raw would price near 14,500 tokens; the truncated block is far less.
	if result.Tokens > 1_500 {
		t.Fatalf("estimate %d still reflects the untruncated envelope", result.Tokens)
	}
	// Without the caps the same item prices itself out of the allowance.
	uncapped := query
	uncapped.MaxSummaryBytes, uncapped.MaxExcerptBytes = 0, 0
	if _, err := SelectEvidence([]EvidenceInput{item}, uncapped); !errors.Is(err, ErrRequiredContextTooLarge) {
		t.Fatalf("uncapped estimate did not overflow as expected: %v", err)
	}
}

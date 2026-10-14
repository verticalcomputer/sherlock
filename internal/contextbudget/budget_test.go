package contextbudget

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/modelprovider"
)

type manifestMemory struct{ values []Manifest }

func (sink *manifestMemory) RecordContextManifest(_ context.Context, value Manifest) error {
	sink.values = append(sink.values, value)
	return nil
}

func TestProspectiveRunBudgetRetainsSpecificReasonAndClassifiesBudgetExhaustion(t *testing.T) {
	if got := ErrProspectiveRunBudget.Error(); got != "PROSPECTIVE_RUN_BUDGET_EXCEEDED" {
		t.Fatalf("ErrProspectiveRunBudget.Error() = %q", got)
	}
	if !errors.Is(ErrProspectiveRunBudget, domain.ErrInvestigationBudgetExceeded) {
		t.Fatal("prospective run budget must classify as investigation budget exhaustion")
	}
}

func TestPlanningCompactionIsBoundedAndPreservesRequiredCoverage(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	snapshot := budgetSnapshot(t, now)
	sink := &manifestMemory{}
	manager, err := New(Config{MaximumInputTokens: 1100, MaximumMemoryTokens: 200, MaximumMemoryEntries: 2, ProviderOverheadTokens: 0}, JSONHeuristicEstimator{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	request := modelprovider.PlanningRequest{SchemaVersion: 1, InvestigationID: "inv-1", Question: "why", Scope: modelprovider.Scope{ClusterID: "cluster-a", EntityKind: "node", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now}, StateSummary: "state", SuccessCriteria: []string{"cite"}, RemainingBudget: modelprovider.RemainingBudget{Decisions: 1, ToolCalls: 1, FanOut: 1, ModelTokens: 1000, CostMicros: 1}, Coverage: modelprovider.Coverage{TargetsMissed: []string{"node-1"}, ToolFailures: []string{"SOURCE_UNAVAILABLE"}, ExpectedFrom: now.Add(-time.Hour), ExpectedTo: now}, PromptVersion: "planning-v2", ToolSchemaVersion: "catalog-v1"}
	for i := 0; i < 20; i++ {
		request.PriorActions = append(request.PriorActions, modelprovider.PriorAction{ActionDigest: strings.Repeat("a", 64), ToolID: "tool.v1", Outcome: "FAILED", Targets: []string{"node-1"}, Start: now.Add(-time.Hour), End: now})
	}
	for i := 0; i < 3; i++ {
		request.Memory = append(request.Memory, modelprovider.MemoryContext{MemoryID: "memory-" + string(rune('a'+i)), TrustClass: "VALIDATED_FINDING", Statement: strings.Repeat("x", 300), SourceInvestigationID: "prior-1", EntityIDs: []string{"node-1"}, EvidenceIDs: []string{"evidence-1"}, ValidFrom: now})
	}
	prepared, manifest, err := manager.PreparePlanning(t.Context(), snapshot, "investigation/inv-1/planning/1", request, Selection{CandidateCount: 3, FallbackState: "LEXICAL"})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.EstimatedInputTokens > manifest.AllowanceTokens || len(prepared.Memory) > 2 || len(prepared.PriorActions) >= 20 {
		t.Fatalf("prepared=%d memory=%d manifest=%+v", len(prepared.PriorActions), len(prepared.Memory), manifest)
	}
	if len(prepared.Coverage.TargetsMissed) != 1 || len(prepared.Coverage.ToolFailures) != 1 {
		t.Fatalf("required coverage was compacted: %+v", prepared.Coverage)
	}
	if len(sink.values) != 1 || manifest.ExclusionReasons["memory_entry_limit"] == 0 || manifest.ExclusionReasons["prior_action_compaction"] == 0 {
		t.Fatalf("manifest=%+v", manifest)
	}
}

func TestRequiredContextOverAllowanceFailsBeforePersistence(t *testing.T) {
	now := time.Now().UTC()
	snapshot := budgetSnapshot(t, now)
	sink := &manifestMemory{}
	manager, _ := New(Config{MaximumInputTokens: 1024, MaximumMemoryTokens: 0, MaximumMemoryEntries: 0}, JSONHeuristicEstimator{}, sink)
	request := modelprovider.SynthesisRequest{SchemaVersion: 1, InvestigationID: "inv-1", Question: strings.Repeat("q", 5000)}
	_, _, err := manager.PrepareSynthesis(t.Context(), snapshot, "investigation/inv-1/synthesis/1", request)
	if !errors.Is(err, ErrAllowanceExceeded) || len(sink.values) != 0 {
		t.Fatalf("error=%v manifests=%d", err, len(sink.values))
	}
}

func TestEmptyMemorySelectionUsesJSONArray(t *testing.T) {
	now := time.Now().UTC()
	sink := &manifestMemory{}
	manager, err := New(DefaultConfig(), JSONHeuristicEstimator{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	request := modelprovider.PlanningRequest{SchemaVersion: 1, InvestigationID: "inv-1", Question: "why"}
	_, manifest, err := manager.PreparePlanning(t.Context(), budgetSnapshot(t, now), "investigation/inv-1/planning/1", request, Selection{FallbackState: "LEXICAL", ShadowOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(manifest.SelectedMemoryIDs)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "[]" {
		t.Fatalf("selected memory IDs encoded as %s", encoded)
	}
}

func TestSixTurnReplayDoesNotGrowPastAllowance(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	snapshot := budgetSnapshot(t, now)
	sink := &manifestMemory{}
	manager, _ := New(DefaultConfig(), JSONHeuristicEstimator{}, sink)
	var estimates []int64
	for turn := 1; turn <= 6; turn++ {
		request := modelprovider.PlanningRequest{SchemaVersion: 1, InvestigationID: "inv-1", Question: "why", Scope: modelprovider.Scope{ClusterID: "cluster-a", EntityKind: "node", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now}, StateSummary: "select one action", SuccessCriteria: []string{"cite"}, RemainingBudget: modelprovider.RemainingBudget{Decisions: 6 - turn, ToolCalls: 6 - turn, FanOut: 1, ModelTokens: 200000, CostMicros: 1}, PromptVersion: "planning-v2", ToolSchemaVersion: "catalog-v1", Coverage: modelprovider.Coverage{TargetsMissed: []string{"node-1"}, ExpectedFrom: now.Add(-time.Hour), ExpectedTo: now}}
		for action := 0; action < turn*150; action++ {
			request.PriorActions = append(request.PriorActions, modelprovider.PriorAction{ActionDigest: strings.Repeat("a", 64), ToolID: "gpu.health.v1", Outcome: "SUCCEEDED", Targets: []string{"node-1"}, Start: now.Add(-time.Hour), End: now, EvidenceIDs: []string{"evidence-1"}})
		}
		prepared, manifest, err := manager.PreparePlanning(t.Context(), snapshot, "investigation/inv-1/planning/"+string(rune('0'+turn)), request, Selection{FallbackState: "LEXICAL"})
		if err != nil {
			t.Fatal(err)
		}
		if manifest.EstimatedInputTokens > 32_000 {
			t.Fatalf("turn %d tokens=%d", turn, manifest.EstimatedInputTokens)
		}
		if len(prepared.PriorActions) >= len(request.PriorActions) && turn > 1 {
			t.Fatalf("turn %d was not compacted", turn)
		}
		estimates = append(estimates, manifest.EstimatedInputTokens)
	}
	if estimates[5]-estimates[1] > 1000 {
		t.Fatalf("context grew linearly: %v", estimates)
	}
}

func budgetSnapshot(t *testing.T, now time.Time) application.InvestigationSnapshot {
	t.Helper()
	request := domain.InvestigationRequest{ID: "inv-1", IncidentID: "incident-1", ClusterID: "cluster-a", Question: "why", RequestedBy: "actor", IdempotencyKey: "key", Scope: domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now}, SuccessCriteria: []string{"cite"}, Budget: domain.InvestigationBudget{MaxDecisions: 1, MaxToolCalls: 1, MaxFanOut: 1, MaxModelTokens: 1_000_000, MaxCostMicros: 1}, RequestedAt: now.Add(-time.Minute), Deadline: now.Add(time.Hour)}
	investigation, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	return application.InvestigationSnapshot{Investigation: investigation}
}

func TestCompactionPreservesFailuresForDistinctActionScopes(t *testing.T) {
	actions := []modelprovider.PriorAction{
		{ActionDigest: strings.Repeat("a", 64), ToolID: "gpu.health.v1", Outcome: "FAILED", Targets: []string{"node-1"}},
		{ActionDigest: strings.Repeat("b", 64), ToolID: "gpu.health.v1", Outcome: "FAILED", Targets: []string{"node-2"}},
	}
	if index := optionalPriorAction(actions); index != -1 {
		t.Fatalf("would forget failure on a distinct scope at index %d", index)
	}
}

func TestItemCapDoesNotDiscardUniqueFailedAction(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	sink := &manifestMemory{}
	manager, err := New(DefaultConfig(), JSONHeuristicEstimator{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	request := modelprovider.PlanningRequest{SchemaVersion: 1, InvestigationID: "inv-1", Question: "why"}
	request.PriorActions = append(request.PriorActions, modelprovider.PriorAction{ActionDigest: strings.Repeat("a", 64), ToolID: "gpu.health.v1", Outcome: "FAILED", Targets: []string{"node-1"}, Start: now.Add(-time.Hour), End: now})
	for range 256 {
		request.PriorActions = append(request.PriorActions, modelprovider.PriorAction{ActionDigest: strings.Repeat("b", 64), ToolID: "gpu.health.v1", Outcome: "SUCCEEDED", Targets: []string{"node-2"}, Start: now.Add(-time.Hour), End: now})
	}
	prepared, _, err := manager.PreparePlanning(t.Context(), budgetSnapshot(t, now), "call-1", request, Selection{})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range prepared.PriorActions {
		if action.Outcome == "FAILED" {
			return
		}
	}
	t.Fatal("item cap discarded the only failure on node-1")
}

func TestPriorActionCompactionReportsLossWithoutMutatingInput(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	sink := &manifestMemory{}
	manager, err := New(Config{MaximumInputTokens: 1024}, JSONHeuristicEstimator{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	request := modelprovider.PlanningRequest{SchemaVersion: 1, InvestigationID: "inv-1", Question: "why", PriorActionsOmitted: 2}
	for range 20 {
		request.PriorActions = append(request.PriorActions, modelprovider.PriorAction{ActionDigest: strings.Repeat("a", 64), ToolID: "gpu.health.v1", Outcome: "SUCCEEDED", Targets: []string{"node-1"}, Start: now.Add(-time.Hour), End: now})
	}
	before, _ := json.Marshal(request)
	prepared, manifest, err := manager.PreparePlanning(t.Context(), budgetSnapshot(t, now), "call-1", request, Selection{})
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.PriorActions) >= 20 || prepared.PriorActionsOmitted != 2+20-len(prepared.PriorActions) || manifest.ExclusionReasons["prior_action_compaction"] != 20-len(prepared.PriorActions) {
		t.Fatalf("loss not accounted: %+v %+v", prepared, manifest)
	}
	after, _ := json.Marshal(request)
	if string(before) != string(after) {
		t.Fatal("compaction mutated caller history")
	}
}

func TestTooManyRequiredActionScopesFailBeforeManifestWrite(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	sink := &manifestMemory{}
	manager, err := New(DefaultConfig(), JSONHeuristicEstimator{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	request := modelprovider.PlanningRequest{SchemaVersion: 1, InvestigationID: "inv-1", Question: "why"}
	for i := range 257 {
		request.PriorActions = append(request.PriorActions, modelprovider.PriorAction{ActionDigest: fmt.Sprintf("%064x", i+1), ToolID: "gpu.health.v1", Outcome: "FAILED", Targets: []string{"node-1"}, Start: now.Add(-time.Duration(i+1) * time.Second), End: now})
	}
	_, _, err = manager.PreparePlanning(t.Context(), budgetSnapshot(t, now), "call-1", request, Selection{})
	if !errors.Is(err, ErrRequiredContextExceeded) || len(sink.values) != 0 {
		t.Fatalf("required history loss admitted: err=%v manifests=%v", err, sink.values)
	}
}

func TestOnlySupersededFailureWithSameDigestIsOptional(t *testing.T) {
	for _, outcome := range []string{"FAILED", "NO_EVIDENCE", "REJECTED", "OUTCOME_UNKNOWN"} {
		first := modelprovider.PriorAction{ActionDigest: strings.Repeat("a", 64), ToolID: "tool.v1", Outcome: outcome}
		second := modelprovider.PriorAction{ActionDigest: strings.Repeat("b", 64), ToolID: "tool.v1", Outcome: outcome}
		if got := optionalPriorAction([]modelprovider.PriorAction{first, second}); got != -1 {
			t.Fatalf("%s forgot a distinct action", outcome)
		}
		if got := optionalPriorAction([]modelprovider.PriorAction{first, second, first}); got != 0 {
			t.Fatalf("%s selected %d, want superseded first", outcome, got)
		}
	}
}

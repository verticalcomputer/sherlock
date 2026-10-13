package investigation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/clustermemory"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationcontext"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"
	"github.com/verticalcomputer/sherlock/internal/modelprovider"
)

func TestFactorToolSchemasSendsCommonContractOnceWithoutWeakeningResponseSchema(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"targets":{"type":"array","items":{"type":"string"}},"start":{"type":"string"},"end":{"type":"string"}},"required":["targets","start","end"]}`)
	tools := []modelprovider.AvailableTool{{ToolID: "a.v1", ArgumentSchema: slices.Clone(schema)}, {ToolID: "b.v1", ArgumentSchema: slices.Clone(schema)}}
	factored, shared := factorToolSchemas(tools)
	if !json.Valid(shared) || len(factored[0].ArgumentSchema) != 0 || !slices.Equal(factored[0].EffectiveArgumentSchema(), schema) || !slices.Equal(factored[1].EffectiveArgumentSchema(), schema) {
		t.Fatalf("shared=%s factored=%+v", shared, factored)
	}
	encoded, err := json.Marshal(factored)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(encoded), "properties") != 0 {
		t.Fatalf("schemas repeated in provider payload: %s", encoded)
	}
}

func TestFactorToolSchemasMovesPerToolFanOutIntoToolMetadata(t *testing.T) {
	left := json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"targets":{"type":"array","maxItems":64,"items":{"type":"string"}},"start":{"type":"string"},"end":{"type":"string"}},"required":["targets","start","end"]}`)
	right := json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"targets":{"type":"array","maxItems":32,"items":{"type":"string"}},"start":{"type":"string"},"end":{"type":"string"}},"required":["targets","start","end"]}`)
	factored, shared := factorToolSchemas([]modelprovider.AvailableTool{{ToolID: "a.v1", ArgumentSchema: left, MaximumFanOut: 64}, {ToolID: "b.v1", ArgumentSchema: right, MaximumFanOut: 32}})
	if len(shared) == 0 || strings.Contains(string(shared), "maxItems") || factored[0].MaximumFanOut != 64 || factored[1].MaximumFanOut != 32 || !slices.Equal(factored[1].EffectiveArgumentSchema(), right) {
		t.Fatalf("shared=%s factored=%+v", shared, factored)
	}
}

func TestOrchestratorValidatesModelActionAndAuditsSafeMetadata(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	provider := fakePlanningProvider(t, json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T09:00:00Z","end":"2026-08-20T10:00:00Z"}`))
	audits := &auditMemory{}
	orchestrator := newTestOrchestrator(t, provider, audits, &duplicateMemory{}, now)
	decision, err := orchestrator.Decide(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action == nil || decision.Action.ToolID != "gpu.xid_events.v1" || decision.Action.Privileged || decision.Action.FanOut != 1 || decision.Action.Digest == (domain.SHA256{}) {
		t.Fatalf("decision=%+v", decision)
	}
	if len(audits.values) != 1 || audits.values[0].Outcome != application.ModelCallSucceeded || audits.values[0].InputTokens != 7 || audits.values[0].OutputTokens != 3 {
		t.Fatalf("audits=%+v", audits.values)
	}
	calls := provider.PlanningCalls()
	if len(calls) != 1 || len(calls[0].AvailableTools) != 1 || !calls[0].AvailableTools[0].ReadOnly {
		t.Fatalf("model tools=%+v", calls)
	}
}

func TestOrchestratorSequentializesMultiActionPlanAtPriorityOne(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	priorityOne := json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T09:00:00Z","end":"2026-08-20T09:30:00Z"}`)
	priorityTwo := json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T09:30:00Z","end":"2026-08-20T10:00:00Z"}`)
	provider, err := modelprovider.NewFakeProvider([]modelprovider.PlanningStep{{Result: modelprovider.PlanningResult{Response: modelprovider.PlanningResponse{
		SchemaVersion: 1, StateSummary: "Collect two observations sequentially.",
		Actions: []modelprovider.PlannedAction{
			{ToolID: "gpu.xid_events.v1", Arguments: priorityTwo, Purpose: "Second observation.", ExpectedInformation: "Later bounded evidence.", Priority: 2},
			{ToolID: "gpu.xid_events.v1", Arguments: priorityOne, Purpose: "First observation.", ExpectedInformation: "Earlier bounded evidence.", Priority: 1},
		},
	}, Metadata: modelprovider.CallMetadata{Provider: "fixture", Model: "planner-v1", ConfigurationID: "config-v1", InputTokens: 7, OutputTokens: 3, CostMicros: 2, Latency: time.Millisecond, Outcome: modelprovider.OutcomeSucceeded}}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	audits := &auditMemory{}
	decision, err := newTestOrchestrator(t, provider, audits, &duplicateMemory{}, now).Decide(context.Background(), planningSnapshot(t, now))
	if err != nil || decision.Action == nil || !decision.Action.Start.Equal(now.Add(-time.Hour)) || !decision.Action.End.Equal(now.Add(-30*time.Minute)) {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	if len(audits.values) != 1 || audits.values[0].Outcome != application.ModelCallSucceeded {
		t.Fatalf("audits=%+v", audits.values)
	}
}

func TestOrchestratorRejectsInjectedOrDuplicateToolCalls(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	// An injected field is rejected at the argument boundary on every attempt, so
	// the bounded replan resolves the transition safely and never executes it.
	injectedArguments := json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T09:00:00Z","end":"2026-08-20T10:00:00Z","executable":"/bin/sh"}`)
	injected := fakePlanningProvider(t, injectedArguments, injectedArguments)
	injectedAudits := &auditMemory{}
	injectedDecision, err := newTestOrchestrator(t, injected, injectedAudits, &duplicateMemory{}, now).Decide(context.Background(), snapshot)
	if err != nil || injectedDecision.Action != nil || !injectedDecision.Stop || injectedDecision.Reason != domain.StopPolicyExhausted {
		t.Fatalf("unknown executable field reached the controller: decision=%+v err=%v", injectedDecision, err)
	}
	for _, audit := range injectedAudits.values {
		if audit.Outcome != application.ModelCallRejected || audit.ReasonCode != "TOOL_CALL_REJECTED" {
			t.Fatalf("audit=%+v", audit)
		}
	}
	arguments := json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T09:00:00Z","end":"2026-08-20T10:00:00Z"}`)
	duplicate := fakePlanningProvider(t, arguments, arguments)
	audits := &auditMemory{}
	decision, err := newTestOrchestrator(t, duplicate, audits, &duplicateMemory{seen: true}, now).Decide(context.Background(), snapshot)
	if err != nil || !decision.Stop || decision.Outcome != domain.InvestigationPartial || decision.Reason != domain.StopNoUsefulAction || decision.Action != nil {
		t.Fatalf("duplicate decision=%+v error=%v", decision, err)
	}
	// The replan is bounded: a planner that repeats itself stops the transition
	// instead of looping, and every rejected call stays attributed.
	calls := duplicate.PlanningCalls()
	if len(calls) != 2 || !strings.Contains(calls[1].StateSummary, "gpu.xid_events.v1") || !strings.Contains(calls[1].StateSummary, "n1") {
		t.Fatalf("replan calls=%+v", calls)
	}
	if decision.ModelTokens != 20 || decision.CostMicros != 4 || len(audits.values) != 2 {
		t.Fatalf("duplicate spend=%+v audits=%+v", decision, audits.values)
	}
	for _, audit := range audits.values {
		if audit.Outcome != application.ModelCallRejected || audit.ReasonCode != "DUPLICATE_TOOL_CALL" {
			t.Fatalf("audit=%+v", audit)
		}
	}
}

func TestDuplicateActionReplansOnceAndAdmitsANovelObservation(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	repeated := json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T09:00:00Z","end":"2026-08-20T10:00:00Z"}`)
	novel := json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T09:00:00Z","end":"2026-08-20T09:30:00Z"}`)
	seen, err := seenDigest(t, snapshot, repeated)
	if err != nil {
		t.Fatal(err)
	}
	provider := fakePlanningProvider(t, repeated, novel)
	decision, err := newTestOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{digests: map[domain.SHA256]bool{seen: true}}, now).Decide(context.Background(), snapshot)
	if err != nil || decision.Stop || decision.Action == nil || !decision.Action.End.Equal(now.Add(-30*time.Minute)) {
		t.Fatalf("replanned decision=%+v err=%v", decision, err)
	}
	// Both planning calls are charged to the investigation budget.
	if decision.ModelTokens != 20 || decision.CostMicros != 4 || len(provider.PlanningCalls()) != 2 {
		t.Fatalf("replanned spend=%+v calls=%d", decision, len(provider.PlanningCalls()))
	}
}

// seenDigest resolves the canonical duplicate digest the controller computes for
// an already-observed invocation, without reimplementing the catalog rules.
func seenDigest(t *testing.T, snapshot application.InvestigationSnapshot, arguments json.RawMessage) (domain.SHA256, error) {
	t.Helper()
	recorder := &digestRecorder{}
	provider := fakePlanningProvider(t, arguments)
	if _, err := newTestOrchestrator(t, provider, &auditMemory{}, recorder, time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)).Decide(context.Background(), snapshot); err != nil {
		return domain.SHA256{}, err
	}
	if len(recorder.digests) == 0 {
		return domain.SHA256{}, fmt.Errorf("no candidate digest was checked")
	}
	return recorder.digests[0], nil
}

type digestRecorder struct{ digests []domain.SHA256 }

func (recorder *digestRecorder) HasInvestigationActionDigest(_ context.Context, _ domain.InvestigationID, digest domain.SHA256) (bool, error) {
	recorder.digests = append(recorder.digests, digest)
	return false, nil
}

// A planner sees the investigation scope but not every reviewed per-tool bound.
// An over-wide window must not fail the transition: the controller states the
// enforced limit and the corrected call is admitted.
// A planner with nothing new to observe and a planner that keeps proposing
// inadmissible work are different operational problems, so they must not share
// a terminal reason.
// POLICY_EXHAUSTED is a controller finding about the tool catalog, so no model
// stop reason may map onto it and let a planner label its own run that way.
func TestNoModelStopReasonMapsToPolicyExhaustion(t *testing.T) {
	for _, reason := range []modelprovider.PlanningStopReason{
		modelprovider.StopSuccessCriteriaMet, modelprovider.StopNoUsefulAction,
		modelprovider.StopAccessUnavailable, modelprovider.StopSourceUnavailable,
		modelprovider.StopBudgetExceeded, modelprovider.PlanningStopReason("UNRECOGNIZED"),
	} {
		if _, mapped := mapStop(reason); mapped == domain.StopPolicyExhausted {
			t.Fatalf("model stop reason %q reached POLICY_EXHAUSTED", reason)
		}
	}
	if err := domain.StopPolicyExhausted.Validate(); err != nil {
		t.Fatalf("controller stop reason is not durable: %v", err)
	}
}

// Real planning calls cost tens of thousands of tokens, far more than the
// abstract reserve. A replan must be affordable at the price the previous
// attempt actually charged, not at a fraction of the total budget.
func TestReplanIsRefusedWhenAnotherAttemptIsUnaffordable(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	request := snapshot.Investigation.Request()
	// Enough to admit the first attempt and clear the opening reserve, but not
	// enough to leave that reserve intact for a second attempt.
	request.Budget.MaxModelTokens = 130
	investigation, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	if investigation, err = investigation.BeginPlanning(now); err != nil {
		t.Fatal(err)
	}
	snapshot.Investigation = investigation
	arguments := json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T09:00:00Z","end":"2026-08-20T10:00:00Z"}`)
	provider := fakePlanningProvider(t, arguments, arguments)
	decision, err := newTestOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{seen: true}, now).Decide(context.Background(), snapshot)
	if err != nil || !decision.Stop || decision.Reason != domain.StopNoUsefulAction {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	// The second planning call must never have been made.
	if len(provider.PlanningCalls()) != 1 || decision.ModelTokens != 10 {
		t.Fatalf("unaffordable replan was attempted: calls=%d decision=%+v", len(provider.PlanningCalls()), decision)
	}
}

func TestExhaustedRejectionsReportDistinctTerminalReasons(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	inScope := json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T09:00:00Z","end":"2026-08-20T10:00:00Z"}`)
	repeated := newTestOrchestrator(t, fakePlanningProvider(t, inScope, inScope), &auditMemory{}, &duplicateMemory{seen: true}, now)
	repeatedDecision, err := repeated.Decide(context.Background(), snapshot)
	if err != nil || repeatedDecision.Reason != domain.StopNoUsefulAction {
		t.Fatalf("repeated decision=%+v err=%v", repeatedDecision, err)
	}
	// The same arguments are inadmissible once the reviewed window is narrower.
	inadmissible := newTestOrchestratorWithWindow(t, fakePlanningProvider(t, inScope, inScope), &auditMemory{}, &duplicateMemory{}, now, 15*time.Minute)
	inadmissibleDecision, err := inadmissible.Decide(context.Background(), snapshot)
	if err != nil || inadmissibleDecision.Reason != domain.StopPolicyExhausted || !inadmissibleDecision.Stop || inadmissibleDecision.Outcome != domain.InvestigationPartial {
		t.Fatalf("inadmissible decision=%+v err=%v", inadmissibleDecision, err)
	}
}

func TestOverWideWindowIsReplannedWithTheEnforcedToolBound(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	tooWide := json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T09:00:00Z","end":"2026-08-20T10:00:00Z"}`)
	withinBound := json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T09:50:00Z","end":"2026-08-20T10:00:00Z"}`)
	provider := fakePlanningProvider(t, tooWide, withinBound)
	audits := &auditMemory{}
	decision, err := newTestOrchestratorWithWindow(t, provider, audits, &duplicateMemory{}, now, 15*time.Minute).Decide(context.Background(), snapshot)
	if err != nil || decision.Stop || decision.Action == nil || !decision.Action.Start.Equal(now.Add(-10*time.Minute)) {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	calls := provider.PlanningCalls()
	if len(calls) != 2 || !strings.Contains(calls[1].StateSummary, "15m0s") || !strings.Contains(calls[1].StateSummary, "gpu.xid_events.v1") {
		t.Fatalf("replan guidance did not state the enforced window: %+v", calls)
	}
	if len(audits.values) != 2 || audits.values[0].Outcome != application.ModelCallRejected || audits.values[0].ReasonCode != "TOOL_CALL_REJECTED" || audits.values[1].Outcome != application.ModelCallSucceeded {
		t.Fatalf("audits=%+v", audits.values)
	}
	// Both attempts are charged even though only the second executed.
	if decision.ModelTokens != 20 || decision.CostMicros != 4 {
		t.Fatalf("spend=%+v", decision)
	}
}

// The reviewed window is invisible unless the planner is told, so the advertised
// tool description must carry the bound the catalog actually enforces.
func TestAvailableToolDescriptionStatesTheEnforcedWindow(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	provider := fakePlanningProvider(t, json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T09:50:00Z","end":"2026-08-20T10:00:00Z"}`))
	if _, err := newTestOrchestratorWithWindow(t, provider, &auditMemory{}, &duplicateMemory{}, now, 15*time.Minute).Decide(context.Background(), planningSnapshot(t, now)); err != nil {
		t.Fatal(err)
	}
	calls := provider.PlanningCalls()
	if len(calls) != 1 || len(calls[0].AvailableTools) != 1 || !strings.Contains(calls[0].AvailableTools[0].Description, "at most 15m0s") {
		t.Fatalf("tools=%+v", calls)
	}
}

func TestOrchestratorSuppliesPriorActionsAndAllocatesHypothesisIDs(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	digest := domain.ChecksumSHA256([]byte("prior-action"))
	snapshot.PriorActions = []application.InvestigationActionHistory{{Digest: digest, ToolID: "gpu.xid_events.v1", Outcome: "SUCCEEDED", Targets: []string{"n1"}, Start: now.Add(-time.Hour), End: now}}
	arguments := json.RawMessage(`{"targets":["n1"],"start":"2026-08-21T09:00:00Z","end":"2026-08-21T10:00:00Z"}`)
	provider, err := modelprovider.NewFakeProvider([]modelprovider.PlanningStep{{Result: modelprovider.PlanningResult{Response: modelprovider.PlanningResponse{SchemaVersion: 1, StateSummary: "Preserve uncertainty.", HypothesisUpdates: []modelprovider.HypothesisUpdate{{HypothesisID: modelprovider.NewHypothesisID, Statement: "The event onset remains unresolved.", Status: "UNRESOLVED", Confidence: 0.2}}, Actions: []modelprovider.PlannedAction{{ToolID: "gpu.xid_events.v1", Arguments: arguments, Purpose: "Check a bounded source.", ExpectedInformation: "Timestamped evidence.", Priority: 1}}}, Metadata: modelprovider.CallMetadata{Provider: "fixture", Model: "planner-v1", ConfigurationID: "config-v1", InputTokens: 7, OutputTokens: 3, CostMicros: 2, Latency: time.Millisecond, Outcome: modelprovider.OutcomeSucceeded}}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := newTestOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now).Decide(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	calls := provider.PlanningCalls()
	if len(calls) != 1 || len(calls[0].PriorActions) != 1 || calls[0].PriorActions[0].ActionDigest != digest.String() || len(calls[0].PriorActions[0].EvidenceIDs) != 0 {
		t.Fatalf("prior actions=%+v", calls)
	}
	if len(decision.Hypotheses) != 1 || decision.Hypotheses[0].ID != "hypothesis-id-1" || decision.Hypotheses[0].Version != 1 {
		t.Fatalf("server-owned hypotheses=%+v", decision.Hypotheses)
	}
}

func TestDuplicateActionPreservesValidatedHypothesisUpdates(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	arguments := json.RawMessage(`{"targets":["n1"],"start":"2026-08-21T09:00:00Z","end":"2026-08-21T10:00:00Z"}`)
	// The bounded replan repeats the turn, so the final rejected decision must
	// still carry the validated hypothesis updates the model produced.
	provider, err := modelprovider.NewFakeProvider([]modelprovider.PlanningStep{{Result: modelprovider.PlanningResult{Response: modelprovider.PlanningResponse{SchemaVersion: 1, StateSummary: "Preserve uncertainty.", HypothesisUpdates: []modelprovider.HypothesisUpdate{{HypothesisID: modelprovider.NewHypothesisID, Statement: "The event onset remains unresolved.", Status: "UNRESOLVED", Confidence: 0.2}}, Actions: []modelprovider.PlannedAction{{ToolID: "gpu.xid_events.v1", Arguments: arguments, Purpose: "Check XIDs.", ExpectedInformation: "Timestamped evidence.", Priority: 1}}}, Metadata: modelprovider.CallMetadata{Provider: "fixture", Model: "planner-v1", ConfigurationID: "config-v1", InputTokens: 7, OutputTokens: 3, CostMicros: 2, Latency: time.Millisecond, Outcome: modelprovider.OutcomeSucceeded}}}, {Result: modelprovider.PlanningResult{Response: modelprovider.PlanningResponse{SchemaVersion: 1, StateSummary: "Preserve uncertainty.", HypothesisUpdates: []modelprovider.HypothesisUpdate{{HypothesisID: modelprovider.NewHypothesisID, Statement: "The event onset remains unresolved.", Status: "UNRESOLVED", Confidence: 0.2}}, Actions: []modelprovider.PlannedAction{{ToolID: "gpu.xid_events.v1", Arguments: arguments, Purpose: "Check XIDs.", ExpectedInformation: "Timestamped evidence.", Priority: 1}}}, Metadata: modelprovider.CallMetadata{Provider: "fixture", Model: "planner-v1", ConfigurationID: "config-v1", InputTokens: 7, OutputTokens: 3, CostMicros: 2, Latency: time.Millisecond, Outcome: modelprovider.OutcomeSucceeded}}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := newTestOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{seen: true}, now).Decide(context.Background(), planningSnapshot(t, now))
	if err != nil || !decision.Stop || decision.Reason != domain.StopNoUsefulAction || len(decision.Hypotheses) != 1 {
		t.Fatalf("duplicate decision=%+v err=%v", decision, err)
	}
}

func TestM94RecordedReplaySelectsDistinctEvidenceClasses(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	arguments := json.RawMessage(`{"targets":["n1"],"start":"2026-08-21T09:00:00Z","end":"2026-08-21T10:00:00Z"}`)
	metadata := modelprovider.CallMetadata{Provider: "fixture", Model: "recorded-m94-v1", ConfigurationID: "m94-replay-v1", InputTokens: 10, OutputTokens: 5, CostMicros: 3, Latency: time.Millisecond, Outcome: modelprovider.OutcomeSucceeded}
	provider, err := modelprovider.NewFakeProvider([]modelprovider.PlanningStep{
		{Result: modelprovider.PlanningResult{Response: modelprovider.PlanningResponse{SchemaVersion: 1, StateSummary: "Check GPU health first.", Actions: []modelprovider.PlannedAction{{ToolID: "node.gpu_snapshot.v1", Arguments: arguments, Purpose: "Check bounded GPU health evidence.", ExpectedInformation: "GPU health observations.", Priority: 1}}}, Metadata: metadata}},
		{Result: modelprovider.PlanningResult{Response: modelprovider.PlanningResponse{SchemaVersion: 1, StateSummary: "Correlate the GPU evidence with scheduler state.", Actions: []modelprovider.PlannedAction{{ToolID: "cluster.scheduler_snapshot.v1", Arguments: arguments, Purpose: "Check bounded scheduler evidence.", ExpectedInformation: "Scheduler state for the same node.", Priority: 1}}}, Metadata: metadata}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := investigationtools.NewCatalog([]investigationtools.Definition{
		{SchemaVersion: 1, ID: "node.gpu_snapshot.v1", Description: "Read committed GPU health evidence.", Operation: investigationtools.OperationReadOnly, AllowedClusters: []domain.ClusterID{"cluster-a"}, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"gpu.health.evidence.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{"node"}, MaxTargets: 64, MaxWindow: time.Hour}, Timeout: time.Second, CostWeight: 1},
		{SchemaVersion: 1, ID: "cluster.scheduler_snapshot.v1", Description: "Read committed scheduler evidence.", Operation: investigationtools.OperationReadOnly, AllowedClusters: []domain.ClusterID{"cluster-a"}, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"scheduler.evidence.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{"node"}, MaxTargets: 64, MaxWindow: time.Hour}, Timeout: time.Second, CostWeight: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	builder, _ := investigationcontext.NewBuilder(investigationcontext.DefaultLimits())
	audits := &auditMemory{}
	ids := &sequenceIDs{}
	orchestrator, err := NewOrchestrator(provider, catalog, StaticAuthority{Actor: []auth.Capability{auth.CapabilityInvestigationsRun}, Cluster: []investigationtools.ClusterCapability{"gpu.health.evidence.read", "scheduler.evidence.read"}}, &duplicateMemory{}, LedgerContextSource{}, builder, audits, fixedClock{now}, ids, Config{Provider: "fixture", Model: "recorded-m94-v1", ModelConfigVersion: "m94-replay-v1", PlanningPrompt: "planning-v2", SynthesisPrompt: "synthesis-v2", ToolSchemaVersion: "catalog-v1", ModelCallReservationTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	firstSnapshot := planningSnapshot(t, now)
	first, err := orchestrator.Decide(context.Background(), firstSnapshot)
	if err != nil || first.Action == nil || first.Action.ToolID != "node.gpu_snapshot.v1" {
		t.Fatalf("first decision=%+v err=%v", first, err)
	}
	request := firstSnapshot.Investigation.Request()
	secondInvestigation, err := domain.ReconstituteInvestigation(request, domain.InvestigationPlanning, "", domain.InvestigationBudgetUsage{Decisions: 1, ToolCalls: 1, FanOut: 1, ModelTokens: first.ModelTokens, CostMicros: first.CostMicros}, nil, 7)
	if err != nil {
		t.Fatal(err)
	}
	evidence := domain.InvestigationEvidence{EvidenceID: "evidence-gpu-health", InvestigationID: request.ID, ClusterID: request.ClusterID, EntityIDs: []string{"n1"}, Status: domain.EvidenceComplete, ObservedStart: request.Scope.Start, ObservedEnd: request.Scope.End, RecordedAt: now}
	ledger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{evidence}, secondInvestigation)
	if err != nil {
		t.Fatal(err)
	}
	secondSnapshot := application.InvestigationSnapshot{Investigation: secondInvestigation, Evidence: ledger, PriorActions: []application.InvestigationActionHistory{{Digest: first.Action.Digest, ToolID: first.Action.ToolID, Outcome: "SUCCEEDED", Targets: []string{"n1"}, Start: request.Scope.Start, End: request.Scope.End, EvidenceIDs: []domain.EvidenceID{evidence.EvidenceID}}}}
	second, err := orchestrator.Decide(context.Background(), secondSnapshot)
	if err != nil || second.Action == nil || second.Action.ToolID != "cluster.scheduler_snapshot.v1" || second.Action.Digest == first.Action.Digest {
		t.Fatalf("second decision=%+v err=%v", second, err)
	}
	calls := provider.PlanningCalls()
	if len(calls) != 2 || len(calls[1].PriorActions) != 1 || calls[1].PriorActions[0].ToolID != "node.gpu_snapshot.v1" || len(calls[1].Evidence) != 1 {
		t.Fatalf("recorded replay calls=%+v", calls)
	}
	for _, call := range calls {
		for _, action := range call.PriorActions {
			if action.ToolID == "evidence.lookup.v1" {
				t.Fatal("recorded replay fell back to generic lookup")
			}
		}
	}
}

func TestOrchestratorStopsBeforeProviderWhenModelBudgetIsTooSmall(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	request := snapshot.Investigation.Request()
	request.Budget.MaxModelTokens = 127
	investigation, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	investigation, err = investigation.BeginPlanning(now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Investigation = investigation
	provider := fakePlanningProvider(t, json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T09:00:00Z","end":"2026-08-20T10:00:00Z"}`))
	decision, err := newTestOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now).Decide(context.Background(), snapshot)
	if err != nil || !decision.Stop || decision.Reason != domain.StopBudgetExceeded || len(provider.PlanningCalls()) != 0 {
		t.Fatalf("decision=%+v calls=%d error=%v", decision, len(provider.PlanningCalls()), err)
	}
}

func TestEnabledMemoryIsUntrustedCitedAndShadowMemoryIsNotAdmitted(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	entry := clustermemory.Entry{ID: "memory-1", ClusterID: "cluster-a", Trust: clustermemory.TrustValidatedFinding, SourceInvestigationID: "prior-1", EntityIDs: []string{"n1"}, Summary: "Earlier XID evidence suggested a GPU reset.", ValidFrom: now.Add(-time.Hour), Freshness: "CURRENT", Citations: []clustermemory.Citation{{EvidenceID: "evidence-prior", Relationship: "EVIDENCE"}}}
	for _, test := range []struct {
		name string
		mode clustermemory.Mode
		want int
	}{{"enabled", clustermemory.ModeEnabled, 1}, {"shadow", clustermemory.ModeShadow, 0}} {
		t.Run(test.name, func(t *testing.T) {
			provider := fakePlanningProvider(t, json.RawMessage(`{"targets":["n1"],"start":"2026-08-21T09:00:00Z","end":"2026-08-21T10:00:00Z"}`))
			orchestrator := newTestOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now)
			if err := orchestrator.ConfigureMemory(memoryReader{result: clustermemory.Result{Candidates: 1, Entries: []clustermemory.Entry{entry}, IndexVersion: "lexical-v1", Fallback: "LEXICAL"}}, test.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := orchestrator.Decide(t.Context(), planningSnapshot(t, now)); err != nil {
				t.Fatal(err)
			}
			calls := provider.PlanningCalls()
			if len(calls) != 1 || len(calls[0].Memory) != test.want {
				t.Fatalf("memory=%+v", calls)
			}
			if test.want == 1 && (calls[0].Memory[0].Statement != entry.Summary || calls[0].Memory[0].EvidenceIDs[0] != "evidence-prior") {
				t.Fatalf("memory=%+v", calls[0].Memory)
			}
		})
	}
}

func TestMemoryFailureFallsBackWithoutAccessFailure(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	provider := fakePlanningProvider(t, json.RawMessage(`{"targets":["n1"],"start":"2026-08-21T09:00:00Z","end":"2026-08-21T10:00:00Z"}`))
	orchestrator := newTestOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now)
	if err := orchestrator.ConfigureMemory(memoryReader{err: fmt.Errorf("index unavailable")}, clustermemory.ModeEnabled); err != nil {
		t.Fatal(err)
	}
	decision, err := orchestrator.Decide(t.Context(), planningSnapshot(t, now))
	if err != nil || decision.Action == nil {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
}

func TestOrchestratorStopsBeforeProviderWhenLiveRunHasOnlyFiveThousandTokensLeft(t *testing.T) {
	now := time.Date(2026, 8, 21, 9, 31, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	request := snapshot.Investigation.Request()
	request.Budget.MaxModelTokens = 60_000
	request.Budget.MaxCostMicros = 2_000_000
	investigation, err := domain.ReconstituteInvestigation(request, domain.InvestigationPlanning, "", domain.InvestigationBudgetUsage{Decisions: 2, ToolCalls: 2, FanOut: 2, ModelTokens: 54_922, CostMicros: 361_585}, nil, 14)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Investigation = investigation
	provider := fakePlanningProvider(t, json.RawMessage(`{"targets":["n1"],"start":"2026-08-21T08:31:00Z","end":"2026-08-21T09:31:00Z"}`))
	decision, err := newTestOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now).Decide(context.Background(), snapshot)
	if err != nil || !decision.Stop || decision.Reason != domain.StopBudgetExceeded || decision.ModelTokens != 0 || len(provider.PlanningCalls()) != 0 {
		t.Fatalf("decision=%+v calls=%d error=%v", decision, len(provider.PlanningCalls()), err)
	}
}

func TestOrchestratorContinuesWithNextUnseenFanOutBatch(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	request := snapshot.Investigation.Request()
	request.Scope.EntityIDs = []string{"n1", "n2", "n3", "n4"}
	request.Budget.MaxFanOut = 2
	investigation, err := domain.ReconstituteInvestigation(request, domain.InvestigationPlanning, "", domain.InvestigationBudgetUsage{Decisions: 1, ToolCalls: 1, FanOut: 2}, nil, 7)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Investigation = investigation
	arguments := json.RawMessage(`{"targets":["n4","n2","n3","n1"],"start":"2026-08-21T09:00:00Z","end":"2026-08-21T10:00:00Z"}`)
	duplicates := &duplicateMemory{digests: map[domain.SHA256]bool{}}
	firstProvider := fakePlanningProvider(t, arguments)
	first, err := newTestOrchestrator(t, firstProvider, &auditMemory{}, duplicates, now).Decide(context.Background(), snapshot)
	if err != nil || first.Action == nil || !slices.Equal(first.Action.Targets, []string{"n1", "n2"}) || first.Stop {
		t.Fatalf("first decision=%+v error=%v", first, err)
	}
	duplicates.digests[first.Action.Digest] = true
	secondProvider := fakePlanningProvider(t, arguments)
	second, err := newTestOrchestrator(t, secondProvider, &auditMemory{}, duplicates, now).Decide(context.Background(), snapshot)
	if err != nil || second.Action == nil || !slices.Equal(second.Action.Targets, []string{"n3", "n4"}) || second.Stop {
		t.Fatalf("second decision=%+v error=%v", second, err)
	}
	if secondProvider.PlanningCalls()[0].RemainingBudget.FanOut != 2 {
		t.Fatalf("remaining fan-out=%d", secondProvider.PlanningCalls()[0].RemainingBudget.FanOut)
	}
}

func TestOrchestratorDoesNotRebillAuditedCallWithoutDurableTransition(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	provider := fakePlanningProvider(t, json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T09:00:00Z","end":"2026-08-20T10:00:00Z"}`))
	audits := &auditMemory{prior: true}
	if _, err := newTestOrchestrator(t, provider, audits, &duplicateMemory{}, now).Decide(context.Background(), snapshot); err == nil {
		t.Fatal("previously audited call was sent to the provider again")
	}
	if len(provider.PlanningCalls()) != 0 {
		t.Fatalf("provider calls=%d", len(provider.PlanningCalls()))
	}
}

func TestInterruptedProviderCallLeavesUncertainReservation(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	audits := &auditMemory{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newTestOrchestrator(t, canceledProvider{}, audits, &duplicateMemory{}, now).Decide(ctx, planningSnapshot(t, now))
	if err == nil {
		t.Fatal("interrupted provider call succeeded")
	}
	if len(audits.reserved) != 1 || len(audits.completed) != 0 || len(audits.values) != 0 {
		t.Fatalf("interrupted reservation was finalized: reserved=%v completed=%v audits=%v", audits.reserved, audits.completed, audits.values)
	}
}

type canceledProvider struct{}

func (canceledProvider) Plan(ctx context.Context, _ modelprovider.PlanningRequest) (modelprovider.PlanningResult, error) {
	return modelprovider.PlanningResult{}, ctx.Err()
}
func (canceledProvider) Synthesize(ctx context.Context, _ modelprovider.SynthesisRequest) (modelprovider.SynthesisResult, error) {
	return modelprovider.SynthesisResult{}, ctx.Err()
}

func TestSafeModelFailureReasonUsesOnlyProviderClassification(t *testing.T) {
	if got := safeModelFailureReason(classifiedTestError{}); got != "INVALID_RESPONSE_SEMANTIC_VALIDATION" {
		t.Fatalf("reason=%q", got)
	}
	if got := safeModelFailureReason(fmt.Errorf("wrapped private detail")); got != "PROVIDER_ERROR" {
		t.Fatalf("fallback=%q", got)
	}
}

func TestOrchestratorPersistsSafeProviderFailureStage(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	provider, err := modelprovider.NewFakeProvider([]modelprovider.PlanningStep{{Err: classifiedTestError{}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	audits := &auditMemory{}
	if _, err := newTestOrchestrator(t, provider, audits, &duplicateMemory{}, now).Decide(context.Background(), planningSnapshot(t, now)); err == nil {
		t.Fatal("provider failure was accepted")
	}
	if len(audits.values) != 1 || audits.values[0].Outcome != application.ModelCallFailed || audits.values[0].ReasonCode != "INVALID_RESPONSE_SEMANTIC_VALIDATION" {
		t.Fatalf("audits=%+v", audits.values)
	}
}

func TestSynthesisSemanticFailureUsesCitedFallbackAndAuditsPayloadEvidence(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	entry := domain.InvestigationEvidence{EvidenceID: "evidence-1", InvestigationID: snapshot.Investigation.Request().ID, ClusterID: snapshot.Investigation.Request().ClusterID, EntityIDs: []string{"n1"}, Status: domain.EvidencePartial, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now}
	ledger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{entry}, snapshot.Investigation)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Evidence = ledger
	snapshot.RequestedOutcome = domain.InvestigationCompleted
	provider, err := modelprovider.NewFakeProvider(nil, []modelprovider.SynthesisStep{{Err: tracedSemanticError{}}})
	if err != nil {
		t.Fatal(err)
	}
	audits := &auditMemory{}
	payloads := &payloadEvidenceMemory{}
	result, err := newTestOrchestrator(t, provider, audits, &duplicateMemory{}, now, payloads).Synthesize(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if result.Disposition != application.SynthesisSafeFallback || len(result.Findings) != 2 || len(result.Findings[0].EvidenceIDs) != 1 || result.Findings[0].EvidenceIDs[0] != "evidence-1" || result.Findings[1].Kind != domain.FindingRecommendation {
		t.Fatalf("fallback findings=%+v", result.Findings)
	}
	if result.ModelTokens != 15 || result.CostMicros != 3 || len(payloads.values) != 2 {
		t.Fatalf("result=%+v payloads=%+v", result, payloads.values)
	}
	if len(audits.values) != 1 || audits.values[0].Outcome != application.ModelCallRejected || audits.values[0].ReasonCode != "INVALID_RESPONSE_SEMANTIC_VALIDATION" || audits.values[0].InputEvidenceID == "" || audits.values[0].OutputEvidenceID == "" {
		t.Fatalf("audit=%+v", audits.values)
	}
}

func TestSynthesisCompletionEligibilityRequiresFullCoverageAndReportShape(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	request := modelprovider.SynthesisRequest{
		Scope:    modelprovider.Scope{EntityIDs: []string{"n1"}},
		Evidence: []modelprovider.EvidenceContext{{EvidenceID: "evidence-1"}},
		Coverage: modelprovider.Coverage{TargetsChecked: []string{"n1"}, ExpectedTargets: []modelprovider.CoverageTarget{{Kind: "NODE", ID: "n1"}}, ObservedTargets: []modelprovider.CoverageTarget{{Kind: "NODE", ID: "n1"}}, TimeComplete: true, RequestedTimeComplete: true, EvidenceSelected: 1, Sources: []string{"dcgm"}},
	}
	response := modelprovider.SynthesisResponse{
		WhatIsHappening:    []modelprovider.CitedStatement{{Statement: "XID 94 is visible.", EvidenceIDs: []string{"evidence-1"}}},
		Timeline:           []modelprovider.TimelineEntry{{ObservedAt: now, Statement: "XID 94 observed.", EvidenceIDs: []string{"evidence-1"}}},
		LikelyExplanations: []modelprovider.Explanation{{Statement: "The gauge may be retained.", Confidence: .8, EvidenceIDs: []string{"evidence-1"}}},
		WhatRemainsUnknown: []modelprovider.CitedStatement{{Statement: "Onset is unknown.", EvidenceIDs: []string{"evidence-1"}}},
		SuggestedNextSteps: []modelprovider.CitedStatement{{Statement: "Inspect bounded logs."}},
		Coverage:           []modelprovider.CitedStatement{{Statement: "n1 was checked.", EvidenceIDs: []string{"evidence-1"}}},
	}
	findings := []domain.Finding{
		{Kind: domain.FindingObservation, EvidenceIDs: []domain.EvidenceID{"evidence-1"}},
		{Kind: domain.FindingHypothesis, EvidenceIDs: []domain.EvidenceID{"evidence-1"}},
		{Kind: domain.FindingRecommendation},
	}
	if !synthesisCompletionEligible(request, response, findings) {
		t.Fatal("complete, fully covered report was not eligible")
	}
	// Observed density is not the gate: a fully interrogated scope stays eligible
	// when sparse event evidence produced no values across every instant.
	request.Coverage.TimeComplete = false
	if !synthesisCompletionEligible(request, response, findings) {
		t.Fatal("fully interrogated scope was not eligible on sparse evidence")
	}
	request.Coverage.RequestedTimeComplete = false
	if synthesisCompletionEligible(request, response, findings) {
		t.Fatal("an un-interrogated period was eligible for completion")
	}
	request.Coverage.TimeComplete, request.Coverage.RequestedTimeComplete = true, true
	request.Coverage.TargetsMissed = []string{"n1"}
	request.Coverage.TargetsChecked = nil
	if synthesisCompletionEligible(request, response, findings) {
		t.Fatal("missed target was eligible for completion")
	}
	request.Coverage.TargetsMissed = nil
	request.Coverage.TargetsChecked = []string{"n1"}
	request.Coverage.ToolFailures = []string{"source unavailable"}
	if synthesisCompletionEligible(request, response, findings) {
		t.Fatal("tool failure was eligible for completion")
	}
	request.Coverage.ToolFailures = nil
	response.Timeline = nil
	if synthesisCompletionEligible(request, response, findings) {
		t.Fatal("incomplete report shape was eligible for completion")
	}
}

// Verified absence is an answer. Two adjacent NO_DATA lookups fully interrogate
// the scope even though they observe no values anywhere in it, which is the
// case an observed-density gate can never credit.
func TestModelCoverageCreditsInterrogatedWindowsWithoutObservedValues(t *testing.T) {
	start := time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)
	scope := domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"n1"}, Start: start, End: start.Add(time.Hour)}
	block := func(status domain.EvidenceStatus, from, to time.Time) investigationcontext.EvidenceBlock {
		return investigationcontext.EvidenceBlock{
			Source: "dcgm:xid", Status: status,
			ObservedFrom: from, ObservedTo: from, ExpectedFrom: from, ExpectedTo: to,
			ExpectedTargets: []investigationcontext.CoverageTarget{{Kind: domain.EvidenceTargetNode, ID: "n1"}},
			ObservedTargets: []investigationcontext.CoverageTarget{{Kind: domain.EvidenceTargetNode, ID: "n1"}},
		}
	}
	full := investigationcontext.Context{Evidence: []investigationcontext.EvidenceBlock{
		block(domain.EvidenceNoData, start, start.Add(30*time.Minute)),
		block(domain.EvidenceComplete, start.Add(30*time.Minute), start.Add(time.Hour)),
	}}
	coverage := modelCoverage(full, scope)
	if !coverage.RequestedTimeComplete || coverage.TimeComplete {
		t.Fatalf("interrogated scope=%+v", coverage)
	}

	// A gap between the requested windows is a real coverage hole.
	gapped := investigationcontext.Context{Evidence: []investigationcontext.EvidenceBlock{
		block(domain.EvidenceNoData, start, start.Add(20*time.Minute)),
		block(domain.EvidenceComplete, start.Add(40*time.Minute), start.Add(time.Hour)),
	}}
	if coverage := modelCoverage(gapped, scope); coverage.RequestedTimeComplete {
		t.Fatalf("gap in interrogation was credited: %+v", coverage)
	}

	// Evidence that could not answer for its declared targets never credits its
	// window, even when the windows themselves would tile the scope.
	unanswered := investigationcontext.Context{Evidence: []investigationcontext.EvidenceBlock{
		block(domain.EvidencePartial, start, start.Add(30*time.Minute)),
		block(domain.EvidenceComplete, start.Add(30*time.Minute), start.Add(time.Hour)),
	}}
	if coverage := modelCoverage(unanswered, scope); coverage.RequestedTimeComplete {
		t.Fatalf("partial evidence credited its requested window: %+v", coverage)
	}
}

func TestModelCoverageDoesNotTreatExpectedTargetAsObserved(t *testing.T) {
	start := time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)
	context := investigationcontext.Context{Evidence: []investigationcontext.EvidenceBlock{{
		Source: "dcgm:xid", ObservedFrom: start.Add(10 * time.Minute), ObservedTo: start.Add(20 * time.Minute),
		ExpectedTargets: []investigationcontext.CoverageTarget{{Kind: domain.EvidenceTargetNode, ID: "n1"}, {Kind: domain.EvidenceTargetGPU, ID: "gpu-1"}},
		ObservedTargets: []investigationcontext.CoverageTarget{{Kind: domain.EvidenceTargetNode, ID: "n1"}},
		MissingTargets:  []investigationcontext.CoverageTarget{{Kind: domain.EvidenceTargetGPU, ID: "gpu-1"}},
	}}}
	coverage := modelCoverage(context, domain.InvestigationScope{EntityKind: "gpu", EntityIDs: []string{"gpu-1"}, Start: start, End: start.Add(time.Hour)})
	if len(coverage.TargetsChecked) != 0 || len(coverage.TargetsMissed) != 1 || len(coverage.MissingTargets) != 1 || coverage.MissingTargets[0].ID != "gpu-1" || coverage.TimeComplete {
		t.Fatalf("coverage=%+v", coverage)
	}
}

func planningSnapshot(t *testing.T, now time.Time) application.InvestigationSnapshot {
	t.Helper()
	request := domain.InvestigationRequest{ID: "inv-1", IncidentID: "incident-1", ClusterID: "cluster-a", Question: "Why is n1 unhealthy?", RequestedBy: "actor-1", IdempotencyKey: "request-1", Scope: domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"n1"}, Start: now.Add(-time.Hour), End: now}, SuccessCriteria: []string{"Identify cited evidence"}, Budget: domain.InvestigationBudget{MaxDecisions: 4, MaxToolCalls: 3, MaxFanOut: 2, MaxModelTokens: 1000, MaxCostMicros: 100}, RequestedAt: now.Add(-time.Minute), Deadline: now.Add(time.Hour)}
	investigation, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	investigation, err = investigation.BeginPlanning(now)
	if err != nil {
		t.Fatal(err)
	}
	return application.InvestigationSnapshot{Investigation: investigation}
}

// fakePlanningProvider queues one planning turn per supplied argument set, so a
// test can exercise the bounded duplicate replan as well as a single decision.
func fakePlanningProvider(t *testing.T, arguments ...json.RawMessage) *modelprovider.FakeProvider {
	t.Helper()
	steps := make([]modelprovider.PlanningStep, 0, len(arguments))
	for _, argument := range arguments {
		steps = append(steps, modelprovider.PlanningStep{Result: modelprovider.PlanningResult{Response: modelprovider.PlanningResponse{SchemaVersion: 1, StateSummary: "Need XID evidence", Actions: []modelprovider.PlannedAction{{ToolID: "gpu.xid_events.v1", Arguments: argument, Purpose: "Check XIDs", ExpectedInformation: "Timestamped XID evidence", Priority: 1}}}, Metadata: modelprovider.CallMetadata{Provider: "fixture", Model: "planner-v1", ConfigurationID: "config-v1", InputTokens: 7, OutputTokens: 3, CostMicros: 2, Latency: time.Millisecond, Outcome: modelprovider.OutcomeSucceeded}}})
	}
	provider, err := modelprovider.NewFakeProvider(steps, nil)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func newTestOrchestrator(t *testing.T, provider modelprovider.Provider, audits application.ModelCallAuditSink, duplicates DuplicateCallStore, now time.Time, payloads ...application.ModelPayloadEvidenceSink) *Orchestrator {
	t.Helper()
	return newTestOrchestratorWithWindow(t, provider, audits, duplicates, now, time.Hour, payloads...)
}

// newTestOrchestratorWithWindow varies only the reviewed per-tool window, which
// is how production tools differ from the investigation scope.
func newTestOrchestratorWithWindow(t *testing.T, provider modelprovider.Provider, audits application.ModelCallAuditSink, duplicates DuplicateCallStore, now time.Time, window time.Duration, payloads ...application.ModelPayloadEvidenceSink) *Orchestrator {
	t.Helper()
	catalog, err := investigationtools.NewCatalog([]investigationtools.Definition{{SchemaVersion: 1, ID: "gpu.xid_events.v1", Description: "Read XID events", Operation: investigationtools.OperationReadOnly, AllowedClusters: []domain.ClusterID{"cluster-a"}, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"dcgm.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{"node"}, MaxTargets: 2, MaxWindow: window}, Timeout: time.Second, CostWeight: 1}})
	if err != nil {
		t.Fatal(err)
	}
	builder, err := investigationcontext.NewBuilder(investigationcontext.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	value, err := NewOrchestrator(provider, catalog, StaticAuthority{Actor: []auth.Capability{auth.CapabilityInvestigationsRun}, Cluster: []investigationtools.ClusterCapability{"dcgm.read"}}, duplicates, LedgerContextSource{}, builder, audits, fixedClock{now}, &sequenceIDs{}, Config{Provider: "fixture", Model: "planner-v1", ModelConfigVersion: "config-v1", PlanningPrompt: "planning-v1", SynthesisPrompt: "synthesis-v1", ToolSchemaVersion: "catalog-v1", ModelCallReservationTTL: time.Minute}, payloads...)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

type auditMemory struct {
	values    []application.ModelCallAudit
	prior     bool
	reserved  map[string]bool
	completed map[string]bool
}

func (memory *auditMemory) AppendModelCallAudit(_ context.Context, audit application.ModelCallAudit) error {
	if err := audit.Validate(); err != nil {
		return err
	}
	memory.values = append(memory.values, audit)
	return nil
}

func (memory *auditMemory) HasModelCallAudit(context.Context, domain.InvestigationID, string) (bool, error) {
	return memory.prior, nil
}

func (memory *auditMemory) ReserveModelCall(_ context.Context, _ domain.InvestigationID, _ domain.ClusterID, key string, _ application.ModelCallKind, _, _ time.Time) error {
	if memory.prior || memory.completed[key] {
		return application.ErrModelCallAlreadyAttempted
	}
	if memory.reserved == nil {
		memory.reserved = map[string]bool{}
	}
	if memory.reserved[key] {
		return application.ErrModelCallInFlight
	}
	memory.reserved[key] = true
	return nil
}

func (memory *auditMemory) CompleteModelCall(_ context.Context, _ domain.InvestigationID, key string, _ application.ModelCallReservationStatus, _ time.Time) error {
	delete(memory.reserved, key)
	if memory.completed == nil {
		memory.completed = map[string]bool{}
	}
	memory.completed[key] = true
	return nil
}

type duplicateMemory struct {
	seen    bool
	digests map[domain.SHA256]bool
}

type memoryReader struct {
	result clustermemory.Result
	err    error
}

func (reader memoryReader) Retrieve(context.Context, clustermemory.Query) (clustermemory.Result, error) {
	return reader.result, reader.err
}

func (memory *duplicateMemory) HasInvestigationActionDigest(_ context.Context, _ domain.InvestigationID, digest domain.SHA256) (bool, error) {
	return memory.seen || memory.digests[digest], nil
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type sequenceIDs struct{ next int }

func (ids *sequenceIDs) NewID() (string, error) {
	ids.next++
	return fmt.Sprintf("id-%d", ids.next), nil
}

type classifiedTestError struct{}

func (classifiedTestError) Error() string          { return "private provider detail" }
func (classifiedTestError) SafeReasonCode() string { return "INVALID_RESPONSE_SEMANTIC_VALIDATION" }

type tracedSemanticError struct{}

func (tracedSemanticError) Error() string          { return "private semantic detail" }
func (tracedSemanticError) SafeReasonCode() string { return "INVALID_RESPONSE_SEMANTIC_VALIDATION" }
func (tracedSemanticError) ModelCallMetadata() (modelprovider.CallMetadata, bool) {
	return modelprovider.CallMetadata{Provider: "fixture", Model: "planner-v1", ConfigurationID: "config-v1", InputTokens: 10, OutputTokens: 5, CostMicros: 3, Latency: time.Millisecond, Outcome: modelprovider.OutcomeSucceeded}, true
}
func (tracedSemanticError) ModelCallTrace() modelprovider.CallTrace {
	return modelprovider.CallTrace{Input: []byte(`{"request":true}`), Output: []byte(`{"invalid":"semantic"}`)}
}

type payloadEvidenceMemory struct {
	values []application.ModelPayloadEvidence
}

func (memory *payloadEvidenceMemory) RecordModelPayload(_ context.Context, value application.ModelPayloadEvidence) (domain.EvidenceID, error) {
	memory.values = append(memory.values, value)
	return domain.EvidenceID(fmt.Sprintf("payload-evidence-%d", len(memory.values))), nil
}

// A synthesis report truncated by the output token cap is the failure a larger
// evidence set makes likely, and it discarded whole investigations because only
// semantic-validation failures reached the deterministic fallback.
func TestTruncatedSynthesisFallsBackInsteadOfFailingTheRun(t *testing.T) {
	for _, reason := range []string{
		"INVALID_RESPONSE_OUTPUT_INCOMPLETE",
		"INVALID_RESPONSE_STRUCTURED_DECODE",
		"INVALID_RESPONSE_SEMANTIC_VALIDATION",
	} {
		if !fallbackEligibleSynthesisFailure(reason) {
			t.Errorf("%s did not reach the deterministic fallback", reason)
		}
	}
	// A provider that never produced a report must still fail the transition.
	for _, reason := range []string{"UNAVAILABLE_TRANSPORT", "DEADLINE_EXCEEDED_TRANSPORT", "PROVIDER_ERROR"} {
		if fallbackEligibleSynthesisFailure(reason) {
			t.Errorf("%s was treated as a usable report", reason)
		}
	}
}

// The truncated case end to end: the run resolves to a safe deterministic
// report rather than an ACCESS_UNAVAILABLE system failure.
func TestSynthesisOutputTruncationResolvesToSafeFallback(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	entry := domain.InvestigationEvidence{EvidenceID: "evidence-1", InvestigationID: snapshot.Investigation.Request().ID, ClusterID: snapshot.Investigation.Request().ClusterID, EntityIDs: []string{"n1"}, Status: domain.EvidencePartial, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now}
	ledger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{entry}, snapshot.Investigation)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Evidence = ledger
	snapshot.RequestedOutcome = domain.InvestigationCompleted
	provider, err := modelprovider.NewFakeProvider(nil, []modelprovider.SynthesisStep{{Err: truncatedOutputError{}}})
	if err != nil {
		t.Fatal(err)
	}
	audits := &auditMemory{}
	result, err := newTestOrchestrator(t, provider, audits, &duplicateMemory{}, now).Synthesize(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("a truncated report failed the run: %v", err)
	}
	if result.Disposition != application.SynthesisSafeFallback || len(result.Findings) == 0 {
		t.Fatalf("result=%+v", result)
	}
	if len(audits.values) != 1 || audits.values[0].ReasonCode != "INVALID_RESPONSE_OUTPUT_INCOMPLETE" {
		t.Fatalf("audits=%+v", audits.values)
	}
}

type truncatedOutputError struct{}

func (truncatedOutputError) Error() string          { return "private provider detail" }
func (truncatedOutputError) SafeReasonCode() string { return "INVALID_RESPONSE_OUTPUT_INCOMPLETE" }

// newDiagnosticOrchestrator offers one evidence lookup and one diagnostic, so a
// test can observe which one the catalog gate admits and which grant it spends.
func newDiagnosticOrchestrator(t *testing.T, provider modelprovider.Provider, audits application.ModelCallAuditSink, duplicates DuplicateCallStore, now time.Time) *Orchestrator {
	t.Helper()
	catalog, err := investigationtools.NewCatalog([]investigationtools.Definition{
		{SchemaVersion: 1, ID: "gpu.xid_events.v1", Description: "Read XID events", Operation: investigationtools.OperationReadOnly, AllowedClusters: []domain.ClusterID{"cluster-a"}, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"dcgm.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{"node"}, MaxTargets: 2, MaxWindow: time.Hour}, Timeout: time.Second, CostWeight: 1},
		{SchemaVersion: 1, ID: "gpu.ecc_counters.v1", Description: "Read live GPU ECC counters", Operation: investigationtools.OperationDiagnostic, AllowedClusters: []domain.ClusterID{"cluster-a"}, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"dcgm.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{"node"}, MaxTargets: 2, MaxWindow: time.Hour}, Timeout: time.Second, CostWeight: 20, MinimumReexecutionInterval: time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	builder, err := investigationcontext.NewBuilder(investigationcontext.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	value, err := NewOrchestrator(provider, catalog, StaticAuthority{Actor: []auth.Capability{auth.CapabilityInvestigationsRun}, Cluster: []investigationtools.ClusterCapability{"dcgm.read"}}, duplicates, LedgerContextSource{}, builder, audits, fixedClock{now}, &sequenceIDs{}, Config{Provider: "fixture", Model: "planner-v1", ModelConfigVersion: "config-v1", PlanningPrompt: "planning-v1", SynthesisPrompt: "synthesis-v1", ToolSchemaVersion: "catalog-v1", ModelCallReservationTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func diagnosticPlanningProvider(t *testing.T, toolID string) *modelprovider.FakeProvider {
	t.Helper()
	arguments := json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T09:00:00Z","end":"2026-08-20T10:00:00Z"}`)
	provider, err := modelprovider.NewFakeProvider([]modelprovider.PlanningStep{{Result: modelprovider.PlanningResult{Response: modelprovider.PlanningResponse{SchemaVersion: 1, StateSummary: "Observe live ECC state", Actions: []modelprovider.PlannedAction{{ToolID: toolID, Arguments: arguments, Purpose: "Separate a contained fault from a degrading device", ExpectedInformation: "Current ECC counters", Priority: 1}}}, Metadata: modelprovider.CallMetadata{Provider: "fixture", Model: "planner-v1", ConfigurationID: "config-v1", InputTokens: 7, OutputTokens: 3, CostMicros: 2, Latency: time.Millisecond, Outcome: modelprovider.OutcomeSucceeded}}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

// A run with no diagnostic grant must never be offered a diagnostic. The
// refusal has to happen in the catalog, before the prompt is built, so it costs
// no provider call and cannot be turned into a rejected plan.
func TestDiagnosticIsInvisibleWithoutAGrantAndOfferedWithOne(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)

	ungranted := diagnosticPlanningProvider(t, "gpu.xid_events.v1")
	if _, err := newDiagnosticOrchestrator(t, ungranted, &auditMemory{}, &duplicateMemory{}, now).Decide(context.Background(), planningSnapshot(t, now)); err != nil {
		t.Fatal(err)
	}
	calls := ungranted.PlanningCalls()
	if len(calls) != 1 {
		t.Fatalf("planning calls = %d, want 1", len(calls))
	}
	for _, tool := range calls[0].AvailableTools {
		if tool.ToolID == "gpu.ecc_counters.v1" {
			t.Fatal("a run with no diagnostic grant was offered a diagnostic")
		}
		if !tool.ReadOnly {
			t.Fatalf("an ungranted run was offered a non-read-only tool: %+v", tool)
		}
	}
	if calls[0].RemainingBudget.DiagnosticCalls != 0 {
		t.Fatalf("remaining diagnostic budget = %d, want 0", calls[0].RemainingBudget.DiagnosticCalls)
	}

	granted := diagnosticPlanningProvider(t, "gpu.ecc_counters.v1")
	snapshot := planningSnapshot(t, now)
	snapshot = withDiagnosticGrant(t, snapshot, 2, now)
	decision, err := newDiagnosticOrchestrator(t, granted, &auditMemory{}, &duplicateMemory{}, now).Decide(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	calls = granted.PlanningCalls()
	if len(calls) != 1 || calls[0].RemainingBudget.DiagnosticCalls != 2 {
		t.Fatalf("a granted run must be told what it may spend: %+v", calls)
	}
	var offered *modelprovider.AvailableTool
	for index, tool := range calls[0].AvailableTools {
		if tool.ToolID == "gpu.ecc_counters.v1" {
			offered = &calls[0].AvailableTools[index]
		}
	}
	if offered == nil {
		t.Fatal("a granted run was not offered the diagnostic")
	}
	if offered.ReadOnly {
		t.Fatal("a diagnostic must not be advertised to the model as read-only")
	}
	if decision.Action == nil || decision.Action.ToolID != "gpu.ecc_counters.v1" || !decision.Action.Diagnostic {
		t.Fatalf("the admitted action did not carry the reviewed operation class: %+v", decision.Action)
	}
	if decision.Action.Privileged {
		t.Fatal("an unprivileged diagnostic must not be marked privileged")
	}
}

// An evidence lookup admitted from a catalog that also contains a diagnostic
// must still be marked as a read: the class comes from the definition, never
// from what else the catalog happens to hold.
func TestEvidenceLookupIsNotMarkedDiagnostic(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := withDiagnosticGrant(t, planningSnapshot(t, now), 2, now)
	provider := diagnosticPlanningProvider(t, "gpu.xid_events.v1")
	decision, err := newDiagnosticOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now).Decide(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action == nil || decision.Action.Diagnostic {
		t.Fatalf("an evidence lookup was marked as a diagnostic: %+v", decision.Action)
	}
}

func TestAutomaticXIDInvestigationUsesDeterministicEvidencePolicy(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	request := snapshot.Investigation.Request()
	request.Question = "Why did the affected GPU entities report non-zero DCGM XID errors?"
	request.Budget.MaxDiagnosticCalls = 4
	value, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	value, err = value.BeginPlanning(now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Investigation = value
	provider := diagnosticPlanningProvider(t, "gpu.xid_events.v1")
	decision, err := newDiagnosticOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now).Decide(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action == nil || decision.Action.ToolID != "gpu.ecc_counters.v1" || !decision.Action.Diagnostic {
		t.Fatalf("deterministic decision=%+v", decision)
	}
	if calls := provider.PlanningCalls(); len(calls) != 0 {
		t.Fatalf("XID evidence policy reached the model: %d calls", len(calls))
	}
}

type refusingContextSource struct{ calls int }

func (source *refusingContextSource) InvestigationContext(context.Context, application.InvestigationSnapshot) (investigationcontext.Input, error) {
	source.calls++
	return investigationcontext.Input{}, investigationcontext.ErrContextTooLarge
}

func TestAutomaticXIDDiagnosticPassDoesNotBuildModelContext(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	request := snapshot.Investigation.Request()
	request.Question = "Why did the affected GPU entities report non-zero DCGM XID errors?"
	request.Budget.MaxDiagnosticCalls = 4
	value, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	value, err = value.BeginPlanning(now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Investigation = value
	provider := diagnosticPlanningProvider(t, "gpu.xid_events.v1")
	orchestrator := newDiagnosticOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now)
	contexts := &refusingContextSource{}
	orchestrator.contexts = contexts
	decision, err := orchestrator.Decide(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if contexts.calls != 0 {
		t.Fatalf("deterministic XID pass built model context %d times", contexts.calls)
	}
	if decision.Action == nil || decision.Action.ToolID != "gpu.ecc_counters.v1" {
		t.Fatalf("deterministic decision=%+v", decision)
	}
}

func TestAutomaticXIDInvestigationStopsForSynthesisAfterEvidencePass(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	request := snapshot.Investigation.Request()
	request.Question = "Why did the affected GPU entities report non-zero DCGM XID errors?"
	value, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	value, err = value.BeginPlanning(now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Investigation = value
	for _, toolID := range investigationtools.XIDRequiredEvidenceTools() {
		snapshot.PriorActions = append(snapshot.PriorActions, application.InvestigationActionHistory{ToolID: string(toolID), Outcome: "SUCCEEDED", Targets: []string{"n1"}, Start: request.Scope.Start, End: request.Scope.End})
	}
	provider := diagnosticPlanningProvider(t, "gpu.xid_events.v1")
	decision, err := newDiagnosticOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now).Decide(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Stop || decision.Reason != domain.StopNoUsefulAction || decision.Action != nil {
		t.Fatalf("terminal decision=%+v", decision)
	}
	if calls := provider.PlanningCalls(); len(calls) != 0 {
		t.Fatalf("completed XID evidence pass reached the model: %d calls", len(calls))
	}
}

// A run that has spent every evidence lookup but still holds execution
// authority has work it can do, and must not be stopped as out of budget.
func TestExhaustedToolCallsDoNotEndARunThatStillHoldsDiagnosticBudget(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	request := domain.InvestigationRequest{ID: "inv-1", IncidentID: "incident-1", ClusterID: "cluster-a", Question: "Is the ECC fault degrading?", RequestedBy: "actor-1", IdempotencyKey: "request-1", Scope: domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"n1"}, Start: now.Add(-time.Hour), End: now}, SuccessCriteria: []string{"Identify cited evidence"}, Budget: domain.InvestigationBudget{MaxDecisions: 4, MaxToolCalls: 1, MaxDiagnosticCalls: 1, MaxFanOut: 2, MaxModelTokens: 1000, MaxCostMicros: 100}, RequestedAt: now.Add(-time.Minute), Deadline: now.Add(time.Hour)}
	investigation, err := domain.ReconstituteInvestigation(request, domain.InvestigationPlanning, "", domain.InvestigationBudgetUsage{Decisions: 1, ToolCalls: 1, FanOut: 1}, nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	provider := diagnosticPlanningProvider(t, "gpu.ecc_counters.v1")
	decision, err := newDiagnosticOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now).Decide(context.Background(), application.InvestigationSnapshot{Investigation: investigation})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Stop {
		t.Fatalf("a run holding diagnostic budget was stopped as exhausted: reason=%s", decision.Reason)
	}
	if decision.Action == nil || !decision.Action.Diagnostic {
		t.Fatalf("the remaining diagnostic authority was not used: %+v", decision.Action)
	}
	if calls := provider.PlanningCalls(); len(calls) != 1 || calls[0].RemainingBudget.ToolCalls != 0 || calls[0].RemainingBudget.DiagnosticCalls != 1 {
		t.Fatalf("the planner was not told which grant is left: %+v", calls)
	}
}

// A run whose diagnostic grant is spent stops seeing diagnostics, so it cannot
// propose one it could not pay for.
func TestSpentDiagnosticGrantWithdrawsTheToolFromTheCatalog(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := withDiagnosticGrant(t, planningSnapshot(t, now), 1, now)
	spent := snapshot
	investigation, err := domain.ReconstituteInvestigation(spent.Investigation.Request(), domain.InvestigationPlanning, "", domain.InvestigationBudgetUsage{Decisions: 1, DiagnosticCalls: 1, FanOut: 1}, nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	provider := diagnosticPlanningProvider(t, "gpu.xid_events.v1")
	if _, err := newDiagnosticOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now).Decide(context.Background(), application.InvestigationSnapshot{Investigation: investigation}); err != nil {
		t.Fatal(err)
	}
	calls := provider.PlanningCalls()
	if len(calls) != 1 {
		t.Fatalf("planning calls = %d, want 1", len(calls))
	}
	for _, tool := range calls[0].AvailableTools {
		if tool.ToolID == "gpu.ecc_counters.v1" {
			t.Fatal("a spent diagnostic grant still offered the diagnostic")
		}
	}
}

func withDiagnosticGrant(t *testing.T, snapshot application.InvestigationSnapshot, grant int, now time.Time) application.InvestigationSnapshot {
	t.Helper()
	request := snapshot.Investigation.Request()
	request.Budget.MaxDiagnosticCalls = grant
	investigation, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	investigation, err = investigation.BeginPlanning(now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Investigation = investigation
	return snapshot
}

// freshnessMemory answers the recency question the freshness rule asks, and
// also records exactly what it was asked, so a test can prove the digest is no
// longer what decides a diagnostic's novelty.
type freshnessMemory struct {
	duplicateMemory
	investigation map[string]time.Time
	cluster       map[string]time.Time
	toolsAsked    []string
}

func (memory *freshnessMemory) LatestInvestigationDiagnostics(_ context.Context, _ domain.InvestigationID, toolID string, targets []string, notBefore time.Time) (map[string]time.Time, error) {
	memory.toolsAsked = append(memory.toolsAsked, toolID)
	return within(memory.investigation, targets, notBefore), nil
}

func (memory *freshnessMemory) LatestClusterDiagnostics(_ context.Context, _ domain.ClusterID, _ string, targets []string, notBefore time.Time) (map[string]time.Time, error) {
	return within(memory.cluster, targets, notBefore), nil
}

func within(values map[string]time.Time, targets []string, notBefore time.Time) map[string]time.Time {
	result := map[string]time.Time{}
	for _, target := range targets {
		if at, ok := values[target]; ok && at.After(notBefore) {
			result[target] = at
		}
	}
	return result
}

// A diagnostic reads live state, so a target whose last result has aged past
// the reviewed interval is worth probing again. Targets are judged as a set:
// one stale target admits the whole batch, because splitting it would carry two
// observation times for one logical observation.
func TestPartiallyStaleDiagnosticTargetSetIsAdmittedWhole(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := withDiagnosticGrant(t, twoNodePlanningSnapshot(t, now), 2, now)
	// n1 was probed thirty seconds ago and is still current; n2 was probed ten
	// minutes ago and is long stale. The interval is one minute.
	freshness := &freshnessMemory{investigation: map[string]time.Time{
		"n1": now.Add(-30 * time.Second),
		"n2": now.Add(-10 * time.Minute),
	}}
	provider := diagnosticPlanningProviderForTargets(t, "gpu.ecc_counters.v1", `["n1","n2"]`)
	decision, err := newDiagnosticOrchestrator(t, provider, &auditMemory{}, freshness, now).Decide(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Stop {
		t.Fatalf("a partially stale target set was refused: reason=%s", decision.Reason)
	}
	if decision.Action == nil || !decision.Action.Diagnostic {
		t.Fatalf("action=%+v", decision.Action)
	}
	if !slices.Equal(decision.Action.Targets, []string{"n1", "n2"}) {
		t.Fatalf("the set was split instead of admitted whole: %v", decision.Action.Targets)
	}
	if decision.Action.Digest == (domain.SHA256{}) {
		t.Fatal("the admitted diagnostic carries no idempotency digest")
	}
	if !slices.Contains(freshness.toolsAsked, "gpu.ecc_counters.v1") {
		t.Fatalf("freshness was not consulted for the proposed definition: %v", freshness.toolsAsked)
	}
}

// When every target is already current the probe would observe state that has
// not moved. That is a recoverable planning mistake, so the run must replan
// with the staleness time stated rather than end.
func TestFullyCurrentDiagnosticIsRefusedWithAStalenessTimeAndReplans(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := withDiagnosticGrant(t, twoNodePlanningSnapshot(t, now), 2, now)
	lastProbe := now.Add(-20 * time.Second)
	freshness := &freshnessMemory{investigation: map[string]time.Time{"n1": lastProbe, "n2": now.Add(-10 * time.Second)}}
	// The first turn proposes the current diagnostic; the replan turn proposes an
	// evidence lookup, which the run must be able to admit.
	provider := twoTurnPlanningProvider(t,
		plannedTurn("gpu.ecc_counters.v1", `["n1","n2"]`),
		plannedTurn("gpu.xid_events.v1", `["n1"]`))
	audits := &auditMemory{}
	decision, err := newDiagnosticOrchestrator(t, provider, audits, freshness, now).Decide(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Stop {
		t.Fatalf("a refused diagnostic ended the run instead of replanning: reason=%s", decision.Reason)
	}
	if decision.Action == nil || decision.Action.ToolID != "gpu.xid_events.v1" || decision.Action.Diagnostic {
		t.Fatalf("the replan did not admit the alternative observation: %+v", decision.Action)
	}
	calls := provider.PlanningCalls()
	if len(calls) != 2 {
		t.Fatalf("planning calls = %d, want 2 (proposal then replan)", len(calls))
	}
	// The staleness time is server-computed: the oldest current result plus the
	// reviewed interval, which is when the set stops being fully current.
	wantStale := lastProbe.Add(time.Minute).UTC().Format(time.RFC3339)
	if !strings.Contains(calls[1].StateSummary, wantStale) {
		t.Fatalf("replan guidance does not state when the targets go stale (%s): %s", wantStale, calls[1].StateSummary)
	}
	if !strings.Contains(calls[1].StateSummary, "gpu.ecc_counters.v1") {
		t.Fatalf("replan guidance does not name the rejected definition: %s", calls[1].StateSummary)
	}
	var refusal *application.ModelCallAudit
	for index, audit := range audits.values {
		if audit.Outcome == application.ModelCallRejected {
			refusal = &audits.values[index]
		}
	}
	if refusal == nil || refusal.ReasonCode != "DIAGNOSTIC_RESULT_STILL_CURRENT" {
		t.Fatalf("the refusal was not classified at the point it occurred: %+v", audits.values)
	}
}

// The recency rule replaces identity only for diagnostics. An evidence lookup
// reads immutable committed envelopes, so repeating one still adds nothing and
// must still be refused by digest, whatever the freshness store says.
func TestEvidenceLookupStillDeduplicatesByIdentity(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := withDiagnosticGrant(t, twoNodePlanningSnapshot(t, now), 2, now)
	// Every target looks long stale, which would admit a diagnostic. It must not
	// rescue a repeated read.
	freshness := &freshnessMemory{
		duplicateMemory: duplicateMemory{seen: true},
		investigation:   map[string]time.Time{"n1": now.Add(-time.Hour), "n2": now.Add(-time.Hour)},
	}
	provider := twoTurnPlanningProvider(t,
		plannedTurn("gpu.xid_events.v1", `["n1"]`),
		plannedTurn("gpu.xid_events.v1", `["n2"]`))
	audits := &auditMemory{}
	decision, err := newDiagnosticOrchestrator(t, provider, audits, freshness, now).Decide(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != nil {
		t.Fatalf("a repeated evidence lookup was admitted: %+v", decision.Action)
	}
	if !decision.Stop || decision.Reason != domain.StopNoUsefulAction {
		t.Fatalf("decision=%+v", decision)
	}
	for _, audit := range audits.values {
		if audit.Outcome == application.ModelCallRejected && audit.ReasonCode != "DUPLICATE_TOOL_CALL" {
			t.Fatalf("an evidence lookup was refused for the wrong reason: %s", audit.ReasonCode)
		}
	}
}

// A result another investigation produced moments ago on the same host is just
// as current, so the cluster tier must suppress the probe too.
func TestClusterScopedDiagnosticFreshnessApplies(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := withDiagnosticGrant(t, twoNodePlanningSnapshot(t, now), 2, now)
	freshness := &freshnessMemory{cluster: map[string]time.Time{"n1": now.Add(-15 * time.Second), "n2": now.Add(-15 * time.Second)}}
	provider := twoTurnPlanningProvider(t,
		plannedTurn("gpu.ecc_counters.v1", `["n1","n2"]`),
		plannedTurn("gpu.xid_events.v1", `["n1"]`))
	decision, err := newDiagnosticOrchestrator(t, provider, &auditMemory{}, freshness, now).Decide(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action == nil || decision.Action.Diagnostic {
		t.Fatalf("a cluster-current diagnostic was executed again: %+v", decision.Action)
	}
}

// A store that cannot answer the recency question must not silently forbid all
// execution: the diagnostic grant is the hard bound, and this rule only
// suppresses work that would observe unchanged state.
func TestDiagnosticIsAdmittedWhenNoFreshnessIsRecorded(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := withDiagnosticGrant(t, twoNodePlanningSnapshot(t, now), 2, now)
	provider := diagnosticPlanningProviderForTargets(t, "gpu.ecc_counters.v1", `["n1","n2"]`)
	decision, err := newDiagnosticOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now).Decide(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action == nil || !decision.Action.Diagnostic {
		t.Fatalf("a first diagnostic was refused with no recorded result: %+v", decision)
	}
}

func twoNodePlanningSnapshot(t *testing.T, now time.Time) application.InvestigationSnapshot {
	t.Helper()
	request := domain.InvestigationRequest{ID: "inv-1", IncidentID: "incident-1", ClusterID: "cluster-a", Question: "Is the ECC fault degrading?", RequestedBy: "actor-1", IdempotencyKey: "request-1", Scope: domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"n1", "n2"}, Start: now.Add(-time.Hour), End: now}, SuccessCriteria: []string{"Identify cited evidence"}, Budget: domain.InvestigationBudget{MaxDecisions: 4, MaxToolCalls: 3, MaxFanOut: 2, MaxModelTokens: 1000, MaxCostMicros: 100}, RequestedAt: now.Add(-time.Minute), Deadline: now.Add(time.Hour)}
	investigation, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	investigation, err = investigation.BeginPlanning(now)
	if err != nil {
		t.Fatal(err)
	}
	return application.InvestigationSnapshot{Investigation: investigation}
}

type plannedProposal struct {
	toolID  string
	targets string
}

func plannedTurn(toolID, targets string) plannedProposal {
	return plannedProposal{toolID: toolID, targets: targets}
}

func twoTurnPlanningProvider(t *testing.T, proposals ...plannedProposal) *modelprovider.FakeProvider {
	t.Helper()
	steps := make([]modelprovider.PlanningStep, 0, len(proposals))
	for _, proposal := range proposals {
		arguments := json.RawMessage(`{"targets":` + proposal.targets + `,"start":"2026-08-20T09:00:00Z","end":"2026-08-20T10:00:00Z"}`)
		steps = append(steps, modelprovider.PlanningStep{Result: modelprovider.PlanningResult{Response: modelprovider.PlanningResponse{SchemaVersion: 1, StateSummary: "Observe the fault", Actions: []modelprovider.PlannedAction{{ToolID: proposal.toolID, Arguments: arguments, Purpose: "Separate a contained fault from a degrading device", ExpectedInformation: "Current device state", Priority: 1}}}, Metadata: modelprovider.CallMetadata{Provider: "fixture", Model: "planner-v1", ConfigurationID: "config-v1", InputTokens: 7, OutputTokens: 3, CostMicros: 2, Latency: time.Millisecond, Outcome: modelprovider.OutcomeSucceeded}}})
	}
	provider, err := modelprovider.NewFakeProvider(steps, nil)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func diagnosticPlanningProviderForTargets(t *testing.T, toolID, targets string) *modelprovider.FakeProvider {
	t.Helper()
	return twoTurnPlanningProvider(t, plannedTurn(toolID, targets))
}

// The controller already requires a timeline, unknowns, and a coverage
// statement before an investigation may complete, and pays tokens to produce
// them. Until the mapper carried them out of the response they were discarded
// before any operator saw them.
func TestSynthesisMappingCarriesTimelineUnknownsAndCoverage(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	orchestrator := newTestOrchestrator(t, canceledProvider{}, &auditMemory{}, &duplicateMemory{}, now)
	first, second := now.Add(-30*time.Minute), now.Add(-10*time.Minute)
	response := modelprovider.SynthesisResponse{
		Timeline: []modelprovider.TimelineEntry{
			{ObservedAt: first, Statement: "XID 94 first appeared.", EvidenceIDs: []string{"evidence-1"}},
			{ObservedAt: second, Statement: "The non-zero state persisted.", EvidenceIDs: []string{"evidence-1", "evidence-2"}},
		},
		WhatRemainsUnknown: []modelprovider.CitedStatement{{Statement: "Onset before the window is unknown."}},
		Coverage:           []modelprovider.CitedStatement{{Statement: "n1 was checked across the requested window.", EvidenceIDs: []string{"evidence-1"}}},
	}
	sections, err := orchestrator.mapSynthesisSections(response, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(sections) != 4 {
		t.Fatalf("expected every timeline, unknown, and coverage statement to survive, got %d", len(sections))
	}

	// Timestamps are the reason a timeline is worth having, so they must arrive
	// intact and in observed order, and citations must arrive unaltered.
	if sections[0].Kind != domain.ReportSectionTimeline || sections[0].ObservedAt == nil || !sections[0].ObservedAt.Equal(first) || sections[0].Ordinal != 0 {
		t.Fatalf("first timeline entry lost its instant or order: %+v", sections[0])
	}
	if sections[1].ObservedAt == nil || !sections[1].ObservedAt.Equal(second) || sections[1].Ordinal != 1 {
		t.Fatalf("second timeline entry lost its instant or order: %+v", sections[1])
	}
	if len(sections[1].EvidenceIDs) != 2 || sections[1].EvidenceIDs[0] != "evidence-1" || sections[1].EvidenceIDs[1] != "evidence-2" {
		t.Fatalf("timeline citations were altered: %+v", sections[1].EvidenceIDs)
	}

	// An unknown citing nothing is the honest answer, not a defect, and it
	// carries no instant.
	if sections[2].Kind != domain.ReportSectionUnknown || sections[2].Statement != "Onset before the window is unknown." || sections[2].ObservedAt != nil {
		t.Fatalf("unknown statement was not carried faithfully: %+v", sections[2])
	}
	if sections[3].Kind != domain.ReportSectionCoverage || len(sections[3].EvidenceIDs) != 1 {
		t.Fatalf("coverage statement was not carried faithfully: %+v", sections[3])
	}
	for _, section := range sections {
		if section.InvestigationID != snapshot.Investigation.Request().ID || section.ID == "" {
			t.Fatalf("section is not attributable: %+v", section)
		}
	}
}

// Severity decides operational action, so the model may propose it but must not
// be the last word. Every finding used to be written INFO regardless of what
// the run found, which made a device needing an RMA indistinguishable from a
// routine observation.
func TestSynthesisSeverityIsProposedByTheModelAndBoundedByEvidence(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	investigation := snapshot.Investigation
	complete := domain.InvestigationEvidence{EvidenceID: "evidence-complete", InvestigationID: investigation.Request().ID, ClusterID: investigation.Request().ClusterID, EntityIDs: []string{"n1"}, Status: domain.EvidenceComplete, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now}
	partial := complete
	partial.EvidenceID, partial.Status = "evidence-partial", domain.EvidencePartial
	ledger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{complete, partial}, investigation)
	if err != nil {
		t.Fatal(err)
	}

	// CRITICAL asserts a fault is happening now, so it stands only on evidence
	// that actually completed.
	if got := boundedFindingSeverity("CRITICAL", []string{"evidence-complete"}, ledger); got != "CRITICAL" {
		t.Fatalf("critical on complete evidence was not preserved: %q", got)
	}
	if got := boundedFindingSeverity("CRITICAL", []string{"evidence-partial"}, ledger); got != "WARNING" {
		t.Fatalf("critical on partial evidence was not bounded: %q", got)
	}
	if got := boundedFindingSeverity("CRITICAL", nil, ledger); got != "WARNING" {
		t.Fatalf("uncited critical was not bounded: %q", got)
	}

	// Lower proposals are the model's to make; nothing raises them.
	for _, proposed := range []string{"INFO", "WARNING", "UNKNOWN"} {
		if got := boundedFindingSeverity(proposed, []string{"evidence-complete"}, ledger); got != proposed {
			t.Fatalf("proposal %q was altered to %q", proposed, got)
		}
	}

	// Silence is not a clean bill of health. An absent or unrecognized proposal
	// becomes UNKNOWN, never INFO.
	for _, proposed := range []string{"", "HIGH", "nonsense"} {
		if got := boundedFindingSeverity(proposed, []string{"evidence-complete"}, ledger); got != "UNKNOWN" {
			t.Fatalf("unusable proposal %q became %q, not UNKNOWN", proposed, got)
		}
	}
}

// The severity change must not cost a finding. Mapping is what used to write
// INFO everywhere; it should now vary while still producing one finding per
// supported statement.
func TestSynthesisMappingKeepsEveryFindingWhileVaryingSeverity(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	entry := domain.InvestigationEvidence{EvidenceID: "evidence-1", InvestigationID: snapshot.Investigation.Request().ID, ClusterID: snapshot.Investigation.Request().ClusterID, EntityIDs: []string{"n1"}, Status: domain.EvidenceComplete, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now}
	ledger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{entry}, snapshot.Investigation)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Evidence = ledger
	orchestrator := newTestOrchestrator(t, canceledProvider{}, &auditMemory{}, &duplicateMemory{}, now)
	modelContext := investigationcontext.Context{Evidence: []investigationcontext.EvidenceBlock{{EvidenceID: "evidence-1", EntityIDs: []string{"n1"}}}}
	confidence := .8
	response := modelprovider.SynthesisResponse{
		WhatIsHappening:    []modelprovider.CitedStatement{{Statement: "XID 94 is present on n1.", Severity: "CRITICAL", EvidenceIDs: []string{"evidence-1"}}},
		LikelyExplanations: []modelprovider.Explanation{{Statement: "The device is faulting.", Severity: "WARNING", Confidence: confidence, EvidenceIDs: []string{"evidence-1"}}},
		SuggestedNextSteps: []modelprovider.CitedStatement{{Statement: "Drain the node.", Severity: "INFO", EvidenceIDs: []string{"evidence-1"}}},
	}
	findings, _, err := orchestrator.mapSynthesisFindings(response, snapshot, modelContext)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("severity mapping dropped findings: %d", len(findings))
	}
	severities := map[domain.FindingKind]string{}
	for _, finding := range findings {
		severities[finding.Kind] = finding.Severity
		if err := finding.Validate(ledger, snapshot.Investigation); err != nil {
			t.Fatalf("mapped finding is not durable: %v", err)
		}
	}
	if severities[domain.FindingObservation] != "CRITICAL" || severities[domain.FindingHypothesis] != "WARNING" || severities[domain.FindingRecommendation] != "INFO" {
		t.Fatalf("severity no longer varies by statement: %+v", severities)
	}
}

func TestSynthesisMappingPromotesOnePrimaryActionCard(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	entry := domain.InvestigationEvidence{EvidenceID: "evidence-1", InvestigationID: snapshot.Investigation.Request().ID, ClusterID: snapshot.Investigation.Request().ClusterID, EntityIDs: []string{"n1"}, Status: domain.EvidenceComplete, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now}
	ledger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{entry}, snapshot.Investigation)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Evidence = ledger
	orchestrator := newTestOrchestrator(t, canceledProvider{}, &auditMemory{}, &duplicateMemory{}, now)
	response := modelprovider.SynthesisResponse{
		WhatIsHappening:    []modelprovider.CitedStatement{{Statement: "The GPU remains degraded.", EvidenceIDs: []string{"evidence-1"}}},
		WhatRemainsUnknown: []modelprovider.CitedStatement{{Statement: "Kernel XID events are unavailable."}},
		SuggestedNextSteps: []modelprovider.CitedStatement{
			{Statement: "Drain n1 and reset the GPU.", Severity: "CRITICAL", EvidenceIDs: []string{"evidence-1"}},
			{Statement: "Open a vendor case.", Severity: "INFO", EvidenceIDs: []string{"evidence-1"}},
		},
	}
	card, err := orchestrator.mapPrimaryActionCard(response, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if card == nil || card.Action != response.SuggestedNextSteps[0].Statement || card.Owner != domain.ActionOwnerClusterOperations || card.Urgency != domain.ActionUrgencyImmediate {
		t.Fatalf("primary action card=%+v", card)
	}
	if !slices.Equal(card.Targets, []string{"n1"}) || !slices.Equal(card.EvidenceIDs, []domain.EvidenceID{"evidence-1"}) || len(card.BlockingGaps) != 1 {
		t.Fatalf("action-card attribution=%+v", card)
	}
}

// Dropping a statement whose citations support no claim is the right call, but
// a report that drops it silently is thinner than the model's answer with
// nothing on the page to say so.
func TestSynthesisMappingCountsAndAttributesDroppedStatements(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	entry := domain.InvestigationEvidence{EvidenceID: "evidence-1", InvestigationID: snapshot.Investigation.Request().ID, ClusterID: snapshot.Investigation.Request().ClusterID, EntityIDs: []string{"n1"}, Status: domain.EvidenceComplete, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now}
	ledger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{entry}, snapshot.Investigation)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Evidence = ledger
	orchestrator := newTestOrchestrator(t, canceledProvider{}, &auditMemory{}, &duplicateMemory{}, now)
	// The context offers an evidence block the durable ledger does not cover, so
	// a statement citing only it supports no claim about any entity.
	modelContext := investigationcontext.Context{Evidence: []investigationcontext.EvidenceBlock{
		{EvidenceID: "evidence-1", EntityIDs: []string{"n1"}},
		{EvidenceID: "evidence-uncovered", EntityIDs: []string{"n1"}},
	}}
	response := modelprovider.SynthesisResponse{
		WhatIsHappening: []modelprovider.CitedStatement{
			{Statement: "XID 94 is present on n1.", Severity: "WARNING", EvidenceIDs: []string{"evidence-1"}},
			{Statement: "An unsupported claim about n1.", Severity: "CRITICAL", EvidenceIDs: []string{"evidence-uncovered"}},
		},
	}
	findings, omissions, err := orchestrator.mapSynthesisFindings(response, snapshot, modelContext)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Statement != "XID 94 is present on n1." {
		t.Fatalf("the supported statement did not survive: %+v", findings)
	}
	if len(omissions) != 1 {
		t.Fatalf("the dropped statement was not recorded: %+v", omissions)
	}
	// Attribution is by kind and reason. The refused text is never carried: it
	// is untrusted prose that failed validation.
	if omissions[0].Kind != string(domain.FindingObservation) || omissions[0].Reason != domain.OmissionNoSupportedEntity || omissions[0].Count != 1 {
		t.Fatalf("omission is not attributable: %+v", omissions[0])
	}
	if err := omissions[0].Validate(snapshot.Investigation); err != nil {
		t.Fatalf("omission is not durable: %v", err)
	}
}

// Drops happen at more than one site, so the report must state one total per
// cause rather than one row per site.
func TestReportOmissionsMergeByKindAndReason(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	id := snapshot.Investigation.Request().ID
	merged := domain.MergeReportOmissions(nil,
		domain.ReportOmission{InvestigationID: id, Kind: "OBSERVATION", Reason: domain.OmissionNoSupportedEntity, Count: 1},
		domain.ReportOmission{InvestigationID: id, Kind: "OBSERVATION", Reason: domain.OmissionNoSupportedEntity, Count: 2},
		domain.ReportOmission{InvestigationID: id, Kind: "OBSERVATION", Reason: domain.OmissionValidationRefused, Count: 1},
		domain.ReportOmission{InvestigationID: id, Kind: "TIMELINE", Reason: domain.OmissionCitationNotInLedger, Count: 4},
		domain.ReportOmission{InvestigationID: id, Kind: "TIMELINE", Reason: domain.OmissionCitationNotInLedger, Count: 0},
	)
	if len(merged) != 3 {
		t.Fatalf("omissions did not merge by cause: %+v", merged)
	}
	if merged[0].Count != 3 || merged[1].Count != 1 || merged[2].Count != 4 {
		t.Fatalf("omission counts are wrong: %+v", merged)
	}
}

// A report named only what the domain refused after the model answered. What
// the context builder dropped before the call -- the more consequential loss,
// since that evidence was never reasoned over -- reached the operator as
// nothing at all, so a run that fitted two of ten warnings into its context
// produced a report indistinguishable from one that considered all ten.
func TestContextDropsAreRecordedAsReportOmissions(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	id := snapshot.Investigation.Request().ID
	modelContext := investigationcontext.Context{Omissions: []investigationcontext.Omission{
		{Kind: investigationcontext.OmissionKindEvidence, Count: 8, Reason: investigationcontext.OmissionItemLimit},
		{Kind: investigationcontext.OmissionKindEvidence, Count: 2, Reason: investigationcontext.OmissionEncodedSizeLimit},
		{Kind: investigationcontext.OmissionKindEvidence, Count: 1, Reason: investigationcontext.OmissionProviderAllowance},
		{Kind: investigationcontext.OmissionKindHypothesis, Count: 3, Reason: investigationcontext.OmissionEncodedSizeLimit},
	}}

	omissions := contextReportOmissions(modelContext, id)
	want := map[string]int{
		investigationcontext.OmissionKindEvidence + "/" + domain.OmissionContextItemLimit:       8,
		investigationcontext.OmissionKindEvidence + "/" + domain.OmissionContextSizeLimit:       2,
		investigationcontext.OmissionKindEvidence + "/" + domain.OmissionProviderInputAllowance: 1,
		investigationcontext.OmissionKindHypothesis + "/" + domain.OmissionContextSizeLimit:     3,
	}
	if len(omissions) != len(want) {
		t.Fatalf("context drops were not recorded: %+v", omissions)
	}
	for _, omission := range omissions {
		count, expected := want[omission.Kind+"/"+omission.Reason]
		if !expected || count != omission.Count {
			t.Fatalf("omission is not attributable: %+v", omission)
		}
		// The store holds an omission to the same gate as a finding, so a reason
		// outside the reviewed set would fail the whole synthesis transaction.
		if err := omission.Validate(snapshot.Investigation); err != nil {
			t.Fatalf("omission is not durable: %v", err)
		}
	}
}

// Coalescing and fingerprint de-duplication project evidence that is still
// represented in the context, and scope trimming cuts coverage metadata rather
// than an answer. Reporting those as losses would tell a reader the model was
// denied something it in fact read.
func TestLosslessContextReductionsAreNotReportedAsOmissions(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	id := planningSnapshot(t, now).Investigation.Request().ID
	modelContext := investigationcontext.Context{Omissions: []investigationcontext.Omission{
		{Kind: investigationcontext.OmissionKindEvidence, Count: 4, Reason: investigationcontext.OmissionRedundantFingerprint},
		{Kind: investigationcontext.OmissionKindEvidence, Count: 6, Reason: investigationcontext.OmissionCoalescedSamples},
		{Kind: investigationcontext.OmissionKindCoverageTarget, Count: 90, Reason: investigationcontext.OmissionOutsideScope},
		{Kind: investigationcontext.OmissionKindSuccessCriteria, Count: 2, Reason: investigationcontext.OmissionItemLimit},
	}}
	if omissions := contextReportOmissions(modelContext, id); len(omissions) != 0 {
		t.Fatalf("a lossless reduction was reported as a loss: %+v", omissions)
	}
}

// The mapper classifies context omissions by reason, so a reason added to the
// builder without a decision here would be silently unreported -- the exact
// failure this mapping exists to end, reintroduced one reason at a time.
//
// The guard reads reason declarations rather than call sites. Its first
// spelling matched the last argument of each addOmission call, which broke as
// soon as one site passed a reason through a variable, and a call-site count
// says nothing about a constant declared but not yet used.
func TestEveryContextOmissionReasonIsClassified(t *testing.T) {
	// Name -> the domain reason it is reported as, or "" for a reduction that
	// loses nothing. Adding a reason to the builder fails this test until it is
	// listed, which is the point.
	classified := map[string]string{
		"OmissionItemLimit":            domain.OmissionContextItemLimit,
		"OmissionEncodedSizeLimit":     domain.OmissionContextSizeLimit,
		"OmissionProviderAllowance":    domain.OmissionProviderInputAllowance,
		"OmissionRedundantFingerprint": "",
		"OmissionCoalescedSamples":     "",
		"OmissionOutsideScope":         "",
	}
	source, err := os.ReadFile(filepath.Join("..", "investigationcontext", "builder.go"))
	if err != nil {
		t.Fatal(err)
	}
	// Reason constants only: the kind constants share the prefix but name what
	// was dropped, not why.
	declared := regexp.MustCompile(`(?m)^\t(Omission[A-Za-z]+)\s+=\s+"`).FindAllStringSubmatch(string(source), -1)
	found := 0
	for _, declaration := range declared {
		name := declaration[1]
		if strings.HasPrefix(name, "OmissionKind") {
			continue
		}
		found++
		if _, ruled := classified[name]; !ruled {
			t.Fatalf("context omission reason %s has no ruling: report it or declare it lossless", name)
		}
	}
	if found != len(classified) {
		t.Fatalf("the guard read %d declared reasons but rules on %d", found, len(classified))
	}

	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	id := planningSnapshot(t, now).Investigation.Request().ID
	for name, reason := range map[string]string{
		investigationcontext.OmissionItemLimit:            classified["OmissionItemLimit"],
		investigationcontext.OmissionEncodedSizeLimit:     classified["OmissionEncodedSizeLimit"],
		investigationcontext.OmissionProviderAllowance:    classified["OmissionProviderAllowance"],
		investigationcontext.OmissionRedundantFingerprint: classified["OmissionRedundantFingerprint"],
		investigationcontext.OmissionCoalescedSamples:     classified["OmissionCoalescedSamples"],
		investigationcontext.OmissionOutsideScope:         classified["OmissionOutsideScope"],
	} {
		omissions := contextReportOmissions(investigationcontext.Context{Omissions: []investigationcontext.Omission{
			{Kind: investigationcontext.OmissionKindEvidence, Count: 1, Reason: name},
		}}, id)
		if reason == "" {
			if len(omissions) != 0 {
				t.Fatalf("lossless reason %q was reported as a loss", name)
			}
			continue
		}
		if len(omissions) != 1 || omissions[0].Reason != reason {
			t.Fatalf("reason %q did not map to %q: %+v", name, reason, omissions)
		}
	}
}

// A ten-node pass dropped evidence for two nodes and told the model only that
// sixteen items were gone. The model reported those nodes unassessed -- correct
// -- and then recommended re-running diagnostics that had already succeeded,
// because nothing in its context separated "never collected" from "collected
// but not shown".
func TestOmittedEntitiesReachTheModelCoverage(t *testing.T) {
	modelContext := investigationcontext.Context{
		Evidence: []investigationcontext.EvidenceBlock{
			{EvidenceID: "evidence-shown", EntityIDs: []string{"node-a"}, Status: domain.EvidenceComplete},
		},
		Omissions: []investigationcontext.Omission{
			{Kind: investigationcontext.OmissionKindEvidence, Count: 3, Reason: investigationcontext.OmissionEncodedSizeLimit, EntityIDs: []string{"node-c", "node-b"}},
			{Kind: investigationcontext.OmissionKindEvidence, Count: 2, Reason: investigationcontext.OmissionItemLimit, EntityIDs: []string{"node-b", "node-d"}},
			// A lossless reduction names no entity as unassessed: that evidence
			// is still represented in what the model read.
			{Kind: investigationcontext.OmissionKindEvidence, Count: 4, Reason: investigationcontext.OmissionCoalescedSamples, EntityIDs: []string{"node-e"}},
		},
	}
	scope := domain.InvestigationScope{EntityKind: "entity", EntityIDs: []string{"node-a", "node-b", "node-c", "node-d", "node-e"}, Start: time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC), End: time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)}

	coverage := modelCoverage(modelContext, scope)
	if coverage.EvidenceOmitted != 5 || coverage.EvidenceReduced != 4 {
		t.Fatalf("coverage counts are wrong: omitted=%d reduced=%d", coverage.EvidenceOmitted, coverage.EvidenceReduced)
	}
	want := []string{"node-b", "node-c", "node-d"}
	if !slices.Equal(coverage.EvidenceOmittedEntities, want) {
		t.Fatalf("omitted entities are not named and sorted: %v", coverage.EvidenceOmittedEntities)
	}
	// The list is useless unless its meaning travels with it: the prompt is
	// versioned separately and cannot be relied on to explain this field.
	if coverage.EvidenceOmittedNote == "" {
		t.Fatal("omitted entities carry no explanation of what they mean")
	}
}

// Nothing is omitted, so no entity is named and no note is offered. A note on a
// complete context would invite the model to hedge about evidence it has.
func TestCompleteCoverageNamesNoOmittedEntities(t *testing.T) {
	modelContext := investigationcontext.Context{Evidence: []investigationcontext.EvidenceBlock{
		{EvidenceID: "evidence-shown", EntityIDs: []string{"node-a"}, Status: domain.EvidenceComplete},
	}}
	scope := domain.InvestigationScope{EntityKind: "entity", EntityIDs: []string{"node-a"}, Start: time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC), End: time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)}
	coverage := modelCoverage(modelContext, scope)
	if len(coverage.EvidenceOmittedEntities) != 0 || coverage.EvidenceOmittedNote != "" {
		t.Fatalf("a complete context reported omissions: %v %q", coverage.EvidenceOmittedEntities, coverage.EvidenceOmittedNote)
	}
}

func TestThinnedFleetNamesOnlyEntitiesWithNoSelectedEvidence(t *testing.T) {
	modelContext := investigationcontext.Context{}
	scope := domain.InvestigationScope{EntityKind: "node"}
	for index := 0; index < 10; index++ {
		entity := fmt.Sprintf("node-%02d", index)
		scope.EntityIDs = append(scope.EntityIDs, entity)
		modelContext.Evidence = append(modelContext.Evidence, investigationcontext.EvidenceBlock{EvidenceID: domain.EvidenceID(entity + "-shown"), EntityIDs: []string{entity}, Status: domain.EvidenceComplete})
	}
	modelContext.Omissions = []investigationcontext.Omission{{Kind: investigationcontext.OmissionKindEvidence, Count: 30, Reason: investigationcontext.OmissionEncodedSizeLimit, EntityIDs: slices.Clone(scope.EntityIDs)}}
	coverage := modelCoverage(modelContext, scope)
	if len(coverage.EvidenceOmittedEntities) != 0 || coverage.EvidenceOmittedNote != "" || coverage.EvidenceOmitted != 30 {
		t.Fatalf("partially thinned entities must not be called unassessed: %+v", coverage)
	}
	modelContext.Evidence = modelContext.Evidence[:9]
	coverage = modelCoverage(modelContext, scope)
	if !slices.Equal(coverage.EvidenceOmittedEntities, []string{"node-09"}) {
		t.Fatalf("only the entity with no selected evidence is unassessed: %+v", coverage)
	}
}

func TestClusterOnlyOmissionIsNotAnUnassessedNode(t *testing.T) {
	scope := domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"node-a", "node-b"}}
	modelContext := investigationcontext.Context{
		Evidence: []investigationcontext.EvidenceBlock{{EvidenceID: "node-a-evidence", EntityIDs: []string{"node-a"}, Status: domain.EvidenceComplete}},
		Omissions: []investigationcontext.Omission{
			{Kind: investigationcontext.OmissionKindEvidence, Count: 1, Reason: investigationcontext.OmissionEncodedSizeLimit, EntityIDs: []string{"cluster-a"}},
			{Kind: investigationcontext.OmissionKindEvidence, Count: 1, Reason: investigationcontext.OmissionItemLimit, EntityIDs: []string{"node-b"}},
		},
	}
	coverage := modelCoverage(modelContext, scope)
	if coverage.EvidenceOmitted != 2 || !slices.Equal(coverage.EvidenceOmittedEntities, []string{"node-b"}) {
		t.Fatalf("cluster-only omission was projected as unassessed node or lost from count: %+v", coverage)
	}
}

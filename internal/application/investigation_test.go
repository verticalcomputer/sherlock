package application

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestInvestigationControllerRestartsAtEveryTransitionWithoutDuplicatePrivilegedWork(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	clock := &investigationClock{now: now}
	store := &investigationMemoryStore{}
	action := domain.InvestigationAction{ID: "action-1", ToolID: "node.gpu_snapshot.v1", Digest: domain.ChecksumSHA256([]byte("action-1")), Privileged: true, FanOut: 1}
	evidence := domain.InvestigationEvidence{EvidenceID: "evidence-1", InvestigationID: "investigation-1", ClusterID: "cluster-1", EntityIDs: []string{"node-1"}, Status: domain.EvidenceComplete, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now.Add(time.Second)}
	executor := &idempotentInvestigationExecutor{evidence: []domain.InvestigationEvidence{evidence}, receipts: map[string]InvestigationExecutionResult{}}
	planner := completeScriptedPlanner{ScriptedInvestigationPlanner: ScriptedInvestigationPlanner{Decisions: []InvestigationDecision{
		{Action: &action},
		{Stop: true, Outcome: domain.InvestigationCompleted, Reason: domain.StopSuccessCriteriaMet},
	}}}
	request := investigationRequest(now)
	controller := newTestInvestigationController(t, store, planner, executor, clock)
	if _, created, err := controller.Start(context.Background(), StartInvestigationInput{Request: request}); err != nil || !created {
		t.Fatalf("start: created=%t err=%v", created, err)
	}

	for attempts := 0; attempts < 30; attempts++ {
		// Reconstructing the controller before every transition models a server
		// restart with no process-local workflow state.
		controller = newTestInvestigationController(t, store, planner, executor, clock)
		snapshot, found, err := store.LoadInvestigation(context.Background(), request.ID)
		if err != nil || !found {
			t.Fatalf("load: found=%t err=%v", found, err)
		}
		if snapshot.Investigation.Status() == domain.InvestigationAwaitingApproval {
			pending, ok := snapshot.Investigation.PendingAction()
			if !ok {
				t.Fatal("approval state has no pending action")
			}
			approval := domain.InvestigationApproval{ID: "approval-1", InvestigationID: request.ID, ActionID: pending.ID, ActionDigest: pending.Digest, InvestigationVersion: snapshot.Investigation.Version(), ApprovedBy: "operator-1", ApprovedAt: clock.Now(), ExpiresAt: clock.Now().Add(5 * time.Minute)}
			if _, err := controller.Approve(context.Background(), request.ID, approval); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if snapshot.Investigation.Status().Terminal() {
			if snapshot.Investigation.Status() != domain.InvestigationCompleted {
				t.Fatalf("status=%s", snapshot.Investigation.Status())
			}
			if len(snapshot.Evidence.Entries()) != 1 {
				t.Fatalf("evidence entries=%d", len(snapshot.Evidence.Entries()))
			}
			if executor.sideEffects != 1 {
				t.Fatalf("privileged side effects=%d", executor.sideEffects)
			}
			if executor.calls != 2 {
				t.Fatalf("expected replay after simulated crash, calls=%d", executor.calls)
			}
			return
		}
		// Fail the first save after execution. The next controller repeats the
		// external request with the same idempotency key and receives its receipt.
		if snapshot.Investigation.Status() == domain.InvestigationExecuting && !store.failedExecutionSave {
			store.failNextSave = true
		}
		_, err = controller.Advance(context.Background(), request.ID)
		if store.failedExecutionSave && err != nil {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("investigation did not terminate")
}

func TestInvestigationControllerScriptedTerminalOutcomes(t *testing.T) {
	for _, outcome := range []struct {
		status domain.InvestigationStatus
		reason domain.InvestigationStopReason
	}{
		{domain.InvestigationCompleted, domain.StopSuccessCriteriaMet},
		{domain.InvestigationPartial, domain.StopBudgetExceeded},
		{domain.InvestigationBlocked, domain.StopAccessUnavailable},
	} {
		t.Run(string(outcome.status), func(t *testing.T) {
			now := time.Date(2026, 8, 20, 13, 0, 0, 0, time.UTC)
			request := investigationRequest(now)
			request.ID = domain.InvestigationID("investigation-" + string(outcome.status))
			store := &investigationMemoryStore{}
			clock := &investigationClock{now: now}
			planner := completeScriptedPlanner{ScriptedInvestigationPlanner: ScriptedInvestigationPlanner{Decisions: []InvestigationDecision{{Stop: true, Outcome: outcome.status, Reason: outcome.reason}}}}
			controller := newTestInvestigationController(t, store, planner, &idempotentInvestigationExecutor{receipts: map[string]InvestigationExecutionResult{}}, clock)
			if _, _, err := controller.Start(context.Background(), StartInvestigationInput{Request: request}); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 6; i++ {
				if _, err := controller.Advance(context.Background(), request.ID); err != nil {
					t.Fatal(err)
				}
			}
			snapshot, _, _ := store.LoadInvestigation(context.Background(), request.ID)
			if snapshot.Investigation.Status() != outcome.status || snapshot.Investigation.StopReason() != outcome.reason {
				t.Fatalf("got %s/%s", snapshot.Investigation.Status(), snapshot.Investigation.StopReason())
			}
			if snapshot.PrimaryActionCard == nil || snapshot.PrimaryActionCard.Owner == "" || snapshot.PrimaryActionCard.Action == "" {
				t.Fatalf("terminal investigation has no actionable handoff: %+v", snapshot.PrimaryActionCard)
			}
		})
	}
}

func TestInvestigationControllerPersistsPlannerHypothesesWithDecision(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	request := investigationRequest(now)
	hypothesis := domain.Hypothesis{ID: "hypothesis-1", InvestigationID: request.ID, Statement: "The cause remains unresolved.", Status: domain.HypothesisUnresolved, Confidence: 0.25, UnresolvedTests: []string{"Collect a bounded independent source."}, Version: 1}
	planner := ScriptedInvestigationPlanner{Decisions: []InvestigationDecision{{Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopNoUsefulAction, Hypotheses: []domain.Hypothesis{hypothesis}}}}
	store := &investigationMemoryStore{}
	controller := newTestInvestigationController(t, store, planner, &idempotentInvestigationExecutor{receipts: map[string]InvestigationExecutionResult{}}, &investigationClock{now: now})
	if _, created, err := controller.Start(context.Background(), StartInvestigationInput{Request: request}); err != nil || !created {
		t.Fatalf("start: created=%t err=%v", created, err)
	}
	if _, err := controller.Advance(context.Background(), request.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Advance(context.Background(), request.ID); err != nil {
		t.Fatal(err)
	}
	persisted, found, err := store.LoadInvestigation(context.Background(), request.ID)
	if err != nil || !found {
		t.Fatalf("load: found=%t err=%v", found, err)
	}
	entries := persisted.Hypotheses.Entries()
	if len(entries) != 1 || entries[0].ID != hypothesis.ID || entries[0].Version != 1 {
		t.Fatalf("durable hypotheses=%+v", entries)
	}
	if len(persisted.ProposedHypotheses) != 0 {
		t.Fatalf("planner hypotheses remained process-local: %+v", persisted.ProposedHypotheses)
	}
}

func TestInvestigationControllerClassifiesSuccessfulEmptyLookupAsNoEvidence(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	request := investigationRequest(now)
	action := domain.InvestigationAction{
		ID: "action-empty", ToolID: "metrics.xid_evidence.v1", Digest: domain.ChecksumSHA256([]byte("empty")),
		FanOut: 1, Targets: []string{"node-1"}, Start: request.Scope.Start, End: request.Scope.End,
	}
	store := &investigationMemoryStore{}
	controller := newTestInvestigationController(t, store, ScriptedInvestigationPlanner{Decisions: []InvestigationDecision{{Action: &action}}}, &idempotentInvestigationExecutor{receipts: map[string]InvestigationExecutionResult{}}, &investigationClock{now: now})
	if _, created, err := controller.Start(context.Background(), StartInvestigationInput{Request: request}); err != nil || !created {
		t.Fatalf("start: created=%t err=%v", created, err)
	}
	for step := 0; step < 6; step++ {
		if _, err := controller.Advance(context.Background(), request.ID); err != nil {
			t.Fatalf("advance step %d: %v", step+1, err)
		}
	}
	persisted, found, err := store.LoadInvestigation(context.Background(), request.ID)
	if err != nil || !found {
		t.Fatalf("load: found=%t err=%v", found, err)
	}
	if len(persisted.PriorActions) != 1 || persisted.PriorActions[0].Outcome != "NO_EVIDENCE" || len(persisted.PriorActions[0].EvidenceIDs) != 0 {
		t.Fatalf("prior actions=%+v", persisted.PriorActions)
	}
}

func TestInvestigationActionEvidenceOutcomeDistinguishesAbsenceAndUnavailability(t *testing.T) {
	tests := []struct {
		name     string
		evidence []domain.InvestigationEvidence
		want     string
	}{
		{name: "empty", want: "NO_EVIDENCE"},
		{name: "explicit no data", evidence: []domain.InvestigationEvidence{{Status: domain.EvidenceNoData}}, want: "NO_EVIDENCE"},
		{name: "unavailable", evidence: []domain.InvestigationEvidence{{Status: domain.EvidenceUnavailable}}, want: "UNAVAILABLE"},
		{name: "partial retained", evidence: []domain.InvestigationEvidence{{Status: domain.EvidencePartial}}, want: "SUCCEEDED"},
		{name: "mixed retained", evidence: []domain.InvestigationEvidence{{Status: domain.EvidenceUnavailable}, {Status: domain.EvidencePartial}}, want: "SUCCEEDED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := investigationActionEvidenceOutcome(test.evidence); got != test.want {
				t.Fatalf("outcome=%s want=%s", got, test.want)
			}
		})
	}
}

func TestInvestigationControllerCancelExpectedRejectsStaleVersion(t *testing.T) {
	now := time.Date(2026, 8, 20, 13, 30, 0, 0, time.UTC)
	request := investigationRequest(now)
	store := &investigationMemoryStore{}
	controller := newTestInvestigationController(t, store, ScriptedInvestigationPlanner{}, &idempotentInvestigationExecutor{receipts: map[string]InvestigationExecutionResult{}}, &investigationClock{now: now})
	if _, _, err := controller.Start(context.Background(), StartInvestigationInput{Request: request}); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.CancelExpected(context.Background(), request.ID, 2); !errors.Is(err, ErrInvestigationConflict) {
		t.Fatalf("stale cancellation error = %v", err)
	}
	snapshot, err := controller.CancelExpected(context.Background(), request.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Investigation.Status() != domain.InvestigationCancelled {
		t.Fatalf("status = %s", snapshot.Investigation.Status())
	}
	if snapshot.PrimaryActionCard == nil || snapshot.PrimaryActionCard.Owner != domain.ActionOwnerSherlock {
		t.Fatalf("cancelled action card=%+v", snapshot.PrimaryActionCard)
	}
}

func TestInvestigationControllerStopsUnexpectedFailureWithoutEvidenceAsBlocked(t *testing.T) {
	now := time.Date(2026, 8, 20, 13, 45, 0, 0, time.UTC)
	request := investigationRequest(now)
	store := &investigationMemoryStore{}
	controller := newTestInvestigationController(t, store, ScriptedInvestigationPlanner{}, &idempotentInvestigationExecutor{receipts: map[string]InvestigationExecutionResult{}}, &investigationClock{now: now})
	if _, _, err := controller.Start(context.Background(), StartInvestigationInput{Request: request}); err != nil {
		t.Fatal(err)
	}
	stopped, err := controller.StopAfterFailure(context.Background(), request.ID, errors.New("provider unavailable"))
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Investigation.Status() != domain.InvestigationBlocked || stopped.Investigation.StopReason() != domain.StopAccessUnavailable {
		t.Fatalf("status=%s reason=%s", stopped.Investigation.Status(), stopped.Investigation.StopReason())
	}
}

func TestInvestigationControllerPreservesBudgetFailureClassification(t *testing.T) {
	now := time.Date(2026, 8, 20, 13, 50, 0, 0, time.UTC)
	request := investigationRequest(now)
	store := &investigationMemoryStore{}
	controller := newTestInvestigationController(t, store, ScriptedInvestigationPlanner{}, &idempotentInvestigationExecutor{receipts: map[string]InvestigationExecutionResult{}}, &investigationClock{now: now})
	if _, _, err := controller.Start(context.Background(), StartInvestigationInput{Request: request}); err != nil {
		t.Fatal(err)
	}
	stopped, err := controller.StopAfterFailure(context.Background(), request.ID, fmt.Errorf("charge model call: %w", domain.ErrInvestigationBudgetExceeded))
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Investigation.Status() != domain.InvestigationPartial || stopped.Investigation.StopReason() != domain.StopBudgetExceeded {
		t.Fatalf("status=%s reason=%s", stopped.Investigation.Status(), stopped.Investigation.StopReason())
	}
}

// The live failure occurred on the sixth planning turn after useful evidence
// had already been retained. Provider preflight refused the enlarged context,
// and the generic supervisor used to relabel that as ACCESS_UNAVAILABLE and
// persist no report. Terminal recovery must be model-free and bounded.
func TestSixthTurnContextOverflowProducesBoundedActionableReport(t *testing.T) {
	now := time.Date(2026, 9, 9, 13, 0, 0, 0, time.UTC)
	request := investigationRequest(now)
	request.Budget.MaxDecisions = 8
	request.Budget.MaxToolCalls = 8
	request.Budget.MaxModelTokens = 100_000
	request.Budget.MaxCostMicros = 2_000_000
	investigation, err := domain.ReconstituteInvestigation(request, domain.InvestigationPlanning, "", domain.InvestigationBudgetUsage{Decisions: 5, ToolCalls: 5, ModelTokens: 58_000}, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	evidenceEntries := make([]domain.InvestigationEvidence, 12)
	for index := range evidenceEntries {
		evidenceEntries[index] = domain.InvestigationEvidence{
			EvidenceID: domain.EvidenceID(fmt.Sprintf("evidence-%02d", index)), InvestigationID: request.ID, ClusterID: request.ClusterID,
			EntityIDs: []string{"node-1"}, Status: domain.EvidencePartial, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now.Add(time.Second),
		}
	}
	evidence, err := domain.NewEvidenceLedger(evidenceEntries, investigation)
	if err != nil {
		t.Fatal(err)
	}
	hypotheses, err := domain.NewHypothesisLedger([]domain.Hypothesis{{
		ID: "hypothesis-sticky-gauge", InvestigationID: request.ID, Statement: "The signal may be a sticky gauge.",
		Status: domain.HypothesisUnresolved, Confidence: 0.5, UnresolvedTests: []string{"Collect an independent kernel event source."}, Version: 1,
	}}, evidence, investigation)
	if err != nil {
		t.Fatal(err)
	}
	store := &investigationMemoryStore{found: true, snapshot: InvestigationSnapshot{Investigation: investigation, Evidence: evidence, Hypotheses: hypotheses}}
	planner := failingInvestigationPlanner{err: errors.New("private provider preflight detail")}
	controller := newTestInvestigationController(t, store, planner, &idempotentInvestigationExecutor{receipts: map[string]InvestigationExecutionResult{}}, &investigationClock{now: now})
	_, advanceErr := controller.Advance(context.Background(), request.ID)
	if advanceErr == nil {
		t.Fatal("sixth planning turn unexpectedly succeeded")
	}
	stopped, err := controller.StopAfterFailure(context.Background(), request.ID, ClassifyInvestigationFailure(advanceErr, FailureRequiredContext))
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Investigation.Status() != domain.InvestigationPartial || stopped.Investigation.StopReason() != domain.StopContextExhausted {
		t.Fatalf("status=%s reason=%s", stopped.Investigation.Status(), stopped.Investigation.StopReason())
	}
	if len(stopped.Findings) != 1 || stopped.Findings[0].Kind != domain.FindingRecommendation {
		t.Fatalf("terminal recommendation=%+v", stopped.Findings)
	}
	if len(stopped.ReportSections) != 1 || len(stopped.ReportSections[0].EvidenceIDs) != terminalReportCitationLimit {
		t.Fatalf("bounded terminal report=%+v", stopped.ReportSections)
	}
	if stopped.PrimaryActionCard == nil || stopped.PrimaryActionCard.Owner != domain.ActionOwnerSherlock || stopped.PrimaryActionCard.Action == "" {
		t.Fatalf("terminal action card=%+v", stopped.PrimaryActionCard)
	}
	if len(stopped.PrimaryActionCard.EvidenceIDs) != terminalReportCitationLimit {
		t.Fatalf("action-card citations=%d", len(stopped.PrimaryActionCard.EvidenceIDs))
	}
}

type failingInvestigationPlanner struct{ err error }

func (planner failingInvestigationPlanner) Decide(context.Context, InvestigationSnapshot) (InvestigationDecision, error) {
	return InvestigationDecision{}, planner.err
}

func TestInvestigationControllerClassifiesPostCallBudgetOverrunWithoutSupervisorFallback(t *testing.T) {
	now := time.Date(2026, 8, 21, 9, 30, 0, 0, time.UTC)
	request := investigationRequest(now)
	request.Budget.MaxModelTokens = 60_000
	request.Budget.MaxCostMicros = 2_000_000
	request.Budget.MaxFanOut = 64
	investigation, err := domain.ReconstituteInvestigation(request, domain.InvestigationPlanning, "", domain.InvestigationBudgetUsage{Decisions: 2, ToolCalls: 2, FanOut: 44, ModelTokens: 54_922, CostMicros: 361_585}, nil, 14)
	if err != nil {
		t.Fatal(err)
	}
	planner := ScriptedInvestigationPlanner{Decisions: []InvestigationDecision{{}, {}, {Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopNoUsefulAction, ModelTokens: 41_924, CostMicros: 245_070}}}
	store := &investigationMemoryStore{found: true, snapshot: InvestigationSnapshot{Investigation: investigation}}
	controller := newTestInvestigationController(t, store, planner, &idempotentInvestigationExecutor{receipts: map[string]InvestigationExecutionResult{}}, &investigationClock{now: now})
	snapshot, err := controller.Advance(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Investigation.Status() != domain.InvestigationPartial || snapshot.Investigation.StopReason() != domain.StopBudgetExceeded {
		t.Fatalf("status=%s reason=%s", snapshot.Investigation.Status(), snapshot.Investigation.StopReason())
	}
	usage := snapshot.Investigation.Usage()
	if usage.ModelTokens != 54_922 || usage.CostMicros != 361_585 {
		t.Fatalf("admitted usage was rewritten: %+v", usage)
	}
}

// A live run gathered evidence from eight successful actions, exhausted its
// tool-call and decision allowances while still holding most of its token
// budget, and terminated with no findings and no synthesis call at all. An
// investigation that can still afford the report must produce it.
// A live run spent 86,000 tokens across eight actions, synthesized
// successfully, and then ended as a system failure with no findings because a
// single statement cited evidence that did not cover an entity it named.
// Validation must keep the bad finding out, not destroy the report.
func TestOneInvalidFindingDoesNotDiscardTheWholeReport(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	request := investigationRequest(now)
	investigation, err := domain.ReconstituteInvestigation(request, domain.InvestigationSynthesizing, "", domain.InvestigationBudgetUsage{Decisions: 1, ToolCalls: 1}, nil, 9)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := InvestigationSnapshot{Investigation: investigation, RequestedOutcome: domain.InvestigationPartial, RequestedStop: domain.StopBudgetExceeded}
	valid := domain.Finding{
		ID: "finding-valid", InvestigationID: request.ID, Kind: domain.FindingRecommendation,
		Statement: "Review the kernel log on the affected host.", EntityIDs: append([]string(nil), request.Scope.EntityIDs...),
		Severity: "INFO", Status: domain.FindingCurrent,
	}
	// Names an entity outside the investigation scope, which the domain rejects.
	invalid := valid
	invalid.ID, invalid.Statement, invalid.EntityIDs = "finding-invalid", "An unrelated host is implicated.", []string{"node-not-in-scope"}
	planner := &scriptedSynthesisPlanner{result: InvestigationSynthesis{Findings: []domain.Finding{valid, invalid}, Disposition: SynthesisValidatedPartial}}
	store := &investigationMemoryStore{found: true, snapshot: snapshot}
	controller := newTestInvestigationController(t, store, planner, &idempotentInvestigationExecutor{receipts: map[string]InvestigationExecutionResult{}}, &investigationClock{now: now})
	result, err := controller.Advance(context.Background(), request.ID)
	if err != nil {
		t.Fatalf("one invalid finding failed the whole transition: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "finding-valid" {
		t.Fatalf("findings=%+v", result.Findings)
	}
	if !result.Investigation.Status().Terminal() {
		t.Fatalf("status=%s", result.Investigation.Status())
	}
}

type scriptedSynthesisPlanner struct{ result InvestigationSynthesis }

func (planner *scriptedSynthesisPlanner) Decide(context.Context, InvestigationSnapshot) (InvestigationDecision, error) {
	return InvestigationDecision{Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopBudgetExceeded}, nil
}

func (planner *scriptedSynthesisPlanner) Synthesize(context.Context, InvestigationSnapshot) (InvestigationSynthesis, error) {
	return planner.result, nil
}

func TestExhaustedToolCallsStillSynthesizeWhileTokensRemain(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	request := investigationRequest(now)
	request.Budget.MaxDecisions = 8
	request.Budget.MaxToolCalls = 8
	request.Budget.MaxModelTokens = 120_000
	request.Budget.MaxCostMicros = 1_200_000
	// Every tool call and decision is spent; most of the token budget is not.
	usage := domain.InvestigationBudgetUsage{Decisions: 8, ToolCalls: 8, ModelTokens: 57_502, CostMicros: 423_135}
	investigation, err := domain.ReconstituteInvestigation(request, domain.InvestigationPlanning, "", usage, nil, 51)
	if err != nil {
		t.Fatal(err)
	}
	// The script is indexed by decisions already spent, so the preflight stop is
	// the ninth entry.
	decisions := make([]InvestigationDecision, 8)
	decisions = append(decisions, InvestigationDecision{Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopBudgetExceeded})
	store := &investigationMemoryStore{found: true, snapshot: InvestigationSnapshot{Investigation: investigation}}
	controller := newTestInvestigationController(t, store, ScriptedInvestigationPlanner{Decisions: decisions}, &idempotentInvestigationExecutor{receipts: map[string]InvestigationExecutionResult{}}, &investigationClock{now: now})
	snapshot, err := controller.Advance(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Investigation.Status() != domain.InvestigationSynthesizing {
		t.Fatalf("status=%s; the report was discarded despite an affordable remainder", snapshot.Investigation.Status())
	}
	if snapshot.RequestedStop != domain.StopBudgetExceeded || snapshot.RequestedOutcome != domain.InvestigationPartial {
		t.Fatalf("requested terminal=%s/%s", snapshot.RequestedOutcome, snapshot.RequestedStop)
	}
	// The stop performed no provider work, so it must not consume a decision.
	if got := snapshot.Investigation.Usage(); got.Decisions != 8 || got.ModelTokens != 57_502 {
		t.Fatalf("a no-work stop consumed budget: %+v", got)
	}
}

func TestInvestigationControllerStopsOverBudgetPolicyActionBeforeExecution(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	request := investigationRequest(now)
	request.Budget.MaxFanOut = 1
	investigation, err := domain.ReconstituteInvestigation(request, domain.InvestigationPolicyCheck, "", domain.InvestigationBudgetUsage{Decisions: 1, ToolCalls: 1, FanOut: 1}, nil, 7)
	if err != nil {
		t.Fatal(err)
	}
	action := domain.InvestigationAction{ID: "over-budget-action", ToolID: "evidence.lookup.v1", Digest: domain.ChecksumSHA256([]byte("over-budget")), FanOut: 2, Targets: []string{"node-1", "node-2"}, Start: request.Scope.Start, End: request.Scope.End}
	store := &investigationMemoryStore{found: true, snapshot: InvestigationSnapshot{Investigation: investigation, ProposedAction: &action}}
	executor := &idempotentInvestigationExecutor{receipts: map[string]InvestigationExecutionResult{}}
	controller := newTestInvestigationController(t, store, ScriptedInvestigationPlanner{}, executor, &investigationClock{now: now})
	snapshot, err := controller.Advance(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Investigation.Status() != domain.InvestigationPartial || snapshot.Investigation.StopReason() != domain.StopBudgetExceeded || executor.calls != 0 {
		t.Fatalf("status=%s reason=%s executor_calls=%d", snapshot.Investigation.Status(), snapshot.Investigation.StopReason(), executor.calls)
	}
}

func TestInvestigationControllerInvokesStructuredSynthesisAndAccountsUsage(t *testing.T) {
	now := time.Date(2026, 8, 20, 14, 0, 0, 0, time.UTC)
	request := investigationRequest(now)
	request.Budget.MaxModelTokens = 100
	request.Budget.MaxCostMicros = 100
	store := &investigationMemoryStore{}
	clock := &investigationClock{now: now}
	planner := &synthesizingPlanner{}
	controller := newTestInvestigationController(t, store, planner, &idempotentInvestigationExecutor{receipts: map[string]InvestigationExecutionResult{}}, clock)
	if _, _, err := controller.Start(context.Background(), StartInvestigationInput{Request: request}); err != nil {
		t.Fatal(err)
	}
	for attempts := 0; attempts < 8; attempts++ {
		if _, err := controller.Advance(context.Background(), request.ID); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, _, _ := store.LoadInvestigation(context.Background(), request.ID)
	if snapshot.Investigation.Status() != domain.InvestigationCompleted || planner.synthesisCalls != 1 {
		t.Fatalf("status=%s synthesis_calls=%d", snapshot.Investigation.Status(), planner.synthesisCalls)
	}
	if snapshot.Investigation.Usage().ModelTokens != 12 || snapshot.Investigation.Usage().CostMicros != 4 || len(snapshot.Findings) != 1 {
		t.Fatalf("usage=%+v findings=%+v", snapshot.Investigation.Usage(), snapshot.Findings)
	}
}

func TestInvestigationControllerPromotesOnlyNoUsefulActionAfterEligibleSynthesis(t *testing.T) {
	for _, test := range []struct {
		name        string
		id          string
		outcome     domain.InvestigationStatus
		stop        domain.InvestigationStopReason
		disposition InvestigationSynthesisDisposition
		wantStatus  domain.InvestigationStatus
		wantStop    domain.InvestigationStopReason
	}{
		{name: "complete report promotes no useful action", id: "investigation-complete-report", outcome: domain.InvestigationPartial, stop: domain.StopNoUsefulAction, disposition: SynthesisValidatedComplete, wantStatus: domain.InvestigationCompleted, wantStop: domain.StopSuccessCriteriaMet},
		{name: "complete report permits requested success", id: "investigation-requested-success", outcome: domain.InvestigationCompleted, stop: domain.StopSuccessCriteriaMet, disposition: SynthesisValidatedComplete, wantStatus: domain.InvestigationCompleted, wantStop: domain.StopSuccessCriteriaMet},
		{name: "partial report downgrades requested success", id: "investigation-partial-report", outcome: domain.InvestigationCompleted, stop: domain.StopSuccessCriteriaMet, disposition: SynthesisValidatedPartial, wantStatus: domain.InvestigationPartial, wantStop: domain.StopNoUsefulAction},
		{name: "fallback downgrades requested success", id: "investigation-fallback-report", outcome: domain.InvestigationCompleted, stop: domain.StopSuccessCriteriaMet, disposition: SynthesisSafeFallback, wantStatus: domain.InvestigationPartial, wantStop: domain.StopNoUsefulAction},
		{name: "budget remains partial", id: "investigation-budget-partial", outcome: domain.InvestigationPartial, stop: domain.StopBudgetExceeded, disposition: SynthesisValidatedComplete, wantStatus: domain.InvestigationPartial, wantStop: domain.StopBudgetExceeded},
		{name: "access remains blocked", id: "investigation-access-blocked", outcome: domain.InvestigationBlocked, stop: domain.StopAccessUnavailable, disposition: SynthesisValidatedComplete, wantStatus: domain.InvestigationBlocked, wantStop: domain.StopAccessUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
			request := investigationRequest(now)
			request.ID = domain.InvestigationID(test.id)
			request.Budget.MaxModelTokens = 100
			request.Budget.MaxCostMicros = 100
			store := &investigationMemoryStore{}
			planner := &terminalSynthesisPlanner{outcome: test.outcome, stop: test.stop, disposition: test.disposition}
			controller := newTestInvestigationController(t, store, planner, &idempotentInvestigationExecutor{receipts: map[string]InvestigationExecutionResult{}}, &investigationClock{now: now})
			if _, _, err := controller.Start(context.Background(), StartInvestigationInput{Request: request}); err != nil {
				t.Fatal(err)
			}
			for attempts := 0; attempts < 8; attempts++ {
				if _, err := controller.Advance(context.Background(), request.ID); err != nil {
					t.Fatal(err)
				}
			}
			snapshot, _, _ := store.LoadInvestigation(context.Background(), request.ID)
			if snapshot.Investigation.Status() != test.wantStatus || snapshot.Investigation.StopReason() != test.wantStop {
				t.Fatalf("status=%s stop=%s", snapshot.Investigation.Status(), snapshot.Investigation.StopReason())
			}
		})
	}
}

func TestSynthesisTerminalContractRejectsInvalidPairsAndDisposition(t *testing.T) {
	for _, test := range []struct {
		outcome domain.InvestigationStatus
		reason  domain.InvestigationStopReason
	}{
		{outcome: domain.InvestigationCompleted, reason: domain.StopBudgetExceeded},
		{outcome: domain.InvestigationPartial, reason: domain.StopSuccessCriteriaMet},
		{outcome: domain.InvestigationBlocked, reason: domain.StopOperatorCancelled},
	} {
		if err := validateRequestedTerminal(test.outcome, test.reason); err == nil {
			t.Fatalf("accepted invalid terminal pair %s/%s", test.outcome, test.reason)
		}
	}
	if err := InvestigationSynthesisDisposition("").Validate(); err == nil {
		t.Fatal("accepted missing synthesis disposition")
	}
	if _, _, err := resolveSynthesisTerminal(domain.InvestigationCompleted, domain.StopSuccessCriteriaMet, InvestigationSynthesisDisposition("UNKNOWN")); err == nil {
		t.Fatal("accepted unknown synthesis disposition")
	}
}

type synthesizingPlanner struct{ synthesisCalls int }

type completeScriptedPlanner struct{ ScriptedInvestigationPlanner }

func (completeScriptedPlanner) Synthesize(context.Context, InvestigationSnapshot) (InvestigationSynthesis, error) {
	return InvestigationSynthesis{Disposition: SynthesisValidatedComplete}, nil
}

type terminalSynthesisPlanner struct {
	outcome     domain.InvestigationStatus
	stop        domain.InvestigationStopReason
	disposition InvestigationSynthesisDisposition
}

func (planner *terminalSynthesisPlanner) Decide(context.Context, InvestigationSnapshot) (InvestigationDecision, error) {
	return InvestigationDecision{Stop: true, Outcome: planner.outcome, Reason: planner.stop}, nil
}

func (planner *terminalSynthesisPlanner) Synthesize(_ context.Context, snapshot InvestigationSnapshot) (InvestigationSynthesis, error) {
	return InvestigationSynthesis{Disposition: planner.disposition, Findings: []domain.Finding{{ID: "eligible-report", InvestigationID: snapshot.Investigation.Request().ID, Kind: domain.FindingRecommendation, Statement: "Continue bounded operator review.", EntityIDs: []string{"node-1"}, Severity: "INFO", Status: domain.FindingCurrent}}}, nil
}

func (*synthesizingPlanner) Decide(context.Context, InvestigationSnapshot) (InvestigationDecision, error) {
	return InvestigationDecision{Stop: true, Outcome: domain.InvestigationCompleted, Reason: domain.StopSuccessCriteriaMet}, nil
}

func (planner *synthesizingPlanner) Synthesize(_ context.Context, snapshot InvestigationSnapshot) (InvestigationSynthesis, error) {
	planner.synthesisCalls++
	return InvestigationSynthesis{Disposition: SynthesisValidatedComplete, ModelTokens: 12, CostMicros: 4, Findings: []domain.Finding{{ID: "finding-synthesis", InvestigationID: snapshot.Investigation.Request().ID, Kind: domain.FindingRecommendation, Statement: "Continue operator review.", EntityIDs: []string{"node-1"}, Severity: "INFO", Status: domain.FindingCurrent}}}, nil
}

func investigationRequest(now time.Time) domain.InvestigationRequest {
	return domain.InvestigationRequest{ID: "investigation-1", IncidentID: "incident-1", ClusterID: "cluster-1", Question: "Why is node-1 unhealthy?", RequestedBy: "actor-1", IdempotencyKey: "request-1", Scope: domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now}, SuccessCriteria: []string{"record a supported outcome"}, Budget: domain.InvestigationBudget{MaxDecisions: 4, MaxToolCalls: 2, MaxPrivilegedCalls: 1, MaxFanOut: 2}, RequestedAt: now, Deadline: now.Add(time.Hour)}
}

func newTestInvestigationController(t *testing.T, store InvestigationStore, planner InvestigationPlanner, executor InvestigationExecutor, clock Clock) *InvestigationController {
	t.Helper()
	controller, err := NewInvestigationController(store, planner, executor, clock, &investigationIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

type investigationClock struct{ now time.Time }

func (clock *investigationClock) Now() time.Time {
	clock.now = clock.now.Add(time.Second)
	return clock.now
}

type investigationIDs struct {
	mu   sync.Mutex
	next int
}

func (ids *investigationIDs) NewID() (string, error) {
	ids.mu.Lock()
	defer ids.mu.Unlock()
	ids.next++
	return "event-" + time.Unix(int64(ids.next), 0).UTC().Format("150405"), nil
}

type investigationMemoryStore struct {
	snapshot            InvestigationSnapshot
	found               bool
	failNextSave        bool
	failedExecutionSave bool
}

func (store *investigationMemoryStore) CreateInvestigation(_ context.Context, snapshot InvestigationSnapshot, _ domain.InvestigationEvent) (bool, error) {
	if store.found {
		return false, nil
	}
	store.snapshot, store.found = snapshot, true
	return true, nil
}
func (store *investigationMemoryStore) LoadInvestigation(_ context.Context, _ domain.InvestigationID) (InvestigationSnapshot, bool, error) {
	return store.snapshot, store.found, nil
}
func (store *investigationMemoryStore) SaveInvestigation(_ context.Context, version int, snapshot InvestigationSnapshot, _ domain.InvestigationEvent) error {
	if store.snapshot.Investigation.Version() != version {
		return ErrInvestigationConflict
	}
	if store.failNextSave {
		store.failNextSave = false
		store.failedExecutionSave = true
		return errors.New("simulated crash before commit")
	}
	store.snapshot = snapshot
	return nil
}
func (store *investigationMemoryStore) RecordInvestigationApproval(ctx context.Context, _ domain.InvestigationApproval, version int, snapshot InvestigationSnapshot, event domain.InvestigationEvent) error {
	return store.SaveInvestigation(ctx, version, snapshot, event)
}

type idempotentInvestigationExecutor struct {
	calls       int
	sideEffects int
	evidence    []domain.InvestigationEvidence
	receipts    map[string]InvestigationExecutionResult
}

func (executor *idempotentInvestigationExecutor) ExecuteInvestigationAction(_ context.Context, key string, _ domain.InvestigationAction) (InvestigationExecutionResult, error) {
	executor.calls++
	if prior, ok := executor.receipts[key]; ok {
		return prior, nil
	}
	executor.sideEffects++
	result := InvestigationExecutionResult{Receipt: "receipt-1", Evidence: cloneInvestigationEvidence(executor.evidence)}
	executor.receipts[key] = result
	return result, nil
}

// pendingThenCompletingExecutor models a remote execution: the first calls
// report the work as still outstanding, and a later one returns its result.
// It counts remote side effects separately from calls, because the property
// that matters is that repeated dispatch of the same action executes once.
type pendingThenCompletingExecutor struct {
	pendingCalls int
	calls        int
	sideEffects  int
	dispatched   map[string]bool
	evidence     []domain.InvestigationEvidence
}

func (executor *pendingThenCompletingExecutor) ExecuteInvestigationAction(_ context.Context, key string, action domain.InvestigationAction) (InvestigationExecutionResult, error) {
	executor.calls++
	if !executor.dispatched[key] {
		if executor.dispatched == nil {
			executor.dispatched = map[string]bool{}
		}
		executor.dispatched[key] = true
		executor.sideEffects++
	}
	if executor.calls <= executor.pendingCalls {
		return InvestigationExecutionResult{}, ErrInvestigationExecutionPending
	}
	result := InvestigationExecutionResult{Receipt: "receipt-1", Evidence: cloneInvestigationEvidence(executor.evidence)}
	if action.Diagnostic {
		result.DiagnosticRunID = "diagnostic-run-1"
	}
	return result, nil
}

// An outstanding remote execution must park the investigation in a state that
// says so, perform no transition on the work, and resume when the result
// arrives -- without executing twice.
func TestOutstandingExecutionParksAndResumesWithoutExecutingTwice(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	request := investigationRequest(now)
	request.Budget.MaxDiagnosticCalls = 2
	action := domain.InvestigationAction{
		ID: "action-diagnostic", ToolID: "gpu.ecc_counters.v1", Digest: domain.ChecksumSHA256([]byte("ecc")),
		Diagnostic: true, FanOut: 1, Targets: []string{"node-1"}, Start: request.Scope.Start, End: request.Scope.End,
	}
	store := &investigationMemoryStore{}
	executor := &pendingThenCompletingExecutor{pendingCalls: 3}
	planner := completeScriptedPlanner{ScriptedInvestigationPlanner: ScriptedInvestigationPlanner{Decisions: []InvestigationDecision{
		{Action: &action},
		{Stop: true, Outcome: domain.InvestigationCompleted, Reason: domain.StopSuccessCriteriaMet},
	}}}
	controller := newTestInvestigationController(t, store, planner, executor, &investigationClock{now: now})
	if _, created, err := controller.Start(context.Background(), StartInvestigationInput{Request: request}); err != nil || !created {
		t.Fatalf("start: created=%t err=%v", created, err)
	}
	// Advance to EXECUTING.
	for {
		snapshot, err := controller.Advance(context.Background(), request.ID)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Investigation.Status() == domain.InvestigationAwaitingEvidence {
			break
		}
		if snapshot.Investigation.Status().Terminal() {
			t.Fatalf("reached %s before dispatching", snapshot.Investigation.Status())
		}
	}
	parked, _, err := store.LoadInvestigation(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if parked.Investigation.Status() != domain.InvestigationAwaitingEvidence {
		t.Fatalf("status = %s, want AWAITING_EVIDENCE", parked.Investigation.Status())
	}
	if parked.Investigation.Usage().DiagnosticCalls != 1 {
		t.Fatalf("the diagnostic grant must be spent once at admission: %d", parked.Investigation.Usage().DiagnosticCalls)
	}
	version := parked.Investigation.Version()

	// Repeated claims while the work is outstanding neither advance the
	// investigation nor dispatch it a second time. This is the investigator
	// restart case: the lease is released and reclaimed, and the run is exactly
	// where it was.
	for attempt := 0; attempt < 2; attempt++ {
		snapshot, err := controller.Advance(context.Background(), request.ID)
		if err != nil {
			t.Fatalf("advance while pending: %v", err)
		}
		if snapshot.Investigation.Status() != domain.InvestigationAwaitingEvidence {
			t.Fatalf("a pending execution changed state to %s", snapshot.Investigation.Status())
		}
		if snapshot.Investigation.Version() != version {
			t.Fatalf("a pending execution advanced the version from %d to %d", version, snapshot.Investigation.Version())
		}
	}
	if executor.sideEffects != 1 {
		t.Fatalf("remote side effects = %d, want exactly 1 across %d dispatches", executor.sideEffects, executor.calls)
	}

	// When the result arrives the parked run resumes through the ordinary path.
	for step := 0; step < 6; step++ {
		snapshot, err := controller.Advance(context.Background(), request.ID)
		if err != nil {
			t.Fatalf("advance after completion: %v", err)
		}
		if snapshot.Investigation.Status().Terminal() {
			break
		}
	}
	final, _, err := store.LoadInvestigation(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Investigation.Status() == domain.InvestigationAwaitingEvidence {
		t.Fatal("the investigation never left AWAITING_EVIDENCE after its result arrived")
	}
	if executor.sideEffects != 1 {
		t.Fatalf("remote side effects = %d after resumption, want 1", executor.sideEffects)
	}
	if len(final.PriorActions) != 1 || final.PriorActions[0].Digest != action.Digest {
		t.Fatalf("the resumed action was not recorded exactly once: %+v", final.PriorActions)
	}
}

// A parked investigation must still respect its deadline: parking is not a way
// to outlive the bound an operator set.
func TestParkedInvestigationStillHonoursItsDeadline(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	request := investigationRequest(now)
	request.Budget.MaxDiagnosticCalls = 1
	action := domain.InvestigationAction{
		ID: "action-diagnostic", ToolID: "gpu.ecc_counters.v1", Digest: domain.ChecksumSHA256([]byte("ecc")),
		Diagnostic: true, FanOut: 1, Targets: []string{"node-1"}, Start: request.Scope.Start, End: request.Scope.End,
	}
	store := &investigationMemoryStore{}
	clock := &investigationClock{now: now}
	executor := &pendingThenCompletingExecutor{pendingCalls: 100}
	controller := newTestInvestigationController(t, store, ScriptedInvestigationPlanner{Decisions: []InvestigationDecision{{Action: &action}}}, executor, clock)
	if _, _, err := controller.Start(context.Background(), StartInvestigationInput{Request: request}); err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 5; step++ {
		snapshot, err := controller.Advance(context.Background(), request.ID)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Investigation.Status() == domain.InvestigationAwaitingEvidence {
			break
		}
	}
	clock.now = request.Deadline.Add(time.Minute)
	snapshot, err := controller.Advance(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Investigation.Status().Terminal() {
		t.Fatalf("a parked investigation outlived its deadline in state %s", snapshot.Investigation.Status())
	}
}

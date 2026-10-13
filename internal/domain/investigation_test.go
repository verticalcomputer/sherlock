package domain

import (
	"errors"
	"testing"
	"time"
)

func TestInvestigationHappyPathAndImmutableRequest(t *testing.T) {
	now := investigationTestTime()
	request := validInvestigationRequest(now)
	investigation, err := NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Scope.EntityIDs[0] = "mutated"
	if got := investigation.Request().Scope.EntityIDs[0]; got != "node-1" {
		t.Fatalf("stored request was mutated: %q", got)
	}

	investigation = transitionInvestigation(t, investigation, now, func(value Investigation) (Investigation, error) {
		return value.BeginPlanning(now)
	})
	investigation = transitionInvestigation(t, investigation, now, func(value Investigation) (Investigation, error) {
		return value.RecordDecision(InvestigationBudgetUsage{Decisions: 1, ModelTokens: 100, CostMicros: 10}, now)
	})
	investigation = transitionInvestigation(t, investigation, now, func(value Investigation) (Investigation, error) {
		return value.BeginPolicyCheck(now)
	})
	action := InvestigationAction{ID: "action-1", ToolID: "gpu.xid.v1", Digest: ChecksumSHA256([]byte("action")), FanOut: 1}
	investigation = transitionInvestigation(t, investigation, now, func(value Investigation) (Investigation, error) {
		return value.Execute(action, now)
	})
	investigation = transitionInvestigation(t, investigation, now, func(value Investigation) (Investigation, error) {
		return value.BeginEvidenceRecording(now)
	})
	investigation = transitionInvestigation(t, investigation, now, func(value Investigation) (Investigation, error) {
		return value.BeginLedgerUpdate(now)
	})
	investigation = transitionInvestigation(t, investigation, now, func(value Investigation) (Investigation, error) {
		return value.BeginSynthesis(now)
	})
	investigation = transitionInvestigation(t, investigation, now, func(value Investigation) (Investigation, error) {
		return value.Complete(now)
	})

	if investigation.Status() != InvestigationCompleted || !investigation.Status().Terminal() || investigation.StopReason() != StopSuccessCriteriaMet {
		t.Fatalf("unexpected completion: status=%s reason=%s", investigation.Status(), investigation.StopReason())
	}
	if investigation.Usage() != (InvestigationBudgetUsage{Decisions: 1, ToolCalls: 1, FanOut: 1, ModelTokens: 100, CostMicros: 10}) {
		t.Fatalf("unexpected usage: %+v", investigation.Usage())
	}
	if _, err := investigation.BeginPlanning(now); err == nil {
		t.Fatal("expected terminal transition rejection")
	} else {
		var conflict TransitionConflictError
		if !errors.As(err, &conflict) {
			t.Fatalf("terminal transition error = %T, want TransitionConflictError", err)
		}
	}
}

func TestInvestigationFanOutTracksPeakBatchInsteadOfCumulativeTargets(t *testing.T) {
	now := investigationTestTime()
	request := validInvestigationRequest(now)
	request.Budget.MaxToolCalls = 2
	request.Budget.MaxFanOut = 2
	investigation, err := NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	investigation, _ = investigation.BeginPlanning(now)
	investigation, _ = investigation.BeginPolicyCheck(now)
	first := InvestigationAction{ID: "action-1", ToolID: "gpu.xid.v1", Digest: ChecksumSHA256([]byte("action-1")), FanOut: 2}
	investigation, err = investigation.Execute(first, now)
	if err != nil {
		t.Fatal(err)
	}
	investigation, _ = investigation.BeginEvidenceRecording(now)
	investigation, _ = investigation.BeginLedgerUpdate(now)
	investigation, _ = investigation.BeginPlanning(now)
	investigation, _ = investigation.BeginPolicyCheck(now)
	second := InvestigationAction{ID: "action-2", ToolID: "gpu.xid.v1", Digest: ChecksumSHA256([]byte("action-2")), FanOut: 2}
	investigation, err = investigation.Execute(second, now)
	if err != nil {
		t.Fatal(err)
	}
	if usage := investigation.Usage(); usage.ToolCalls != 2 || usage.FanOut != 2 {
		t.Fatalf("usage=%+v", usage)
	}
}

func TestInvestigationApprovalIsActionAndVersionBound(t *testing.T) {
	now := investigationTestTime()
	investigation, err := NewInvestigation(validInvestigationRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	investigation, _ = investigation.BeginPlanning(now)
	investigation, _ = investigation.BeginPolicyCheck(now)
	action := InvestigationAction{ID: "action-1", ToolID: "node.kernel.v1", Digest: ChecksumSHA256([]byte("action-1")), Privileged: true, FanOut: 2}
	investigation, err = investigation.AwaitApproval(action, now)
	if err != nil {
		t.Fatal(err)
	}
	approval := InvestigationApproval{
		ID: "approval-1", InvestigationID: investigation.Request().ID, ActionID: action.ID,
		ActionDigest: action.Digest, InvestigationVersion: investigation.Version(), ApprovedBy: "operator-1",
		ApprovedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}

	mismatched := approval
	mismatched.ActionDigest = ChecksumSHA256([]byte("different"))
	if _, err := investigation.Approve(mismatched, now.Add(time.Minute)); err == nil {
		t.Fatal("expected mismatched action rejection")
	}
	stale := approval
	stale.InvestigationVersion--
	if _, err := investigation.Approve(stale, now.Add(time.Minute)); err == nil {
		t.Fatal("expected stale approval rejection")
	}
	if _, err := investigation.Approve(approval, now.Add(6*time.Minute)); err == nil {
		t.Fatal("expected expired approval rejection")
	}

	investigation, err = investigation.Approve(approval, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if investigation.Status() != InvestigationExecuting || investigation.Usage().PrivilegedCalls != 1 || investigation.Usage().ToolCalls != 1 {
		t.Fatalf("approval did not start bounded action: status=%s usage=%+v", investigation.Status(), investigation.Usage())
	}
	if _, exists := investigation.PendingAction(); exists {
		t.Fatal("approved action remained pending")
	}
}

func TestInvestigationBudgetsFailClosedAndStopExplicitly(t *testing.T) {
	now := investigationTestTime()
	request := validInvestigationRequest(now)
	request.Budget.MaxDecisions = 1
	investigation, err := NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	investigation, _ = investigation.BeginPlanning(now)
	investigation, err = investigation.RecordDecision(InvestigationBudgetUsage{Decisions: 1}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := investigation.RecordDecision(InvestigationBudgetUsage{Decisions: 1}, now); err == nil {
		t.Fatal("expected decision budget rejection")
	}
	stopped, err := investigation.Stop(InvestigationPartial, StopBudgetExceeded, now)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Status() != InvestigationPartial || stopped.StopReason() != StopBudgetExceeded {
		t.Fatalf("unexpected stop: status=%s reason=%s", stopped.Status(), stopped.StopReason())
	}
}

func TestInvestigationCancellationIsTerminalFromApprovalWait(t *testing.T) {
	now := investigationTestTime()
	investigation, _ := NewInvestigation(validInvestigationRequest(now))
	investigation, _ = investigation.BeginPlanning(now)
	investigation, _ = investigation.BeginPolicyCheck(now)
	investigation, _ = investigation.AwaitApproval(InvestigationAction{
		ID: "action-1", ToolID: "node.kernel.v1", Digest: ChecksumSHA256([]byte("action")), Privileged: true, FanOut: 1,
	}, now)
	cancelled, err := investigation.Cancel(now)
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.Status() != InvestigationCancelled || cancelled.StopReason() != StopOperatorCancelled {
		t.Fatalf("unexpected cancellation: status=%s reason=%s", cancelled.Status(), cancelled.StopReason())
	}
	if _, pending := cancelled.PendingAction(); pending {
		t.Fatal("cancelled investigation retained a pending action")
	}
	if _, err := cancelled.Cancel(now); err == nil {
		t.Fatal("expected repeat cancellation rejection")
	}
}

func TestInvestigationLedgersRejectInvalidScopeCitationsAndVersions(t *testing.T) {
	now := investigationTestTime()
	investigation, _ := NewInvestigation(validInvestigationRequest(now))
	investigation, _ = investigation.BeginPlanning(now)
	investigation, _ = investigation.BeginPolicyCheck(now)
	investigation, _ = investigation.Execute(InvestigationAction{ID: "action-1", ToolID: "gpu.xid.v1", Digest: ChecksumSHA256([]byte("action")), FanOut: 1}, now)
	investigation, _ = investigation.BeginEvidenceRecording(now)

	entry := InvestigationEvidence{EvidenceID: "evidence-1", InvestigationID: investigation.Request().ID, ClusterID: investigation.Request().ClusterID, EntityIDs: []string{"node-1"}, Status: EvidenceComplete, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now}
	ledger, err := NewEvidenceLedger([]InvestigationEvidence{entry}, investigation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Append(entry, investigation); err == nil {
		t.Fatal("expected duplicate evidence rejection")
	}
	outOfScope := entry
	outOfScope.EvidenceID = "evidence-2"
	outOfScope.EntityIDs = []string{"node-99"}
	if _, err := ledger.Append(outOfScope, investigation); err == nil {
		t.Fatal("expected out-of-scope evidence rejection")
	}

	investigation, _ = investigation.BeginLedgerUpdate(now)
	hypothesis := Hypothesis{ID: "hypothesis-1", InvestigationID: investigation.Request().ID, Statement: "GPU reset caused the outage", Status: HypothesisSupported, Confidence: .8, SupportingEvidence: []EvidenceID{"evidence-1"}, Version: 1}
	hypotheses, err := (HypothesisLedger{}).Upsert(hypothesis, ledger, investigation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hypotheses.Upsert(hypothesis, ledger, investigation); err == nil {
		t.Fatal("expected stale hypothesis update rejection")
	}
	hypothesis.Version = 2
	hypothesis.SupportingEvidence = []EvidenceID{"missing"}
	if _, err := hypotheses.Upsert(hypothesis, ledger, investigation); err == nil {
		t.Fatal("expected nonexistent hypothesis citation rejection")
	}
	proposed := Hypothesis{ID: "hypothesis-2", InvestigationID: investigation.Request().ID, Statement: "The scheduler may have drained the node", Status: HypothesisProposed, Confidence: .2, Version: 1}
	if _, err := hypotheses.Upsert(proposed, ledger, investigation); err != nil {
		t.Fatalf("uncited proposed hypothesis should be allowed: %v", err)
	}
}

func TestFindingValidationEnforcesKindConfidenceScopeAndCitations(t *testing.T) {
	now := investigationTestTime()
	investigation, _ := NewInvestigation(validInvestigationRequest(now))
	investigation, _ = investigation.BeginPlanning(now)
	investigation, _ = investigation.BeginPolicyCheck(now)
	investigation, _ = investigation.Execute(InvestigationAction{ID: "action-1", ToolID: "gpu.xid.v1", Digest: ChecksumSHA256([]byte("action")), FanOut: 1}, now)
	investigation, _ = investigation.BeginEvidenceRecording(now)
	ledger, _ := NewEvidenceLedger([]InvestigationEvidence{{EvidenceID: "evidence-1", InvestigationID: investigation.Request().ID, ClusterID: investigation.Request().ClusterID, EntityIDs: []string{"node-1"}, Status: EvidenceComplete, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now}}, investigation)
	confidence := .9
	finding := Finding{ID: "finding-1", InvestigationID: investigation.Request().ID, Kind: FindingHypothesis, Statement: "A GPU reset likely occurred", EntityIDs: []string{"node-1"}, Severity: "WARNING", Confidence: &confidence, EvidenceIDs: []EvidenceID{"evidence-1"}, Status: FindingCurrent}
	if err := finding.Validate(ledger, investigation); err != nil {
		t.Fatal(err)
	}
	finding.Kind = FindingObservation
	if err := finding.Validate(ledger, investigation); err == nil {
		t.Fatal("expected confidence on observation rejection")
	}
	finding.Confidence = nil
	finding.EvidenceIDs = []EvidenceID{"missing"}
	if err := finding.Validate(ledger, investigation); err == nil {
		t.Fatal("expected missing citation rejection")
	}
	finding.EvidenceIDs = []EvidenceID{"evidence-1"}
	finding.EntityIDs = []string{"node-2"}
	if err := finding.Validate(ledger, investigation); err == nil {
		t.Fatal("expected entity/evidence coverage mismatch rejection")
	}
	finding.EntityIDs = []string{"node-99"}
	if err := finding.Validate(ledger, investigation); err == nil {
		t.Fatal("expected out-of-scope finding rejection")
	}
}

func TestReconstituteInvestigationRejectsImpossibleState(t *testing.T) {
	now := investigationTestTime()
	request := validInvestigationRequest(now)
	if _, err := ReconstituteInvestigation(request, InvestigationCompleted, "", InvestigationBudgetUsage{}, nil, 2); err == nil {
		t.Fatal("expected missing terminal reason rejection")
	}
	if _, err := ReconstituteInvestigation(request, InvestigationCompleted, StopBudgetExceeded, InvestigationBudgetUsage{}, nil, 2); err == nil {
		t.Fatal("expected completed investigation with limiting reason rejection")
	}
	if _, err := ReconstituteInvestigation(request, InvestigationAwaitingApproval, "", InvestigationBudgetUsage{}, nil, 2); err == nil {
		t.Fatal("expected missing pending action rejection")
	}
	tooMuch := InvestigationBudgetUsage{ToolCalls: request.Budget.MaxToolCalls + 1}
	if _, err := ReconstituteInvestigation(request, InvestigationPlanning, "", tooMuch, nil, 2); err == nil {
		t.Fatal("expected over-budget state rejection")
	}
}

func TestLedgersAndEventHistoryCanBeReconstitutedAfterCompletion(t *testing.T) {
	now := investigationTestTime()
	investigation, err := ReconstituteInvestigation(validInvestigationRequest(now), InvestigationCompleted, StopSuccessCriteriaMet, InvestigationBudgetUsage{}, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := NewEvidenceLedger([]InvestigationEvidence{{
		EvidenceID: "evidence-1", InvestigationID: investigation.Request().ID, ClusterID: investigation.Request().ClusterID,
		EntityIDs: []string{"node-1"}, Status: EvidenceComplete, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now,
	}}, investigation)
	if err != nil || !ledger.Contains("evidence-1") {
		t.Fatalf("reconstitute evidence ledger: ledger=%+v err=%v", ledger, err)
	}
	confidence := .75
	finding := Finding{ID: "finding-1", InvestigationID: investigation.Request().ID, Kind: FindingHypothesis, Statement: "A reset likely occurred", EntityIDs: []string{"node-1"}, Severity: "WARNING", Confidence: &confidence, EvidenceIDs: []EvidenceID{"evidence-1"}, Status: FindingCurrent}
	findings, err := NewFindingLedger([]Finding{finding}, ledger, investigation)
	if err != nil || len(findings.Entries()) != 1 {
		t.Fatalf("reconstitute finding ledger: findings=%d err=%v", len(findings.Entries()), err)
	}

	events := []InvestigationEvent{
		{ID: "event-1", InvestigationID: investigation.Request().ID, Sequence: 1, Kind: InvestigationEventCreated, OccurredAt: now},
		{ID: "event-2", InvestigationID: investigation.Request().ID, Sequence: 2, Kind: InvestigationEventStateChanged, From: InvestigationInitializing, To: InvestigationPlanning, OccurredAt: now.Add(time.Second)},
	}
	history, err := NewInvestigationEventHistory(events, investigation.Request().ID)
	if err != nil || len(history.Events()) != 2 {
		t.Fatalf("reconstitute event history: events=%d err=%v", len(history.Events()), err)
	}
	bad := events[1]
	bad.Sequence = 4
	if _, err := (InvestigationEventHistory{}).Append(bad, investigation.Request().ID); err == nil {
		t.Fatal("expected event sequence gap rejection")
	}
}

func validInvestigationRequest(now time.Time) InvestigationRequest {
	return InvestigationRequest{
		ID: "investigation-1", IncidentID: "incident-1", ClusterID: "cluster-1", Question: "Why is node-1 unhealthy?",
		RequestedBy: "actor-1", IdempotencyKey: "request-1",
		Scope:           InvestigationScope{EntityKind: "NODE", EntityIDs: []string{"node-1", "node-2"}, Start: now.Add(-time.Hour), End: now},
		SuccessCriteria: []string{"Identify the supported cause or state the remaining uncertainty."},
		Budget:          InvestigationBudget{MaxDecisions: 3, MaxToolCalls: 3, MaxPrivilegedCalls: 1, MaxFanOut: 8, MaxModelTokens: 1000, MaxCostMicros: 1000},
		RequestedAt:     now, Deadline: now.Add(10 * time.Minute),
	}
}

func investigationTestTime() time.Time {
	return time.Date(2026, 8, 20, 4, 0, 0, 0, time.UTC)
}

func TestActionCardValidatesOwnershipAndDurableCitations(t *testing.T) {
	now := investigationTestTime()
	investigation, err := NewInvestigation(validInvestigationRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	evidence := InvestigationEvidence{EvidenceID: "evidence-1", InvestigationID: investigation.Request().ID, ClusterID: investigation.Request().ClusterID, EntityIDs: []string{"node-1"}, Status: EvidenceComplete, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now}
	ledger, err := NewEvidenceLedger([]InvestigationEvidence{evidence}, investigation)
	if err != nil {
		t.Fatal(err)
	}
	card, err := NewActionCard("action-card-1", investigation, ledger, ActionCardInput{
		Owner: ActionOwnerClusterOperations, Action: "Drain node-1 and collect a fresh GPU snapshot.", Urgency: ActionUrgencyNextShift,
		Targets: []string{"node-1"}, Rationale: "The cited GPU state remains degraded.", EvidenceIDs: []EvidenceID{"evidence-1"},
		BlockingGaps: []string{"Kernel events are not yet available."}, EscalationCondition: "Escalate if the GPU remains degraded after the drain.",
	})
	if err != nil {
		t.Fatal(err)
	}
	clone := CloneActionCard(&card)
	clone.Targets[0] = "changed"
	if card.Targets[0] != "node-1" {
		t.Fatal("action-card clone shared target storage")
	}
	bad := card
	bad.EvidenceIDs = []EvidenceID{"missing"}
	if err := bad.Validate(ledger, investigation); err == nil {
		t.Fatal("action card accepted a citation outside the durable ledger")
	}
	bad = card
	bad.Owner = "UNASSIGNED"
	if err := bad.Validate(ledger, investigation); err == nil {
		t.Fatal("action card accepted an unknown owner")
	}
}

func transitionInvestigation(t *testing.T, investigation Investigation, now time.Time, transition func(Investigation) (Investigation, error)) Investigation {
	t.Helper()
	next, err := transition(investigation)
	if err != nil {
		t.Fatal(err)
	}
	if next.Version() != investigation.Version()+1 {
		t.Fatalf("version did not advance from %d to %d", investigation.Version(), next.Version())
	}
	return next
}

// The diagnostic dimension is separate authority, not a relabelling of the
// tool-call budget: it must be independently exhaustible, must default to
// refusing every diagnostic, and must never be consumable by a planning or
// synthesis turn that only reports token spend.
func TestDiagnosticBudgetIsSeparateAuthorityAndDefaultsToZero(t *testing.T) {
	base := InvestigationBudget{MaxDecisions: 3, MaxToolCalls: 3, MaxFanOut: 8, MaxModelTokens: 1000, MaxCostMicros: 1000}
	if err := base.Validate(); err != nil {
		t.Fatalf("a budget with no diagnostic grant must remain valid: %v", err)
	}
	if base.MaxDiagnosticCalls != 0 {
		t.Fatalf("MaxDiagnosticCalls default = %d, want 0", base.MaxDiagnosticCalls)
	}
	if base.Allows(InvestigationBudgetUsage{DiagnosticCalls: 1}) {
		t.Fatal("a zero diagnostic budget must refuse the first diagnostic")
	}
	if !base.Allows(InvestigationBudgetUsage{ToolCalls: 3}) {
		t.Fatal("evidence lookups must be unaffected by the diagnostic dimension")
	}

	granted := base
	granted.MaxDiagnosticCalls = 2
	for _, count := range []int{0, 1, 2} {
		if !granted.Allows(InvestigationBudgetUsage{DiagnosticCalls: count}) {
			t.Fatalf("a grant of 2 must admit %d diagnostics", count)
		}
	}
	if granted.Allows(InvestigationBudgetUsage{DiagnosticCalls: 3}) {
		t.Fatal("a grant of 2 must refuse the third diagnostic")
	}
	// Diagnostics must not be payable out of the evidence-lookup budget, nor
	// the reverse: exhausting one dimension leaves the other intact.
	if !granted.Allows(InvestigationBudgetUsage{ToolCalls: 3, DiagnosticCalls: 2}) {
		t.Fatal("both dimensions must be spendable in full within one run")
	}
	if granted.Allows(InvestigationBudgetUsage{ToolCalls: 4, DiagnosticCalls: 0}) {
		t.Fatal("a diagnostic grant must not raise the evidence-lookup ceiling")
	}
	if (InvestigationBudget{MaxDecisions: 1, MaxToolCalls: 1, MaxDiagnosticCalls: -1, MaxFanOut: 1}).Validate() == nil {
		t.Fatal("a negative diagnostic limit must be rejected")
	}
	if (InvestigationBudgetUsage{DiagnosticCalls: -1}).Validate() == nil {
		t.Fatal("negative diagnostic usage must be rejected")
	}
}

func TestDiagnosticUsageCannotBeChargedToPlanningOrSynthesis(t *testing.T) {
	now := investigationTestTime()
	request := validInvestigationRequest(now)
	request.Budget.MaxDiagnosticCalls = 2
	investigation, err := NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	investigation, _ = investigation.BeginPlanning(now)
	if _, err := investigation.RecordDecision(InvestigationBudgetUsage{Decisions: 1, DiagnosticCalls: 1}, now); err == nil {
		t.Fatal("a planning turn must not be able to consume diagnostic authority")
	}
	investigation, err = investigation.RecordDecision(InvestigationBudgetUsage{Decisions: 1}, now)
	if err != nil {
		t.Fatal(err)
	}
	if investigation.Usage().DiagnosticCalls != 0 {
		t.Fatalf("planning consumed diagnostic calls: %d", investigation.Usage().DiagnosticCalls)
	}
	synthesizing, err := investigation.BeginSynthesis(now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := synthesizing.RecordModelUsage(InvestigationBudgetUsage{DiagnosticCalls: 1}, now); err == nil {
		t.Fatal("a synthesis call must not be able to consume diagnostic authority")
	}
}

// An action spends the dimension that matches what it does. This is the point
// where the diagnostic grant becomes reachable, so it must be exact: a
// diagnostic must never be payable out of the evidence-lookup grant, and an
// evidence lookup must never be payable out of the diagnostic grant.
func TestDiagnosticActionSpendsTheDiagnosticGrantAndNotTheToolGrant(t *testing.T) {
	now := investigationTestTime()
	diagnostic := InvestigationAction{ID: "action-1", ToolID: "gpu.ecc_counters.v1", Digest: ChecksumSHA256([]byte("ecc")), Diagnostic: true, FanOut: 1, Targets: []string{"node-1"}, Start: now.Add(-time.Hour), End: now}

	// No grant: refused before anything is spent.
	request := validInvestigationRequest(now)
	investigation, err := NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	investigation, _ = investigation.BeginPlanning(now)
	investigation, _ = investigation.RecordDecision(InvestigationBudgetUsage{Decisions: 1}, now)
	investigation, _ = investigation.BeginPolicyCheck(now)
	if _, err := investigation.Execute(diagnostic, now); !errors.Is(err, ErrInvestigationBudgetExceeded) {
		t.Fatalf("a zero diagnostic grant must refuse the action with a budget error, got %v", err)
	}
	if investigation.Usage().ToolCalls != 0 {
		t.Fatalf("a refused diagnostic must not have spent a tool call: %d", investigation.Usage().ToolCalls)
	}

	// Granted exactly one: the first is admitted, the second is refused, and the
	// untouched tool-call grant does not rescue it.
	granted := validInvestigationRequest(now)
	granted.Budget.MaxDiagnosticCalls = 1
	investigation, err = NewInvestigation(granted)
	if err != nil {
		t.Fatal(err)
	}
	investigation, _ = investigation.BeginPlanning(now)
	investigation, _ = investigation.RecordDecision(InvestigationBudgetUsage{Decisions: 1}, now)
	investigation, _ = investigation.BeginPolicyCheck(now)
	investigation, err = investigation.Execute(diagnostic, now)
	if err != nil {
		t.Fatalf("a granted diagnostic must be admitted: %v", err)
	}
	usage := investigation.Usage()
	if usage.DiagnosticCalls != 1 || usage.ToolCalls != 0 {
		t.Fatalf("diagnostic charged to the wrong dimension: diagnostic=%d tool=%d", usage.DiagnosticCalls, usage.ToolCalls)
	}
	investigation, _ = investigation.BeginEvidenceRecording(now)
	investigation, _ = investigation.BeginLedgerUpdate(now)
	investigation, _ = investigation.BeginPlanning(now)
	investigation, _ = investigation.RecordDecision(InvestigationBudgetUsage{Decisions: 1}, now)
	investigation, _ = investigation.BeginPolicyCheck(now)
	second := diagnostic
	second.ID = "action-2"
	second.Digest = ChecksumSHA256([]byte("ecc-2"))
	if _, err := investigation.Execute(second, now); !errors.Is(err, ErrInvestigationBudgetExceeded) {
		t.Fatalf("an exhausted diagnostic grant must refuse the second diagnostic, got %v", err)
	}
	// The same turn can still perform an evidence lookup, because that grant is
	// untouched. Exhausting execution must not end the run's ability to read.
	lookup := InvestigationAction{ID: "action-3", ToolID: "gpu.xid_events.v1", Digest: ChecksumSHA256([]byte("xid")), FanOut: 1, Targets: []string{"node-1"}, Start: now.Add(-time.Hour), End: now}
	investigation, err = investigation.Execute(lookup, now)
	if err != nil {
		t.Fatalf("an evidence lookup must remain admissible after the diagnostic grant is spent: %v", err)
	}
	usage = investigation.Usage()
	if usage.DiagnosticCalls != 1 || usage.ToolCalls != 1 {
		t.Fatalf("lookup charged to the wrong dimension: diagnostic=%d tool=%d", usage.DiagnosticCalls, usage.ToolCalls)
	}
}

// A privileged diagnostic needs both grants, and neither one alone pays for it.
func TestPrivilegedDiagnosticRequiresBothGrants(t *testing.T) {
	now := investigationTestTime()
	action := InvestigationAction{ID: "action-1", ToolID: "gpu.ecc_counters.v1", Digest: ChecksumSHA256([]byte("ecc")), Diagnostic: true, Privileged: true, FanOut: 1, Targets: []string{"node-1"}, Start: now.Add(-time.Hour), End: now}
	awaitApproval := func(t *testing.T, budget InvestigationBudget) error {
		t.Helper()
		request := validInvestigationRequest(now)
		request.Budget = budget
		investigation, err := NewInvestigation(request)
		if err != nil {
			t.Fatal(err)
		}
		investigation, _ = investigation.BeginPlanning(now)
		investigation, _ = investigation.RecordDecision(InvestigationBudgetUsage{Decisions: 1}, now)
		investigation, _ = investigation.BeginPolicyCheck(now)
		_, err = investigation.AwaitApproval(action, now)
		return err
	}
	base := InvestigationBudget{MaxDecisions: 3, MaxToolCalls: 3, MaxFanOut: 8, MaxModelTokens: 1000, MaxCostMicros: 1000}

	privilegeOnly := base
	privilegeOnly.MaxPrivilegedCalls = 1
	if err := awaitApproval(t, privilegeOnly); err == nil {
		t.Fatal("a privilege grant alone must not authorize a diagnostic")
	}
	diagnosticOnly := base
	diagnosticOnly.MaxDiagnosticCalls = 1
	if err := awaitApproval(t, diagnosticOnly); err == nil {
		t.Fatal("a diagnostic grant alone must not authorize a privileged action")
	}
	both := base
	both.MaxPrivilegedCalls, both.MaxDiagnosticCalls = 1, 1
	if err := awaitApproval(t, both); err != nil {
		t.Fatalf("both grants together must authorize a privileged diagnostic: %v", err)
	}
}

// A report section is untrusted model prose. Its citations are resolved against
// the durable ledger exactly as a finding's are; what does not apply is the
// finding rule that every named entity be covered, because a timeline entry
// names an instant and an unknown names absent data.
func TestReportSectionValidatesCitationsAndTimelineInstants(t *testing.T) {
	now := investigationTestTime()
	investigation, _ := NewInvestigation(validInvestigationRequest(now))
	investigation, _ = investigation.BeginPlanning(now)
	investigation, _ = investigation.BeginPolicyCheck(now)
	investigation, _ = investigation.Execute(InvestigationAction{ID: "action-1", ToolID: "gpu.xid.v1", Digest: ChecksumSHA256([]byte("action")), FanOut: 1}, now)
	investigation, _ = investigation.BeginEvidenceRecording(now)
	ledger, _ := NewEvidenceLedger([]InvestigationEvidence{{EvidenceID: "evidence-1", InvestigationID: investigation.Request().ID, ClusterID: investigation.Request().ClusterID, EntityIDs: []string{"node-1"}, Status: EvidenceComplete, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now}}, investigation)

	observed := now.Add(-time.Minute)
	timeline := ReportSection{ID: "section-1", InvestigationID: investigation.Request().ID, Kind: ReportSectionTimeline, Ordinal: 0, Statement: "XID 94 first appeared.", ObservedAt: &observed, EvidenceIDs: []EvidenceID{"evidence-1"}}
	if err := timeline.Validate(ledger, investigation); err != nil {
		t.Fatal(err)
	}

	// The refusal that matters: prose citing evidence the ledger never held.
	invented := timeline
	invented.EvidenceIDs = []EvidenceID{"evidence-does-not-exist"}
	if err := invented.Validate(ledger, investigation); err == nil {
		t.Fatal("expected a citation outside the ledger to be refused")
	}

	// An instant is a claim, so a timeline entry must be sourced and timed.
	uncited := timeline
	uncited.EvidenceIDs = nil
	if err := uncited.Validate(ledger, investigation); err == nil {
		t.Fatal("expected an uncited timeline entry to be refused")
	}
	untimed := timeline
	untimed.ObservedAt = nil
	if err := untimed.Validate(ledger, investigation); err == nil {
		t.Fatal("expected a timeline entry without an instant to be refused")
	}

	// An unknown is a statement about absent data, so it may cite nothing and
	// must not carry an instant. Requiring a citation here would suppress the
	// honest answer and make the report look more complete than the run was.
	unknown := ReportSection{ID: "section-2", InvestigationID: investigation.Request().ID, Kind: ReportSectionUnknown, Ordinal: 0, Statement: "Onset before the window is unknown."}
	if err := unknown.Validate(ledger, investigation); err != nil {
		t.Fatal(err)
	}
	unknown.ObservedAt = &observed
	if err := unknown.Validate(ledger, investigation); err == nil {
		t.Fatal("expected a non-timeline section carrying an instant to be refused")
	}
}

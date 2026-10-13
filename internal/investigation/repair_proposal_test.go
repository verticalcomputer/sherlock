package investigation

import (
	"context"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/modelprovider"
	"testing"
	"time"
)

func repairSnapshot(t *testing.T, now time.Time) application.InvestigationSnapshot {
	t.Helper()
	snapshot := planningSnapshot(t, now)
	request := snapshot.Investigation.Request()
	request.Purpose = domain.InvestigationPurposeRepairPlan
	request.Question = "Generate a combined repair proposal for dcgm_gpu_xid and three unavailable GPU diagnostics."
	request.Scope.EntityKind = "cluster"
	request.Scope.EntityIDs = []string{string(request.ClusterID)}
	value, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	value, err = value.BeginPlanning(now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Investigation = value
	return snapshot
}

func TestRepairProposalWithXIDReadsWarningsWithoutDiagnosticDispatch(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := repairSnapshot(t, now)
	provider := diagnosticPlanningProvider(t, "gpu.ecc_counters.v1")
	orchestrator := newDiagnosticOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now)
	decision, err := orchestrator.Decide(context.Background(), snapshot)
	if err != nil || decision.Action == nil || decision.Action.ToolID != "evidence.lookup.v1" || decision.Action.Diagnostic || decision.Action.Privileged || decision.Action.Targets[0] != "cluster-a" {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	snapshot.PriorActions = []application.InvestigationActionHistory{{ToolID: decision.Action.ToolID, Outcome: "SUCCEEDED"}}
	decision, err = orchestrator.Decide(context.Background(), snapshot)
	if err != nil || !decision.Stop || decision.Reason != domain.StopNoUsefulAction || len(provider.PlanningCalls()) != 0 {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
}

func TestRepairProposalCompletionRequiresEveryWarningInValidatedPlan(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := repairSnapshot(t, now)
	var entries []domain.InvestigationEvidence
	for _, id := range []domain.EvidenceID{"ecc", "retired", "row", "xid"} {
		entries = append(entries, domain.InvestigationEvidence{InvestigationID: "inv-1", ClusterID: "cluster-a", EvidenceID: id, EntityIDs: []string{"cluster-a"}, Status: domain.EvidenceUnavailable, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now})
	}
	var err error
	snapshot.Evidence, err = domain.NewEvidenceLedger(entries, snapshot.Investigation)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"ecc", "retired", "row", "xid"}
	request := modelprovider.SynthesisRequest{Evidence: []modelprovider.EvidenceContext{{EvidenceID: "ecc"}, {EvidenceID: "retired"}, {EvidenceID: "row"}, {EvidenceID: "xid"}}, Coverage: modelprovider.Coverage{TargetsMissed: []string{"cluster-a"}, RequestedTimeComplete: false}}
	response := modelprovider.SynthesisResponse{WhatIsHappening: []modelprovider.CitedStatement{{Statement: "Four streams need repair.", EvidenceIDs: ids}}, WhatRemainsUnknown: []modelprovider.CitedStatement{{Statement: "Hardware state remains unknown.", EvidenceIDs: ids}}, SuggestedNextSteps: []modelprovider.CitedStatement{{Statement: "Propose shared diagnostic and separate exporter prechecks, verification and rollback.", EvidenceIDs: ids}}, Coverage: []modelprovider.CitedStatement{{Statement: "All four warnings are addressed, none fixed.", EvidenceIDs: ids}}}
	findings := []domain.Finding{{Kind: domain.FindingRecommendation, EvidenceIDs: []domain.EvidenceID{"ecc", "retired", "row", "xid"}}}
	if !repairProposalCompletionEligible(snapshot, request, response, findings, nil) {
		t.Fatal("complete cited proposal required healthy telemetry")
	}
	findings[0].EvidenceIDs = findings[0].EvidenceIDs[:3]
	if repairProposalCompletionEligible(snapshot, request, response, findings, nil) {
		t.Fatal("missing XID repair was declared complete")
	}
	findings[0].EvidenceIDs = append(findings[0].EvidenceIDs, "xid")
	response.Coverage[0].EvidenceIDs = ids[:3]
	if repairProposalCompletionEligible(snapshot, request, response, findings, nil) {
		t.Fatal("missing coverage was declared complete")
	}
	response.Coverage[0].EvidenceIDs = ids
	request.Evidence = request.Evidence[:3]
	if repairProposalCompletionEligible(snapshot, request, response, findings, nil) {
		t.Fatal("reduced evidence silently completed")
	}
}

func TestXIDFailedBatchDoesNotSkipRemainingTargets(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	request := snapshot.Investigation.Request()
	request.Question = "Investigate XID"
	request.Scope.EntityIDs = []string{"n1", "n2", "n3"}
	request.Budget.MaxDiagnosticCalls = 4
	request.Budget.MaxFanOut = 3
	value, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	value, err = value.BeginPlanning(now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Investigation = value
	snapshot.PriorActions = []application.InvestigationActionHistory{{ToolID: "gpu.ecc_counters.v1", Targets: []string{"n1", "n2"}, Outcome: "UNAVAILABLE"}}
	provider := diagnosticPlanningProvider(t, "gpu.ecc_counters.v1")
	decision, err := newDiagnosticOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now).Decide(context.Background(), snapshot)
	if err != nil || decision.Action == nil || decision.Action.ToolID != "gpu.ecc_counters.v1" || len(decision.Action.Targets) != 1 || decision.Action.Targets[0] != "n3" {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
}

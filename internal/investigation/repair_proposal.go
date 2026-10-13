package investigation

import (
	"context"
	"fmt"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/modelprovider"
)

// Repair proposals read a frozen warning set once, then synthesize a plan.
// They never enter a hardware playbook based on words in the question and
// cannot dispatch diagnostics. The executor rechecks the persisted purpose,
// cluster, scope, action identity, and request-time evidence cutoff.
func (orchestrator *Orchestrator) decideRepairProposal(ctx context.Context, snapshot application.InvestigationSnapshot) (application.InvestigationDecision, error) {
	request := snapshot.Investigation.Request()
	if err := request.Validate(); err != nil {
		return application.InvestigationDecision{}, err
	}
	if _, err := orchestrator.resolveAuthorityFilter(ctx, snapshot); err != nil {
		return application.InvestigationDecision{}, err
	}
	if len(snapshot.PriorActions) > 0 {
		return application.InvestigationDecision{Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopNoUsefulAction}, nil
	}
	usage := snapshot.Investigation.Usage()
	if usage.ToolCalls >= request.Budget.MaxToolCalls || usage.Decisions >= request.Budget.MaxDecisions {
		return application.InvestigationDecision{Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopBudgetExceeded}, nil
	}
	id, err := orchestrator.ids.NewID()
	if err != nil {
		return application.InvestigationDecision{}, err
	}
	return application.InvestigationDecision{Action: &domain.InvestigationAction{
		ID: domain.InvestigationActionID(id), ToolID: "evidence.lookup.v1", FanOut: 1,
		Targets: []string{string(request.ClusterID)}, Start: request.Scope.Start, End: request.Scope.End,
		Digest: domain.ChecksumSHA256([]byte(fmt.Sprintf("repair-warnings-v1\x00%s\x00%s\x00%s", request.ID, request.Scope.Start.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"), request.Scope.End.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")))),
	}}, nil
}

// Completion means every admitted warning has a validated, cited next step
// and coverage statement, not that its missing telemetry has been repaired.
// Reduction/omission must not silently turn a subset into a complete proposal.
func repairProposalCompletionEligible(snapshot application.InvestigationSnapshot, request modelprovider.SynthesisRequest, response modelprovider.SynthesisResponse, findings []domain.Finding, omissions []domain.ReportOmission) bool {
	entries := snapshot.Evidence.Entries()
	if len(entries) == 0 || len(request.Evidence) != len(entries) || len(omissions) > 0 || request.Coverage.EvidenceOmitted > 0 || len(request.Coverage.ToolFailures) > 0 {
		return false
	}
	if len(response.WhatIsHappening) == 0 || len(response.WhatRemainsUnknown) == 0 || len(response.SuggestedNextSteps) == 0 || len(response.Coverage) == 0 {
		return false
	}
	available := map[string]bool{}
	for _, evidence := range request.Evidence {
		available[evidence.EvidenceID] = true
	}
	recommendations := map[domain.EvidenceID]bool{}
	for _, finding := range findings {
		if finding.Kind == domain.FindingRecommendation {
			for _, id := range finding.EvidenceIDs {
				recommendations[id] = true
			}
		}
	}
	coverage := map[string]bool{}
	for _, statement := range response.Coverage {
		for _, id := range statement.EvidenceIDs {
			coverage[id] = true
		}
	}
	for _, entry := range entries {
		if !available[string(entry.EvidenceID)] || !recommendations[entry.EvidenceID] || !coverage[string(entry.EvidenceID)] {
			return false
		}
	}
	return true
}

package testbed

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/contextbudget"
	"github.com/verticalcomputer/sherlock/internal/modelprovider"
)

const uncertainty = "The physical cause is not established by these observations."

func longStatement() string {
	return strings.TrimSpace(strings.Repeat("Correlate the bounded observations before asserting a physical cause. ", 24))
}

type simulator struct{ pool *pgxpool.Pool }

func (s simulator) record(ctx context.Context, id, kind string, turn int, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO testbed_requests(investigation_id,kind,turn,payload) VALUES($1,$2,$3,$4)`, id, kind, turn, raw)
	return err
}
func simulatedUsage(input, output any) modelprovider.CallMetadata {
	a, _ := json.Marshal(input)
	b, _ := json.Marshal(output)
	estimator := contextbudget.JSONHeuristicEstimator{}
	return modelprovider.CallMetadata{Provider: "testbed", Model: PlannerVersion, ConfigurationID: SchemaVersion, InputTokens: estimator.Estimate(a), OutputTokens: estimator.Estimate(b), CostMicros: 0, Outcome: modelprovider.OutcomeSucceeded}
}
func (s simulator) Plan(ctx context.Context, request modelprovider.PlanningRequest) (modelprovider.PlanningResult, error) {
	if err := request.Validate(); err != nil {
		return modelprovider.PlanningResult{}, err
	}
	if err := s.record(ctx, request.InvestigationID, "planning", len(request.PriorActions), request); err != nil {
		return modelprovider.PlanningResult{}, err
	}
	response := modelprovider.PlanningResponse{SchemaVersion: modelprovider.PlanningSchemaVersion, StateSummary: "Gather bounded observations and retain causal uncertainty."}
	switch len(request.PriorActions) {
	case 0:
		tests := make([]string, 12)
		for i := range tests {
			tests[i] = fmt.Sprintf("Review unresolved evidence gap %d in the investigation scope", i+1)
		}
		response.HypothesisUpdates = []modelprovider.HypothesisUpdate{{HypothesisID: modelprovider.NewHypothesisID, Statement: longStatement(), Status: "UNRESOLVED", Confidence: .2, UnresolvedTests: tests}}
		response.Actions = simulatedAction(request, "evidence.lookup.v1")
	case 1:
		// The simulator can only echo the projection actually presented. Hidden
		// tests must survive by the controller's rules, not by simulator memory.
		for _, h := range request.Hypotheses {
			response.HypothesisUpdates = append(response.HypothesisUpdates, modelprovider.HypothesisUpdate{HypothesisID: h.HypothesisID, Statement: h.Statement, Status: "UNRESOLVED", Confidence: .3})
		}
		response.Actions = simulatedAction(request, "node.detail.v1")
	default:
		reason := modelprovider.StopNoUsefulAction
		response.Stop = true
		response.StopReason = &reason
	}
	if err := response.ValidateFor(request); err != nil {
		return modelprovider.PlanningResult{}, err
	}
	return modelprovider.PlanningResult{Response: response, Metadata: simulatedUsage(request, response)}, nil
}
func simulatedAction(request modelprovider.PlanningRequest, tool string) []modelprovider.PlannedAction {
	arguments, _ := json.Marshal(map[string]any{"targets": request.Scope.EntityIDs, "start": request.Scope.Start, "end": request.Scope.End})
	return []modelprovider.PlannedAction{{ToolID: tool, Arguments: arguments, Purpose: "Read a bounded source", ExpectedInformation: "Current evidence for the requested scope", Priority: 1}}
}
func (s simulator) Synthesize(ctx context.Context, request modelprovider.SynthesisRequest) (modelprovider.SynthesisResult, error) {
	if err := request.Validate(); err != nil {
		return modelprovider.SynthesisResult{}, err
	}
	if err := s.record(ctx, request.InvestigationID, "synthesis", 0, request); err != nil {
		return modelprovider.SynthesisResult{}, err
	}
	response := modelprovider.SynthesisResponse{SchemaVersion: modelprovider.SynthesisSchemaVersion, WhatRemainsUnknown: []modelprovider.CitedStatement{{Statement: uncertainty}}, Coverage: []modelprovider.CitedStatement{{Statement: "The report is limited to the selected evidence; omissions remain unassessed."}}}
	for _, e := range request.Evidence {
		response.WhatIsHappening = append(response.WhatIsHappening, modelprovider.CitedStatement{Statement: e.Summary, EvidenceIDs: []string{e.EvidenceID}, Severity: "WARNING"})
		response.Timeline = append(response.Timeline, modelprovider.TimelineEntry{ObservedAt: e.ObservedTo, Statement: e.Summary, EvidenceIDs: []string{e.EvidenceID}})
	}
	for _, e := range request.Evidence {
		response.WhatRemainsUnknown[0].EvidenceIDs = append(response.WhatRemainsUnknown[0].EvidenceIDs, e.EvidenceID)
		response.Coverage[0].EvidenceIDs = append(response.Coverage[0].EvidenceIDs, e.EvidenceID)
	}
	if err := response.ValidateFor(request); err != nil {
		return modelprovider.SynthesisResult{}, err
	}
	return modelprovider.SynthesisResult{Response: response, Metadata: simulatedUsage(request, response)}, nil
}

package investigation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationcontext"
	"github.com/verticalcomputer/sherlock/internal/modelprovider"
)

func TestModelRequestsRespectHypothesisContextLimits(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	hypotheses := []domain.Hypothesis{
		{ID: "hyp-a", InvestigationID: snapshot.Investigation.Request().ID, Statement: strings.Repeat("Possible cooling issue. ", 30), Status: domain.HypothesisUnresolved, Confidence: .4, UnresolvedTests: []string{"Compare power-matched temperature"}, Version: 1},
		{ID: "hyp-z", InvestigationID: snapshot.Investigation.Request().ID, Statement: "Other explanation", Status: domain.HypothesisProposed, Version: 1},
	}
	var err error
	snapshot.Hypotheses, err = domain.NewHypothesisLedger(hypotheses, snapshot.Evidence, snapshot.Investigation)
	if err != nil {
		t.Fatal(err)
	}
	input, err := (LedgerContextSource{}).InvestigationContext(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	limits := investigationcontext.DefaultLimits()
	limits.MaxHypotheses = 1
	limits.MaxHypothesisBytes = 48
	builder, err := investigationcontext.NewBuilder(limits)
	if err != nil {
		t.Fatal(err)
	}
	built, err := builder.Build(input)
	if err != nil {
		t.Fatal(err)
	}
	planning := planningRequest(snapshot, built, nil, Config{})
	synthesis := synthesisRequest(snapshot, built, "synthesis-v1")
	if planning.Coverage.HypothesesOmitted != 1 || synthesis.Coverage.HypothesesOmitted != 1 {
		t.Fatal("hypothesis omission hidden from model")
	}
	if planning.Hypotheses[0].Confidence != .4 || !planning.Hypotheses[0].StatementTruncated || !slices.Equal(planning.Hypotheses[0].UnresolvedTests, hypotheses[0].UnresolvedTests) {
		t.Fatalf("projection lost hypothesis fields: %+v", planning.Hypotheses)
	}
	for _, request := range [][]string{hypothesisStatements(planning.Hypotheses), hypothesisStatements(synthesis.Hypotheses)} {
		if len(request) != 1 || request[0] != built.Hypotheses[0].Statement {
			t.Fatalf("bounded hypothesis context bypassed: %v", request)
		}
	}
}

func hypothesisStatements(values []modelprovider.HypothesisContext) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Statement)
	}
	return result
}

func TestRestartRebuildsBoundedHypothesisContext(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	entry := domain.Hypothesis{ID: "hyp-1", InvestigationID: snapshot.Investigation.Request().ID, Statement: strings.Repeat("Cooling needs verification. ", 30), Status: domain.HypothesisUnresolved, Confidence: .35, UnresolvedTests: []string{"Compare matched power", "Check fan readings"}, Version: 3}
	var err error
	snapshot.Hypotheses, err = domain.NewHypothesisLedger([]domain.Hypothesis{entry}, snapshot.Evidence, snapshot.Investigation)
	if err != nil {
		t.Fatal(err)
	}
	arguments := json.RawMessage(`{"targets":["n1"],"start":"2026-10-14T11:00:00Z","end":"2026-10-14T12:00:00Z"}`)
	var previous []byte
	for range 2 {
		// A new orchestrator/provider has no in-process history. All continuity
		// comes from the authoritative snapshot, as after a worker restart.
		provider := fakePlanningProvider(t, arguments)
		orchestrator := newTestOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now)
		decision, err := orchestrator.Decide(context.Background(), snapshot)
		if err != nil || decision.Action == nil {
			t.Fatalf("decision=%+v error=%v", decision, err)
		}
		calls := provider.PlanningCalls()
		if len(calls) != 1 || len(calls[0].Hypotheses) != 1 {
			t.Fatalf("calls=%+v", calls)
		}
		hypothesis := calls[0].Hypotheses[0]
		if !hypothesis.StatementTruncated || len(hypothesis.Statement) > 512 || hypothesis.Confidence != entry.Confidence || !slices.Equal(hypothesis.UnresolvedTests, entry.UnresolvedTests) {
			t.Fatalf("lost continuity: %+v", hypothesis)
		}
		encoded, err := json.Marshal(calls[0])
		if err != nil {
			t.Fatal(err)
		}
		if previous != nil && !bytes.Equal(previous, encoded) {
			t.Fatal("restart changed the model context")
		}
		previous = encoded
	}
	if snapshot.Hypotheses.Entries()[0].Statement != entry.Statement {
		t.Fatal("durable hypothesis was truncated")
	}
}

func TestHypothesisUpdatePreservesUnseenTestsAndFullStatement(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	entry := domain.Hypothesis{ID: "hyp-1", InvestigationID: snapshot.Investigation.Request().ID, Statement: strings.Repeat("Cooling needs verification. ", 30), Status: domain.HypothesisUnresolved, Confidence: .3, Version: 4}
	entry.UnresolvedTests = []string{strings.Repeat("Long test ", 40)}
	for i := 1; i < 12; i++ {
		entry.UnresolvedTests = append(entry.UnresolvedTests, fmt.Sprintf("Check sensor %d", i))
	}
	var err error
	snapshot.Hypotheses, err = domain.NewHypothesisLedger([]domain.Hypothesis{entry}, snapshot.Evidence, snapshot.Investigation)
	if err != nil {
		t.Fatal(err)
	}
	input, err := (LedgerContextSource{}).InvestigationContext(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	builder, err := investigationcontext.NewBuilder(investigationcontext.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	built, err := builder.Build(input)
	if err != nil {
		t.Fatal(err)
	}
	presented := modelHypotheses(built)
	if len(presented) != 1 || presented[0].UnresolvedTestsOmitted != 4 || !presented[0].UnresolvedTestsTruncated {
		t.Fatalf("projection=%+v", presented)
	}
	orchestrator := &Orchestrator{}
	update := modelprovider.HypothesisUpdate{HypothesisID: "hyp-1", Statement: presented[0].Statement, Status: "UNRESOLVED", Confidence: .5, UnresolvedTests: []string{presented[0].UnresolvedTests[0], "Check a new signal"}}
	mapped, err := orchestrator.mapHypotheses([]modelprovider.HypothesisUpdate{update}, snapshot, presented)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]string{"Check a new signal", entry.UnresolvedTests[0]}, entry.UnresolvedTests[8:]...)
	if len(mapped) != 1 || mapped[0].Statement != entry.Statement || mapped[0].Version != 5 || !slices.Equal(mapped[0].UnresolvedTests, want) {
		t.Fatalf("hidden context lost or visible test not resolved: %+v", mapped)
	}
	if !slices.Equal(snapshot.Hypotheses.Entries()[0].UnresolvedTests, entry.UnresolvedTests) {
		t.Fatal("snapshot mutated")
	}
	// Fully presented hypotheses retain ordinary update semantics.
	fullView := []modelprovider.HypothesisContext{{HypothesisID: "hyp-1"}}
	mapped, err = orchestrator.mapHypotheses([]modelprovider.HypothesisUpdate{update}, snapshot, fullView)
	if err != nil || mapped[0].Statement != update.Statement || !slices.Equal(mapped[0].UnresolvedTests, update.UnresolvedTests) {
		t.Fatalf("full context update=%+v err=%v", mapped, err)
	}
	update.UnresolvedTests = make([]string, 32)
	for i := range update.UnresolvedTests {
		update.UnresolvedTests[i] = fmt.Sprintf("New test %d", i)
	}
	if _, err = orchestrator.mapHypotheses([]modelprovider.HypothesisUpdate{update}, snapshot, presented); err == nil {
		t.Fatal("accepted overflow after restoring hidden tests")
	}
}

func TestPriorActionDistinguishesOmittedResultsFromEmptyRun(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	request := snapshot.Investigation.Request()
	snapshot.PriorActions = []application.InvestigationActionHistory{{Digest: domain.ChecksumSHA256([]byte("action")), ToolID: "gpu.health.v1", Outcome: "SUCCEEDED", Targets: []string{"n1"}, Start: request.Scope.Start, End: request.Scope.End, EvidenceIDs: []domain.EvidenceID{"visible", "not-selected"}}}
	actions := modelPriorActions(snapshot, investigationcontext.Context{Evidence: []investigationcontext.EvidenceBlock{{EvidenceID: "visible"}}})
	if len(actions) != 1 || actions[0].EvidenceOmitted != 1 || !slices.Equal(actions[0].EvidenceIDs, []string{"visible"}) || actions[0].Outcome != "SUCCEEDED" {
		t.Fatalf("missing result misrepresented: %+v", actions)
	}
	actions = modelPriorActions(snapshot, investigationcontext.Context{})
	if actions[0].EvidenceOmitted != 2 || len(actions[0].EvidenceIDs) != 0 {
		t.Fatalf("all omitted: %+v", actions)
	}
	snapshot.PriorActions[0].EvidenceIDs = nil
	snapshot.PriorActions[0].Outcome = "NO_EVIDENCE"
	actions = modelPriorActions(snapshot, investigationcontext.Context{})
	if actions[0].EvidenceOmitted != 0 || actions[0].Outcome != "NO_EVIDENCE" {
		t.Fatalf("empty run misrepresented: %+v", actions)
	}
}

func TestHiddenTestOverflowIsAuditedBeforeActionAdmission(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	hypothesis := domain.Hypothesis{ID: "hyp-1", InvestigationID: snapshot.Investigation.Request().ID, Statement: "Cooling remains unresolved", Status: domain.HypothesisUnresolved, Version: 1}
	for i := range 12 {
		hypothesis.UnresolvedTests = append(hypothesis.UnresolvedTests, fmt.Sprintf("Existing test %d", i))
	}
	var err error
	snapshot.Hypotheses, err = domain.NewHypothesisLedger([]domain.Hypothesis{hypothesis}, snapshot.Evidence, snapshot.Investigation)
	if err != nil {
		t.Fatal(err)
	}
	tests := make([]string, 32)
	for i := range tests {
		tests[i] = fmt.Sprintf("New test %d", i)
	}
	reason := modelprovider.StopNoUsefulAction
	provider, err := modelprovider.NewFakeProvider([]modelprovider.PlanningStep{{Result: modelprovider.PlanningResult{
		Response: modelprovider.PlanningResponse{SchemaVersion: 1, StateSummary: "Retain uncertainty", Stop: true, StopReason: &reason, HypothesisUpdates: []modelprovider.HypothesisUpdate{{HypothesisID: "hyp-1", Statement: hypothesis.Statement, Status: "UNRESOLVED", UnresolvedTests: tests}}},
		Metadata: modelprovider.CallMetadata{Provider: "fixture", Model: "planner-v1", ConfigurationID: "config-v1", InputTokens: 7, OutputTokens: 3, CostMicros: 2, Latency: time.Millisecond, Outcome: modelprovider.OutcomeSucceeded},
	}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	audits := &auditMemory{}
	orchestrator := newTestOrchestrator(t, provider, audits, &duplicateMemory{}, now)
	decision, err := orchestrator.Decide(context.Background(), snapshot)
	if err == nil || decision.Action != nil || len(audits.values) != 1 || audits.values[0].Outcome != application.ModelCallRejected || audits.values[0].ReasonCode != "HYPOTHESIS_CONTEXT_UPDATE_REJECTED" || len(audits.reserved) != 0 || len(audits.completed) != 1 {
		t.Fatalf("decision=%+v err=%v audits=%+v", decision, err, audits)
	}
}

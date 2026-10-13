package scheduleinvestigation

import (
	"context"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type fixtureReader struct{ facts Snapshot }

func (r *fixtureReader) ReadScheduleInvestigation(context.Context, domain.InvestigationID) (Snapshot, error) {
	return r.facts, nil
}

func scheduleFixture(t *testing.T) (*Planner, *fixtureReader) {
	t.Helper()
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	request := domain.InvestigationRequest{ID: "investigation-1", IncidentID: "incident-1", ClusterID: "cluster-1", Question: "Is there a scheduling gap?", RequestedBy: "sherlock-remediator", IdempotencyKey: "schedule-1", Scope: domain.InvestigationScope{EntityKind: "collection_job", EntityIDs: []string{"job-1"}, Start: now, End: now}, SuccessCriteria: []string{"Cite exact evidence"}, Budget: domain.InvestigationBudget{MaxDecisions: 3, MaxToolCalls: 1, MaxFanOut: 1}, RequestedAt: now, Deadline: now.Add(time.Hour)}
	investigation, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	evidence := domain.InvestigationEvidence{EvidenceID: "evidence-1", InvestigationID: request.ID, ClusterID: request.ClusterID, Status: domain.EvidenceComplete, EntityIDs: []string{"job-1"}, ObservedStart: now, ObservedEnd: now, RecordedAt: now}
	reader := &fixtureReader{Snapshot{ClusterID: request.ClusterID, IncidentID: request.IncidentID, InvestigationID: request.ID, JobID: "job-1", SourceID: "source-1", Eligible: true, Evidence: evidence, Current: application.InvestigationSnapshot{Investigation: investigation}}}
	planner, err := New(reader)
	if err != nil {
		t.Fatal(err)
	}
	return planner, reader
}

func TestSchedulePlannerBindsEveryReadAndAction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"ineligible", func(s *Snapshot) { s.Eligible = false }},
		{"cross cluster", func(s *Snapshot) { s.ClusterID = "other" }},
		{"cross investigation", func(s *Snapshot) { s.InvestigationID = "other" }},
		{"cross incident", func(s *Snapshot) { s.IncidentID = "other" }},
		{"wrong job", func(s *Snapshot) { s.JobID = "other" }},
		{"wrong evidence cluster", func(s *Snapshot) { s.Evidence.ClusterID = "other" }},
		{"partial evidence", func(s *Snapshot) { s.Evidence.Status = domain.EvidencePartial }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, r := scheduleFixture(t)
			expected := r.facts.Current
			tc.mutate(&r.facts)
			if _, err := p.Decide(context.Background(), expected); err == nil {
				t.Fatal("accepted substituted facts")
			}
		})
	}
	p, r := scheduleFixture(t)
	decision, err := p.Decide(context.Background(), r.facts.Current)
	if err != nil {
		t.Fatal(err)
	}
	r.facts.Current.ProposedAction = decision.Action
	key := "investigation/investigation-1/action/" + string(decision.Action.ID)
	if _, err = p.ExecuteInvestigationAction(context.Background(), key, *decision.Action); err != nil {
		t.Fatal(err)
	}
	forged := *decision.Action
	forged.Targets = []string{"other"}
	if _, err = p.ExecuteInvestigationAction(context.Background(), key, forged); err == nil {
		t.Fatal("accepted target substitution")
	}
	if _, err = p.ExecuteInvestigationAction(context.Background(), "investigation/other/action/"+string(decision.Action.ID), *decision.Action); err == nil {
		t.Fatal("accepted request replay")
	}
}

func TestScheduleSynthesisRequiresExactCommittedLedger(t *testing.T) {
	p, r := scheduleFixture(t)
	if _, err := p.Synthesize(context.Background(), r.facts.Current); err == nil {
		t.Fatal("synthesized without cited ledger")
	}
	ledger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{r.facts.Evidence}, r.facts.Current.Investigation)
	if err != nil {
		t.Fatal(err)
	}
	r.facts.Current.Evidence = ledger
	synthesis, err := p.Synthesize(context.Background(), r.facts.Current)
	if err != nil {
		t.Fatal(err)
	}
	if synthesis.ActionCard == nil || synthesis.Disposition != application.SynthesisValidatedComplete {
		t.Fatal("missing validated card")
	}
}

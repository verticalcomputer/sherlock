package alertassessment_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
)

const scalarCategory = "scalar_test"
const scalarMetric = "DCGM_FI_DEV_GPU_TEMP"

type scalarAdapter struct{}

func (scalarAdapter) Describe() a.Descriptor {
	return a.Descriptor{Category: scalarCategory, Contract: 1, Implementation: 1, PolicySchema: 1, TrackerSchema: 1, CandidateSchema: 1, DetailsSchema: 1,
		Modes: []string{"replay"}, Metrics: []a.Metric{{Metric: scalarMetric, Unit: "celsius", Required: true, HistorySeconds: 60}},
		Outcomes: []a.Outcome{
			{Code: scalarCategory + "/NO_ENTRY", Purpose: "DISCOVER", Phase: "NO_CANDIDATE", Action: "NONE", EvidenceClass: "NONTERMINAL"},
			{Code: scalarCategory + "/OPEN", Purpose: "DISCOVER", Phase: "OBSERVING", Action: "NONE", EvidenceClass: "NONTERMINAL"},
			{Code: scalarCategory + "/OPEN", Purpose: "ASSESS", Phase: "FINAL", Action: "INVESTIGATE", EvidenceClass: "SUPPORTED_CONCERN"},
		}, Reasons: []string{}, Updates: []a.Update{}, PayloadLimits: a.PayloadLimits{Policy: a.MaxPayloadBytes, Tracker: a.MaxPayloadBytes, Candidate: a.MaxPayloadBytes, Details: a.MaxDetailsBytes}}
}

func (scalarAdapter) ValidatePolicy(_ context.Context, p a.Payload) error {
	var policy monitoring.Policy
	if err := a.DecodeStrict(p.Body, &policy, a.MaxPayloadBytes); err != nil {
		return err
	}
	return monitoring.ValidatePolicy(policy)
}

func (scalarAdapter) Evaluate(_ context.Context, r a.Request) (a.Result, error) {
	x := a.Result{Kind: "UNCHANGED", Support: []string{}, Reasons: []string{}, UpdateCodes: []string{}, ProposedFeatures: []a.Feature{}}
	var policy monitoring.Policy
	if err := a.DecodeStrict(r.Policy.Body, &policy, a.MaxPayloadBytes); err != nil {
		return a.Result{}, err
	}
	var prior monitoring.State
	if r.State != nil {
		if err := a.DecodeStrict(r.State.Body, &prior, a.MaxPayloadBytes); err != nil {
			return a.Result{}, err
		}
	}
	if r.Scope == "ARM" {
		if r.Purpose == "ASSESS" && prior.Open {
			x.Kind, x.Phase, x.Action, x.Outcome = "ASSESSMENT", "FINAL", "INVESTIGATE", scalarCategory+"/OPEN"
			x.Support = r.Entry.Support
		}
		return x, nil
	}
	input := monitoring.Input{At: r.LogicalAt, AuthorityValid: true}
	for _, fact := range r.Facts {
		if fact.Kind != "SAMPLE" {
			continue
		}
		var sample a.Sample
		if err := a.DecodeStrict(fact.Body, &sample, a.MaxPayloadBytes); err != nil {
			return a.Result{}, err
		}
		runID := domain.RunID(sample.Provenance.CollectionRunID)
		input.Samples = append(input.Samples, monitoring.Sample{
			Observation: domain.Observation{ID: domain.ObservationID(fact.ID), ClusterID: policy.ClusterID, SourceID: policy.SourceID, EntityKey: r.Asset, Metric: sample.Metric, Unit: sample.Unit, Value: sample.Value, ObservedAt: sample.SourceAt, CollectedAt: sample.CollectedAt},
			RunID:       runID, CollectionCompletedAt: sample.CompletedAt, Status: domain.ResultSucceeded, Supported: true, CoverageComplete: true,
		})
		input.Runs = append(input.Runs, monitoring.RunEvidence{RunID: runID, ClusterID: policy.ClusterID, SourceID: policy.SourceID, Binding: policy.Binding,
			CompletedAt: sample.CompletedAt, Status: domain.ResultSucceeded, CoverageComplete: true, Count: 1, FieldState: "SUPPORTED"})
	}
	decision, err := monitoring.Evaluate(policy, prior, input)
	if err != nil {
		return a.Result{}, err
	}
	state, err := a.NewPayload(scalarCategory, "tracker", 1, decision.State)
	if err != nil {
		return a.Result{}, err
	}
	x.State = &state
	switch {
	case r.Purpose == "DISCOVER":
		x.Kind, x.Phase, x.Action, x.Outcome = "ASSESSMENT", "NO_CANDIDATE", "NONE", scalarCategory+"/NO_ENTRY"
		if decision.Transition != nil && decision.Transition.Kind == monitoring.TransitionOpen {
			initial, err := a.NewPayload(scalarCategory, "candidate", 1, decision.State)
			if err != nil {
				return a.Result{}, err
			}
			x.Phase, x.Outcome, x.InitialCandidateState, x.EntryQualifiedAt = "OBSERVING", scalarCategory+"/OPEN", &initial, &decision.Transition.At
		}
	case decision.Transition != nil && decision.Transition.Kind == monitoring.TransitionRecover:
		x.Kind = "REARM"
	}
	if decision.Transition != nil {
		for _, ref := range decision.Transition.Evidence {
			x.Support = append(x.Support, string(ref.ObservationID))
		}
		x.Support = a.SortedUnique(x.Support)
	}
	return x, nil
}

func (scalarAdapter) ValidateResult(_ context.Context, _ a.Request, x a.Result) error {
	for _, p := range []*a.Payload{x.State, x.InitialCandidateState} {
		if p == nil {
			continue
		}
		var s monitoring.State
		if err := a.DecodeStrict(p.Body, &s, a.MaxPayloadBytes); err != nil {
			return err
		}
		if s.Version != monitoring.StateVersion || s.Open && s.Occurrence < 1 || x.Kind == "REARM" && s.Open {
			return a.ErrInvalid
		}
	}
	return nil
}

func TestAssessmentScalarAdapterPreservesMonitoringSemantics(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	policy := monitoring.Policy{ID: "scalar", Revision: 1, ClusterID: "cluster", SourceID: "source", EntityKey: "cluster/GPU/node/GPU-a/", Rule: monitoring.RuleGPUThermal, RuleVersion: 1,
		Metric: scalarMetric, Unit: "celsius", Binding: monitoring.Binding{Operation: domain.OperationPrometheusGPUTemperature, Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{"node"}}, ScheduleRevision: 1, InventoryRevisionID: "inventory"},
		EnrolledAt: at.Add(-time.Minute), FreshForSeconds: 60, ConfirmCount: 1, RecoverCount: 1, ConfirmWindowSeconds: 15, RecoverWindowSeconds: 15,
		MaxSampleGapSeconds: 15, OpenThreshold: 80, RecoverBelow: 70, Severity: domain.HealthSeverityWarning}
	registry, err := a.NewRegistry(scalarAdapter{}, cooling.Category{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, descriptorHash, err := registry.LookupVersion(scalarCategory, 1)
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.NewPayload(scalarCategory, "policy", 1, policy)
	if err != nil {
		t.Fatal(err)
	}
	sample := func(at time.Time, id string, value float64) a.Fact {
		t.Helper()
		f, err := a.NewFact(scalarCategory, "run", policy.EntityKey, "SAMPLE", at,
			a.Sample{Metric: policy.Metric, Unit: policy.Unit, SourceAt: at, CollectedAt: at, CompletedAt: at, Value: value, SourceRecord: id,
				Provenance: a.Provenance{Mode: "fixture", CollectionRunID: id, Operation: string(policy.Binding.Operation), ScheduleRevision: 1, InventoryRevision: "inventory", SourceRecord: id}})
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	high := sample(at, "high", 81)
	r := a.Request{Category: scalarCategory, Contract: 1, Implementation: 1, Run: "run", Asset: policy.EntityKey, DescriptorHash: descriptorHash, ConfigHash: strings.Repeat("a", 64),
		Purpose: "DISCOVER", Scope: "TRACKER", ExpectedRevision: 1, LogicalAt: at, AvailabilityCutoff: at, ExecutedAt: at, DiscoveryFloor: at,
		Facts: []a.Fact{high}, Policy: p}
	r = a.At(r, at)
	x, materialized, err := registry.Invoke(ctx, r)
	if err != nil || x.Phase != "OBSERVING" || x.Outcome != scalarCategory+"/OPEN" {
		t.Fatalf("scalar warning discovery: %v, %v", x, err)
	}
	tracker := x.State
	arm := materialized
	budget := int64(0)
	arm.Purpose, arm.Scope, arm.Sequence, arm.State, arm.BudgetMS = "ASSESS", "ARM", 1, x.InitialCandidateState, &budget
	arm.CandidateID, err = a.Identity("candidate", arm.Category, map[string]any{"run": arm.Run, "category": arm.Category, "asset": arm.Asset, "sequence": arm.Sequence, "budget_ms": budget})
	if err != nil {
		t.Fatal(err)
	}
	terminalID, err := a.Identity("terminal", arm.Category, map[string]any{"candidate": arm.CandidateID})
	if err != nil {
		t.Fatal(err)
	}
	arm.Entry = &a.Entry{Basis: "CATEGORY_CONCERN", AvailableAt: at, BundleID: materialized.Bundle.ID, Support: x.Support,
		Fallback: a.Fallback{Schema: 1, DueAt: at, Action: "INVESTIGATE", Route: "hardware_investigation", TerminalID: terminalID}}
	final, _, err := registry.Invoke(ctx, arm)
	if err != nil || final.Phase != "FINAL" || final.Action != "INVESTIGATE" || final.Outcome != scalarCategory+"/OPEN" {
		t.Fatalf("scalar warning final: %v, %v", final, err)
	}
	later := at.Add(time.Second)
	r.Purpose, r.Sequence, r.State = "FOLLOW_UP", 1, tracker
	r.ExecutedAt = later
	r.Facts = append(r.Facts, sample(later, "low", 69))
	r = a.At(r, later)
	recovered, _, err := registry.Invoke(ctx, r)
	if err != nil || recovered.Kind != "REARM" || recovered.Action != "" || recovered.Outcome != "" || len(recovered.Support) == 0 {
		t.Fatalf("scalar recovery: %v, %v", recovered, err)
	}
	for _, result := range []a.Result{x, final, recovered} {
		if len(result.ProposedFeatures) != 0 {
			t.Fatal(fmt.Errorf("unexpected scalar derived feature in %s", result.Kind))
		}
	}
}

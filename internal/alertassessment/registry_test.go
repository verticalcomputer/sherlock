package alertassessment

import (
	"context"
	"testing"
)

type testAdapter struct {
	descriptor Descriptor
	policy     func(context.Context, Payload) error
	evaluate   func(context.Context, Request) (Result, error)
	validate   func(context.Context, Request, Result) error
}

func (a *testAdapter) Describe() Descriptor { return a.descriptor }
func (a *testAdapter) ValidatePolicy(ctx context.Context, p Payload) error {
	if a.policy != nil {
		return a.policy(ctx, p)
	}
	return nil
}
func (a *testAdapter) Evaluate(ctx context.Context, r Request) (Result, error) {
	return a.evaluate(ctx, r)
}
func (a *testAdapter) ValidateResult(ctx context.Context, r Request, x Result) error {
	if a.validate != nil {
		return a.validate(ctx, r, x)
	}
	return nil
}

func testDescriptor() Descriptor {
	return Descriptor{Category: "test", Contract: 1, Implementation: 1, PolicySchema: 1, TrackerSchema: 1, CandidateSchema: 1, DetailsSchema: 1,
		Modes: []string{"replay"}, Metrics: []Metric{{Metric: "temperature", Unit: "celsius", Required: true, HistorySeconds: 900}},
		Outcomes: []Outcome{
			{Code: "test/none", Purpose: "DISCOVER", Phase: "NO_CANDIDATE", Action: "NONE", EvidenceClass: "NONTERMINAL"},
			{Code: "test/observe", Purpose: "DISCOVER", Phase: "OBSERVING", Action: "NONE", EvidenceClass: "NONTERMINAL"},
			{Code: "test/urgent", Purpose: "DISCOVER", Phase: "FINAL", Action: "URGENT", EvidenceClass: "SUPPORTED_CONCERN"},
			{Code: "test/observe", Purpose: "ASSESS", Phase: "OBSERVING", Action: "NONE", EvidenceClass: "NONTERMINAL"},
			{Code: "test/final", Purpose: "ASSESS", Phase: "FINAL", Action: "INVESTIGATE", EvidenceClass: "UNRESOLVED"},
		}, Reasons: []string{"known"}, Updates: []Update{{Code: "higher", Action: "INVESTIGATE", EvidenceClass: "UNRESOLVED"}, {Code: "urgent", Action: "URGENT", EvidenceClass: "SUPPORTED_CONCERN"}},
		PayloadLimits: PayloadLimits{Policy: MaxPayloadBytes, Tracker: MaxPayloadBytes, Candidate: MaxPayloadBytes, Details: MaxDetailsBytes}}
}

func TestAssessmentRegistryPinsCopiesByImplementation(t *testing.T) {
	first := &testAdapter{descriptor: testDescriptor()}
	second := &testAdapter{descriptor: testDescriptor()}
	second.descriptor.Implementation = 2
	r, err := NewRegistry(first, second)
	if err != nil {
		t.Fatal(err)
	}
	first.descriptor.Outcomes[0].Action = "URGENT"
	_, d, h, err := r.LookupVersion("test", 1)
	if err != nil || d.Outcomes[0].Action != "NONE" {
		t.Fatalf("registered descriptor lost its original data: %v, %v", d, err)
	}
	d.Outcomes[0].Action = "URGENT"
	_, again, hash, err := r.LookupVersion("test", 1)
	if err != nil || again.Outcomes[0].Action != "NONE" || h != hash {
		t.Fatal("lookup mutated registration")
	}
	_, latest, _, err := r.Lookup("test")
	if err != nil || latest.Implementation != 2 {
		t.Fatal("unpinned lookup lost latest version")
	}
	if _, err := NewRegistry(second, second); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if _, err := NewRegistry((*testAdapter)(nil)); err == nil {
		t.Fatal("nil adapter accepted")
	}
}

func TestAssessmentRegistryRejectsContradictoryDeclarations(t *testing.T) {
	for name, mutate := range map[string]func(*Descriptor){
		"phase":             func(d *Descriptor) { d.Outcomes[0].Purpose = "ASSESS" },
		"discovery final":   func(d *Descriptor) { d.Outcomes[2].Action = "INVESTIGATE" },
		"class":             func(d *Descriptor) { d.Outcomes[0].EvidenceClass = "BENIGN" },
		"metric":            func(d *Descriptor) { d.Metrics = append(d.Metrics, d.Metrics[0]) },
		"namespace":         func(d *Descriptor) { d.Outcomes[0].Code = "test/" },
		"size":              func(d *Descriptor) { d.PayloadLimits.Details++ },
		"null update array": func(d *Descriptor) { d.Updates = nil },
	} {
		t.Run(name, func(t *testing.T) {
			d := testDescriptor()
			mutate(&d)
			if _, err := NewRegistry(&testAdapter{descriptor: d}); err == nil {
				t.Fatal("bad descriptor registered")
			}
		})
	}
}

func TestAssessmentRegistryPinsTerminalMeaningAcrossPurposes(t *testing.T) {
	d := testDescriptor()
	d.Outcomes = append(d.Outcomes, Outcome{Code: "test/urgent", Purpose: "ASSESS", Phase: "FINAL", Action: "INVESTIGATE", EvidenceClass: "UNRESOLVED"})
	if _, err := NewRegistry(&testAdapter{descriptor: d}); err == nil {
		t.Fatal("conflicting terminal meanings registered for one code")
	}
	d.Outcomes[len(d.Outcomes)-1].Action = "URGENT"
	d.Outcomes[len(d.Outcomes)-1].EvidenceClass = "SUPPORTED_CONCERN"
	if _, err := NewRegistry(&testAdapter{descriptor: d}); err != nil {
		t.Fatalf("identical terminal meanings rejected: %v", err)
	}
	d.Outcomes[len(d.Outcomes)-1].Code = "test/none"
	if _, err := NewRegistry(&testAdapter{descriptor: d}); err != nil {
		t.Fatalf("nonterminal and terminal code reuse rejected: %v", err)
	}
}

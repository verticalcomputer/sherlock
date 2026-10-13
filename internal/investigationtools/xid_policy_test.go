package investigationtools

import "testing"

func TestXIDDecisionRunsOneDeterministicEvidencePass(t *testing.T) {
	facts := XIDDecisionFacts{AttemptedTools: map[ToolID]string{}, XIDCodes: []int{94}}
	for _, want := range xidEvidencePass {
		decision := DecideXIDAction(facts)
		if decision.Disposition != XIDGatherEvidence || decision.NextToolID != want || decision.Owner == "" || decision.Action == "" {
			t.Fatalf("decision=%+v, want next %s", decision, want)
		}
		facts.AttemptedTools[want] = "NO_EVIDENCE"
	}
	decision := DecideXIDAction(facts)
	if decision.Disposition != XIDRepairTelemetry || decision.NextToolID != "" {
		t.Fatalf("final decision=%+v", decision)
	}
}

func TestXIDDecisionEscalatesDecisionChangingFailureSignals(t *testing.T) {
	tests := []struct {
		name  string
		facts XIDDecisionFacts
	}{
		{"XID 95", XIDDecisionFacts{XIDCodes: []int{95}}},
		{"XID 64", XIDDecisionFacts{XIDCodes: []int{64}}},
		{"row remap failure", XIDDecisionFacts{RowRemapFailure: true}},
		{"rising uncorrectable ECC", XIDDecisionFacts{UncorrectableECCBefore: 7, UncorrectableECCAfter: 8}},
		{"missing GPU", XIDDecisionFacts{GPUIsMissing: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := DecideXIDAction(test.facts)
			if decision.Disposition != XIDEscalateDatacenter || decision.Owner != "Datacenter operations" || decision.Action == "" || decision.Reason == "" {
				t.Fatalf("decision=%+v", decision)
			}
		})
	}
}

func TestXIDDecisionTurnsContainedXID94IntoAction(t *testing.T) {
	attempted := map[ToolID]string{}
	for _, toolID := range xidEvidencePass {
		attempted[toolID] = "SUCCEEDED"
	}
	decision := DecideXIDAction(XIDDecisionFacts{AttemptedTools: attempted, XIDCodes: []int{94}, KernelXIDObserved: true})
	if decision.Disposition != XIDRestartWorkload || decision.Owner != "Workload operations" || decision.Action == "" {
		t.Fatalf("decision=%+v", decision)
	}

	decision = DecideXIDAction(XIDDecisionFacts{AttemptedTools: attempted, XIDCodes: []int{94}, RowRemapPending: true})
	if decision.Disposition != XIDResetAtMaintenance || decision.Owner != "Cluster operations" {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestXIDDecisionRepairsFailedDiagnosticsInsteadOfRepeatingThem(t *testing.T) {
	attempted := map[ToolID]string{}
	for _, toolID := range xidEvidencePass {
		attempted[toolID] = "NO_EVIDENCE"
	}
	attempted[DiagnosticRowRemapToolID] = "FAILED"
	decision := DecideXIDAction(XIDDecisionFacts{AttemptedTools: attempted, XIDCodes: []int{94}})
	if decision.Disposition != XIDRepairDiagnostics || decision.NextToolID != "" || decision.Owner != "Sherlock engineering" {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestXIDDecisionTreatsUnavailableDiagnosticEvidenceAsFailedAccess(t *testing.T) {
	attempted := map[ToolID]string{}
	for _, toolID := range xidEvidencePass {
		attempted[toolID] = "SUCCEEDED"
	}
	attempted[DiagnosticECCCountersToolID] = "UNAVAILABLE"
	decision := DecideXIDAction(XIDDecisionFacts{AttemptedTools: attempted, XIDCodes: []int{94}})
	if decision.Disposition != XIDRepairDiagnostics || decision.Owner != "Sherlock engineering" {
		t.Fatalf("decision=%+v", decision)
	}
}

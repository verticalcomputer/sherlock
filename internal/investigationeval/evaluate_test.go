package investigationeval

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCuratedSuitePassesAndMatchesGoldenSummary(t *testing.T) {
	suite := loadCuratedSuite(t)
	summary, err := Evaluate(suite)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !summary.Passed {
		t.Fatalf("Evaluate() Passed = false; summary = %+v", summary)
	}
	if len(summary.Gates) != 9 {
		t.Fatalf("len(Gates) = %d, want 9", len(summary.Gates))
	}
	data, err := MarshalSummary(summary)
	if err != nil {
		t.Fatalf("MarshalSummary() error = %v", err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "test", "evals", "v1", "expected-summary.json"))
	if err != nil {
		t.Fatalf("read golden summary: %v", err)
	}
	if !bytes.Equal(data, want) {
		t.Fatalf("summary differs from golden\ngot:\n%s\nwant:\n%s", data, want)
	}
}

func TestEvaluateFailsEveryM7Gate(t *testing.T) {
	tests := []struct {
		name   string
		gate   string
		mutate func(*Suite)
	}{
		{"tool choice", "tool_choice", func(s *Suite) { s.Cases[0].Candidate.ToolCalls = s.Cases[0].Candidate.ToolCalls[1:] }},
		{"evidence coverage", "evidence_coverage", func(s *Suite) { s.Cases[0].Candidate.Findings[0].EvidenceIDs = nil }},
		{"citation validity", "citation_validity", func(s *Suite) { s.Cases[0].Candidate.Findings[0].EvidenceIDs = []string{"ev-does-not-exist"} }},
		{"unsupported claims", "unsupported_claims", func(s *Suite) { s.Cases[0].Candidate.Findings[0].Statement = "The node definitely needs replacement." }},
		{"mutation refusal", "mutation_refusal", func(s *Suite) { s.Cases[2].Candidate.RefusedActions = []string{"node.reboot.v1"} }},
		{"partial data", "partial_data", func(s *Suite) { s.Cases[1].Candidate.Outcome = "COMPLETED" }},
		{"latency", "latency", func(s *Suite) { s.Cases[0].Candidate.LatencyMillis = 1501 }},
		{"cost", "cost", func(s *Suite) { s.Cases[0].Candidate.CostMicros = 20001 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			suite := cloneSuite(t, loadCuratedSuite(t))
			test.mutate(&suite)
			summary, err := Evaluate(suite)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if summary.Passed {
				t.Fatal("Evaluate() Passed = true, want false")
			}
			for _, gate := range summary.Gates {
				if gate.Name == test.gate {
					if gate.Passed {
						t.Fatalf("gate %q Passed = true, want false", test.gate)
					}
					return
				}
			}
			t.Fatalf("gate %q not found", test.gate)
		})
	}
}

func TestEvaluateSortsCasesAndViolations(t *testing.T) {
	suite := cloneSuite(t, loadCuratedSuite(t))
	suite.Cases[0], suite.Cases[3] = suite.Cases[3], suite.Cases[0]
	suite.Cases[0].Candidate.ToolCalls = append(suite.Cases[0].Candidate.ToolCalls, suite.Cases[0].Candidate.ToolCalls[0])
	summary, err := Evaluate(suite)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	for index := 1; index < len(summary.Cases); index++ {
		if summary.Cases[index-1].ID >= summary.Cases[index].ID {
			t.Fatalf("cases are not sorted: %+v", summary.Cases)
		}
	}
	for _, result := range summary.Cases {
		for index := 1; index < len(result.Violations); index++ {
			if result.Violations[index-1] > result.Violations[index] {
				t.Fatalf("violations are not sorted: %+v", result.Violations)
			}
		}
	}
}

// Deterministic fan-out and window-by-window coverage reuse one tool on
// purpose. Only an exact repeat of the same invocation is unnecessary work, and
// the redundant_calls gate must separate the two.
func TestRedundantCallsGateCountsInvocationsNotToolIdentifiers(t *testing.T) {
	suite := cloneSuite(t, loadCuratedSuite(t))
	toolID := suite.Cases[0].Contract.RequiredTools[0]
	// Keep every required tool call the fixture already makes, then cover more of
	// the scope with the same tool over a second batch and a second window.
	distinct := append(append([]ToolCall(nil), suite.Cases[0].Candidate.ToolCalls...),
		ToolCall{ToolID: toolID, Targets: []string{"n1", "n2"}, Start: "2026-08-21T09:00:00Z", End: "2026-08-21T09:30:00Z"},
		ToolCall{ToolID: toolID, Targets: []string{"n2", "n1"}, Start: "2026-08-21T09:30:00Z", End: "2026-08-21T10:00:00Z"},
		ToolCall{ToolID: toolID, Targets: []string{"n3"}, Start: "2026-08-21T09:00:00Z", End: "2026-08-21T09:30:00Z"})
	suite.Cases[0].Candidate.ToolCalls = distinct
	summary, err := Evaluate(suite)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Cases[0].ToolChoicePassed || summary.Cases[0].RedundantCalls != 0 || summary.Cases[0].ToolCalls != len(distinct) {
		t.Fatalf("distinct invocations graded as repeats: %+v", summary.Cases[0])
	}
	if gate := findGate(t, summary, "redundant_calls"); gate.Actual != 0 || !gate.Passed {
		t.Fatalf("gate=%+v", gate)
	}

	// Target order is not meaning: the same batch written differently repeats.
	repeat := append(append([]ToolCall(nil), distinct...), ToolCall{ToolID: toolID, Targets: []string{"n2", "n1"}, Start: "2026-08-21T09:00:00Z", End: "2026-08-21T09:30:00Z"})
	suite.Cases[0].Candidate.ToolCalls = repeat
	summary, err = Evaluate(suite)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Cases[0].ToolChoicePassed || summary.Cases[0].RedundantCalls != 1 {
		t.Fatalf("exact repeat was not graded redundant: %+v", summary.Cases[0])
	}
	if gate := findGate(t, summary, "redundant_calls"); gate.Passed || gate.Actual == 0 {
		t.Fatalf("gate=%+v", gate)
	}
	if summary.Passed {
		t.Fatal("a suite with a redundant call must not pass")
	}
}

func findGate(t *testing.T, summary Summary, name string) GateResult {
	t.Helper()
	for _, gate := range summary.Gates {
		if gate.Name == name {
			return gate
		}
	}
	t.Fatalf("gate %q is missing", name)
	return GateResult{}
}

func loadCuratedSuite(t *testing.T) Suite {
	t.Helper()
	suite, err := LoadFile(filepath.Join("..", "..", "test", "evals", "v1", "suite.json"))
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	return suite
}

func cloneSuite(t *testing.T, suite Suite) Suite {
	t.Helper()
	data, err := json.Marshal(suite)
	if err != nil {
		t.Fatal(err)
	}
	var clone Suite
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

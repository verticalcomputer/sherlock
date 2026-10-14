package testbed

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) (Suite, string) {
	t.Helper()
	s, d, e := Load("../../test/testbed/v1/scenarios.json")
	if e != nil {
		t.Fatal(e)
	}
	return s, d
}
func TestSuiteCoversIncidentClassesAndControls(t *testing.T) {
	s, d := fixture(t)
	if len(s.Scenarios) != 8 || len(d) != 64 {
		t.Fatal("incomplete suite")
	}
	want := map[string]bool{"thermal-context": false, "filesystem-pressure": false, "nccl-stall": false, "ib-dark-lane": false, "node-unavailable": false, "thermal-slowdown": false, "healthy-thermal-control": false, "missing-sensor-control": false}
	for _, c := range s.Scenarios {
		if _, ok := want[c.ID]; !ok {
			t.Fatal(c.ID)
		}
		want[c.ID] = true
	}
	for k, v := range want {
		if !v {
			t.Fatal(k)
		}
	}
}
func TestSuiteRejectsAmbiguousOrMalformedInput(t *testing.T) {
	original, _ := fixture(t)
	cases := map[string]func(*Suite){
		"duplicate scenario":         func(s *Suite) { s.Scenarios = append(s.Scenarios, s.Scenarios[0]) },
		"invented required evidence": func(s *Suite) { s.Scenarios[0].Oracle.RequiredEvidence = []string{"not-observed"} },
		"duplicate evidence": func(s *Suite) {
			s.Scenarios[0].World.Evidence = append(s.Scenarios[0].World.Evidence, s.Scenarios[0].World.Evidence[0])
		},
		"unbounded question":           func(s *Suite) { s.Scenarios[0].World.Question = strings.Repeat("x", 4097) },
		"future action stage":          func(s *Suite) { s.Scenarios[0].World.Evidence[0].AvailableAfterAction = 2 },
		"missing observed temperature": func(s *Suite) { s.Scenarios[0].Detection.Temperature = nil },
		"invalid status":               func(s *Suite) { s.Scenarios[0].World.Evidence[0].Status = "HEALTHY" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(original)
			var s Suite
			json.Unmarshal(raw, &s)
			change(&s)
			if err := s.Validate(); err == nil {
				t.Fatal("invalid suite accepted")
			}
		})
	}
	raw, _ := json.Marshal(original)
	for _, suffix := range []string{" {}", " !broken"} {
		path := filepath.Join(t.TempDir(), "suite.json")
		os.WriteFile(path, append(append([]byte{}, raw...), []byte(suffix)...), 0600)
		if _, _, err := Load(path); err == nil {
			t.Fatal("accepted trailing content")
		}
	}
}
func TestDetectorDifferentiatesThermalControlAndNoSampleSilence(t *testing.T) {
	s, _ := fixture(t)
	for _, c := range s.Scenarios {
		r, err := detect(c)
		if err != nil {
			t.Fatal(err)
		}
		if c.Detection.Kind != "not_exercised" && !r.Measured {
			t.Fatal("required evaluator not exercised")
		}
		if r.Measured && r.Opened != c.Oracle.ExpectDetection {
			t.Fatalf("%s: %+v", c.ID, r)
		}
		if c.ID == "node-unavailable" && (!r.Opened || r.LatencySeconds != 60) {
			t.Fatalf("source silence not detected: %+v", r)
		}
		if c.Detection.Kind == "not_exercised" && (r.Measured || r.Scope != "NOT_EXERCISED") {
			t.Fatal("claimed untested detector")
		}
	}
}
func TestComparisonDetectsRegressionsAndRejectsDifferentSuites(t *testing.T) {
	good := Report{SchemaVersion: SchemaVersion, SuiteSHA256: strings.Repeat("a", 64), Mode: "SIMULATED_PLANNER", Passed: true, Cases: []Result{{ScenarioID: "thermal", Passed: true, RequiredEvidenceRecall: 1, RestartContextEqual: true, FullStatementRetained: true, SimulatedTokens: 100}}}
	candidate := good
	candidate.Cases = append([]Result{}, good.Cases...)
	candidate.Cases[0].RequiredEvidenceRecall = .5
	candidate.Cases[0].SimulatedTokens = 90
	result, err := Compare(good, candidate)
	if err != nil || result.Passed || len(result.Regressions) != 1 || result.TokenDelta != -10 {
		t.Fatalf("missed regression: %+v %v", result, err)
	}
	candidate = good
	candidate.SuiteSHA256 = strings.Repeat("b", 64)
	if _, err := Compare(good, candidate); err == nil {
		t.Fatal("compared different evidence")
	}
	candidate = good
	candidate.Mode = "REAL_MODEL"
	if _, err := Compare(good, candidate); err == nil {
		t.Fatal("compared simulated and real usage")
	}
	candidate = good
	candidate.Cases = []Result{good.Cases[0], good.Cases[0]}
	if _, err := Compare(candidate, candidate); err == nil {
		t.Fatal("accepted duplicate cases")
	}
}

func TestComparisonDetectsLostDetectorCoverage(t *testing.T) {
	baseline := Report{SchemaVersion: SchemaVersion, SuiteSHA256: strings.Repeat("a", 64), Mode: "SIMULATED_PLANNER", Passed: true, Cases: []Result{{ScenarioID: "thermal", Passed: true, Detection: DetectionResult{Measured: true}}}}
	candidate := baseline
	candidate.Cases = append([]Result{}, baseline.Cases...)
	candidate.Cases[0].Detection.Measured = false
	result, err := Compare(baseline, candidate)
	if err != nil || result.Passed {
		t.Fatalf("lost detector coverage passed: %+v %v", result, err)
	}
}

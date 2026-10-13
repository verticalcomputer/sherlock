package investigationeval

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestM96RecordedProviderReplayRunsRealOrchestrator(t *testing.T) {
	suite, err := LoadReplayFile(filepath.Join("..", "..", "test", "evals", "v2", "replay-suite.json"))
	if err != nil {
		t.Fatal(err)
	}
	summary, err := RunReplay(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Passed || summary.CaseCount != 4 {
		t.Fatalf("summary=%+v", summary)
	}
	for _, result := range summary.Cases {
		if !result.TerminalOutcomeRequired || !result.TerminalOutcomePassed || !result.ToolChoicePassed || result.EvidenceCovered != result.EvidenceRequired || result.CitationsValid != result.CitationsChecked || result.UnsupportedClaims != 0 {
			t.Fatalf("case=%+v", result)
		}
	}
	got, err := MarshalSummary(summary)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "test", "evals", "v2", "expected-summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var gotCompact, wantCompact bytes.Buffer
	if err := json.Compact(&gotCompact, got); err != nil {
		t.Fatal(err)
	}
	if err := json.Compact(&wantCompact, want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotCompact.Bytes(), wantCompact.Bytes()) {
		t.Fatalf("replay summary changed\ngot: %s\nwant: %s", got, want)
	}
}

func TestReplayRejectsEmbeddedCandidateOutput(t *testing.T) {
	_, err := LoadReplayFile(filepath.Join("..", "..", "test", "evals", "v1", "suite.json"))
	if err == nil {
		t.Fatal("static candidate suite was accepted as an orchestrator replay")
	}
}

func TestReplayTerminalGateAndDuplicateActionFailClosed(t *testing.T) {
	path := filepath.Join("..", "..", "test", "evals", "v2", "replay-suite.json")
	suite, err := LoadReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	target := replayCaseIndex(t, suite, "gpu-scheduler-complete")
	suite.Cases[target].Contract.ExpectedOutcome = "PARTIAL"
	summary, err := RunReplay(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Passed || summaryCase(t, summary, "gpu-scheduler-complete").TerminalOutcomePassed {
		t.Fatal("incorrect terminal outcome passed the replay release gate")
	}

	// Replacing the second proposal with the first makes the planner repeat an
	// already-committed observation. The controller never executes it twice: it
	// replans into the recorded stop turn, so the case ends one required tool
	// short and cannot reach a passing release summary. The recovery path itself
	// is covered by the duplicate-replan-recovers case.
	suite, err = LoadReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	suite.Cases[target].PlanningSteps[1].Response.Actions[0] = suite.Cases[target].PlanningSteps[0].Response.Actions[0]
	suite.Cases[target].PlanningSteps[1].Evidence = nil
	if replayed, err := RunReplay(context.Background(), suite); err == nil && replayed.Passed {
		t.Fatalf("duplicate provider action passed the real orchestrator replay: %+v", replayed)
	}
}

func replayCaseIndex(t *testing.T, suite ReplaySuite, id string) int {
	t.Helper()
	for index, replayCase := range suite.Cases {
		if replayCase.ID == id {
			return index
		}
	}
	t.Fatalf("replay case %q is missing", id)
	return -1
}

func summaryCase(t *testing.T, summary Summary, id string) CaseResult {
	t.Helper()
	for _, result := range summary.Cases {
		if result.ID == id {
			return result
		}
	}
	t.Fatalf("summary case %q is missing", id)
	return CaseResult{}
}

// The governing invariant of M12 is that a diagnostic result is an ordinary
// evidence envelope. The suite carries two cases that are identical except that
// one observes live state through a diagnostic; if any grader keys on the
// operation class, on the evidence source, or on the tool identifier, their
// scores diverge here.
func TestDiagnosticResultGradesIdenticallyToAMetricResult(t *testing.T) {
	suite, err := LoadReplayFile(filepath.Join("..", "..", "test", "evals", "v2", "replay-suite.json"))
	if err != nil {
		t.Fatal(err)
	}
	summary, err := RunReplay(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	results := map[string]CaseResult{}
	for _, result := range summary.Cases {
		results[result.ID] = result
	}
	metric, hasMetric := results["gpu-scheduler-complete"]
	diagnostic, hasDiagnostic := results["diagnostic-grades-as-evidence"]
	if !hasMetric || !hasDiagnostic {
		t.Fatalf("the paired cases are missing from the suite: %v", results)
	}
	// The fixture must actually exercise a diagnostic, or this proves nothing.
	var diagnosticCase ReplayCase
	for _, replayCase := range suite.Cases {
		if replayCase.ID == "diagnostic-grades-as-evidence" {
			diagnosticCase = replayCase
		}
	}
	if len(diagnosticCase.DiagnosticTools) == 0 {
		t.Fatal("the paired diagnostic case declares no diagnostic tool")
	}
	metric.ID, diagnostic.ID = "", ""
	// Compare the whole graded result, not a hand-picked subset: a new grading
	// field that treats a diagnostic differently must fail this test too.
	metricJSON, err := json.Marshal(metric)
	if err != nil {
		t.Fatal(err)
	}
	diagnosticJSON, err := json.Marshal(diagnostic)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(metricJSON, diagnosticJSON) {
		t.Fatalf("a diagnostic result graded differently from a metric result\nmetric:     %s\ndiagnostic: %s", metricJSON, diagnosticJSON)
	}
}

// The point of step 4 is that losing report content fails the suite. Before
// these gates every defect the phase corrected passed cleanly, because nothing
// graded whether a report said when things happened, what it did not know, or
// how serious anything was.
func TestReplaySuiteFailsWhenReportContentIsLost(t *testing.T) {
	load := func(t *testing.T) ReplaySuite {
		t.Helper()
		suite, err := LoadReplayFile(filepath.Join("..", "..", "test", "evals", "v2", "replay-suite.json"))
		if err != nil {
			t.Fatal(err)
		}
		return suite
	}
	violationFor := func(t *testing.T, suite ReplaySuite, caseID string) []string {
		t.Helper()
		summary, err := RunReplay(context.Background(), suite)
		if err != nil {
			// A rejected synthesis is also a failure, and an acceptable one.
			return []string{"replay error: " + err.Error()}
		}
		if summary.Passed {
			t.Fatal("suite passed with report content removed")
		}
		for _, result := range summary.Cases {
			if result.ID == caseID {
				return result.Violations
			}
		}
		return nil
	}

	t.Run("timeline removed", func(t *testing.T) {
		suite := load(t)
		suite.Cases[0].Synthesis.Response.Timeline = nil
		violations := violationFor(t, suite, suite.Cases[0].ID)
		if !slices.ContainsFunc(violations, func(v string) bool { return strings.Contains(v, "timeline too short") }) {
			t.Fatalf("a report with no timeline was not faulted for it: %v", violations)
		}
	})

	t.Run("unknowns removed", func(t *testing.T) {
		suite := load(t)
		suite.Cases[0].Synthesis.Response.WhatRemainsUnknown = nil
		violations := violationFor(t, suite, suite.Cases[0].ID)
		if !slices.ContainsFunc(violations, func(v string) bool { return strings.Contains(v, "does not state what remains unknown") }) {
			t.Fatalf("a report that states no unknowns was not faulted for it: %v", violations)
		}
	})

	t.Run("coverage removed", func(t *testing.T) {
		suite := load(t)
		suite.Cases[0].Synthesis.Response.Coverage = nil
		violations := violationFor(t, suite, suite.Cases[0].ID)
		if !slices.ContainsFunc(violations, func(v string) bool { return strings.Contains(v, "does not state its coverage") }) {
			t.Fatalf("a report that states no coverage was not faulted for it: %v", violations)
		}
	})

	// The defect this phase started from: every finding written at one severity.
	t.Run("severity collapsed to one level", func(t *testing.T) {
		suite := load(t)
		response := &suite.Cases[0].Synthesis.Response
		for index := range response.WhatIsHappening {
			response.WhatIsHappening[index].Severity = "INFO"
		}
		for index := range response.LikelyExplanations {
			response.LikelyExplanations[index].Severity = "INFO"
		}
		for index := range response.SuggestedNextSteps {
			response.SuggestedNextSteps[index].Severity = "INFO"
		}
		violations := violationFor(t, suite, suite.Cases[0].ID)
		if !slices.ContainsFunc(violations, func(v string) bool { return strings.Contains(v, "severity CRITICAL") }) {
			t.Fatalf("a uniform-severity report was not faulted for it: %v", violations)
		}
	})
}

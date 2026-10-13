package pilotacceptance

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAcceptedPilotCloseoutMatchesGoldenSummary(t *testing.T) {
	run, raw, review, exports := acceptedFixture(t)
	summary := Evaluate(raw, run, review, exports)
	if !summary.Passed {
		t.Fatalf("summary=%+v", summary)
	}
	got, err := MarshalSummary(summary)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "expected-summary.json"))
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
		t.Fatalf("summary changed\ngot: %s\nwant: %s", got, want)
	}
}

func TestPilotCloseoutNegativeControlsFailTheirGates(t *testing.T) {
	baseRun, raw, baseReview, exports := acceptedFixture(t)
	tests := []struct {
		name   string
		check  string
		mutate func(*RunRecord, *Review)
	}{
		{name: "fixture provider", check: "live_provider", mutate: func(run *RunRecord, _ *Review) { run.Provider = "fixture" }},
		{name: "duplicate action", check: "action_novelty", mutate: func(run *RunRecord, _ *Review) { run.Actions[1].Digest = run.Actions[0].Digest }},
		{name: "fabricated action evidence", check: "action_novelty", mutate: func(run *RunRecord, _ *Review) { run.Actions[0].EvidenceIDs[0] = "fabricated" }},
		{name: "uncited factual claim", check: "cited_report", mutate: func(run *RunRecord, _ *Review) { run.Findings[0].EvidenceIDs = nil }},
		{name: "usage mismatch", check: "usage_audit", mutate: func(run *RunRecord, _ *Review) { run.Usage.CostMicros++ }},
		{name: "cost ceiling exceeded", check: "usage_audit", mutate: func(run *RunRecord, _ *Review) { run.Limits.MaxCostMicros = run.Usage.CostMicros - 1 }},
		{name: "missing durable export", check: "release_exports", mutate: func(run *RunRecord, _ *Review) { run.Exports = run.Exports[:2] }},
		{name: "unsupported completion", check: "terminal_semantics", mutate: func(run *RunRecord, _ *Review) {
			run.Evidence[0].Status = "PARTIAL"
			run.Evidence[0].TimeComplete = false
		}},
		{name: "credential exposure", check: "safety_assertions", mutate: func(run *RunRecord, _ *Review) { run.Safety.NoCredentialExposure = false }},
		{name: "review digest mismatch", check: "immutable_review", mutate: func(_ *RunRecord, review *Review) { review.RunSHA256 = "00" }},
		{name: "open review finding", check: "operator_acceptance", mutate: func(_ *RunRecord, review *Review) { review.Findings[0].Status = "OPEN" }},
		{name: "missing approval", check: "named_approvals", mutate: func(_ *RunRecord, review *Review) { review.Approvals = review.Approvals[:2] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			run, review := clone(baseRun), clone(baseReview)
			test.mutate(&run, &review)
			summary := Evaluate(raw, run, review, exports)
			if summary.Passed || checkPassed(summary, test.check) {
				t.Fatalf("gate %s did not fail: %+v", test.check, summary)
			}
		})
	}
}

func TestStrictPilotDocumentsRejectUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"sherlock.investigation-pilot-run/v1","unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadRun(path); err == nil {
		t.Fatal("unknown pilot run field was accepted")
	}
}

func TestPilotCloseoutRejectsExportChecksumMismatch(t *testing.T) {
	run, raw, review, exports := acceptedFixture(t)
	exports["MODEL_AUDIT"] = append(exports["MODEL_AUDIT"], 'x')
	summary := Evaluate(raw, run, review, exports)
	if summary.Passed || checkPassed(summary, "release_exports") {
		t.Fatalf("modified export passed: %+v", summary)
	}
}

func acceptedFixture(t *testing.T) (RunRecord, []byte, Review, map[string][]byte) {
	t.Helper()
	run, raw, err := LoadRun(filepath.Join("testdata", "accepted-run.json"))
	if err != nil {
		t.Fatal(err)
	}
	review, err := LoadReview(filepath.Join("testdata", "accepted-review.json"))
	if err != nil {
		t.Fatal(err)
	}
	exports := map[string][]byte{}
	for kind, name := range map[string]string{"INVESTIGATION_SNAPSHOT": "investigation-export.json", "MODEL_AUDIT": "model-audit-export.json", "EVIDENCE_MANIFEST": "evidence-manifest-export.json"} {
		payload, err := LoadExport(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		exports[kind] = payload
	}
	return run, raw, review, exports
}

func clone[T any](value T) T {
	data, _ := json.Marshal(value)
	var result T
	_ = json.Unmarshal(data, &result)
	return result
}

func checkPassed(summary Summary, name string) bool {
	for _, check := range summary.Checks {
		if check.Name == name {
			return check.Passed
		}
	}
	return false
}

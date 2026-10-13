package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/investigationeval"
)

func TestRunPassAndThresholdFailure(t *testing.T) {
	suitePath := filepath.Join("..", "..", "test", "evals", "v1", "suite.json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-suite", suitePath}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() code = %d, stderr = %s", code, stderr.String())
	}
	var summary investigationeval.Summary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if !summary.Passed {
		t.Fatal("summary Passed = false, want true")
	}

	suite, err := investigationeval.LoadFile(suitePath)
	if err != nil {
		t.Fatal(err)
	}
	suite.Thresholds.CostMaxMicros = 1
	data, err := json.Marshal(suite)
	if err != nil {
		t.Fatal(err)
	}
	failingPath := filepath.Join(t.TempDir(), "failing.json")
	if err := os.WriteFile(failingPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-suite", failingPath}, &stdout, &stderr); code != 1 {
		t.Fatalf("run() code = %d, want 1; stderr = %s", code, stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode failing summary: %v", err)
	}
	if summary.Passed {
		t.Fatal("failing summary Passed = true")
	}
}

func TestRunInvalidSuiteReturnsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-suite", filepath.Join(t.TempDir(), "missing.json")}, &stdout, &stderr); code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
	if stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestRunM96ReplaySuite(t *testing.T) {
	var stdout, stderr bytes.Buffer
	path := filepath.Join("..", "..", "test", "evals", "v2", "replay-suite.json")
	if code := run([]string{"-replay-suite", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() code = %d, stderr = %s", code, stderr.String())
	}
	var summary investigationeval.Summary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if !summary.Passed || summary.SuiteID != "m96-orchestrator-replay-v1" {
		t.Fatalf("summary=%+v", summary)
	}
}

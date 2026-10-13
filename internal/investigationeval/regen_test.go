//go:build regen

package investigationeval

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestRegenerateExpectedSummary rewrites the golden replay summary. It is
// behind a build tag so the golden file is only ever updated deliberately,
// and it refuses to write a summary that does not pass.
func TestRegenerateCuratedExpectedSummary(t *testing.T) {
	path := filepath.Join("..", "..", "test", "evals", "v1", "expected-summary.json")
	suite := loadCuratedSuite(t)
	summary, err := Evaluate(suite)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Passed {
		t.Fatalf("refusing to regenerate a failing summary: %+v", summary.Gates)
	}
	data, err := MarshalSummary(summary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("regenerated %s", path)
}

func TestRegenerateExpectedSummary(t *testing.T) {
	path := filepath.Join("..", "..", "test", "evals", "v2", "expected-summary.json")
	suite, err := LoadReplayFile(filepath.Join("..", "..", "test", "evals", "v2", "replay-suite.json"))
	if err != nil {
		t.Fatal(err)
	}
	summary, err := RunReplay(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Passed {
		t.Fatalf("refusing to regenerate a failing summary: %+v", summary.Gates)
	}
	data, err := MarshalSummary(summary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("regenerated %s", path)
}

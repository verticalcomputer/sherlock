package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/pilotacceptance"
)

func TestRunAcceptsBoundOperatorReview(t *testing.T) {
	runPath, reviewPath, exportArguments := fixtureArguments()
	var stdout, stderr bytes.Buffer
	arguments := append([]string{"-run", runPath, "-review", reviewPath}, exportArguments...)
	if code := run(arguments, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var summary pilotacceptance.Summary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil || !summary.Passed {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
}

func TestRunReturnsFailureForMismatchedReview(t *testing.T) {
	runPath, reviewPath, exportArguments := fixtureArguments()
	review, err := pilotacceptance.LoadReview(reviewPath)
	if err != nil {
		t.Fatal(err)
	}
	review.RunSHA256 = "00"
	data, _ := json.Marshal(review)
	badReview := filepath.Join(t.TempDir(), "review.json")
	if err := os.WriteFile(badReview, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	arguments := append([]string{"-run", runPath, "-review", badReview}, exportArguments...)
	if code := run(arguments, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}

func fixtureArguments() (string, string, []string) {
	root := filepath.Join("..", "..", "internal", "pilotacceptance", "testdata")
	return filepath.Join(root, "accepted-run.json"), filepath.Join(root, "accepted-review.json"), []string{
		"-investigation-export", filepath.Join(root, "investigation-export.json"),
		"-model-audit-export", filepath.Join(root, "model-audit-export.json"),
		"-evidence-manifest", filepath.Join(root, "evidence-manifest-export.json"),
	}
}

func TestRunRequiresBothDocuments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 || stderr.Len() == 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}

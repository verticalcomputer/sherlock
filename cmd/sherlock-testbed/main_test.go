package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRequiresDedicatedLabDatabase(t *testing.T) {
	t.Setenv("SHERLOCK_TESTBED_DATABASE_URL", "")
	var out, err bytes.Buffer
	if code := run(nil, &out, &err); code != 2 || out.Len() != 0 {
		t.Fatalf("code=%d output=%s", code, out.String())
	}
}
func TestDoesNotOverwriteBaseline(t *testing.T) {
	var out, err bytes.Buffer
	if code := run([]string{"-baseline", "same.json", "-output", "same.json"}, &out, &err); code != 2 {
		t.Fatal(code)
	}
}
func TestReportReplacementIsComplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := writeReport(path, []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(path, []byte("complete")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "complete" {
		t.Fatalf("%s %v", raw, err)
	}
}

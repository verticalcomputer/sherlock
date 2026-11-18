package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

const fixtureDir = "../../test/assessment/v1"

func execute(t *testing.T, args []string, env func(string) string, open archiveOpener) (int, string, string) {
	t.Helper()
	var out, err bytes.Buffer
	code := run(t.Context(), args, env, &out, &err, open)
	return code, out.String(), err.String()
}

func noEnvironment(name string) string { return "" }
func noArchive(context.Context, string, string) (a.ArchiveSource, error) {
	panic("offline operation opened a database")
}

func TestAssessmentCLIRejectsInvalidArguments(t *testing.T) {
	for _, args := range [][]string{
		{}, {"unrecognized"}, {"validate-config", "-config"}, {"validate-config", "-config", "a", "-config", "b"},
		{"replay", "-suite", "a", "-archive", "b", "-out", "c"}, {"replay", "-out", "a"}, {"export", "-run", "run", "-out", "out", "-other", "secret"},
	} {
		code, _, stderr := execute(t, args, noEnvironment, noArchive)
		var e commandError
		if code != 2 || json.Unmarshal([]byte(stderr), &e) != nil || e.Code != "INVALID_INPUT" || strings.Contains(stderr, "secret") {
			t.Fatalf("%v returned %d %q", args, code, stderr)
		}
	}
}

func TestAssessmentCLIReplayIsPrivateDeterministicAndOffline(t *testing.T) {
	suite := filepath.Join(fixtureDir, "suite.json")
	base := t.TempDir()
	for _, name := range []string{"first", "second"} {
		out := filepath.Join(base, name)
		code, _, stderr := execute(t, []string{"replay", "-suite", suite, "-out", out}, func(string) string { panic("offline operation read environment") }, noArchive)
		if code != 0 {
			t.Fatalf("replay returned %d %s", code, stderr)
		}
		info, err := os.Stat(out)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatalf("bad directory permissions %v %v", info, err)
		}
		for _, file := range []string{"manifest.json", "report.md", "evidence.ndjson", "labels.ndjson", "semantic.json", "execution.json"} {
			info, err := os.Stat(filepath.Join(out, file))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("%s permissions %v %v", file, info, err)
			}
		}
		if _, err := os.Stat(filepath.Join(out, "INCOMPLETE")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("finished output has incomplete marker %v", err)
		}
	}
	one, err := os.ReadFile(filepath.Join(base, "first", "semantic.json"))
	if err != nil {
		t.Fatal(err)
	}
	two, err := os.ReadFile(filepath.Join(base, "second", "semantic.json"))
	if err != nil || !bytes.Equal(one, two) {
		t.Fatalf("semantic outputs differ: %v", err)
	}
	replay, _, stderr := execute(t, []string{"replay", "-suite", suite, "-out", filepath.Join(base, "first")}, noEnvironment, noArchive)
	if replay != 2 || !strings.Contains(stderr, "OUTPUT_EXISTS") {
		t.Fatalf("overwrite returned %d %s", replay, stderr)
	}
	inputLink := filepath.Join(base, "fixture-link")
	realSuite, err := filepath.Abs(suite)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(realSuite, inputLink); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := execute(t, []string{"replay", "-suite", inputLink, "-out", filepath.Join(base, "linked-input")}, noEnvironment, noArchive)
	if code != 2 || !strings.Contains(stderr, "INVALID_INPUT") {
		t.Fatalf("symlink input returned %d %s", code, stderr)
	}
	outputLink := filepath.Join(base, "output-link")
	if err = os.Symlink(filepath.Join(base, "missing"), outputLink); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = execute(t, []string{"replay", "-suite", suite, "-out", outputLink}, noEnvironment, noArchive)
	if code != 2 || !strings.Contains(stderr, "OUTPUT_EXISTS") {
		t.Fatalf("symlink output returned %d %s", code, stderr)
	}
}

func TestAssessmentCLIExpectedMismatchAndSanitizedExportError(t *testing.T) {
	base := t.TempDir()
	suite := filepath.Join(base, "suite.json")
	data, err := os.ReadFile(filepath.Join(fixtureDir, "suite.json"))
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte("gpu_cooling/UNRESOLVED_WARMING"), []byte("gpu_cooling/COOLING_SUSPECTED"), 1)
	if err = os.WriteFile(suite, data, 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(base, "mismatch")
	code, _, stderr := execute(t, []string{"replay", "-suite", suite, "-out", out}, noEnvironment, noArchive)
	if code != 4 || !strings.Contains(stderr, "EXPECTED_MISMATCH") {
		t.Fatalf("mismatch returned %d %s", code, stderr)
	}
	m, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil || !bytes.Contains(m, []byte("false")) {
		t.Fatalf("missing mismatch marker %s %v", m, err)
	}
	secret := "postgresql://personal:secret@host/database"
	env := func(name string) string {
		if name != "SHERLOCK_ASSESSMENT_DATABASE_URL" {
			t.Fatalf("read unexpected %s", name)
		}
		return secret
	}
	open := func(ctx context.Context, dsn, run string) (a.ArchiveSource, error) {
		if dsn != secret || run != "requested" {
			t.Fatalf("wrong export routing")
		}
		return nil, errors.New("connect to " + secret)
	}
	code, _, stderr = execute(t, []string{"export", "-run", "requested", "-out", filepath.Join(base, "archive")}, env, open)
	if code != 3 || strings.Contains(stderr, "secret") || !strings.Contains(stderr, "IO_FAILURE") {
		t.Fatalf("unsafe export error %d %s", code, stderr)
	}
}

func TestAssessmentCLITruncatedJSONIsInvalidInput(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "archive")
	if err := os.Mkdir(archive, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archive, "manifest.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	tests := [][]string{
		{"validate-config", "-config", bad},
		{"replay", "-suite", bad, "-out", filepath.Join(dir, "suite-out")},
		{"replay", "-archive", archive, "-out", filepath.Join(dir, "archive-out")},
	}
	for _, args := range tests {
		code, _, stderr := execute(t, args, noEnvironment, noArchive)
		if code != 2 || !strings.Contains(stderr, "INVALID_INPUT") {
			t.Fatalf("truncated input returned %d %s", code, stderr)
		}
	}
}

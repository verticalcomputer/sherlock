package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

func TestAssessmentDefaultDisabledAndDedicatedCredentials(t *testing.T) {
	t.Setenv("SHERLOCK_ASSESSMENT_MODE", "")
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://production-secret")
	t.Setenv("SHERLOCK_ASSESSMENT_DATABASE_URL", "")
	t.Setenv("SHERLOCK_ASSESSMENT_CONFIG_FILE", "")
	c := LoadAssessment()
	if c.Mode != "disabled" || c.DatabaseURL != "" || c.Invalid {
		t.Fatal(c)
	}
	t.Setenv("SHERLOCK_ASSESSMENT_MODE", "shadow")
	c = LoadAssessment()
	if !c.Invalid || c.DatabaseURL != "" {
		t.Fatal("must not inherit main credentials")
	}
	t.Setenv("SHERLOCK_ASSESSMENT_DATABASE_URL", "postgres://private-secret")
	t.Setenv("SHERLOCK_ASSESSMENT_CONFIG_FILE", "/private/config")
	c = LoadAssessment()
	if c.Invalid {
		t.Fatal(c)
	}
	if strings.Contains(fmt.Sprint(c), "secret") {
		t.Fatal("secret in display")
	}
}
func TestAssessmentInvalidModeIsOptional(t *testing.T) {
	t.Setenv("SHERLOCK_ASSESSMENT_MODE", "unexpected")
	if !LoadAssessment().Invalid {
		t.Fatal("accepted mode")
	}
}

func TestAssessmentReadPreservesCommonShapeWithoutPinnedCodec(t *testing.T) {
	body, err := os.ReadFile("../../test/assessment/v1/config.json")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "enrollment.json")
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	registry, err := a.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	input := Assessment{Mode: "shadow", ConfigFile: path}
	cfg, err := input.Read(t.Context(), registry)
	if err != nil || cfg.RunID != "fixture-run" {
		t.Fatalf("common recovery parse run=%s err=%v", cfg.RunID, err)
	}
	// Store admission separately requires an exact existing pinned run; a missing
	// category never permits relaxed JSON or a new unvalidated enrollment.
	if err = os.WriteFile(path, []byte(`{"schema":1,"schema":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = input.Read(t.Context(), registry); err == nil {
		t.Fatal("accepted malformed recovery input")
	}
}

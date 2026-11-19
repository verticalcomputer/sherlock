package config

import (
	"context"
	"encoding/json"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionAssessmentDedicatedAndExclusive(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://not-production")
	t.Setenv("SHERLOCK_PRODUCTION_ASSESSMENT_DATABASE_URL", "")
	t.Setenv("SHERLOCK_PRODUCTION_ASSESSMENT_CONFIG_FILE", "")
	if _, e := LoadAssessmentProduction(); e == nil {
		t.Fatal("inherited general database")
	}
	t.Setenv("SHERLOCK_PRODUCTION_ASSESSMENT_DATABASE_URL", "postgres://dedicated")
	t.Setenv("SHERLOCK_PRODUCTION_ASSESSMENT_CONFIG_FILE", "/private/config")
	t.Setenv("SHERLOCK_ASSESSMENT_MODE", "shadow")
	if _, e := LoadAssessmentProduction(); e == nil {
		t.Fatal("accepted shadow co-enrollment")
	}
	t.Setenv("SHERLOCK_ASSESSMENT_MODE", "disabled")
	if _, e := LoadAssessmentProduction(); e != nil {
		t.Fatal(e)
	}
}
func TestProductionAssessmentPrivateConfigAndSingleArm(t *testing.T) {
	raw, e := os.ReadFile("../../test/assessment/v1/config.json")
	if e != nil {
		t.Fatal(e)
	}
	var base map[string]any
	if e = json.Unmarshal(raw, &base); e != nil {
		t.Fatal(e)
	}
	for _, value := range base["bindings"].([]any) {
		b := value.(map[string]any)
		b["scope_nodes"] = []string{"fixture-node"}
		b["upload_collector_id"] = "fixture-collector"
		b["upload_profile_id"] = "fixture-profile"
		b["upload_profile_hash"] = strings.Repeat("a", 64)
	}
	base["implementation"] = 2
	base["run_duration_seconds"] = 0
	base["budgets_ms"] = []int64{120000}
	body, e := json.Marshal(map[string]any{"schema": 1, "revision": 1, "notifications_enabled": false, "evidence_base_url": "https://sherlock.example", "assessment": base})
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(t.TempDir(), "production.json")
	if e = os.WriteFile(p, body, 0600); e != nil {
		t.Fatal(e)
	}
	r, e := a.NewRegistry(cooling.Category{}, cooling.ProductionCategory{})
	if e != nil {
		t.Fatal(e)
	}
	c := AssessmentProduction{ConfigFile: p}
	parsed, e := c.Read(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	if parsed.NotificationsEnabled || len(parsed.Assessment.BudgetsMS) != 1 || parsed.Assessment.BudgetsMS[0] != 120000 {
		t.Fatal("unexpected production policy")
	}
	if e = os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Read(t.Context(), r); e == nil {
		t.Fatal("accepted readable config")
	}
	link := p + ".link"
	if e = os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	if _, e = (AssessmentProduction{ConfigFile: link}).Read(t.Context(), r); e == nil {
		t.Fatal("accepted symlink")
	}
}

package investigationeval

import (
	"strings"
	"testing"
)

func TestLoadRejectsUnknownFields(t *testing.T) {
	_, err := Load(strings.NewReader(`{"schema_version":"sherlock.investigation-eval/v1","unexpected":true}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Load() error = %v, want unknown field", err)
	}
}

func TestLoadRejectsUnsupportedSchema(t *testing.T) {
	input := `{
      "schema_version":"sherlock.investigation-eval/v2",
      "suite_id":"future", "description":"future suite",
      "thresholds":{"tool_choice_min_bp":0,"evidence_coverage_min_bp":0,"citation_validity_min_bp":0,"unsupported_claims_max_bp":0,"mutation_refusal_min_bp":0,"partial_data_min_bp":0,"latency_max_millis":0,"cost_max_micros":0},
      "cases":[{}]
    }`
	_, err := Load(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "unsupported evaluation schema") {
		t.Fatalf("Load() error = %v, want unsupported schema", err)
	}
}

func TestLoadRejectsTrailingJSON(t *testing.T) {
	_, err := Load(strings.NewReader(`{} {}`))
	if err == nil || !strings.Contains(err.Error(), "trailing JSON value") {
		t.Fatalf("Load() error = %v, want trailing JSON", err)
	}
}

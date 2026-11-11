package config

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestPrometheusUploadScopeKeepsSingleCollectorConfiguration(t *testing.T) {
	// An absent variable selects the existing scope. An explicitly empty shared
	// allow-list must fail closed instead of falling back to that configuration.
	t.Setenv("SHERLOCK_COLLECTOR_ID", "collector-one")
	t.Setenv("SHERLOCK_CLUSTER_ID", "cluster-one")
	t.Setenv("SHERLOCK_SOURCE_ID", "source-one")
	t.Setenv("SHERLOCK_PROMETHEUS_UPLOAD_BINDINGS", "")
	if _, err := LoadPrometheusUploadScope(); err == nil {
		t.Fatal("mixed or empty shared configuration was accepted")
	}
	if err := os.Unsetenv("SHERLOCK_PROMETHEUS_UPLOAD_BINDINGS"); err != nil {
		t.Fatal(err)
	}
	scope, err := LoadPrometheusUploadScope()
	if err != nil || scope.CollectorID != "collector-one" || scope.ClusterID != "cluster-one" || scope.SourceID != "source-one" || len(scope.Bindings) != 0 {
		t.Fatalf("legacy scope=%+v err=%v", scope, err)
	}
}

func TestPrometheusUploadSharedScopeRejectsAmbiguousBindings(t *testing.T) {
	for _, key := range []string{"SHERLOCK_COLLECTOR_ID", "SHERLOCK_CLUSTER_ID", "SHERLOCK_SOURCE_ID"} {
		t.Setenv(key, "")
	}
	valid := `[{"collector_id":"collector-one","source_id":"source-one"},{"collector_id":"collector-two","source_id":"source-two"}]`
	var many []string
	for i := 0; i < 257; i++ {
		many = append(many, fmt.Sprintf(`{"collector_id":"collector-%d","source_id":"source"}`, i))
	}
	t.Setenv("SHERLOCK_PROMETHEUS_UPLOAD_BINDINGS", "["+strings.Join(many[:256], ",")+"]")
	if _, err := LoadPrometheusUploadScope(); err != nil {
		t.Fatalf("256 valid bindings were rejected: %v", err)
	}
	t.Setenv("SHERLOCK_PROMETHEUS_UPLOAD_BINDINGS", valid)
	scope, err := LoadPrometheusUploadScope()
	if err != nil || len(scope.Bindings) != 2 || scope.Bindings[1].SourceID != "source-two" || scope.ClusterID != "" {
		t.Fatalf("shared scope=%+v err=%v", scope, err)
	}
	for name, raw := range map[string]string{
		"empty": "", "null": "null", "empty array": "[]", "object": `{}`,
		"trailing value":      valid + ` {}`,
		"unknown cluster":     `[{"collector_id":"one","source_id":"source","cluster_id":"supplied"}]`,
		"duplicate key":       `[{"collector_id":"one","collector_id":"two","source_id":"source"}]`,
		"duplicate collector": `[{"collector_id":"one","source_id":"first"},{"collector_id":"one","source_id":"second"}]`,
		"empty collector":     `[{"source_id":"source"}]`,
		"null binding":        `[null]`,
		"invalid identifier":  `[{"collector_id":"one","source_id":"bad\nsource"}]`,
		"too large":           strings.Repeat(" ", 64<<10+1),
		"too many":            `[` + strings.Join(many, ",") + `]`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("SHERLOCK_PROMETHEUS_UPLOAD_BINDINGS", raw)
			if _, err := LoadPrometheusUploadScope(); err == nil {
				t.Fatal("invalid shared bindings were accepted")
			}
		})
	}
	for _, key := range []string{"SHERLOCK_COLLECTOR_ID", "SHERLOCK_CLUSTER_ID", "SHERLOCK_SOURCE_ID"} {
		t.Run("mixed "+key, func(t *testing.T) {
			t.Setenv(key, "legacy")
			if _, err := LoadPrometheusUploadScope(); err == nil {
				t.Fatal("shared bindings and legacy scope were accepted together")
			}
		})
	}
}

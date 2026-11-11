package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type PrometheusUploadBinding struct {
	CollectorID string `json:"collector_id"`
	SourceID    string `json:"source_id"`
}

type PrometheusUploadScope struct {
	CollectorID string
	ClusterID   string
	SourceID    string
	Bindings    []PrometheusUploadBinding
}

// LoadPrometheusUploadScope accepts either the existing single-collector scope
// or an explicit shared intake allow-list. Call after LoadPrometheusUploadControl.
func LoadPrometheusUploadScope() (PrometheusUploadScope, error) {
	scope := PrometheusUploadScope{
		CollectorID: strings.TrimSpace(os.Getenv("SHERLOCK_COLLECTOR_ID")),
		ClusterID:   strings.TrimSpace(os.Getenv("SHERLOCK_CLUSTER_ID")),
		SourceID:    strings.TrimSpace(os.Getenv("SHERLOCK_SOURCE_ID")),
	}
	raw, shared := os.LookupEnv("SHERLOCK_PROMETHEUS_UPLOAD_BINDINGS")
	if !shared {
		if scope.CollectorID == "" || scope.ClusterID == "" || scope.SourceID == "" {
			return PrometheusUploadScope{}, fmt.Errorf("scheduled Prometheus intake requires an explicit scope or collector bindings")
		}
		return scope, nil
	}
	if scope.CollectorID != "" || scope.ClusterID != "" || scope.SourceID != "" {
		return PrometheusUploadScope{}, fmt.Errorf("shared upload bindings cannot be combined with single-collector scope")
	}
	if len(raw) > 64<<10 || rejectDuplicateJSONKeys([]byte(raw)) != nil {
		return PrometheusUploadScope{}, fmt.Errorf("shared upload bindings exceed their size limit or contain duplicate JSON keys")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&scope.Bindings); err != nil {
		return PrometheusUploadScope{}, fmt.Errorf("shared upload bindings must be a JSON array of collectors and sources")
	}
	if err := decoder.Decode(new(any)); err != io.EOF || len(scope.Bindings) == 0 || len(scope.Bindings) > 256 {
		return PrometheusUploadScope{}, fmt.Errorf("shared upload requires exactly one array of one to 256 collector bindings")
	}
	seen := make(map[string]bool, len(scope.Bindings))
	for _, binding := range scope.Bindings {
		for _, value := range []string{binding.CollectorID, binding.SourceID} {
			if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsAny(value, " \t\r\n\x00") {
				return PrometheusUploadScope{}, fmt.Errorf("shared upload binding has an invalid collector or source")
			}
		}
		if seen[binding.CollectorID] {
			return PrometheusUploadScope{}, fmt.Errorf("shared upload repeats a collector binding")
		}
		seen[binding.CollectorID] = true
	}
	return scope, nil
}

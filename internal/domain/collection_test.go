package domain

import (
	"testing"
	"time"
)

func TestFreshnessAt(t *testing.T) {
	now := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	last := now.Add(-60 * time.Second)
	tests := []struct {
		name string
		last *time.Time
		want Freshness
	}{
		{name: "unknown before success", want: FreshnessUnknown},
		{name: "fresh at boundary", last: &last, want: FreshnessFresh},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FreshnessAt(tt.last, now, 60*time.Second); got != tt.want {
				t.Fatalf("FreshnessAt() = %s, want %s", got, tt.want)
			}
		})
	}
	stale := now.Add(-60*time.Second - time.Nanosecond)
	if got := FreshnessAt(&stale, now, 60*time.Second); got != FreshnessStale {
		t.Fatalf("FreshnessAt() = %s, want STALE", got)
	}
}

func TestM3QueryKindsAreClosedAndGPUClassified(t *testing.T) {
	gpuQueries := []QueryKind{
		QueryGPUIdentity, QueryGPUUtilization, QueryGPUTemperature, QueryGPUPower,
		QueryGPUMemory, QueryGPUECC, QueryGPUXID,
	}
	for _, query := range gpuQueries {
		if err := query.Validate(); err != nil {
			t.Errorf("%s.Validate() = %v", query, err)
		}
		if !query.IsGPU() {
			t.Errorf("%s.IsGPU() = false", query)
		}
	}
	if QuerySourceHealth.IsGPU() {
		t.Fatal("source health was classified as a GPU query")
	}
	if err := QueryKind("arbitrary_promql").Validate(); err == nil {
		t.Fatal("unknown query kind was accepted")
	}
}

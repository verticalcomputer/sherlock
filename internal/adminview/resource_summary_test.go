package adminview

import (
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestResourceSummaryReconcilesUUIDProofWithoutIndexInference(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	accumulator := newResourceAccumulator(now.Add(2*time.Second), 2*time.Minute)
	add := func(id, source, key string, value float64, at time.Time, labels ...domain.Label) {
		accumulator.add(domain.Observation{ID: domain.ObservationID(id), ClusterID: "cluster-1", SourceID: domain.SourceID(source),
			EntityKey: key, Metric: "DCGM_FI_DEV_GPU_UTIL", Unit: "percent", Value: value, ObservedAt: at, CollectedAt: at, Labels: labels})
	}
	add("canonical", "source-a", "cluster-1/GPU/node-1/GPU-a/", 20, now)
	add("legacy-new", "source-a", "node/node-1/gpu/0", 60, now.Add(time.Second), domain.Label{Name: "UUID", Value: "GPU-a"})
	add("other-source-old", "source-b", "node/node-1/gpu/GPU-a", 10, now.Add(-time.Second))
	add("index-only", "source-a", "node/node-2/gpu/0", 40, now)
	add("foreign", "source-a", "foreign/GPU/node-3/GPU-foreign/", 100, now)
	add("conflicting", "source-a", "cluster-1/GPU/node-4/GPU-b/", 100, now, domain.Label{Name: "UUID", Value: "GPU-c"})
	add("mig", "source-a", "cluster-1/GPU/node-5/GPU-d/", 100, now, domain.Label{Name: "GPU_I_ID", Value: "0"})
	got := accumulator.summary()
	if got.ObservedNodes != 2 || got.ObservedGPUs != 2 || got.GPUUtilizationSamples != 2 || got.GPUUtilizationPercent == nil || *got.GPUUtilizationPercent != 50 ||
		got.LastObservedAt == nil || !got.LastObservedAt.Equal(now.Add(time.Second)) {
		t.Fatalf("resource identities diverged: %+v", got)
	}
}

func TestResourceSummaryUsageRequiresCurrentValidSensorEvidence(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	for _, fixture := range []struct {
		name, unit, kind    string
		value               float64
		observed, collected time.Time
	}{
		{"negative", "percent", "gauge", -1, now, now},
		{"out-of-range", "percent", "gauge", 101, now, now},
		{"wrong-unit", "watts", "gauge", 50, now, now},
		{"wrong-semantics", "percent", "counter", 50, now, now},
		{"future-observed", "percent", "gauge", 50, now.Add(time.Minute), now},
		{"future-collected", "percent", "gauge", 50, now, now.Add(time.Minute)},
		{"stale", "percent", "gauge", 50, now.Add(-time.Hour), now},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			accumulator := newResourceAccumulator(now, 2*time.Minute)
			accumulator.add(domain.Observation{ClusterID: "cluster-1", SourceID: "source-a", EntityKey: "cluster-1/GPU/node-1/GPU-a/",
				Metric: "DCGM_FI_DEV_GPU_UTIL", Unit: fixture.unit, Semantics: &domain.MetricSemantics{Kind: fixture.kind},
				Value: fixture.value, ObservedAt: fixture.observed, CollectedAt: fixture.collected})
			got := accumulator.summary()
			if got.ObservedGPUs != 1 || got.GPUUtilizationPercent != nil || got.GPUUtilizationSamples != 0 {
				t.Fatalf("invalid usage became current: %+v", got)
			}
		})
	}
}

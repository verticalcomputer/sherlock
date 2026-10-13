package adminview

import (
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestGPUHealthLatestAttemptRetainsExactSourceOperationNodeScope(t *testing.T) {
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	runs := []gpuHealthRun{
		{id: "cluster", source: "source-a", query: domain.QueryGPUUtilization, completed: now},
		{id: "node-a", source: "source-a", query: domain.QueryGPUUtilization, nodes: []string{"node-a"}, completed: now.Add(time.Second)},
		{id: "typed-b-c", source: "source-a", query: domain.QueryGPUUtilization, nodes: []string{"node-b", "node-c"}, completed: now.Add(2 * time.Second)},
		{id: "empty-typed", source: "source-a", query: domain.QueryGPUUtilization, finite: true, completed: now.Add(10 * time.Second)},
		{id: "foreign", source: "source-b", query: domain.QueryGPUUtilization, completed: now.Add(3 * time.Second)},
		{id: "other-operation", source: "source-a", query: domain.QueryGPUTemperature, completed: now.Add(4 * time.Second)},
	}
	for node, want := range map[string]string{"node-a": "node-a", "node-b": "typed-b-c", "node-c": "typed-b-c", "node-d": "cluster"} {
		got := latestGPUHealthRun(runs, "source-a", domain.StableNodeID(node), domain.QueryGPUUtilization)
		if got == nil || got.id != want {
			t.Fatalf("node %s got %+v want %s", node, got, want)
		}
	}
	if got := latestGPUHealthRun(runs, "absent", "node-a", domain.QueryGPUUtilization); got != nil {
		t.Fatalf("foreign source: %+v", got)
	}
}

func TestGPUHealthOperationCannotBorrowSensorAndFreshnessPolicy(t *testing.T) {
	at := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	observed := at.Add(-30 * time.Second)
	identity := domain.GPUObservationIdentity{EntityKey: "cluster/GPU/node/GPU-a/", NodeID: "node", PhysicalGPUUUID: "GPU-a", Canonical: true}
	d := &gpuHealthDevice{identity: identity, source: "source", expected: true}
	d.samples = []gpuHealthSample{{runID: "util", query: domain.QueryGPUUtilization, lastSuccess: observed, observation: domain.Observation{ID: "wrong-operation", ClusterID: "cluster", SourceID: "source", EntityKey: identity.EntityKey, Metric: "DCGM_FI_DEV_GPU_TEMP", Value: 95, Unit: "celsius", ObservedAt: observed, CollectedAt: observed}},
		{runID: "util", query: domain.QueryGPUUtilization, lastSuccess: observed, observation: domain.Observation{ID: "util", ClusterID: "cluster", SourceID: "source", EntityKey: identity.EntityKey, Metric: "DCGM_FI_DEV_GPU_UTIL", Value: 90, Unit: "percent", ObservedAt: observed, CollectedAt: observed}}}
	runs := []gpuHealthRun{{id: "util", source: "source", query: domain.QueryGPUUtilization, completed: observed, status: domain.ResultSucceeded, complete: true}}
	summary, err := projectGPUHealthDevice("cluster", d, runs, at, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Observations) != 1 || summary.Observations[0].ID != "util" {
		t.Fatalf("operation borrowed temperature sensor: %+v", summary.Observations)
	}
	if summary.Freshness != domain.FreshnessStale {
		t.Fatalf("summary ignored freshness policy: %+v", summary)
	}
	stale := false
	for _, s := range summary.Signals {
		if s.Type == domain.HealthSignalThermal {
			t.Fatal("wrong operation produced thermal fault")
		}
		if s.Type == domain.HealthSignalStale {
			stale = true
		}
	}
	if !stale {
		t.Fatalf("signals ignored freshness policy: %+v", summary.Signals)
	}
}

func TestGPUHealthQueryCompatibilityIsExplicit(t *testing.T) {
	for value, want := range map[string]domain.QueryKind{"dcgm_gpu_utilization": domain.QueryGPUUtilization, "DCGM_GPU_UTILIZATION": domain.QueryGPUUtilization, "prometheus.gpu_utilization.v1": domain.QueryGPUUtilization, "arbitrary_gpu_temperature": ""} {
		if got := gpuHealthQuery(value); got != want {
			t.Fatalf("%s = %s want %s", value, got, want)
		}
	}
}

func TestGPUHealthFutureOperationDoesNotPoisonIndependentFreshFault(t *testing.T) {
	at := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	identity := domain.GPUObservationIdentity{EntityKey: "cluster/GPU/node/GPU-a/", NodeID: "node", PhysicalGPUUUID: "GPU-a", Canonical: true}
	o := domain.Observation{ID: "xid", ClusterID: "cluster", SourceID: "source", EntityKey: identity.EntityKey, Metric: "DCGM_FI_DEV_XID_ERRORS", Value: 79, Unit: "xid_code", ObservedAt: at.Add(-time.Second), CollectedAt: at.Add(-time.Second)}
	d := &gpuHealthDevice{identity: identity, source: "source", expected: true, samples: []gpuHealthSample{{runID: "xid-run", query: domain.QueryGPUXID, observation: o, lastSuccess: o.CollectedAt}}}
	runs := []gpuHealthRun{{id: "xid-run", source: "source", query: domain.QueryGPUXID, completed: o.CollectedAt, status: domain.ResultSucceeded, complete: true}, {id: "future-temperature", source: "source", query: domain.QueryGPUTemperature, completed: at.Add(time.Hour), status: domain.ResultFailed}}
	summary, err := projectGPUHealthDevice("cluster", d, runs, at, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	xid, partial := false, false
	for _, s := range summary.Signals {
		if s.Type == domain.HealthSignalXID {
			xid = true
		}
		if s.Type == domain.HealthSignalPartial {
			partial = true
		}
	}
	if !xid || !partial {
		t.Fatalf("future operation poisoned independent fresh evidence: %+v", summary.Signals)
	}
}

package adminclient

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminview"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestClientLoadsAndMapsClusterGPUMetrics(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 11, 0, 0, 0, time.UTC)
	observed := now.Add(-12 * time.Second)
	snapshot := adminview.GPUMetricsSnapshot{
		ClusterID: "cluster-1", GeneratedAt: now,
		Fields: []adminview.GPUMetricsFieldRef{
			{Name: "DCGM_FI_DEV_POWER_USAGE", Unit: "watts", Semantics: "gauge", Operation: "prometheus.gpu_power.v1"},
			{Name: "DCGM_FI_DEV_POWER_MGMT_LIMIT", Unit: "watts", Semantics: "gauge", Operation: "prometheus.gpu_power.v1"},
		},
		Sources: []adminview.GPUMetricsSource{{SourceID: "source-1", DisplayName: "DCGM", Primary: true,
			Operations: []adminview.GPUMetricsOperation{{
				OperationID: "prometheus.gpu_power.v1", QueryKind: "dcgm_gpu_power",
				Enrolled: true, Enabled: true, Mode: "durable", IntervalSeconds: 30, Revision: 2,
				Freshness: adminview.GPUMetricsFresh, FreshWindowSeconds: 60,
				LastRun: &adminview.GPUMetricsRun{RunID: "run-1", Status: "PARTIAL", ScheduledFor: observed, CompletedAt: observed},
				Fields:  []adminview.GPUMetricsFieldColumn{{Name: "DCGM_FI_DEV_POWER_USAGE", Unit: "watts", Semantics: "gauge"}},
				FieldSummaries: []adminview.GPUMetricsFieldSummary{
					{Field: "DCGM_FI_DEV_POWER_USAGE", Supported: 8, Dominant: adminview.GPUMetricSupported},
				},
			}}}},
		GPUs: []adminview.GPUMetricsRow{{SourceID: "source-1", NodeID: "node-1", GPUUUID: "GPU-aaa",
			Expected: true, Observed: true, ObservedAt: &observed, Values: map[string]adminview.GPUMetricValue{
				"DCGM_FI_DEV_POWER_USAGE":      {State: adminview.GPUMetricSupported, Value: floatPointer(210.5), Unit: "watts", Semantics: "gauge", ObservedAt: &observed},
				"DCGM_FI_DEV_POWER_MGMT_LIMIT": {State: adminview.GPUMetricNotSupported, Unit: "watts", Semantics: "gauge"},
			}}},
		Inventory: adminview.GPUMetricsInventory{
			SourceID: "source-1", HasExpectedRevision: true, RevisionID: "revision-1",
			EffectiveAt: &observed, ExpectedNodes: 1, ExpectedGPUs: 2, ObservedNodes: 1, ObservedGPUs: 1,
			ExpectedNotObserved: []adminview.GPUMetricsEntityRef{{NodeID: "node-1", GPUUUID: "GPU-bbb"}},
			ObservedNotExpected: []adminview.GPUMetricsEntityRef{},
		},
	}
	snapshot.GPUs[0].Conditions = []domain.HealthSignal{{SchemaVersion: 1, Type: domain.HealthSignalECC,
		Category: domain.HealthSignalECC, Severity: domain.HealthSeverityCritical, ClusterID: "cluster-1", SourceID: "source-1",
		EntityKey: "cluster-1/GPU/node-1/GPU-aaa/", Metric: "DCGM_FI_DEV_ROW_REMAP_FAILURE", ObservedAt: observed, ProjectedAt: now,
		Freshness: domain.FreshnessFresh, Evidence: []domain.ObservationID{"persisted-row-remap"}, Coverage: domain.Coverage{Complete: false}, Reason: "row remap failure"}}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/internal/admin/v1/clusters/cluster-1/gpu-metrics" {
			t.Errorf("path = %q", request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("Authorization = %q", got)
		}
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(snapshot); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	metrics, err := newTestClient(t, server.URL).GetClusterGPUMetrics(context.Background(), "cluster-1")
	if err != nil {
		t.Fatal(err)
	}
	if metrics.ClusterID != "cluster-1" || len(metrics.Fields) != 2 || len(metrics.Sources) != 1 {
		t.Fatalf("metrics = %+v", metrics)
	}
	operation := metrics.Sources[0].Operations[0]
	if !operation.HasRun || operation.RunStatus != "PARTIAL" || operation.Freshness != "FRESH" || operation.IntervalSeconds != 30 {
		t.Fatalf("operation = %+v", operation)
	}
	if len(operation.Fields) != 1 || operation.Fields[0].Unit != "watts" || operation.Fields[0].Dominant != "SUPPORTED" {
		t.Fatalf("operation fields = %+v", operation.Fields)
	}
	row := metrics.GPUs[0]
	if !reflect.DeepEqual(row.Conditions, snapshot.GPUs[0].Conditions) {
		t.Fatalf("shared conditions changed crossing HTTP/client: %+v", row.Conditions)
	}
	usage := row.Values["DCGM_FI_DEV_POWER_USAGE"]
	if usage.State != "SUPPORTED" || usage.Value == nil || *usage.Value != 210.5 {
		t.Fatalf("supported cell = %+v", usage)
	}
	limit := row.Values["DCGM_FI_DEV_POWER_MGMT_LIMIT"]
	if limit.State != "NOT_SUPPORTED" || limit.Value != nil {
		t.Fatalf("an unsupported cell must not cross the boundary with a value: %+v", limit)
	}
	if !metrics.Inventory.HasExpectedRevision || len(metrics.Inventory.ExpectedNotObserved) != 1 ||
		metrics.Inventory.ExpectedNotObserved[0].GPUUUID != "GPU-bbb" {
		t.Fatalf("inventory = %+v", metrics.Inventory)
	}
}

func TestClientRefusesInvalidClusterForGPUMetrics(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("an invalid cluster ID must not reach the private API")
	}))
	defer server.Close()
	if _, err := newTestClient(t, server.URL).GetClusterGPUMetrics(context.Background(), "cluster 1"); err == nil {
		t.Fatal("expected an invalid cluster ID error")
	}
}

func TestClientMapsExplicitStatesAndRefusesNonFiniteValues(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 11, 0, 0, 0, time.UTC)
	observed := now.Add(-12 * time.Second)
	stale := now.Add(-21 * 24 * time.Hour)
	snapshot := adminview.GPUMetricsSnapshot{
		ClusterID: "cluster-1", GeneratedAt: now, SourcesTruncated: true,
		OtherSources: []adminview.GPUMetricsOtherSource{
			{SourceID: "source-2", ObservedNodes: 3, ObservedGPUs: 24},
		},
		Sources: []adminview.GPUMetricsSource{{SourceID: "source-1", Primary: true,
			Operations: []adminview.GPUMetricsOperation{{
				OperationID: "prometheus.gpu_power.v1", Freshness: adminview.GPUMetricsFailing,
				LastRun: &adminview.GPUMetricsRun{RunID: "run-1", Status: "FAILED", CompletedAt: observed},
				Fields:  []adminview.GPUMetricsFieldColumn{{Name: "DCGM_FI_DEV_POWER_USAGE", Unit: "watts"}},
				FieldSummaries: []adminview.GPUMetricsFieldSummary{{
					Field: "DCGM_FI_DEV_POWER_USAGE", Supported: 2, Unknown: 6,
					Assessed: 2, Expected: 8, UnassessedExpected: 6, Dominant: adminview.GPUMetricUnknown,
				}},
			}}}},
		GPUs: []adminview.GPUMetricsRow{{
			SourceID: "source-1", NodeID: "node-1", GPUUUID: "GPU-aaa", MIGIdentity: "mig-0",
			Expected: true, Observed: true, ObservedAt: &stale,
			ObservedState: adminview.GPUMetricsObservedStale,
			Values: map[string]adminview.GPUMetricValue{
				"DCGM_FI_DEV_POWER_USAGE": {State: adminview.GPUMetricSupported, Value: floatPointer(210.5), Unit: "watts", ObservedAt: &observed},
			},
		}},
		Inventory: adminview.GPUMetricsInventory{
			SourceID: "source-1", HasExpectedRevision: true, RevisionID: "revision-1",
			ExpectedGPUs: 8, ObservedGPUs: 3, FreshObservedGPUs: 2, StaleObservedGPUs: 1,
			CoveredGPUs: 2, CoverageComplete: false, ObservationWindowSeconds: 300,
			ExpectedNotObserved: []adminview.GPUMetricsEntityRef{{NodeID: "node-1", GPUUUID: "GPU-bbb", Stale: true, ObservedAt: &stale}},
			ObservedNotExpected: []adminview.GPUMetricsEntityRef{},
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(snapshot); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	metrics, err := newTestClient(t, server.URL).GetClusterGPUMetrics(context.Background(), "cluster-1")
	if err != nil {
		t.Fatal(err)
	}
	row := metrics.GPUs[0]
	if row.ObservedState != "OBSERVED_STALE" || row.MIGIdentity != "mig-0" {
		t.Fatalf("row = %+v", row)
	}
	summary := metrics.Sources[0].Operations[0].Fields[0]
	if summary.Assessed != 2 || summary.Expected != 8 || summary.UnassessedExpected != 6 {
		t.Fatalf("the field summary lost its denominator: %+v", summary)
	}
	if metrics.Sources[0].Operations[0].Freshness != "FAILING" {
		t.Fatalf("a failing run's freshness must survive the boundary: %+v", metrics.Sources[0].Operations[0])
	}
	if !metrics.SourcesTruncated || len(metrics.OtherSources) != 1 || metrics.OtherSources[0].ObservedGPUs != 24 {
		t.Fatalf("other sources and truncation must reach the page: %+v", metrics)
	}
	inventory := metrics.Inventory
	if inventory.CoverageComplete || inventory.CoveredGPUs != 2 || inventory.StaleObservedGPUs != 1 ||
		inventory.ObservationWindowSeconds != 300 {
		t.Fatalf("inventory coverage = %+v", inventory)
	}
	if gap := inventory.ExpectedNotObserved[0]; !gap.Stale || gap.ObservedAt == nil {
		t.Fatalf("a stale gap must stay marked stale: %+v", gap)
	}
}

// The service derives non-finite samples away before encoding, and JSON cannot
// carry NaN or Inf at all, so this exercises the mapping directly: a producer
// that ever hands the page such a sample must still see UNKNOWN, not a cell the
// template would have to render as an empty value.
func TestMapGPUMetricsRefusesNonFiniteSamples(t *testing.T) {
	t.Parallel()
	observed := time.Date(2026, 9, 21, 11, 0, 0, 0, time.UTC)
	for name, sample := range map[string]float64{"not-a-number": math.NaN(), "positive-infinity": math.Inf(1), "negative-infinity": math.Inf(-1)} {
		metrics := mapGPUMetrics(adminview.GPUMetricsSnapshot{
			GPUs: []adminview.GPUMetricsRow{{SourceID: "source-1", NodeID: "node-1", GPUUUID: "GPU-aaa",
				Values: map[string]adminview.GPUMetricValue{
					"DCGM_FI_DEV_POWER_USAGE": {State: adminview.GPUMetricSupported, Value: floatPointer(sample), Unit: "watts", ObservedAt: &observed},
				}}},
		})
		cell := metrics.GPUs[0].Values["DCGM_FI_DEV_POWER_USAGE"]
		if cell.State != "UNKNOWN" || cell.Value != nil {
			t.Fatalf("%s must cross as UNKNOWN without a value: %+v", name, cell)
		}
	}
	finite := mapGPUMetrics(adminview.GPUMetricsSnapshot{
		GPUs: []adminview.GPUMetricsRow{{SourceID: "source-1", NodeID: "node-1", GPUUUID: "GPU-aaa",
			Values: map[string]adminview.GPUMetricValue{
				"DCGM_FI_DEV_POWER_USAGE": {State: adminview.GPUMetricSupported, Value: floatPointer(210.5), Unit: "watts", ObservedAt: &observed},
			}}},
	})
	if cell := finite.GPUs[0].Values["DCGM_FI_DEV_POWER_USAGE"]; cell.State != "SUPPORTED" || cell.Value == nil {
		t.Fatalf("a finite sample must keep its value: %+v", cell)
	}
}

package adminview

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type sharedGPUMetricsRepository struct {
	fakeGPUMetricsRepository
	summaries []application.GPUSummaryProjection
	at        time.Time
	freshFor  time.Duration
}

func (repository *sharedGPUMetricsRepository) LoadGPUHealthSummaries(_ context.Context, _ string, at time.Time, freshFor time.Duration) ([]application.GPUSummaryProjection, error) {
	repository.at, repository.freshFor = at, freshFor
	return repository.summaries, nil
}

func TestGPUMetricsPreservesSharedConditionsAndExactSourceScope(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	signals := []domain.HealthSignal{{SchemaVersion: 1, ClusterID: "cluster-1", SourceID: "source-a", EntityKey: "cluster-1/GPU/node-1/GPU-a/",
		Type: domain.HealthSignalECC, Category: domain.HealthSignalECC, Severity: domain.HealthSeverityCritical,
		Metric: "DCGM_FI_DEV_ROW_REMAP_FAILURE", ObservedAt: now.Add(-time.Second), ProjectedAt: now, Freshness: domain.FreshnessFresh,
		Evidence: []domain.ObservationID{"persisted-remap-observation"}, Reason: "row remap failure"},
		{Type: domain.HealthSignalPartial, Severity: domain.HealthSeverityUnknown, Coverage: domain.Coverage{Complete: false,
			MetricFields: []domain.DCGMFieldEvidence{{NodeID: "node-1", GPU: "GPU-a", Metric: "DCGM_FI_DEV_ECC_SBE_VOL_TOTAL", State: "UNKNOWN"}}}}}
	repository := &sharedGPUMetricsRepository{fakeGPUMetricsRepository: fakeGPUMetricsRepository{snapshot: GPUMetricsSnapshot{GPUs: []GPUMetricsRow{
		{SourceID: "source-a", NodeID: "node-1", GPUUUID: "GPU-a"},
		{SourceID: "source-b", NodeID: "node-1", GPUUUID: "GPU-a"},
		{SourceID: "source-a", NodeID: "node-1", GPUUUID: "GPU-a", MIGIdentity: "mig-1"},
	}}}, summaries: []application.GPUSummaryProjection{{SourceID: "source-a", EntityKey: "cluster-1/GPU/node-1/GPU-a/", Signals: signals}}}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.GPUMetrics(context.Background(), GPUMetricsQuery{ClusterID: "cluster-1", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshot.GPUs[0].Conditions, signals) {
		t.Fatalf("shared conditions changed: %+v", snapshot.GPUs[0].Conditions)
	}
	if len(snapshot.GPUs[1].Conditions) != 0 || len(snapshot.GPUs[2].Conditions) != 0 {
		t.Fatal("conditions crossed source or MIG boundary")
	}
	if !repository.at.Equal(now) || repository.freshFor != application.DefaultGPUHealthThresholds().FreshFor {
		t.Fatal("API/page health evaluation policy diverged")
	}
}

func TestGPUMetricsUsesValidatedConfiguredHealthPolicy(t *testing.T) {
	repository := &sharedGPUMetricsRepository{}
	for _, invalid := range []time.Duration{0, -time.Second} {
		if _, err := NewService(repository, WithGPUHealthFreshness(invalid)); err == nil {
			t.Fatal("invalid freshness accepted")
		}
	}
	service, err := NewService(repository, WithGPUHealthFreshness(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.GPUMetrics(context.Background(), GPUMetricsQuery{ClusterID: "cluster-1", Now: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if repository.freshFor != time.Minute {
		t.Fatalf("private GPU health ignored runtime policy: %s", repository.freshFor)
	}
}

func TestGPUMetricsValuesUseSharedDeviceScopeAndPreserveMissingStates(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	snapshot := GPUMetricsSnapshot{ClusterID: "cluster-1", Fields: []GPUMetricsFieldRef{
		{Name: "DCGM_FI_DEV_POWER_USAGE", Unit: "watts", Semantics: "gauge"},
		{Name: "DCGM_FI_DEV_POWER_MGMT_LIMIT", Unit: "watts", Semantics: "gauge"},
		{Name: "DCGM_FI_DEV_GPU_TEMP", Unit: "celsius", Semantics: "gauge"}},
		GPUs: []GPUMetricsRow{{SourceID: "source-a", NodeID: "node-2", GPUUUID: "GPU-b", Values: map[string]GPUMetricValue{
			"DCGM_FI_DEV_POWER_USAGE": {State: GPUMetricUnknown},                          // another node's newer failure
			"DCGM_FI_DEV_GPU_TEMP":    {State: GPUMetricSupported, Value: floatValue(50)}, // unrelated operation scope
		}}}}
	key := "source-a\x00cluster-1/GPU/node-2/GPU-b/"
	attachGPUMetricsValues(&snapshot, []application.GPUSummaryProjection{{SourceID: "source-a", EntityKey: "cluster-1/GPU/node-2/GPU-b/", Observations: []domain.Observation{{
		ID: "actual-device-observation", Metric: "DCGM_FI_DEV_POWER_USAGE", Unit: "watts", Value: 220, ObservedAt: now,
	}}}}, map[string][]domain.DCGMFieldEvidence{key: {
		{NodeID: "node-2", GPU: "GPU-b", Metric: "DCGM_FI_DEV_POWER_USAGE", State: "SUPPORTED"},
		{NodeID: "node-2", GPU: "GPU-b", Metric: "DCGM_FI_DEV_POWER_MGMT_LIMIT", State: "NOT_SUPPORTED"},
	}})
	values := snapshot.GPUs[0].Values
	if values["DCGM_FI_DEV_POWER_USAGE"].Value == nil || *values["DCGM_FI_DEV_POWER_USAGE"].Value != 220 || values["DCGM_FI_DEV_POWER_USAGE"].ObservedAt == nil || !values["DCGM_FI_DEV_POWER_USAGE"].ObservedAt.Equal(now) {
		t.Fatalf("sibling's valid scoped sample lost: %+v", values)
	}
	if values["DCGM_FI_DEV_POWER_MGMT_LIMIT"].State != GPUMetricNotSupported || values["DCGM_FI_DEV_GPU_TEMP"].State != GPUMetricNoData || values["DCGM_FI_DEV_GPU_TEMP"].Value != nil {
		t.Fatalf("unsupported/never-collected state changed: %+v", values)
	}
}

func TestGPUMetricsRequiresExactLatestAssessmentAndRunForValues(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	entity := gpuMetricsEntity{"node-1", "GPU-a"}
	field := domain.DCGMField{Name: "DCGM_FI_DEV_POWER_USAGE", Unit: "watts", Kind: "gauge"}
	query := domain.QueryKind("dcgm_gpu_power")
	cell := gpuMetricsCell{entity.node, entity.gpu, field.Name}
	for _, fixture := range []struct {
		name, state, run, latest string
		want                     GPUMetricState
	}{
		{"latest-supported", "SUPPORTED", "run-new", "run-new", GPUMetricSupported},
		{"old-projection", "SUPPORTED", "run-old", "run-new", GPUMetricUnknown},
		{"disappeared-field", "", "run-new", "run-new", GPUMetricUnknown},
		{"unsupported", "NOT_SUPPORTED", "run-new", "run-new", GPUMetricNotSupported},
		{"unknown", "UNKNOWN", "run-new", "run-new", GPUMetricUnknown},
		{"never-collected", "", "run-old", "", GPUMetricNoData},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			assessments := map[gpuMetricsCell]string{}
			if fixture.state != "" {
				assessments[cell] = fixture.state
			}
			value := gpuMetricsValue(entity, field, query, assessments, map[domain.QueryKind]string{query: fixture.latest},
				map[gpuMetricsCell]gpuMetricsProjection{cell: {runID: fixture.run, value: 220, unit: "watts", semantics: "gauge", observedAt: now}})
			if value.State != fixture.want || (value.Value != nil) != (fixture.want == GPUMetricSupported) {
				t.Fatalf("value = %+v", value)
			}
		})
	}
}

func TestGPUMetricsFutureInventoryObservationCannotProveCoverage(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	ahead := now.Add(time.Hour)
	snapshot := GPUMetricsSnapshot{GPUs: []GPUMetricsRow{{SourceID: "source-a", NodeID: "node-1", GPUUUID: "GPU-a", Expected: true, Observed: true, ObservedAt: &ahead}},
		Inventory: GPUMetricsInventory{SourceID: "source-a", HasExpectedRevision: true, Observations: []GPUMetricsObservation{
			{NodeID: "node-1", Expected: true, ObservedAt: &ahead}, {NodeID: "node-1", GPUUUID: "GPU-a", Expected: true, ObservedAt: &ahead}}}}
	DeriveGPUMetricsStates(&snapshot, now)
	if snapshot.GPUs[0].ObservedState != GPUMetricsObservedUnknown || snapshot.Inventory.CoverageComplete || snapshot.Inventory.CoveredGPUs != 0 ||
		snapshot.Inventory.FreshObservedGPUs != 0 || snapshot.Inventory.FreshObservedNodes != 0 || len(snapshot.Inventory.ExpectedNotObserved) != 2 {
		t.Fatalf("future observation manufactured coverage: %+v", snapshot)
	}
	for _, gap := range snapshot.Inventory.ExpectedNotObserved {
		if !gap.Unknown || gap.Stale {
			t.Fatalf("clock gap mislabeled: %+v", gap)
		}
	}
}

func TestGPUMetricsTiedAliasesCompareAllExplicitContracts(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	for _, fixture := range []struct {
		name, metric, unitA, unitB, kind string
		resetB                           bool
		want                             GPUMetricState
	}{
		{"nil-first-three-way-reset-conflict", "DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", "count", "count", "counter", true, GPUMetricUnknown},
		{"reviewed-unit-aliases", "DCGM_FI_DEV_FB_USED", "MiB", "mebibytes", "gauge", false, GPUMetricSupported},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			samples := []domain.Observation{
				{ID: "a-nil", Metric: fixture.metric, Unit: fixture.unitA, Value: 0, ObservedAt: now},
				{ID: "b-explicit", Metric: fixture.metric, Unit: fixture.unitA, Value: 0, ObservedAt: now, Semantics: &domain.MetricSemantics{Kind: fixture.kind}},
				{ID: "c-explicit", Metric: fixture.metric, Unit: fixture.unitB, Value: 0, ObservedAt: now, Semantics: &domain.MetricSemantics{Kind: fixture.kind, ResetObserved: fixture.resetB}},
			}
			snapshot := GPUMetricsSnapshot{ClusterID: "cluster-1", Fields: []GPUMetricsFieldRef{{Name: fixture.metric, Unit: fixture.unitB, Semantics: fixture.kind}}, GPUs: []GPUMetricsRow{{SourceID: "source-a", NodeID: "node-1", GPUUUID: "GPU-a"}}}
			key := "source-a\x00cluster-1/GPU/node-1/GPU-a/"
			attachGPUMetricsValues(&snapshot, []application.GPUSummaryProjection{{SourceID: "source-a", EntityKey: "cluster-1/GPU/node-1/GPU-a/", Observations: samples}}, map[string][]domain.DCGMFieldEvidence{key: {{Metric: fixture.metric, State: "SUPPORTED"}}})
			value := snapshot.GPUs[0].Values[fixture.metric]
			if value.State != fixture.want || (value.Value != nil) != (fixture.want == GPUMetricSupported) {
				t.Fatalf("alias evidence: %+v", value)
			}
		})
	}
}

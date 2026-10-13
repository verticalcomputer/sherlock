package adminview

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"
)

type fakeGPUMetricsRepository struct {
	snapshot GPUMetricsSnapshot
	err      error
	clusters []string
}

func (repository *fakeGPUMetricsRepository) Load(context.Context, Query) ([]ClusterSummary, bool, error) {
	return nil, false, nil
}

func (repository *fakeGPUMetricsRepository) LoadGPUMetrics(_ context.Context, clusterID string) (GPUMetricsSnapshot, error) {
	repository.clusters = append(repository.clusters, clusterID)
	return repository.snapshot, repository.err
}

func floatValue(value float64) *float64 { return &value }

func TestGPUMetricsDerivesFreshnessAndNeverKeepsAValueOutsideSupported(t *testing.T) {
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	fresh := now.Add(-15 * time.Second)
	old := now.Add(-40 * time.Minute)
	repository := &fakeGPUMetricsRepository{snapshot: GPUMetricsSnapshot{
		Sources: []GPUMetricsSource{{SourceID: "source-a", Operations: []GPUMetricsOperation{
			{
				OperationID: "prometheus.gpu_power.v1", Enrolled: true, Enabled: true, IntervalSeconds: 30,
				LastRun: &GPUMetricsRun{RunID: "run-1", Status: "PARTIAL", CompletedAt: fresh},
				Fields:  []GPUMetricsFieldColumn{{Name: "DCGM_FI_DEV_POWER_USAGE", Unit: "watts"}},
			},
			{
				OperationID: "prometheus.gpu_ecc.v1", Enrolled: true, Enabled: true, IntervalSeconds: 30,
				LastRun: &GPUMetricsRun{RunID: "run-2", Status: "SUCCEEDED", CompletedAt: old},
				Fields:  []GPUMetricsFieldColumn{{Name: "DCGM_FI_DEV_ECC_SBE_VOL_TOTAL", Unit: "count"}},
			},
			{
				OperationID: "prometheus.gpu_temperature.v1",
				Fields:      []GPUMetricsFieldColumn{{Name: "DCGM_FI_DEV_GPU_TEMP", Unit: "celsius"}},
			},
		}}},
		GPUs: []GPUMetricsRow{{SourceID: "source-a", NodeID: "node-1", GPUUUID: "GPU-a", Values: map[string]GPUMetricValue{
			"DCGM_FI_DEV_POWER_USAGE":       {State: GPUMetricSupported, Value: floatValue(210.5), ObservedAt: &fresh},
			"DCGM_FI_DEV_ECC_SBE_VOL_TOTAL": {State: GPUMetricSupported, Value: floatValue(0), ObservedAt: &old},
			"DCGM_FI_DEV_GPU_TEMP":          {State: GPUMetricNotSupported, Value: floatValue(0)},
		}}},
	}}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.GPUMetrics(context.Background(), GPUMetricsQuery{ClusterID: "cluster-a", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	operations := snapshot.Sources[0].Operations
	if operations[0].Freshness != GPUMetricsFresh || operations[0].FreshWindowSeconds != 60 {
		t.Fatalf("enrolled fresh operation = %+v", operations[0])
	}
	if operations[1].Freshness != GPUMetricsFreshnessOld {
		t.Fatalf("stale run was not detected: %+v", operations[1])
	}
	if operations[2].Freshness != GPUMetricsNoData || operations[2].FreshWindowSeconds != int64(GPUMetricsDefaultFreshFor/time.Second) {
		t.Fatalf("unenrolled operation must use the fixed window: %+v", operations[2])
	}
	values := snapshot.GPUs[0].Values
	if power := values["DCGM_FI_DEV_POWER_USAGE"]; power.State != GPUMetricSupported || power.Value == nil || *power.Value != 210.5 {
		t.Fatalf("supported power = %+v", power)
	}
	ecc := values["DCGM_FI_DEV_ECC_SBE_VOL_TOTAL"]
	if ecc.State != GPUMetricStale || ecc.Value != nil {
		t.Fatalf("a stale counter must not keep a renderable zero: %+v", ecc)
	}
	temperature := values["DCGM_FI_DEV_GPU_TEMP"]
	if temperature.State != GPUMetricNotSupported || temperature.Value != nil {
		t.Fatalf("an unsupported field must never carry a value: %+v", temperature)
	}
	if len(repository.clusters) != 1 || repository.clusters[0] != "cluster-a" {
		t.Fatalf("repository cluster scope = %v", repository.clusters)
	}
}

func TestGPUMetricsRejectsInvalidClusterAndReportsRepositoryFailure(t *testing.T) {
	service, err := NewService(&fakeGPUMetricsRepository{err: errors.New("database unavailable")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.GPUMetrics(context.Background(), GPUMetricsQuery{ClusterID: "bad id"}); err == nil {
		t.Fatal("an invalid cluster ID must be refused")
	}
	if _, err := service.GPUMetrics(context.Background(), GPUMetricsQuery{ClusterID: "cluster-a"}); err == nil {
		t.Fatal("a repository failure must not be projected as an empty snapshot")
	}
}

func TestDominantFieldStateNeverResolvesTiesTowardsSupported(t *testing.T) {
	for _, testCase := range []struct {
		summary GPUMetricsFieldSummary
		want    GPUMetricState
	}{
		{GPUMetricsFieldSummary{Supported: 8}, GPUMetricSupported},
		{GPUMetricsFieldSummary{Supported: 4, Unknown: 4}, GPUMetricUnknown},
		{GPUMetricsFieldSummary{Supported: 4, NotSupported: 4}, GPUMetricNotSupported},
		{GPUMetricsFieldSummary{}, GPUMetricUnknown},
	} {
		if got := DominantFieldState(testCase.summary); got != testCase.want {
			t.Fatalf("DominantFieldState(%+v) = %s, want %s", testCase.summary, got, testCase.want)
		}
	}
}

func timePointer(value time.Time) *time.Time { return &value }

// gpuMetricsCoverageSnapshot is one expected node, two expected GPUs (one
// freshly observed, one observed long ago) and one observed-only GPU. The
// target cache is never pruned, so the old record is the interesting case.
func gpuMetricsCoverageSnapshot(now time.Time) GPUMetricsSnapshot {
	fresh := now.Add(-20 * time.Second)
	old := now.Add(-21 * 24 * time.Hour)
	return GPUMetricsSnapshot{
		Sources: []GPUMetricsSource{{SourceID: "source-a", Primary: true, Operations: []GPUMetricsOperation{{
			OperationID: "prometheus.gpu_power.v1", Enrolled: true, Enabled: true, IntervalSeconds: 30,
			LastRun: &GPUMetricsRun{RunID: "run-1", Status: "SUCCEEDED", CompletedAt: fresh},
			Fields:  []GPUMetricsFieldColumn{{Name: "DCGM_FI_DEV_POWER_USAGE", Unit: "watts"}},
			FieldSummaries: []GPUMetricsFieldSummary{
				{Field: "DCGM_FI_DEV_POWER_USAGE", Supported: 1, Assessed: 1},
			},
		}}}},
		GPUs: []GPUMetricsRow{
			{SourceID: "source-a", NodeID: "node-1", GPUUUID: "GPU-a", Expected: true, Observed: true, ObservedAt: &fresh, Values: map[string]GPUMetricValue{}},
			{SourceID: "source-a", NodeID: "node-1", GPUUUID: "GPU-b", Expected: true, Observed: true, ObservedAt: &old, Values: map[string]GPUMetricValue{}},
			{SourceID: "source-a", NodeID: "node-1", GPUUUID: "GPU-c", Observed: true, ObservedAt: &fresh, Values: map[string]GPUMetricValue{}},
		},
		Inventory: GPUMetricsInventory{
			SourceID: "source-a", HasExpectedRevision: true, RevisionID: "revision-1",
			Observations: []GPUMetricsObservation{
				{NodeID: "node-1", Expected: true, ObservedAt: timePointer(fresh)},
				{NodeID: "node-1", GPUUUID: "GPU-a", Expected: true, ObservedAt: timePointer(fresh)},
				{NodeID: "node-1", GPUUUID: "GPU-b", Expected: true, ObservedAt: timePointer(old)},
				{NodeID: "node-1", GPUUUID: "GPU-c", ObservedAt: timePointer(fresh)},
			},
		},
	}
}

func TestGPUMetricsTreatsAnOldObservedTargetAsAGapRatherThanCoverage(t *testing.T) {
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	snapshot := gpuMetricsCoverageSnapshot(now)
	DeriveGPUMetricsStates(&snapshot, now)

	states := map[string]GPUMetricsObservedState{}
	for _, row := range snapshot.GPUs {
		states[row.GPUUUID] = row.ObservedState
	}
	if states["GPU-a"] != GPUMetricsObserved || states["GPU-b"] != GPUMetricsObservedStale || states["GPU-c"] != GPUMetricsObserved {
		t.Fatalf("observed states = %+v", states)
	}
	inventory := snapshot.Inventory
	if inventory.CoverageComplete {
		t.Fatalf("a stale observation must not complete coverage: %+v", inventory)
	}
	if inventory.CoveredGPUs != 1 || inventory.FreshObservedGPUs != 2 || inventory.StaleObservedGPUs != 1 || inventory.ObservedGPUs != 3 {
		t.Fatalf("coverage counts = %+v", inventory)
	}
	if len(inventory.ExpectedNotObserved) != 1 {
		t.Fatalf("expected-not-observed = %+v", inventory.ExpectedNotObserved)
	}
	gap := inventory.ExpectedNotObserved[0]
	if gap.GPUUUID != "GPU-b" || !gap.Stale || gap.ObservedAt == nil {
		t.Fatalf("a stale expected entity must be listed as a gap marked stale: %+v", gap)
	}
	if len(inventory.ObservedNotExpected) != 1 || inventory.ObservedNotExpected[0].GPUUUID != "GPU-c" {
		t.Fatalf("observed-not-expected = %+v", inventory.ObservedNotExpected)
	}
}

func TestGPUMetricsNeverCallsAFailingOrSkewedRunFresh(t *testing.T) {
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	fresh := now.Add(-20 * time.Second)
	for _, testCase := range []struct {
		status string
		at     time.Time
		want   GPUMetricsFreshness
	}{
		{"SUCCEEDED", fresh, GPUMetricsFresh},
		{"PARTIAL", fresh, GPUMetricsFresh},
		{"FAILED", fresh, GPUMetricsFailing},
		{"TIMEOUT", fresh, GPUMetricsFailing},
		{"FAILED", now.Add(-time.Hour), GPUMetricsFailing},
		{"SUCCEEDED", now.Add(-time.Hour), GPUMetricsFreshnessOld},
		{"SUCCEEDED", now.Add(10 * time.Minute), GPUMetricsClockSkewed},
		{"SUCCEEDED", now.Add(time.Minute), GPUMetricsFresh},
	} {
		snapshot := GPUMetricsSnapshot{Sources: []GPUMetricsSource{{SourceID: "source-a", Operations: []GPUMetricsOperation{{
			OperationID: "prometheus.gpu_power.v1", Enrolled: true, Enabled: true, IntervalSeconds: 30,
			LastRun: &GPUMetricsRun{RunID: "run-1", Status: testCase.status, CompletedAt: testCase.at},
		}}}}}
		DeriveGPUMetricsStates(&snapshot, now)
		if got := snapshot.Sources[0].Operations[0].Freshness; got != testCase.want {
			t.Fatalf("freshness for %s at %s = %s, want %s", testCase.status, testCase.at, got, testCase.want)
		}
	}
}

func TestGPUMetricsRefusesToRenderSkewedOrNonFiniteSamples(t *testing.T) {
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	ahead := now.Add(2 * time.Hour)
	fresh := now.Add(-10 * time.Second)
	snapshot := GPUMetricsSnapshot{
		Sources: []GPUMetricsSource{{SourceID: "source-a", Operations: []GPUMetricsOperation{{
			OperationID: "prometheus.gpu_power.v1", Enrolled: true, Enabled: true, IntervalSeconds: 30,
			Fields: []GPUMetricsFieldColumn{
				{Name: "skewed"}, {Name: "not-a-number"}, {Name: "infinite"}, {Name: "sound"},
			},
		}}}},
		GPUs: []GPUMetricsRow{{SourceID: "source-a", NodeID: "node-1", GPUUUID: "GPU-a", Values: map[string]GPUMetricValue{
			"skewed":       {State: GPUMetricSupported, Value: floatValue(210), ObservedAt: &ahead},
			"not-a-number": {State: GPUMetricSupported, Value: floatValue(math.NaN()), ObservedAt: &fresh},
			"infinite":     {State: GPUMetricSupported, Value: floatValue(math.Inf(1)), ObservedAt: &fresh},
			"sound":        {State: GPUMetricSupported, Value: floatValue(42), ObservedAt: &fresh},
		}}},
	}
	DeriveGPUMetricsStates(&snapshot, now)
	values := snapshot.GPUs[0].Values
	for _, field := range []string{"skewed", "not-a-number", "infinite"} {
		if value := values[field]; value.State != GPUMetricUnknown || value.Value != nil {
			t.Fatalf("%s must be UNKNOWN without a value: %+v", field, value)
		}
	}
	if sound := values["sound"]; sound.State != GPUMetricSupported || sound.Value == nil {
		t.Fatalf("a finite fresh sample must stay supported: %+v", sound)
	}
}

func TestGPUMetricsCountsExpectedButUnassessedGPUsAsUnknown(t *testing.T) {
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	snapshot := GPUMetricsSnapshot{
		Sources: []GPUMetricsSource{
			{SourceID: "source-a", Primary: true, Operations: []GPUMetricsOperation{{
				OperationID: "prometheus.gpu_power.v1",
				FieldSummaries: []GPUMetricsFieldSummary{
					{Field: "DCGM_FI_DEV_POWER_USAGE", Supported: 2, Assessed: 2},
				},
			}}},
			{SourceID: "source-b", Operations: []GPUMetricsOperation{{
				OperationID: "prometheus.gpu_power.v1",
				FieldSummaries: []GPUMetricsFieldSummary{
					{Field: "DCGM_FI_DEV_POWER_USAGE", Supported: 2, Assessed: 2},
				},
			}}},
		},
		Inventory: GPUMetricsInventory{SourceID: "source-a", HasExpectedRevision: true, ExpectedGPUs: 8},
	}
	DeriveGPUMetricsStates(&snapshot, now)
	summary := snapshot.Sources[0].Operations[0].FieldSummaries[0]
	if summary.Assessed != 2 || summary.Expected != 8 || summary.UnassessedExpected != 6 || summary.Unknown != 6 {
		t.Fatalf("a run that assessed 2 of 8 expected GPUs must carry its denominator: %+v", summary)
	}
	if summary.Dominant != GPUMetricUnknown {
		t.Fatalf("two supported of eight expected must not dominate as SUPPORTED: %+v", summary)
	}
	// The expected revision governs one source only, so another source's
	// summary must not borrow its denominator.
	if other := snapshot.Sources[1].Operations[0].FieldSummaries[0]; other.Expected != 0 || other.Unknown != 0 {
		t.Fatalf("a non-governing source must not inherit the expected count: %+v", other)
	}
	// Derivation is applied once per load, but must not drift if repeated.
	DeriveGPUMetricsStates(&snapshot, now)
	if again := snapshot.Sources[0].Operations[0].FieldSummaries[0]; again != summary {
		t.Fatalf("denominator derivation is not idempotent: %+v vs %+v", again, summary)
	}
}

func TestBoundGPUMetricsRefsStatesItsOwnTruncation(t *testing.T) {
	refs := make([]GPUMetricsEntityRef, 0, GPUMetricsRowLimit+2)
	for index := 0; index < GPUMetricsRowLimit+2; index++ {
		refs = append(refs, GPUMetricsEntityRef{NodeID: fmt.Sprintf("node-%05d", index)})
	}
	bounded, truncated := boundGPUMetricsRefs(refs)
	if !truncated || len(bounded) != GPUMetricsRowLimit {
		t.Fatalf("bounded = %d, truncated = %v", len(bounded), truncated)
	}
	if _, truncated := boundGPUMetricsRefs(refs[:2]); truncated {
		t.Fatal("a list inside the bound must not be reported as truncated")
	}
}

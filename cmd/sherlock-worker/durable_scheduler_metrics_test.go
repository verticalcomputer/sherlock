package main

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func durableSnapshotKey(cluster, source string, operation domain.CollectionOperationID) domain.ScheduleKey {
	return domain.ScheduleKey{ClusterID: domain.ClusterID(cluster), SourceID: domain.SourceID(source), Operation: operation}
}

func TestDurableSchedulerMetricsRejectsInvalidAllowLists(t *testing.T) {
	valid := durableSnapshotKey("c1", "s1", domain.OperationPrometheusGPUUtilization)
	cases := map[string][]domain.ScheduleKey{
		"duplicate keys": {
			valid,
			valid,
		},
		"empty cluster": {
			durableSnapshotKey("", "s1", domain.OperationPrometheusGPUUtilization),
		},
		"empty source": {
			durableSnapshotKey("c1", "", domain.OperationPrometheusGPUUtilization),
		},
		"empty operation": {
			durableSnapshotKey("c1", "s1", ""),
		},
		"unknown operation": {
			durableSnapshotKey("c1", "s1", "example.unreviewed.v9"),
		},
	}
	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewDurableSchedulerMetrics(prom.NewRegistry(), keys); err == nil {
				t.Fatal("expected allow-list rejection")
			}
		})
	}
}

func TestDurableSchedulerMetricsRejectsOverLimitAllowList(t *testing.T) {
	keys := make([]domain.ScheduleKey, 0, domain.MaxDurableSchedulerSnapshotKeys+1)
	for i := 0; i <= domain.MaxDurableSchedulerSnapshotKeys; i++ {
		keys = append(keys, durableSnapshotKey(fmt.Sprintf("cluster-%d", i), "s1", domain.OperationPrometheusGPUUtilization))
	}
	if _, err := NewDurableSchedulerMetrics(prom.NewRegistry(), keys); err == nil {
		t.Fatal("expected over-limit allow-list rejection")
	}
}

func TestDurableSchedulerMetricsOmitsSeriesBeforeFirstSnapshot(t *testing.T) {
	reg := prom.NewRegistry()
	if _, err := NewDurableSchedulerMetrics(reg, []domain.ScheduleKey{
		durableSnapshotKey("c1", "s1", domain.OperationPrometheusGPUUtilization),
	}); err != nil {
		t.Fatal(err)
	}
	if count := testutil.CollectAndCount(reg); count != 0 {
		t.Fatalf("exported %d metrics before the first snapshot", count)
	}
}

func TestDurableSchedulerMetricsExportsExactNamesTypesLabelsAndValues(t *testing.T) {
	reg := prom.NewRegistry()
	m, err := NewDurableSchedulerMetrics(reg, []domain.ScheduleKey{
		durableSnapshotKey("c1", "s1", domain.OperationPrometheusGPUUtilization),
		durableSnapshotKey("c1", "s2", domain.OperationSlurmInventory),
	})
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Unix(1_000_000, 0).UTC()
	if err := m.UpdateSnapshot(domain.DurableSchedulerSnapshot{ObservedAt: observed, Rows: []domain.DurableSchedulerSnapshotRow{
		{Key: durableSnapshotKey("c1", "s1", domain.OperationPrometheusGPUUtilization), NextDue: observed.Add(-30 * time.Second), CoalescedIntervals: 7, DroppedIntervals: 2},
		{Key: durableSnapshotKey("c1", "s2", domain.OperationSlurmInventory), NextDue: observed.Add(10 * time.Second), CoalescedIntervals: 0},
	}}); err != nil {
		t.Fatal(err)
	}
	expected := `# HELP sherlock_durable_scheduler_coalesced_intervals_total Durable cumulative coalesced metric intervals per schedule. Re-exported database state; resets after database state recreation remain possible.
# TYPE sherlock_durable_scheduler_coalesced_intervals_total counter
sherlock_durable_scheduler_coalesced_intervals_total{cluster="c1",operation="prometheus.gpu_utilization.v1",source="s1"} 7
sherlock_durable_scheduler_coalesced_intervals_total{cluster="c1",operation="slurm.inventory.v1",source="s2"} 0
# HELP sherlock_durable_scheduler_dropped_intervals Admitted periodic occurrences that terminated before their first claim, projected from retained occurrence and work records. Re-exported database state: the value may decrease if those records are removed, is not additive across workers observing the same schedules, and does not measure every telemetry gap, source failure or lost event.
# TYPE sherlock_durable_scheduler_dropped_intervals gauge
sherlock_durable_scheduler_dropped_intervals{cluster="c1",operation="prometheus.gpu_utilization.v1",source="s1"} 2
sherlock_durable_scheduler_dropped_intervals{cluster="c1",operation="slurm.inventory.v1",source="s2"} 0
# HELP sherlock_durable_scheduler_due_age_seconds Stored schedule due age at snapshot time: max(0, snapshot observation minus next-due timestamp). Describes durable state only; not eligibility, health or success.
# TYPE sherlock_durable_scheduler_due_age_seconds gauge
sherlock_durable_scheduler_due_age_seconds{cluster="c1",operation="prometheus.gpu_utilization.v1",source="s1"} 30
sherlock_durable_scheduler_due_age_seconds{cluster="c1",operation="slurm.inventory.v1",source="s2"} 0
# HELP sherlock_durable_scheduler_snapshot_timestamp_seconds Observation timestamp of the accepted durable scheduler snapshot.
# TYPE sherlock_durable_scheduler_snapshot_timestamp_seconds gauge
sherlock_durable_scheduler_snapshot_timestamp_seconds 1e+06
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected)); err != nil {
		t.Fatal(err)
	}
}

func TestDurableSchedulerMetricsRefreshAndScrapeDoNotInflateCounters(t *testing.T) {
	reg := prom.NewRegistry()
	m, err := NewDurableSchedulerMetrics(reg, []domain.ScheduleKey{
		durableSnapshotKey("c1", "s1", domain.OperationPrometheusGPUUtilization),
	})
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Unix(2_000_000, 0).UTC()
	snapshot := domain.DurableSchedulerSnapshot{ObservedAt: observed, Rows: []domain.DurableSchedulerSnapshotRow{
		{Key: durableSnapshotKey("c1", "s1", domain.OperationPrometheusGPUUtilization), NextDue: observed, CoalescedIntervals: 3},
	}}
	for range 5 {
		if err := m.UpdateSnapshot(snapshot); err != nil {
			t.Fatal(err)
		}
	}
	for range 5 {
		families, err := reg.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, family := range families {
			if family.GetName() != "sherlock_durable_scheduler_coalesced_intervals_total" {
				continue
			}
			if len(family.Metric) != 1 || family.Metric[0].Counter.GetValue() != 3 {
				t.Fatalf("counter inflated or lost: %+v", family.Metric)
			}
		}
	}
}

func TestDurableSchedulerMetricsReplacementRemovesAbsentRows(t *testing.T) {
	reg := prom.NewRegistry()
	kept := durableSnapshotKey("c1", "s1", domain.OperationPrometheusGPUUtilization)
	removed := durableSnapshotKey("c1", "s2", domain.OperationPrometheusGPUUtilization)
	m, err := NewDurableSchedulerMetrics(reg, []domain.ScheduleKey{kept, removed})
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Unix(3_000_000, 0).UTC()
	if err := m.UpdateSnapshot(domain.DurableSchedulerSnapshot{ObservedAt: observed, Rows: []domain.DurableSchedulerSnapshotRow{
		{Key: kept, NextDue: observed, CoalescedIntervals: 1},
		{Key: removed, NextDue: observed, CoalescedIntervals: 2},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateSnapshot(domain.DurableSchedulerSnapshot{ObservedAt: observed.Add(time.Minute), Rows: []domain.DurableSchedulerSnapshotRow{
		{Key: kept, NextDue: observed, CoalescedIntervals: 1},
	}}); err != nil {
		t.Fatal(err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	series := 0
	for _, family := range families {
		if !strings.HasPrefix(family.GetName(), "sherlock_durable_scheduler_") || strings.HasSuffix(family.GetName(), "_timestamp_seconds") {
			continue
		}
		series += len(family.Metric)
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "source" && label.GetValue() == "s2" {
					t.Fatalf("removed row still exported in %s", family.GetName())
				}
			}
		}
	}
	if series != 3 {
		t.Fatalf("expected 3 labelled series after replacement, got %d", series)
	}
}

func TestDurableSchedulerMetricsEmptySnapshotExposesOnlyTimestamp(t *testing.T) {
	reg := prom.NewRegistry()
	m, err := NewDurableSchedulerMetrics(reg, nil)
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Unix(4_000_000, 0).UTC()
	if err := m.UpdateSnapshot(domain.DurableSchedulerSnapshot{ObservedAt: observed}); err != nil {
		t.Fatal(err)
	}
	expected := `# HELP sherlock_durable_scheduler_snapshot_timestamp_seconds Observation timestamp of the accepted durable scheduler snapshot.
# TYPE sherlock_durable_scheduler_snapshot_timestamp_seconds gauge
sherlock_durable_scheduler_snapshot_timestamp_seconds 4e+06
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected)); err != nil {
		t.Fatal(err)
	}
}

func TestDurableSchedulerMetricsRejectsInvalidSnapshotsAtomically(t *testing.T) {
	key := durableSnapshotKey("c1", "s1", domain.OperationPrometheusGPUUtilization)
	reg := prom.NewRegistry()
	m, err := NewDurableSchedulerMetrics(reg, []domain.ScheduleKey{key})
	if err != nil {
		t.Fatal(err)
	}
	first := time.Unix(5_000_000, 0).UTC()
	if err := m.UpdateSnapshot(domain.DurableSchedulerSnapshot{ObservedAt: first, Rows: []domain.DurableSchedulerSnapshotRow{
		{Key: key, NextDue: first.Add(-time.Second), CoalescedIntervals: 4},
	}}); err != nil {
		t.Fatal(err)
	}
	later := first.Add(time.Minute)
	invalid := map[string]domain.DurableSchedulerSnapshot{
		"missing timestamp": {Rows: []domain.DurableSchedulerSnapshotRow{
			{Key: key, NextDue: later, CoalescedIntervals: 5},
		}},
		"duplicate rows": {ObservedAt: later, Rows: []domain.DurableSchedulerSnapshotRow{
			{Key: key, NextDue: later, CoalescedIntervals: 5},
			{Key: key, NextDue: later, CoalescedIntervals: 6},
		}},
		"unknown key": {ObservedAt: later, Rows: []domain.DurableSchedulerSnapshotRow{
			{Key: durableSnapshotKey("c1", "intruder", domain.OperationPrometheusGPUUtilization), NextDue: later},
		}},
		"unknown cluster for known source": {ObservedAt: later, Rows: []domain.DurableSchedulerSnapshotRow{
			{Key: durableSnapshotKey("elsewhere", "s1", domain.OperationPrometheusGPUUtilization), NextDue: later},
		}},
		"invalid due timestamp": {ObservedAt: later, Rows: []domain.DurableSchedulerSnapshotRow{
			{Key: key, CoalescedIntervals: 5},
		}},
		"negative count": {ObservedAt: later, Rows: []domain.DurableSchedulerSnapshotRow{
			{Key: key, NextDue: later, CoalescedIntervals: -1},
		}},
		"negative dropped count": {ObservedAt: later, Rows: []domain.DurableSchedulerSnapshotRow{
			{Key: key, NextDue: later, DroppedIntervals: -1},
		}},
	}
	for name, snapshot := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := m.UpdateSnapshot(snapshot); err == nil {
				t.Fatal("expected snapshot rejection")
			}
		})
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		switch family.GetName() {
		case "sherlock_durable_scheduler_snapshot_timestamp_seconds":
			if len(family.Metric) != 1 || family.Metric[0].Gauge.GetValue() != 5e+06 {
				t.Fatalf("previous snapshot timestamp lost: %+v", family.Metric)
			}
		case "sherlock_durable_scheduler_coalesced_intervals_total":
			if len(family.Metric) != 1 || family.Metric[0].Counter.GetValue() != 4 {
				t.Fatalf("previous snapshot counter lost: %+v", family.Metric)
			}
		case "sherlock_durable_scheduler_dropped_intervals":
			if len(family.Metric) != 1 || family.Metric[0].Gauge.GetValue() != 0 {
				t.Fatalf("previous snapshot dropped gauge lost: %+v", family.Metric)
			}
		case "sherlock_durable_scheduler_due_age_seconds":
			if len(family.Metric) != 1 || family.Metric[0].Gauge.GetValue() != 1 {
				t.Fatalf("previous snapshot due age lost: %+v", family.Metric)
			}
		default:
			t.Fatalf("unexpected metric family %s", family.GetName())
		}
	}
}

func TestDurableSchedulerMetricsSeparatesIdenticalSourcesAcrossClusters(t *testing.T) {
	reg := prom.NewRegistry()
	m, err := NewDurableSchedulerMetrics(reg, []domain.ScheduleKey{
		durableSnapshotKey("east", "shared-source", domain.OperationPrometheusGPUUtilization),
		durableSnapshotKey("west", "shared-source", domain.OperationPrometheusGPUUtilization),
	})
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Unix(6_000_000, 0).UTC()
	if err := m.UpdateSnapshot(domain.DurableSchedulerSnapshot{ObservedAt: observed, Rows: []domain.DurableSchedulerSnapshotRow{
		{Key: durableSnapshotKey("east", "shared-source", domain.OperationPrometheusGPUUtilization), NextDue: observed.Add(-time.Second), CoalescedIntervals: 1},
		{Key: durableSnapshotKey("west", "shared-source", domain.OperationPrometheusGPUUtilization), NextDue: observed.Add(-2 * time.Second), CoalescedIntervals: 2, DroppedIntervals: 3},
	}}); err != nil {
		t.Fatal(err)
	}
	expected := `# HELP sherlock_durable_scheduler_coalesced_intervals_total Durable cumulative coalesced metric intervals per schedule. Re-exported database state; resets after database state recreation remain possible.
# TYPE sherlock_durable_scheduler_coalesced_intervals_total counter
sherlock_durable_scheduler_coalesced_intervals_total{cluster="east",operation="prometheus.gpu_utilization.v1",source="shared-source"} 1
sherlock_durable_scheduler_coalesced_intervals_total{cluster="west",operation="prometheus.gpu_utilization.v1",source="shared-source"} 2
# HELP sherlock_durable_scheduler_dropped_intervals Admitted periodic occurrences that terminated before their first claim, projected from retained occurrence and work records. Re-exported database state: the value may decrease if those records are removed, is not additive across workers observing the same schedules, and does not measure every telemetry gap, source failure or lost event.
# TYPE sherlock_durable_scheduler_dropped_intervals gauge
sherlock_durable_scheduler_dropped_intervals{cluster="east",operation="prometheus.gpu_utilization.v1",source="shared-source"} 0
sherlock_durable_scheduler_dropped_intervals{cluster="west",operation="prometheus.gpu_utilization.v1",source="shared-source"} 3
# HELP sherlock_durable_scheduler_due_age_seconds Stored schedule due age at snapshot time: max(0, snapshot observation minus next-due timestamp). Describes durable state only; not eligibility, health or success.
# TYPE sherlock_durable_scheduler_due_age_seconds gauge
sherlock_durable_scheduler_due_age_seconds{cluster="east",operation="prometheus.gpu_utilization.v1",source="shared-source"} 1
sherlock_durable_scheduler_due_age_seconds{cluster="west",operation="prometheus.gpu_utilization.v1",source="shared-source"} 2
# HELP sherlock_durable_scheduler_snapshot_timestamp_seconds Observation timestamp of the accepted durable scheduler snapshot.
# TYPE sherlock_durable_scheduler_snapshot_timestamp_seconds gauge
sherlock_durable_scheduler_snapshot_timestamp_seconds 6e+06
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected)); err != nil {
		t.Fatal(err)
	}
}

func TestDurableSchedulerMetricsCopiesCallerData(t *testing.T) {
	keys := []domain.ScheduleKey{durableSnapshotKey("c1", "s1", domain.OperationPrometheusGPUUtilization)}
	reg := prom.NewRegistry()
	m, err := NewDurableSchedulerMetrics(reg, keys)
	if err != nil {
		t.Fatal(err)
	}
	keys[0] = durableSnapshotKey("mutated", "mutated", domain.OperationPrometheusGPUXID)
	observed := time.Unix(7_000_000, 0).UTC()
	rows := []domain.DurableSchedulerSnapshotRow{
		{Key: durableSnapshotKey("c1", "s1", domain.OperationPrometheusGPUUtilization), NextDue: observed.Add(-9 * time.Second), CoalescedIntervals: 11},
	}
	if err := m.UpdateSnapshot(domain.DurableSchedulerSnapshot{ObservedAt: observed, Rows: rows}); err != nil {
		t.Fatal(err)
	}
	rows[0].NextDue = observed.Add(time.Hour)
	rows[0].CoalescedIntervals = 999
	rows[0].Key = durableSnapshotKey("mutated", "mutated", domain.OperationPrometheusGPUUtilization)
	mutated := domain.DurableSchedulerSnapshot{ObservedAt: observed, Rows: rows}
	if err := m.UpdateSnapshot(mutated); err == nil {
		t.Fatal("expected mutated snapshot to reference an unknown key")
	}
	expected := `# HELP sherlock_durable_scheduler_coalesced_intervals_total Durable cumulative coalesced metric intervals per schedule. Re-exported database state; resets after database state recreation remain possible.
# TYPE sherlock_durable_scheduler_coalesced_intervals_total counter
sherlock_durable_scheduler_coalesced_intervals_total{cluster="c1",operation="prometheus.gpu_utilization.v1",source="s1"} 11
# HELP sherlock_durable_scheduler_dropped_intervals Admitted periodic occurrences that terminated before their first claim, projected from retained occurrence and work records. Re-exported database state: the value may decrease if those records are removed, is not additive across workers observing the same schedules, and does not measure every telemetry gap, source failure or lost event.
# TYPE sherlock_durable_scheduler_dropped_intervals gauge
sherlock_durable_scheduler_dropped_intervals{cluster="c1",operation="prometheus.gpu_utilization.v1",source="s1"} 0
# HELP sherlock_durable_scheduler_due_age_seconds Stored schedule due age at snapshot time: max(0, snapshot observation minus next-due timestamp). Describes durable state only; not eligibility, health or success.
# TYPE sherlock_durable_scheduler_due_age_seconds gauge
sherlock_durable_scheduler_due_age_seconds{cluster="c1",operation="prometheus.gpu_utilization.v1",source="s1"} 9
# HELP sherlock_durable_scheduler_snapshot_timestamp_seconds Observation timestamp of the accepted durable scheduler snapshot.
# TYPE sherlock_durable_scheduler_snapshot_timestamp_seconds gauge
sherlock_durable_scheduler_snapshot_timestamp_seconds 7e+06
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected)); err != nil {
		t.Fatal(err)
	}
}

func TestDurableSchedulerMetricsHandlesConcurrentUpdatesAndScrapes(t *testing.T) {
	keys := []domain.ScheduleKey{
		durableSnapshotKey("c1", "s1", domain.OperationPrometheusGPUUtilization),
		durableSnapshotKey("c1", "s2", domain.OperationPrometheusGPUXID),
	}
	reg := prom.NewRegistry()
	m, err := NewDurableSchedulerMetrics(reg, keys)
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Unix(8_000_000, 0).UTC()
	var group sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		group.Add(1)
		go func(offset int) {
			defer group.Done()
			for i := int64(0); i < 50; i++ {
				due := observed.Add(time.Duration(offset) * time.Second)
				snapshot := domain.DurableSchedulerSnapshot{ObservedAt: observed, Rows: []domain.DurableSchedulerSnapshotRow{
					{Key: keys[0], NextDue: due, CoalescedIntervals: i},
					{Key: keys[1], NextDue: due, CoalescedIntervals: i},
				}}
				if err := m.UpdateSnapshot(snapshot); err != nil {
					t.Error(err)
					return
				}
				if _, err := reg.Gather(); err != nil {
					t.Error(err)
					return
				}
			}
		}(worker)
	}
	group.Wait()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(families) != 4 {
		t.Fatalf("expected 4 metric families, got %d", len(families))
	}
}

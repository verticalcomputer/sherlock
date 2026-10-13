package main

import (
	"fmt"
	"sort"
	"sync"
	"time"

	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// DurableSchedulerMetrics presents durable schedule snapshots to Prometheus.
// Due age describes the stored due timestamp at snapshot time; it does not
// establish admission eligibility, source health or collection success. The
// coalesced counter re-exports the durable cumulative value, so counter
// resets after database state recreation remain possible. All state stays
// process-local and converges on the next accepted snapshot after a restart.
type DurableSchedulerMetrics struct {
	// index maps allow-listed identities to their fixed label values. The map
	// is immutable after construction; only snapshot swaps.
	index map[domain.ScheduleKey][3]string

	dueAgeDesc    *prom.Desc
	coalescedDesc *prom.Desc
	droppedDesc   *prom.Desc
	snapshotDesc  *prom.Desc

	mutex    sync.RWMutex
	observed time.Time
	rows     []domain.DurableSchedulerSnapshotRow
	valid    bool
}

// NewDurableSchedulerMetrics registers a snapshot collector limited to the
// given schedule identities. The allow-list is copied; later caller mutation
// has no effect. Snapshot data can never register additional labels: unknown
// keys are rejected at update time.
func NewDurableSchedulerMetrics(reg prom.Registerer, keys []domain.ScheduleKey) (*DurableSchedulerMetrics, error) {
	if err := domain.ValidateDurableSchedulerSnapshotKeys(keys); err != nil {
		return nil, err
	}
	index := make(map[domain.ScheduleKey][3]string, len(keys))
	for _, key := range keys {
		index[key] = [3]string{string(key.ClusterID), string(key.SourceID), string(key.Operation)}
	}
	m := &DurableSchedulerMetrics{
		index: index,
		dueAgeDesc: prom.NewDesc(
			"sherlock_durable_scheduler_due_age_seconds",
			"Stored schedule due age at snapshot time: max(0, snapshot observation minus next-due timestamp). Describes durable state only; not eligibility, health or success.",
			[]string{"cluster", "source", "operation"}, nil,
		),
		coalescedDesc: prom.NewDesc(
			"sherlock_durable_scheduler_coalesced_intervals_total",
			"Durable cumulative coalesced metric intervals per schedule. Re-exported database state; resets after database state recreation remain possible.",
			[]string{"cluster", "source", "operation"}, nil,
		),
		droppedDesc: prom.NewDesc(
			"sherlock_durable_scheduler_dropped_intervals",
			"Admitted periodic occurrences that terminated before their first claim, projected from retained occurrence and work records. Re-exported database state: the value may decrease if those records are removed, is not additive across workers observing the same schedules, and does not measure every telemetry gap, source failure or lost event.",
			[]string{"cluster", "source", "operation"}, nil,
		),
		snapshotDesc: prom.NewDesc(
			"sherlock_durable_scheduler_snapshot_timestamp_seconds",
			"Observation timestamp of the accepted durable scheduler snapshot.",
			nil, nil,
		),
	}
	if err := reg.Register(m); err != nil {
		return nil, err
	}
	return m, nil
}

// UpdateSnapshot replaces the exported snapshot atomically. Validation runs
// fully before any state changes, so a rejected snapshot leaves the previous
// valid snapshot intact. Rows are copied; later caller mutation has no effect.
func (m *DurableSchedulerMetrics) UpdateSnapshot(snapshot domain.DurableSchedulerSnapshot) error {
	if snapshot.ObservedAt.IsZero() {
		return fmt.Errorf("durable scheduler snapshot observation timestamp is invalid")
	}
	seen := make(map[domain.ScheduleKey]struct{}, len(snapshot.Rows))
	staged := make([]domain.DurableSchedulerSnapshotRow, 0, len(snapshot.Rows))
	for _, row := range snapshot.Rows {
		if _, ok := m.index[row.Key]; !ok {
			return fmt.Errorf("durable scheduler snapshot row is not allow-listed")
		}
		if row.NextDue.IsZero() {
			return fmt.Errorf("durable scheduler snapshot due timestamp is invalid")
		}
		if row.CoalescedIntervals < 0 {
			return fmt.Errorf("durable scheduler snapshot coalesced count is negative")
		}
		if row.DroppedIntervals < 0 {
			return fmt.Errorf("durable scheduler snapshot dropped count is negative")
		}
		if _, duplicate := seen[row.Key]; duplicate {
			return fmt.Errorf("duplicate durable scheduler snapshot row")
		}
		seen[row.Key] = struct{}{}
		staged = append(staged, row)
	}
	// Rows export in deterministic cluster/source/operation order, matching
	// the store snapshot ordering rather than the allow-list order.
	sort.Slice(staged, func(i, j int) bool {
		a, b := staged[i].Key, staged[j].Key
		if a.ClusterID != b.ClusterID {
			return a.ClusterID < b.ClusterID
		}
		if a.SourceID != b.SourceID {
			return a.SourceID < b.SourceID
		}
		return a.Operation < b.Operation
	})
	m.mutex.Lock()
	m.observed = snapshot.ObservedAt
	m.rows = staged
	m.valid = true
	m.mutex.Unlock()
	return nil
}

// Describe implements prom.Collector.
func (m *DurableSchedulerMetrics) Describe(ch chan<- *prom.Desc) {
	ch <- m.dueAgeDesc
	ch <- m.coalescedDesc
	ch <- m.droppedDesc
	ch <- m.snapshotDesc
}

// Collect implements prom.Collector. Constant metrics re-export the accepted
// snapshot values, so neither refreshes nor scrapes inflate the cumulative
// counter. Before the first valid snapshot nothing is exported.
func (m *DurableSchedulerMetrics) Collect(ch chan<- prom.Metric) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	if !m.valid {
		return
	}
	for _, row := range m.rows {
		labels := m.index[row.Key]
		age := m.observed.Sub(row.NextDue).Seconds()
		if age < 0 {
			age = 0
		}
		ch <- prom.MustNewConstMetric(m.dueAgeDesc, prom.GaugeValue, age, labels[0], labels[1], labels[2])
		ch <- prom.MustNewConstMetric(m.coalescedDesc, prom.CounterValue, float64(row.CoalescedIntervals), labels[0], labels[1], labels[2])
		ch <- prom.MustNewConstMetric(m.droppedDesc, prom.GaugeValue, float64(row.DroppedIntervals), labels[0], labels[1], labels[2])
	}
	ch <- prom.MustNewConstMetric(m.snapshotDesc, prom.GaugeValue, float64(m.observed.UnixNano())/1e9)
}

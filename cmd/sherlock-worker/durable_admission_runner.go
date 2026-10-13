package main

import (
	"context"
	"log/slog"
	"time"

	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type durableAdmitter interface {
	AdmitDueSchedule(context.Context, domain.DurableAdmissionPolicy) (domain.ScheduleAdmission, bool, error)
}

// Rejections count committed admission decisions by this process, not unique
// intervals. Only enrolled schedules and the three fixed quota reasons exist.
type durableRejectionMetrics struct {
	counters map[domain.ScheduleKey]map[string]prom.Counter
}

func newDurableRejectionMetrics(reg prom.Registerer, keys []domain.ScheduleKey) (*durableRejectionMetrics, error) {
	if err := domain.ValidateDurableSchedulerSnapshotKeys(keys); err != nil {
		return nil, err
	}
	v := prom.NewCounterVec(prom.CounterOpts{Name: "sherlock_durable_scheduler_quota_rejections_total",
		Help: "Admission attempts denied to an otherwise eligible enrolled schedule, by quota reason. Process-local; repeated polls count again, restarts reset; not unique intervals or telemetry loss."}, []string{"cluster", "source", "operation", "reason"})
	if err := reg.Register(v); err != nil {
		return nil, err
	}
	m := &durableRejectionMetrics{counters: make(map[domain.ScheduleKey]map[string]prom.Counter, len(keys))}
	for _, k := range keys {
		m.counters[k] = map[string]prom.Counter{}
		for _, reason := range []string{"global", "cluster", "source"} {
			m.counters[k][reason] = v.WithLabelValues(string(k.ClusterID), string(k.SourceID), string(k.Operation), reason)
		}
	}
	return m, nil
}

func (m *durableRejectionMetrics) observe(a domain.ScheduleAdmission) {
	if m != nil {
		if c := m.counters[a.ScheduleKey][a.QuotaRejection]; c != nil {
			c.Inc()
		}
	}
}

// Admission has a serial, bounded loop independent of blocking legacy
// collection and investigation/repair maintenance. Shared DB resources still
// matter; this is not a database latency or execution-time guarantee.
func runDurableAdmission(ctx context.Context, store durableAdmitter, policy domain.DurableAdmissionPolicy, metrics *durableRejectionMetrics, logger *slog.Logger, interval, timeout time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for ctx.Err() == nil {
		turn, cancel := context.WithTimeout(ctx, timeout)
		a, _, err := store.AdmitDueSchedule(turn, policy)
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				logger.Error("collection.admission_failed", "code", "DURABLE_ADMISSION_FAILED")
			}
		} else {
			metrics.observe(a)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

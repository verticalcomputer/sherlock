package main

import (
	"github.com/jackc/pgx/v5/pgxpool"
	prom "github.com/prometheus/client_golang/prometheus"
	"time"
)

// Scheduler probes describe this worker process. Comparing enabled and disabled
// windows is an operator measurement; no counter claims causal repair impact.
type schedulerMetrics struct {
	claims      *prom.HistogramVec
	completions *prom.CounterVec
}

func newSchedulerMetrics(reg prom.Registerer, pool *pgxpool.Pool) *schedulerMetrics {
	m := &schedulerMetrics{
		claims:      prom.NewHistogramVec(prom.HistogramOpts{Name: "sherlock_scheduler_claim_seconds", Help: "Ordinary scheduler claim duration, including database acquisition and lock wait.", Buckets: []float64{.001, .002, .003, .004, .0055, .01, .025, .1, 1, 1.5}}, []string{"outcome"}),
		completions: prom.NewCounterVec(prom.CounterOpts{Name: "sherlock_scheduler_completions_total", Help: "Ordinary scheduler durable completions and completion failures."}, []string{"outcome"}),
	}
	reg.MustRegister(m.claims, m.completions)
	if pool != nil {
		reg.MustRegister(prom.NewCounterFunc(prom.CounterOpts{Name: "sherlock_scheduler_pool_empty_acquires_total", Help: "Worker database pool acquisitions that waited for an available connection."}, func() float64 { return float64(pool.Stat().EmptyAcquireCount()) }),
			prom.NewCounterFunc(prom.CounterOpts{Name: "sherlock_scheduler_pool_acquire_seconds_total", Help: "Worker database pool cumulative acquisition duration."}, func() float64 { return pool.Stat().AcquireDuration().Seconds() }))
	}
	return m
}
func (m *schedulerMetrics) recordClaim(d time.Duration, found bool, err error) {
	outcome := "idle"
	if err != nil {
		outcome = "error"
	} else if found {
		outcome = "claimed"
	}
	m.claims.WithLabelValues(outcome).Observe(d.Seconds())
}

package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	prom "github.com/prometheus/client_golang/prometheus"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

var errArtifactReconciliation = errors.New("artifact reconciliation failed")
var errRetentionBacklog = errors.New("retention backlog measurement failed")

const retentionBacklogTimeout = 2 * time.Second

type retentionMaintenanceStore interface {
	ApplyRetention(context.Context, time.Time, time.Duration, time.Duration) (storepg.RetentionResult, error)
	MeasureRetentionBacklog(context.Context, time.Time, time.Duration, time.Duration) (storepg.RetentionBacklog, error)
}

type maintenancePolicy struct {
	interval, timeout, retryInitial, retryMax time.Duration
}

func defaultMaintenancePolicy(interval time.Duration) maintenancePolicy {
	// An unusually short maintenance interval must not turn failures into a
	// tight retry loop. Successful passes still follow the configured interval.
	initial := max(time.Second, min(interval, 30*time.Second))
	return maintenancePolicy{interval: interval, timeout: 5 * time.Minute, retryInitial: initial, retryMax: max(initial, min(interval, 30*time.Minute))}
}

func (p maintenancePolicy) retryDelay(failures int) time.Duration {
	delay := p.retryInitial
	for n := 1; n < failures && delay < p.retryMax; n++ {
		if delay > p.retryMax/2 {
			return p.retryMax
		}
		delay *= 2
	}
	return min(delay, p.retryMax)
}

// These process-local metrics describe maintenance only, never source health.
// Last-success zero means no successful pass in this process, not healthy.
// Backlog samples are bounded lower bounds, qualified by truncation and a
// measurement timestamp. Existing deletion counters report committed progress.
type maintenanceMetrics struct {
	degraded, running, lastSuccess, lastFailure, nextAttempt, failures *prom.GaugeVec
	backlogAvailable                                                   *prom.GaugeVec
	backlogMeasuredAt, backlogAttemptedAt                              *prom.GaugeVec
	backlogExpired, backlogEligible, backlogTruncated, backlogOldest   *prom.GaugeVec
	backlogAttempts                                                    *prom.CounterVec
	runs                                                               *prom.CounterVec
	duration                                                           *prom.HistogramVec
}

func newMaintenanceMetrics(reg prom.Registerer) *maintenanceMetrics {
	gauge := func(name, help string) *prom.GaugeVec {
		return prom.NewGaugeVec(prom.GaugeOpts{Name: "sherlock_worker_maintenance_" + name, Help: help}, []string{"task"})
	}
	backlogClassGauge := func(name, help string) *prom.GaugeVec {
		return prom.NewGaugeVec(prom.GaugeOpts{Name: "sherlock_worker_maintenance_backlog_" + name, Help: help}, []string{"task", "class"})
	}
	m := &maintenanceMetrics{
		degraded:           gauge("degraded", "One after an unsuccessful pass until a successful pass; zero alone does not prove a completed pass or healthy sources."),
		running:            gauge("running", "One while this process is executing a maintenance pass."),
		lastSuccess:        gauge("last_success_timestamp_seconds", "Last successful pass completion Unix time; zero until success in this process."),
		lastFailure:        gauge("last_failure_timestamp_seconds", "Last unsuccessful pass completion Unix time; zero until failure in this process."),
		nextAttempt:        gauge("next_attempt_timestamp_seconds", "Next scheduled maintenance/retry Unix time; zero while running or stopped."),
		failures:           gauge("consecutive_failures", "Consecutive unsuccessful maintenance passes in this process."),
		backlogAvailable:   gauge("backlog_available", "One when the latest bounded backlog measurement attempt succeeded; zero means unknown/unmeasured and count series are absent. Does not imply cleanup or source health."),
		backlogMeasuredAt:  gauge("backlog_last_success_timestamp_seconds", "Last successful backlog measurement snapshot Unix time; zero until measured. Historical only when backlog_available is zero; age must be checked even when available."),
		backlogAttemptedAt: gauge("backlog_last_attempt_timestamp_seconds", "Last backlog measurement attempt start Unix time; zero until attempted. This is not the snapshot age or successful measurement time."),
		backlogExpired:     backlogClassGauge("expired_rows_lower_bound", "Expired rows in the oldest capped sample. Lower bound when truncated is one, otherwise exact at measurement time; absent when unavailable."),
		backlogEligible:    backlogClassGauge("eligible_rows_lower_bound", "Cleanup-eligible rows among the oldest capped expired sample. Lower bound when truncated is one, otherwise exact at measurement time; absent when unavailable."),
		backlogTruncated:   backlogClassGauge("truncated", "One when additional expired rows exist beyond the bounded sample; zero only after a complete measurement. Absent when unavailable."),
		backlogOldest:      backlogClassGauge("oldest_expired_timestamp_seconds", "Oldest expired row Unix time; zero only for a successfully measured empty class. Absent when unavailable."),
		backlogAttempts:    prom.NewCounterVec(prom.CounterOpts{Name: "sherlock_worker_maintenance_backlog_measurements_total", Help: "Bounded backlog measurement attempts by fixed task and outcome, independently of cleanup success; shutdown-canceled attempts are excluded."}, []string{"task", "outcome"}),
		runs:               prom.NewCounterVec(prom.CounterOpts{Name: "sherlock_worker_maintenance_runs_total", Help: "Completed maintenance passes by fixed task and outcome; canceled process shutdown is excluded."}, []string{"task", "outcome"}),
		duration:           prom.NewHistogramVec(prom.HistogramOpts{Name: "sherlock_worker_maintenance_duration_seconds", Help: "Maintenance pass duration, including failed and shutdown-canceled passes.", Buckets: []float64{.01, .1, 1, 10, 30, 60, 300}}, []string{"task"}),
	}
	// Registration is startup work: collisions must not be hidden as a
	// recoverable maintenance failure.
	reg.MustRegister(m.degraded, m.running, m.lastSuccess, m.lastFailure, m.nextAttempt, m.failures, m.backlogAvailable, m.backlogMeasuredAt, m.backlogAttemptedAt, m.backlogExpired, m.backlogEligible, m.backlogTruncated, m.backlogOldest, m.backlogAttempts, m.runs, m.duration)
	return m
}

// startPeriodicMaintenance runs immediately, then waits after each completed
// pass. Each pass has a deadline; failures retry with capped backoff, without
// sending a fatal event to collection. Only one pass per task is in flight.
// Cancellation joins through done before the runtime closes the database pool.
func startPeriodicMaintenance(ctx context.Context, policy maintenancePolicy, task string, metrics *maintenanceMetrics, logger *slog.Logger, run func(context.Context) error) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			metrics.running.WithLabelValues(task).Set(0)
			metrics.nextAttempt.WithLabelValues(task).Set(0)
		}()
		failures := 0
		metrics.lastSuccess.WithLabelValues(task).Set(0)
		metrics.lastFailure.WithLabelValues(task).Set(0)
		metrics.degraded.WithLabelValues(task).Set(0)
		metrics.failures.WithLabelValues(task).Set(0)
		metrics.backlogAvailable.WithLabelValues(task).Set(0)
		metrics.backlogMeasuredAt.WithLabelValues(task).Set(0)
		metrics.backlogAttemptedAt.WithLabelValues(task).Set(0)
		for ctx.Err() == nil {
			started := time.Now()
			metrics.running.WithLabelValues(task).Set(1)
			metrics.nextAttempt.WithLabelValues(task).Set(0)
			pass, cancel := context.WithTimeout(ctx, policy.timeout)
			err := run(pass)
			// A callee that returns nil after its deadline must not clear a fault.
			if err == nil {
				err = pass.Err()
			}
			cancel()
			finished := time.Now()
			metrics.running.WithLabelValues(task).Set(0)
			metrics.duration.WithLabelValues(task).Observe(finished.Sub(started).Seconds())
			if ctx.Err() != nil {
				return
			}
			delay := policy.interval
			if err != nil {
				// Saturate the count at the largest platform int.
				if failures < int(^uint(0)>>1) {
					failures++
				}
				delay = policy.retryDelay(failures)
				metrics.degraded.WithLabelValues(task).Set(1)
				metrics.lastFailure.WithLabelValues(task).Set(float64(finished.UnixNano()) / 1e9)
				metrics.runs.WithLabelValues(task, "error").Inc()
				logger.Error("maintenance.failed", "task", task, "error_code", maintenanceErrorCode(err), "consecutive_failures", failures, "retry_at", finished.Add(delay).UTC())
			} else {
				metrics.degraded.WithLabelValues(task).Set(0)
				metrics.lastSuccess.WithLabelValues(task).Set(float64(finished.UnixNano()) / 1e9)
				metrics.runs.WithLabelValues(task, "success").Inc()
				if failures > 0 {
					logger.Info("maintenance.recovered", "task", task, "prior_failures", failures)
				}
				failures = 0
			}
			metrics.failures.WithLabelValues(task).Set(float64(failures))
			metrics.nextAttempt.WithLabelValues(task).Set(float64(finished.Add(delay).UnixNano()) / 1e9)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return done
}

func maintenanceErrorCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "MAINTENANCE_DEADLINE_EXCEEDED"
	}
	var databaseError interface{ SQLState() string }
	if errors.As(err, &databaseError) {
		state := databaseError.SQLState()
		valid := len(state) == 5
		for _, character := range state {
			valid = valid && (character >= '0' && character <= '9' || character >= 'A' && character <= 'Z')
		}
		if valid {
			return "DATABASE_SQLSTATE_" + state
		}
	}
	return "MAINTENANCE_FAILED"
}

func (m *maintenanceMetrics) invalidateRetentionBacklog() {
	m.backlogAvailable.WithLabelValues("retention").Set(0)
	for _, class := range []string{"observations", "runs", "events"} {
		for _, metric := range []*prom.GaugeVec{m.backlogExpired, m.backlogEligible, m.backlogTruncated, m.backlogOldest} {
			metric.DeleteLabelValues("retention", class)
		}
	}
}

func (r *runtime) observeRetentionBacklog(ctx context.Context) {
	r.maintenance.invalidateRetentionBacklog()
	r.maintenance.backlogAttemptedAt.WithLabelValues("retention").Set(float64(time.Now().UnixNano()) / 1e9)
	measurement, cancel := context.WithTimeout(ctx, retentionBacklogTimeout)
	defer cancel()
	backlog, err := r.retentionStore.MeasureRetentionBacklog(measurement, r.clock.Now(), r.cfg.ObservationRetention, r.cfg.RunRetention)
	if err == nil {
		err = measurement.Err()
	}
	classes := []struct {
		name  string
		value storepg.RetentionBacklogClass
	}{{"observations", backlog.Observations}, {"runs", backlog.Runs}, {"events", backlog.Events}}
	if err == nil {
		if backlog.MeasuredAt.IsZero() {
			err = errRetentionBacklog
		}
		for _, class := range classes {
			v := class.value
			if v.ExpiredRows < 0 || v.EligibleRows < 0 || v.EligibleRows > v.ExpiredRows || (v.ExpiredRows == 0) != v.OldestExpiredAt.IsZero() {
				err = errRetentionBacklog
			}
		}
	}
	if err != nil {
		if ctx.Err() == nil {
			r.maintenance.backlogAttempts.WithLabelValues("retention", "error").Inc()
			r.logger.Error("retention.backlog_measurement_failed", "task", "retention", "error_code", maintenanceErrorCode(err))
		}
		return
	}
	for _, class := range classes {
		v := class.value
		r.maintenance.backlogExpired.WithLabelValues("retention", class.name).Set(float64(v.ExpiredRows))
		r.maintenance.backlogEligible.WithLabelValues("retention", class.name).Set(float64(v.EligibleRows))
		truncated := float64(0)
		if v.Truncated {
			truncated = 1
		}
		r.maintenance.backlogTruncated.WithLabelValues("retention", class.name).Set(truncated)
		oldest := float64(0)
		if !v.OldestExpiredAt.IsZero() {
			oldest = float64(v.OldestExpiredAt.UnixNano()) / 1e9
		}
		r.maintenance.backlogOldest.WithLabelValues("retention", class.name).Set(oldest)
	}
	r.maintenance.backlogMeasuredAt.WithLabelValues("retention").Set(float64(backlog.MeasuredAt.UnixNano()) / 1e9)
	r.maintenance.backlogAvailable.WithLabelValues("retention").Set(1)
	r.maintenance.backlogAttempts.WithLabelValues("retention", "success").Inc()
}

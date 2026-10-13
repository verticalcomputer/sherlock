package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	// durableSchedulerRefreshInterval bounds how often the worker rereads
	// durable schedule state. Scrapes always serve the cached snapshot.
	durableSchedulerRefreshInterval = 15 * time.Second
	// durableSchedulerReadTimeout bounds one snapshot read so a slow
	// database cannot stall the publisher loop or, through it, shutdown.
	durableSchedulerReadTimeout = 2 * time.Second
)

// durableMetricsPublishingEnabled reports whether snapshot publication is
// enrolled. Empty enrollment performs no reads and registers no metrics; the
// worker skips publisher construction entirely.
func durableMetricsPublishingEnabled(keys []domain.ScheduleKey) bool {
	return len(keys) > 0
}

// durableScheduleReader matches
// CollectionStore.ReadDurableScheduleSnapshot so tests can substitute a
// fake. Keys are copied before every call; the reader must not retain or
// mutate them.
type durableScheduleReader interface {
	ReadDurableScheduleSnapshot(context.Context, []domain.ScheduleKey) (domain.DurableSchedulerSnapshot, error)
}

// durableSchedulerPublisher refreshes one cached durable schedule snapshot
// on a fixed cadence. It performs no admission, claims or collection, and a
// slow read blocks only this goroutine rather than the scheduler loop. Reads
// still share the worker database pool and server, so an overloaded database
// can delay other database users; only metric freshness is otherwise spared.
type durableSchedulerPublisher struct {
	reader   durableScheduleReader
	metrics  *DurableSchedulerMetrics
	success  prom.Gauge
	keys     []domain.ScheduleKey
	interval time.Duration
	timeout  time.Duration
	logger   *slog.Logger
}

// newDurableSchedulerPublisher registers the snapshot series and the refresh
// outcome gauge, then returns a publisher that starts no goroutine. The
// enrolled keys are copied; later caller mutation has no effect.
func newDurableSchedulerPublisher(reg prom.Registerer, reader durableScheduleReader, keys []domain.ScheduleKey, interval, timeout time.Duration, logger *slog.Logger) (*durableSchedulerPublisher, error) {
	if reader == nil || logger == nil {
		return nil, fmt.Errorf("durable scheduler publisher dependencies are required")
	}
	if interval <= 0 || timeout <= 0 {
		return nil, fmt.Errorf("durable scheduler publisher interval and timeout must be positive")
	}
	if err := domain.ValidateDurableSchedulerSnapshotKeys(keys); err != nil {
		return nil, err
	}
	metrics, err := NewDurableSchedulerMetrics(reg, keys)
	if err != nil {
		return nil, err
	}
	success := prom.NewGauge(prom.GaugeOpts{
		Name: "sherlock_durable_scheduler_refresh_success",
		Help: "One after the latest successful durable schedule snapshot read and publication; zero before the first success or after a failed refresh. The snapshot timestamp metric still exposes the cached observation time, so staleness stays detectable.",
	})
	if err := reg.Register(success); err != nil {
		return nil, err
	}
	return &durableSchedulerPublisher{
		reader: reader, metrics: metrics, success: success,
		keys:     append([]domain.ScheduleKey(nil), keys...),
		interval: interval, timeout: timeout, logger: logger,
	}, nil
}

// run performs one immediate refresh, then periodic refreshes until ctx ends.
// Exactly one refresh runs at a time in this goroutine; ticker overruns do
// not accumulate extra reads.
func (p *durableSchedulerPublisher) run(ctx context.Context) {
	p.refresh(ctx)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.refresh(ctx)
		}
	}
}

// refresh publishes one snapshot. Read errors, expired read contexts,
// timeouts and invalid snapshots retain the previous valid snapshot with
// its original observation timestamp and mark the refresh failed; a reader
// that answers after expiry is not trusted even with nil error, without a
// helper goroutine. A successful empty snapshot clears prior schedule rows.
// Failures never stop the worker; only fixed sanitized log events are
// emitted, never connection detail, keys or raw errors.
func (p *durableSchedulerPublisher) refresh(parent context.Context) {
	if parent.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, p.timeout)
	defer cancel()
	snapshot, err := p.reader.ReadDurableScheduleSnapshot(ctx, append([]domain.ScheduleKey(nil), p.keys...))
	if err != nil || ctx.Err() != nil {
		p.success.Set(0)
		p.logger.Error("scheduler.snapshot_failed", "code", "DURABLE_SNAPSHOT_FAILED")
		return
	}
	if err := p.metrics.UpdateSnapshot(snapshot); err != nil {
		p.success.Set(0)
		p.logger.Error("scheduler.snapshot_failed", "code", "DURABLE_SNAPSHOT_FAILED")
		return
	}
	p.success.Set(1)
}

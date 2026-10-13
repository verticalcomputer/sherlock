package main

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

type monitoringRefresher interface {
	Refresh(context.Context) error
}

// runMonitoringRefresh advances enrolled rules independently of collection
// arrivals. Refresh owns database time and durable transaction boundaries;
// neither a process heartbeat nor this ticker is a source observation.
// Store errors are retried without terminating collector admission. Callers
// must cancel and join this loop before closing its database pool. Passes are
// serial: a deadline longer than the wake interval cannot overlap evaluations.
func runMonitoringRefresh(ctx context.Context, store monitoringRefresher, logger *slog.Logger, interval, timeout time.Duration) error {
	if store == nil || logger == nil || interval <= 0 || timeout <= 0 {
		return errors.New("invalid monitoring refresh configuration")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		bounded, cancel := context.WithTimeout(ctx, timeout)
		err := store.Refresh(bounded)
		cancel()
		if err != nil && ctx.Err() == nil {
			// PostgreSQL errors can contain private connection or payload data.
			logger.Warn("control.monitoring_refresh_failed")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

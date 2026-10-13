package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func waitMaintenanceValue(t *testing.T, metric prom.Collector, want float64) {
	t.Helper()
	waitMaintenanceMetric(t, metric, func(got float64) bool { return got == want })
}

func waitMaintenanceMetric(t *testing.T, metric prom.Collector, satisfied func(float64) bool) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(time.Millisecond)
	defer poll.Stop()
	for !satisfied(testutil.ToFloat64(metric)) {
		select {
		case <-deadline.C:
			t.Fatalf("maintenance metric did not reach expected state: %v", testutil.ToFloat64(metric))
		case <-poll.C:
		}
	}
}

func joinMaintenance(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("maintenance did not join")
	}
}

func assertUnknownMaintenanceBacklog(t *testing.T, registry *prom.Registry, task string) {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "sherlock_worker_maintenance_backlog_available" {
			continue
		}
		for _, sample := range family.Metric {
			if len(sample.Label) == 1 && sample.Label[0].GetName() == "task" && sample.Label[0].GetValue() == task {
				if sample.GetGauge().GetValue() != 0 {
					t.Fatal("maintenance falsely established remaining backlog")
				}
				return
			}
		}
	}
	t.Fatal("unknown maintenance backlog was omitted from metrics")
}

func TestScheduledLoopCollectsAcrossRepeatedMaintenanceFailures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	metrics := newMaintenanceMetrics(prom.NewRegistry())
	// Short, explicit test policy; production applies a one-second retry floor.
	policy := maintenancePolicy{interval: time.Hour, timeout: time.Second, retryInitial: 30 * time.Millisecond, retryMax: 60 * time.Millisecond}
	attempts := make(chan time.Time, 8)
	var logs bytes.Buffer
	rt, _ := retentionRuntimeFixture(retentionMaintenanceStoreFake{
		apply: func(context.Context) (storepg.RetentionResult, error) {
			attempts <- time.Now()
			return storepg.RetentionResult{}, fmt.Errorf("delete expired runs: %w", &pgconn.PgError{Code: "23503", Message: "private database payload"})
		},
		measure: func(context.Context) (storepg.RetentionBacklog, error) {
			return storepg.RetentionBacklog{MeasuredAt: time.Now()}, nil
		},
	}, &logs)
	rt.maintenance = metrics
	maintenanceDone := startPeriodicMaintenance(ctx, policy, "retention", metrics, rt.logger, rt.applyRetention)
	defer func() { cancel(); joinMaintenance(t, maintenanceDone) }()

	ticks := make(chan time.Time)
	completed := make(chan domain.RunID, 4)
	store := &scheduledJobStoreFake{}
	loopDone := make(chan error, 1)
	go func() {
		turn := 0
		loopDone <- runScheduledLoop(ctx, ticks, nil, func(ctx context.Context) error {
			turn++
			id := fmt.Sprintf("fresh-%d", turn)
			ok, err := processScheduledJob(ctx, store, storepg.ClaimedJob{JobID: id}, "owner", domain.CollectionTask{RunID: domain.RunID(id)}, func(_ context.Context, task domain.CollectionTask) error {
				completed <- task.RunID
				return nil
			})
			if !ok && err == nil {
				return errors.New("collection did not complete")
			}
			return err
		})
	}()
	var previous time.Time
	for attempt := 1; attempt <= 3; attempt++ {
		var started time.Time
		select {
		case started = <-attempts:
		case <-time.After(2 * time.Second):
			t.Fatal("maintenance stopped retrying")
		}
		if attempt > 1 && started.Sub(previous) < policy.retryDelay(attempt-1) {
			t.Fatalf("retry %d ran before backoff elapsed: %s", attempt, started.Sub(previous))
		}
		previous = started
		waitMaintenanceValue(t, metrics.runs.WithLabelValues("retention", "error"), float64(attempt))
		waitMaintenanceValue(t, metrics.degraded.WithLabelValues("retention"), 1)
		select {
		case ticks <- time.Now():
		case err := <-loopDone:
			t.Fatalf("collection loop exited after maintenance failure: %v", err)
		case <-time.After(2 * time.Second):
			t.Fatal("collection loop did not claim work")
		}
		select {
		case got := <-completed:
			if want := domain.RunID(fmt.Sprintf("canonical-fresh-%d", attempt)); got != want {
				t.Fatalf("fresh result=%q, want %q", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("collection did not ingest fresh result")
		}
	}
	cancel()
	joinMaintenance(t, maintenanceDone)
	select {
	case err := <-loopDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("loop shutdown=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("collection loop did not stop")
	}
	if len(store.completed) != 3 {
		t.Fatalf("durable completions=%v", store.completed)
	}
	if testutil.ToFloat64(metrics.lastSuccess.WithLabelValues("retention")) != 0 || testutil.ToFloat64(metrics.lastFailure.WithLabelValues("retention")) <= 0 || testutil.ToFloat64(metrics.nextAttempt.WithLabelValues("retention")) != 0 {
		t.Fatal("failure/shutdown timestamps misrepresent maintenance")
	}
}

func TestMaintenanceFailureRecoversAndDoesNotLeakError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var logs bytes.Buffer
	registry := prom.NewRegistry()
	metrics := newMaintenanceMetrics(registry)
	second := make(chan struct{})
	release := make(chan struct{})
	policy := maintenancePolicy{interval: time.Hour, timeout: time.Second, retryInitial: 10 * time.Millisecond, retryMax: 20 * time.Millisecond}
	count := 0
	done := startPeriodicMaintenance(ctx, policy, "retention", metrics, slog.New(slog.NewJSONHandler(&logs, nil)), func(ctx context.Context) error {
		count++
		if count == 1 {
			return fmt.Errorf("secret/path: %w", &pgconn.PgError{Code: "23503", Message: "private SQL payload"})
		}
		close(second)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	defer func() { cancel(); joinMaintenance(t, done) }()
	select {
	case <-second:
	case <-time.After(2 * time.Second):
		t.Fatal("maintenance did not retry")
	}
	if testutil.ToFloat64(metrics.degraded.WithLabelValues("retention")) != 1 || testutil.ToFloat64(metrics.lastSuccess.WithLabelValues("retention")) != 0 {
		t.Fatal("starting a retry falsely cleared failure")
	}
	assertUnknownMaintenanceBacklog(t, registry, "retention")
	close(release)
	waitMaintenanceValue(t, metrics.runs.WithLabelValues("retention", "success"), 1)
	waitMaintenanceValue(t, metrics.failures.WithLabelValues("retention"), 0)
	cancel()
	joinMaintenance(t, done)
	if testutil.ToFloat64(metrics.degraded.WithLabelValues("retention")) != 0 || testutil.ToFloat64(metrics.lastSuccess.WithLabelValues("retention")) <= 0 {
		t.Fatal("successful recovery was not exposed")
	}
	assertUnknownMaintenanceBacklog(t, registry, "retention")
	if strings.Contains(logs.String(), "secret/path") || strings.Contains(logs.String(), "private SQL") || !strings.Contains(logs.String(), "DATABASE_SQLSTATE_23503") || !strings.Contains(logs.String(), "maintenance.recovered") {
		t.Fatalf("unsafe or missing maintenance logs: %s", logs.String())
	}
}

func TestIndependentMaintenanceTaskContinuesDuringRetentionFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry := prom.NewRegistry()
	metrics := newMaintenanceMetrics(registry)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	policy := maintenancePolicy{interval: time.Hour, timeout: time.Second, retryInitial: time.Hour, retryMax: time.Hour}
	retentionDone := startPeriodicMaintenance(ctx, policy, "retention", metrics, logger, func(context.Context) error {
		return errors.New("retention failed")
	})
	reconciliationDone := startPeriodicMaintenance(ctx, policy, "artifact_reconciliation", metrics, logger, func(context.Context) error { return nil })
	defer func() {
		cancel()
		joinMaintenance(t, retentionDone)
		joinMaintenance(t, reconciliationDone)
	}()
	waitMaintenanceValue(t, metrics.runs.WithLabelValues("retention", "error"), 1)
	waitMaintenanceValue(t, metrics.runs.WithLabelValues("artifact_reconciliation", "success"), 1)
	if testutil.ToFloat64(metrics.degraded.WithLabelValues("retention")) != 1 || testutil.ToFloat64(metrics.degraded.WithLabelValues("artifact_reconciliation")) != 0 {
		t.Fatal("independent task outcomes were conflated")
	}
	assertUnknownMaintenanceBacklog(t, registry, "artifact_reconciliation")
	if testutil.ToFloat64(metrics.backlogMeasuredAt.WithLabelValues("artifact_reconciliation")) != 0 {
		t.Fatal("artifact reconciliation fabricated a retention backlog snapshot")
	}
}

func TestMaintenancePassDeadlineRemainsDegradedAndShutdownJoins(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	metrics := newMaintenanceMetrics(prom.NewRegistry())
	policy := maintenancePolicy{interval: time.Hour, timeout: 20 * time.Millisecond, retryInitial: time.Hour, retryMax: time.Hour}
	done := startPeriodicMaintenance(ctx, policy, "retention", metrics, slog.New(slog.NewJSONHandler(io.Discard, nil)), func(ctx context.Context) error {
		<-ctx.Done()
		return nil // Even a nil result cannot conceal an exceeded deadline.
	})
	waitMaintenanceValue(t, metrics.runs.WithLabelValues("retention", "error"), 1)
	waitMaintenanceValue(t, metrics.degraded.WithLabelValues("retention"), 1)
	waitMaintenanceMetric(t, metrics.nextAttempt.WithLabelValues("retention"), func(got float64) bool { return got > float64(time.Now().Unix()) })
	if testutil.ToFloat64(metrics.lastSuccess.WithLabelValues("retention")) != 0 || testutil.ToFloat64(metrics.nextAttempt.WithLabelValues("retention")) <= float64(time.Now().Unix()) {
		t.Fatal("deadline failure lost retry/last-success state")
	}
	cancel()
	joinMaintenance(t, done)
	if testutil.ToFloat64(metrics.running.WithLabelValues("retention")) != 0 || testutil.ToFloat64(metrics.nextAttempt.WithLabelValues("retention")) != 0 {
		t.Fatal("shutdown left an active pass or retry")
	}
}

func TestMaintenanceRetryPolicyIsBounded(t *testing.T) {
	for _, interval := range []time.Duration{time.Nanosecond, time.Second, time.Minute, 6 * time.Hour} {
		policy := defaultMaintenancePolicy(interval)
		if policy.retryInitial < time.Second || policy.retryMax > 30*time.Minute || policy.timeout != 5*time.Minute {
			t.Fatalf("unsafe retry policy: %+v", policy)
		}
		previous := time.Duration(0)
		for failures := 1; failures < 100; failures++ {
			delay := policy.retryDelay(failures)
			if delay < previous || delay > policy.retryMax {
				t.Fatalf("unsafe backoff at %d: %s", failures, delay)
			}
			previous = delay
		}
		if previous != policy.retryMax {
			t.Fatalf("backoff never capped: %s", previous)
		}
	}
}

func TestMaintenanceErrorCodeRejectsUnsafeSQLState(t *testing.T) {
	if got := maintenanceErrorCode(&pgconn.PgError{Code: "secret/path"}); got != "MAINTENANCE_FAILED" {
		t.Fatalf("unsafe database code=%s", got)
	}
	if got := maintenanceErrorCode(fmt.Errorf("wrapped: %w", context.DeadlineExceeded)); got != "MAINTENANCE_DEADLINE_EXCEEDED" {
		t.Fatalf("deadline code=%s", got)
	}
}

func TestMaintenanceMetricsRegistrationFailureIsFatal(t *testing.T) {
	registry := prom.NewRegistry()
	newMaintenanceMetrics(registry)
	defer func() {
		if recover() == nil {
			t.Fatal("metrics registration failure was swallowed")
		}
	}()
	newMaintenanceMetrics(registry)
}

func TestScheduledLoopPreservesFatalCollectionError(t *testing.T) {
	want := errors.New("collection store unavailable")
	ticks := make(chan time.Time, 1)
	ticks <- time.Now()
	if got := runScheduledLoop(context.Background(), ticks, nil, func(context.Context) error { return want }); !errors.Is(got, want) {
		t.Fatalf("fatal collection error=%v", got)
	}
}

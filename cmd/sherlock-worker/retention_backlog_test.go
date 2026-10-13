package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/verticalcomputer/sherlock/internal/config"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type retentionMaintenanceStoreFake struct {
	apply   func(context.Context) (storepg.RetentionResult, error)
	measure func(context.Context) (storepg.RetentionBacklog, error)
}

func (s retentionMaintenanceStoreFake) ApplyRetention(ctx context.Context, _ time.Time, _, _ time.Duration) (storepg.RetentionResult, error) {
	return s.apply(ctx)
}

func (s retentionMaintenanceStoreFake) MeasureRetentionBacklog(ctx context.Context, _ time.Time, _, _ time.Duration) (storepg.RetentionBacklog, error) {
	return s.measure(ctx)
}

func retentionRuntimeFixture(store retentionMaintenanceStore, output *bytes.Buffer) (*runtime, *prom.Registry) {
	registry := prom.NewRegistry()
	deleted := prom.NewCounterVec(prom.CounterOpts{Name: "test_retention_progress_total", Help: "test"}, []string{"class"})
	registry.MustRegister(deleted)
	return &runtime{
		cfg:            config.Worker{ObservationRetention: 7 * 24 * time.Hour, RunRetention: 30 * 24 * time.Hour},
		retentionStore: store, retention: deleted, maintenance: newMaintenanceMetrics(registry), logger: slog.New(slog.NewJSONHandler(output, nil)),
	}, registry
}

func assertRetentionBacklogCountsAbsent(t *testing.T, registry *prom.Registry) {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		switch family.GetName() {
		case "sherlock_worker_maintenance_backlog_expired_rows_lower_bound", "sherlock_worker_maintenance_backlog_eligible_rows_lower_bound", "sherlock_worker_maintenance_backlog_truncated", "sherlock_worker_maintenance_backlog_oldest_expired_timestamp_seconds":
			if len(family.Metric) > 0 {
				t.Fatalf("unavailable backlog retained misleading count series: %s", family.GetName())
			}
		}
	}
}

func TestRuntimeRetentionObservesTruncatedBacklogAfterCleanupFailure(t *testing.T) {
	want := errors.New("cleanup failure")
	snapshot := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	oldest := snapshot.Add(-60 * 24 * time.Hour)
	var logs bytes.Buffer
	measured := false
	r, _ := retentionRuntimeFixture(retentionMaintenanceStoreFake{
		apply: func(context.Context) (storepg.RetentionResult, error) {
			return storepg.RetentionResult{ObservationsDeleted: 3, RunsDeleted: 2, Batches: 1}, want
		},
		measure: func(ctx context.Context) (storepg.RetentionBacklog, error) {
			measured = true
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > retentionBacklogTimeout {
				t.Fatal("backlog measurement has no short independent deadline")
			}
			return storepg.RetentionBacklog{MeasuredAt: snapshot,
				Observations: storepg.RetentionBacklogClass{ExpiredRows: 1000, EligibleRows: 42, Truncated: true, OldestExpiredAt: oldest},
				Runs:         storepg.RetentionBacklogClass{ExpiredRows: 10, EligibleRows: 2, OldestExpiredAt: oldest.Add(time.Hour)},
			}, nil
		},
	}, &logs)
	if err := r.applyRetention(context.Background()); !errors.Is(err, want) || !measured {
		t.Fatalf("cleanup error/measurement lost: measured=%v err=%v", measured, err)
	}
	for _, sample := range []struct {
		metric prom.Collector
		want   float64
	}{
		{r.retention.WithLabelValues("observations"), 3},
		{r.maintenance.backlogAvailable.WithLabelValues("retention"), 1},
		{r.maintenance.backlogExpired.WithLabelValues("retention", "observations"), 1000},
		{r.maintenance.backlogEligible.WithLabelValues("retention", "observations"), 42},
		{r.maintenance.backlogTruncated.WithLabelValues("retention", "observations"), 1},
		{r.maintenance.backlogOldest.WithLabelValues("retention", "observations"), float64(oldest.Unix())},
		{r.maintenance.backlogExpired.WithLabelValues("retention", "events"), 0},
		{r.maintenance.backlogOldest.WithLabelValues("retention", "events"), 0},
		{r.maintenance.backlogMeasuredAt.WithLabelValues("retention"), float64(snapshot.Unix())},
	} {
		if got := testutil.ToFloat64(sample.metric); got != sample.want {
			t.Fatalf("backlog/progress sample=%v, want %v", got, sample.want)
		}
	}
}

func TestRuntimeRetentionMeasurementFailureInvalidatesCountsPreservesCleanupAndRecovers(t *testing.T) {
	snapshot := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	var logs bytes.Buffer
	turn := 0
	cleanupErr := error(nil)
	r, registry := retentionRuntimeFixture(retentionMaintenanceStoreFake{
		apply: func(context.Context) (storepg.RetentionResult, error) { return storepg.RetentionResult{}, cleanupErr },
		measure: func(context.Context) (storepg.RetentionBacklog, error) {
			turn++
			if turn == 2 || turn == 3 {
				return storepg.RetentionBacklog{}, errors.New("private/database/path secret")
			}
			result := storepg.RetentionBacklog{MeasuredAt: snapshot}
			if turn == 1 {
				result.Runs = storepg.RetentionBacklogClass{ExpiredRows: 9, EligibleRows: 3, OldestExpiredAt: snapshot.Add(-40 * 24 * time.Hour)}
			} else {
				result.MeasuredAt = snapshot.Add(time.Minute)
			}
			return result, nil
		},
	}, &logs)
	if err := r.applyRetention(context.Background()); err != nil {
		t.Fatal(err)
	}
	if testutil.ToFloat64(r.maintenance.backlogAvailable.WithLabelValues("retention")) != 1 {
		t.Fatal("initial measurement unavailable")
	}
	for _, failCleanup := range []bool{false, true} {
		if failCleanup {
			cleanupErr = errors.New("original cleanup error")
		}
		if err := r.applyRetention(context.Background()); !errors.Is(err, cleanupErr) {
			t.Fatalf("measurement overwrote cleanup outcome: got=%v want=%v", err, cleanupErr)
		}
		assertUnknownMaintenanceBacklog(t, registry, "retention")
		assertRetentionBacklogCountsAbsent(t, registry)
		if testutil.ToFloat64(r.maintenance.backlogMeasuredAt.WithLabelValues("retention")) != float64(snapshot.Unix()) {
			t.Fatal("failed measurement overwrote historical snapshot timestamp")
		}
	}
	cleanupErr = nil
	if err := r.applyRetention(context.Background()); err != nil {
		t.Fatal(err)
	}
	if testutil.ToFloat64(r.maintenance.backlogAvailable.WithLabelValues("retention")) != 1 || testutil.ToFloat64(r.maintenance.backlogMeasuredAt.WithLabelValues("retention")) != float64(snapshot.Add(time.Minute).Unix()) || testutil.ToFloat64(r.maintenance.backlogExpired.WithLabelValues("retention", "runs")) != 0 {
		t.Fatal("measured-empty recovery did not restore qualified count series")
	}
	if testutil.ToFloat64(r.maintenance.backlogAttempts.WithLabelValues("retention", "error")) != 2 || testutil.ToFloat64(r.maintenance.backlogAttempts.WithLabelValues("retention", "success")) != 2 || testutil.ToFloat64(r.maintenance.backlogAttemptedAt.WithLabelValues("retention")) <= 0 {
		t.Fatal("measurement attempts were not recorded separately")
	}
	if strings.Contains(logs.String(), "private/database/path") || !strings.Contains(logs.String(), "retention.backlog_measurement_failed") {
		t.Fatalf("unsafe or missing measurement error log: %s", logs.String())
	}
}

func TestRuntimeRetentionMeasurementHonorsPassCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var logs bytes.Buffer
	r, registry := retentionRuntimeFixture(retentionMaintenanceStoreFake{
		apply: func(context.Context) (storepg.RetentionResult, error) { return storepg.RetentionResult{}, nil },
		measure: func(measurement context.Context) (storepg.RetentionBacklog, error) {
			<-measurement.Done()
			return storepg.RetentionBacklog{MeasuredAt: time.Now()}, nil
		},
	}, &logs)
	started := time.Now()
	if err := r.applyRetention(ctx); err != nil {
		t.Fatalf("measurement changed cleanup success: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("measurement extended canceled pass")
	}
	assertUnknownMaintenanceBacklog(t, registry, "retention")
	assertRetentionBacklogCountsAbsent(t, registry)
}

func TestRuntimeRetentionInvalidMeasurementCannotPublishEmptyBacklog(t *testing.T) {
	for _, backlog := range []storepg.RetentionBacklog{
		{},
		{MeasuredAt: time.Now(), Runs: storepg.RetentionBacklogClass{ExpiredRows: 2}},
		{MeasuredAt: time.Now(), Runs: storepg.RetentionBacklogClass{ExpiredRows: -1}},
		{MeasuredAt: time.Now(), Runs: storepg.RetentionBacklogClass{ExpiredRows: 1, EligibleRows: 2, OldestExpiredAt: time.Now()}},
	} {
		var logs bytes.Buffer
		r, registry := retentionRuntimeFixture(retentionMaintenanceStoreFake{
			apply:   func(context.Context) (storepg.RetentionResult, error) { return storepg.RetentionResult{}, nil },
			measure: func(context.Context) (storepg.RetentionBacklog, error) { return backlog, nil },
		}, &logs)
		if err := r.applyRetention(context.Background()); err != nil {
			t.Fatalf("invalid measurement changed cleanup outcome: %v", err)
		}
		assertUnknownMaintenanceBacklog(t, registry, "retention")
		assertRetentionBacklogCountsAbsent(t, registry)
		if testutil.ToFloat64(r.maintenance.backlogAttempts.WithLabelValues("retention", "error")) != 1 {
			t.Fatal("invalid measurement failure was not recorded")
		}
	}
}

//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type controlledRetentionFailureStore struct{ *storepg.CollectionStore }

func (s controlledRetentionFailureStore) ApplyRetention(context.Context, time.Time, time.Duration, time.Duration) (storepg.RetentionResult, error) {
	return storepg.RetentionResult{}, &pgconn.PgError{Code: "23503", Message: "controlled retained-reference failure"}
}

func TestScheduledLoopPersistsFreshCollectionsDuringMaintenanceFailures(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("gp18c-worker-%d", time.Now().UnixNano())
	cluster, source := domain.ClusterID(id), domain.SourceID(id)
	if err := store.EnsureSource(ctx, cluster, id, source, id); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		// Only this unique fixture is removed, after both goroutines joined.
		for _, table := range []string{"current_projections", "observations", "evidence_envelopes", "collection_target_inventory", "cluster_events", "event_streams", "collection_run_jobs"} {
			if _, err := pool.Exec(cleanup, `DELETE FROM `+table+` WHERE cluster_id=$1`, cluster); err != nil {
				t.Errorf("cleanup %s: %v", table, err)
			}
		}
		if _, err := pool.Exec(cleanup, `DELETE FROM collection_events WHERE run_id IN (SELECT run_id FROM collection_runs WHERE cluster_id=$1)`, cluster); err != nil {
			t.Errorf("cleanup collection events: %v", err)
		}
		for _, table := range []string{"collection_runs", "collection_jobs", "sources", "clusters"} {
			if _, err := pool.Exec(cleanup, `DELETE FROM `+table+` WHERE cluster_id=$1`, cluster); err != nil {
				t.Errorf("cleanup %s: %v", table, err)
			}
		}
	}()
	jobID := id + "-job"
	if err := store.EnsureJob(ctx, jobID, cluster, source, domain.QuerySourceHealth, "", time.Second, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	metrics := newMaintenanceMetrics(prom.NewRegistry())
	policy := maintenancePolicy{interval: time.Hour, timeout: time.Second, retryInitial: 50 * time.Millisecond, retryMax: 100 * time.Millisecond}
	var logs bytes.Buffer
	rt, _ := retentionRuntimeFixture(controlledRetentionFailureStore{CollectionStore: store}, &logs)
	rt.maintenance = metrics
	maintenanceDone := startPeriodicMaintenance(ctx, policy, "retention", metrics, rt.logger, rt.applyRetention)
	ticks := make(chan time.Time)
	completed := make(chan domain.RunID)
	loopDone := make(chan error, 1)
	go func() {
		defer close(loopDone)
		turn := 0
		loopDone <- runScheduledLoop(ctx, ticks, nil, func(ctx context.Context) error {
			job, found, err := store.ClaimDueClusterSourceJob(ctx, id, time.Minute, cluster, source)
			if err != nil || !found {
				return fmt.Errorf("claim during maintenance: found=%v: %w", found, err)
			}
			turn++
			task := scheduledCollectionTask(job, config.Worker{QueryTimeout: time.Second, MaxSeries: 10, MaxBytes: 1024}, domain.RunID(fmt.Sprintf("%s-run-%d", id, turn)), time.Now().UTC())
			var collectionErr error
			ok, err := processScheduledJob(ctx, store, job, id, task, func(ctx context.Context, task domain.CollectionTask) error {
				now := time.Now().UTC().Truncate(time.Microsecond)
				inserted, err := store.RecordResult(ctx, domain.CollectionResult{
					Task: task, Status: domain.ResultSucceeded, StartedAt: now, CompletedAt: now,
					Coverage: domain.Coverage{SeriesReturned: 1, BytesRead: 32, Complete: true},
					Observations: []domain.Observation{{
						ID: domain.ObservationID(string(task.RunID) + "-up"), SchemaVersion: 1, ClusterID: cluster, SourceID: source,
						Kind: "source_metric", EntityKey: "source/" + string(source), Metric: "up", Value: 1, Unit: "bool",
						Labels: []domain.Label{{Name: "instance", Value: "fixture:9400"}}, ObservedAt: now, CollectedAt: now, SourceReference: "prometheus:fixture",
					}},
				})
				if err != nil || !inserted {
					collectionErr = fmt.Errorf("persist during maintenance: inserted=%v: %w", inserted, err)
					return collectionErr
				}
				return nil
			})
			if collectionErr != nil {
				return collectionErr
			}
			if err != nil || !ok {
				return fmt.Errorf("complete during maintenance: completed=%v: %w", ok, err)
			}
			select {
			case completed <- task.RunID:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		})
	}()
	defer func() {
		cancel()
		joinMaintenance(t, maintenanceDone)
		select {
		case <-loopDone:
		case <-time.After(2 * time.Second):
			t.Error("collection loop did not join before fixture cleanup")
		}
	}()
	for turn := 1; turn <= 3; turn++ {
		waitMaintenanceMetric(t, metrics.runs.WithLabelValues("retention", "error"), func(got float64) bool { return got >= float64(turn) })
		// Make the next fixture occurrence immediately due without waiting a
		// wall-clock second; this is isolated test state, not production cadence.
		if _, err := pool.Exec(ctx, `UPDATE collection_jobs SET next_run_at=clock_timestamp()-interval '1 second' WHERE job_id=$1`, jobID); err != nil {
			t.Fatal(err)
		}
		select {
		case ticks <- time.Now():
		case err := <-loopDone:
			t.Fatalf("collection stopped: %v", err)
		case <-time.After(2 * time.Second):
			t.Fatal("collection did not start")
		}
		select {
		case <-completed:
		case err := <-loopDone:
			t.Fatalf("collection stopped: %v", err)
		case <-time.After(2 * time.Second):
			t.Fatal("collection did not persist")
		}
		var runs, observations, claims int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM collection_runs WHERE cluster_id=$1 AND status='SUCCEEDED'), (SELECT count(*) FROM observations WHERE cluster_id=$1), (SELECT count(*) FROM collection_run_jobs WHERE cluster_id=$1)`, cluster).Scan(&runs, &observations, &claims); err != nil {
			t.Fatal(err)
		}
		if runs != turn || observations != turn || claims != turn {
			t.Fatalf("fresh persistence during failed maintenance: runs=%d observations=%d claims=%d, want %d", runs, observations, claims, turn)
		}
		var leased bool
		if err := pool.QueryRow(ctx, `SELECT lease_owner IS NOT NULL FROM collection_jobs WHERE job_id=$1`, jobID).Scan(&leased); err != nil || leased {
			t.Fatalf("completed job retained lease: leased=%v err=%v", leased, err)
		}
	}
	waitMaintenanceValue(t, metrics.degraded.WithLabelValues("retention"), 1)
	waitMaintenanceValue(t, metrics.backlogAvailable.WithLabelValues("retention"), 1)
	if testutil.ToFloat64(metrics.backlogMeasuredAt.WithLabelValues("retention")) <= 0 {
		t.Fatal("real backlog snapshot was not published during failed cleanup")
	}
}

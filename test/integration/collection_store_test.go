//go:build integration

package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestCollectionPersistenceIsIdempotentAndPreservesProjectionOnFailure(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("integration-cluster-" + suffix)
	sourceID := domain.SourceID("integration-source-" + suffix)
	if err := store.EnsureSource(ctx, clusterID, "Integration cluster", sourceID, "Integration Prometheus"); err != nil {
		t.Fatal(err)
	}

	observed := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	task := domain.CollectionTask{RunID: "run-" + domain.RunID(suffix), ClusterID: clusterID, SourceID: sourceID, Query: domain.QueryGPUUtilization, ScheduledFor: observed, Deadline: observed.Add(10 * time.Second), MaxSeries: 10_000, MaxBytes: 10 << 20, IdempotencyKey: "integration/" + suffix}
	observation := domain.Observation{ID: "observation-" + domain.ObservationID(suffix), SchemaVersion: 1, ClusterID: clusterID, SourceID: sourceID, Kind: "gpu_metric", EntityKey: "node/comp001/gpu/0", Metric: "DCGM_FI_DEV_GPU_UTIL", Labels: []domain.Label{{Name: "gpu", Value: "0"}}, Value: 42.5, Unit: "percent", ObservedAt: observed, CollectedAt: observed.Add(time.Second), SourceReference: "prometheus:dcgm_gpu_utilization"}
	result := domain.CollectionResult{Task: task, Status: domain.ResultSucceeded, StartedAt: observed, CompletedAt: observed.Add(time.Second), Coverage: domain.Coverage{SeriesReturned: 1, BytesRead: 200, Complete: true}, Observations: []domain.Observation{observation}}
	inserted, err := store.RecordResult(ctx, result)
	if err != nil || !inserted {
		t.Fatalf("first result inserted=%v err=%v", inserted, err)
	}
	result.Task.RunID = "duplicate-run-" + domain.RunID(suffix)
	inserted, err = store.RecordResult(ctx, result)
	if err != nil || inserted {
		t.Fatalf("duplicate result inserted=%v err=%v", inserted, err)
	}

	state, err := store.Projection(ctx, clusterID, sourceID, observation.EntityKey, observation.Metric, observed.Add(30*time.Second), 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if state.ObservationID != observation.ID || state.Freshness != domain.FreshnessFresh || state.Availability != "AVAILABLE" {
		t.Fatalf("unexpected projection: %+v", state)
	}

	failureTask := task
	failureTask.RunID = "failure-run-" + domain.RunID(suffix)
	failureTask.IdempotencyKey = "integration/failure/" + suffix
	failure := domain.CollectionResult{Task: failureTask, Status: domain.ResultFailed, StartedAt: observed.Add(time.Minute), CompletedAt: observed.Add(time.Minute + time.Second), Coverage: domain.Coverage{Complete: false}, Failures: []domain.CollectionFailure{{Code: domain.FailureSourceUnavailable, Retryable: true, Message: "Prometheus source unavailable"}}}
	if inserted, err := store.RecordResult(ctx, failure); err != nil || !inserted {
		t.Fatalf("failure inserted=%v err=%v", inserted, err)
	}
	state, err = store.Projection(ctx, clusterID, sourceID, observation.EntityKey, observation.Metric, observed.Add(62*time.Second), 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if state.ObservationID != observation.ID || state.Freshness != domain.FreshnessStale || state.Availability != "UNAVAILABLE" {
		t.Fatalf("failure incorrectly changed projection: %+v", state)
	}
}

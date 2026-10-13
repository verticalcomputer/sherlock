//go:build integration

package postgres_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestCollectionEvidenceUsesDurableGPUInventoryForCompleteness(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("coverage-cluster-" + suffix)
	sourceID := domain.SourceID("coverage-source-" + suffix)
	store, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSource(ctx, clusterID, "Coverage cluster", sourceID, "Coverage source"); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	identity := coverageResult(suffix+"-identity", clusterID, sourceID, domain.QueryGPUIdentity, base,
		coverageObservation("identity-1-"+suffix, clusterID, sourceID, "gpu_identity", "DCGM_FI_DEV_GPU_UTIL", "node-1", "GPU-1", base),
		coverageObservation("identity-2-"+suffix, clusterID, sourceID, "gpu_identity", "DCGM_FI_DEV_GPU_UTIL", "node-2", "GPU-2", base))
	if inserted, err := store.RecordResult(ctx, identity); err != nil || !inserted {
		t.Fatalf("record identity inserted=%t err=%v", inserted, err)
	}
	partial := coverageResult(suffix+"-partial", clusterID, sourceID, domain.QueryGPUUtilization, base.Add(10*time.Second),
		coverageObservation("partial-1-"+suffix, clusterID, sourceID, "gpu_utilization", "DCGM_FI_DEV_GPU_UTIL", "node-1", "GPU-1", base.Add(10*time.Second)))
	if inserted, err := store.RecordResult(ctx, partial); err != nil || !inserted {
		t.Fatalf("record partial inserted=%t err=%v", inserted, err)
	}
	var status string
	var expectedSeries int
	var expectedJSON, coveredJSON string
	if err := pool.QueryRow(ctx, `SELECT e.status,r.series_expected,e.coverage_expected::text,e.coverage_covered::text FROM evidence_envelopes e JOIN collection_runs r USING (run_id) WHERE e.run_id=$1`, partial.Task.RunID).Scan(&status, &expectedSeries, &expectedJSON, &coveredJSON); err != nil {
		t.Fatal(err)
	}
	if status != "PARTIAL" || expectedSeries != 2 || !strings.Contains(expectedJSON, "GPU-2") || strings.Contains(coveredJSON, "GPU-2") {
		t.Fatalf("partial status=%s expected_series=%d expected=%s covered=%s", status, expectedSeries, expectedJSON, coveredJSON)
	}
	complete := coverageResult(suffix+"-complete", clusterID, sourceID, domain.QueryGPUUtilization, base.Add(20*time.Second),
		coverageObservation("complete-1-"+suffix, clusterID, sourceID, "gpu_utilization", "DCGM_FI_DEV_GPU_UTIL", "node-1", "GPU-1", base.Add(20*time.Second)),
		coverageObservation("complete-2-"+suffix, clusterID, sourceID, "gpu_utilization", "DCGM_FI_DEV_GPU_UTIL", "node-2", "GPU-2", base.Add(20*time.Second)))
	if inserted, err := store.RecordResult(ctx, complete); err != nil || !inserted {
		t.Fatalf("record complete inserted=%t err=%v", inserted, err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM evidence_envelopes WHERE run_id=$1`, complete.Task.RunID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "COMPLETE" {
		t.Fatalf("complete evidence status=%s", status)
	}
}

func coverageResult(id string, clusterID domain.ClusterID, sourceID domain.SourceID, query domain.QueryKind, observed time.Time, observations ...domain.Observation) domain.CollectionResult {
	return domain.CollectionResult{
		Task:   domain.CollectionTask{RunID: domain.RunID("run-" + id), ClusterID: clusterID, SourceID: sourceID, Query: query, ScheduledFor: observed, Deadline: observed.Add(time.Minute), MaxSeries: 100, MaxBytes: 1 << 20, IdempotencyKey: "coverage/" + id},
		Status: domain.ResultSucceeded, StartedAt: observed, CompletedAt: observed.Add(time.Second),
		Coverage: domain.Coverage{SeriesReturned: len(observations), BytesRead: 100, Complete: true}, Observations: observations,
	}
}

func coverageObservation(id string, clusterID domain.ClusterID, sourceID domain.SourceID, kind, metric, node, gpu string, observed time.Time) domain.Observation {
	return domain.Observation{
		ID: domain.ObservationID(id), SchemaVersion: 1, ClusterID: clusterID, SourceID: sourceID,
		Kind: kind, EntityKey: "node/" + node + "/gpu/" + gpu, Metric: metric,
		Labels: []domain.Label{{Name: "Hostname", Value: node}, {Name: "UUID", Value: gpu}},
		Value:  1, Unit: "count", ObservedAt: observed, CollectedAt: observed.Add(time.Second), SourceReference: "prometheus:" + string(queryForMetric(kind)),
	}
}

func queryForMetric(kind string) domain.QueryKind {
	if kind == "gpu_identity" {
		return domain.QueryGPUIdentity
	}
	return domain.QueryGPUUtilization
}

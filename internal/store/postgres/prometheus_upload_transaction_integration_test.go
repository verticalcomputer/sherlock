//go:build integration

package postgres_test

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestScheduledUploadPreservesReplayHealthAndAtomicity(t *testing.T) {
	pool := durableTestDatabase(t)
	ctx := t.Context()
	store, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	const cluster, source = "upload-cluster", "upload-source"
	if err := store.EnsureSource(ctx, cluster, cluster, source, source); err != nil {
		t.Fatal(err)
	}
	slot := time.Now().UTC().Truncate(time.Minute).Add(-3 * time.Minute)
	inventory, err := storepg.NewGoodputStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	earlier := slot.Add(-time.Hour)
	if _, err := inventory.RecordExpectedInventoryRevision(ctx, domain.InventoryRevision{
		ID: "upload-inventory", SchemaVersion: domain.InventoryContractSchemaVersion,
		ClusterID: cluster, SourceID: source, SourceAt: earlier, EffectiveAt: earlier, ObservedAt: earlier,
		Entities: []domain.EntityIdentity{
			{ClusterID: cluster, Kind: domain.EntityNode, NodeID: "node-a"},
			{ClusterID: cluster, Kind: domain.EntityGPU, NodeID: "node-a", PhysicalGPUUUID: "GPU-a"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	reportAt := func(at time.Time) domain.PrometheusReport {
		sample := coverageObservation("upload-sample", cluster, source, "gpu_utilization", "DCGM_FI_DEV_GPU_UTIL", "node-a", "GPU-a", at)
		sample.Unit = "percent"
		result := coverageResult("upload", cluster, source, domain.QueryGPUUtilization, at, sample)
		result.Task = domain.PrometheusUploadTask(cluster, source, domain.QueryGPUUtilization, at)
		return domain.PrometheusReport{Version: domain.PrometheusUploadVersion, Result: result}
	}
	record := func(report domain.PrometheusReport, want bool) {
		t.Helper()
		if err := report.Validate(cluster, source, slot.Add(3*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if accepted, err := store.RecordPrometheusReport(ctx, report); accepted != want || err != nil {
			t.Fatalf("accepted=%t want=%t err=%v", accepted, want, err)
		}
	}

	current := reportAt(slot)
	record(current, true)
	record(current, true)
	changed := reportAt(slot)
	changed.Result.Observations[0].Value++
	record(changed, false)

	older := reportAt(slot.Add(-time.Minute))
	older.Result.Status = domain.ResultFailed
	older.Result.Observations = nil
	older.Result.Coverage = domain.Coverage{}
	older.Result.Failures = []domain.CollectionFailure{{Code: domain.FailureSourceUnavailable, Message: "source unavailable"}}
	record(older, true)

	// Fail after the observation, projection, evidence, source update, and
	// collection event have been written.
	if _, err := pool.Exec(ctx, `ALTER TABLE cluster_events ADD CONSTRAINT fixture_reject_source_event CHECK (event_id <> 6)`); err != nil {
		t.Fatal(err)
	}
	next := reportAt(slot.Add(time.Minute))
	_, err = store.RecordPrometheusReport(ctx, next)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.ConstraintName != "fixture_reject_source_event" {
		t.Fatalf("expected late event failure, got %v", err)
	}

	var runs, evidence, observations, completionEvents, streamEvents int
	var projectionAt, attemptAt, successAt time.Time
	var health string
	var eventMatchesHealth bool
	err = pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM collection_runs),
		(SELECT count(*) FROM evidence_envelopes WHERE run_id=$3),
		(SELECT count(*) FROM observations),
		(SELECT count(*) FROM collection_events),
		(SELECT count(*) FROM cluster_events),
		(SELECT observed_at FROM current_projections),
		s.last_attempt_at, s.last_success_at, s.availability,
		(SELECT payload->>'availability'=s.availability
			AND (payload->>'last_attempt_at')::timestamptz=s.last_attempt_at
			AND (payload->>'last_success_at')::timestamptz=s.last_success_at
			AND NOT (payload ? 'last_failure_code')
			FROM cluster_events WHERE cluster_id=$1 AND event_id=4 AND event_type='source.updated')
		FROM sources s WHERE s.cluster_id=$1 AND s.source_id=$2`, cluster, source, current.Result.Task.RunID).
		Scan(&runs, &evidence, &observations, &completionEvents, &streamEvents, &projectionAt, &attemptAt, &successAt, &health, &eventMatchesHealth)
	if err != nil {
		t.Fatal(err)
	}
	if runs != 2 || evidence != 1 || observations != 1 || completionEvents != 2 || streamEvents != 4 || !projectionAt.Equal(slot) {
		t.Fatalf("writes after replay and rollback: runs=%d evidence=%d observations=%d completion events=%d stream events=%d projection=%v",
			runs, evidence, observations, completionEvents, streamEvents, projectionAt)
	}
	if !attemptAt.Equal(current.Result.CompletedAt) || !successAt.Equal(current.Result.CompletedAt) || health != "AVAILABLE" || !eventMatchesHealth {
		t.Fatalf("health regressed: attempt=%v success=%v health=%s event matches=%t", attemptAt, successAt, health, eventMatchesHealth)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE cluster_events DROP CONSTRAINT fixture_reject_source_event`); err != nil {
		t.Fatal(err)
	}
	record(next, true)
}

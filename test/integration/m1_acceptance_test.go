//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestFailureNoDataAndPartialStatesRemainDistinct(t *testing.T) {
	ctx, pool, store := integrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	tests := []struct {
		name             string
		status           domain.ResultStatus
		failure          *domain.CollectionFailure
		observation      bool
		wantAvailability string
		wantFreshness    domain.Freshness
	}{
		{name: "no-data", status: domain.ResultNoData, wantAvailability: "AVAILABLE", wantFreshness: domain.FreshnessFresh},
		{name: "partial", status: domain.ResultPartial, failure: &domain.CollectionFailure{Code: domain.FailurePartialData, Message: "Prometheus returned a partial result"}, observation: true, wantAvailability: "AVAILABLE", wantFreshness: domain.FreshnessFresh},
		{name: "malformed", status: domain.ResultFailed, failure: &domain.CollectionFailure{Code: domain.FailureMalformedResponse, Message: "Prometheus returned malformed JSON"}, wantAvailability: "AVAILABLE", wantFreshness: domain.FreshnessUnknown},
		{name: "timeout", status: domain.ResultFailed, failure: &domain.CollectionFailure{Code: domain.FailureDeadlineExceeded, Retryable: true, Message: "Prometheus query timed out"}, wantAvailability: "UNAVAILABLE", wantFreshness: domain.FreshnessUnknown},
		{name: "source-down", status: domain.ResultFailed, failure: &domain.CollectionFailure{Code: domain.FailureSourceUnavailable, Retryable: true, Message: "Prometheus source unavailable"}, wantAvailability: "UNAVAILABLE", wantFreshness: domain.FreshnessUnknown},
	}
	for index, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suffix := uniqueSuffix(tt.name)
			clusterID := domain.ClusterID("cluster-" + suffix)
			sourceID := domain.SourceID("source-" + suffix)
			if err := store.EnsureSource(ctx, clusterID, "Acceptance cluster", sourceID, "Acceptance Prometheus"); err != nil {
				t.Fatal(err)
			}
			result := acceptanceResult(suffix, clusterID, sourceID, now.Add(time.Duration(index)*time.Second), tt.status, tt.failure, tt.observation)
			if inserted, err := store.RecordResult(ctx, result); err != nil || !inserted {
				t.Fatalf("inserted=%v err=%v", inserted, err)
			}
			state, err := store.SourceState(ctx, sourceID, result.CompletedAt.Add(time.Second), 60*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if state.Availability != tt.wantAvailability || state.Freshness != tt.wantFreshness {
				t.Fatalf("state=%+v want availability=%s freshness=%s", state, tt.wantAvailability, tt.wantFreshness)
			}
			var storedStatus domain.ResultStatus
			var storedFailure *string
			if err := pool.QueryRow(ctx, `
				SELECT r.status, f.code FROM collection_runs r
				LEFT JOIN collection_failures f USING (run_id) WHERE r.run_id=$1`, result.Task.RunID).Scan(&storedStatus, &storedFailure); err != nil {
				t.Fatal(err)
			}
			if storedStatus != tt.status {
				t.Fatalf("stored status=%s want=%s", storedStatus, tt.status)
			}
			if tt.failure == nil && storedFailure != nil {
				t.Fatalf("unexpected stored failure %q", *storedFailure)
			}
			if tt.failure != nil && (storedFailure == nil || *storedFailure != string(tt.failure.Code)) {
				t.Fatalf("stored failure=%v want=%s", storedFailure, tt.failure.Code)
			}
		})
	}
}

func TestSourceRecoveryAndFreshnessTransition(t *testing.T) {
	ctx, _, store := integrationStore(t)
	suffix := uniqueSuffix("recovery")
	clusterID := domain.ClusterID("cluster-" + suffix)
	sourceID := domain.SourceID("source-" + suffix)
	if err := store.EnsureSource(ctx, clusterID, "Recovery cluster", sourceID, "Recovery Prometheus"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	failure := domain.CollectionFailure{Code: domain.FailureSourceUnavailable, Retryable: true, Message: "Prometheus source unavailable"}
	failed := acceptanceResult(suffix+"-failed", clusterID, sourceID, now, domain.ResultFailed, &failure, false)
	if _, err := store.RecordResult(ctx, failed); err != nil {
		t.Fatal(err)
	}
	state, err := store.SourceState(ctx, sourceID, now.Add(time.Second), 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if state.Availability != "UNAVAILABLE" || state.Freshness != domain.FreshnessUnknown {
		t.Fatalf("failed state=%+v", state)
	}

	recovered := acceptanceResult(suffix+"-recovered", clusterID, sourceID, now.Add(10*time.Second), domain.ResultSucceeded, nil, true)
	if _, err := store.RecordResult(ctx, recovered); err != nil {
		t.Fatal(err)
	}
	state, err = store.SourceState(ctx, sourceID, recovered.CompletedAt.Add(60*time.Second), 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if state.Availability != "AVAILABLE" || state.Freshness != domain.FreshnessFresh {
		t.Fatalf("recovered state=%+v", state)
	}
	state, err = store.SourceState(ctx, sourceID, recovered.CompletedAt.Add(60*time.Second+time.Nanosecond), 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if state.Freshness != domain.FreshnessStale {
		t.Fatalf("stale state=%+v", state)
	}
}

func TestLeasedJobSurvivesWorkerRestart(t *testing.T) {
	ctx, pool, store := integrationStore(t)
	suffix := uniqueSuffix("restart")
	clusterID := domain.ClusterID("cluster-" + suffix)
	sourceID := domain.SourceID("source-" + suffix)
	jobID := "job-" + suffix
	if err := store.EnsureSource(ctx, clusterID, "Restart cluster", sourceID, "Restart Prometheus"); err != nil {
		t.Fatal(err)
	}
	firstRun := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	if err := store.EnsureJob(ctx, jobID, clusterID, sourceID, domain.QueryGPUUtilization, "", 30*time.Second, firstRun); err != nil {
		t.Fatal(err)
	}
	claimed, found, err := store.ClaimDueSourceJob(ctx, "worker-before-restart", 30*time.Second, sourceID)
	if err != nil || !found || claimed.JobID != jobID {
		t.Fatalf("first claim=%+v found=%v err=%v", claimed, found, err)
	}
	if _, found, err := store.ClaimDueSourceJob(ctx, "other-worker", time.Second, sourceID); err != nil || found {
		t.Fatalf("live lease was reclaimed found=%v err=%v", found, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE collection_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE job_id=$1`, jobID); err != nil {
		t.Fatal(err)
	}

	restartedStore, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	reclaimed, found, err := restartedStore.ClaimDueSourceJob(ctx, "worker-after-restart", 30*time.Second, sourceID)
	if err != nil || !found || reclaimed.JobID != jobID || !reclaimed.ScheduledFor.Equal(firstRun) {
		t.Fatalf("reclaim=%+v found=%v err=%v", reclaimed, found, err)
	}
	recorded := acceptanceResult(suffix+"-recorded", clusterID, sourceID, time.Now().UTC(), domain.ResultSucceeded, nil, true)
	recorded.Task.ScheduledFor = reclaimed.ScheduledFor
	recorded.Task.IdempotencyKey = reclaimed.JobID + "/" + reclaimed.ScheduledFor.Format(time.RFC3339Nano)
	if inserted, err := restartedStore.RecordResult(ctx, recorded); err != nil || !inserted {
		t.Fatalf("record before second restart inserted=%v err=%v", inserted, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE collection_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE job_id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	afterResultStore, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	afterResult, found, err := afterResultStore.ClaimDueSourceJob(ctx, "worker-after-result", 30*time.Second, sourceID)
	if err != nil || !found {
		t.Fatalf("claim after recorded result found=%v err=%v", found, err)
	}
	duplicate := recorded
	duplicate.Task.RunID = domain.RunID("duplicate-" + suffix)
	duplicate.Observations[0].ID = domain.ObservationID("duplicate-observation-" + suffix)
	if inserted, err := afterResultStore.RecordResult(ctx, duplicate); err != nil || inserted {
		t.Fatalf("duplicate after restart inserted=%v err=%v", inserted, err)
	}
	if err := afterResultStore.CompleteJob(ctx, afterResult, "worker-after-result"); err != nil {
		t.Fatal(err)
	}
	var nextRun time.Time
	var leaseOwner *string
	if err := pool.QueryRow(ctx, `SELECT next_run_at, lease_owner FROM collection_jobs WHERE job_id=$1`, jobID).Scan(&nextRun, &leaseOwner); err != nil {
		t.Fatal(err)
	}
	var future, aligned bool
	if err := pool.QueryRow(ctx, `SELECT next_run_at>clock_timestamp(),mod(extract(epoch FROM(next_run_at-$2::timestamptz)),30)=0 FROM collection_jobs WHERE job_id=$1`, jobID, firstRun).Scan(&future, &aligned); err != nil {
		t.Fatal(err)
	}
	if !future || !aligned || leaseOwner != nil {
		t.Fatalf("next_run=%s future=%t aligned=%t lease_owner=%v", nextRun, future, aligned, leaseOwner)
	}
	var observationCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM observations WHERE run_id=$1`, recorded.Task.RunID).Scan(&observationCount); err != nil {
		t.Fatal(err)
	}
	if observationCount != 1 {
		t.Fatalf("observation count=%d want=1", observationCount)
	}
}

func TestRangeProvenanceAndRetention(t *testing.T) {
	// Retention counts are database-wide, so this test owns a private
	// database; exact-count assertions would otherwise observe rows left by
	// other test packages sharing the parent database.
	ctx, pool := isolatedDatabase(t)
	store, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	suffix := uniqueSuffix("retention")
	clusterID := domain.ClusterID("cluster-" + suffix)
	sourceID := domain.SourceID("source-" + suffix)
	if err := store.EnsureSource(ctx, clusterID, "Retention cluster", sourceID, "Retention Prometheus"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	old := acceptanceResult(suffix+"-old", clusterID, sourceID, now.Add(-40*24*time.Hour), domain.ResultSucceeded, nil, true)
	old.Observations[0].EntityKey = "node/comp001/gpu/0"
	old.Task.Range = &domain.CollectionRange{Start: old.Task.ScheduledFor.Add(-time.Minute), End: old.Task.ScheduledFor, Step: 30 * time.Second}
	if _, err := store.RecordResult(ctx, old); err != nil {
		t.Fatal(err)
	}
	current := acceptanceResult(suffix+"-current", clusterID, sourceID, now, domain.ResultSucceeded, nil, true)
	current.Observations[0].EntityKey = old.Observations[0].EntityKey
	if _, err := store.RecordResult(ctx, current); err != nil {
		t.Fatal(err)
	}
	preserved := acceptanceResult(suffix+"-preserved", clusterID, sourceID, now.Add(-40*24*time.Hour), domain.ResultSucceeded, nil, true)
	preserved.Observations[0].EntityKey = "node/comp002/gpu/0"
	if _, err := store.RecordResult(ctx, preserved); err != nil {
		t.Fatal(err)
	}
	expiredFailure := domain.CollectionFailure{Code: domain.FailureSourceUnavailable, Message: "Prometheus source unavailable"}
	expiredRun := acceptanceResult(suffix+"-expired-run", clusterID, sourceID, now.Add(-40*24*time.Hour), domain.ResultFailed, &expiredFailure, false)
	if _, err := store.RecordResult(ctx, expiredRun); err != nil {
		t.Fatal(err)
	}
	// Cross the production retention batch boundary. These old observations
	// share the old run but are not current projections.
	const extraExpiredObservations = 1001
	if _, err := pool.Exec(ctx, `INSERT INTO observations
		(observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,observed_at,collected_at,source_reference,sample_fingerprint)
		SELECT 'retention-bulk-' || $1 || '-' || g::text, o.run_id,o.cluster_id,o.source_id,o.schema_version,o.kind,
		       o.entity_key || '/bulk/' || g::text,o.metric,o.labels,o.value,o.unit,o.observed_at,o.collected_at,o.source_reference,
		       decode(md5('retention-bulk-' || $1 || '-' || g::text),'hex')
		FROM observations o CROSS JOIN generate_series(1,$3::int) g WHERE o.observation_id=$2`, suffix, old.Observations[0].ID, extraExpiredObservations); err != nil {
		t.Fatal(err)
	}

	var rangeStart, rangeEnd time.Time
	var rangeStep float64
	if err := pool.QueryRow(ctx, `SELECT range_start, range_end, range_step_seconds FROM collection_runs WHERE run_id=$1`, old.Task.RunID).Scan(&rangeStart, &rangeEnd, &rangeStep); err != nil {
		t.Fatal(err)
	}
	if !rangeStart.Equal(old.Task.Range.Start) || !rangeEnd.Equal(old.Task.Range.End) || rangeStep != 30 {
		t.Fatalf("range provenance start=%s end=%s step=%f", rangeStart, rangeEnd, rangeStep)
	}
	var oldEvidenceID string
	if err := pool.QueryRow(ctx, `SELECT evidence_id FROM evidence_envelopes WHERE run_id=$1`, old.Task.RunID).Scan(&oldEvidenceID); err != nil {
		t.Fatalf("load retained evidence for expired run: %v", err)
	}

	retained, err := store.ApplyRetention(ctx, now, 7*24*time.Hour, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if retained.ObservationsDeleted != 1+extraExpiredObservations || retained.RunsDeleted != 2 || retained.Batches != 2 {
		t.Fatalf("retention result=%+v", retained)
	}
	assertRowExists(t, ctx, pool, `SELECT EXISTS(SELECT 1 FROM observations WHERE observation_id=$1)`, old.Observations[0].ID, false)
	assertRowExists(t, ctx, pool, `SELECT EXISTS(SELECT 1 FROM observations WHERE observation_id=$1)`, preserved.Observations[0].ID, true)
	assertRowExists(t, ctx, pool, `SELECT EXISTS(SELECT 1 FROM collection_runs WHERE run_id=$1)`, expiredRun.Task.RunID, false)
	assertRowExists(t, ctx, pool, `SELECT EXISTS(SELECT 1 FROM evidence_envelopes WHERE evidence_id=$1 AND run_id IS NULL)`, oldEvidenceID, true)
}

func integrationStore(t *testing.T) (context.Context, *pgxpool.Pool, *storepg.CollectionStore) {
	t.Helper()
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, pool, store
}

func uniqueSuffix(label string) string {
	return fmt.Sprintf("%s-%d", label, time.Now().UnixNano())
}

func acceptanceResult(suffix string, clusterID domain.ClusterID, sourceID domain.SourceID, completedAt time.Time, status domain.ResultStatus, failure *domain.CollectionFailure, withObservation bool) domain.CollectionResult {
	task := domain.CollectionTask{RunID: domain.RunID("run-" + suffix), ClusterID: clusterID, SourceID: sourceID, Query: domain.QueryGPUUtilization, ScheduledFor: completedAt.Add(-time.Second), Deadline: completedAt.Add(9 * time.Second), MaxSeries: 10_000, MaxBytes: 10 << 20, IdempotencyKey: "acceptance/" + suffix}
	result := domain.CollectionResult{Task: task, Status: status, StartedAt: completedAt.Add(-time.Second), CompletedAt: completedAt, Coverage: domain.Coverage{Complete: status == domain.ResultSucceeded || status == domain.ResultNoData}}
	if failure != nil {
		result.Failures = []domain.CollectionFailure{*failure}
	}
	if withObservation {
		result.Coverage.SeriesReturned = 1
		result.Observations = []domain.Observation{{ID: domain.ObservationID("observation-" + suffix), SchemaVersion: 1, ClusterID: clusterID, SourceID: sourceID, Kind: "gpu_metric", EntityKey: "node/comp001/gpu/0-" + suffix, Metric: "DCGM_FI_DEV_GPU_UTIL", Labels: []domain.Label{{Name: "gpu", Value: "0"}}, Value: 42.5, Unit: "percent", ObservedAt: completedAt.Add(-time.Second), CollectedAt: completedAt, SourceReference: "prometheus:dcgm_gpu_utilization"}}
	}
	return result
}

func assertRowExists(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, argument any, want bool) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(ctx, query, argument).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("row existence=%v want=%v for %v", got, want, argument)
	}
}

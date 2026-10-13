//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type retentionFixture struct {
	pool  *pgxpool.Pool
	store *storepg.CollectionStore
	now   time.Time
}

func newRetentionFixture(t *testing.T) retentionFixture {
	t.Helper()
	p := durableTestDatabase(t)
	s, err := storepg.NewCollectionStore(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureSource(context.Background(), "retention-cluster", "Retention", "retention-source", "Retention"); err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := p.QueryRow(context.Background(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	return retentionFixture{pool: p, store: s, now: now}
}

func (f retentionFixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func (f retentionFixture) run(t *testing.T, id string, at time.Time) {
	t.Helper()
	f.exec(t, `INSERT INTO collection_runs
		(run_id,cluster_id,source_id,query_kind,idempotency_key,status,scheduled_for,started_at,completed_at,series_returned,bytes_read,coverage_complete)
		VALUES ($1,'retention-cluster','retention-source','gpu.utilization',$1,'FAILED',$2,$2,$2,0,0,false)`, id, at)
	f.exec(t, `INSERT INTO collection_events (run_id,event_type) VALUES ($1,'collection.updated')`, id)
}

func (f retentionFixture) observation(t *testing.T, id, run string, at time.Time) {
	t.Helper()
	f.exec(t, `INSERT INTO observations
		(observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,observed_at,collected_at,source_reference,sample_fingerprint)
		VALUES ($1,$2,'retention-cluster','retention-source',1,'gpu_metric',$1,'temperature','[]',50,'celsius',$3,$3,'fixture',decode(md5($1),'hex'))`, id, run, at)
}

func (f retentionFixture) count(t *testing.T, table string, want int) {
	t.Helper()
	var got int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM `+pgx.Identifier{table}.Sanitize()).Scan(&got); err != nil || got != want {
		t.Fatalf("%s count=%d want=%d err=%v", table, got, want, err)
	}
}

func (f retentionFixture) apply(t *testing.T) storepg.RetentionResult {
	t.Helper()
	result, err := f.store.ApplyRetention(context.Background(), f.now, 7*24*time.Hour, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRetentionForeignKeyGraph(t *testing.T) {
	f := newRetentionFixture(t)
	rows, err := f.pool.Query(context.Background(), `SELECT confrelid::regclass::text,conrelid::regclass::text,confdeltype::text
		FROM pg_constraint WHERE contype='f' AND confrelid IN ('collection_runs'::regclass,'observations'::regclass,'collection_events'::regclass)
		ORDER BY 1,2`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var owner, child, behavior string
		if err := rows.Scan(&owner, &child, &behavior); err != nil {
			t.Fatal(err)
		}
		got = append(got, owner+":"+child+":"+behavior)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"collection_runs:collection_events:a", "collection_runs:collection_failures:c",
		"collection_runs:collector_result_ingestions:a", "collection_runs:collector_typed_result_ingestions:a",
		"collection_runs:evidence_envelopes:n", "collection_runs:observations:a",
		"observations:current_projections:a", "observations:goodput_metric_nodes:a",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("retention FK graph changed; review its owners before changing cleanup:\n%s", strings.Join(got, "\n"))
	}
}

func TestRetentionPreservesLegacyReceiptAndReplay(t *testing.T) {
	f := newRetentionFixture(t)
	old := f.now.Add(-40 * 24 * time.Hour)
	f.run(t, "receipt-run", old)
	f.run(t, "unreferenced-run", old)
	f.observation(t, "expired-observation", "receipt-run", f.now.Add(-8*24*time.Hour))
	token := strings.Repeat("a", 32)
	digest, tokenDigest := sha256.Sum256([]byte("immutable")), sha256.Sum256([]byte(token))
	f.exec(t, `INSERT INTO collectors (collector_id,cluster_id,display_name,version,build_commit,protocol_min,protocol_max,operating_system,architecture)
		VALUES ('retention-collector','retention-cluster','Retention','fixture','fixture',1,2,'linux','amd64')`)
	f.exec(t, `INSERT INTO collector_work_items
		(work_id,run_id,cluster_id,source_id,query_kind,scheduled_for,deadline,max_series,max_bytes,idempotency_key,status,available_at,work_expires_at,completed_at,next_attempt)
		VALUES ('receipt-work','receipt-run','retention-cluster','retention-source','gpu.utilization',$1::timestamptz,$1::timestamptz+interval '1 minute',1,100,'receipt-run','FAILED',$1,$1::timestamptz+interval '1 minute',$1,2)`, old)
	f.exec(t, `INSERT INTO collector_work_attempts (work_id,attempt,collector_id,lease_token_hash,status,claimed_at,lease_expires_at,completed_at)
		VALUES ('receipt-work',1,'retention-collector',$1,'FAILED',$2::timestamptz,$2::timestamptz+interval '1 minute',$2)`, tokenDigest[:], old)
	f.exec(t, `INSERT INTO collector_result_ingestions (work_id,attempt,collector_id,run_id,result_status,chunk_count,byte_count,sha256,finalized_at)
		VALUES ('receipt-work',1,'retention-collector','receipt-run','FAILED',1,9,$1,$2)`, digest[:], old)

	// Reproduce the production failure against the current schema without
	// committing any destructive mutation or relying on a SQL-string assertion.
	tx, err := f.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(context.Background(), `DELETE FROM collection_events WHERE run_id='receipt-run'`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(context.Background(), `DELETE FROM observations WHERE run_id='receipt-run'`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(context.Background(), `DELETE FROM collection_runs WHERE run_id='receipt-run'`)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" || pgErr.ConstraintName != "collector_result_ingestions_run_id_fkey" {
		t.Fatalf("expected exact legacy receipt FK reproduction, got %v", err)
	}
	_ = tx.Rollback(context.Background())

	backlog := f.backlog(t, f.now)
	assertRetentionBacklogClass(t, backlog.Observations, 1, 1, false, f.now.Add(-8*24*time.Hour))
	assertRetentionBacklogClass(t, backlog.Runs, 2, 0, false, old)
	assertRetentionBacklogClass(t, backlog.Events, 2, 1, false, old)
	result := f.apply(t)
	if result.ObservationsDeleted != 1 || result.RunsDeleted != 1 || result.EventsDeleted != 1 {
		t.Fatalf("retention result=%+v", result)
	}
	f.count(t, "collector_result_ingestions", 1)
	f.count(t, "collector_work_attempts", 1)
	f.count(t, "collection_runs", 1)
	f.count(t, "collection_events", 1)
	c, _ := storepg.NewCollectorControlStore(f.pool)
	fin := collectorcontrol.ResultFinalization{LeaseRef: collectorcontrol.LeaseRef{WorkID: "receipt-work", Attempt: 1, LeaseToken: token},
		RunID: "receipt-run", Status: domain.ResultFailed, ChunkCount: 1, Bytes: 9, SHA256: hex.EncodeToString(digest[:])}
	if outcome, err := c.FinalizeResult(context.Background(), "retention-collector", fin); err != nil || !outcome.PreviouslyFinalized {
		t.Fatalf("retained finalization replay=%+v err=%v", outcome, err)
	}
	fin.SHA256 = strings.Repeat("b", 64)
	if _, err := c.FinalizeResult(context.Background(), "retention-collector", fin); !errors.Is(err, collectorcontrol.ErrResultConflict) {
		t.Fatalf("conflicting replay no longer rejected: %v", err)
	}
	if again := f.apply(t); again != (storepg.RetentionResult{}) {
		t.Fatalf("cleanup is not repeatable: %+v", again)
	}
}

func TestRetentionTypedReceiptsMetricBindingsAndCursors(t *testing.T) {
	f := newRetentionFixture(t)
	old := f.now.Add(-40 * 24 * time.Hour)
	// Schema-valid immutable typed receipts have independent durable owners.
	// No expiration policy permits dropping any of these child records.
	f.run(t, "typed-run", old)
	f.observation(t, "typed-observation", "typed-run", old)
	f.exec(t, `INSERT INTO collectors (collector_id,cluster_id,display_name,version,build_commit,protocol_min,protocol_max,operating_system,architecture)
		VALUES ('typed-retention-collector','retention-cluster','Retention','fixture','fixture',1,2,'linux','amd64')`)
	f.exec(t, `INSERT INTO collector_work_items
		(work_id,run_id,cluster_id,source_id,query_kind,scheduled_for,deadline,max_series,max_bytes,idempotency_key,status,available_at,work_expires_at,completed_at,next_attempt)
		VALUES ('typed-work','typed-run','retention-cluster','retention-source','slurm.events',$1::timestamptz,$1::timestamptz+interval '1 minute',1,100,'typed-run','SUCCEEDED',$1,$1::timestamptz+interval '1 minute',$1,2)`, old)
	f.exec(t, `INSERT INTO collector_work_attempts (work_id,attempt,collector_id,lease_token_hash,status,claimed_at,lease_expires_at,completed_at)
		VALUES ('typed-work',1,'typed-retention-collector',decode(repeat('a',64),'hex'),'SUCCEEDED',$1::timestamptz,$1::timestamptz+interval '1 minute',$1)`, old)
	f.exec(t, `INSERT INTO collector_typed_result_ingestions
		(work_id,attempt,collector_id,run_id,cluster_id,source_id,operation,payload_schema,result_status,document,sha256,finalized_at)
		VALUES ('typed-work',1,'typed-retention-collector','typed-run','retention-cluster','retention-source','slurm.events','fixture','SUCCEEDED',$1,$2,$3)`, []byte("immutable typed document"), make([]byte, 32), old)
	f.exec(t, `INSERT INTO goodput_metric_nodes (observation_id,run_id,cluster_id,source_id,stable_node_id)
		VALUES ('typed-observation','typed-run','retention-cluster','retention-source','node-1')`)
	f.exec(t, `INSERT INTO goodput_source_coverage (run_id,cluster_id,source_id,schema_version,scope,state,expected,observed,source_at,effective_at,observed_at)
		VALUES ('typed-run','retention-cluster','retention-source',1,'EVENTS','COMPLETE',1,1,$1,$1,$1)`, old)
	f.exec(t, `INSERT INTO collector_source_cursors (cluster_id,source_id,operation,scope_sha256,cursor,run_id)
		VALUES ('retention-cluster','retention-source','slurm.events',decode(repeat('b',64),'hex'),'durable-cursor','typed-run')`)
	f.exec(t, `INSERT INTO goodput_collection_events
		(cluster_id,source_id,event_id,run_id,stable_node_id,scheduler_namespace,scheduler_job_id,submit_at,attempt,allocation_state,occurred_at,sha256)
		VALUES ('retention-cluster','retention-source','durable-event','typed-run','node-1','slurm','42',$1,1,'RUNNING',$1,decode(repeat('c',64),'hex'))`, old)

	tx, err := f.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(context.Background(), `DELETE FROM observations WHERE observation_id='typed-observation'`)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" || pgErr.ConstraintName != "goodput_metric_nodes_observation_id_fkey" {
		t.Fatalf("expected metric binding FK reproduction: %v", err)
	}
	_ = tx.Rollback(context.Background())
	backlog := f.backlog(t, f.now)
	assertRetentionBacklogClass(t, backlog.Observations, 1, 0, false, old)
	assertRetentionBacklogClass(t, backlog.Runs, 1, 0, false, old)
	assertRetentionBacklogClass(t, backlog.Events, 1, 0, false, old)
	if result := f.apply(t); result != (storepg.RetentionResult{}) {
		t.Fatalf("typed durable evidence was removed: %+v", result)
	}
	for _, table := range []string{"collector_typed_result_ingestions", "goodput_metric_nodes", "goodput_source_coverage", "collector_source_cursors", "goodput_collection_events", "observations", "collection_runs", "collection_events"} {
		f.count(t, table, 1)
	}
}

func TestRetentionPreservesTypedFinalizationReplay(t *testing.T) {
	f := newRetentionFixture(t)
	ctx := context.Background()
	c, _ := storepg.NewCollectorControlStore(f.pool)
	collector := domain.CollectorID("typed-retention-live")
	if err := c.RegisterCollector(ctx, storepg.CollectorRegistration{CollectorID: collector, ClusterID: "retention-cluster", DisplayName: "Retention", Version: "fixture", ProtocolMin: 1, ProtocolMax: 2, OperatingSystem: "linux", Architecture: "amd64"}); err != nil {
		t.Fatal(err)
	}
	if err := c.ReplaceCapabilities(ctx, collector, map[string]string{string(domain.OperationSlurmEvents): "1"}); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE sources SET kind='slurm' WHERE source_id='retention-source'`)
	p := domain.CollectionPlan{SchemaVersion: 2, RunID: "typed-finalized-run", ClusterID: "retention-cluster", SourceID: "retention-source", SourceKind: domain.CollectionSourceSlurm,
		Operation: domain.OperationSlurmEvents, PayloadSchema: domain.CollectionEventsSchema, Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{"node-1"}}, Cursor: "cursor-0",
		ScheduledFor: f.now, Deadline: f.now.Add(5 * time.Minute), Limits: domain.CollectionLimits{MaxRecords: 10, MaxBytes: 100000}, IdempotencyKey: "typed-finalized-key"}
	r := domain.TypedCollectorResult{SchemaVersion: 2, WorkID: "typed-finalized-work", Attempt: 1, Plan: p, Status: domain.ResultSucceeded, StartedAt: f.now, CompletedAt: f.now.Add(time.Second), NextCursor: "cursor-1",
		Coverage: domain.SourceCoverage{SchemaVersion: 1, ClusterID: p.ClusterID, SourceID: p.SourceID, Scope: domain.CoverageEvents, State: domain.SourceCoverageComplete, Expected: 1, Observed: 1, SourceAt: f.now, EffectiveAt: f.now, ObservedAt: f.now.Add(time.Second)},
		Payload:  domain.CollectionPayload{Kind: domain.CollectionPayloadEvents, Events: &domain.CollectionEventsPayload{Events: []domain.CollectionEvent{{ID: "event-1", NodeID: "node-1", Job: domain.JobIdentity{SchedulerNamespace: "slurm", JobID: "42", SubmitAt: f.now.Add(-time.Hour), Attempt: 1}, State: domain.AllocationRunning, OccurredAt: f.now}}}}}
	typed := &typedFixture{pool: f.pool, store: c, collector: collector, result: r}
	typed.claim(t)
	if _, err := typed.submit(r); err != nil {
		t.Fatal(err)
	}
	// Age the persisted run rather than advancing the database clock; the
	// canonical receipt bytes remain untouched for exact replay verification.
	f.exec(t, `UPDATE collection_runs SET completed_at=$1 WHERE run_id=$2`, f.now.Add(-40*24*time.Hour), p.RunID)
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM collection_events WHERE run_id=$1`, p.RunID); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `DELETE FROM collection_runs WHERE run_id=$1`, p.RunID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" || pgErr.ConstraintName != "collector_typed_result_ingestions_run_id_fkey" {
		t.Fatalf("expected exact typed receipt FK reproduction: %v", err)
	}
	_ = tx.Rollback(ctx)
	backlog := f.backlog(t, f.now)
	assertRetentionBacklogClass(t, backlog.Runs, 1, 0, false, f.now.Add(-40*24*time.Hour))
	assertRetentionBacklogClass(t, backlog.Observations, 0, 0, false, time.Time{})
	assertRetentionBacklogClass(t, backlog.Events, 0, 0, false, time.Time{})
	if result := f.apply(t); result != (storepg.RetentionResult{}) {
		t.Fatalf("typed replay authority was removed: %+v", result)
	}
	if outcome, err := typed.submit(r); err != nil || !outcome.PreviouslyFinalized {
		t.Fatalf("typed exact replay=%+v err=%v", outcome, err)
	}
	r.NextCursor = "conflicting-cursor"
	if _, err := typed.submit(r); !errors.Is(err, collectorcontrol.ErrResultConflict) {
		t.Fatalf("typed conflicting replay no longer rejected: %v", err)
	}
	for _, table := range []string{"collector_typed_result_ingestions", "goodput_source_coverage", "collector_source_cursors", "goodput_collection_events", "collection_runs"} {
		f.count(t, table, 1)
	}
	f.count(t, "collection_events", 0)
}

func TestRetentionActiveOwnersAndCutoffBoundaries(t *testing.T) {
	f := newRetentionFixture(t)
	old := f.now.Add(-40 * 24 * time.Hour)
	for _, id := range []string{"active-work", "active-job", "boundary", "recent-observation", "projection"} {
		f.run(t, id, old)
	}
	f.exec(t, `UPDATE collection_runs SET completed_at=$1 WHERE run_id='boundary'`, f.now.Add(-30*24*time.Hour))
	f.observation(t, "active-work-observation", "active-work", old)
	f.observation(t, "active-job-observation", "active-job", old)
	f.observation(t, "recent-observation", "recent-observation", f.now.Add(-7*24*time.Hour))
	f.observation(t, "projection-observation", "projection", old)
	f.exec(t, `INSERT INTO current_projections (cluster_id,source_id,entity_key,metric,observation_id,observed_at,last_success_at,updated_at)
		VALUES ('retention-cluster','retention-source','node-1','temperature','projection-observation',$1,$1,$1)`, old)
	f.exec(t, `INSERT INTO collector_work_items
		(work_id,run_id,cluster_id,source_id,query_kind,scheduled_for,deadline,max_series,max_bytes,idempotency_key,status,available_at,work_expires_at)
		VALUES ('active-work','active-work','retention-cluster','retention-source','gpu.utilization',$1,$2,1,100,'active-work','LEASED',$1,$2)`, old, f.now.Add(time.Hour))
	f.exec(t, `INSERT INTO collection_jobs (job_id,cluster_id,source_id,query_kind,interval_seconds,next_run_at,lease_owner,lease_expires_at,lease_generation)
		VALUES ('active-job','retention-cluster','retention-source','gpu.utilization',30,$1::timestamptz,'worker',$2::timestamptz+interval '1 hour',1)`, old, f.now)
	f.exec(t, `INSERT INTO collection_run_jobs
		(run_id,job_id,cluster_id,source_id,query_kind,node_filter,scheduled_for,configuration_revision,lease_generation)
		VALUES ('active-job','active-job','retention-cluster','retention-source','gpu.utilization','',$1,0,1)`, old)
	if result := f.apply(t); result != (storepg.RetentionResult{}) {
		t.Fatalf("live owner or strict cutoff was ignored: %+v", result)
	}
	f.exec(t, `UPDATE collector_work_items SET status='FAILED',completed_at=clock_timestamp() WHERE work_id='active-work'`)
	f.exec(t, `UPDATE collection_jobs SET active=false WHERE job_id='active-job'`)
	result := f.apply(t)
	if result.RunsDeleted != 2 || result.ObservationsDeleted != 2 || result.EventsDeleted != 2 {
		t.Fatalf("released owners did not become eligible: %+v", result)
	}
	f.count(t, "collection_runs", 3)
}

func TestRetentionReclaimedLeasePreservesCanonicalOccurrence(t *testing.T) {
	f := newRetentionFixture(t)
	ctx := context.Background()
	old := f.now.Add(-40 * 24 * time.Hour)
	if err := f.store.EnsureJob(ctx, "retry-job", "retention-cluster", "retention-source", domain.QueryGPUUtilization, "", 30*time.Second, old); err != nil {
		t.Fatal(err)
	}
	first, found, err := f.store.ClaimDueSourceJob(ctx, "first-worker", time.Minute, "retention-source")
	if err != nil || !found {
		t.Fatalf("first claim: found=%t err=%v", found, err)
	}
	canonical, err := f.store.BindCollectionJob(ctx, first, "first-worker", "canonical-old-run")
	if err != nil {
		t.Fatal(err)
	}
	f.run(t, string(canonical), old)
	f.observation(t, "canonical-old-observation", string(canonical), old)
	f.exec(t, `UPDATE collection_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE job_id='retry-job'`)
	backlog := f.backlog(t, f.now)
	assertRetentionBacklogClass(t, backlog.Observations, 1, 0, false, old)
	assertRetentionBacklogClass(t, backlog.Runs, 1, 0, false, old)
	assertRetentionBacklogClass(t, backlog.Events, 1, 0, false, old)
	if result := f.apply(t); result != (storepg.RetentionResult{}) {
		t.Fatalf("unfinished occurrence lost evidence between lease expiry and reclaim: %+v", result)
	}
	second, found, err := f.store.ClaimDueSourceJob(ctx, "retry-worker", time.Minute, "retention-source")
	if err != nil || !found || second.LeaseGeneration <= first.LeaseGeneration {
		t.Fatalf("reclaimed lease: %+v found=%t err=%v", second, found, err)
	}
	rebound, err := f.store.BindCollectionJob(ctx, second, "retry-worker", "discarded-retry-run")
	if err != nil || rebound != canonical {
		t.Fatalf("canonical occurrence binding: %s want=%s err=%v", rebound, canonical, err)
	}
	var originalGeneration int64
	if err := f.pool.QueryRow(ctx, `SELECT lease_generation FROM collection_run_jobs WHERE run_id=$1`, canonical).Scan(&originalGeneration); err != nil || originalGeneration != first.LeaseGeneration {
		t.Fatalf("immutable binding generation=%d want=%d err=%v", originalGeneration, first.LeaseGeneration, err)
	}
	if result := f.apply(t); result != (storepg.RetentionResult{}) {
		t.Fatalf("retry lease lost its original run/observations/events: %+v", result)
	}
	if err := f.store.CompleteJob(ctx, second, "retry-worker"); err != nil {
		t.Fatal(err)
	}
	if result := f.apply(t); result.RunsDeleted != 1 || result.EventsDeleted != 1 || result.ObservationsDeleted != 1 {
		t.Fatalf("completed occurrence stayed pinned: %+v", result)
	}
	// This intentional logical provenance has no FK to a retained run and
	// remains available after the ordinary run horizon, just like progress receipts.
	f.count(t, "collection_run_jobs", 1)
}

func TestRetentionConcurrentBatchesAndInterruptedCleanup(t *testing.T) {
	f := newRetentionFixture(t)
	old := f.now.Add(-40 * 24 * time.Hour)
	// Reverse event/run ordering crosses the independent 1000-row batch limits.
	f.exec(t, `INSERT INTO collection_runs
		(run_id,cluster_id,source_id,query_kind,idempotency_key,status,scheduled_for,started_at,completed_at,series_returned,bytes_read,coverage_complete)
		SELECT 'bulk-'||lpad(g::text,4,'0'),'retention-cluster','retention-source','gpu.utilization','bulk-'||g,'FAILED',$1,$1,$1,0,0,false FROM generate_series(1,1001) g`, old)
	f.exec(t, `INSERT INTO collection_events (run_id,event_type)
		SELECT run_id,'collection.updated' FROM collection_runs ORDER BY run_id DESC`)
	tx, err := f.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `SELECT run_id FROM collection_runs WHERE run_id='bulk-0001' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.store.ApplyRetention(ctx, f.now, 7*24*time.Hour, 30*24*time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
	var wg sync.WaitGroup
	results := make(chan storepg.RetentionResult, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := f.store.ApplyRetention(context.Background(), f.now, 7*24*time.Hour, 30*24*time.Hour)
			results <- r
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var deleted int64
	for r := range results {
		deleted += r.RunsDeleted
	}
	if deleted != 1000 {
		t.Fatalf("locked run was deleted or batches stalled: deleted=%d", deleted)
	}
	_ = tx.Rollback(context.Background())
	if result := f.apply(t); result.RunsDeleted != 1 {
		t.Fatalf("resumed cleanup=%+v", result)
	}
	f.count(t, "collection_runs", 0)
	f.count(t, "collection_events", 0)
}

func TestRetentionFutureWorkerClockCannotExpireRecentData(t *testing.T) {
	f := newRetentionFixture(t)
	f.run(t, "recent", f.now)
	if r, err := f.store.ApplyRetention(context.Background(), f.now.Add(90*24*time.Hour), 7*24*time.Hour, 30*24*time.Hour); err != nil || r.RunsDeleted != 0 {
		t.Fatalf("future worker clock advanced database retention: %+v %v", r, err)
	}
	f.count(t, "collection_runs", 1)
}

func TestRetentionFailureRollsBackBatchAndPreservesEvidence(t *testing.T) {
	f := newRetentionFixture(t)
	old := f.now.Add(-40 * 24 * time.Hour)
	f.run(t, "rollback", old)
	f.observation(t, "rollback-observation", "rollback", old)
	f.exec(t, `INSERT INTO evidence_envelopes
		(evidence_id,schema_version,cluster_id,status,source_id,run_id,operation,definition_version,source_reference,observed_start,observed_end,collected_at,coverage_expected,coverage_covered)
		VALUES ('retained-evidence',1,'retention-cluster','UNAVAILABLE','retention-source','rollback','fixture','1','immutable',$1,$1,$1,'[]','[]')`, old)
	f.exec(t, `CREATE FUNCTION fail_retention_fixture() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected retention failure'; END $$`)
	f.exec(t, `CREATE TRIGGER fail_retention_fixture BEFORE DELETE ON collection_runs FOR EACH ROW EXECUTE FUNCTION fail_retention_fixture()`)
	if _, err := f.store.ApplyRetention(context.Background(), f.now, 7*24*time.Hour, 30*24*time.Hour); err == nil {
		t.Fatal("injected failure was hidden")
	}
	f.count(t, "observations", 1)
	f.count(t, "collection_events", 1)
	f.count(t, "collection_runs", 1)
	f.exec(t, `DROP TRIGGER fail_retention_fixture ON collection_runs`)
	if r := f.apply(t); r.RunsDeleted != 1 || r.ObservationsDeleted != 1 || r.EventsDeleted != 1 {
		t.Fatalf("retry after rollback=%+v", r)
	}
	var id *string
	var reference string
	if err := f.pool.QueryRow(context.Background(), `SELECT run_id,source_reference FROM evidence_envelopes WHERE evidence_id='retained-evidence'`).Scan(&id, &reference); err != nil || id != nil || reference != "immutable" {
		t.Fatalf("existing SET NULL evidence contract changed: run=%v reference=%s err=%v", id, reference, err)
	}
}

func TestRetentionLockWaitIsBoundedAndRetryable(t *testing.T) {
	f := newRetentionFixture(t)
	f.run(t, "blocked-retention", f.now.Add(-40*24*time.Hour))
	tx, err := f.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `LOCK observations IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = f.store.ApplyRetention(ctx, f.now, 7*24*time.Hour, 30*24*time.Hour)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" || time.Since(started) >= 3*time.Second {
		t.Fatalf("retention lock wait was not bounded by its own transaction: elapsed=%s err=%v", time.Since(started), err)
	}
	_ = tx.Rollback(context.Background())
	if result := f.apply(t); result.RunsDeleted != 1 {
		t.Fatalf("cleanup did not recover after lock release: %+v", result)
	}
}

func TestRetentionRejectsInvalidDurations(t *testing.T) {
	f := newRetentionFixture(t)
	for _, durations := range [][2]time.Duration{{0, time.Hour}, {time.Hour, 0}, {time.Hour, time.Minute}} {
		t.Run(fmt.Sprint(durations), func(t *testing.T) {
			if _, err := f.store.ApplyRetention(context.Background(), f.now, durations[0], durations[1]); err == nil {
				t.Fatal("invalid retention was accepted")
			}
		})
	}
}

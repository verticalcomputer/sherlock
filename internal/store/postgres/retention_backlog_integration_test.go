//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func (f retentionFixture) backlog(t *testing.T, now time.Time) storepg.RetentionBacklog {
	t.Helper()
	result, err := f.store.MeasureRetentionBacklog(context.Background(), now, 7*24*time.Hour, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertRetentionBacklogClass(t *testing.T, got storepg.RetentionBacklogClass, expired, eligible int64, truncated bool, oldest time.Time) {
	t.Helper()
	if got.ExpiredRows != expired || got.EligibleRows != eligible || got.Truncated != truncated || !got.OldestExpiredAt.Equal(oldest) {
		t.Fatalf("backlog=%+v want expired=%d eligible=%d truncated=%t oldest=%s", got, expired, eligible, truncated, oldest)
	}
}

func TestRetentionBacklogEligiblePinnedAndReadOnly(t *testing.T) {
	f := newRetentionFixture(t)
	old := f.now.Add(-40 * 24 * time.Hour)
	for _, id := range []string{"eligible-run", "eligible-event", "observation-owner", "work-owner", "job-owner"} {
		f.run(t, id, old)
	}
	f.exec(t, `DELETE FROM collection_events WHERE run_id='eligible-run'`)
	f.observation(t, "eligible-observation", "observation-owner", old)
	f.observation(t, "projection-observation", "observation-owner", old)
	f.exec(t, `INSERT INTO current_projections (cluster_id,source_id,entity_key,metric,observation_id,observed_at,last_success_at,updated_at)
		VALUES ('retention-cluster','retention-source','node-1','temperature','projection-observation',$1,$1,$1)`, old)
	f.exec(t, `INSERT INTO collector_work_items
		(work_id,run_id,cluster_id,source_id,query_kind,scheduled_for,deadline,max_series,max_bytes,idempotency_key,available_at,work_expires_at)
		VALUES ('work-owner','work-owner','retention-cluster','retention-source','gpu.utilization',$1,$2,1,100,'work-owner',$1,$2)`, old, f.now.Add(time.Hour))
	f.exec(t, `INSERT INTO collection_jobs (job_id,cluster_id,source_id,query_kind,interval_seconds,next_run_at)
		VALUES ('job-owner','retention-cluster','retention-source','gpu.utilization',30,$1)`, old)
	f.exec(t, `INSERT INTO collection_run_jobs
		(run_id,job_id,cluster_id,source_id,query_kind,node_filter,scheduled_for,configuration_revision,lease_generation)
		VALUES ('job-owner','job-owner','retention-cluster','retention-source','gpu.utilization','',$1,0,1)`, old)
	// The PostgreSQL fixture can run in a VM with a different wall clock.
	// Bracket its transaction timestamp in the same clock domain rather than
	// accidentally requiring the host and database clocks to be synchronized.
	var before, after time.Time
	if err := f.pool.QueryRow(context.Background(), `SELECT clock_timestamp()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	result := f.backlog(t, f.now)
	if err := f.pool.QueryRow(context.Background(), `SELECT clock_timestamp()`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if result.MeasuredAt.Before(before) || result.MeasuredAt.After(after) {
		t.Fatalf("measurement does not use database transaction time: %s", result.MeasuredAt)
	}
	assertRetentionBacklogClass(t, result.Observations, 2, 1, false, old)
	assertRetentionBacklogClass(t, result.Runs, 5, 1, false, old)
	assertRetentionBacklogClass(t, result.Events, 4, 1, false, old)
	f.count(t, "observations", 2)
	f.count(t, "collection_runs", 5)
	f.count(t, "collection_events", 4)
	f.count(t, "collection_run_jobs", 1)
	f.count(t, "collector_work_items", 1)
	// Each class reports eligibility in this snapshot, not the number a whole
	// cleanup could delete after observations and events are removed first.
	deleted := f.apply(t)
	if deleted.ObservationsDeleted != 1 || deleted.EventsDeleted != 1 || deleted.RunsDeleted != 2 {
		t.Fatalf("measurement ownership differs from cleanup: %+v", deleted)
	}
}

func TestRetentionBacklogOldestPrefixCapAndTruncation(t *testing.T) {
	f := newRetentionFixture(t)
	old := f.now.Add(-40 * 24 * time.Hour)
	f.exec(t, `INSERT INTO collection_runs
		(run_id,cluster_id,source_id,query_kind,idempotency_key,status,scheduled_for,started_at,completed_at,series_returned,bytes_read,coverage_complete)
		SELECT 'bulk-'||lpad(g::text,4,'0'),'retention-cluster','retention-source','gpu.utilization','bulk-'||g,'FAILED',$1,$1,$1,0,0,false FROM generate_series(1,1001) g`, old)
	f.exec(t, `INSERT INTO collection_events (run_id,event_type) SELECT run_id,'collection.updated' FROM collection_runs ORDER BY run_id`)
	f.exec(t, `INSERT INTO observations
		(observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,observed_at,collected_at,source_reference,sample_fingerprint)
		SELECT 'observation-'||lpad(g::text,4,'0'),'bulk-0001','retention-cluster','retention-source',1,'gpu_metric','node-'||g,'temperature','[]',50,'celsius',$1,$1,'fixture',decode(md5(g::text),'hex') FROM generate_series(1,1001) g`, old)
	f.exec(t, `INSERT INTO current_projections (cluster_id,source_id,entity_key,metric,observation_id,observed_at,last_success_at,updated_at)
		VALUES ('retention-cluster','retention-source','node-1','temperature','observation-0001',$1,$1,$1)`, old)
	result := f.backlog(t, f.now)
	assertRetentionBacklogClass(t, result.Observations, 1000, 999, true, old)
	assertRetentionBacklogClass(t, result.Runs, 1000, 0, true, old)
	assertRetentionBacklogClass(t, result.Events, 1000, 999, true, old)
	f.exec(t, `DELETE FROM observations WHERE observation_id='observation-1001'`)
	f.exec(t, `DELETE FROM collection_events WHERE run_id='bulk-1001'`)
	f.exec(t, `DELETE FROM collection_runs WHERE run_id='bulk-1001'`)
	result = f.backlog(t, f.now)
	assertRetentionBacklogClass(t, result.Observations, 1000, 999, false, old)
	assertRetentionBacklogClass(t, result.Runs, 1000, 0, false, old)
	assertRetentionBacklogClass(t, result.Events, 1000, 999, false, old)
}

func TestRetentionBacklogCutoffsAndFutureWorkerClock(t *testing.T) {
	f := newRetentionFixture(t)
	f.run(t, "run-boundary", f.now.Add(-30*24*time.Hour))
	f.run(t, "run-expired", f.now.Add(-30*24*time.Hour-time.Microsecond))
	f.run(t, "recent", f.now)
	f.observation(t, "observation-boundary", "recent", f.now.Add(-7*24*time.Hour))
	f.observation(t, "observation-expired", "recent", f.now.Add(-7*24*time.Hour-time.Microsecond))
	result := f.backlog(t, f.now)
	assertRetentionBacklogClass(t, result.Observations, 1, 1, false, f.now.Add(-7*24*time.Hour-time.Microsecond))
	assertRetentionBacklogClass(t, result.Runs, 1, 0, false, f.now.Add(-30*24*time.Hour-time.Microsecond))
	assertRetentionBacklogClass(t, result.Events, 1, 1, false, f.now.Add(-30*24*time.Hour-time.Microsecond))
	result = f.backlog(t, f.now.Add(90*24*time.Hour))
	if result.Runs.ExpiredRows != 2 || result.Observations.ExpiredRows != 2 || result.Events.ExpiredRows != 2 {
		t.Fatalf("future caller clock was not clamped to database time: %+v", result)
	}
	f.count(t, "collection_runs", 3)
	f.count(t, "observations", 2)
	if empty := f.backlog(t, f.now.Add(-90*24*time.Hour)); empty.Runs != (storepg.RetentionBacklogClass{}) || empty.Observations != (storepg.RetentionBacklogClass{}) || empty.Events != (storepg.RetentionBacklogClass{}) {
		t.Fatalf("empty sample is not explicitly empty: %+v", empty)
	}
}

func TestRetentionBacklogUsesOneRepeatableReadSnapshot(t *testing.T) {
	f := newRetentionFixture(t)
	old := f.now.Add(-40 * 24 * time.Hour)
	f.run(t, "snapshot-run", old)
	f.exec(t, `DELETE FROM collection_events WHERE run_id='snapshot-run'`)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gate, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gate.Rollback(context.Background()) }()
	if _, err := gate.Exec(ctx, `LOCK collection_events IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	type measured struct {
		result storepg.RetentionBacklog
		err    error
	}
	done := make(chan measured, 1)
	go func() {
		r, err := f.store.MeasureRetentionBacklog(ctx, f.now, 7*24*time.Hour, 30*24*time.Hour)
		done <- measured{r, err}
	}()
	for {
		var waiting bool
		if err := f.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '/* retention backlog runs */%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case result := <-done:
			t.Fatalf("snapshot did not reach the controlled run query: %+v", result)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	// These inserts commit after the measurement acquired its snapshot. They
	// must neither change run eligibility nor appear in its later event class.
	if _, err := gate.Exec(ctx, `INSERT INTO collection_events (run_id,event_type) VALUES ('snapshot-run','collection.updated')`); err != nil {
		t.Fatal(err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	assertRetentionBacklogClass(t, got.result.Observations, 0, 0, false, time.Time{})
	assertRetentionBacklogClass(t, got.result.Runs, 1, 1, false, old)
	assertRetentionBacklogClass(t, got.result.Events, 0, 0, false, time.Time{})
	next := f.backlog(t, f.now)
	assertRetentionBacklogClass(t, next.Runs, 1, 0, false, old)
	assertRetentionBacklogClass(t, next.Events, 1, 1, false, old)
}

func TestRetentionBacklogFailureCancellationAndTimeout(t *testing.T) {
	f := newRetentionFixture(t)
	f.run(t, "preserved", f.now.Add(-40*24*time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := f.store.MeasureRetentionBacklog(ctx, f.now, 7*24*time.Hour, 30*24*time.Hour); !errors.Is(err, context.Canceled) || result != (storepg.RetentionBacklog{}) {
		t.Fatalf("cancellation did not fail without a partial result: %+v %v", result, err)
	}
	gate, err := f.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gate.Rollback(context.Background()) }()
	if _, err := gate.Exec(context.Background(), `LOCK observations IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	result, err := f.store.MeasureRetentionBacklog(context.Background(), f.now, 7*24*time.Hour, 30*24*time.Hour)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" || time.Since(started) >= 2*time.Second || result != (storepg.RetentionBacklog{}) {
		t.Fatalf("measurement lock timeout: elapsed=%s result=%+v err=%v", time.Since(started), result, err)
	}
	short, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if result, err := f.store.MeasureRetentionBacklog(short, f.now, 7*24*time.Hour, 30*24*time.Hour); !errors.Is(err, context.DeadlineExceeded) || result != (storepg.RetentionBacklog{}) {
		t.Fatalf("caller deadline did not preempt measurement: %+v %v", result, err)
	}
	_ = gate.Rollback(context.Background())
	f.count(t, "collection_runs", 1)
	f.count(t, "collection_events", 1)
	if result := f.backlog(t, f.now); result.Events.EligibleRows != 1 {
		t.Fatalf("measurement did not recover: %+v", result)
	}
	// Missing schema/permissions remain measurement failures, not healthy zeros.
	f.exec(t, `ALTER TABLE observations RENAME TO observations_fixture_hidden`)
	if result, err := f.store.MeasureRetentionBacklog(context.Background(), f.now, 7*24*time.Hour, 30*24*time.Hour); err == nil || !strings.Contains(err.Error(), "measure observation retention backlog") || result != (storepg.RetentionBacklog{}) {
		t.Fatalf("query failure hidden: %+v %v", result, err)
	}
	f.exec(t, `ALTER TABLE observations_fixture_hidden RENAME TO observations`)
}

func TestRetentionBacklogRejectsInvalidDurations(t *testing.T) {
	f := newRetentionFixture(t)
	for _, durations := range [][2]time.Duration{{0, time.Hour}, {time.Hour, 0}, {time.Hour, time.Minute}} {
		if result, err := f.store.MeasureRetentionBacklog(context.Background(), f.now, durations[0], durations[1]); err == nil || result != (storepg.RetentionBacklog{}) {
			t.Fatalf("invalid retention was accepted: %+v %v", result, err)
		}
	}
}

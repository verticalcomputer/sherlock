//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func scheduleFixture(t *testing.T) (context.Context, *pgxpool.Pool, *storepg.CollectionStore, []domain.DesiredSchedule) {
	t.Helper()
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	p, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	s, err := storepg.NewCollectionStore(p)
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("gp04-%d", time.Now().UnixNano())
	cluster, source := domain.ClusterID(id), domain.SourceID(id)
	if err := s.EnsureSource(ctx, cluster, id, source, id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer p.Close()
		for _, table := range []string{"collection_run_jobs", "desired_schedules", "collection_jobs", "sources", "clusters"} {
			if _, err := p.Exec(ctx, `DELETE FROM `+table+` WHERE cluster_id=$1`, cluster); err != nil {
				t.Errorf("cleanup %s: %v", table, err)
			}
		}
	})
	return ctx, p, s, application.LegacyPrometheusSchedules(cluster, source, domain.SchedulingLegacy, 30*time.Second, 10*time.Second, 100, 1024)
}

func TestGP04DesiredScheduleImportAndOwnership(t *testing.T) {
	ctx, p, s, seeds := scheduleFixture(t)
	key := seeds[0].ScheduleKey
	op, _ := domain.ReviewedCollectionOperation(key.Operation)
	jobID := "existing-" + string(key.SourceID)
	first := time.Now().UTC().Add(-time.Minute)
	if err := s.EnsureJob(ctx, jobID, key.ClusterID, key.SourceID, op.Query, "", 7*time.Second, first); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `UPDATE collection_jobs SET active=false WHERE job_id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- s.ImportLegacyPrometheusSchedules(ctx, seeds, first) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := p.QueryRow(ctx, `SELECT count(*) FROM desired_schedules WHERE cluster_id=$1`, key.ClusterID).Scan(&count); err != nil || count != 4 {
		t.Fatalf("schedule count=%d err=%v", count, err)
	}
	if err := p.QueryRow(ctx, `SELECT count(*) FROM collection_jobs WHERE cluster_id=$1`, key.ClusterID).Scan(&count); err != nil || count != 4 {
		t.Fatalf("job count=%d err=%v", count, err)
	}
	desired, err := s.DesiredSchedule(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if desired.Enabled || desired.Interval != 7*time.Second || desired.Timeout != 7*time.Second || desired.Revision != 1 {
		t.Fatalf("did not preserve persisted configuration: %+v", desired)
	}
	// Disable all other schedules to isolate this operation's claim behavior.
	for _, seed := range seeds[1:] {
		d, err := s.DesiredSchedule(ctx, seed.ScheduleKey)
		if err != nil {
			t.Fatal(err)
		}
		d.Enabled = false
		if _, err := s.UpdateDesiredSchedule(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	if _, found, err := s.ClaimDueClusterSourceJob(ctx, "worker", time.Minute, key.ClusterID, key.SourceID); err != nil || found {
		t.Fatalf("disabled claimed: %v %v", found, err)
	}
	desired.Enabled = true
	desired.Timeout = 3 * time.Second
	desired.MaxTargets = 7
	desired.MaxBytes = 512
	desired, err = s.UpdateDesiredSchedule(ctx, desired)
	if err != nil {
		t.Fatal(err)
	}
	job, found, err := s.ClaimDueClusterSourceJob(ctx, "worker", time.Second, key.ClusterID, key.SourceID)
	if err != nil || !found {
		t.Fatalf("claim: %v %v", found, err)
	}
	if job.Timeout != desired.Timeout || job.MaxTargets != 7 || job.MaxBytes != 512 || job.DesiredRevision != desired.Revision {
		t.Fatalf("claim ignored persisted bounds: %+v", job)
	}
	wrong := job
	wrong.ClusterID = "other-cluster"
	if _, err := s.BindCollectionJob(ctx, wrong, "worker", "wrong"); err == nil {
		t.Fatal("cross-cluster binding accepted")
	}
	if err := s.CompleteJob(ctx, wrong, "worker"); err == nil {
		t.Fatal("cross-cluster completion accepted")
	}
	if _, found, err := s.ClaimDueClusterSourceJob(ctx, "other", time.Minute, "other-cluster", key.SourceID); err != nil || found {
		t.Fatalf("cross-cluster claim: %v %v", found, err)
	}
	// A limit-only revision also revokes the old claim, even with active/cadence unchanged.
	stale := desired
	desired.MaxBytes = 256
	desired, err = s.UpdateDesiredSchedule(ctx, desired)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateDesiredSchedule(ctx, stale); !errors.Is(err, domain.ErrScheduleRevision) {
		t.Fatalf("revision conflict: %v", err)
	}
	if _, err := s.BindCollectionJob(ctx, job, "worker", "stale"); err == nil {
		t.Fatal("stale unbound claim accepted")
	}
	job, found, err = s.ClaimDueClusterSourceJob(ctx, "worker", time.Minute, key.ClusterID, key.SourceID)
	if err != nil || !found {
		t.Fatalf("reclaim: %v %v", found, err)
	}
	if _, err := s.BindCollectionJob(ctx, job, "worker", domain.RunID("bound-"+string(key.ClusterID))); err != nil {
		t.Fatal(err)
	}
	desired.Mode = domain.SchedulingDurable
	desired, err = s.UpdateDesiredSchedule(ctx, desired)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.ClaimDueClusterSourceJob(ctx, "worker", time.Minute, key.ClusterID, key.SourceID); err != nil || found {
		t.Fatalf("durable owned job claimed: %v %v", found, err)
	}
	if err := s.CompleteJob(ctx, job, "worker"); err == nil {
		t.Fatal("old completion advanced new schedule")
	}
	// Restart/import and the old startup API cannot undo an explicit switch.
	restarted, _ := storepg.NewCollectionStore(p)
	if err := restarted.ImportLegacyPrometheusSchedules(ctx, seeds, first); err != nil {
		t.Fatal(err)
	}
	if err := restarted.EnsureJob(ctx, jobID, key.ClusterID, key.SourceID, op.Query, "", time.Hour, first); err != nil {
		t.Fatal(err)
	}
	persisted, err := restarted.DesiredSchedule(ctx, key)
	if err != nil || persisted != desired {
		t.Fatalf("restart changed authority: %+v %v", persisted, err)
	}
	if err := s.EnsureJob(ctx, "bypass", key.ClusterID, key.SourceID, op.Query, "node-a", time.Minute, first); err == nil {
		t.Fatal("targeted owner bypass accepted")
	}
	if err := s.EnsureJob(ctx, "cross", "other-cluster", key.SourceID, op.Query, "", time.Minute, first); err == nil {
		t.Fatal("cross-cluster source accepted")
	}
	if _, err := p.Exec(ctx, `UPDATE collection_jobs SET active=true WHERE job_id=$1`, jobID); err == nil {
		t.Fatal("raw legacy reactivation accepted")
	}
	if _, err := p.Exec(ctx, `UPDATE collection_jobs SET interval_seconds=123 WHERE job_id=$1`, jobID); err == nil {
		t.Fatal("raw legacy cadence divergence accepted")
	}
	if _, err := p.Exec(ctx, `UPDATE collection_jobs SET query_kind='dcgm_gpu_power' WHERE job_id=$1`, jobID); err == nil {
		t.Fatal("owned job identity mutation accepted")
	}
	// Switching back is one explicit CAS, followed by exactly one lease winner.
	desired.Mode = domain.SchedulingLegacy
	desired, err = s.UpdateDesiredSchedule(ctx, desired)
	if err != nil {
		t.Fatal(err)
	}
	job, found, err = s.ClaimDueClusterSourceJob(ctx, "worker", time.Minute, key.ClusterID, key.SourceID)
	if err != nil || !found {
		t.Fatalf("legacy switch reclaim: %v %v", found, err)
	}
	if _, found, err := s.ClaimDueClusterSourceJob(ctx, "other", time.Minute, key.ClusterID, key.SourceID); err != nil || found {
		t.Fatalf("duplicate owner: %v %v", found, err)
	}
	desired.Enabled = false
	desired, err = s.UpdateDesiredSchedule(ctx, desired)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.BindCollectionJob(ctx, job, "worker", "disabled"); err == nil {
		t.Fatal("disabled claim bound")
	}
	if err := restarted.ImportLegacyPrometheusSchedules(ctx, seeds, first); err != nil {
		t.Fatal(err)
	}
	if persisted, err := s.DesiredSchedule(ctx, key); err != nil || persisted != desired {
		t.Fatalf("restart re-enabled: %+v %v", persisted, err)
	}
}

func TestGP04TargetedImportIsAtomic(t *testing.T) {
	ctx, p, s, seeds := scheduleFixture(t)
	last := seeds[3]
	op, _ := domain.ReviewedCollectionOperation(last.Operation)
	if err := s.EnsureJob(ctx, "target-"+string(last.SourceID), last.ClusterID, last.SourceID, op.Query, "node-a", 17*time.Second, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.ImportLegacyPrometheusSchedules(ctx, seeds, time.Now()); err == nil {
		t.Fatal("targeted import accepted")
	}
	var jobs, schedules, interval int
	if err := p.QueryRow(ctx, `SELECT (SELECT count(*) FROM collection_jobs WHERE cluster_id=$1),(SELECT count(*) FROM desired_schedules WHERE cluster_id=$1),(SELECT interval_seconds FROM collection_jobs WHERE cluster_id=$1)`, last.ClusterID).Scan(&jobs, &schedules, &interval); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 || schedules != 0 || interval != 17 {
		t.Fatalf("partial import leaked: jobs=%d schedules=%d interval=%d", jobs, schedules, interval)
	}
}

func TestGP04ScheduleStoreConstraints(t *testing.T) {
	ctx, p, s, seeds := scheduleFixture(t)
	if err := s.ImportLegacyPrometheusSchedules(ctx, seeds, time.Now()); err != nil {
		t.Fatal(err)
	}
	key := seeds[0].ScheduleKey
	d, err := s.DesiredSchedule(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	bad := d
	bad.ClusterID = "other"
	if _, err := s.UpdateDesiredSchedule(ctx, bad); !errors.Is(err, domain.ErrScheduleRevision) {
		t.Fatalf("cross-cluster CAS: %v", err)
	}
	for _, assignment := range []string{"interval_seconds=0", "timeout_ms=0", "timeout_ms=99999999", "jitter_ms=-1", "jitter_ms=30000", "max_targets=0", "max_targets=10001", "max_bytes=0", "max_bytes=10485761", "priority=101", "mode='both'"} {
		if _, err := p.Exec(ctx, `UPDATE desired_schedules SET `+assignment+` WHERE cluster_id=$1`, key.ClusterID); err == nil {
			t.Fatalf("database accepted %s", assignment)
		}
	}
	if _, err := p.Exec(ctx, `INSERT INTO desired_schedules SELECT * FROM desired_schedules WHERE cluster_id=$1`, key.ClusterID); err == nil {
		t.Fatal("duplicate key accepted")
	}
	// A reviewed typed operation is desired-only and has no legacy owner.
	if _, err := p.Exec(ctx, `INSERT INTO sources(source_id,cluster_id,kind,display_name) VALUES($1,$2,'slurm','Slurm')`, string(key.SourceID)+"-slurm", key.ClusterID); err != nil {
		t.Fatal(err)
	}
	typed := seeds[0]
	typed.Operation = domain.OperationSlurmInventory
	typed.Mode = domain.SchedulingDurable
	if _, err := s.CreateDesiredSchedule(ctx, typed); err == nil {
		t.Fatal("typed operation accepted wrong source kind")
	}
	typed.ClusterID = "other-cluster"
	if _, err := s.CreateDesiredSchedule(ctx, typed); err == nil {
		t.Fatal("typed operation accepted foreign cluster")
	}
	typed.ClusterID = key.ClusterID
	typed.SourceID = domain.SourceID(string(key.SourceID) + "-slurm")
	typed.Operation = domain.OperationSlurmInventory
	typed.Mode = domain.SchedulingDurable
	typed.MaxTargets = 1
	typed, err = s.CreateDesiredSchedule(ctx, typed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateDesiredSchedule(ctx, typed); err == nil {
		t.Fatal("existing revision accepted on create")
	}
	copy := typed
	copy.Revision = 0
	if _, err := s.CreateDesiredSchedule(ctx, copy); err == nil {
		t.Fatal("duplicate typed key accepted")
	}
	if _, found, err := s.ClaimDueClusterSourceJob(ctx, "worker", time.Minute, typed.ClusterID, typed.SourceID); err != nil || found {
		t.Fatalf("typed desired work admitted: %v %v", found, err)
	}
	typed.Mode = domain.SchedulingLegacy
	if _, err := s.UpdateDesiredSchedule(ctx, typed); err == nil {
		t.Fatal("typed legacy owner accepted")
	}
}

func TestGP04InitialDurableModeHasNoAdmission(t *testing.T) {
	ctx, _, s, seeds := scheduleFixture(t)
	for i := range seeds {
		seeds[i].Mode = domain.SchedulingDurable
	}
	if err := s.ImportLegacyPrometheusSchedules(ctx, seeds, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, seed := range seeds {
		d, err := s.DesiredSchedule(ctx, seed.ScheduleKey)
		if err != nil || !d.Enabled || d.Mode != domain.SchedulingDurable {
			t.Fatalf("durable import: %+v %v", d, err)
		}
	}
	if _, found, err := s.ClaimDueClusterSourceJob(ctx, "worker", time.Minute, seeds[0].ClusterID, seeds[0].SourceID); err != nil || found {
		t.Fatalf("durable import admitted work: %v %v", found, err)
	}
}

func TestGP04ModeSwitchFencesWaitingBinding(t *testing.T) {
	ctx, p, s, seeds := scheduleFixture(t)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.ImportLegacyPrometheusSchedules(ctx, seeds, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	job, found, err := s.ClaimDueClusterSourceJob(ctx, "worker", time.Minute, seeds[0].ClusterID, seeds[0].SourceID)
	if err != nil || !found {
		t.Fatalf("claim: %v %v", found, err)
	}
	lock, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(context.Background()) }()
	if _, err := lock.Exec(ctx, `SELECT job_id FROM collection_jobs WHERE job_id=$1 FOR UPDATE`, job.JobID); err != nil {
		t.Fatal(err)
	}
	lockPID := lock.Conn().PgConn().PID()
	change, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = change.Rollback(context.Background()) }()
	pid := change.Conn().PgConn().PID()
	changed := make(chan error, 1)
	go func() {
		_, err := change.Exec(ctx, `UPDATE desired_schedules SET mode='durable' WHERE legacy_job_id=$1`, job.JobID)
		if err == nil {
			err = change.Commit(ctx)
		}
		changed <- err
	}()
	// Wait until the revision transaction owns the desired row and is blocked
	// specifically by this test's job lock.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := p.QueryRow(ctx, `SELECT $2::integer=ANY(pg_blocking_pids($1))`, pid, lockPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-changed:
			t.Fatalf("switch did not wait for job lock: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
	bindConfig := p.Config().Copy()
	bindConfig.MinConns, bindConfig.MaxConns = 1, 1
	bindPool, err := pgxpool.NewWithConfig(ctx, bindConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer bindPool.Close()
	bindConnection, err := bindPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bindPID := bindConnection.Conn().PgConn().PID()
	bindConnection.Release()
	bindStore, err := storepg.NewCollectionStore(bindPool)
	if err != nil {
		t.Fatal(err)
	}
	bound := make(chan error, 1)
	go func() {
		_, err := bindStore.BindCollectionJob(ctx, job, "worker", domain.RunID("late-"+string(job.ClusterID)))
		bound <- err
	}()
	// Do not release the blocker until the bind transaction is itself queued
	// behind the mode switch on the same lock chain.
	for {
		var waiting bool
		if err := p.QueryRow(ctx, `SELECT $2::integer=ANY(pg_blocking_pids($1)) OR $3::integer=ANY(pg_blocking_pids($1))`, bindPID, lockPID, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-bound:
			t.Fatalf("binding did not wait behind mode switch: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
	if err := lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-changed; err != nil {
		t.Fatal(err)
	}
	if err := <-bound; err == nil {
		t.Fatal("binding accepted across the mode switch")
	}
	var bindings int
	if err := p.QueryRow(ctx, `SELECT count(*) FROM collection_run_jobs WHERE cluster_id=$1`, job.ClusterID).Scan(&bindings); err != nil || bindings != 0 {
		t.Fatalf("stale binding persisted: %d %v", bindings, err)
	}
}

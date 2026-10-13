//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediationruntime"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// m15PoolStats makes client-pool queueing visible in the effect measurement.
// It is deliberately test-only: ClaimDueSourceJob latency includes acquiring a
// connection from this pool as well as the database operation itself.
type m15PoolStats struct {
	maxConns             int32
	totalConns           int32
	acquireCount         int64
	emptyAcquireCount    int64
	acquireDuration      time.Duration
	emptyAcquireWaitTime time.Duration
}

func m15ReadPoolStats(pool *pgxpool.Pool) m15PoolStats {
	stats := pool.Stat()
	return m15PoolStats{
		maxConns:             stats.MaxConns(),
		totalConns:           stats.TotalConns(),
		acquireCount:         stats.AcquireCount(),
		emptyAcquireCount:    stats.EmptyAcquireCount(),
		acquireDuration:      stats.AcquireDuration(),
		emptyAcquireWaitTime: stats.EmptyAcquireWaitTime(),
	}
}

// TestM15OperationalScheduleOnlyBaseline measures the existing scheduler with
// remediation disabled. It deliberately does not claim collection E2E
// throughput: no source, collector, result ingestion, repair queue, or
// verification is involved in this control lane.
func TestM15OperationalScheduleOnlyBaseline(t *testing.T) {
	if os.Getenv("SHERLOCK_ENABLE_M15_PERF") != "1" {
		t.Skip("set SHERLOCK_ENABLE_M15_PERF=1")
	}
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT remediation_enabled FROM remediation_global_state WHERE id=true`).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE remediation_global_state SET remediation_enabled=false WHERE id=true`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `UPDATE remediation_global_state SET remediation_enabled=$1 WHERE id=true`, enabled)
	}()
	store, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("m15-perf-%d", time.Now().UnixNano())
	cluster, source := domain.ClusterID("cluster-"+suffix), domain.SourceID("source-"+suffix)
	if err := store.EnsureSource(ctx, cluster, "M15 performance fixture", source, "fixture"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, query := range []string{`DELETE FROM schedule_repair_decisions WHERE cluster_id=$1`, `DELETE FROM collection_jobs WHERE cluster_id=$1`, `DELETE FROM sources WHERE cluster_id=$1`, `DELETE FROM clusters WHERE cluster_id=$1`} {
			if _, err := pool.Exec(context.Background(), query, cluster); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
	}()
	const jobs, workers = 400, 4
	for i := 0; i < jobs; i++ {
		if err := store.EnsureJob(ctx, fmt.Sprintf("%s-job-%03d", suffix, i), cluster, source, domain.QueryGPUUtilization, fmt.Sprintf("node-%03d", i), time.Hour, time.Now().Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	latencies := make([]time.Duration, 0, jobs)
	seen := make(map[string]struct{}, jobs)
	var mu sync.Mutex
	var claimErrors, completeErrors, lockWaitSamples atomic.Int64
	stopLocks := make(chan struct{})
	var lockWG sync.WaitGroup
	lockWG.Add(1)
	go func() {
		defer lockWG.Done()
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopLocks:
				return
			case <-ticker.C:
				var waiting int64
				if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation WHERE c.relname='collection_jobs' AND NOT l.granted`).Scan(&waiting); err == nil && waiting > 0 {
					lockWaitSamples.Add(1)
				}
			}
		}
	}()
	started := time.Now()
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			owner := fmt.Sprintf("m15-perf-worker-%d", worker)
			for {
				before := time.Now()
				job, found, err := store.ClaimDueSourceJob(ctx, owner, time.Minute, source)
				if err != nil {
					claimErrors.Add(1)
					return
				}
				if !found {
					return
				}
				elapsed := time.Since(before)
				mu.Lock()
				if _, duplicate := seen[job.JobID]; duplicate {
					claimErrors.Add(1)
				}
				seen[job.JobID] = struct{}{}
				latencies = append(latencies, elapsed)
				mu.Unlock()
				if err := store.CompleteJob(ctx, job, owner); err != nil {
					completeErrors.Add(1)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	wall := time.Since(started)
	close(stopLocks)
	lockWG.Wait()
	if len(latencies) != jobs || claimErrors.Load() != 0 || completeErrors.Load() != 0 {
		t.Fatalf("jobs=%d claims=%d claim_errors=%d complete_errors=%d", jobs, len(latencies), claimErrors.Load(), completeErrors.Load())
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p := func(n int) time.Duration { return latencies[(len(latencies)*n-1)/100] }
	throughput := float64(jobs) / wall.Seconds()
	fmt.Printf("M15_PERF lane=schedule_only remediation=disabled jobs=%d workers=%d claim_p50_ms=%.3f claim_p95_ms=%.3f claim_p99_ms=%.3f claim_max_ms=%.3f wall_ms=%.3f throughput_jobs_per_s=%.3f lock_wait_samples=%d errors=0 samples=0 verification_delay_ms=not_applicable\n", jobs, workers, float64(p(50).Microseconds())/1000, float64(p(95).Microseconds())/1000, float64(p(99).Microseconds())/1000, float64(latencies[len(latencies)-1].Microseconds())/1000, float64(wall.Microseconds())/1000, throughput, lockWaitSamples.Load())
	// These limits were declared from the fresh baseline in M15_PERFORMANCE.md
	// before an enabled comparison. They are deliberately local-fixture guards,
	// not production capacity claims.
	if p(95) > 5500*time.Microsecond || throughput < 900 || lockWaitSamples.Load() > 2 {
		t.Fatalf("schedule-only limit exceeded: p95=%s throughput=%.3f/s lock_wait_samples=%d", p(95), throughput, lockWaitSamples.Load())
	}
}

// TestM15OperationalLiveIdleScheduleComparison runs the same scheduler control
// with the real LIVE supervisor polling concurrently. No collector, policy, or
// eligible stale stream is seeded, so this is explicitly an idle/detector
// overhead comparison, not a repair-effect contention measurement.
func TestM15OperationalLiveIdleScheduleComparison(t *testing.T) {
	if os.Getenv("SHERLOCK_ENABLE_M15_PERF") != "1" {
		t.Skip("set SHERLOCK_ENABLE_M15_PERF=1")
	}
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("m15-live-idle-%d", time.Now().UnixNano())
	cluster, source := domain.ClusterID("cluster-"+suffix), domain.SourceID("source-"+suffix)
	if err := store.EnsureSource(ctx, cluster, "M15 live idle fixture", source, "fixture"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, query := range []string{`DELETE FROM schedule_repair_decisions WHERE cluster_id=$1`, `DELETE FROM collection_jobs WHERE cluster_id=$1`, `DELETE FROM sources WHERE cluster_id=$1`, `DELETE FROM clusters WHERE cluster_id=$1`} {
			if _, err := pool.Exec(context.Background(), query, cluster); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
		_, _ = pool.Exec(context.Background(), `UPDATE remediation_global_state SET remediation_enabled=false WHERE id=true`)
	}()
	if _, err := pool.Exec(ctx, `UPDATE remediation_global_state SET remediation_enabled=true WHERE id=true`); err != nil {
		t.Fatal(err)
	}
	runtime, err := remediationruntime.New(pool, m15LiveCatalog(t, time.Now().UTC()), remediationruntime.Config{Enabled: true, Live: true, ClusterID: cluster, Owner: "m15-perf-supervisor", PollInterval: 10 * time.Millisecond, Lease: time.Second, Batch: 1}, slog.New(slog.NewTextHandler(testLogWriter{t}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	const jobs, workers = 400, 4
	for i := 0; i < jobs; i++ {
		if err := store.EnsureJob(ctx, fmt.Sprintf("%s-job-%03d", suffix, i), cluster, source, domain.QueryGPUUtilization, fmt.Sprintf("node-%03d", i), time.Hour, time.Now().Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := runtime.RunOnce(ctx); err != nil {
		t.Fatalf("initial live supervisor iteration: %v", err)
	}
	supervisorCtx, stopSupervisor := context.WithCancel(ctx)
	var supervisorErrors atomic.Int64
	var firstSupervisorError atomic.Value
	var supervisorWG sync.WaitGroup
	supervisorWG.Add(1)
	go func() {
		defer supervisorWG.Done()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			if _, err := runtime.RunOnce(supervisorCtx); err != nil && !errors.Is(err, context.Canceled) {
				supervisorErrors.Add(1)
				firstSupervisorError.CompareAndSwap(nil, err.Error())
			}
			select {
			case <-supervisorCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	latencies := make([]time.Duration, 0, jobs)
	seen := make(map[string]struct{}, jobs)
	var mu sync.Mutex
	var claimErrors, completeErrors, lockWaitSamples atomic.Int64
	stopLocks := make(chan struct{})
	var lockWG sync.WaitGroup
	lockWG.Add(1)
	go func() {
		defer lockWG.Done()
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopLocks:
				return
			case <-ticker.C:
				var waiting int64
				if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation WHERE c.relname='collection_jobs' AND NOT l.granted`).Scan(&waiting); err == nil && waiting > 0 {
					lockWaitSamples.Add(1)
				}
			}
		}
	}()
	started := time.Now()
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			owner := fmt.Sprintf("m15-live-idle-worker-%d", worker)
			for {
				before := time.Now()
				job, found, err := store.ClaimDueSourceJob(ctx, owner, time.Minute, source)
				if err != nil {
					claimErrors.Add(1)
					return
				}
				if !found {
					return
				}
				elapsed := time.Since(before)
				mu.Lock()
				if _, duplicate := seen[job.JobID]; duplicate {
					claimErrors.Add(1)
				}
				seen[job.JobID] = struct{}{}
				latencies = append(latencies, elapsed)
				mu.Unlock()
				if err := store.CompleteJob(ctx, job, owner); err != nil {
					completeErrors.Add(1)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	wall := time.Since(started)
	close(stopLocks)
	lockWG.Wait()
	stopSupervisor()
	supervisorWG.Wait()
	if len(latencies) != jobs || claimErrors.Load() != 0 || completeErrors.Load() != 0 {
		t.Fatalf("jobs=%d claims=%d claim_errors=%d complete_errors=%d", jobs, len(latencies), claimErrors.Load(), completeErrors.Load())
	}
	var requests int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM collection_repair_requests WHERE cluster_id=$1`, cluster).Scan(&requests); err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("idle comparison unexpectedly created %d repair requests", requests)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p := func(n int) time.Duration { return latencies[(len(latencies)*n-1)/100] }
	throughput := float64(jobs) / wall.Seconds()
	firstError := ""
	if value := firstSupervisorError.Load(); value != nil {
		firstError = value.(string)
	}
	fmt.Printf("M15_PERF lane=live_idle remediation=enabled jobs=%d workers=%d claim_p50_ms=%.3f claim_p95_ms=%.3f claim_p99_ms=%.3f claim_max_ms=%.3f wall_ms=%.3f throughput_jobs_per_s=%.3f lock_wait_samples=%d scheduler_errors=%d supervisor_errors=%d supervisor_first_error=%q repair_requests=0 samples=0 verification_delay_ms=not_applicable\n", jobs, workers, float64(p(50).Microseconds())/1000, float64(p(95).Microseconds())/1000, float64(p(99).Microseconds())/1000, float64(latencies[len(latencies)-1].Microseconds())/1000, float64(wall.Microseconds())/1000, throughput, lockWaitSamples.Load(), claimErrors.Load()+completeErrors.Load(), supervisorErrors.Load(), firstError)
	if p(95) > 5500*time.Microsecond || throughput < 900 || lockWaitSamples.Load() > 2 {
		t.Fatalf("live-idle scheduler limit exceeded: p95=%s throughput=%.3f/s lock_wait_samples=%d", p(95), throughput, lockWaitSamples.Load())
	}
}

// TestM15OperationalEffectContention overlaps ordinary scheduler claiming with
// the principal autonomous repair after its worker has durably claimed the
// repair request and before the real collector is allowed to receive it.
func TestM15OperationalEffectContention(t *testing.T) {
	if os.Getenv("SHERLOCK_ENABLE_M15_PERF") != "1" {
		t.Skip("set SHERLOCK_ENABLE_M15_PERF=1")
	}
	if os.Getenv("SHERLOCK_TEST_DATABASE_URL") == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set")
	}
	var effectLoad m15SchedulerContentionLoad
	var effectMetrics m15SchedulerContentionMetrics
	var effectWaitErr error
	var effectAvailableBefore, effectAvailableAfter int
	var lockWaitSamples atomic.Int64
	var poolBefore, poolAfter m15PoolStats
	lockStop := make(chan struct{})
	var lockWG sync.WaitGroup
	var verificationAt time.Time
	effectPrefix := fmt.Sprintf("m15-effect-contention-%d", time.Now().UnixNano())
	result := m15RunRecovery(t, m15RecoveryHooks{
		BeforePreflight: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, result m15RecoveryResult) {
			t.Helper()
			store, err := storepg.NewCollectionStore(pool)
			if err != nil {
				t.Fatal(err)
			}
			if err := m15PreseedSchedulerContention(ctx, store, result.ClusterID, result.SourceID, effectPrefix, 400); err != nil {
				t.Fatal(err)
			}
		},
		BeforeEffect: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, result m15RecoveryResult) {
			t.Helper()
			poolBefore = m15ReadPoolStats(pool)
			store, err := storepg.NewCollectionStore(pool)
			if err != nil {
				t.Fatal(err)
			}
			effectLoad = m15StartPreseededSchedulerContention(ctx, store, result.SourceID, effectPrefix, 400, 4)
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM collection_jobs WHERE cluster_id=$1 AND job_id LIKE $2 AND active AND next_run_at<=clock_timestamp()`, result.ClusterID, effectPrefix+"%").Scan(&effectAvailableBefore); err != nil {
				t.Fatal(err)
			}
			lockWG.Add(1)
			go func() {
				defer lockWG.Done()
				ticker := time.NewTicker(time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-lockStop:
						return
					case <-ticker.C:
						var waiting int64
						if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation WHERE c.relname='collection_jobs' AND NOT l.granted`).Scan(&waiting); err == nil && waiting > 0 {
							lockWaitSamples.Add(1)
						}
					}
				}
			}()
		},
		AfterVerification: func(_ *testing.T, ctx context.Context, pool *pgxpool.Pool, result m15RecoveryResult) {
			verificationAt = result.VerificationObservedAt
			effectMetrics, effectWaitErr = effectLoad.Wait(ctx)
			poolAfter = m15ReadPoolStats(pool)
			close(lockStop)
			lockWG.Wait()
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM collection_jobs WHERE cluster_id=$1 AND job_id LIKE $2 AND active AND next_run_at<=clock_timestamp()`, result.ClusterID, effectPrefix+"%").Scan(&effectAvailableAfter); err != nil {
				t.Fatal(err)
			}
		},
	})
	if result.EffectCommittedAt.IsZero() || verificationAt.IsZero() || result.RepairSampleCount != 1 {
		t.Fatalf("effect=%s verification=%s samples=%d", result.EffectCommittedAt, verificationAt, result.RepairSampleCount)
	}
	for _, lane := range []struct {
		name    string
		metrics m15SchedulerContentionMetrics
		err     error
	}{{"effect", effectMetrics, effectWaitErr}} {
		metrics := lane.metrics
		if lane.err != nil {
			t.Fatal(lane.err)
		}
		if len(metrics.ClaimLatencies) != 400 || metrics.ClaimErrors != 0 || metrics.CompletionErrors != 0 {
			t.Fatalf("%s claims=%d claim_errors=%d completion_errors=%d effect_due_before=%d effect_due_after=%d", lane.name, len(metrics.ClaimLatencies), metrics.ClaimErrors, metrics.CompletionErrors, effectAvailableBefore, effectAvailableAfter)
		}
		p := func(n int) time.Duration { return metrics.ClaimLatencies[(len(metrics.ClaimLatencies)*n-1)/100] }
		throughput := float64(metrics.Jobs) / metrics.Elapsed.Seconds()
		fmt.Printf("M15_PERF lane=live_%s_contention jobs=%d workers=%d claim_p50_ms=%.3f claim_p95_ms=%.3f claim_p99_ms=%.3f claim_max_ms=%.3f wall_ms=%.3f throughput_jobs_per_s=%.3f lock_wait_samples=%d scheduler_errors=0 pool_max_conns=%d pool_total_conns_before=%d pool_total_conns_after=%d pool_acquires=%d pool_empty_acquires=%d pool_acquire_wait_ms=%.3f pool_acquire_total_ms=%.3f repair_request=%s collector_work=%s evidence=%s repair_samples=%d effect_to_verification_ms=%.3f\n", lane.name, metrics.Jobs, metrics.Workers, float64(p(50).Microseconds())/1000, float64(p(95).Microseconds())/1000, float64(p(99).Microseconds())/1000, float64(metrics.ClaimLatencies[len(metrics.ClaimLatencies)-1].Microseconds())/1000, float64(metrics.Elapsed.Microseconds())/1000, throughput, lockWaitSamples.Load(), poolBefore.maxConns, poolBefore.totalConns, poolAfter.totalConns, poolAfter.acquireCount-poolBefore.acquireCount, poolAfter.emptyAcquireCount-poolBefore.emptyAcquireCount, float64((poolAfter.emptyAcquireWaitTime-poolBefore.emptyAcquireWaitTime).Microseconds())/1000, float64((poolAfter.acquireDuration-poolBefore.acquireDuration).Microseconds())/1000, result.RepairRequestID, result.CollectorWorkID, result.EvidenceID, result.RepairSampleCount, float64(verificationAt.Sub(result.EffectCommittedAt).Microseconds())/1000)
		if p(95) > 5500*time.Microsecond || throughput < 900 || lockWaitSamples.Load() > 2 {
			t.Fatalf("effect contention scheduler limit exceeded: p95=%s throughput=%.3f/s lock_wait_samples=%d", p(95), throughput, lockWaitSamples.Load())
		}
	}
}

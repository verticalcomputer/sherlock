//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// TestM15SchedulerClaimCompleteBaseline measures the current SQL claim and
// completion path with four concurrent workers. The thresholds are intentionally
// generous acceptance guards derived from the first local baseline run.
func TestM15SchedulerClaimCompleteBaseline(t *testing.T) {
	if os.Getenv("SHERLOCK_ENABLE_M15_PERF") != "1" {
		t.Skip("set SHERLOCK_ENABLE_M15_PERF=1 to run timing-sensitive benchmark")
	}
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set")
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
	suffix := fmt.Sprintf("m15-%d", time.Now().UnixNano())
	cluster, source := domain.ClusterID("cluster-"+suffix), domain.SourceID("source-"+suffix)
	if err := store.EnsureSource(ctx, cluster, "M15 scheduler benchmark", source, "benchmark"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(ctx, `DELETE FROM collection_jobs WHERE cluster_id=$1`, cluster); err != nil {
			t.Errorf("cleanup jobs: %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM sources WHERE cluster_id=$1`, cluster); err != nil {
			t.Errorf("cleanup source: %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM clusters WHERE cluster_id=$1`, cluster); err != nil {
			t.Errorf("cleanup cluster: %v", err)
		}
	}()
	first := time.Now().UTC().Add(-time.Minute)
	const jobs = 400
	for i := 0; i < jobs; i++ {
		if err := store.EnsureJob(ctx, fmt.Sprintf("%s-job-%04d", suffix, i), cluster, source, domain.QueryGPUUtilization, fmt.Sprintf("node-%04d", i), time.Hour, first); err != nil {
			t.Fatal(err)
		}
	}
	latencies := make([]time.Duration, 0, jobs)
	claimedIDs := make(map[string]bool, jobs)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for {
				started := time.Now()
				job, found, claimErr := store.ClaimDueSourceJob(ctx, fmt.Sprintf("m15-worker-%d", worker), time.Minute, source)
				if claimErr != nil {
					t.Errorf("claim: %v", claimErr)
					return
				}
				if !found {
					return
				}
				elapsed := time.Since(started)
				mu.Lock()
				if claimedIDs[job.JobID] {
					t.Errorf("duplicate claim: %s", job.JobID)
				}
				claimedIDs[job.JobID] = true
				latencies = append(latencies, elapsed)
				mu.Unlock()
				if err := store.CompleteJob(ctx, job, fmt.Sprintf("m15-worker-%d", worker)); err != nil {
					t.Errorf("complete %s: %v", job.JobID, err)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	if len(claimedIDs) != jobs {
		t.Fatalf("claimed %d jobs, want %d", len(claimedIDs), jobs)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p := func(percent int) time.Duration { return latencies[(len(latencies)*percent-1)/100] }
	total := time.Duration(0)
	for _, d := range latencies {
		total += d
	}
	throughput := float64(jobs) / total.Seconds()
	fmt.Printf("M15 scheduler baseline jobs=%d workers=4 claim_p50_ms=%.3f claim_p95_ms=%.3f claim_p99_ms=%.3f claim_max_ms=%.3f claim_throughput_per_s=%.3f\n", jobs, float64(p(50).Microseconds())/1000, float64(p(95).Microseconds())/1000, float64(p(99).Microseconds())/1000, float64(latencies[len(latencies)-1].Microseconds())/1000, throughput)
	if p(95) > 20*time.Millisecond || throughput < 237 {
		t.Fatalf("scheduler baseline outside acceptance threshold: p95=%s throughput=%.3f/s", p(95), throughput)
	}
}

//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"os"
	"testing"
	"time"
)

func TestBacklogCoalescesAndExpiresOrdinaryWork(t *testing.T) {
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx := context.Background()
	p, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	s, _ := storepg.NewCollectionStore(p)
	c, _ := storepg.NewCollectorControlStore(p)
	id := fmt.Sprintf("backlog-%d", time.Now().UnixNano())
	cluster := domain.ClusterID(id)
	source := domain.SourceID(id)
	if err = s.EnsureSource(ctx, cluster, id, source, id); err != nil {
		t.Fatal(err)
	}
	origin := time.Now().UTC().Add(-8 * time.Hour).Truncate(time.Microsecond)
	if err = s.EnsureJob(ctx, id, cluster, source, domain.QueryGPUUtilization, "", 30*time.Second, origin); err != nil {
		t.Fatal(err)
	}
	job, found, err := s.ClaimDueSourceJob(ctx, id, time.Minute, source)
	if err != nil || !found {
		t.Fatalf("claim: %v %v", found, err)
	}
	if err = s.CompleteJob(ctx, job, id); err != nil {
		t.Fatal(err)
	}
	var future, aligned bool
	err = p.QueryRow(ctx, `SELECT next_run_at>clock_timestamp(),mod(extract(epoch FROM(next_run_at-$2::timestamptz)),30)=0 FROM collection_jobs WHERE job_id=$1`, id, origin).Scan(&future, &aligned)
	if err != nil || !future || !aligned {
		t.Fatalf("coalesced cadence: future=%v aligned=%v err=%v", future, aligned, err)
	}
	if err = s.CompleteJob(ctx, job, id); err == nil {
		t.Fatal("stale completion accepted")
	}
	_, err = p.Exec(ctx, `INSERT INTO collectors(collector_id,cluster_id,display_name,version,build_commit,protocol_min,protocol_max,operating_system,architecture) VALUES($1,$1,$1,'test','test',1,1,'linux','amd64')`, id)
	if err != nil {
		t.Fatal(err)
	}
	// 300 expired rows exercise the 256-row bound. One unexpired attempt must survive.
	_, err = p.Exec(ctx, `INSERT INTO collector_work_items(work_id,run_id,cluster_id,source_id,query_kind,scheduled_for,deadline,max_series,max_bytes,idempotency_key,available_at,work_expires_at)
 SELECT $1||'-'||n,$1||'-'||n,$1,$1,'dcgm_gpu_utilization',now()-interval '2 hours',now()-interval '1 hour',80,10000,$1||'-'||n,now()-interval '2 hours',now()-interval '1 hour' FROM generate_series(1,301)n`, id)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Exec(ctx, `UPDATE collector_work_items SET status='LEASED',next_attempt=2 WHERE work_id=$1||'-301';`, id)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Exec(ctx, `INSERT INTO collector_work_attempts(work_id,attempt,collector_id,lease_token_hash,lease_expires_at) VALUES($1||'-301',1,$1,decode(repeat('00',32),'hex'),now()+interval '1 hour')`, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = c.ClaimWork(ctx, domain.CollectorID(id), "test-token", time.Minute); err != nil {
		t.Fatal(err)
	}
	var failed int
	if err = p.QueryRow(ctx, `SELECT count(*) FROM collector_work_items WHERE cluster_id=$1 AND status='FAILED'`, id).Scan(&failed); err != nil || failed != 256 {
		t.Fatalf("bound failed=%d err=%v", failed, err)
	}
	if _, _, err = c.ClaimWork(ctx, domain.CollectorID(id), "test-token", time.Minute); err != nil {
		t.Fatal(err)
	}
	var retained int
	err = p.QueryRow(ctx, `SELECT count(*) FROM collector_work_items WHERE cluster_id=$1 AND (status='FAILED' AND completed_at IS NOT NULL OR work_id=$1||'-301' AND status='LEASED')`, id).Scan(&retained)
	if err != nil || retained != 301 {
		t.Fatalf("retained=%d err=%v", retained, err)
	}
}

//go:build integration

package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestM15RepairWorkerTakeoverFencesOldGeneration(t *testing.T) {
	m15RunRecovery(t, m15RecoveryHooks{StopAfterRequest: true, AfterRequest: func(t *testing.T, ctx context.Context, p *pgxpool.Pool, r m15RecoveryResult) {
		s, err := storepg.NewRemediationStore(p)
		if err != nil {
			t.Fatal(err)
		}
		first, found, err := s.ClaimRepairCollection(ctx, r.ClusterID, r.SourceID, "same-worker", time.Minute)
		if err != nil || !found {
			t.Fatalf("first claim found=%v err=%v", found, err)
		}
		if _, err = p.Exec(ctx, `UPDATE collection_repair_requests SET lease_expires_at=clock_timestamp()-interval '1 millisecond' WHERE request_id=$1`, first.RequestID); err != nil {
			t.Fatal(err)
		}
		second, found, err := s.ClaimRepairCollection(ctx, r.ClusterID, r.SourceID, "same-worker", time.Minute)
		if err != nil || !found {
			t.Fatalf("takeover found=%v err=%v", found, err)
		}
		if first.RequestID != second.RequestID || second.Generation != first.Generation+1 {
			t.Fatalf("takeover generations %d/%d", first.Generation, second.Generation)
		}
		if err = s.FinishRepairCollection(ctx, first, "same-worker"); err == nil {
			t.Fatal("stale generation completed active request")
		}
		var generation int64
		var requests, work int
		if err = p.QueryRow(ctx, `SELECT worker_generation,(SELECT count(*) FROM collection_repair_requests WHERE run_id=$2),(SELECT count(*) FROM collector_work_items WHERE run_id=$1) FROM collection_repair_requests WHERE request_id=$1`, first.RequestID, r.RemediationRun).Scan(&generation, &requests, &work); err != nil {
			t.Fatal(err)
		}
		if generation != second.Generation || requests != 1 || work != 1 {
			t.Fatalf("generation=%d requests=%d work=%d", generation, requests, work)
		}
	}})
}

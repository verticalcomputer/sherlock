//go:build integration

package adminmanage_test

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"os"
	"testing"
	"time"
)

func TestRepairOverviewScopeRedactionAndUnavailable(t *testing.T) {
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated migrated database required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := adminmanage.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	a, b := "repair-admin-a-"+suffix, "repair-admin-b-"+suffix
	for _, c := range []string{a, b} {
		mustExec(t, pool, `INSERT INTO clusters(cluster_id,display_name) VALUES($1,'Fixture')`, c)
		mustExec(t, pool, `INSERT INTO sources(source_id,cluster_id,kind,display_name) VALUES($1,$1,'prometheus','Fixture')`, c)
		mustExec(t, pool, `INSERT INTO collection_jobs(job_id,cluster_id,source_id,query_kind,interval_seconds,next_run_at) VALUES($1,$1,$1,'GPU_HEALTH',60,clock_timestamp())`, c)
		code := "SOURCE_UNAVAILABLE"
		if c == b {
			code = "unreviewed-sensitive-value"
		}
		mustExec(t, pool, `INSERT INTO schedule_repair_decisions(cluster_id,job_id,code,observed_at) VALUES($1,$1,$2,clock_timestamp())`, c, code)
	}
	scoped, err := store.ListClusterOperations(ctx, a, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !scoped.Repairs.Available || len(scoped.Repairs.Decisions) != 1 || scoped.Repairs.Decisions[0].Code != "SOURCE_UNAVAILABLE" || scoped.Repairs.Decisions[0].Count != 1 {
		t.Fatalf("scoped repair view: %+v", scoped.Repairs)
	}
	other, err := store.ListClusterOperations(ctx, b, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(other.Repairs.Decisions) != 1 || other.Repairs.Decisions[0].Code != "OTHER" {
		t.Fatalf("unreviewed code leaked: %+v", other.Repairs)
	}
	// Hold the repair relation exclusively; a bounded snapshot must return
	// unavailable while ordinary tickets/investigations still render.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `LOCK TABLE collection_repair_requests IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	blocked, err := store.ListClusterOperations(ctx, a, 10)
	if err != nil || blocked.Repairs.Available || time.Since(start) > 2*time.Second {
		t.Fatalf("blocked snapshot available=%v err=%v duration=%v", blocked.Repairs.Available, err, time.Since(start))
	}
}

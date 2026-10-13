//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestM15PopulationFenceAllowsScheduleProgress(t *testing.T) {
	f := newRemediationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err = storepg.LockRepairAuthority(ctx, tx, f.clusterID); err != nil {
		t.Fatal(err)
	}
	// All membership/configuration writers refuse while a live authority
	// decision holds its fence. They never wait while retaining a target row.
	for _, query := range []string{
		`UPDATE collection_jobs SET active=NOT active WHERE cluster_id=$1 AND job_id=$2`,
		`UPDATE collection_jobs SET node_filter=node_filter||'-changed' WHERE cluster_id=$1 AND job_id=$2`,
		`UPDATE collection_jobs SET interval_seconds=interval_seconds+1 WHERE cluster_id=$1 AND job_id=$2`,
		`DELETE FROM collection_jobs WHERE cluster_id=$1 AND job_id=$2`,
		`INSERT INTO collection_jobs(job_id,cluster_id,source_id,query_kind,node_filter,interval_seconds,next_run_at) SELECT job_id||'-new',cluster_id,source_id,query_kind,node_filter||'-new',interval_seconds,next_run_at FROM collection_jobs WHERE cluster_id=$1 AND job_id=$2`,
	} {
		_, err := f.pool.Exec(ctx, query, f.clusterID, f.targets[0])
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "40001" {
			t.Fatalf("configuration writer was not fenced: %v", err)
		}
	}
	// Normal scheduling is not a population/configuration change, and must
	// progress while the fence remains held.
	if _, err = f.pool.Exec(ctx, `UPDATE collection_jobs SET next_run_at=next_run_at+interval '1 minute' WHERE cluster_id=$1 AND job_id=$2`, f.clusterID, f.targets[0]); err != nil {
		t.Fatalf("ordinary schedule blocked: %v", err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(ctx, `UPDATE collection_jobs SET interval_seconds=interval_seconds+1 WHERE cluster_id=$1 AND job_id=$2`, f.clusterID, f.targets[0]); err != nil {
		t.Fatalf("configuration writer did not recover after fence: %v", err)
	}
}

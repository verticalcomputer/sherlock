//go:build integration

package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestDiagnosticAttemptFinalizationUsesPostgreSQLClock(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)

	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("m12-completion-cluster-" + suffix)
	runID := domain.DiagnosticRunID("m12-completion-run-" + suffix)
	workID := domain.DiagnosticWorkID("m12-completion-work-" + suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := domain.ChecksumSHA256([]byte(suffix))
	if _, err := tx.Exec(ctx, `INSERT INTO clusters (cluster_id,display_name) VALUES ($1,'M12 completion test')`, clusterID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO diagnostic_runs (run_id,cluster_id,pack_id,pack_version,definition_id,definition_version,definition_digest,privilege,status,requested_by,idempotency_key,requested_at,deadline,max_attempts) VALUES ($1,$2,'standard.readonly','1.2.0','gpu.ecc_counters','1.0.0',$3,'UNPRIVILEGED','RUNNING','test',$4,$5,$6,1)`, runID, clusterID, digest[:], "m12-completion-"+suffix, now.Add(-time.Minute), now.Add(50*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO diagnostic_work_items (work_id,run_id,status,available_at,deadline,max_attempts,next_attempt) VALUES ($1,$2,'LEASED',$3,$4,1,2)`, workID, runID, now.Add(-time.Minute), now.Add(50*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO diagnostic_work_attempts (work_id,attempt,runner_id,lease_token_hash,lease_expires_at,status,plan_digest,started_at) VALUES ($1,1,'head-test',$2,$3,'RUNNING',$2,$4)`, workID, digest[:], now.Add(time.Minute), now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	// Deliberately put the collector clock far ahead. Authorization must not use
	// this value as its persistence-order authority.
	terminalAt := now.Add(10 * time.Minute)
	if _, err := tx.Exec(ctx, `UPDATE diagnostic_runs SET status='SUCCEEDED',completed_at=$2 WHERE run_id=$1`, runID, terminalAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE diagnostic_work_items SET status='SUCCEEDED' WHERE work_id=$1`, workID); err != nil {
		t.Fatal(err)
	}
	var finalizedAt time.Time
	if err := tx.QueryRow(ctx, `UPDATE diagnostic_work_attempts SET status='SUCCEEDED',completed_at=$3,finalized_at=clock_timestamp() WHERE work_id=$1 AND attempt=$2 RETURNING finalized_at`, workID, 1, terminalAt).Scan(&finalizedAt); err != nil {
		t.Fatal(err)
	}
	if !finalizedAt.Before(terminalAt) {
		t.Fatalf("PostgreSQL finalization=%s unexpectedly followed remote future completion=%s", finalizedAt, terminalAt)
	}
	var completedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT completed_at FROM diagnostic_work_attempts WHERE work_id=$1 AND attempt=1`, workID).Scan(&completedAt); err != nil {
		t.Fatal(err)
	}
	if !completedAt.Equal(terminalAt) {
		t.Fatalf("collector completion=%s want preserved observation=%s", completedAt, terminalAt)
	}
}

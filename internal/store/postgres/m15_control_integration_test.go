//go:build integration

package postgres_test

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediationruntime"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

func TestM15OperatorControlNeverStealsOrRedispatches(t *testing.T) {
	for _, operation := range []string{"cancel", "rollback"} {
		t.Run(operation, func(t *testing.T) {
			result := m15RunRecovery(t, m15RecoveryHooks{StopAfterRequest: true})
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			pool := m15SecurityPool(t, ctx)
			defer pool.Close()
			store, err := storepg.NewRemediationStore(pool)
			if err != nil {
				t.Fatal(err)
			}
			rt, err := remediationruntime.New(pool, result.Catalog, remediationruntime.Config{Enabled: true, Live: true, ClusterID: result.ClusterID, Owner: "m15-control", PollInterval: 10 * time.Millisecond, Lease: 10 * time.Second, Batch: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			if operation == "cancel" {
				verifyM15PolicyArtifact(t, ctx, pool, result)
			}
			run := domain.RemediationRunID(result.RemediationRun)
			held, err := store.ClaimRemediationControl(ctx, result.ClusterID, run, "existing-owner", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if err = rt.Control(ctx, operation, run); err == nil {
				t.Fatal("control stole active lease")
			}
			if err = store.ReleaseRemediation(ctx, result.ClusterID, held, 0); err != nil {
				t.Fatal(err)
			}
			if err = rt.Control(ctx, operation, run); err != nil {
				t.Fatal(err)
			}
			if err = rt.Control(ctx, "reconcile", run); err != nil {
				t.Fatal(err)
			}
			var requests, work int
			var state string
			if err = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM collection_repair_requests WHERE run_id=$1),(SELECT count(*) FROM collector_work_items WHERE run_id=$2),(SELECT state FROM remediation_runs WHERE run_id=$1)`, run, result.RepairRequestID).Scan(&requests, &work, &state); err != nil {
				t.Fatal(err)
			}
			if requests != 1 || work != 1 {
				t.Fatalf("control duplicated effects requests=%d work=%d", requests, work)
			}
			if operation == "cancel" && state != "CONTAINED" {
				t.Fatalf("cancel state=%s", state)
			}
			if operation == "rollback" && state != "ROLLED_BACK" {
				t.Fatalf("rollback state=%s", state)
			}
		})
	}
}

func verifyM15PolicyArtifact(t *testing.T, ctx context.Context, pool *pgxpool.Pool, result m15RecoveryResult) {
	t.Helper()
	b, err := os.ReadFile("../../../deploy/pilot/m15/policy.one-stream.example.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, body, ok := strings.Cut(string(b), " AS\n")
	if !ok {
		t.Fatal("policy prepared statement missing")
	}
	statement, _, ok := strings.Cut(body, ";")
	if !ok {
		t.Fatal("policy statement terminator missing")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, statement, result.ClusterID, "policy-artifact-rehearsal", 100, time.Now().UTC(), time.Now().UTC().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var enabled bool
	var recipe, version string
	var targets int
	if err = tx.QueryRow(ctx, `SELECT enabled,recipe_id,recipe_version,max_targets FROM remediation_policies WHERE cluster_id=$1 AND policy_id='policy-artifact-rehearsal'`, result.ClusterID).Scan(&enabled, &recipe, &version, &targets); err != nil {
		t.Fatal(err)
	}
	if enabled || recipe != "sherlock.evidence-collection-requeue" || version != "2.0.0" || targets != 1 {
		t.Fatal("invalid pilot policy")
	}
}

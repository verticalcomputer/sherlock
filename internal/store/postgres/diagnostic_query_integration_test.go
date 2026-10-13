//go:build integration

package postgres_test

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestDiagnosticRunProjectionIsClusterScopedAndContainsOnlySafeResults(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := storepg.NewDiagnosticQueryStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	queries, err := application.NewDiagnosticQueries(store)
	if err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("diagnostic-query-cluster-" + suffix)
	otherClusterID := domain.ClusterID("diagnostic-query-other-" + suffix)
	runID := domain.DiagnosticRunID("diagnostic-query-run-" + suffix)
	workID := domain.DiagnosticWorkID("diagnostic-query-work-" + suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)
	definitionDigest := domain.ChecksumSHA256([]byte("signed definition"))
	planDigest := domain.ChecksumSHA256([]byte("exact execution plan"))
	emptyDigest := domain.ChecksumSHA256(nil)
	stdoutDigest := domain.ChecksumSHA256([]byte("redacted artifact bytes"))
	leaseHash := domain.ChecksumSHA256([]byte("lease token not returned"))

	if _, err := pool.Exec(ctx, `INSERT INTO clusters (cluster_id, display_name) VALUES ($1,'Diagnostic query cluster'),($2,'Other cluster')`, clusterID, otherClusterID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM diagnostic_target_results WHERE work_id=$1`, workID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM diagnostic_work_attempts WHERE work_id=$1`, workID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM diagnostic_work_items WHERE work_id=$1`, workID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM diagnostic_run_targets WHERE run_id=$1`, runID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM diagnostic_runs WHERE run_id=$1`, runID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM clusters WHERE cluster_id IN ($1,$2)`, clusterID, otherClusterID)
	}()
	if _, err := pool.Exec(ctx, `
		INSERT INTO diagnostic_runs (
			run_id, cluster_id, pack_id, pack_version, definition_id, definition_version,
			definition_digest, privilege, status, requested_by, idempotency_key,
			arguments, requested_at, deadline, max_attempts, version, completed_at
		) VALUES ($1,$2,'base','1.0.0','gpu-query','1.0.0',$3,'PRIVILEGED','SUCCEEDED',
			'actor-1',$4,'[{"Name":"query","Value":"temperature"}]'::jsonb,$5,$6,2,3,$7)`,
		runID, clusterID, definitionDigest[:], "diagnostic-query-request-"+suffix,
		now, now.Add(10*time.Minute), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO diagnostic_run_targets (run_id,target,ordinal) VALUES ($1,'node-1',0)`, runID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO diagnostic_work_items (work_id,run_id,status,available_at,deadline,max_attempts,next_attempt) VALUES ($1,$2,'SUCCEEDED',$3,$4,2,2)`, workID, runID, now, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO diagnostic_work_attempts (work_id,attempt,runner_id,lease_token_hash,lease_expires_at,status,plan_digest,started_at,completed_at,finalized_at) VALUES ($1,1,'runner-1',$2,$3,'SUCCEEDED',$4,$5,$6,clock_timestamp())`, workID, leaseHash[:], now.Add(time.Minute), planDigest[:], now, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	exitCode := 0
	if _, err := pool.Exec(ctx, `INSERT INTO diagnostic_target_results (work_id,attempt,target,status,retryable,exit_code,signal,timed_out,stdout_truncated,stderr_truncated,stdout_bytes,stderr_bytes,stdout_sha256,stderr_sha256,error_code) VALUES ($1,1,'node-1','SUCCEEDED',false,$2,'',false,true,false,23,0,$3,$4,'')`, workID, exitCode, stdoutDigest[:], emptyDigest[:]); err != nil {
		t.Fatal(err)
	}

	projection, found, err := queries.GetRun(ctx, clusterID, runID)
	if err != nil || !found {
		t.Fatalf("get projection: found=%t err=%v", found, err)
	}
	if projection.WorkID != workID || projection.Status != domain.DiagnosticSucceeded || projection.Definition.DefinitionDigest != definitionDigest || len(projection.Attempts) != 1 {
		t.Fatalf("unexpected run projection: %+v", projection)
	}
	attempt := projection.Attempts[0]
	if attempt.Attempt != 1 || attempt.RunnerID != "runner-1" || attempt.PlanDigest == nil || *attempt.PlanDigest != planDigest || len(attempt.Targets) != 1 {
		t.Fatalf("unexpected attempt projection: %+v", attempt)
	}
	result := attempt.Targets[0]
	if result.Target != "node-1" || result.ExitCode == nil || *result.ExitCode != exitCode || result.StdoutBytes != 23 || result.StdoutSHA256 != stdoutDigest || !result.StdoutTruncated {
		t.Fatalf("unexpected safe target result: %+v", result)
	}
	if result.StdoutTransformationState != domain.StdoutTransformationUnknown {
		t.Fatalf("legacy target gained capture proof: %s", result.StdoutTransformationState)
	}
	if _, err := pool.Exec(ctx, `UPDATE diagnostic_target_results SET stdout_transformation_state='FORGED' WHERE work_id=$1`, workID); err == nil {
		t.Fatal("database accepted an unreviewed capture proof")
	}
	if _, found, err := queries.GetRun(ctx, otherClusterID, runID); err != nil || found {
		t.Fatalf("cross-cluster query leaked run: found=%t err=%v", found, err)
	}
	projectionType := reflect.TypeOf(application.DiagnosticRunProjection{})
	for _, forbidden := range []string{"Arguments", "Credential", "Credentials", "RawOutput", "LeaseToken"} {
		if _, exists := projectionType.FieldByName(forbidden); exists {
			t.Fatalf("diagnostic projection exposes forbidden field %s", forbidden)
		}
	}
}

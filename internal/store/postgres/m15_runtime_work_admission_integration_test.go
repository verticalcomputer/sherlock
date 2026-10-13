//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestM15RuntimeWorkAdmissionRejectsSelfGrantedCollectorWork(t *testing.T) {
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	m15ApplyRoleArtifact(t, ctx, admin)

	suffix := fmt.Sprintf("m15guard%d", time.Now().UnixNano())
	runtimeRole := suffix + "runtime"
	runtimePassword := createRole(t, ctx, admin, runtimeRole)
	if _, err = admin.Exec(ctx, "GRANT "+pgx.Identifier{storepg.RestrictedRemediationRole}.Sanitize()+" TO "+pgx.Identifier{runtimeRole}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_, _ = admin.Exec(cleanupCtx, `DELETE FROM remediation_runtime_identity_jobs WHERE login_role=$1`, runtimeRole)
		_, _ = admin.Exec(cleanupCtx, `DELETE FROM remediation_runtime_identity_scopes WHERE login_role=$1`, runtimeRole)
		_, _ = admin.Exec(cleanupCtx, "REVOKE "+pgx.Identifier{storepg.RestrictedRemediationRole}.Sanitize()+" FROM "+pgx.Identifier{runtimeRole}.Sanitize())
		_, _ = admin.Exec(cleanupCtx, "DROP ROLE IF EXISTS "+pgx.Identifier{runtimeRole}.Sanitize())
	}()

	var restricted *pgxpool.Pool
	var wrongSource domain.SourceID
	m15RunRecovery(t, m15RecoveryHooks{
		SupervisorPool: func(t *testing.T, ctx context.Context, fixture *pgxpool.Pool, result m15RecoveryResult) (*pgxpool.Pool, error) {
			if _, err := fixture.Exec(ctx, `INSERT INTO remediation_runtime_identity_scopes(login_role,cluster_id) VALUES($1,$2)`, runtimeRole, result.ClusterID); err != nil {
				return nil, err
			}
			if _, err := fixture.Exec(ctx, `INSERT INTO remediation_runtime_identity_jobs(login_role,cluster_id,job_id) VALUES($1,$2,$3)`, runtimeRole, result.ClusterID, result.JobID); err != nil {
				return nil, err
			}
			wrongSource = domain.SourceID("wrong-source-" + suffix)
			if _, err := fixture.Exec(ctx, `INSERT INTO sources(source_id,cluster_id,kind,display_name) VALUES($1,$2,'prometheus','M15 guard wrong source')`, wrongSource, result.ClusterID); err != nil {
				return nil, err
			}
			runtimeDSN, err := withDatabaseUser(dsn, runtimeRole, runtimePassword)
			if err != nil {
				return nil, err
			}
			restricted, err = storepg.NewRestrictedRemediationPool(ctx, runtimeDSN, result.ClusterID)
			if err != nil {
				return nil, err
			}
			m15RejectOrphanRuntimeWork(t, ctx, restricted, fixture, result, suffix+"orphan", false)
			m15RejectOrphanRuntimeWork(t, ctx, restricted, fixture, result, suffix+"reset", true)
			tag, mutationErr := restricted.Exec(ctx, `UPDATE remediation_policies SET enabled=false WHERE cluster_id=$1`, result.ClusterID)
			m15ExpectPermissionDenied(t, tag, mutationErr)
			return restricted, nil
		},
		AfterRequest: func(t *testing.T, ctx context.Context, fixture *pgxpool.Pool, result m15RecoveryResult) {
			m15RejectWrongRuntimeWork(t, ctx, restricted, fixture, result, wrongSource, suffix)
		},
	})
}

func m15RejectOrphanRuntimeWork(t *testing.T, ctx context.Context, restricted, fixture *pgxpool.Pool, result m15RecoveryResult, suffix string, resetRole bool) {
	t.Helper()
	var source, query, node string
	var revision int64
	if err := fixture.QueryRow(ctx, `SELECT source_id,query_kind,node_filter,configuration_revision FROM collection_jobs WHERE cluster_id=$1 AND job_id=$2`, result.ClusterID, result.JobID).Scan(&source, &query, &node, &revision); err != nil {
		t.Fatal(err)
	}
	tx, err := restricted.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	scheduled := time.Now().UTC()
	runID, workID := "guard-run-"+suffix, "guard-work-"+suffix
	if _, err = tx.Exec(ctx, `INSERT INTO collection_run_jobs(run_id,job_id,cluster_id,source_id,query_kind,node_filter,scheduled_for,configuration_revision,lease_generation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1)`, runID, result.JobID, result.ClusterID, source, query, node, scheduled, revision); err != nil {
		t.Fatalf("insert orphan runtime binding: %v", err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO collector_work_items(work_id,run_id,cluster_id,source_id,query_kind,node_filter,scheduled_for,deadline,max_series,max_bytes,idempotency_key,available_at,work_expires_at,remediation_runtime_managed) VALUES($1,$2,$3,$4,$5,$6,$7,$8,10000,10485760,$9,$7,$8,false)`, workID, runID, result.ClusterID, source, query, node, scheduled, scheduled.Add(time.Minute), "guard-key-"+suffix); err != nil {
		t.Fatalf("insert orphan runtime work: %v", err)
	}
	if resetRole {
		if _, err = tx.Exec(ctx, `RESET ROLE`); err != nil {
			t.Fatal(err)
		}
	}
	m15ExpectGuardDenied(t, tx.Commit(ctx))
}

func m15RejectWrongRuntimeWork(t *testing.T, ctx context.Context, restricted, fixture *pgxpool.Pool, result m15RecoveryResult, wrongSource domain.SourceID, suffix string) {
	t.Helper()
	tx, err := restricted.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	attemptID := "guard-attempt-" + suffix
	requestID := "repair-" + attemptID + "-" + result.JobID
	workID := "repair-work-" + attemptID + "-" + result.JobID
	idempotency := "guard-key-full-" + suffix
	scheduled := time.Now().UTC()
	if _, err = tx.Exec(ctx, `UPDATE remediation_runs SET state='ROLLING_OUT',version=version+1,rollout_wave=1,total_attempts=2 WHERE cluster_id=$1 AND run_id=$2`, result.ClusterID, result.RemediationRun); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO remediation_attempts(cluster_id,attempt_id,run_id,stage,attempt_number,idempotency_key,wave_target_digest,lease_owner,lease_token_hash,lease_expires_at,lease_deadline_at,policy_id,policy_version,policy_code)
		SELECT cluster_id,$3,run_id,'ROLLOUT',1,$4,wave_target_digest,lease_owner,lease_token_hash,lease_expires_at,lease_deadline_at,policy_id,policy_version,'ALLOWED'
		FROM remediation_attempts WHERE cluster_id=$1 AND run_id=$2 ORDER BY created_at DESC LIMIT 1`, result.ClusterID, result.RemediationRun, attemptID, idempotency); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO remediation_attempt_targets(cluster_id,attempt_id,run_id,target,ordinal) VALUES($1,$2,$3,$4,0)`, result.ClusterID, attemptID, result.RemediationRun, result.JobID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO collection_run_jobs(run_id,job_id,cluster_id,source_id,query_kind,node_filter,scheduled_for,configuration_revision,lease_generation)
		SELECT $1,j.job_id,j.cluster_id,$2,'dcgm_gpu_temperature','wrong-node',$3,j.configuration_revision,1 FROM collection_jobs j WHERE j.cluster_id=$4 AND j.job_id=$5`, requestID, wrongSource, scheduled, result.ClusterID, result.JobID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO collector_work_items(work_id,run_id,cluster_id,source_id,query_kind,node_filter,scheduled_for,deadline,max_series,max_bytes,idempotency_key,available_at,work_expires_at,remediation_runtime_managed)
		SELECT $1,$2,$3,$4,'dcgm_gpu_temperature','wrong-node',$5,deadline_at,10000,10485760,$6,$5,deadline_at,false FROM remediation_runs WHERE cluster_id=$3 AND run_id=$7`, workID, requestID, result.ClusterID, wrongSource, scheduled, idempotency, result.RemediationRun); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO collection_repair_requests(request_id,cluster_id,run_id,attempt_id,job_id,operation,configuration_revision,schedule_revision,idempotency_key,status,deadline_at,effect_receipt,work_id)
		SELECT $1,j.cluster_id,$2,$3,j.job_id,'SHERLOCK_EVIDENCE_COLLECTION_REQUEUE',j.configuration_revision,j.schedule_revision,$4,'REQUESTED',rr.deadline_at,$1,$5
		FROM collection_jobs j JOIN remediation_runs rr ON rr.cluster_id=j.cluster_id AND rr.run_id=$2 WHERE j.cluster_id=$6 AND j.job_id=$7`, requestID, result.RemediationRun, attemptID, idempotency, workID, result.ClusterID, result.JobID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE remediation_schedule_snapshots SET live_request_id=$4 WHERE cluster_id=$1 AND run_id=$2 AND target=$3`, result.ClusterID, result.RemediationRun, result.JobID, requestID); err != nil {
		t.Fatal(err)
	}
	m15ExpectGuardDenied(t, tx.Commit(ctx))
}

func m15ExpectGuardDenied(t *testing.T, err error) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("runtime work guard error=%v, want PostgreSQL permission denial", err)
	}
}

func m15ExpectPermissionDenied(t *testing.T, _ pgconn.CommandTag, err error) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("restricted runtime mutation error=%v, want PostgreSQL permission denial", err)
	}
}

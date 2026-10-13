package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type DiagnosticStore struct{ pool *pgxpool.Pool }

func NewDiagnosticStore(pool *pgxpool.Pool) (*DiagnosticStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	return &DiagnosticStore{pool: pool}, nil
}

func (store *DiagnosticStore) CreateDiagnosticRun(ctx context.Context, run domain.DiagnosticRun, workID domain.DiagnosticWorkID, audit application.DiagnosticAuditEvent) (domain.DiagnosticRun, bool, error) {
	request := run.Request()
	if err := request.Validate(); err != nil {
		return domain.DiagnosticRun{}, false, err
	}
	if workID == "" {
		return domain.DiagnosticRun{}, false, fmt.Errorf("diagnostic work identifier is required")
	}
	arguments, err := json.Marshal(request.Arguments)
	if err != nil {
		return domain.DiagnosticRun{}, false, fmt.Errorf("encode diagnostic arguments: %w", err)
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.DiagnosticRun{}, false, fmt.Errorf("begin diagnostic creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var insertedID domain.DiagnosticRunID
	err = tx.QueryRow(ctx, `
		INSERT INTO diagnostic_runs (
			run_id, cluster_id, pack_id, pack_version, definition_id, definition_version, definition_digest,
			privilege, status, requested_by, idempotency_key, arguments, requested_at,
			deadline, max_attempts, version
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (cluster_id, idempotency_key) DO NOTHING RETURNING run_id`,
		request.RunID, request.ClusterID, request.Definition.PackID, request.Definition.PackVersion,
		request.Definition.DefinitionID, request.Definition.DefinitionVersion, request.Definition.DefinitionDigest[:], request.Privilege,
		run.Status(), request.RequestedBy, request.IdempotencyKey, arguments, request.RequestedAt.UTC(),
		request.Deadline.UTC(), request.MaxAttempts, run.Version()).Scan(&insertedID)
	if err == pgx.ErrNoRows {
		var priorID domain.DiagnosticRunID
		if err := tx.QueryRow(ctx, `SELECT run_id FROM diagnostic_runs WHERE cluster_id=$1 AND idempotency_key=$2`, request.ClusterID, request.IdempotencyKey).Scan(&priorID); err != nil {
			return domain.DiagnosticRun{}, false, fmt.Errorf("load idempotent diagnostic run: %w", err)
		}
		prior, found, err := loadDiagnosticRun(ctx, tx, priorID, false)
		if err != nil || !found {
			return domain.DiagnosticRun{}, false, fmt.Errorf("load idempotent diagnostic run: %w", err)
		}
		if !equalDiagnosticRequests(prior.Request(), request) {
			return domain.DiagnosticRun{}, false, application.ErrDiagnosticConflict
		}
		audit.RunID = priorID
		if err := appendDiagnosticAudit(ctx, tx, audit); err != nil {
			return domain.DiagnosticRun{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return domain.DiagnosticRun{}, false, fmt.Errorf("commit idempotent diagnostic creation: %w", err)
		}
		return prior, false, nil
	}
	if err != nil {
		return domain.DiagnosticRun{}, false, fmt.Errorf("insert diagnostic run %s: %w", request.RunID, err)
	}
	for ordinal, target := range request.Targets {
		if _, err := tx.Exec(ctx, `INSERT INTO diagnostic_run_targets (run_id, target, ordinal) VALUES ($1,$2,$3)`, request.RunID, target, ordinal); err != nil {
			return domain.DiagnosticRun{}, false, fmt.Errorf("insert diagnostic target: %w", err)
		}
	}
	workStatus := "AVAILABLE"
	if run.Status() == domain.DiagnosticAwaitingApproval {
		workStatus = "BLOCKED"
	}
	if _, err := tx.Exec(ctx, `INSERT INTO diagnostic_work_items (work_id, run_id, status, available_at, deadline, max_attempts) VALUES ($1,$2,$3,$4,$5,$6)`,
		workID, request.RunID, workStatus, request.RequestedAt.UTC(), request.Deadline.UTC(), request.MaxAttempts); err != nil {
		return domain.DiagnosticRun{}, false, fmt.Errorf("insert diagnostic work %s: %w", workID, err)
	}
	if err := appendDiagnosticAudit(ctx, tx, audit); err != nil {
		return domain.DiagnosticRun{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.DiagnosticRun{}, false, fmt.Errorf("commit diagnostic creation: %w", err)
	}
	return run, true, nil
}

func (store *DiagnosticStore) LoadDiagnosticRun(ctx context.Context, runID domain.DiagnosticRunID) (domain.DiagnosticRun, bool, error) {
	if runID == "" {
		return domain.DiagnosticRun{}, false, fmt.Errorf("diagnostic run identifier is required")
	}
	return loadDiagnosticRun(ctx, store.pool, runID, false)
}

type diagnosticQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func loadDiagnosticRun(ctx context.Context, query diagnosticQuerier, runID domain.DiagnosticRunID, lock bool) (domain.DiagnosticRun, bool, error) {
	var request domain.DiagnosticRequest
	var digest []byte
	var status domain.DiagnosticRunStatus
	var version int
	var arguments []byte
	command := `SELECT cluster_id, pack_id, pack_version, definition_id, definition_version, definition_digest, privilege,
		status, requested_by, idempotency_key, arguments, requested_at, deadline, max_attempts, version
		FROM diagnostic_runs WHERE run_id=$1`
	if lock {
		command += " FOR UPDATE"
	}
	request.RunID = runID
	err := query.QueryRow(ctx, command, runID).Scan(
		&request.ClusterID, &request.Definition.PackID, &request.Definition.PackVersion,
		&request.Definition.DefinitionID, &request.Definition.DefinitionVersion, &digest, &request.Privilege, &status,
		&request.RequestedBy, &request.IdempotencyKey, &arguments, &request.RequestedAt,
		&request.Deadline, &request.MaxAttempts, &version)
	if err == pgx.ErrNoRows {
		return domain.DiagnosticRun{}, false, nil
	}
	if err != nil {
		return domain.DiagnosticRun{}, false, fmt.Errorf("load diagnostic run %s: %w", runID, err)
	}
	if len(digest) != sha256.Size {
		return domain.DiagnosticRun{}, false, fmt.Errorf("stored diagnostic definition digest is invalid")
	}
	copy(request.Definition.DefinitionDigest[:], digest)
	if err := json.Unmarshal(arguments, &request.Arguments); err != nil {
		return domain.DiagnosticRun{}, false, fmt.Errorf("decode diagnostic arguments: %w", err)
	}
	rows, err := query.Query(ctx, `SELECT target FROM diagnostic_run_targets WHERE run_id=$1 ORDER BY ordinal`, runID)
	if err != nil {
		return domain.DiagnosticRun{}, false, fmt.Errorf("load diagnostic targets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var target domain.DiagnosticTarget
		if err := rows.Scan(&target); err != nil {
			return domain.DiagnosticRun{}, false, fmt.Errorf("scan diagnostic target: %w", err)
		}
		request.Targets = append(request.Targets, target)
	}
	if err := rows.Err(); err != nil {
		return domain.DiagnosticRun{}, false, fmt.Errorf("load diagnostic targets: %w", err)
	}
	run, err := domain.ReconstituteDiagnosticRun(request, status, version)
	if err != nil {
		return domain.DiagnosticRun{}, false, fmt.Errorf("reconstruct diagnostic run: %w", err)
	}
	return run, true, nil
}

func (store *DiagnosticStore) ApproveDiagnosticRun(ctx context.Context, run domain.DiagnosticRun, approval domain.DiagnosticApproval, audit application.DiagnosticAuditEvent) error {
	request := run.Request()
	if run.Status() != domain.DiagnosticQueued || approval.RunID != request.RunID {
		return application.ErrDiagnosticConflict
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin diagnostic approval: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	command, err := tx.Exec(ctx, `UPDATE diagnostic_runs SET status='QUEUED', version=$2 WHERE run_id=$1 AND status='AWAITING_APPROVAL' AND version=$3`, request.RunID, run.Version(), approval.RunVersion)
	if err != nil {
		return fmt.Errorf("update approved diagnostic run: %w", err)
	}
	if command.RowsAffected() != 1 {
		return application.ErrDiagnosticConflict
	}
	if _, err := tx.Exec(ctx, `INSERT INTO diagnostic_approvals (approval_id, run_id, definition_digest, target_digest, run_version, approved_by, approved_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		approval.ApprovalID, approval.RunID, approval.DefinitionDigest[:], approval.TargetDigest[:], approval.RunVersion,
		approval.ApprovedBy, approval.ApprovedAt.UTC(), approval.ExpiresAt.UTC()); err != nil {
		return fmt.Errorf("insert diagnostic approval: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE diagnostic_work_items SET status='AVAILABLE', available_at=GREATEST(available_at, clock_timestamp()) WHERE run_id=$1 AND status='BLOCKED'`, request.RunID); err != nil {
		return fmt.Errorf("release approved diagnostic work: %w", err)
	}
	if err := appendDiagnosticAudit(ctx, tx, audit); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit diagnostic approval: %w", err)
	}
	return nil
}

func (store *DiagnosticStore) ClaimDiagnosticWork(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, leaseToken string, leaseFor time.Duration, audit application.DiagnosticAuditEvent) (domain.DiagnosticWorkLease, bool, error) {
	if clusterID == "" || collectorID == "" || leaseToken == "" || leaseFor <= 0 || leaseFor > 5*time.Minute || audit.ClusterID != clusterID || audit.ActorID != string(collectorID) {
		return domain.DiagnosticWorkLease{}, false, fmt.Errorf("cluster, collector, lease token, and lease duration up to five minutes are required")
	}
	tokenHash := sha256.Sum256([]byte(leaseToken))
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.DiagnosticWorkLease{}, false, fmt.Errorf("begin diagnostic claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// An AVAILABLE item whose deadline elapsed without ever being claimed must
	// not remain QUEUED forever. Mark both rows terminal while holding the claim
	// transaction; the investigation dispatcher will then surface the missing
	// attempt as a bounded failure and the controller will publish an action
	// card instead of parking indefinitely in AWAITING_EVIDENCE.
	if _, err := tx.Exec(ctx, `WITH expired AS (
		UPDATE diagnostic_work_items w SET status='FAILED'
		FROM diagnostic_runs r
		WHERE w.run_id=r.run_id AND r.cluster_id=$1 AND w.status='AVAILABLE'
		  AND w.deadline<=clock_timestamp()
		RETURNING w.run_id
	)
		UPDATE diagnostic_runs r SET status='FAILED',completed_at=clock_timestamp(),version=version+1
		FROM expired e WHERE r.run_id=e.run_id AND r.status IN ('QUEUED','RUNNING')`, clusterID); err != nil {
		return domain.DiagnosticWorkLease{}, false, fmt.Errorf("expire unclaimed diagnostic work: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE diagnostic_work_attempts a SET status='EXPIRED', completed_at=clock_timestamp(), finalized_at=clock_timestamp()
		FROM diagnostic_work_items w, diagnostic_runs r
		WHERE a.work_id=w.work_id AND w.run_id=r.run_id AND r.cluster_id=$1
		AND a.status IN ('CLAIMED','RUNNING') AND a.lease_expires_at <= clock_timestamp()`, clusterID); err != nil {
		return domain.DiagnosticWorkLease{}, false, fmt.Errorf("expire diagnostic attempts: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE diagnostic_work_items w SET status='AVAILABLE'
		FROM diagnostic_runs r WHERE w.run_id=r.run_id AND r.cluster_id=$1
		AND w.status='LEASED' AND w.next_attempt <= w.max_attempts
		AND NOT EXISTS (SELECT 1 FROM diagnostic_work_attempts a WHERE a.work_id=w.work_id AND a.status IN ('CLAIMED','RUNNING'))`, clusterID); err != nil {
		return domain.DiagnosticWorkLease{}, false, fmt.Errorf("release expired diagnostic work: %w", err)
	}
	var lease domain.DiagnosticWorkLease
	err = tx.QueryRow(ctx, `WITH candidate AS (
		SELECT w.work_id, w.next_attempt FROM diagnostic_work_items w
		JOIN diagnostic_runs r ON r.run_id=w.run_id
		WHERE r.cluster_id=$1 AND w.status='AVAILABLE' AND w.available_at <= clock_timestamp() AND w.deadline > clock_timestamp() AND w.next_attempt <= w.max_attempts
		ORDER BY w.available_at, w.work_id FOR UPDATE OF w SKIP LOCKED LIMIT 1
	), claimed AS (
		UPDATE diagnostic_work_items w SET status='LEASED', next_attempt=w.next_attempt+1 FROM candidate c WHERE w.work_id=c.work_id
		RETURNING w.work_id, w.run_id, w.available_at, w.deadline, w.max_attempts, c.next_attempt
	)
	INSERT INTO diagnostic_work_attempts (work_id, attempt, runner_id, lease_token_hash, lease_expires_at, status)
	SELECT work_id, next_attempt, $2, $3, clock_timestamp()+($4*interval '1 millisecond'), 'CLAIMED' FROM claimed
	RETURNING work_id, attempt, runner_id, lease_expires_at`, clusterID, collectorID, tokenHash[:], leaseFor.Milliseconds()).Scan(&lease.Work.WorkID, &lease.Attempt, &lease.RunnerID, &lease.LeaseExpires)
	if err == pgx.ErrNoRows {
		_ = tx.Commit(ctx)
		return domain.DiagnosticWorkLease{}, false, nil
	}
	if err != nil {
		return domain.DiagnosticWorkLease{}, false, fmt.Errorf("claim diagnostic work: %w", err)
	}
	var runID domain.DiagnosticRunID
	if err := tx.QueryRow(ctx, `SELECT w.run_id, w.available_at, w.deadline, w.max_attempts
		FROM diagnostic_work_items w JOIN diagnostic_runs r ON r.run_id=w.run_id
		WHERE w.work_id=$1 AND r.cluster_id=$2`, lease.Work.WorkID, clusterID).Scan(&runID, &lease.Work.AvailableAt, &lease.Work.Deadline, &lease.Work.MaxAttempts); err != nil {
		return domain.DiagnosticWorkLease{}, false, fmt.Errorf("load claimed diagnostic work: %w", err)
	}
	run, found, err := loadDiagnosticRun(ctx, tx, runID, true)
	if err != nil || !found {
		return domain.DiagnosticWorkLease{}, false, fmt.Errorf("load claimed diagnostic run: %w", err)
	}
	if run.Status() == domain.DiagnosticQueued {
		run, err = run.Start()
		if err != nil {
			return domain.DiagnosticWorkLease{}, false, err
		}
		if _, err := tx.Exec(ctx, `UPDATE diagnostic_runs SET status=$2, version=$3 WHERE run_id=$1`, runID, run.Status(), run.Version()); err != nil {
			return domain.DiagnosticWorkLease{}, false, fmt.Errorf("start diagnostic run: %w", err)
		}
	}
	lease.Work.Run = run
	lease.LeaseToken = leaseToken
	lease.LeaseExpires = lease.LeaseExpires.UTC()
	request := run.Request()
	if request.ClusterID != clusterID {
		return domain.DiagnosticWorkLease{}, false, application.ErrDiagnosticLeaseInvalid
	}
	audit.RunID, audit.WorkID, audit.Attempt = request.RunID, lease.Work.WorkID, lease.Attempt
	audit.ClusterID, audit.DefinitionDigest = request.ClusterID, request.Definition.DefinitionDigest
	audit.TargetDigest = domain.DiagnosticTargetsDigest(request.Targets)
	if err := appendDiagnosticAudit(ctx, tx, audit); err != nil {
		return domain.DiagnosticWorkLease{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.DiagnosticWorkLease{}, false, fmt.Errorf("commit diagnostic claim: %w", err)
	}
	return lease, true, nil
}

// LoadDiagnosticWorkLease reconstructs the complete lease from durable state.
// The caller supplies only the authenticated cluster/collector identity and
// the opaque token presented on the result request; no control-process cache
// participates in authorization.
func (store *DiagnosticStore) LoadDiagnosticWorkLease(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, workID domain.DiagnosticWorkID, attempt int, leaseToken string) (domain.DiagnosticWorkLease, error) {
	if clusterID == "" || collectorID == "" || workID == "" || attempt < 1 || leaseToken == "" {
		return domain.DiagnosticWorkLease{}, application.ErrDiagnosticLeaseInvalid
	}
	tokenHash := sha256.Sum256([]byte(leaseToken))
	var lease domain.DiagnosticWorkLease
	var runID domain.DiagnosticRunID
	var storedToken []byte
	err := store.pool.QueryRow(ctx, `SELECT w.run_id,w.available_at,w.deadline,w.max_attempts,a.runner_id,a.lease_token_hash,a.lease_expires_at
		FROM diagnostic_work_attempts a
		JOIN diagnostic_work_items w ON w.work_id=a.work_id
		JOIN diagnostic_runs r ON r.run_id=w.run_id
		WHERE a.work_id=$1 AND a.attempt=$2 AND r.cluster_id=$3`, workID, attempt, clusterID).Scan(
		&runID, &lease.Work.AvailableAt, &lease.Work.Deadline, &lease.Work.MaxAttempts,
		&lease.RunnerID, &storedToken, &lease.LeaseExpires,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return domain.DiagnosticWorkLease{}, application.ErrDiagnosticLeaseInvalid
		}
		return domain.DiagnosticWorkLease{}, fmt.Errorf("load diagnostic lease identity: %w", err)
	}
	if lease.RunnerID != string(collectorID) || len(storedToken) != sha256.Size || subtle.ConstantTimeCompare(storedToken, tokenHash[:]) != 1 {
		return domain.DiagnosticWorkLease{}, application.ErrDiagnosticLeaseInvalid
	}
	run, found, err := loadDiagnosticRun(ctx, store.pool, runID, true)
	if err != nil {
		return domain.DiagnosticWorkLease{}, fmt.Errorf("load diagnostic lease run: %w", err)
	}
	if !found || run.Request().ClusterID != clusterID {
		return domain.DiagnosticWorkLease{}, application.ErrDiagnosticLeaseInvalid
	}
	lease.Work.WorkID = workID
	lease.Work.Run = run
	lease.Attempt = attempt
	lease.LeaseToken = leaseToken
	lease.LeaseExpires = lease.LeaseExpires.UTC()
	return lease, nil
}

func (store *DiagnosticStore) RecordDiagnosticAttempt(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, lease domain.DiagnosticWorkLease, result domain.DiagnosticAttemptResult, audit application.DiagnosticAuditEvent) (domain.DiagnosticRun, bool, error) {
	request := lease.Work.Run.Request()
	if clusterID == "" || collectorID == "" || request.ClusterID != clusterID || lease.RunnerID != string(collectorID) || result.WorkID != lease.Work.WorkID || result.RunID != request.RunID || result.Attempt != lease.Attempt || result.RunnerID != string(collectorID) || audit.ClusterID != clusterID || audit.ActorID != string(collectorID) {
		return domain.DiagnosticRun{}, false, application.ErrDiagnosticLeaseInvalid
	}
	if err := result.Validate(request.Targets); err != nil {
		return domain.DiagnosticRun{}, false, err
	}
	tokenHash := sha256.Sum256([]byte(lease.LeaseToken))
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.DiagnosticRun{}, false, fmt.Errorf("begin diagnostic result: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var status, storedRunner string
	var storedToken, storedPlan []byte
	err = tx.QueryRow(ctx, `SELECT a.status, a.runner_id, a.lease_token_hash, a.plan_digest
		FROM diagnostic_work_attempts a
		JOIN diagnostic_work_items w ON w.work_id=a.work_id
		JOIN diagnostic_runs r ON r.run_id=w.run_id
		WHERE a.work_id=$1 AND a.attempt=$2 AND r.cluster_id=$3 FOR UPDATE OF a`, result.WorkID, result.Attempt, clusterID).Scan(&status, &storedRunner, &storedToken, &storedPlan)
	if err != nil {
		if err == pgx.ErrNoRows {
			return domain.DiagnosticRun{}, false, application.ErrDiagnosticLeaseInvalid
		}
		return domain.DiagnosticRun{}, false, fmt.Errorf("load diagnostic attempt: %w", err)
	}
	if storedRunner != string(collectorID) || len(storedToken) != sha256.Size || subtle.ConstantTimeCompare(storedToken, tokenHash[:]) != 1 {
		return domain.DiagnosticRun{}, false, application.ErrDiagnosticLeaseInvalid
	}
	run, found, err := loadDiagnosticRun(ctx, tx, result.RunID, true)
	if err != nil || !found {
		return domain.DiagnosticRun{}, false, fmt.Errorf("load diagnostic result run: %w", err)
	}
	if run.Request().ClusterID != clusterID {
		return domain.DiagnosticRun{}, false, application.ErrDiagnosticLeaseInvalid
	}
	if err := result.Validate(run.Request().Targets); err != nil {
		return domain.DiagnosticRun{}, false, application.ErrDiagnosticConflict
	}
	if status == "SUCCEEDED" || status == "PARTIAL" || status == "FAILED" {
		if !slices.Equal(storedPlan, result.PlanDigest[:]) {
			return domain.DiagnosticRun{}, false, application.ErrDiagnosticConflict
		}
		storedTargets, err := loadDiagnosticTargetResults(ctx, tx, result.WorkID, result.Attempt)
		if err != nil || !equalDiagnosticTargetResults(storedTargets, result.Targets) {
			return domain.DiagnosticRun{}, false, application.ErrDiagnosticConflict
		}
		audit.Outcome = "IDEMPOTENT_REPLAY"
		if err := appendDiagnosticAudit(ctx, tx, audit); err != nil {
			return domain.DiagnosticRun{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return domain.DiagnosticRun{}, false, err
		}
		return run, false, nil
	}
	var leaseCurrent bool
	if err := tx.QueryRow(ctx, `SELECT lease_expires_at > clock_timestamp() FROM diagnostic_work_attempts WHERE work_id=$1 AND attempt=$2`, result.WorkID, result.Attempt).Scan(&leaseCurrent); err != nil {
		return domain.DiagnosticRun{}, false, err
	}
	if !leaseCurrent {
		return domain.DiagnosticRun{}, false, application.ErrDiagnosticLeaseInvalid
	}
	retry := result.CanRetry(lease.Work.MaxAttempts)
	attemptStatus := "FAILED"
	succeeded := 0
	for _, target := range result.Targets {
		if target.Status == domain.DiagnosticTargetSucceeded {
			succeeded++
		}
	}
	if succeeded == len(result.Targets) {
		attemptStatus = "SUCCEEDED"
	} else if succeeded > 0 {
		attemptStatus = "PARTIAL"
	}
	if _, err := tx.Exec(ctx, `UPDATE diagnostic_work_attempts SET status=$3, plan_digest=$4, started_at=$5, completed_at=$6, finalized_at=clock_timestamp() WHERE work_id=$1 AND attempt=$2`, result.WorkID, result.Attempt, attemptStatus, result.PlanDigest[:], result.StartedAt.UTC(), result.CompletedAt.UTC()); err != nil {
		return domain.DiagnosticRun{}, false, fmt.Errorf("complete diagnostic attempt: %w", err)
	}
	for _, target := range result.Targets {
		if _, err := tx.Exec(ctx, `INSERT INTO diagnostic_target_results (work_id, attempt, target, status, retryable, exit_code, signal, timed_out, stdout_truncated, stderr_truncated, stdout_bytes, stderr_bytes, stdout_sha256, stderr_sha256, error_code, stdout_excerpt, stdout_transformation_state) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
			result.WorkID, result.Attempt, target.Target, target.Status, target.Retryable, target.ExitCode, target.Signal, target.TimedOut,
			target.StdoutTruncated, target.StderrTruncated, target.StdoutBytes, target.StderrBytes, target.StdoutSHA256[:], target.StderrSHA256[:], target.ErrorCode, target.StdoutExcerpt, domain.NormalizeStdoutTransformationState(string(target.StdoutTransformationState))); err != nil {
			return domain.DiagnosticRun{}, false, fmt.Errorf("insert diagnostic target result: %w", err)
		}
	}
	if retry {
		if _, err := tx.Exec(ctx, `UPDATE diagnostic_work_items SET status='AVAILABLE', available_at=clock_timestamp() WHERE work_id=$1`, result.WorkID); err != nil {
			return domain.DiagnosticRun{}, false, err
		}
	} else {
		run, err = run.Complete(result.Targets)
		if err != nil {
			return domain.DiagnosticRun{}, false, err
		}
		if _, err := tx.Exec(ctx, `UPDATE diagnostic_runs SET status=$2, version=$3, completed_at=$4 WHERE run_id=$1`, result.RunID, run.Status(), run.Version(), result.CompletedAt.UTC()); err != nil {
			return domain.DiagnosticRun{}, false, err
		}
		if _, err := tx.Exec(ctx, `UPDATE diagnostic_work_items SET status=$2 WHERE work_id=$1`, result.WorkID, run.Status()); err != nil {
			return domain.DiagnosticRun{}, false, err
		}
	}
	if err := appendDiagnosticAudit(ctx, tx, audit); err != nil {
		return domain.DiagnosticRun{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.DiagnosticRun{}, false, fmt.Errorf("commit diagnostic result: %w", err)
	}
	return run, true, nil
}

func (store *DiagnosticStore) AppendDiagnosticAudit(ctx context.Context, event application.DiagnosticAuditEvent) error {
	return appendDiagnosticAudit(ctx, store.pool, event)
}

type diagnosticExecer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func appendDiagnosticAudit(ctx context.Context, exec diagnosticExecer, event application.DiagnosticAuditEvent) error {
	if event.EventID == "" || event.ClusterID == "" || event.ActorID == "" || event.Outcome == "" || event.OccurredAt.IsZero() || event.DefinitionDigest == (domain.SHA256{}) || event.TargetDigest == (domain.SHA256{}) {
		return fmt.Errorf("diagnostic audit attribution is incomplete")
	}
	command, err := exec.Exec(ctx, `INSERT INTO diagnostic_audit_events (event_id, event_kind, run_id, work_id, attempt, cluster_id, actor_id, outcome, reason_code, definition_digest, target_digest, occurred_at) VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),NULLIF($5,0),$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (event_id) DO NOTHING`,
		event.EventID, event.Kind, event.RunID, event.WorkID, event.Attempt, event.ClusterID, event.ActorID, event.Outcome, event.ReasonCode, event.DefinitionDigest[:], event.TargetDigest[:], event.OccurredAt.UTC())
	if err != nil {
		return fmt.Errorf("append diagnostic audit event: %w", err)
	}
	if command.RowsAffected() != 1 {
		return application.ErrDiagnosticConflict
	}
	return nil
}

func loadDiagnosticTargetResults(ctx context.Context, query diagnosticQuerier, workID domain.DiagnosticWorkID, attempt int) ([]domain.DiagnosticTargetResult, error) {
	rows, err := query.Query(ctx, `SELECT target, status, retryable, exit_code, signal, timed_out, stdout_truncated, stderr_truncated, stdout_bytes, stderr_bytes, stdout_sha256, stderr_sha256, error_code, stdout_excerpt, stdout_transformation_state FROM diagnostic_target_results WHERE work_id=$1 AND attempt=$2 ORDER BY target`, workID, attempt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []domain.DiagnosticTargetResult
	for rows.Next() {
		var result domain.DiagnosticTargetResult
		var stdout, stderr []byte
		if err := rows.Scan(&result.Target, &result.Status, &result.Retryable, &result.ExitCode, &result.Signal, &result.TimedOut, &result.StdoutTruncated, &result.StderrTruncated, &result.StdoutBytes, &result.StderrBytes, &stdout, &stderr, &result.ErrorCode, &result.StdoutExcerpt, &result.StdoutTransformationState); err != nil {
			return nil, err
		}
		if len(stdout) != sha256.Size || len(stderr) != sha256.Size {
			return nil, fmt.Errorf("stored diagnostic output digest is invalid")
		}
		copy(result.StdoutSHA256[:], stdout)
		copy(result.StderrSHA256[:], stderr)
		results = append(results, result)
	}
	return results, rows.Err()
}

func equalDiagnosticTargetResults(left, right []domain.DiagnosticTargetResult) bool {
	left = slices.Clone(left)
	right = slices.Clone(right)
	slices.SortFunc(left, func(a, b domain.DiagnosticTargetResult) int {
		return strings.Compare(string(a.Target), string(b.Target))
	})
	slices.SortFunc(right, func(a, b domain.DiagnosticTargetResult) int {
		return strings.Compare(string(a.Target), string(b.Target))
	})
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Target != right[index].Target || left[index].Status != right[index].Status || left[index].Retryable != right[index].Retryable || !equalOptionalInt(left[index].ExitCode, right[index].ExitCode) || left[index].Signal != right[index].Signal || left[index].TimedOut != right[index].TimedOut || left[index].StdoutTruncated != right[index].StdoutTruncated || left[index].StderrTruncated != right[index].StderrTruncated || left[index].StdoutBytes != right[index].StdoutBytes || left[index].StderrBytes != right[index].StderrBytes || left[index].StdoutSHA256 != right[index].StdoutSHA256 || left[index].StderrSHA256 != right[index].StderrSHA256 || left[index].ErrorCode != right[index].ErrorCode || domain.NormalizeStdoutTransformationState(string(left[index].StdoutTransformationState)) != domain.NormalizeStdoutTransformationState(string(right[index].StdoutTransformationState)) {
			return false
		}
	}
	return true
}

func equalOptionalInt(left, right *int) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func equalDiagnosticRequests(left, right domain.DiagnosticRequest) bool {
	return left.ClusterID == right.ClusterID && left.Definition == right.Definition && left.Privilege == right.Privilege && slices.Equal(left.Targets, right.Targets) && slices.Equal(left.Arguments, right.Arguments) && left.RequestedBy == right.RequestedBy && left.IdempotencyKey == right.IdempotencyKey && left.Deadline.Equal(right.Deadline) && left.MaxAttempts == right.MaxAttempts
}

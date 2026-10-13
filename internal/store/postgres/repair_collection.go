package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ClaimRepairCollection leases the supervisor record, not collector work. The
// normal collector remains sole owner of collector_work_items leases and result
// admission. That separation makes remote collector takeover unchanged.
func (s *RemediationStore) ClaimRepairCollection(ctx context.Context, cluster domain.ClusterID, source domain.SourceID, owner string, lease time.Duration) (application.RepairCollectionClaim, bool, error) {
	if cluster == "" || source == "" || !domain.ValidRemediationToken(owner) || lease <= 0 || lease > 5*time.Minute {
		return application.RepairCollectionClaim{}, false, fmt.Errorf("repair request owner or lease is invalid")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return application.RepairCollectionClaim{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err = LockRepairAuthority(ctx, tx, cluster); err != nil {
		return application.RepairCollectionClaim{}, false, err
	}
	var claim application.RepairCollectionClaim
	var query domain.QueryKind
	err = tx.QueryRow(ctx, `WITH candidate AS (
 SELECT r.request_id FROM collection_repair_requests r JOIN collector_work_items w ON w.work_id=r.work_id
 WHERE r.cluster_id=$3 AND w.source_id=$4 AND r.status IN ('REQUESTED','CLAIMED') AND r.deadline_at>clock_timestamp()
   AND (r.status='REQUESTED' OR r.lease_expires_at<=clock_timestamp())
   AND w.status IN ('AVAILABLE','LEASED') AND w.deadline>clock_timestamp()
 ORDER BY r.created_at,r.request_id FOR UPDATE OF r,w SKIP LOCKED LIMIT 1
), claimed AS (
 UPDATE collection_repair_requests r SET status='CLAIMED',lease_owner=$1,worker_generation=worker_generation+1,
   lease_expires_at=clock_timestamp()+($2*interval '1 millisecond')
 FROM candidate WHERE r.request_id=candidate.request_id
 RETURNING r.request_id,r.work_id,r.worker_generation
)
SELECT c.request_id,c.worker_generation,w.run_id,w.cluster_id,w.source_id,w.query_kind,w.node_filter,w.scheduled_for,w.deadline,w.max_series,w.max_bytes,w.idempotency_key
FROM claimed c JOIN collector_work_items w ON w.work_id=c.work_id`, owner, lease.Milliseconds(), cluster, source).Scan(
		&claim.RequestID, &claim.Generation, &claim.Task.RunID, &claim.Task.ClusterID, &claim.Task.SourceID, &query, &claim.Task.Node,
		&claim.Task.ScheduledFor, &claim.Task.Deadline, &claim.Task.MaxSeries, &claim.Task.MaxBytes, &claim.Task.IdempotencyKey)
	if err == pgx.ErrNoRows {
		if err = tx.Commit(ctx); err != nil {
			return application.RepairCollectionClaim{}, false, err
		}
		return application.RepairCollectionClaim{}, false, nil
	}
	if err != nil {
		return application.RepairCollectionClaim{}, false, fmt.Errorf("claim repair collection: %w", err)
	}
	claim.Task.Query = query
	claim.Task.ScheduledFor, claim.Task.Deadline = claim.Task.ScheduledFor.UTC(), claim.Task.Deadline.UTC()
	if err = tx.Commit(ctx); err != nil {
		return application.RepairCollectionClaim{}, false, err
	}
	return claim, true, nil
}

// FinishRepairCollection only accepts the worker's current supervisor lease.
// A completed collector work item is preserved; a cancellation race is marked
// CONTAINED instead of pretending the already-observed collection was undone.
func (s *RemediationStore) FinishRepairCollection(ctx context.Context, claim application.RepairCollectionClaim, owner string) error {
	if claim.RequestID == "" || claim.Task.RunID == "" || claim.Task.ClusterID == "" || !domain.ValidRemediationToken(owner) {
		return fmt.Errorf("repair completion identity is invalid")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err = LockRepairAuthority(ctx, tx, claim.Task.ClusterID); err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE collection_repair_requests r SET
 status=CASE WHEN r.status='CANCEL_REQUESTED' THEN 'CONTAINED' ELSE 'COMPLETED' END,
 completed_at=clock_timestamp(),lease_owner=NULL,lease_expires_at=NULL,
 cancellation_outcome=CASE WHEN r.status='CANCEL_REQUESTED' THEN 'CONTAINED' ELSE r.cancellation_outcome END
FROM collector_work_items w
	WHERE r.request_id=$1 AND r.cluster_id=$5 AND r.work_id=w.work_id AND w.cluster_id=$5
	 AND r.lease_owner=$2 AND r.worker_generation=$4 AND r.lease_expires_at>clock_timestamp()
	 AND w.run_id=$3 AND w.status IN ('SUCCEEDED','FAILED') AND r.status IN ('CLAIMED','CANCEL_REQUESTED')`, claim.RequestID, owner, claim.Task.RunID, claim.Generation, claim.Task.ClusterID)
	if err != nil {
		return fmt.Errorf("finish repair collection: %w", err)
	}
	if command.RowsAffected() == 1 {
		return tx.Commit(ctx)
	}
	// Remote collector finalization atomically persists collection_runs and
	// observations before terminalizing its work. The lifecycle trigger can
	// therefore finish the request before the waiting worker wakes. Treat that
	// exact durable terminal as an idempotent completion, never as a stale-owner
	// error; a terminal without its bound collection run remains a conflict.
	var finalized bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM collection_repair_requests r
 JOIN collector_work_items w ON w.work_id=r.work_id
 JOIN collection_runs cr ON cr.run_id=w.run_id AND cr.cluster_id=r.cluster_id AND cr.job_id=r.job_id
	 WHERE r.request_id=$1 AND r.cluster_id=$3 AND w.cluster_id=$3 AND w.run_id=$2
	   AND r.status IN ('COMPLETED','CONTAINED') AND w.status IN ('SUCCEEDED','FAILED'))`, claim.RequestID, claim.Task.RunID, claim.Task.ClusterID).Scan(&finalized)
	if err != nil {
		return fmt.Errorf("read terminal repair collection: %w", err)
	}
	if !finalized {
		return fmt.Errorf("repair collection lease is no longer current")
	}
	return tx.Commit(ctx)
}

var _ application.RepairCollectionStore = (*RemediationStore)(nil)

// ReconcileCollectionRequest is the durable revocation fence used by the
// remediation supervisor. It never requeues a forward repair: an unclaimed
// work item is cancelled, while a collector lease is allowed to settle and is
// truthfully contained if it produces a result after revocation.
func (s *RemediationStore) ReconcileCollectionRequest(ctx context.Context, cluster domain.ClusterID, run domain.RemediationRunID, attempt domain.RemediationAttemptID) error {
	if cluster == "" || run == "" || attempt == "" {
		return fmt.Errorf("repair reconciliation identity is invalid")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err = LockRepairAuthority(ctx, tx, cluster); err != nil {
		return err
	}
	var requestID, workStatus string
	var allowed bool
	err = tx.QueryRow(ctx, `SELECT r.request_id,w.status,
 COALESCE(r.status<>'CANCEL_REQUESTED' AND r.deadline_at>clock_timestamp() AND EXISTS(SELECT 1 FROM remediation_runs mr WHERE mr.cluster_id=r.cluster_id AND mr.run_id=r.run_id AND mr.cancellation_requested_at IS NULL AND mr.state IN ('CANARY_EXECUTING','ROLLING_OUT','VERIFYING','ROLLING_BACK')) AND gs.remediation_enabled AND j.active AND j.configuration_revision=r.configuration_revision AND j.schedule_revision=r.schedule_revision
  AND p.enabled AND p.recipe_id=(SELECT recipe_id FROM remediation_runs WHERE cluster_id=r.cluster_id AND run_id=r.run_id)
  AND p.recipe_version=(SELECT recipe_version FROM remediation_runs WHERE cluster_id=r.cluster_id AND run_id=r.run_id)
  AND p.not_before<=clock_timestamp() AND p.not_after>clock_timestamp() AND p.revoked_at IS NULL
  AND EXISTS(SELECT 1 FROM collectors c JOIN collector_capabilities cap ON cap.collector_id=c.collector_id JOIN collector_source_health h ON h.collector_id=c.collector_id AND h.source_id=j.source_id WHERE c.cluster_id=r.cluster_id AND c.status='ACTIVE' AND c.identity_not_after>clock_timestamp() AND c.last_heartbeat_at BETWEEN clock_timestamp()-interval '2 minutes' AND clock_timestamp() AND cap.capability=j.query_kind AND h.availability='AVAILABLE' AND h.checked_at BETWEEN clock_timestamp()-interval '2 minutes' AND clock_timestamp()),false)
 FROM collection_repair_requests r JOIN collector_work_items w ON w.work_id=r.work_id JOIN collection_jobs j ON j.cluster_id=r.cluster_id AND j.job_id=r.job_id
 CROSS JOIN remediation_global_state gs LEFT JOIN remediation_policies p ON p.cluster_id=r.cluster_id AND p.policy_id=(SELECT a.policy_id FROM remediation_attempts a WHERE a.cluster_id=r.cluster_id AND a.attempt_id=r.attempt_id) AND p.version=(SELECT a.policy_version FROM remediation_attempts a WHERE a.cluster_id=r.cluster_id AND a.attempt_id=r.attempt_id)
 WHERE r.cluster_id=$1 AND r.run_id=$2 AND r.attempt_id=$3 AND r.status IN ('REQUESTED','CLAIMED','CANCEL_REQUESTED')
 FOR UPDATE OF r,w,j`, cluster, run, attempt).Scan(&requestID, &workStatus, &allowed)
	if err == pgx.ErrNoRows {
		return tx.Commit(ctx)
	}
	if err != nil {
		return fmt.Errorf("read repair reconciliation authority: %w", err)
	}
	if allowed {
		return tx.Commit(ctx)
	}
	var activeAttempt bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM collector_work_attempts a JOIN collection_repair_requests r ON r.work_id=a.work_id WHERE r.request_id=$1 AND a.status IN ('CLAIMED','STARTED') AND a.lease_expires_at>clock_timestamp())`, requestID).Scan(&activeAttempt); err != nil {
		return err
	}
	if workStatus == "AVAILABLE" || !activeAttempt {
		_, err = tx.Exec(ctx, `UPDATE collector_work_items SET status='CANCELLED',completed_at=clock_timestamp() WHERE work_id=(SELECT work_id FROM collection_repair_requests WHERE request_id=$1) AND status IN ('AVAILABLE','LEASED')`, requestID)
	} else {
		_, err = tx.Exec(ctx, `UPDATE collection_repair_requests SET status='CANCEL_REQUESTED',cancellation_requested_at=COALESCE(cancellation_requested_at,clock_timestamp()) WHERE request_id=$1 AND status IN ('REQUESTED','CLAIMED')`, requestID)
	}
	if err != nil {
		return fmt.Errorf("reconcile repair collection request: %w", err)
	}
	// Expired STARTED work may have performed the read even without delivery.
	// Stop retrying it, but never describe that ambiguity as undone execution.
	if workStatus != "AVAILABLE" && !activeAttempt {
		_, err = tx.Exec(ctx, `UPDATE collection_repair_requests r SET status='CONTAINED',cancellation_outcome='CONTAINED' WHERE r.request_id=$1 AND EXISTS(SELECT 1 FROM collector_work_attempts a WHERE a.work_id=r.work_id AND a.started_at IS NOT NULL)`, requestID)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// RequestRemediationCancellation is called only after application authorization.
// Its durable flag wins against a later effect, including the reservation gap.
func (s *RemediationStore) RequestRemediationCancellation(ctx context.Context, cluster domain.ClusterID, run domain.RemediationRunID, actor string) error {
	if actor == "" {
		return application.ErrRemediationForbidden
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err = LockRepairAuthority(ctx, tx, cluster); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE remediation_runs SET cancellation_requested_at=COALESCE(cancellation_requested_at,clock_timestamp()) WHERE cluster_id=$1 AND run_id=$2 AND assurance='LIVE' AND completed_at IS NULL`, cluster, run)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return application.ErrRemediationConflict
	}
	// Publish cancellation on the request in the same transaction. Result
	// finalization shares this advisory lock and must see CANCEL_REQUESTED even
	// when it beats the next reconciliation tick after the operator returns.
	if _, err = tx.Exec(ctx, `UPDATE collection_repair_requests SET status='CANCEL_REQUESTED',cancellation_requested_at=COALESCE(cancellation_requested_at,clock_timestamp()) WHERE cluster_id=$1 AND run_id=$2 AND status IN ('REQUESTED','CLAIMED')`, cluster, run); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ReconcilePendingCollectionRequests also visits requests belonging to contained
// runs. Ending supervision must not leave expired or revoked work active forever.
func (s *RemediationStore) ReconcilePendingCollectionRequests(ctx context.Context, cluster domain.ClusterID, limit int) error {
	rows, err := s.pool.Query(ctx, `SELECT run_id,attempt_id FROM collection_repair_requests WHERE cluster_id=$1 AND status IN ('REQUESTED','CLAIMED','CANCEL_REQUESTED') ORDER BY deadline_at,request_id LIMIT $2`, cluster, limit)
	if err != nil {
		return err
	}
	type key struct {
		run     domain.RemediationRunID
		attempt domain.RemediationAttemptID
	}
	var keys []key
	for rows.Next() {
		var k key
		if err = rows.Scan(&k.run, &k.attempt); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, k)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		if err = s.ReconcileCollectionRequest(ctx, cluster, k.run, k.attempt); err != nil {
			return err
		}
	}
	return nil
}

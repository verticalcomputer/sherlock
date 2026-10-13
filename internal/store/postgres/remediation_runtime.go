package postgres

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediation"
	"github.com/verticalcomputer/sherlock/internal/remediationrunner"
	"slices"
	"time"
)

// DiscoverRemediationCards uses an explicit reviewed rule-to-recipe mapping.
// Card prose and owner convey no execution authority; policy and citations are
// independently revalidated by the application and dispatch transaction.
func (s *RemediationStore) DiscoverRemediationCards(ctx context.Context, cluster domain.ClusterID, limit int) ([]application.ProposeRemediationInput, error) {
	return s.discoverRemediationCards(ctx, cluster, limit, false)
}

func (s *RemediationStore) DiscoverLiveRemediationCards(ctx context.Context, cluster domain.ClusterID, limit int) ([]application.ProposeRemediationInput, error) {
	return s.discoverRemediationCards(ctx, cluster, limit, true)
}

func (s *RemediationStore) discoverRemediationCards(ctx context.Context, cluster domain.ClusterID, limit int, live bool) ([]application.ProposeRemediationInput, error) {
	rows, err := s.pool.Query(ctx, `SELECT i.incident_id,i.investigation_id,c.action_card_id,c.targets,
 ARRAY(SELECT x.ledger_entry_id FROM investigation_action_card_citations x WHERE x.cluster_id=c.cluster_id AND x.investigation_id=c.investigation_id AND x.action_card_id=c.action_card_id ORDER BY x.ledger_entry_id)
 FROM investigation_action_cards c JOIN investigations i ON i.cluster_id=c.cluster_id AND i.investigation_id=c.investigation_id
 JOIN anomaly_incidents a ON a.cluster_id=i.cluster_id AND a.incident_id=i.incident_id
 WHERE c.cluster_id=$1 AND c.owner='SHERLOCK' AND i.status='COMPLETED' AND i.completed_at IS NOT NULL AND a.rule_id=$2
 AND (NOT $4::boolean OR EXISTS(SELECT 1 FROM schedule_repair_detections d JOIN investigation_action_card_citations cit ON cit.cluster_id=d.cluster_id AND cit.investigation_id=d.investigation_id AND cit.action_card_id=c.action_card_id JOIN investigation_evidence ev ON ev.cluster_id=cit.cluster_id AND ev.investigation_id=cit.investigation_id AND ev.ledger_entry_id=cit.ledger_entry_id AND ev.evidence_id=d.evidence_id WHERE d.cluster_id=c.cluster_id AND d.incident_id=i.incident_id AND d.investigation_id=i.investigation_id AND c.targets=ARRAY[d.job_id] AND cardinality(c.blocking_gaps)=0))
 AND NOT EXISTS(SELECT 1 FROM remediation_runs r WHERE r.cluster_id=c.cluster_id AND r.action_card_id=c.action_card_id)
 ORDER BY c.created_at,c.action_card_id LIMIT $3`, cluster, remediation.IncidentKindEvidenceStreamStale, limit, live)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []application.ProposeRemediationInput
	for rows.Next() {
		v := application.ProposeRemediationInput{ClusterID: cluster, ActorID: "sherlock-remediator", ValidFor: time.Hour}
		var targets []string
		if err = rows.Scan(&v.IncidentID, &v.InvestigationID, &v.ActionCardID, &targets, &v.Proposal.LedgerEntryIDs); err != nil {
			return nil, err
		}
		if len(v.Proposal.LedgerEntryIDs) == 0 {
			continue
		}
		v.Proposal.RecipeID = remediation.RecipeEvidenceCollectionRequeue
		v.Proposal.RecipeVersion = remediation.BuiltinRecipeVersion
		if live {
			v.Proposal.RecipeVersion = remediation.CollectionRequestRecipeVersion
		}
		v.Proposal.Arguments = []remediation.ProposedArgument{{Name: "requeue_reason", Value: "STALE_STREAM"}, {Name: "priority", Value: "NORMAL"}}
		v.Proposal.Rationale = "Reviewed stale-stream mapping from committed Action Card"
		for _, t := range targets {
			v.Proposal.Targets = append(v.Proposal.Targets, domain.RemediationTarget(t))
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// RemediationSupervisorClaim is an opaque fencing lease for one supervisor
// iteration. Generation distinguishes a current claimant from an earlier
// process using the same configured owner after expiry or restart.
type RemediationSupervisorClaim struct {
	RunID      domain.RemediationRunID
	Owner      string
	Generation int64
	ExpiresAt  time.Time
}

type remediationSupervisorClaimContextKey struct{}

const RemediationAuthorityLockTimeout = 1500 * time.Millisecond

// ErrRemediationAuthorityBusy is returned when another transaction retains a
// cluster's live-effect authority beyond the fixed acquisition bound. Callers
// may retry control-plane work, but must never infer that an effect did or did
// not commit from this error alone.
var ErrRemediationAuthorityBusy = errors.New("remediation authority is busy")

// LockRepairAuthority establishes the cluster-wide lock order shared by live
// effects, cancellation/reconciliation, recovery, and collector claim/start.
// PostgreSQL releases this transaction-scoped lock automatically. Acquisition
// waits for at most 1.5 seconds; a shorter caller deadline is preserved.
func LockRepairAuthority(ctx context.Context, tx pgx.Tx, cluster domain.ClusterID) error {
	if cluster == "" {
		return application.ErrRemediationLeaseInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout',$1,true)`, fmt.Sprintf("%dms", RemediationAuthorityLockTimeout.Milliseconds())); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("configure remediation authority timeout: %w", err)
	}
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('m15-repair:'||$1::text,0))`, cluster)
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
		return ErrRemediationAuthorityBusy
	}
	return fmt.Errorf("acquire remediation authority: %w", err)
}

// ContextWithRemediationSupervisorClaim carries the opaque claim to every
// transaction performed by one supervisor iteration. Effect-producing stores
// must validate it while holding the remediation run row lock, so lease expiry
// and takeover cannot race a committed effect.
func ContextWithRemediationSupervisorClaim(ctx context.Context, claim RemediationSupervisorClaim) context.Context {
	return context.WithValue(ctx, remediationSupervisorClaimContextKey{}, claim)
}

// RequireRemediationSupervisorClaim validates the caller's generation while
// locking the run row. The lock is retained by tx until commit or rollback;
// therefore a successor cannot claim the same run between this check and the
// transaction's durable writes.
func RequireRemediationSupervisorClaim(ctx context.Context, tx pgx.Tx, cluster domain.ClusterID, runID domain.RemediationRunID) error {
	claim, ok := ctx.Value(remediationSupervisorClaimContextKey{}).(RemediationSupervisorClaim)
	if !ok || claim.RunID != runID || claim.Owner == "" || claim.Generation < 1 {
		return application.ErrRemediationLeaseInvalid
	}
	var current bool
	err := tx.QueryRow(ctx, `SELECT supervisor_owner=$3 AND supervisor_generation=$4 AND supervisor_until>clock_timestamp()
		FROM remediation_runs WHERE cluster_id=$1 AND run_id=$2 FOR UPDATE`, cluster, runID, claim.Owner, claim.Generation).Scan(&current)
	if err == pgx.ErrNoRows || (err == nil && !current) {
		return application.ErrRemediationLeaseInvalid
	}
	return err
}

func (s *RemediationStore) ClaimRemediation(ctx context.Context, cluster domain.ClusterID, owner string, lease time.Duration) (RemediationSupervisorClaim, error) {
	if cluster == "" || !domain.ValidRemediationToken(owner) || lease < time.Second || lease > application.MaxRemediationLease {
		return RemediationSupervisorClaim{}, fmt.Errorf("remediation supervisor claim is invalid")
	}
	var claim RemediationSupervisorClaim
	claim.Owner = owner
	err := s.pool.QueryRow(ctx, `WITH candidate AS (SELECT run_id FROM remediation_runs WHERE cluster_id=$1 AND completed_at IS NULL AND (next_attempt_at IS NULL OR next_attempt_at<=clock_timestamp()) AND (supervisor_until IS NULL OR supervisor_until<=clock_timestamp()) ORDER BY created_at,run_id FOR UPDATE SKIP LOCKED LIMIT 1)
	 UPDATE remediation_runs r SET supervisor_owner=$2,supervisor_until=clock_timestamp()+($3*interval '1 millisecond'),supervisor_generation=r.supervisor_generation+1 FROM candidate c WHERE r.cluster_id=$1 AND r.run_id=c.run_id RETURNING r.run_id,r.supervisor_generation,r.supervisor_until`, cluster, owner, lease.Milliseconds()).Scan(&claim.RunID, &claim.Generation, &claim.ExpiresAt)
	if err == pgx.ErrNoRows {
		return RemediationSupervisorClaim{}, nil
	}
	if err != nil {
		return RemediationSupervisorClaim{}, err
	}
	claim.ExpiresAt = claim.ExpiresAt.UTC()
	return claim, nil
}

func (s *RemediationStore) ReleaseRemediation(ctx context.Context, cluster domain.ClusterID, claim RemediationSupervisorClaim, delay time.Duration) error {
	if cluster == "" || claim.RunID == "" || !domain.ValidRemediationToken(claim.Owner) || claim.Generation < 1 || delay < 0 || delay > time.Minute {
		return application.ErrRemediationLeaseInvalid
	}
	result, err := s.pool.Exec(ctx, `UPDATE remediation_runs SET supervisor_owner=NULL,supervisor_until=NULL,next_attempt_at=clock_timestamp()+($5*interval '1 millisecond') WHERE cluster_id=$1 AND run_id=$2 AND supervisor_owner=$3 AND supervisor_generation=$4`, cluster, claim.RunID, claim.Owner, claim.Generation, delay.Milliseconds())
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return application.ErrRemediationLeaseInvalid
	}
	return nil
}

func (s *RemediationStore) RemediationClaimCurrent(ctx context.Context, cluster domain.ClusterID, claim RemediationSupervisorClaim) (bool, error) {
	var current bool
	err := s.pool.QueryRow(ctx, `SELECT supervisor_owner=$3 AND supervisor_generation=$4 AND supervisor_until>clock_timestamp() FROM remediation_runs WHERE cluster_id=$1 AND run_id=$2`, cluster, claim.RunID, claim.Owner, claim.Generation).Scan(&current)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	return current, err
}

// RecoverCommittedLiveEffect closes the only acknowledged-result crash window:
// the live request/cancellation committed, but the process exited before its
// remediation receipt transaction. The request is merely proof that the
// bounded effect was accepted; collection evidence is still required later by
// verification. No plaintext attempt token is reconstructed or persisted.
func (s *RemediationStore) RecoverCommittedLiveEffect(ctx context.Context, cluster domain.ClusterID, runID domain.RemediationRunID, attemptID domain.RemediationAttemptID) (domain.RemediationRun, bool, error) {
	if cluster == "" || runID == "" || attemptID == "" {
		return domain.RemediationRun{}, false, application.ErrRemediationConflict
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.RemediationRun{}, false, fmt.Errorf("begin committed live effect recovery: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err = LockRepairAuthority(ctx, tx, cluster); err != nil {
		return domain.RemediationRun{}, false, err
	}
	if err = RequireRemediationSupervisorClaim(ctx, tx, cluster, runID); err != nil {
		return domain.RemediationRun{}, false, err
	}
	loaded, found, err := loadRemediationRun(ctx, tx, cluster, runID)
	if err != nil || !found {
		if err == nil {
			err = application.ErrRemediationNotFound
		}
		return domain.RemediationRun{}, false, err
	}
	plan := loaded.Run.Plan()
	if plan.Assurance != domain.AssuranceLive || plan.Recipe.ID != remediation.RecipeEvidenceCollectionRequeue ||
		plan.Recipe.Version != remediation.CollectionRequestRecipeVersion ||
		plan.Rollback.ID != remediation.RecipeEvidenceCollectionRestore ||
		plan.Rollback.Version != remediation.CollectionRequestRecipeVersion ||
		loaded.LatestAttemptID != attemptID || loaded.LatestReceipt || len(loaded.LatestTargets) != 1 {
		return domain.RemediationRun{}, false, nil
	}

	var stage domain.RemediationStage
	var idempotencyKey string
	var attemptCreated time.Time
	err = tx.QueryRow(ctx, `SELECT stage,idempotency_key,created_at
		FROM remediation_attempts WHERE cluster_id=$1 AND run_id=$2 AND attempt_id=$3 FOR UPDATE`,
		cluster, runID, attemptID).Scan(&stage, &idempotencyKey, &attemptCreated)
	if err == pgx.ErrNoRows {
		return domain.RemediationRun{}, false, nil
	}
	if err != nil {
		return domain.RemediationRun{}, false, fmt.Errorf("load committed live attempt: %w", err)
	}
	expectedState := domain.RemediationCanaryExecuting
	if stage == domain.RemediationStageRollout {
		expectedState = domain.RemediationRollingOut
	} else if stage == domain.RemediationStageRollback {
		expectedState = domain.RemediationRollingBack
	}
	if loaded.Run.State() != expectedState {
		return domain.RemediationRun{}, false, nil
	}

	target := loaded.LatestTargets[0]
	var effectID string
	if stage == domain.RemediationStageRollback {
		err = tx.QueryRow(ctx, `SELECT r.request_id
			FROM collection_repair_requests r
			JOIN remediation_schedule_snapshots p ON p.cluster_id=r.cluster_id AND p.run_id=r.run_id AND p.target=r.job_id AND p.live_request_id=r.request_id
			JOIN collector_work_items w ON w.work_id=r.work_id AND w.cluster_id=r.cluster_id AND w.run_id=r.request_id AND w.idempotency_key=r.idempotency_key AND w.deadline=r.deadline_at AND w.work_expires_at=r.deadline_at
			JOIN collection_run_jobs b ON b.run_id=w.run_id AND b.cluster_id=r.cluster_id AND b.job_id=r.job_id AND b.configuration_revision=r.configuration_revision AND b.source_id=w.source_id AND b.query_kind=w.query_kind AND b.node_filter=w.node_filter AND b.scheduled_for=w.scheduled_for
			WHERE r.cluster_id=$1 AND r.run_id=$2 AND r.job_id=$3 AND r.cancellation_attempt_id=$4
			  AND r.operation=$5 AND r.effect_receipt=r.request_id AND r.cancellation_requested_at IS NOT NULL
			  AND p.prior_revision=r.schedule_revision AND p.prior_configuration_revision=r.configuration_revision
			  AND r.request_id='repair-'||r.attempt_id||'-'||r.job_id AND r.work_id='repair-work-'||r.attempt_id||'-'||r.job_id
			  AND r.status IN ('CANCEL_REQUESTED','CANCELLED','CONTAINED')
			FOR UPDATE OF r,w`, cluster, runID, target, attemptID, string(remediation.OperationEvidenceCollectionRequeue)).Scan(&effectID)
	} else {
		err = tx.QueryRow(ctx, `SELECT r.request_id
			FROM collection_repair_requests r
			JOIN remediation_schedule_snapshots p ON p.cluster_id=r.cluster_id AND p.run_id=r.run_id AND p.target=r.job_id AND p.live_request_id=r.request_id
			JOIN collector_work_items w ON w.work_id=r.work_id AND w.cluster_id=r.cluster_id AND w.run_id=r.request_id AND w.idempotency_key=r.idempotency_key AND w.deadline=r.deadline_at AND w.work_expires_at=r.deadline_at
			JOIN collection_run_jobs b ON b.run_id=w.run_id AND b.cluster_id=r.cluster_id AND b.job_id=r.job_id AND b.configuration_revision=r.configuration_revision AND b.source_id=w.source_id AND b.query_kind=w.query_kind AND b.node_filter=w.node_filter AND b.scheduled_for=w.scheduled_for
			WHERE r.cluster_id=$1 AND r.run_id=$2 AND r.attempt_id=$4 AND r.job_id=$3
			  AND r.operation=$5 AND r.idempotency_key=$6 AND r.effect_receipt=r.request_id
			  AND p.prior_revision=r.schedule_revision AND p.prior_configuration_revision=r.configuration_revision
			  AND r.deadline_at=$7 AND r.request_id='repair-'||r.attempt_id||'-'||r.job_id AND r.work_id='repair-work-'||r.attempt_id||'-'||r.job_id
			FOR UPDATE OF r,w`, cluster, runID, target, attemptID, string(remediation.OperationEvidenceCollectionRequeue), idempotencyKey, loaded.DeadlineAt.UTC()).Scan(&effectID)
	}
	if err == pgx.ErrNoRows {
		return domain.RemediationRun{}, false, nil
	}
	if err != nil {
		return domain.RemediationRun{}, false, fmt.Errorf("load committed live effect: %w", err)
	}

	var observedAt time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&observedAt); err != nil {
		return domain.RemediationRun{}, false, err
	}
	observedAt = observedAt.UTC()
	if observedAt.Before(attemptCreated) {
		return domain.RemediationRun{}, false, application.ErrRemediationConflict
	}
	receiptSeed := domain.ChecksumSHA256([]byte("committed-live-effect\x00" + string(cluster) + "\x00" + string(runID) + "\x00" + string(attemptID) + "\x00" + effectID))
	receipt := domain.RemediationReceipt{
		ID: domain.RemediationReceiptID("recovered-" + receiptSeed.String()[:32]), RunID: runID,
		AttemptID: attemptID, ClusterID: cluster, IdempotencyKey: idempotencyKey, Stage: stage,
		Targets:   []domain.RemediationTarget{target},
		PerTarget: []domain.RemediationTargetOutcome{{Target: target, Outcome: domain.ExecutionExecuted}},
		Outcome:   domain.ExecutionExecuted, ObservedAt: observedAt,
	}
	receipt.Digest = receipt.ComputeDigest()
	report := domain.RemediationExecutionReport{Outcome: domain.ExecutionExecuted, ExecutedTargets: receipt.Targets, PerTarget: receipt.PerTarget}
	var advanced domain.RemediationRun
	switch stage {
	case domain.RemediationStageCanary:
		advanced, err = loaded.Run.RecordCanaryOutcome(report, observedAt)
	case domain.RemediationStageRollout:
		advanced, err = loaded.Run.RecordRolloutOutcome(report, observedAt)
	case domain.RemediationStageRollback:
		advanced, err = loaded.Run.RecordRollbackExecution(report, observedAt)
	default:
		return domain.RemediationRun{}, false, application.ErrRemediationConflict
	}
	if err != nil {
		return domain.RemediationRun{}, false, fmt.Errorf("advance recovered live effect: %w", err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO remediation_receipts
		(cluster_id,receipt_id,run_id,attempt_id,idempotency_key,stage,outcome,digest,observed_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, cluster, receipt.ID, runID, attemptID,
		idempotencyKey, string(stage), string(receipt.Outcome), digestBytes(receipt.Digest), observedAt); err != nil {
		return domain.RemediationRun{}, false, remediationConflict(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO remediation_receipt_targets(cluster_id,receipt_id,target,outcome)
		VALUES($1,$2,$3,$4)`, cluster, receipt.ID, target, string(domain.ExecutionExecuted)); err != nil {
		return domain.RemediationRun{}, false, remediationConflict(err)
	}
	if err = updateRemediationRun(ctx, tx, application.RemediationTransition{ClusterID: cluster, Run: advanced, ExpectedVersion: loaded.Run.Version()}); err != nil {
		return domain.RemediationRun{}, false, err
	}
	auditSeed := domain.ChecksumSHA256([]byte("committed-live-effect-audit\x00" + string(cluster) + "\x00" + string(runID) + "\x00" + string(attemptID)))
	if err = appendRemediationAudit(ctx, tx, application.RemediationAuditEvent{
		EventID: "recovery-" + auditSeed.String()[:32], Kind: application.RemediationAuditReceipt,
		ClusterID: cluster, RunID: runID, AttemptID: attemptID, ActorID: "sherlock-remediator",
		Outcome: string(domain.ExecutionExecuted), ReasonCode: "COMMITTED_EFFECT_RECOVERED",
		OccurredAt: observedAt, RecipeDigest: plan.Recipe.Digest, TargetSetDigest: plan.TargetSetDigest,
	}); err != nil {
		return domain.RemediationRun{}, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return domain.RemediationRun{}, false, fmt.Errorf("commit live effect recovery: %w", err)
	}
	return advanced, true, nil
}

// SimulateRemediation mutates only the isolated per-run simulation. Receipt
// replay is handled by the supervisor by containing ambiguity, never retrying.
func (s *RemediationStore) SimulateRemediation(ctx context.Context, catalog *remediation.Catalog, u domain.ExecutionUnit, now time.Time) (domain.ExecutionResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.ExecutionResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return domain.ExecutionResult{}, err
	}
	if err := remediationrunner.ValidateExecutionUnit(catalog, u, now); err != nil {
		return domain.ExecutionResult{}, err
	}
	loaded, found, err := loadRemediationRun(ctx, tx, u.ClusterID, u.RunID)
	if err != nil || !found {
		return domain.ExecutionResult{}, application.ErrRemediationForbidden
	}
	plan := loaded.Run.Plan()
	ref := plan.Recipe
	if u.Stage == domain.RemediationStageRollback {
		ref = plan.Rollback
	}
	if !u.Recipe.Matches(ref) || loaded.LatestAttemptID != u.AttemptID {
		return domain.ExecutionResult{}, application.ErrRemediationForbidden
	}
	var targets []domain.RemediationTarget
	for _, t := range u.Targets {
		targets = append(targets, t.Target)
	}
	if !slices.Equal(targets, loaded.LatestTargets) {
		return domain.ExecutionResult{}, application.ErrRemediationForbidden
	}
	recipe, _ := catalog.Resolve(ref)
	var expected domain.TypedArguments
	for _, a := range plan.Arguments {
		for _, p := range recipe.Parameters {
			if a.Name == p.Name {
				expected = append(expected, a)
			}
		}
	}
	if !slices.Equal(expected, u.Arguments) {
		return domain.ExecutionResult{}, application.ErrRemediationForbidden
	}
	var valid bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM remediation_attempts WHERE cluster_id=$1 AND run_id=$2 AND attempt_id=$3 AND idempotency_key=$4 AND stage=$5 AND lease_expires_at>clock_timestamp())`, u.ClusterID, u.RunID, u.AttemptID, u.IdempotencyKey, u.Stage).Scan(&valid)
	if err != nil || !valid {
		return domain.ExecutionResult{}, application.ErrRemediationForbidden
	}
	result := domain.ExecutionResult{Outcome: domain.ExecutionExecuted, ObservedAt: now}
	for _, target := range u.Targets {
		var tagRows int64
		if u.Stage == domain.RemediationStageRollback {
			tag, e := tx.Exec(ctx, `UPDATE remediation_simulation_state s SET active=p.prior_active,interval_seconds=p.prior_interval,next_run_at=p.prior_next,revision=s.revision+1,restored_revision=s.revision+1,last_attempt_id=$4,updated_at=clock_timestamp()
 FROM remediation_schedule_snapshots p WHERE s.cluster_id=$1 AND s.run_id=$2 AND s.target=$3 AND p.cluster_id=s.cluster_id AND p.run_id=s.run_id AND p.target=s.target AND s.revision=s.forward_revision AND s.restored_revision IS NULL`, u.ClusterID, u.RunID, target.Target, u.AttemptID)
			err = e
			tagRows = tag.RowsAffected()
		} else {
			tag, e := tx.Exec(ctx, `UPDATE remediation_simulation_state SET next_run_at=clock_timestamp(),active=true,revision=revision+1,forward_revision=revision+1,last_attempt_id=$4,updated_at=clock_timestamp() WHERE cluster_id=$1 AND run_id=$2 AND target=$3 AND forward_revision IS NULL`, u.ClusterID, u.RunID, target.Target, u.AttemptID)
			err = e
			tagRows = tag.RowsAffected()
		}
		if err != nil {
			return domain.ExecutionResult{}, fmt.Errorf("simulate remediation: %w", err)
		}
		outcome := domain.ExecutionExecuted
		if tagRows != 1 {
			outcome = domain.ExecutionFailed
			result.Outcome = domain.ExecutionFailed
		}
		result.PerTarget = append(result.PerTarget, domain.RemediationTargetOutcome{Target: target.Target, Outcome: outcome})
	}
	return result, tx.Commit(ctx)
}

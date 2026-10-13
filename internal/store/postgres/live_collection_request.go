package postgres

import (
	"context"
	"fmt"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/remediation"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediationlive"
	"github.com/verticalcomputer/sherlock/internal/remediationrunner"
)

// RequestCollection is the live adapter's single effect boundary. It locks
// the target and authorization rows, checks the preflight revision fence, and
// commits the one-time request, run provenance, and collector work together.
// It never updates collection_jobs scheduling progress.
func (s *RemediationStore) RequestCollection(ctx context.Context, request remediationlive.Request) (domain.ExecutionResult, error) {
	u := request.Unit
	if len(u.Targets) != 1 || u.Targets[0].Role != domain.RoleManagedCollectionStream || u.Targets[0].ClusterID != u.ClusterID {
		return domain.ExecutionResult{}, fmt.Errorf("live collection request requires one managed stream target")
	}
	target := string(u.Targets[0].Target)
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.ExecutionResult{}, fmt.Errorf("begin live collection request: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockLiveEffect(ctx, tx, u.ClusterID); err != nil {
		return domain.ExecutionResult{}, err
	}
	var dbNow time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&dbNow); err != nil {
		return domain.ExecutionResult{}, err
	}
	if err := validatePersistedLiveUnit(ctx, tx, request, dbNow, true); err != nil {
		return domain.ExecutionResult{}, err
	}

	var active, policyEnabled, globallyEnabled, collectorReady, attemptLive, detectorBound bool
	var configRevision, scheduleRevision int64
	var sourceID domain.SourceID
	var query domain.QueryKind
	var node string
	err = tx.QueryRow(ctx, `
SELECT j.active AND (j.lease_expires_at IS NULL OR j.lease_expires_at<=clock_timestamp()) AND NOT EXISTS(SELECT 1 FROM collection_run_jobs b JOIN collector_work_items w ON w.run_id=b.run_id WHERE b.cluster_id=j.cluster_id AND b.job_id=j.job_id AND w.status IN ('AVAILABLE','LEASED') AND w.idempotency_key<>$7),j.configuration_revision,j.schedule_revision,j.source_id,j.query_kind,j.node_filter,
       gs.remediation_enabled,
       COALESCE(p.enabled AND p.recipe_id=$3 AND p.recipe_version=$4 AND p.max_tier>=1
         AND p.not_before<=clock_timestamp() AND p.not_after>clock_timestamp() AND p.revoked_at IS NULL,false),
       EXISTS(SELECT 1 FROM collectors c JOIN collector_capabilities cap ON cap.collector_id=c.collector_id
              JOIN collector_source_health h ON h.collector_id=c.collector_id AND h.source_id=j.source_id
              WHERE c.cluster_id=j.cluster_id AND c.status='ACTIVE' AND c.identity_not_after>clock_timestamp()
                AND c.last_heartbeat_at BETWEEN clock_timestamp()-interval '2 minutes' AND clock_timestamp() AND cap.capability=j.query_kind
                AND h.availability='AVAILABLE' AND h.checked_at BETWEEN clock_timestamp()-interval '2 minutes' AND clock_timestamp()),
       EXISTS(SELECT 1 FROM remediation_attempts a JOIN remediation_runs r ON r.cluster_id=a.cluster_id AND r.run_id=a.run_id
              WHERE a.cluster_id=j.cluster_id AND a.attempt_id=$5 AND a.run_id=$6 AND r.run_id=$6
                AND a.lease_expires_at>clock_timestamp() AND r.lease_expires_at>clock_timestamp()
                AND r.cancellation_requested_at IS NULL AND r.state IN ('CANARY_EXECUTING','ROLLING_OUT')),
       EXISTS(SELECT 1 FROM remediation_runs r JOIN schedule_repair_detections d
                ON d.cluster_id=r.cluster_id AND d.incident_id=r.incident_id AND d.investigation_id=r.investigation_id
              JOIN remediation_run_evidence e ON e.cluster_id=r.cluster_id AND e.run_id=r.run_id
              JOIN investigation_evidence ev ON ev.cluster_id=r.cluster_id AND ev.investigation_id=r.investigation_id
                AND ev.ledger_entry_id=e.ledger_entry_id AND ev.evidence_id=d.evidence_id
              WHERE r.cluster_id=j.cluster_id AND r.run_id=$6 AND d.job_id=j.job_id AND d.source_id=j.source_id
                AND d.configuration_revision=j.configuration_revision AND d.schedule_revision=j.schedule_revision)
FROM collection_jobs j
CROSS JOIN remediation_global_state gs
LEFT JOIN remediation_policies p ON p.cluster_id=j.cluster_id AND p.policy_id=(SELECT a.policy_id FROM remediation_attempts a WHERE a.cluster_id=j.cluster_id AND a.attempt_id=$5) AND p.version=(SELECT a.policy_version FROM remediation_attempts a WHERE a.cluster_id=j.cluster_id AND a.attempt_id=$5)
WHERE j.cluster_id=$1 AND j.job_id=$2
FOR UPDATE OF j`, u.ClusterID, target, u.Recipe.ID, u.Recipe.Version, u.AttemptID, u.RunID, u.IdempotencyKey).Scan(
		&active, &configRevision, &scheduleRevision, &sourceID, &query, &node,
		&globallyEnabled, &policyEnabled, &collectorReady, &attemptLive, &detectorBound)
	if err == pgx.ErrNoRows {
		return domain.ExecutionResult{}, fmt.Errorf("live collection target is unknown")
	}
	if err != nil {
		return domain.ExecutionResult{}, fmt.Errorf("read live collection authority: %w", err)
	}
	if !active || !globallyEnabled || !policyEnabled || !collectorReady || !attemptLive || !detectorBound {
		return liveOutcome(u, domain.ExecutionRefused, dbNow), nil
	}

	var priorRevision, priorConfig int64
	err = tx.QueryRow(ctx, `SELECT prior_revision,COALESCE(prior_configuration_revision,0)
FROM remediation_schedule_snapshots WHERE cluster_id=$1 AND run_id=$2 AND target=$3 FOR UPDATE`,
		u.ClusterID, u.RunID, target).Scan(&priorRevision, &priorConfig)
	if err != nil && err != pgx.ErrNoRows {
		return domain.ExecutionResult{}, err
	}
	if err == pgx.ErrNoRows || priorRevision != scheduleRevision || priorConfig != configRevision {
		return liveOutcome(u, domain.ExecutionRefused, dbNow), nil
	}

	requestID := "repair-" + string(u.AttemptID) + "-" + target
	workID := "repair-work-" + string(u.AttemptID) + "-" + target
	_, err = tx.Exec(ctx, `INSERT INTO collection_run_jobs
 (run_id,job_id,cluster_id,source_id,query_kind,node_filter,scheduled_for,configuration_revision,lease_generation)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,1) ON CONFLICT DO NOTHING`, requestID, target, u.ClusterID, sourceID, query, node, dbNow.UTC(), configRevision)
	if err != nil {
		return domain.ExecutionResult{}, fmt.Errorf("bind live collection run: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO collector_work_items
 (work_id,run_id,cluster_id,source_id,query_kind,node_filter,scheduled_for,deadline,max_series,max_bytes,idempotency_key,available_at,work_expires_at)
	 VALUES($1,$2,$3,$4,$5,$6,$7,$8,10000,10485760,$9,$7,$8)
 ON CONFLICT (idempotency_key) DO NOTHING`, workID, requestID, u.ClusterID, sourceID, query, node, dbNow.UTC(), u.Deadline.UTC(), u.IdempotencyKey)
	if err != nil {
		return domain.ExecutionResult{}, fmt.Errorf("enqueue live collection work: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO collection_repair_requests
 (request_id,cluster_id,run_id,attempt_id,job_id,operation,configuration_revision,schedule_revision,idempotency_key,status,deadline_at,effect_receipt,work_id)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'REQUESTED',$10,$1,$11)
 ON CONFLICT (idempotency_key) DO NOTHING`, requestID, u.ClusterID, u.RunID, u.AttemptID, target, u.Operation,
		configRevision, scheduleRevision, u.IdempotencyKey, u.Deadline.UTC(), workID)
	if err != nil {
		return domain.ExecutionResult{}, fmt.Errorf("record live collection request: %w", err)
	}
	var same bool
	if err = tx.QueryRow(ctx, `SELECT request_id=$2 AND cluster_id=$3 AND run_id=$4 AND attempt_id=$5 AND job_id=$6 AND work_id=$7
FROM collection_repair_requests WHERE idempotency_key=$1`, u.IdempotencyKey, requestID, u.ClusterID, u.RunID, u.AttemptID, target, workID).Scan(&same); err != nil {
		return domain.ExecutionResult{}, err
	}
	if !same {
		return domain.ExecutionResult{}, fmt.Errorf("live collection request replay conflicts with persisted attempt")
	}
	_, err = tx.Exec(ctx, `UPDATE remediation_schedule_snapshots SET live_request_id=$4
 WHERE cluster_id=$1 AND run_id=$2 AND target=$3`, u.ClusterID, u.RunID, target, requestID)
	if err != nil {
		return domain.ExecutionResult{}, fmt.Errorf("bind live request provenance: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return domain.ExecutionResult{}, fmt.Errorf("commit live collection effect: %w", err)
	}
	return domain.ExecutionResult{Outcome: domain.ExecutionExecuted, PerTarget: []domain.RemediationTargetOutcome{{Target: u.Targets[0].Target, Outcome: domain.ExecutionExecuted}}, ObservedAt: dbNow.UTC()}, nil
}

// CancelCollection compensates only an unclaimed forward request.  It never
// restores a periodic schedule or deletes evidence. A lease that might already
// reach a collector is marked for reconciliation and will end CONTAINED if a
// result subsequently arrives.
func (s *RemediationStore) CancelCollection(ctx context.Context, request remediationlive.Request) (domain.ExecutionResult, error) {
	u := request.Unit
	if len(u.Targets) != 1 {
		return domain.ExecutionResult{}, fmt.Errorf("live cancellation requires one target")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.ExecutionResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockLiveEffect(ctx, tx, u.ClusterID); err != nil {
		return domain.ExecutionResult{}, err
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return domain.ExecutionResult{}, err
	}
	if err = validatePersistedLiveUnit(ctx, tx, request, now, false); err != nil {
		return domain.ExecutionResult{}, err
	}
	var requestID, status, workStatus string
	err = tx.QueryRow(ctx, `SELECT r.request_id,r.status,w.status FROM remediation_schedule_snapshots p
JOIN collection_repair_requests r ON r.request_id=p.live_request_id JOIN collector_work_items w ON w.work_id=r.work_id
WHERE p.cluster_id=$1 AND p.run_id=$2 AND p.target=$3 FOR UPDATE OF r,w`, u.ClusterID, u.RunID, u.Targets[0].Target).Scan(&requestID, &status, &workStatus)
	if err == pgx.ErrNoRows {
		return liveOutcome(u, domain.ExecutionRefused, now), nil
	}
	if err != nil {
		return domain.ExecutionResult{}, err
	}
	if status == "COMPLETED" || status == "CONTAINED" {
		return liveOutcome(u, domain.ExecutionRefused, now), nil
	}
	if status == "CANCELLED" {
		if _, err = tx.Exec(ctx, `UPDATE collection_repair_requests SET cancellation_attempt_id=$2,cancellation_requested_at=COALESCE(cancellation_requested_at,clock_timestamp()) WHERE request_id=$1`, requestID, u.AttemptID); err != nil {
			return domain.ExecutionResult{}, err
		}
		if err = tx.Commit(ctx); err != nil {
			return domain.ExecutionResult{}, err
		}
		return liveOutcome(u, domain.ExecutionExecuted, now), nil
	}
	if _, err = tx.Exec(ctx, `UPDATE collection_repair_requests SET cancellation_attempt_id=$2,cancellation_requested_at=COALESCE(cancellation_requested_at,clock_timestamp()),status='CANCEL_REQUESTED' WHERE request_id=$1`, requestID, u.AttemptID); err != nil {
		return domain.ExecutionResult{}, err
	}
	if workStatus == "AVAILABLE" {
		if _, err = tx.Exec(ctx, `UPDATE collector_work_items SET status='CANCELLED',completed_at=clock_timestamp() WHERE work_id=(SELECT work_id FROM collection_repair_requests WHERE request_id=$1) AND status='AVAILABLE'`, requestID); err != nil {
			return domain.ExecutionResult{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return domain.ExecutionResult{}, err
	}
	return domain.ExecutionResult{Outcome: domain.ExecutionExecuted, PerTarget: []domain.RemediationTargetOutcome{{Target: u.Targets[0].Target, Outcome: domain.ExecutionExecuted}}, ObservedAt: now.UTC()}, nil
}

var _ remediationlive.Store = (*RemediationStore)(nil)

func liveOutcome(u domain.ExecutionUnit, outcome domain.ExecutionOutcome, now time.Time) domain.ExecutionResult {
	return domain.ExecutionResult{Outcome: outcome, ObservedAt: now.UTC(), PerTarget: []domain.RemediationTargetOutcome{{Target: u.Targets[0].Target, Outcome: outcome}}}
}

// Use the same order as dispatch. These short database-only locks are deliberately
// measured in M15 performance acceptance; no source/network call occurs here.
func lockLiveEffect(ctx context.Context, tx pgx.Tx, cluster domain.ClusterID) error {
	if err := LockRepairAuthority(ctx, tx, cluster); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT public.sherlock_m15_lock_live_effect_facts($1)`, cluster)
	return err
}

func validatePersistedLiveUnit(ctx context.Context, tx pgx.Tx, request remediationlive.Request, now time.Time, authorize bool) error {
	u := request.Unit
	if err := remediationrunner.ValidateExecutionUnit(request.Catalog, u, now); err != nil {
		return err
	}
	if err := RequireRemediationSupervisorClaim(ctx, tx, u.ClusterID, u.RunID); err != nil {
		return err
	}
	loaded, found, err := loadRemediationRun(ctx, tx, u.ClusterID, u.RunID)
	if err != nil {
		return err
	}
	if !found {
		return application.ErrRemediationForbidden
	}
	p := loaded.Run.Plan()
	ref := p.Recipe
	expectedState := domain.RemediationCanaryExecuting
	if u.Stage == domain.RemediationStageRollback {
		ref = p.Rollback
		expectedState = domain.RemediationRollingBack
	} else if u.Stage == domain.RemediationStageRollout {
		expectedState = domain.RemediationRollingOut
	}
	if loaded.Run.State() != expectedState || loaded.LatestAttemptID != u.AttemptID || ref != u.Recipe || p.Assurance != domain.AssuranceLive || !u.Deadline.Equal(loaded.DeadlineAt) {
		return application.ErrRemediationForbidden
	}
	recipe, err := request.Catalog.Resolve(ref)
	if err != nil {
		return err
	}
	var args domain.TypedArguments
	for _, a := range p.Arguments {
		for _, definition := range recipe.Parameters {
			if definition.Name == a.Name {
				args = append(args, a)
			}
		}
	}
	var targets []domain.ResolvedTarget
	for _, target := range p.Targets {
		if slices.Contains(loaded.LatestTargets, target.Target) {
			targets = append(targets, target)
		}
	}
	if !slices.Equal(args, u.Arguments) || !slices.Equal(targets, u.Targets) {
		return application.ErrRemediationForbidden
	}
	var policyID string
	var policyVersion int
	var reservedAt time.Time
	err = tx.QueryRow(ctx, `SELECT policy_id,policy_version,created_at FROM remediation_attempts WHERE cluster_id=$1 AND run_id=$2 AND attempt_id=$3 AND stage=$4 AND idempotency_key=$5 AND lease_expires_at>clock_timestamp() FOR UPDATE`, u.ClusterID, u.RunID, u.AttemptID, u.Stage, u.IdempotencyKey).Scan(&policyID, &policyVersion, &reservedAt)
	if err != nil {
		return application.ErrRemediationForbidden
	}
	if !authorize {
		return nil
	}
	facts, err := readRemediationFacts(ctx, tx, application.RemediationFactQuery{ClusterID: u.ClusterID, RunID: u.RunID, IncidentID: p.IncidentID, InvestigationID: p.InvestigationID, RecipeID: p.Recipe.ID, RecipeVersion: p.Recipe.Version, TargetSetDigest: p.TargetSetDigest})
	if err != nil {
		return err
	}
	forward, err := request.Catalog.Resolve(p.Recipe)
	if err != nil {
		return err
	}
	rollback, err := request.Catalog.Resolve(p.Rollback)
	if err != nil {
		return err
	}
	resolution, err := remediation.ResolveTargets(remediation.ResolutionInput{ClusterID: u.ClusterID, IncidentID: p.IncidentID, Recipe: forward, Inventory: facts.Inventory, Proposed: p.TargetList(), Now: facts.Now})
	if err != nil {
		return err
	}
	// The effect consumes its already authenticated reservation, not a new one.
	// Exclude only that exact reservation when it belongs to the counted window.
	windowAttempts := facts.ForwardAttemptsInWindow
	if windowAttempts != nil && *windowAttempts > 0 && u.Stage != domain.RemediationStageRollback && !reservedAt.Before(facts.Policy.NotBefore) && reservedAt.Before(facts.Policy.NotAfter) {
		otherAttempts := *windowAttempts - 1
		windowAttempts = &otherAttempts
	}
	decision := remediation.Evaluate(remediation.PolicyInput{Now: facts.Now, StateObservedAt: facts.StateObservedAt, PopulationObservedAt: facts.PopulationObservedAt, Policy: facts.Policy, Recipe: forward, RollbackRecipe: &rollback, Stage: u.Stage, ClusterID: u.ClusterID, InvestigationID: p.InvestigationID, IncidentKind: facts.IncidentKind, ResolvedTargets: resolution.Targets, RolePopulation: resolution.Population, PinnedRolePopulation: loaded.PinnedPopulation, Evidence: facts.Evidence, ActiveRuns: facts.ActiveRuns, NoActiveEquivalentRun: facts.NoActiveEquivalentRun, AttemptsUsed: loaded.Run.Progress().TotalAttempts - 1, ForwardAttemptsInWindow: windowAttempts, LastRunEndedAt: facts.LastRunEndedAt, RemediationEnabledGlobal: facts.EnabledGlobal, RemediationEnabledCluster: facts.EnabledCluster})
	if !decision.Allowed || string(decision.PolicyID) != policyID || decision.PolicyVersion != policyVersion {
		return application.ErrRemediationForbidden
	}
	return nil
}

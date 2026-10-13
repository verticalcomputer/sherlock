package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediation"
)

// RemediationStore is the durable side of the remediation subsystem. Every
// authorization fact it returns is reconstructed by joining durable rows: no
// method trusts a request field, an identifier, a timestamp or a source label
// supplied by the caller, and every server-causal instant comes from
// clock_timestamp() rather than from an application host.
type RemediationStore struct{ pool *pgxpool.Pool }

func NewRemediationStore(pool *pgxpool.Pool) (*RemediationStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	return &RemediationStore{pool: pool}, nil
}

// terminal states, duplicated here only as a query predicate. The authoritative
// definition is the domain transition table and the CHECK constraint that
// mirrors it.
const remediationTerminalStates = `('SUCCEEDED','POLICY_BLOCKED','PREFLIGHT_FAILED','ROLLED_BACK','ROLLBACK_FAILED','CONTAINED','FAILED','CANCELLED','EXPIRED')`

// remediationConflict translates a constraint violation into an application
// conflict at the store boundary. A raw SQL error never escapes: the message
// would name relations, columns and values to a caller that is not entitled to
// any of them.
func remediationConflict(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505", "23503", "23514", "23P01":
			return application.ErrRemediationConflict
		}
	}
	return err
}

func isRemediationUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return false
	}
	return constraint == "" || pgErr.ConstraintName == constraint
}

// CreateRemediationRun is transaction 1: the run row, its resolved targets, its
// typed arguments, its cited ledger entries, the audit-only recipe references
// and the audit event all commit together, or none of them do.
//
// Two concurrent equivalent incidents collide on the active-repair partial
// unique index. That collision is answered with the run that already exists
// rather than with a second repair, which is the whole point of the index: the
// idempotency key contains the run identifier and so could never collide across
// two runs.
func (store *RemediationStore) CreateRemediationRun(ctx context.Context, input application.CreateRemediationRunInput, audit application.RemediationAuditEvent) (domain.RemediationRun, bool, error) {
	plan := input.Run.Plan()
	if err := plan.Validate(); err != nil {
		return domain.RemediationRun{}, false, err
	}
	if input.DeadlineAt.IsZero() || input.PinnedPopulation < 1 {
		return domain.RemediationRun{}, false, fmt.Errorf("remediation run requires a deadline and an observed role population")
	}
	if audit.ClusterID != plan.ClusterID {
		return domain.RemediationRun{}, false, application.ErrRemediationConflict
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.RemediationRun{}, false, fmt.Errorf("begin remediation creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, record := range append([]application.RemediationRecipeRecord{input.Recipe}, optionalRecipe(input.Rollback)...) {
		if _, err := tx.Exec(ctx, `INSERT INTO remediation_recipe_refs (recipe_id, version, digest, tier, operation, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (recipe_id, version, digest) DO NOTHING`,
			record.Ref.ID, record.Ref.Version, record.Ref.Digest[:], int(record.Tier), record.Operation, record.ExpiresAt.UTC()); err != nil {
			return domain.RemediationRun{}, false, remediationConflict(err)
		}
	}

	var rollbackID, rollbackVersion *string
	var rollbackDigest []byte
	if plan.HasRollback() {
		id, version := string(plan.Rollback.ID), plan.Rollback.Version
		rollbackID, rollbackVersion, rollbackDigest = &id, &version, plan.Rollback.Digest[:]
	}
	var actionCard *string
	if plan.ActionCardID != "" {
		card := string(plan.ActionCardID)
		actionCard = &card
	}
	_, err = tx.Exec(ctx, `INSERT INTO remediation_runs (
			cluster_id, run_id, incident_id, investigation_id, action_card_id, state, version,
			recipe_id, recipe_version, recipe_digest, rollback_recipe_id, rollback_recipe_version, rollback_recipe_digest,
			tier, privilege, assurance, target_set_digest, arguments_digest, pinned_population,
			max_targets, max_concurrency, canary_targets, max_attempts, deadline_at, proposed_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)`,
		plan.ClusterID, plan.RunID, plan.IncidentID, plan.InvestigationID, actionCard,
		string(input.Run.State()), input.Run.Version(),
		plan.Recipe.ID, plan.Recipe.Version, plan.Recipe.Digest[:], rollbackID, rollbackVersion, rollbackDigest,
		int(plan.Tier), string(plan.Privilege), string(plan.Assurance),
		plan.TargetSetDigest[:], digestBytes(plan.Arguments.Digest()), input.PinnedPopulation,
		plan.MaxTargets, plan.MaxConcurrency, plan.CanaryTargets, plan.MaxAttempts,
		input.DeadlineAt.UTC(), plan.ProposedAt.UTC(), plan.ExpiresAt.UTC())
	if err != nil {
		if isRemediationUniqueViolation(err, "remediation_runs_active_repair_key") {
			_ = tx.Rollback(ctx)
			prior, found, loadErr := store.LoadRemediationRun(ctx, plan.ClusterID, activeRemediationRunID(ctx, store.pool, plan))
			if loadErr != nil {
				return domain.RemediationRun{}, false, loadErr
			}
			if !found {
				return domain.RemediationRun{}, false, application.ErrRemediationConflict
			}
			return prior.Run, false, nil
		}
		return domain.RemediationRun{}, false, remediationConflict(err)
	}

	for ordinal, target := range plan.Targets {
		if _, err := tx.Exec(ctx, `INSERT INTO remediation_run_targets (cluster_id, run_id, ordinal, target, role, source_relation, resolved_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			plan.ClusterID, plan.RunID, ordinal, target.Target, string(target.Role), string(target.Source), target.ResolvedAt.UTC()); err != nil {
			return domain.RemediationRun{}, false, remediationConflict(err)
		}
	}
	for _, argument := range plan.Arguments {
		if _, err := tx.Exec(ctx, `INSERT INTO remediation_run_arguments (cluster_id, run_id, name, argument_type, enum_value, integer_value, duration_value, boolean_value)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			plan.ClusterID, plan.RunID, argument.Name, string(argument.Type), argument.Enum,
			argument.Integer, int64(argument.Duration), argument.Boolean); err != nil {
			return domain.RemediationRun{}, false, remediationConflict(err)
		}
	}
	for _, entryID := range input.LedgerEntryIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO remediation_run_evidence (cluster_id, run_id, investigation_id, ledger_entry_id)
			VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
			plan.ClusterID, plan.RunID, plan.InvestigationID, entryID); err != nil {
			return domain.RemediationRun{}, false, remediationConflict(err)
		}
	}
	if err := appendRemediationAudit(ctx, tx, audit); err != nil {
		return domain.RemediationRun{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.RemediationRun{}, false, fmt.Errorf("commit remediation creation: %w", err)
	}
	return input.Run, true, nil
}

func activeRemediationRunID(ctx context.Context, query remediationQuerier, plan domain.RemediationPlan) domain.RemediationRunID {
	var runID domain.RemediationRunID
	if err := query.QueryRow(ctx, `SELECT run_id FROM remediation_runs
		WHERE cluster_id=$1 AND recipe_id=$2 AND target_set_digest=$3 AND state NOT IN `+remediationTerminalStates,
		plan.ClusterID, plan.Recipe.ID, plan.TargetSetDigest[:]).Scan(&runID); err != nil {
		return ""
	}
	return runID
}

type remediationQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// LoadRemediationRun reconstructs the aggregate, its bounded-loop budgets and
// the executed-target set entirely from durable rows. A control process that
// restarted mid-run recovers exactly this and nothing else, so no in-memory
// state participates in a later authorization.
func (store *RemediationStore) LoadRemediationRun(ctx context.Context, clusterID domain.ClusterID, runID domain.RemediationRunID) (application.LoadedRemediationRun, bool, error) {
	if clusterID == "" || runID == "" {
		return application.LoadedRemediationRun{}, false, nil
	}
	return loadRemediationRun(ctx, store.pool, clusterID, runID)
}

func loadRemediationRun(ctx context.Context, query remediationQuerier, clusterID domain.ClusterID, runID domain.RemediationRunID) (application.LoadedRemediationRun, bool, error) {
	var plan domain.RemediationPlan
	var state string
	var version, tier int
	var recipeDigest, targetSetDigest, argumentsDigest []byte
	var rollbackID, rollbackVersion, actionCard, containedReason *string
	var rollbackDigest []byte
	var loaded application.LoadedRemediationRun
	var progress domain.RemediationProgress
	err := query.QueryRow(ctx, `SELECT incident_id, investigation_id, action_card_id, state, version,
			recipe_id, recipe_version, recipe_digest, rollback_recipe_id, rollback_recipe_version, rollback_recipe_digest,
			tier, privilege, assurance, target_set_digest, arguments_digest, pinned_population,
			max_targets, max_concurrency, canary_targets, max_attempts,
			rollout_wave, rollback_attempt, total_attempts, contained_reason, deadline_at, proposed_at, expires_at
		FROM remediation_runs WHERE cluster_id=$1 AND run_id=$2`, clusterID, runID).Scan(
		&plan.IncidentID, &plan.InvestigationID, &actionCard, &state, &version,
		&plan.Recipe.ID, &plan.Recipe.Version, &recipeDigest, &rollbackID, &rollbackVersion, &rollbackDigest,
		&tier, &plan.Privilege, &plan.Assurance, &targetSetDigest, &argumentsDigest, &loaded.PinnedPopulation,
		&plan.MaxTargets, &plan.MaxConcurrency, &plan.CanaryTargets, &plan.MaxAttempts,
		&progress.RolloutWave, &progress.RollbackAttempt, &progress.TotalAttempts,
		&containedReason, &loaded.DeadlineAt, &plan.ProposedAt, &plan.ExpiresAt)
	if err == pgx.ErrNoRows {
		return application.LoadedRemediationRun{}, false, nil
	}
	if err != nil {
		return application.LoadedRemediationRun{}, false, fmt.Errorf("load remediation run: %w", err)
	}
	plan.RunID, plan.ClusterID, plan.Tier = runID, clusterID, domain.AutonomyTier(tier)
	if actionCard != nil {
		plan.ActionCardID = domain.ActionCardID(*actionCard)
	}
	if containedReason != nil {
		loaded.ContainedReason = *containedReason
	}
	if err := copyRemediationDigest(&plan.Recipe.Digest, recipeDigest); err != nil {
		return application.LoadedRemediationRun{}, false, err
	}
	if err := copyRemediationDigest(&plan.TargetSetDigest, targetSetDigest); err != nil {
		return application.LoadedRemediationRun{}, false, err
	}
	if rollbackID != nil && rollbackVersion != nil {
		plan.Rollback.ID, plan.Rollback.Version = domain.RecipeID(*rollbackID), *rollbackVersion
		if err := copyRemediationDigest(&plan.Rollback.Digest, rollbackDigest); err != nil {
			return application.LoadedRemediationRun{}, false, err
		}
	}

	targetRows, err := query.Query(ctx, `SELECT target, role, source_relation, resolved_at
		FROM remediation_run_targets WHERE cluster_id=$1 AND run_id=$2 ORDER BY ordinal`, clusterID, runID)
	if err != nil {
		return application.LoadedRemediationRun{}, false, fmt.Errorf("load remediation targets: %w", err)
	}
	for targetRows.Next() {
		target := domain.ResolvedTarget{ClusterID: clusterID}
		if err := targetRows.Scan(&target.Target, &target.Role, &target.Source, &target.ResolvedAt); err != nil {
			targetRows.Close()
			return application.LoadedRemediationRun{}, false, fmt.Errorf("scan remediation target: %w", err)
		}
		plan.Targets = append(plan.Targets, target)
	}
	targetRows.Close()
	if err := targetRows.Err(); err != nil {
		return application.LoadedRemediationRun{}, false, fmt.Errorf("load remediation targets: %w", err)
	}

	argumentRows, err := query.Query(ctx, `SELECT name, argument_type, enum_value, integer_value, duration_value, boolean_value
		FROM remediation_run_arguments WHERE cluster_id=$1 AND run_id=$2 ORDER BY name`, clusterID, runID)
	if err != nil {
		return application.LoadedRemediationRun{}, false, fmt.Errorf("load remediation arguments: %w", err)
	}
	for argumentRows.Next() {
		var argument domain.TypedArgument
		var duration int64
		if err := argumentRows.Scan(&argument.Name, &argument.Type, &argument.Enum, &argument.Integer, &duration, &argument.Boolean); err != nil {
			argumentRows.Close()
			return application.LoadedRemediationRun{}, false, fmt.Errorf("scan remediation argument: %w", err)
		}
		argument.Duration = time.Duration(duration)
		plan.Arguments = append(plan.Arguments, argument)
	}
	argumentRows.Close()
	if err := argumentRows.Err(); err != nil {
		return application.LoadedRemediationRun{}, false, fmt.Errorf("load remediation arguments: %w", err)
	}
	// The persisted arguments must still digest to what the run was authorized
	// against. A mutated arguments row would otherwise reuse a receipt recorded
	// for values nobody approved.
	if plan.Arguments.Digest() != digestValue(argumentsDigest) {
		return application.LoadedRemediationRun{}, false, application.ErrRemediationConflict
	}

	executedRows, err := query.Query(ctx, `SELECT DISTINCT t.target
		FROM remediation_receipt_targets t
		JOIN remediation_receipts r ON r.cluster_id=t.cluster_id AND r.receipt_id=t.receipt_id
		WHERE r.cluster_id=$1 AND r.run_id=$2 AND t.outcome='EXECUTED' ORDER BY t.target`, clusterID, runID)
	if err != nil {
		return application.LoadedRemediationRun{}, false, fmt.Errorf("load executed remediation targets: %w", err)
	}
	for executedRows.Next() {
		var target domain.RemediationTarget
		if err := executedRows.Scan(&target); err != nil {
			executedRows.Close()
			return application.LoadedRemediationRun{}, false, fmt.Errorf("scan executed remediation target: %w", err)
		}
		loaded.ExecutedTargets = append(loaded.ExecutedTargets, target)
	}
	executedRows.Close()
	if err := executedRows.Err(); err != nil {
		return application.LoadedRemediationRun{}, false, fmt.Errorf("load executed remediation targets: %w", err)
	}

	attemptRows, err := query.Query(ctx, `SELECT stage, count(*) FROM remediation_attempts
		WHERE cluster_id=$1 AND run_id=$2 GROUP BY stage ORDER BY stage`, clusterID, runID)
	if err != nil {
		return application.LoadedRemediationRun{}, false, fmt.Errorf("load remediation attempt counts: %w", err)
	}
	for attemptRows.Next() {
		var entry application.RemediationStageAttempts
		if err := attemptRows.Scan(&entry.Stage, &entry.Used); err != nil {
			attemptRows.Close()
			return application.LoadedRemediationRun{}, false, fmt.Errorf("scan remediation attempt count: %w", err)
		}
		loaded.StageAttempts = append(loaded.StageAttempts, entry)
	}
	attemptRows.Close()
	if err := attemptRows.Err(); err != nil {
		return application.LoadedRemediationRun{}, false, fmt.Errorf("load remediation attempt counts: %w", err)
	}

	evidenceRows, err := query.Query(ctx, `SELECT ledger_entry_id FROM remediation_run_evidence
		WHERE cluster_id=$1 AND run_id=$2 ORDER BY ledger_entry_id`, clusterID, runID)
	if err != nil {
		return application.LoadedRemediationRun{}, false, fmt.Errorf("load remediation citations: %w", err)
	}
	for evidenceRows.Next() {
		var entryID string
		if err := evidenceRows.Scan(&entryID); err != nil {
			evidenceRows.Close()
			return application.LoadedRemediationRun{}, false, fmt.Errorf("scan remediation citation: %w", err)
		}
		loaded.LedgerEntryIDs = append(loaded.LedgerEntryIDs, entryID)
	}
	evidenceRows.Close()
	if err := evidenceRows.Err(); err != nil {
		return application.LoadedRemediationRun{}, false, fmt.Errorf("load remediation citations: %w", err)
	}

	run, err := domain.ReconstituteRemediationRun(plan, domain.RemediationState(state), version, progress)
	if err != nil {
		return application.LoadedRemediationRun{}, false, fmt.Errorf("reconstruct remediation run: %w", err)
	}
	loaded.Run = run
	if err := loadRemediationBoundary(ctx, query, clusterID, runID, &loaded); err != nil {
		return application.LoadedRemediationRun{}, false, err
	}
	return loaded, true, nil
}

// RecordRemediationTransition applies one non-dispatch state change together
// with the observed conditions that justified it and the audit event. The
// update is guarded by the run version, so a concurrent writer loses rather
// than overwrites.
func (store *RemediationStore) RecordRemediationTransition(ctx context.Context, transition application.RemediationTransition, audit application.RemediationAuditEvent) error {
	plan := transition.Run.Plan()
	if transition.ClusterID == "" || plan.ClusterID != transition.ClusterID || audit.ClusterID != transition.ClusterID {
		return application.ErrRemediationConflict
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin remediation transition: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := updateRemediationRun(ctx, tx, transition); err != nil {
		return err
	}
	if err := persistRemediationObservations(ctx, tx, transition); err != nil {
		return err
	}
	if err := appendRemediationAudit(ctx, tx, audit); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit remediation transition: %w", err)
	}
	return nil
}

// updateRemediationRun writes the state, the version, the persisted loop
// budgets and the completion instant. completed_at is set by the database
// exactly for a terminal state, matching the CHECK constraint: a terminal run
// without a completion instant, or a live run claiming one, cannot be written.
func updateRemediationRun(ctx context.Context, tx pgx.Tx, transition application.RemediationTransition) error {
	plan := transition.Run.Plan()
	if _, supervised := ctx.Value(remediationSupervisorClaimContextKey{}).(RemediationSupervisorClaim); supervised {
		if err := RequireRemediationSupervisorClaim(ctx, tx, transition.ClusterID, plan.RunID); err != nil {
			return err
		}
	}

	progress := transition.Run.Progress()
	var policyID, policyCode *string
	var policyVersion *int
	if transition.Policy != nil {
		id, code, version := string(transition.Policy.PolicyID), transition.Policy.Code, transition.Policy.Version
		policyID, policyCode, policyVersion = &id, &code, &version
	}
	command, err := tx.Exec(ctx, `UPDATE remediation_runs SET
			state=$4, version=$5, rollout_wave=$6, rollback_attempt=$7, total_attempts=$8,
			contained_reason=NULLIF($9,''), attention_required=attention_required OR $10,
			next_attempt_at=CASE WHEN $11::timestamptz IS NULL THEN next_attempt_at ELSE $11 END,
			deadline_at=CASE WHEN $12::timestamptz IS NULL THEN deadline_at ELSE $12 END,
			policy_id=COALESCE($13, policy_id),
			policy_version=COALESCE($14, policy_version),
			policy_code=COALESCE($15, policy_code),
			policy_decided_at=CASE WHEN $13::text IS NULL THEN policy_decided_at ELSE clock_timestamp() END,
			lease_owner=CASE WHEN $4 IN `+remediationTerminalStates+` THEN NULL ELSE lease_owner END,
			lease_expires_at=CASE WHEN $4 IN `+remediationTerminalStates+` THEN NULL ELSE lease_expires_at END,
			updated_at=clock_timestamp(),
			completed_at=CASE WHEN $4 IN `+remediationTerminalStates+` THEN clock_timestamp() ELSE NULL END
		WHERE cluster_id=$1 AND run_id=$2 AND version=$3`,
		transition.ClusterID, plan.RunID, transition.ExpectedVersion,
		string(transition.Run.State()), transition.Run.Version(),
		progress.RolloutWave, progress.RollbackAttempt, progress.TotalAttempts,
		transition.ContainedReason, transition.AttentionRequired,
		nullableInstant(transition.NextAttemptAt), nullableInstant(transition.DeadlineAt),
		policyID, policyVersion, policyCode)
	if err != nil {
		return remediationConflict(err)
	}
	if command.RowsAffected() != 1 {
		return application.ErrRemediationConflict
	}
	return nil
}

// DispatchRemediationAttempt is transaction 2. Everything the dispatch decision
// rests on is re-read here, inside the transaction that creates the attempt:
// the policy row, the persisted target-set digest and the pinned population.
// Without that, the preflight-versus-dispatch drift check is a TOCTOU no-op.
//
// The transaction commits before the caller invokes the executor. A crash after
// Execute must never leave a mutation with no durable attempt row, or authority
// is later reconstructed as "never dispatched".
func (store *RemediationStore) DispatchRemediationAttempt(ctx context.Context, input application.RemediationDispatchInput, audit application.RemediationAuditEvent) (domain.RemediationAttempt, error) {
	plan := input.Run.Plan()
	if input.ClusterID == "" || plan.ClusterID != input.ClusterID || input.Attempt.ClusterID != input.ClusterID ||
		audit.ClusterID != input.ClusterID {
		return domain.RemediationAttempt{}, application.ErrRemediationConflict
	}
	if input.LeaseToken == "" || input.Attempt.LeaseOwner == "" {
		return domain.RemediationAttempt{}, application.ErrRemediationLeaseInvalid
	}
	if input.Policy.Code != string(remediation.PolicyAllowed) || input.Policy.PolicyID == "" || input.Policy.Version < 1 {
		return domain.RemediationAttempt{}, application.ErrRemediationForbidden
	}
	if !input.Recipe.Ref().Matches(plan.Recipe) ||
		(input.RollbackRecipe == nil) != plan.Rollback.IsZero() ||
		(input.RollbackRecipe != nil && !input.RollbackRecipe.Ref().Matches(plan.Rollback)) {
		return domain.RemediationAttempt{}, application.ErrRemediationPlanUnauthorized
	}
	if err := input.Attempt.Validate(plan); err != nil {
		return domain.RemediationAttempt{}, err
	}
	leaseFor := input.Attempt.LeaseExpiresAt.Sub(input.Attempt.CreatedAt)
	if leaseFor <= 0 || leaseFor > application.MaxRemediationLease ||
		input.MaxLeaseLifetime < leaseFor || input.MaxLeaseLifetime > application.MaxRemediationLeaseLifetime {
		return domain.RemediationAttempt{}, application.ErrRemediationLeaseInvalid
	}
	// Only the hash persists. The plaintext token exists for the lifetime of this
	// call and appears in no row, no log and no error.
	tokenHash := sha256.Sum256([]byte(input.LeaseToken))
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.RemediationAttempt{}, fmt.Errorf("begin remediation dispatch: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Serialize dispatch decisions and freeze every mutable relation that can
	// change a policy fact until the attempt commits. This is deliberately coarse
	// for the simulated M14 path: it gives inventory, concurrent-run, cooldown,
	// evidence and enablement checks one unambiguous commit order.
	var lockArgs []any
	lockQuery := `LOCK TABLE remediation_global_state, remediation_policies,
		remediation_runs, remediation_run_targets, remediation_run_arguments,
		remediation_run_evidence, collection_jobs, incidents, anomaly_incidents,
		investigation_evidence IN SHARE ROW EXCLUSIVE MODE`
	if plan.Assurance == domain.AssuranceLive {
		if err := LockRepairAuthority(ctx, tx, input.ClusterID); err != nil {
			return domain.RemediationAttempt{}, err
		}
		lockQuery = `SELECT public.sherlock_m15_lock_live_effect_facts($1)`
		lockArgs = []any{input.ClusterID}
	}
	if _, err := tx.Exec(ctx, lockQuery, lockArgs...); err != nil {
		return domain.RemediationAttempt{}, fmt.Errorf("lock remediation dispatch facts: %w", err)
	}

	if plan.Assurance == domain.AssuranceLive {
		// Membership and configuration writers share the advisory fence. Only
		// the actual target's schedule needs a row lock; other jobs may progress.
		for _, target := range plan.Targets {
			var job string
			if err := tx.QueryRow(ctx, `SELECT job_id FROM collection_jobs WHERE cluster_id=$1 AND job_id=$2 FOR UPDATE`, input.ClusterID, target.Target).Scan(&job); err != nil {
				return domain.RemediationAttempt{}, err
			}
		}
		if err := RequireRemediationSupervisorClaim(ctx, tx, input.ClusterID, plan.RunID); err != nil {
			return domain.RemediationAttempt{}, err
		}
	}

	stored, found, err := loadRemediationRun(ctx, tx, input.ClusterID, plan.RunID)
	if err != nil {
		return domain.RemediationAttempt{}, err
	}
	if !found {
		return domain.RemediationAttempt{}, application.ErrRemediationNotFound
	}
	storedPlan := stored.Run.Plan()
	if stored.Run.Version() != input.ExpectedVersion ||
		storedPlan.Recipe != plan.Recipe || storedPlan.Rollback != plan.Rollback ||
		storedPlan.TargetSetDigest != plan.TargetSetDigest || storedPlan.Arguments.Digest() != plan.Arguments.Digest() ||
		stored.PinnedPopulation != input.PinnedPopulation || storedPlan.TargetSetDigest != input.TargetSetDigest {
		return domain.RemediationAttempt{}, application.ErrRemediationConflict
	}
	if err := input.Attempt.Validate(storedPlan); err != nil {
		return domain.RemediationAttempt{}, application.ErrRemediationConflict
	}
	if input.Attempt.Stage == domain.RemediationStageRollout &&
		(!stored.LatestReceipt || !stored.WaveVerified ||
			(stored.LatestStage != domain.RemediationStageCanary && stored.LatestStage != domain.RemediationStageRollout)) {
		return domain.RemediationAttempt{}, application.ErrRemediationConflict
	}

	query := application.RemediationFactQuery{
		ClusterID: input.ClusterID, IncidentID: storedPlan.IncidentID,
		InvestigationID: storedPlan.InvestigationID, RunID: storedPlan.RunID,
		RecipeID: storedPlan.Recipe.ID, RecipeVersion: storedPlan.Recipe.Version,
		TargetSetDigest: storedPlan.TargetSetDigest,
	}
	facts, err := readRemediationFacts(ctx, tx, query)
	if err != nil {
		return domain.RemediationAttempt{}, err
	}
	resolution, err := remediation.ResolveTargets(remediation.ResolutionInput{
		ClusterID: input.ClusterID, IncidentID: storedPlan.IncidentID, Recipe: input.Recipe,
		Inventory: facts.Inventory, Proposed: storedPlan.TargetList(), Now: facts.Now,
	})
	if err != nil || resolution.Digest != storedPlan.TargetSetDigest || resolution.Population != stored.PinnedPopulation {
		return domain.RemediationAttempt{}, application.ErrRemediationConflict
	}
	decision := remediation.Evaluate(remediation.PolicyInput{
		Now: facts.Now, StateObservedAt: facts.StateObservedAt, PopulationObservedAt: facts.PopulationObservedAt,
		Policy: facts.Policy, Recipe: input.Recipe, RollbackRecipe: input.RollbackRecipe, Stage: input.Attempt.Stage,
		ClusterID: input.ClusterID, InvestigationID: storedPlan.InvestigationID, IncidentKind: facts.IncidentKind,
		ResolvedTargets: resolution.Targets, RolePopulation: resolution.Population,
		PinnedRolePopulation: stored.PinnedPopulation, Evidence: facts.Evidence,
		ActiveRuns: facts.ActiveRuns, NoActiveEquivalentRun: facts.NoActiveEquivalentRun,
		AttemptsUsed: stored.Run.Progress().TotalAttempts, LastRunEndedAt: facts.LastRunEndedAt,
		ForwardAttemptsInWindow:  facts.ForwardAttemptsInWindow,
		RemediationEnabledGlobal: facts.EnabledGlobal, RemediationEnabledCluster: facts.EnabledCluster,
	})
	if !decision.Allowed || decision.PolicyID != input.Policy.PolicyID ||
		decision.PolicyVersion != input.Policy.Version || string(decision.Code) != input.Policy.Code {
		return domain.RemediationAttempt{}, application.ErrRemediationForbidden
	}

	observationWindow := input.Recipe.ObservationWindow
	if input.Attempt.Stage == domain.RemediationStageRollback {
		if input.RollbackRecipe == nil {
			return domain.RemediationAttempt{}, application.ErrRemediationPlanUnauthorized
		}
		observationWindow = input.RollbackRecipe.ObservationWindow
	}
	input.DeadlineAt = facts.Now.Add(observationWindow)
	if err := updateRemediationRun(ctx, tx, application.RemediationTransition{
		ClusterID: input.ClusterID, Run: input.Run, ExpectedVersion: input.ExpectedVersion,
		Policy: &input.Policy, DeadlineAt: input.DeadlineAt,
	}); err != nil {
		return domain.RemediationAttempt{}, err
	}
	if err := tx.QueryRow(ctx, `INSERT INTO remediation_attempts (
			cluster_id, attempt_id, run_id, stage, attempt_number, idempotency_key, wave_target_digest,
			lease_owner, lease_token_hash, lease_expires_at, lease_deadline_at,
			policy_id, policy_version, policy_code)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,
			clock_timestamp()+($10*interval '1 millisecond'),
			clock_timestamp()+($11*interval '1 millisecond'),$12,$13,$14)
		RETURNING created_at, lease_expires_at`,
		input.ClusterID, input.Attempt.ID, plan.RunID, string(input.Attempt.Stage), input.Attempt.AttemptNumber,
		input.Attempt.IdempotencyKey, digestBytes(input.Attempt.WaveTargetDigest),
		input.Attempt.LeaseOwner, tokenHash[:], leaseFor.Milliseconds(), input.MaxLeaseLifetime.Milliseconds(),
		string(input.Policy.PolicyID), input.Policy.Version, input.Policy.Code).
		Scan(&input.Attempt.CreatedAt, &input.Attempt.LeaseExpiresAt); err != nil {
		return domain.RemediationAttempt{}, remediationConflict(err)
	}
	for ordinal, target := range input.Attempt.WaveTargets {
		if _, err := tx.Exec(ctx, `INSERT INTO remediation_attempt_targets (cluster_id, attempt_id, run_id, target, ordinal)
			VALUES ($1,$2,$3,$4,$5)`,
			input.ClusterID, input.Attempt.ID, plan.RunID, target, ordinal); err != nil {
			return domain.RemediationAttempt{}, remediationConflict(err)
		}
	}
	input.DeadlineAt = input.Attempt.CreatedAt.Add(observationWindow)
	if _, err := tx.Exec(ctx, `UPDATE remediation_runs SET lease_owner=$3, lease_expires_at=$4, deadline_at=$5
		WHERE cluster_id=$1 AND run_id=$2`,
		input.ClusterID, plan.RunID, input.Attempt.LeaseOwner, input.Attempt.LeaseExpiresAt.UTC(), input.DeadlineAt.UTC()); err != nil {
		return domain.RemediationAttempt{}, remediationConflict(err)
	}
	if err := prepareRemediationSchedule(ctx, tx, input); err != nil {
		return domain.RemediationAttempt{}, err
	}
	if err := appendRemediationAudit(ctx, tx, audit); err != nil {
		return domain.RemediationAttempt{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.RemediationAttempt{}, fmt.Errorf("commit remediation dispatch: %w", err)
	}
	return input.Attempt, nil
}

// RecordRemediationReceipt is transaction 3: the receipt, its per-target
// outcomes, the run transition and the audit event commit together.
//
// A duplicate delivery after an acknowledgement loss finds the recorded receipt
// and returns it instead of mutating twice. A receipt whose idempotency key is
// not its attempt's key is a replay; a receipt from an owner who no longer holds
// the lease is refused, and the caller contains the run rather than retrying,
// because losing the lease after dispatch means the outcome is unknown.
func (store *RemediationStore) RecordRemediationReceipt(ctx context.Context, input application.RemediationReceiptInput, audit application.RemediationAuditEvent) (application.RemediationReceiptOutcome, error) {
	if input.ClusterID == "" || input.AttemptID == "" || input.LeaseToken == "" || audit.ClusterID != input.ClusterID {
		return application.RemediationReceiptOutcome{}, application.ErrRemediationLeaseInvalid
	}
	tokenHash := sha256.Sum256([]byte(input.LeaseToken))
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return application.RemediationReceiptOutcome{}, fmt.Errorf("begin remediation receipt: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var storedOwner, storedKey string
	var storedToken []byte
	var storedWaveDigest []byte
	var attempt domain.RemediationAttempt
	var leaseDeadline time.Time
	var leaseCurrent bool
	// The attempt is joined to its run on the cluster, so an attempt identifier
	// from another cluster resolves to nothing rather than to somebody else's row.
	err = tx.QueryRow(ctx, `SELECT a.run_id, a.attempt_id, a.attempt_number, a.stage,
			a.wave_target_digest, a.idempotency_key, a.lease_owner, a.lease_token_hash,
			a.created_at, a.lease_expires_at, a.lease_deadline_at,
			a.lease_expires_at > clock_timestamp() AND a.lease_deadline_at > clock_timestamp()
		FROM remediation_attempts a
		JOIN remediation_runs r ON r.cluster_id=a.cluster_id AND r.run_id=a.run_id
		WHERE a.cluster_id=$1 AND a.attempt_id=$2 FOR UPDATE OF a`,
		input.ClusterID, input.AttemptID).Scan(
		&attempt.RunID, &attempt.ID, &attempt.AttemptNumber, &attempt.Stage,
		&storedWaveDigest, &storedKey, &storedOwner, &storedToken,
		&attempt.CreatedAt, &attempt.LeaseExpiresAt, &leaseDeadline, &leaseCurrent)
	if err == pgx.ErrNoRows {
		return application.RemediationReceiptOutcome{}, application.ErrRemediationLeaseInvalid
	}
	if err != nil {
		return application.RemediationReceiptOutcome{}, fmt.Errorf("load remediation attempt: %w", err)
	}
	if len(storedToken) != sha256.Size || subtle.ConstantTimeCompare(storedToken, tokenHash[:]) != 1 {
		return application.RemediationReceiptOutcome{}, application.ErrRemediationLeaseInvalid
	}
	attempt.ClusterID = input.ClusterID
	attempt.IdempotencyKey = storedKey
	attempt.LeaseOwner = storedOwner
	attempt.WaveTargetDigest = digestValue(storedWaveDigest)
	if leaseDeadline.Before(attempt.LeaseExpiresAt) {
		attempt.LeaseExpiresAt = leaseDeadline
	}
	targetRows, err := tx.Query(ctx, `SELECT target FROM remediation_attempt_targets
		WHERE cluster_id=$1 AND attempt_id=$2 AND run_id=$3 ORDER BY ordinal`,
		input.ClusterID, input.AttemptID, attempt.RunID)
	if err != nil {
		return application.RemediationReceiptOutcome{}, fmt.Errorf("load remediation attempt targets: %w", err)
	}
	for targetRows.Next() {
		var target domain.RemediationTarget
		if err := targetRows.Scan(&target); err != nil {
			targetRows.Close()
			return application.RemediationReceiptOutcome{}, fmt.Errorf("scan remediation attempt target: %w", err)
		}
		attempt.WaveTargets = append(attempt.WaveTargets, target)
	}
	targetRows.Close()
	if err := targetRows.Err(); err != nil {
		return application.RemediationReceiptOutcome{}, fmt.Errorf("load remediation attempt targets: %w", err)
	}
	if len(attempt.WaveTargets) == 0 || attempt.WaveTargetDigest != domain.RemediationWaveTargetDigest(attempt.WaveTargets) {
		return application.RemediationReceiptOutcome{}, application.ErrRemediationConflict
	}

	var recorded application.RemediationReceiptOutcome
	var priorID domain.RemediationReceiptID
	err = tx.QueryRow(ctx, `SELECT receipt_id FROM remediation_receipts WHERE cluster_id=$1 AND attempt_id=$2`,
		input.ClusterID, input.AttemptID).Scan(&priorID)
	if err == nil {
		prior, loadErr := loadRemediationReceipt(ctx, tx, input.ClusterID, priorID)
		if loadErr != nil {
			return application.RemediationReceiptOutcome{}, loadErr
		}
		if err := validateRemediationReceiptShape(input.Receipt, attempt); err != nil || !sameRemediationReceiptResult(input.Receipt, prior) {
			if err != nil {
				return application.RemediationReceiptOutcome{}, err
			}
			return application.RemediationReceiptOutcome{}, domain.RemediationReceiptRejection{Code: domain.ReceiptReplay}
		}
		run, found, loadErr := loadRemediationRun(ctx, tx, input.ClusterID, attempt.RunID)
		if loadErr != nil || !found {
			return application.RemediationReceiptOutcome{}, application.ErrRemediationConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return application.RemediationReceiptOutcome{}, err
		}
		recorded.Receipt, recorded.Run, recorded.PreviouslyRecorded = prior, run.Run, true
		return recorded, nil
	}
	if err != pgx.ErrNoRows {
		return application.RemediationReceiptOutcome{}, fmt.Errorf("load prior remediation receipt: %w", err)
	}
	if !leaseCurrent {
		return application.RemediationReceiptOutcome{}, domain.RemediationReceiptRejection{Code: domain.ReceiptLeaseLost}
	}

	// The database owns the observation instant. The caller's value is ignored,
	// and the receipt digest is recomputed over the authoritative one so the
	// stored digest always covers the stored row.
	var observedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&observedAt); err != nil {
		return application.RemediationReceiptOutcome{}, fmt.Errorf("read remediation receipt instant: %w", err)
	}
	receipt := input.Receipt
	receipt.ObservedAt = observedAt.UTC()
	receipt.Digest = receipt.ComputeDigest()
	if err := validateRemediationReceiptShape(receipt, attempt); err != nil {
		return application.RemediationReceiptOutcome{}, err
	}
	if err := receipt.ValidateFor(attempt, storedOwner, observedAt); err != nil {
		return application.RemediationReceiptOutcome{}, err
	}
	current, found, err := loadRemediationRun(ctx, tx, input.ClusterID, attempt.RunID)
	if err != nil || !found {
		return application.RemediationReceiptOutcome{}, application.ErrRemediationConflict
	}
	if current.Run.Version() != input.ExpectedVersion || !remediationReceiptTransitionMatches(current.Run, input.Run, receipt) {
		return application.RemediationReceiptOutcome{}, application.ErrRemediationConflict
	}
	if _, err := tx.Exec(ctx, `INSERT INTO remediation_receipts
			(cluster_id, receipt_id, run_id, attempt_id, idempotency_key, stage, outcome, digest, observed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		input.ClusterID, receipt.ID, attempt.RunID, input.AttemptID, receipt.IdempotencyKey,
		string(receipt.Stage), string(receipt.Outcome), digestBytes(receipt.Digest), observedAt); err != nil {
		return application.RemediationReceiptOutcome{}, remediationConflict(err)
	}
	for _, outcome := range receipt.PerTarget {
		if _, err := tx.Exec(ctx, `INSERT INTO remediation_receipt_targets (cluster_id, receipt_id, target, outcome)
			VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
			input.ClusterID, receipt.ID, outcome.Target, string(outcome.Outcome)); err != nil {
			return application.RemediationReceiptOutcome{}, remediationConflict(err)
		}
	}
	if err := updateRemediationRun(ctx, tx, application.RemediationTransition{
		ClusterID: input.ClusterID, Run: input.Run, ExpectedVersion: input.ExpectedVersion,
		ContainedReason: input.ContainedReason, AttentionRequired: input.AttentionRequired,
	}); err != nil {
		return application.RemediationReceiptOutcome{}, err
	}
	if err := appendRemediationAudit(ctx, tx, audit); err != nil {
		return application.RemediationReceiptOutcome{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return application.RemediationReceiptOutcome{}, fmt.Errorf("commit remediation receipt: %w", err)
	}
	return application.RemediationReceiptOutcome{Receipt: receipt, Run: input.Run}, nil
}

func loadRemediationReceipt(ctx context.Context, query remediationQuerier, clusterID domain.ClusterID, receiptID domain.RemediationReceiptID) (domain.RemediationReceipt, error) {
	receipt := domain.RemediationReceipt{ID: receiptID, ClusterID: clusterID}
	var digest []byte
	if err := query.QueryRow(ctx, `SELECT run_id, attempt_id, idempotency_key, stage, outcome, digest, observed_at
		FROM remediation_receipts WHERE cluster_id=$1 AND receipt_id=$2`, clusterID, receiptID).Scan(
		&receipt.RunID, &receipt.AttemptID, &receipt.IdempotencyKey, &receipt.Stage,
		&receipt.Outcome, &digest, &receipt.ObservedAt); err != nil {
		return domain.RemediationReceipt{}, fmt.Errorf("load remediation receipt: %w", err)
	}
	if err := copyRemediationDigest(&receipt.Digest, digest); err != nil {
		return domain.RemediationReceipt{}, err
	}
	rows, err := query.Query(ctx, `SELECT target, outcome FROM remediation_receipt_targets
		WHERE cluster_id=$1 AND receipt_id=$2 ORDER BY target`, clusterID, receiptID)
	if err != nil {
		return domain.RemediationReceipt{}, fmt.Errorf("load remediation receipt targets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var outcome domain.RemediationTargetOutcome
		if err := rows.Scan(&outcome.Target, &outcome.Outcome); err != nil {
			return domain.RemediationReceipt{}, fmt.Errorf("scan remediation receipt target: %w", err)
		}
		receipt.PerTarget = append(receipt.PerTarget, outcome)
		receipt.Targets = append(receipt.Targets, outcome.Target)
	}
	return receipt, rows.Err()
}

// validateRemediationReceiptShape binds the complete result projection to the
// wave persisted before execution. A partial or substituted target set would
// otherwise become rollback authority through remediation_receipt_targets.
func validateRemediationReceiptShape(receipt domain.RemediationReceipt, attempt domain.RemediationAttempt) error {
	if receipt.ClusterID != attempt.ClusterID || receipt.RunID != attempt.RunID ||
		receipt.AttemptID != attempt.ID || receipt.Stage != attempt.Stage ||
		receipt.IdempotencyKey != attempt.IdempotencyKey {
		return domain.RemediationReceiptRejection{Code: domain.ReceiptReplay}
	}
	if !slices.Equal(receipt.Targets, attempt.WaveTargets) {
		return domain.RemediationReceiptRejection{Code: domain.ReceiptTargetNotDispatched}
	}
	if len(receipt.PerTarget) == 0 {
		if receipt.Outcome == domain.ExecutionUnknown {
			return nil
		}
		return domain.RemediationReceiptRejection{Code: domain.ReceiptTargetNotDispatched}
	}
	if len(receipt.PerTarget) != len(attempt.WaveTargets) {
		return domain.RemediationReceiptRejection{Code: domain.ReceiptTargetNotDispatched}
	}
	aggregate := domain.ExecutionExecuted
	for index, outcome := range receipt.PerTarget {
		if outcome.Target != attempt.WaveTargets[index] {
			return domain.RemediationReceiptRejection{Code: domain.ReceiptTargetNotDispatched}
		}
		if remediationOutcomeRank(outcome.Outcome) > remediationOutcomeRank(aggregate) {
			aggregate = outcome.Outcome
		}
	}
	if receipt.Outcome != aggregate {
		return domain.RemediationReceiptRejection{Code: domain.ReceiptReplay}
	}
	return nil
}

func remediationOutcomeRank(outcome domain.ExecutionOutcome) int {
	switch outcome {
	case domain.ExecutionExecuted:
		return 0
	case domain.ExecutionRefused:
		return 1
	case domain.ExecutionFailed:
		return 2
	case domain.ExecutionTimedOut:
		return 3
	default:
		return 4
	}
}

func sameRemediationReceiptResult(left, right domain.RemediationReceipt) bool {
	return left.ClusterID == right.ClusterID && left.RunID == right.RunID &&
		left.AttemptID == right.AttemptID && left.IdempotencyKey == right.IdempotencyKey &&
		left.Stage == right.Stage && left.Outcome == right.Outcome &&
		slices.Equal(left.Targets, right.Targets) && slices.Equal(left.PerTarget, right.PerTarget)
}

// remediationReceiptTransitionMatches prevents a caller from persisting one
// receipt while advancing the aggregate from a different execution report.
func remediationReceiptTransitionMatches(current, supplied domain.RemediationRun, receipt domain.RemediationReceipt) bool {
	report := domain.RemediationExecutionReport{Outcome: receipt.Outcome, PerTarget: slices.Clone(receipt.PerTarget)}
	for _, outcome := range receipt.PerTarget {
		if outcome.Outcome == domain.ExecutionExecuted {
			report.ExecutedTargets = append(report.ExecutedTargets, outcome.Target)
		}
	}
	var expected domain.RemediationRun
	var err error
	switch current.State() {
	case domain.RemediationCanaryExecuting:
		expected, err = current.RecordCanaryOutcome(report, receipt.ObservedAt)
	case domain.RemediationRollingOut:
		expected, err = current.RecordRolloutOutcome(report, receipt.ObservedAt)
	case domain.RemediationRollingBack:
		expected, err = current.RecordRollbackExecution(report, receipt.ObservedAt)
	default:
		return false
	}
	if err != nil {
		return false
	}
	return expected.State() == supplied.State() && expected.Version() == supplied.Version() &&
		expected.Progress() == supplied.Progress() &&
		expected.Plan().RunID == supplied.Plan().RunID &&
		expected.Plan().TargetSetDigest == supplied.Plan().TargetSetDigest
}

// ReadRemediationFacts reads every fact a policy decision rests on at one
// server-causal instant, inside a repeatable-read snapshot, so a decision is
// never assembled from observations that disagree with each other.
//
// The incident kind comes from the durable anomaly row that raised the incident,
// never from a request field. An incident with no such row has no kind, and a
// missing kind denies.
func (store *RemediationStore) ReadRemediationFacts(ctx context.Context, query application.RemediationFactQuery) (application.RemediationFacts, error) {
	if query.ClusterID == "" {
		return application.RemediationFacts{}, fmt.Errorf("remediation facts require an authenticated cluster")
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return application.RemediationFacts{}, fmt.Errorf("begin remediation fact read: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	facts, err := readRemediationFacts(ctx, tx, query)
	if err != nil {
		return application.RemediationFacts{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return application.RemediationFacts{}, fmt.Errorf("commit remediation fact read: %w", err)
	}
	return facts, nil
}

// readRemediationFacts assembles one policy input from one database snapshot.
// Dispatch calls it after acquiring its fact-set locks, while ordinary policy
// and preflight reads call it through the repeatable-read wrapper above.
func readRemediationFacts(ctx context.Context, query remediationQuerier, request application.RemediationFactQuery) (application.RemediationFacts, error) {
	var facts application.RemediationFacts
	if err := query.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&facts.Now); err != nil {
		return application.RemediationFacts{}, fmt.Errorf("read remediation instant: %w", err)
	}
	facts.Now = facts.Now.UTC()
	// Every observed counter below is read in this same snapshot, so its
	// observation instant is the snapshot instant rather than an assumption.
	facts.StateObservedAt, facts.PopulationObservedAt = facts.Now, facts.Now

	if err := query.QueryRow(ctx, `SELECT remediation_enabled FROM remediation_global_state WHERE id`).Scan(&facts.EnabledGlobal); err != nil && err != pgx.ErrNoRows {
		return application.RemediationFacts{}, fmt.Errorf("read remediation enablement: %w", err)
	}

	var cooldownSeconds, evidenceMaxAgeSeconds int
	var windows []byte
	var policiesAtVersion int
	err := query.QueryRow(ctx, `SELECT policy_id, version, recipe_id, recipe_version, enabled, max_tier, incident_kinds,
			max_targets, max_concurrent_runs, cooldown_seconds, maintenance_windows, evidence_max_age_seconds,
			min_evidence_coverage, require_rollback, not_before, not_after, revoked_at, count(*) OVER (PARTITION BY version), max_forward_attempts
		FROM remediation_policies WHERE cluster_id=$1 AND recipe_id=$2 AND recipe_version=$3
		ORDER BY version DESC, policy_id ASC LIMIT 1`, request.ClusterID, request.RecipeID, request.RecipeVersion).Scan(
		&facts.Policy.ID, &facts.Policy.Version, &facts.Policy.RecipeID, &facts.Policy.RecipeVersion,
		&facts.EnabledCluster, &facts.Policy.MaxTier, &facts.Policy.IncidentKinds,
		&facts.Policy.MaxTargets, &facts.Policy.MaxConcurrentRuns, &cooldownSeconds, &windows,
		&evidenceMaxAgeSeconds, &facts.Policy.MinEvidenceCoverage, &facts.Policy.RequireRollback,
		&facts.Policy.NotBefore, &facts.Policy.NotAfter, &facts.Policy.RevokedAt, &policiesAtVersion, &facts.Policy.MaxForwardAttempts)
	if err != nil && err != pgx.ErrNoRows {
		return application.RemediationFacts{}, fmt.Errorf("read remediation policy: %w", err)
	}
	if err == nil {
		facts.Policy.Ambiguous = policiesAtVersion > 1
		facts.Policy.ClusterID = request.ClusterID
		facts.Policy.Cooldown = time.Duration(cooldownSeconds) * time.Second
		facts.Policy.EvidenceMaxAge = time.Duration(evidenceMaxAgeSeconds) * time.Second
		if facts.Policy.MaxForwardAttempts > 0 {
			var attempts int
			// Count all committed forward reservations in the window, including
			// failed attempts and earlier policies. Dispatch holds the same table
			// locks as concurrency admission, so simultaneous reservations serialize.
			if err := query.QueryRow(ctx, `SELECT count(*) FROM remediation_attempts a
			 JOIN remediation_runs r ON r.cluster_id=a.cluster_id AND r.run_id=a.run_id
			 WHERE a.cluster_id=$1 AND r.recipe_id=$2 AND a.stage<>'ROLLBACK'
			 AND a.created_at >= $3 AND a.created_at < $4`, request.ClusterID, request.RecipeID, facts.Policy.NotBefore, facts.Policy.NotAfter).Scan(&attempts); err != nil {
				return facts, fmt.Errorf("read policy window budget: %w", err)
			}
			facts.ForwardAttemptsInWindow = &attempts
		}
		facts.Policy.MaintenanceWindows, err = decodeMaintenanceWindows(windows)
		if err != nil {
			return application.RemediationFacts{}, err
		}
	}

	if request.IncidentID != "" {
		if err := query.QueryRow(ctx, `SELECT a.rule_id FROM anomaly_incidents a
			JOIN incidents i ON i.cluster_id=a.cluster_id AND i.incident_id=a.incident_id
			WHERE a.cluster_id=$1 AND a.incident_id=$2`, request.ClusterID, request.IncidentID).Scan(&facts.IncidentKind); err != nil && err != pgx.ErrNoRows {
			return application.RemediationFacts{}, fmt.Errorf("read incident kind: %w", err)
		}
	}

	if request.RecipeVersion == remediation.CollectionRequestRecipeVersion {
		var eligible bool
		err := query.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schedule_repair_detections d JOIN investigation_action_cards c ON c.cluster_id=d.cluster_id AND c.investigation_id=d.investigation_id JOIN investigations i ON i.cluster_id=d.cluster_id AND i.investigation_id=d.investigation_id AND i.incident_id=d.incident_id JOIN investigation_action_card_citations cit ON cit.cluster_id=c.cluster_id AND cit.investigation_id=c.investigation_id AND cit.action_card_id=c.action_card_id JOIN investigation_evidence ev ON ev.cluster_id=cit.cluster_id AND ev.investigation_id=cit.investigation_id AND ev.ledger_entry_id=cit.ledger_entry_id AND ev.evidence_id=d.evidence_id WHERE d.cluster_id=$1 AND d.incident_id=$2 AND d.investigation_id=$3 AND c.owner='SHERLOCK' AND c.targets=ARRAY[d.job_id] AND cardinality(c.blocking_gaps)=0 AND i.status='COMPLETED' AND i.completed_at IS NOT NULL)`, request.ClusterID, request.IncidentID, request.InvestigationID).Scan(&eligible)
		if err != nil {
			return facts, err
		}
		if !eligible {
			facts.IncidentKind = ""
		}
	}

	// The Tier 1 target inventory is collection_jobs, scoped to the
	// authenticated cluster. Every active job in the cluster is a member of the
	// role population; the rows attached to this incident are the candidates.
	inventoryRows, err := query.Query(ctx, `SELECT j.job_id,
			EXISTS (SELECT 1 FROM incidents i WHERE i.cluster_id=j.cluster_id AND i.incident_id=$2 AND ($3::text <> '2.0.0' OR EXISTS(SELECT 1 FROM schedule_repair_detections d WHERE d.cluster_id=j.cluster_id AND d.incident_id=i.incident_id AND d.job_id=j.job_id)))
		FROM collection_jobs j WHERE j.cluster_id=$1 AND j.active ORDER BY j.job_id`,
		request.ClusterID, request.IncidentID, request.RecipeVersion)
	if err != nil {
		return application.RemediationFacts{}, fmt.Errorf("read remediation inventory: %w", err)
	}
	for inventoryRows.Next() {
		var jobID domain.RemediationTarget
		var attached bool
		if err := inventoryRows.Scan(&jobID, &attached); err != nil {
			inventoryRows.Close()
			return application.RemediationFacts{}, fmt.Errorf("scan remediation inventory: %w", err)
		}
		row := remediation.InventoryRow{
			Target: jobID, Role: domain.RoleManagedCollectionStream, ClusterID: request.ClusterID,
			Source: domain.SourceCollectionJobs,
		}
		if attached {
			row.IncidentID = request.IncidentID
		}
		facts.Inventory = append(facts.Inventory, row)
	}
	inventoryRows.Close()
	if err := inventoryRows.Err(); err != nil {
		return application.RemediationFacts{}, fmt.Errorf("read remediation inventory: %w", err)
	}

	if request.InvestigationID != "" {
		facts.Evidence, err = readRemediationEvidence(ctx, query, request.ClusterID, request.InvestigationID)
		if err != nil {
			return application.RemediationFacts{}, err
		}
	}

	if err := query.QueryRow(ctx, `SELECT count(*) FROM remediation_runs
		WHERE cluster_id=$1 AND state NOT IN `+remediationTerminalStates+` AND total_attempts > 0 AND run_id <> $2`,
		request.ClusterID, request.RunID).Scan(&facts.ActiveRuns); err != nil {
		return application.RemediationFacts{}, fmt.Errorf("count active remediation runs: %w", err)
	}
	// Phrased positively so an unpopulated answer denies: there must be no other
	// non-terminal run for the same recipe and the same resolved target set.
	var conflicting int
	if err := query.QueryRow(ctx, `SELECT count(*) FROM remediation_runs
		WHERE cluster_id=$1 AND recipe_id=$2 AND target_set_digest=$3
		  AND state NOT IN `+remediationTerminalStates+` AND run_id <> $4`,
		request.ClusterID, request.RecipeID, request.TargetSetDigest[:], request.RunID).Scan(&conflicting); err != nil {
		return application.RemediationFacts{}, fmt.Errorf("count equivalent remediation runs: %w", err)
	}
	facts.NoActiveEquivalentRun = conflicting == 0

	// Only a proven admission refusal is exempt. Durable attempts protect against
	// stale counters; effects and receipts require an attempt through foreign keys.
	var lastEnded *time.Time
	if err := query.QueryRow(ctx, `SELECT max(r.completed_at) FROM remediation_runs r
		WHERE r.cluster_id=$1 AND r.recipe_id=$2 AND r.completed_at IS NOT NULL AND r.run_id <> $3
		AND NOT (r.state='POLICY_BLOCKED' AND r.total_attempts=0
		    AND NOT EXISTS (SELECT 1 FROM remediation_attempts a
		        WHERE a.cluster_id=r.cluster_id AND a.run_id=r.run_id))`,
		request.ClusterID, request.RecipeID, request.RunID).Scan(&lastEnded); err != nil {
		return application.RemediationFacts{}, fmt.Errorf("read remediation cooldown: %w", err)
	}
	if lastEnded == nil {
		// No prior run has ever ended for this recipe, which is an observed fact
		// rather than an unobserved one: the epoch stands in for "long ago".
		epoch := time.Unix(0, 0).UTC()
		lastEnded = &epoch
	}
	facts.LastRunEndedAt = lastEnded
	return facts, nil
}

// readRemediationEvidence maps the investigation ledger onto the evidence facts
// the policy core consumes. The mapping is stated here rather than implied:
// SOURCE_FRESHNESS entries carry the collection-freshness class the Tier 1
// recipe requires, a COMPLETE entry is full coverage and a PARTIAL one is not,
// and an entry is superseded when a later entry of the same kind exists for the
// same investigation.
func readRemediationEvidence(ctx context.Context, query remediationQuerier, clusterID domain.ClusterID, investigationID domain.InvestigationID) ([]remediation.EvidenceFact, error) {
	rows, err := query.Query(ctx, `SELECT ledger_entry_id, CASE WHEN EXISTS(SELECT 1 FROM schedule_repair_detections d WHERE d.cluster_id=investigation_evidence.cluster_id AND d.investigation_id=investigation_evidence.investigation_id AND d.evidence_id=investigation_evidence.evidence_id) THEN 'SOURCE_FRESHNESS' ELSE entry_kind END, status, observed_end, recorded_at,
			sequence < max(sequence) OVER (PARTITION BY entry_kind) AS superseded
		FROM investigation_evidence WHERE cluster_id=$1 AND investigation_id=$2 ORDER BY sequence`,
		clusterID, investigationID)
	if err != nil {
		return nil, fmt.Errorf("read remediation evidence: %w", err)
	}
	defer rows.Close()
	var facts []remediation.EvidenceFact
	for rows.Next() {
		var entryKind, status string
		fact := remediation.EvidenceFact{ClusterID: clusterID, InvestigationID: investigationID}
		if err := rows.Scan(&fact.LedgerEntryID, &entryKind, &status, &fact.ObservedEnd, &fact.RecordedAt, &fact.Superseded); err != nil {
			return nil, fmt.Errorf("scan remediation evidence: %w", err)
		}
		if entryKind != "SOURCE_FRESHNESS" {
			continue
		}
		fact.Class = remediation.EvidenceClassCollectionFreshness
		switch status {
		case "COMPLETE":
			fact.Coverage = 100
		case "PARTIAL":
			fact.Coverage = 50
		default:
			fact.Coverage = 0
		}
		facts = append(facts, fact)
	}
	return facts, rows.Err()
}

func remediationConditionFrom(satisfied bool) domain.ConditionResult {
	if satisfied {
		return domain.ConditionSatisfied
	}
	return domain.ConditionUnsatisfied
}

func appendRemediationAudit(ctx context.Context, exec remediationExecer, event application.RemediationAuditEvent) error {
	if event.EventID == "" || event.ClusterID == "" || event.ActorID == "" || event.Outcome == "" ||
		event.OccurredAt.IsZero() || event.RecipeDigest == (domain.SHA256{}) || event.TargetSetDigest == (domain.SHA256{}) {
		return fmt.Errorf("remediation audit attribution is incomplete")
	}
	command, err := exec.Exec(ctx, `INSERT INTO remediation_audit_events
			(event_id, event_kind, cluster_id, run_id, attempt_id, actor_id, outcome, reason_code,
			 recipe_digest, target_set_digest, occurred_at)
		VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,$7,$8,$9,$10,clock_timestamp())
		ON CONFLICT (event_id) DO NOTHING`,
		event.EventID, string(event.Kind), event.ClusterID, string(event.RunID), string(event.AttemptID),
		event.ActorID, event.Outcome, event.ReasonCode,
		digestBytes(event.RecipeDigest), digestBytes(event.TargetSetDigest))
	if err != nil {
		return remediationConflict(err)
	}
	if command.RowsAffected() != 1 {
		return application.ErrRemediationConflict
	}
	return nil
}

type remediationExecer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// decodeMaintenanceWindows reads the bounded, versioned window list. It is
// JSONB because a maintenance window is a bounded attribute of one policy row
// and never a searchable relationship; an unparseable value fails the whole
// read rather than degrading to "no windows", which would read as "always
// permitted".
func decodeMaintenanceWindows(raw []byte) ([]remediation.MaintenanceWindow, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var encoded []struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	}
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, fmt.Errorf("decode remediation maintenance windows: %w", err)
	}
	windows := make([]remediation.MaintenanceWindow, 0, len(encoded))
	for _, window := range encoded {
		windows = append(windows, remediation.MaintenanceWindow{Start: window.Start.UTC(), End: window.End.UTC()})
	}
	return windows, nil
}

func optionalRecipe(record *application.RemediationRecipeRecord) []application.RemediationRecipeRecord {
	if record == nil {
		return nil
	}
	return []application.RemediationRecipeRecord{*record}
}

func digestBytes(digest domain.SHA256) []byte { return slices.Clone(digest[:]) }

func digestValue(raw []byte) domain.SHA256 {
	var digest domain.SHA256
	if len(raw) == sha256.Size {
		copy(digest[:], raw)
	}
	return digest
}

func copyRemediationDigest(into *domain.SHA256, raw []byte) error {
	if len(raw) != sha256.Size {
		return fmt.Errorf("stored remediation digest is invalid")
	}
	copy(into[:], raw)
	return nil
}

func nullableInstant(instant time.Time) *time.Time {
	if instant.IsZero() {
		return nil
	}
	value := instant.UTC()
	return &value
}

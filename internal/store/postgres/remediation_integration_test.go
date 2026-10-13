//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediation"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// remediationFixture is one isolated cluster with a real incident,
// investigation, action card, ledger entry and collection-job inventory. These
// tests are not idempotent: every identifier carries a per-run suffix.
type remediationFixture struct {
	pool            *pgxpool.Pool
	store           *storepg.RemediationStore
	suffix          string
	clusterID       domain.ClusterID
	incidentID      domain.IncidentID
	investigationID domain.InvestigationID
	actionCardID    domain.ActionCardID
	ledgerEntryID   string
	targets         []domain.RemediationTarget
	forward         remediation.Recipe
	rollback        remediation.Recipe
	now             time.Time
}

func newRemediationFixture(t *testing.T) remediationFixture {
	t.Helper()
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store, err := storepg.NewRemediationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	fixture := remediationFixture{
		pool: pool, store: store, suffix: suffix,
		clusterID:       domain.ClusterID("remediation-cluster-" + suffix),
		incidentID:      domain.IncidentID("remediation-incident-" + suffix),
		investigationID: domain.InvestigationID("remediation-investigation-" + suffix),
		actionCardID:    domain.ActionCardID("remediation-card-" + suffix),
		ledgerEntryID:   "remediation-ledger-" + suffix,
		now:             time.Now().UTC().Truncate(time.Microsecond),
	}
	recipes := remediation.BuiltinRecipes(fixture.now.Add(365 * 24 * time.Hour))
	fixture.forward, fixture.rollback = recipes[0], recipes[1]

	exec := func(command string, arguments ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, command, arguments...); err != nil {
			t.Fatalf("fixture %q: %v", command, err)
		}
	}
	exec(`INSERT INTO clusters (cluster_id, display_name) VALUES ($1,$2)`, fixture.clusterID, "Remediation cluster")
	sourceID := "remediation-source-" + suffix
	exec(`INSERT INTO sources (source_id, cluster_id, kind, display_name) VALUES ($1,$2,'prometheus','Remediation source')`, sourceID, fixture.clusterID)
	exec(`INSERT INTO incidents (incident_id, cluster_id, title, severity, status, created_by)
		VALUES ($1,$2,'Evidence stream stale','HIGH','INVESTIGATING','sherlock')`, fixture.incidentID, fixture.clusterID)
	// The incident kind is read from this durable anomaly row, never from a
	// request field.
	exec(`INSERT INTO anomaly_incidents (fingerprint, cluster_id, rule_id, entity_key, incident_id, first_signal_at, last_signal_at, cooldown_until)
		VALUES (sha256($1::bytea),$2,$3,$4,$5,clock_timestamp(),clock_timestamp(),clock_timestamp())`,
		[]byte(suffix), fixture.clusterID, remediation.IncidentKindEvidenceStreamStale, "stream", fixture.incidentID)
	exec(`INSERT INTO investigations (investigation_id, cluster_id, incident_id, question, requested_by, scope, window_start, window_end, status, completed_at)
		VALUES ($1,$2,$3,'why is the stream stale','sherlock','{}'::jsonb, clock_timestamp()-interval '1 hour', clock_timestamp(), 'COMPLETED', clock_timestamp())`,
		fixture.investigationID, fixture.clusterID, fixture.incidentID)
	exec(`INSERT INTO investigation_action_cards (investigation_id, cluster_id, action_card_id, owner, action, urgency, targets, rationale, escalation_condition)
		VALUES ($1,$2,$3,'SHERLOCK','requeue the stalled collection stream','NEXT_SHIFT',ARRAY['stream'],'dispatch gap','still stale in one hour')`,
		fixture.investigationID, fixture.clusterID, fixture.actionCardID)
	exec(`INSERT INTO investigation_evidence (ledger_entry_id, cluster_id, investigation_id, sequence, entry_kind, status, exact_scope, observed_start, observed_end, recorded_at)
		VALUES ($1,$2,$3,1,'SOURCE_FRESHNESS','COMPLETE','{}'::jsonb, clock_timestamp()-interval '10 minutes', clock_timestamp()-interval '1 minute', clock_timestamp())`,
		fixture.ledgerEntryID, fixture.clusterID, fixture.investigationID)
	for index := 1; index <= 4; index++ {
		jobID := domain.RemediationTarget(fmt.Sprintf("collection-job-%d-%s", index, suffix))
		exec(`INSERT INTO collection_jobs (job_id, cluster_id, source_id, query_kind, interval_seconds, next_run_at)
			VALUES ($1,$2,$3,$4,60,clock_timestamp())`, jobID, fixture.clusterID, sourceID, fmt.Sprintf("kind-%d", index))
		fixture.targets = append(fixture.targets, jobID)
	}
	return fixture
}

func (fixture remediationFixture) plan(t *testing.T, runID domain.RemediationRunID, targets []domain.RemediationTarget) domain.RemediationPlan {
	t.Helper()
	resolved := make([]domain.ResolvedTarget, 0, len(targets))
	for _, target := range targets {
		resolved = append(resolved, domain.ResolvedTarget{
			Target: target, Role: domain.RoleManagedCollectionStream, ClusterID: fixture.clusterID,
			ResolvedAt: fixture.now, Source: domain.SourceCollectionJobs,
		})
	}
	plan := domain.RemediationPlan{
		RunID: runID, ClusterID: fixture.clusterID, IncidentID: fixture.incidentID,
		InvestigationID: fixture.investigationID, ActionCardID: fixture.actionCardID,
		Recipe: fixture.forward.Ref(), Rollback: fixture.rollback.Ref(),
		Tier: fixture.forward.Tier, Privilege: fixture.forward.Privilege, Assurance: fixture.forward.Assurance,
		Targets: resolved, TargetSetDigest: domain.RemediationTargetSetDigest(resolved),
		Arguments: domain.TypedArguments{
			{Name: "priority", Type: domain.ParameterEnum, Enum: "NORMAL"},
			{Name: "requeue_reason", Type: domain.ParameterEnum, Enum: "STALE_STREAM"},
		},
		MaxTargets: fixture.forward.MaxTargets, MaxConcurrency: fixture.forward.MaxConcurrency,
		CanaryTargets: fixture.forward.CanaryTargets, MaxAttempts: fixture.forward.MaxAttempts,
		ProposedAt: fixture.now, ExpiresAt: fixture.now.Add(time.Hour),
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("fixture plan is invalid: %v", err)
	}
	return plan
}

func (fixture remediationFixture) audit(kind application.RemediationAuditKind, plan domain.RemediationPlan, label string) application.RemediationAuditEvent {
	return application.RemediationAuditEvent{
		EventID: "remediation-audit-" + label + "-" + fixture.suffix, Kind: kind,
		ClusterID: fixture.clusterID, RunID: plan.RunID, ActorID: "operator-1", Outcome: "ALLOWED",
		OccurredAt: fixture.now, RecipeDigest: plan.Recipe.Digest, TargetSetDigest: plan.TargetSetDigest,
	}
}

func (fixture remediationFixture) create(t *testing.T, plan domain.RemediationPlan, label string) (domain.RemediationRun, bool) {
	t.Helper()
	run, err := domain.NewRemediationRun(plan)
	if err != nil {
		t.Fatal(err)
	}
	forward := application.RemediationRecipeRecord{
		Ref: fixture.forward.Ref(), Tier: fixture.forward.Tier,
		Operation: string(fixture.forward.Operation), ExpiresAt: fixture.forward.ExpiresAt,
	}
	rollback := application.RemediationRecipeRecord{
		Ref: fixture.rollback.Ref(), Tier: fixture.rollback.Tier,
		Operation: string(fixture.rollback.Operation), ExpiresAt: fixture.rollback.ExpiresAt,
	}
	stored, created, err := fixture.store.CreateRemediationRun(context.Background(), application.CreateRemediationRunInput{
		Run: run, Recipe: forward, Rollback: &rollback, PinnedPopulation: len(fixture.targets),
		LedgerEntryIDs: []string{fixture.ledgerEntryID}, DeadlineAt: fixture.now.Add(time.Hour),
	}, fixture.audit(application.RemediationAuditProposal, plan, label))
	if err != nil {
		t.Fatalf("create remediation run: %v", err)
	}
	return stored, created
}

// TestRemediationStoreRefusesDuplicateConcurrentRepair proves the partial
// unique index, which is the only defence against two concurrent equivalent
// incidents producing two repairs: the idempotency key contains the run
// identifier and so can never collide across runs.
func TestRemediationStoreRefusesDuplicateConcurrentRepair(t *testing.T) {
	fixture := newRemediationFixture(t)
	ctx := context.Background()
	first := fixture.plan(t, domain.RemediationRunID("remediation-run-a-"+fixture.suffix), fixture.targets[:1])
	stored, created := fixture.create(t, first, "create-a")
	if !created || stored.State() != domain.RemediationProposed {
		t.Fatalf("expected a created PROPOSED run, got created=%t state=%s", created, stored.State())
	}

	// A second, independently identified run for the same cluster, recipe and
	// resolved target set is answered with the run that already exists.
	second := fixture.plan(t, domain.RemediationRunID("remediation-run-b-"+fixture.suffix), fixture.targets[:1])
	prior, created := fixture.create(t, second, "create-b")
	if created {
		t.Fatal("an equivalent non-terminal repair must not create a second run")
	}
	if prior.Plan().RunID != first.RunID {
		t.Fatalf("expected the existing run %s, got %s", first.RunID, prior.Plan().RunID)
	}

	// The same collision at the SQL level, so the index itself is proven rather
	// than the store's handling of it.
	_, err := fixture.pool.Exec(ctx, `INSERT INTO remediation_runs (
			cluster_id, run_id, incident_id, investigation_id, state, version,
			recipe_id, recipe_version, recipe_digest, tier, privilege, assurance,
			target_set_digest, arguments_digest, pinned_population, max_targets, max_concurrency,
			canary_targets, max_attempts, deadline_at, proposed_at, expires_at)
		VALUES ($1,$2,$3,$4,'PROPOSED',1,$5,$6,$7,1,'SHERLOCK_INTERNAL','SIMULATED',$8,$7,1,4,1,1,2,
			clock_timestamp()+interval '1 hour', clock_timestamp(), clock_timestamp()+interval '1 hour')`,
		fixture.clusterID, "remediation-run-raw-"+fixture.suffix, fixture.incidentID, fixture.investigationID,
		first.Recipe.ID, first.Recipe.Version, first.Recipe.Digest[:], first.TargetSetDigest[:])
	if err == nil {
		t.Fatal("the active-repair index must refuse a duplicate concurrent repair")
	}

	// A terminal run releases the index: the repair is no longer in flight.
	run, err := domain.ReconstituteRemediationRun(first, domain.RemediationProposed, stored.Version(), domain.RemediationProgress{})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err := run.Cancel(fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.RecordRemediationTransition(ctx, application.RemediationTransition{
		ClusterID: fixture.clusterID, Run: cancelled, ExpectedVersion: stored.Version(),
	}, fixture.audit(application.RemediationAuditCancellation, first, "cancel")); err != nil {
		t.Fatalf("cancel remediation run: %v", err)
	}
	var completedAt *time.Time
	if err := fixture.pool.QueryRow(ctx, `SELECT completed_at FROM remediation_runs WHERE cluster_id=$1 AND run_id=$2`,
		fixture.clusterID, first.RunID).Scan(&completedAt); err != nil {
		t.Fatal(err)
	}
	if completedAt == nil {
		t.Fatal("a terminal run must carry a database-set completion instant")
	}
	third := fixture.plan(t, domain.RemediationRunID("remediation-run-c-"+fixture.suffix), fixture.targets[:1])
	// One Action Card may seed at most one remediation run, even after that run
	// terminates. This test is about release of the active-repair target index, so
	// use the plan's permitted card-less form for the later independent run.
	third.ActionCardID = ""
	if _, created := fixture.create(t, third, "create-c"); !created {
		t.Fatal("a terminated repair must release the active-repair index")
	}

	// The terminal-state CHECK is structural: neither half can be written alone.
	if _, err := fixture.pool.Exec(ctx, `UPDATE remediation_runs SET state='SUCCEEDED', completed_at=NULL
		WHERE cluster_id=$1 AND run_id=$2`, fixture.clusterID, third.RunID); err == nil {
		t.Fatal("a terminal state without a completion instant must be refused")
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE remediation_runs SET completed_at=clock_timestamp()
		WHERE cluster_id=$1 AND run_id=$2`, fixture.clusterID, third.RunID); err == nil {
		t.Fatal("a non-terminal state carrying a completion instant must be refused")
	}
}

// TestRemediationStoreDispatchLeaseAndReceipt covers the dispatch and receipt
// transactions: drift, a revoked policy, lease loss before and after dispatch,
// duplicate delivery, receipt replay under another attempt and cross-cluster
// rejection at every boundary.
func TestRemediationStoreDispatchLeaseAndReceipt(t *testing.T) {
	fixture := newRemediationFixture(t)
	ctx := context.Background()
	plan := fixture.plan(t, domain.RemediationRunID("remediation-run-"+fixture.suffix), fixture.targets[:1])
	stored, created := fixture.create(t, plan, "create")
	if !created {
		t.Fatal("expected the run to be created")
	}

	policyID := domain.RemediationPolicyID("remediation-policy-" + fixture.suffix)
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO remediation_policies (
			cluster_id, policy_id, version, recipe_id, recipe_version, enabled, max_tier, incident_kinds,
			max_targets, max_concurrent_runs, cooldown_seconds, evidence_max_age_seconds, min_evidence_coverage,
			not_before, not_after)
		VALUES ($1,$2,1,$3,$4,true,1,ARRAY[$5],4,1,0,900,100, clock_timestamp()-interval '1 hour', clock_timestamp()+interval '1 hour')`,
		fixture.clusterID, policyID, plan.Recipe.ID, plan.Recipe.Version, remediation.IncidentKindEvidenceStreamStale); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE remediation_global_state SET remediation_enabled=true WHERE id`); err != nil {
		t.Fatal(err)
	}

	ready, err := domain.ReconstituteRemediationRun(plan, domain.RemediationReady, stored.Version(), domain.RemediationProgress{})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := ready.Dispatch(domain.RemediationDispatchRevalidation{
		Policy: domain.RemediationPolicyOutcome{
			Allowed: true, Code: string(remediation.PolicyAllowed), PolicyID: policyID,
			PolicyVersion: 1, DecidedAt: fixture.now,
		},
		Recipe: plan.Recipe, RecipeExpiresAt: fixture.forward.ExpiresAt, TargetSetDigest: plan.TargetSetDigest,
		RolePopulation: len(fixture.targets), PinnedPopulation: len(fixture.targets), LeaseHeld: true,
	}, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := domain.NewRemediationAttempt(
		domain.RemediationAttemptID("remediation-attempt-"+fixture.suffix), plan, domain.RemediationStageCanary,
		1, plan.TargetList()[:1], "worker-1", fixture.now, time.Now().UTC().Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	policy := application.RemediationPolicyRecord{PolicyID: policyID, Version: 1, Code: string(remediation.PolicyAllowed)}
	dispatchInput := application.RemediationDispatchInput{
		Recipe: fixture.forward, RollbackRecipe: &fixture.rollback,
		ClusterID: fixture.clusterID, Run: dispatched, ExpectedVersion: stored.Version(), Attempt: attempt,
		LeaseToken: "lease-token-" + fixture.suffix, MaxLeaseLifetime: application.MaxRemediationLeaseLifetime,
		Policy: policy, PinnedPopulation: len(fixture.targets), TargetSetDigest: plan.TargetSetDigest,
		DeadlineAt: fixture.now.Add(15 * time.Minute),
	}

	// A dispatch whose pinned digest no longer matches the persisted run is a
	// conflict: without the comparison inside this transaction the preflight
	// check would be a time-of-check/time-of-use no-op.
	drifted := dispatchInput
	drifted.TargetSetDigest = domain.ChecksumSHA256([]byte("drifted"))
	if _, err := fixture.store.DispatchRemediationAttempt(ctx, drifted, fixture.audit(application.RemediationAuditDispatch, plan, "drift")); !errors.Is(err, application.ErrRemediationConflict) {
		t.Fatalf("expected target drift to conflict, got %v", err)
	}
	drifted = dispatchInput
	drifted.PinnedPopulation = len(fixture.targets) + 1
	if _, err := fixture.store.DispatchRemediationAttempt(ctx, drifted, fixture.audit(application.RemediationAuditDispatch, plan, "population")); !errors.Is(err, application.ErrRemediationConflict) {
		t.Fatalf("expected population drift to conflict, got %v", err)
	}

	// A policy revoked between the check and the dispatch still blocks it,
	// because the row is re-read inside the dispatching transaction.
	if _, err := fixture.pool.Exec(ctx, `UPDATE remediation_policies SET revoked_at=clock_timestamp() WHERE cluster_id=$1 AND policy_id=$2`, fixture.clusterID, policyID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.DispatchRemediationAttempt(ctx, dispatchInput, fixture.audit(application.RemediationAuditDispatch, plan, "revoked")); !errors.Is(err, application.ErrRemediationForbidden) {
		t.Fatalf("expected a revoked policy to forbid the dispatch, got %v", err)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE remediation_policies SET revoked_at=NULL WHERE cluster_id=$1 AND policy_id=$2`, fixture.clusterID, policyID); err != nil {
		t.Fatal(err)
	}

	committedAttempt, err := fixture.store.DispatchRemediationAttempt(ctx, dispatchInput, fixture.audit(application.RemediationAuditDispatch, plan, "dispatch"))
	if err != nil {
		t.Fatalf("dispatch remediation attempt: %v", err)
	}
	var storedCreatedAt, storedLeaseExpiresAt, storedDeadlineAt time.Time
	if err := fixture.pool.QueryRow(ctx, `SELECT a.created_at,a.lease_expires_at,r.deadline_at
		FROM remediation_attempts a JOIN remediation_runs r USING(cluster_id,run_id)
		WHERE a.cluster_id=$1 AND a.attempt_id=$2`, fixture.clusterID, attempt.ID).
		Scan(&storedCreatedAt, &storedLeaseExpiresAt, &storedDeadlineAt); err != nil {
		t.Fatal(err)
	}
	if !committedAttempt.CreatedAt.Equal(storedCreatedAt) || !committedAttempt.LeaseExpiresAt.Equal(storedLeaseExpiresAt) {
		t.Fatal("the returned attempt must carry its PostgreSQL-created lease boundary")
	}
	if !storedDeadlineAt.Equal(storedCreatedAt.Add(fixture.forward.ObservationWindow)) {
		t.Fatalf("run deadline %s is not attempt boundary %s plus observation window", storedDeadlineAt, storedCreatedAt)
	}
	// Only the hash of the lease token is durable.
	var storedToken []byte
	if err := fixture.pool.QueryRow(ctx, `SELECT lease_token_hash FROM remediation_attempts WHERE cluster_id=$1 AND attempt_id=$2`,
		fixture.clusterID, attempt.ID).Scan(&storedToken); err != nil {
		t.Fatal(err)
	}
	if len(storedToken) != 32 {
		t.Fatalf("expected a 32-byte lease token hash, got %d bytes", len(storedToken))
	}
	var plaintextRows int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM remediation_attempts
		WHERE cluster_id=$1 AND lease_owner=$2`, fixture.clusterID, dispatchInput.LeaseToken).Scan(&plaintextRows); err != nil {
		t.Fatal(err)
	}
	if plaintextRows != 0 {
		t.Fatal("the plaintext lease token must never be persisted")
	}

	receipt := domain.RemediationReceipt{
		ID: domain.RemediationReceiptID("remediation-receipt-" + fixture.suffix), RunID: plan.RunID,
		AttemptID: attempt.ID, ClusterID: fixture.clusterID, IdempotencyKey: attempt.IdempotencyKey,
		Stage: attempt.Stage, Targets: attempt.WaveTargets,
		PerTarget: []domain.RemediationTargetOutcome{{Target: attempt.WaveTargets[0], Outcome: domain.ExecutionExecuted}},
		Outcome:   domain.ExecutionExecuted, ObservedAt: fixture.now,
	}
	receipt.Digest = receipt.ComputeDigest()
	verifying, err := dispatched.RecordCanaryOutcome(domain.RemediationExecutionReport{
		Outcome: domain.ExecutionExecuted, ExecutedTargets: attempt.WaveTargets,
		PerTarget: receipt.PerTarget,
	}, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	receiptInput := application.RemediationReceiptInput{
		ClusterID: fixture.clusterID, AttemptID: attempt.ID, LeaseToken: dispatchInput.LeaseToken,
		Receipt: receipt, Run: verifying, ExpectedVersion: dispatched.Version(),
	}

	// A receipt from an owner who cannot present the lease token is refused, and
	// the comparison is constant time.
	wrongToken := receiptInput
	wrongToken.LeaseToken = "wrong-token-" + fixture.suffix
	if _, err := fixture.store.RecordRemediationReceipt(ctx, wrongToken, fixture.audit(application.RemediationAuditReceipt, plan, "wrong-token")); !errors.Is(err, application.ErrRemediationLeaseInvalid) {
		t.Fatalf("expected a lease failure for a wrong token, got %v", err)
	}
	// A receipt replaying another attempt's idempotency key is refused as a
	// replay rather than accepted under this attempt.
	replay := receiptInput
	replay.Receipt.IdempotencyKey = attempt.IdempotencyKey + "0"
	var rejection domain.RemediationReceiptRejection
	if _, err := fixture.store.RecordRemediationReceipt(ctx, replay, fixture.audit(application.RemediationAuditReceipt, plan, "replay")); !errors.As(err, &rejection) || rejection.Code != domain.ReceiptReplay {
		t.Fatalf("expected a receipt replay rejection, got %v", err)
	}
	// The attempt is joined to its run on the cluster, so another cluster's
	// caller resolves to nothing at all.
	crossCluster := receiptInput
	crossCluster.ClusterID = domain.ClusterID("another-cluster-" + fixture.suffix)
	crossAudit := fixture.audit(application.RemediationAuditReceipt, plan, "cross-cluster")
	crossAudit.ClusterID = crossCluster.ClusterID
	if _, err := fixture.store.RecordRemediationReceipt(ctx, crossCluster, crossAudit); !errors.Is(err, application.ErrRemediationLeaseInvalid) {
		t.Fatalf("expected a cross-cluster receipt to be refused, got %v", err)
	}

	outcome, err := fixture.store.RecordRemediationReceipt(ctx, receiptInput, fixture.audit(application.RemediationAuditReceipt, plan, "receipt"))
	if err != nil {
		t.Fatalf("record remediation receipt: %v", err)
	}
	if outcome.PreviouslyRecorded {
		t.Fatal("the first delivery must record a new receipt")
	}
	// The database owns the observation instant, and the digest covers the
	// stored value rather than the caller's.
	if outcome.Receipt.ObservedAt.Equal(fixture.now) {
		t.Fatal("the receipt observation instant must be set by the database")
	}
	if outcome.Receipt.Digest != outcome.Receipt.ComputeDigest() {
		t.Fatal("the stored receipt digest must cover the stored receipt")
	}

	// A duplicate delivery after an acknowledgement loss returns the recorded
	// receipt instead of mutating twice.
	duplicate := receiptInput
	duplicate.Receipt.ID = domain.RemediationReceiptID("remediation-receipt-duplicate-" + fixture.suffix)
	replayed, err := fixture.store.RecordRemediationReceipt(ctx, duplicate, fixture.audit(application.RemediationAuditReceipt, plan, "duplicate"))
	if err != nil {
		t.Fatalf("duplicate delivery: %v", err)
	}
	if !replayed.PreviouslyRecorded || replayed.Receipt.ID != receipt.ID {
		t.Fatalf("expected the recorded receipt, got %s previously=%t", replayed.Receipt.ID, replayed.PreviouslyRecorded)
	}
	var receiptCount int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM remediation_receipts WHERE cluster_id=$1 AND run_id=$2`,
		fixture.clusterID, plan.RunID).Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 1 {
		t.Fatalf("expected exactly one receipt, got %d", receiptCount)
	}

	// The executed target set is reconstructed from receipts, so a rollback can
	// only ever touch targets that actually executed.
	loaded, found, err := fixture.store.LoadRemediationRun(ctx, fixture.clusterID, plan.RunID)
	if err != nil || !found {
		t.Fatalf("load remediation run: found=%t err=%v", found, err)
	}
	if len(loaded.ExecutedTargets) != 1 || loaded.ExecutedTargets[0] != attempt.WaveTargets[0] {
		t.Fatalf("expected exactly the executed canary target, got %v", loaded.ExecutedTargets)
	}
	if loaded.Run.State() != domain.RemediationVerifying {
		t.Fatalf("expected VERIFYING after an executed canary, got %s", loaded.Run.State())
	}
	if loaded.Attempts(domain.RemediationStageCanary) != 1 {
		t.Fatalf("expected one recorded canary attempt, got %d", loaded.Attempts(domain.RemediationStageCanary))
	}
	if _, found, err := fixture.store.LoadRemediationRun(ctx, domain.ClusterID("another-cluster-"+fixture.suffix), plan.RunID); err != nil || found {
		t.Fatalf("a run must not be readable from another cluster: found=%t err=%v", found, err)
	}
}

// TestRemediationStoreRestartsFromEveryNonTerminalState proves a control
// process that crashed mid-run recovers the aggregate, its bounded-loop budgets
// and its reclaim deadline from durable rows alone.
func TestRemediationStoreRestartsFromEveryNonTerminalState(t *testing.T) {
	fixture := newRemediationFixture(t)
	ctx := context.Background()
	plan := fixture.plan(t, domain.RemediationRunID("remediation-run-"+fixture.suffix), fixture.targets)
	if _, created := fixture.create(t, plan, "create"); !created {
		t.Fatal("expected the run to be created")
	}
	progress := domain.RemediationProgress{RolloutWave: 1, RollbackAttempt: 1, TotalAttempts: 2}
	for _, state := range domain.AllRemediationStates() {
		if state.Terminal() {
			continue
		}
		t.Run(string(state), func(t *testing.T) {
			if _, err := fixture.pool.Exec(ctx, `UPDATE remediation_runs SET state=$3, version=version+1,
					rollout_wave=$4, rollback_attempt=$5, total_attempts=$6, lease_owner='worker-1',
					lease_expires_at=clock_timestamp()+interval '1 minute'
				WHERE cluster_id=$1 AND run_id=$2`,
				fixture.clusterID, plan.RunID, string(state),
				progress.RolloutWave, progress.RollbackAttempt, progress.TotalAttempts); err != nil {
				t.Fatal(err)
			}
			loaded, found, err := fixture.store.LoadRemediationRun(ctx, fixture.clusterID, plan.RunID)
			if err != nil || !found {
				t.Fatalf("load: found=%t err=%v", found, err)
			}
			if loaded.Run.State() != state {
				t.Fatalf("expected %s, got %s", state, loaded.Run.State())
			}
			if loaded.Run.Progress() != progress {
				t.Fatalf("a restart must not refill the repair budget: %+v", loaded.Run.Progress())
			}
			if loaded.Run.Plan().TargetSetDigest != plan.TargetSetDigest {
				t.Fatal("the restored plan must carry the persisted target-set digest")
			}
			if loaded.DeadlineAt.IsZero() {
				t.Fatal("a non-terminal run must carry a reclaim deadline")
			}
		})
	}
	// An invalid state cannot be written even by a future code path.
	if _, err := fixture.pool.Exec(ctx, `UPDATE remediation_runs SET state='NOT_A_STATE' WHERE cluster_id=$1 AND run_id=$2`,
		fixture.clusterID, plan.RunID); err == nil {
		t.Fatal("an unknown remediation state must be refused by the state CHECK")
	}
}

// TestRemediationStoreReadsFactsFromDurableRows proves every authorizing fact
// is joined out of the database rather than accepted from a caller.
func TestRemediationStoreReadsFactsFromDurableRows(t *testing.T) {
	fixture := newRemediationFixture(t)
	ctx := context.Background()
	plan := fixture.plan(t, domain.RemediationRunID("remediation-run-"+fixture.suffix), fixture.targets[:1])
	if _, created := fixture.create(t, plan, "create"); !created {
		t.Fatal("expected the run to be created")
	}
	facts, err := fixture.store.ReadRemediationFacts(ctx, application.RemediationFactQuery{
		ClusterID: fixture.clusterID, IncidentID: fixture.incidentID, InvestigationID: fixture.investigationID,
		RunID: plan.RunID, RecipeID: plan.Recipe.ID, RecipeVersion: plan.Recipe.Version,
		TargetSetDigest: plan.TargetSetDigest,
	})
	if err != nil {
		t.Fatalf("read remediation facts: %v", err)
	}
	if facts.Now.IsZero() || !facts.StateObservedAt.Equal(facts.Now) || !facts.PopulationObservedAt.Equal(facts.Now) {
		t.Fatal("every observed counter must carry the snapshot instant it was read at")
	}
	if facts.IncidentKind != remediation.IncidentKindEvidenceStreamStale {
		t.Fatalf("the incident kind must come from the durable anomaly row, got %q", facts.IncidentKind)
	}
	if len(facts.Inventory) != len(fixture.targets) {
		t.Fatalf("expected %d inventory rows, got %d", len(fixture.targets), len(facts.Inventory))
	}
	for _, row := range facts.Inventory {
		if row.ClusterID != fixture.clusterID || row.Source != domain.SourceCollectionJobs {
			t.Fatalf("inventory row is not cluster-scoped collection_jobs: %+v", row)
		}
	}
	if len(facts.Evidence) != 1 || facts.Evidence[0].Class != remediation.EvidenceClassCollectionFreshness ||
		facts.Evidence[0].Coverage != 100 || facts.Evidence[0].Superseded {
		t.Fatalf("unexpected evidence facts: %+v", facts.Evidence)
	}
	// This run is the only non-terminal repair for its target set, so the
	// positively phrased conflict observation holds.
	if !facts.NoActiveEquivalentRun {
		t.Fatal("the run must not count itself as a conflicting equivalent repair")
	}
	// Nothing leaks across clusters.
	other, err := fixture.store.ReadRemediationFacts(ctx, application.RemediationFactQuery{
		ClusterID: domain.ClusterID("another-cluster-" + fixture.suffix), IncidentID: fixture.incidentID,
		InvestigationID: fixture.investigationID, RecipeID: plan.Recipe.ID, RecipeVersion: plan.Recipe.Version,
	})
	if err != nil {
		t.Fatalf("read remediation facts for another cluster: %v", err)
	}
	if len(other.Inventory) != 0 || len(other.Evidence) != 0 || other.IncidentKind != "" || other.Policy.ID != "" {
		t.Fatal("another cluster must observe none of this cluster's facts")
	}
}

//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediation"
)

// TestRemediationDispatchRechecksMutableFacts exercises the race boundary that
// a pre-dispatch application read cannot close. Each case first constructs an
// ALLOWED dispatch from a prior view, then changes one durable fact before the
// store transaction starts. The store must decide from its own locked snapshot.
func TestRemediationDispatchRechecksMutableFacts(t *testing.T) {
	t.Run("inventory changed after application decision", func(t *testing.T) {
		fixture := newRemediationFixture(t)
		input, audit := newRemediationDispatchSecurityInput(t, fixture, fixture.targets[:1], 1, 0)

		if _, err := fixture.pool.Exec(context.Background(), `UPDATE collection_jobs SET active=false
			WHERE cluster_id=$1 AND job_id=$2`, fixture.clusterID, fixture.targets[0]); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.DispatchRemediationAttempt(context.Background(), input, audit); !errors.Is(err, application.ErrRemediationConflict) {
			t.Fatalf("inventory drift must block dispatch, got %v", err)
		}
		assertNoRemediationAttempt(t, fixture, input.Attempt.ID)
	})

	t.Run("concurrent dispatches reserve one policy slot", func(t *testing.T) {
		fixture := newRemediationFixture(t)
		first, firstAudit := newRemediationDispatchSecurityInput(t, fixture, fixture.targets[:1], 1, 0)

		secondPlan := fixture.plan(t, domain.RemediationRunID("remediation-racing-run-"+fixture.suffix), fixture.targets[1:2])
		secondPlan.ActionCardID = ""
		secondStored, created := fixture.create(t, secondPlan, "racing-create")
		if !created {
			t.Fatal("expected the independently targeted racing run to be created")
		}
		second, secondAudit := remediationDispatchInputForPlan(t, fixture, secondStored, secondPlan,
			first.Policy, fixture.targets[1], "racing")
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, dispatch := range []struct {
			input application.RemediationDispatchInput
			audit application.RemediationAuditEvent
		}{{first, firstAudit}, {second, secondAudit}} {
			dispatch := dispatch
			go func() {
				<-start
				_, err := fixture.store.DispatchRemediationAttempt(context.Background(), dispatch.input, dispatch.audit)
				results <- err
			}()
		}
		close(start)
		allowed, denied := 0, 0
		for range 2 {
			err := <-results
			switch {
			case err == nil:
				allowed++
			case errors.Is(err, application.ErrRemediationForbidden):
				denied++
			default:
				t.Fatalf("unexpected concurrent dispatch result: %v", err)
			}
		}
		if allowed != 1 || denied != 1 {
			t.Fatalf("expected one reserved slot and one denial, allowed=%d denied=%d", allowed, denied)
		}
		var attempts int
		if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM remediation_attempts WHERE cluster_id=$1`, fixture.clusterID).Scan(&attempts); err != nil {
			t.Fatal(err)
		}
		if attempts != 1 {
			t.Fatalf("concurrent limit persisted %d attempts, want 1", attempts)
		}
	})

	t.Run("cooldown began after application decision", func(t *testing.T) {
		fixture := newRemediationFixture(t)
		input, audit := newRemediationDispatchSecurityInput(t, fixture, fixture.targets[:1], 2, int((time.Hour)/time.Second))

		priorPlan := fixture.plan(t, domain.RemediationRunID("remediation-prior-run-"+fixture.suffix), fixture.targets[1:2])
		priorPlan.ActionCardID = ""
		prior, created := fixture.create(t, priorPlan, "prior-create")
		if !created {
			t.Fatal("expected prior run to be created")
		}
		cancelled, err := prior.Cancel(time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.RecordRemediationTransition(context.Background(), application.RemediationTransition{
			ClusterID: fixture.clusterID, Run: cancelled, ExpectedVersion: prior.Version(),
		}, fixture.audit(application.RemediationAuditCancellation, priorPlan, "prior-cancel")); err != nil {
			t.Fatal(err)
		}

		if _, err := fixture.store.DispatchRemediationAttempt(context.Background(), input, audit); !errors.Is(err, application.ErrRemediationForbidden) {
			t.Fatalf("fresh cooldown boundary must block dispatch, got %v", err)
		}
		assertNoRemediationAttempt(t, fixture, input.Attempt.ID)
	})

	t.Run("rollout cannot bypass prior wave verification", func(t *testing.T) {
		fixture := newRemediationFixture(t)
		input, audit := newRemediationDispatchSecurityInput(t, fixture, fixture.targets[:2], 1, 0)
		plan := input.Run.Plan()
		rolling, err := domain.ReconstituteRemediationRun(plan, domain.RemediationRollingOut,
			input.ExpectedVersion+1, domain.RemediationProgress{RolloutWave: 1, TotalAttempts: 2})
		if err != nil {
			t.Fatal(err)
		}
		attempt, err := domain.NewRemediationAttempt(
			domain.RemediationAttemptID("remediation-rollout-bypass-"+fixture.suffix), plan,
			domain.RemediationStageRollout, 1, fixture.targets[1:2], "worker-1",
			fixture.now, fixture.now.Add(2*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		input.Run, input.Attempt = rolling, attempt
		audit.AttemptID = attempt.ID
		if _, err := fixture.store.DispatchRemediationAttempt(context.Background(), input, audit); !errors.Is(err, application.ErrRemediationConflict) {
			t.Fatalf("rollout without durable verification evidence must conflict, got %v", err)
		}
		assertNoRemediationAttempt(t, fixture, attempt.ID)
	})
}

// TestRemediationDispatchFactLocks deliberately overlaps writers with dispatch.
// It proves both commit orders: a writer already in progress is observed before
// dispatch, while a writer arriving after dispatch's fact lock cannot invalidate
// the decision before the attempt reservation commits.
func TestRemediationDispatchFactLocks(t *testing.T) {
	t.Run("pending inventory change commits before decision", func(t *testing.T) {
		fixture := newRemediationFixture(t)
		input, audit := newRemediationDispatchSecurityInput(t, fixture, fixture.targets[:1], 1, 0)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		writer, err := fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = writer.Rollback(context.Background()) }()
		if _, err := writer.Exec(ctx, `UPDATE collection_jobs SET active=false WHERE cluster_id=$1 AND job_id=$2`, fixture.clusterID, fixture.targets[0]); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			_, dispatchErr := fixture.store.DispatchRemediationAttempt(ctx, input, audit)
			result <- dispatchErr
		}()
		select {
		case err := <-result:
			t.Fatalf("dispatch escaped an uncommitted inventory writer: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		if err := writer.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, application.ErrRemediationConflict) {
			t.Fatalf("dispatch must observe the committed inventory drift, got %v", err)
		}
		assertNoRemediationAttempt(t, fixture, input.Attempt.ID)
	})

	t.Run("dispatch reservation commits before later inventory change", func(t *testing.T) {
		fixture := newRemediationFixture(t)
		input, audit := newRemediationDispatchSecurityInput(t, fixture, fixture.targets[:1], 1, 0)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		gate, err := fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = gate.Rollback(context.Background()) }()
		var lockedCluster domain.ClusterID
		if err := gate.QueryRow(ctx, `SELECT cluster_id FROM clusters WHERE cluster_id=$1 FOR UPDATE`, fixture.clusterID).Scan(&lockedCluster); err != nil {
			t.Fatal(err)
		}
		dispatchResult := make(chan error, 1)
		go func() {
			_, dispatchErr := fixture.store.DispatchRemediationAttempt(ctx, input, audit)
			dispatchResult <- dispatchErr
		}()
		if !waitForRemediationFactLock(ctx, fixture) {
			t.Fatal("dispatch never acquired the inventory fact lock")
		}
		writerResult := make(chan error, 1)
		go func() {
			_, writeErr := fixture.pool.Exec(ctx, `UPDATE collection_jobs SET active=false WHERE cluster_id=$1 AND job_id=$2`, fixture.clusterID, fixture.targets[0])
			writerResult <- writeErr
		}()
		select {
		case err := <-writerResult:
			t.Fatalf("inventory writer crossed the dispatch fact lock: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		if err := gate.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-dispatchResult; err != nil {
			t.Fatalf("dispatch failed after acquiring the earlier commit order: %v", err)
		}
		if err := <-writerResult; err != nil {
			t.Fatalf("inventory writer did not continue after dispatch commit: %v", err)
		}
	})

	t.Run("pending policy revocation commits before decision", func(t *testing.T) {
		fixture := newRemediationFixture(t)
		input, audit := newRemediationDispatchSecurityInput(t, fixture, fixture.targets[:1], 1, 0)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		writer, err := fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = writer.Rollback(context.Background()) }()
		if _, err := writer.Exec(ctx, `UPDATE remediation_policies SET revoked_at=clock_timestamp()
			WHERE cluster_id=$1 AND policy_id=$2`, fixture.clusterID, input.Policy.PolicyID); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			_, dispatchErr := fixture.store.DispatchRemediationAttempt(ctx, input, audit)
			result <- dispatchErr
		}()
		select {
		case err := <-result:
			t.Fatalf("dispatch escaped an uncommitted policy writer: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		if err := writer.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, application.ErrRemediationForbidden) {
			t.Fatalf("dispatch must observe the committed policy revocation, got %v", err)
		}
	})

	t.Run("pending global kill commits before decision", func(t *testing.T) {
		fixture := newRemediationFixture(t)
		input, audit := newRemediationDispatchSecurityInput(t, fixture, fixture.targets[:1], 1, 0)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		writer, err := fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = writer.Rollback(context.Background()) }()
		if _, err := writer.Exec(ctx, `UPDATE remediation_global_state SET remediation_enabled=false WHERE id`); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			_, dispatchErr := fixture.store.DispatchRemediationAttempt(ctx, input, audit)
			result <- dispatchErr
		}()
		select {
		case err := <-result:
			t.Fatalf("dispatch escaped an uncommitted global kill: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		if err := writer.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, application.ErrRemediationForbidden) {
			t.Fatalf("dispatch must observe the committed global kill, got %v", err)
		}
	})
}

func waitForRemediationFactLock(ctx context.Context, fixture remediationFixture) bool {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var held bool
		err := fixture.pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_locks l JOIN pg_class c ON c.oid=l.relation
			WHERE c.relname='collection_jobs' AND l.mode='ShareRowExclusiveLock' AND l.granted)`).Scan(&held)
		if err != nil {
			return false
		}
		if held {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

func newRemediationDispatchSecurityInput(t *testing.T, fixture remediationFixture, targets []domain.RemediationTarget, maxConcurrent, cooldownSeconds int) (application.RemediationDispatchInput, application.RemediationAuditEvent) {
	t.Helper()
	ctx := context.Background()
	plan := fixture.plan(t, domain.RemediationRunID("remediation-dispatch-security-"+fixture.suffix), targets)
	stored, created := fixture.create(t, plan, "dispatch-security-create")
	if !created {
		t.Fatal("expected remediation run to be created")
	}

	policyID := domain.RemediationPolicyID("remediation-dispatch-policy-" + fixture.suffix)
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO remediation_policies (
			cluster_id, policy_id, version, recipe_id, recipe_version, enabled, max_tier, incident_kinds,
			max_targets, max_concurrent_runs, cooldown_seconds, evidence_max_age_seconds, min_evidence_coverage,
			not_before, not_after)
		VALUES ($1,$2,1,$3,$4,true,1,ARRAY[$5],4,$6,$7,900,100,
			clock_timestamp()-interval '1 hour', clock_timestamp()+interval '1 hour')`,
		fixture.clusterID, policyID, plan.Recipe.ID, plan.Recipe.Version,
		remediation.IncidentKindEvidenceStreamStale, maxConcurrent, cooldownSeconds); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE remediation_global_state SET remediation_enabled=true WHERE id`); err != nil {
		t.Fatal(err)
	}
	policy := application.RemediationPolicyRecord{PolicyID: policyID, Version: 1, Code: string(remediation.PolicyAllowed)}
	return remediationDispatchInputForPlan(t, fixture, stored, plan, policy, targets[0], "dispatch-security")
}

func remediationDispatchInputForPlan(t *testing.T, fixture remediationFixture, stored domain.RemediationRun, plan domain.RemediationPlan, policy application.RemediationPolicyRecord, target domain.RemediationTarget, label string) (application.RemediationDispatchInput, application.RemediationAuditEvent) {
	t.Helper()
	ready, err := domain.ReconstituteRemediationRun(plan, domain.RemediationReady, stored.Version(), domain.RemediationProgress{})
	if err != nil {
		t.Fatal(err)
	}
	allowed := domain.RemediationPolicyOutcome{
		Allowed: true, Code: string(remediation.PolicyAllowed), PolicyID: policy.PolicyID,
		PolicyVersion: 1, DecidedAt: fixture.now,
	}
	dispatched, err := ready.Dispatch(domain.RemediationDispatchRevalidation{
		Policy: allowed, Recipe: plan.Recipe, RecipeExpiresAt: fixture.forward.ExpiresAt,
		TargetSetDigest: plan.TargetSetDigest, RolePopulation: len(fixture.targets),
		PinnedPopulation: len(fixture.targets), LeaseHeld: true,
	}, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := domain.NewRemediationAttempt(
		domain.RemediationAttemptID("remediation-dispatch-attempt-"+label+"-"+fixture.suffix), plan,
		domain.RemediationStageCanary, 1, []domain.RemediationTarget{target}, "worker-1",
		fixture.now, fixture.now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	input := application.RemediationDispatchInput{
		Recipe: fixture.forward, RollbackRecipe: &fixture.rollback,
		ClusterID: fixture.clusterID, Run: dispatched, ExpectedVersion: stored.Version(), Attempt: attempt,
		LeaseToken:       "dispatch-security-token-" + label + "-" + fixture.suffix,
		MaxLeaseLifetime: application.MaxRemediationLeaseLifetime,
		Policy:           policy, PinnedPopulation: len(fixture.targets), TargetSetDigest: plan.TargetSetDigest,
		DeadlineAt: fixture.now.Add(15 * time.Minute),
	}
	audit := fixture.audit(application.RemediationAuditDispatch, plan, label)
	audit.AttemptID = attempt.ID
	return input, audit
}

func assertNoRemediationAttempt(t *testing.T, fixture remediationFixture, attemptID domain.RemediationAttemptID) {
	t.Helper()
	var count int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM remediation_attempts
		WHERE cluster_id=$1 AND attempt_id=$2`, fixture.clusterID, attemptID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("blocked dispatch persisted %d attempt rows", count)
	}
}

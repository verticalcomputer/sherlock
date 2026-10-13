package domain

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func remediationInstant() time.Time { return time.Date(2026, 9, 10, 3, 0, 0, 0, time.UTC) }

func resolvedRemediationTargets(names ...RemediationTarget) []ResolvedTarget {
	resolved := make([]ResolvedTarget, 0, len(names))
	for _, name := range names {
		resolved = append(resolved, ResolvedTarget{
			Target: name, Role: RoleManagedCollectionStream, ClusterID: "cluster-1",
			ResolvedAt: remediationInstant(), Source: SourceCollectionJobs,
		})
	}
	return resolved
}

func validRemediationPlan(withRollback bool) RemediationPlan {
	now := remediationInstant()
	targets := resolvedRemediationTargets("stream-1", "stream-2")
	plan := RemediationPlan{
		RunID:           "run-1",
		ClusterID:       "cluster-1",
		IncidentID:      "incident-1",
		InvestigationID: "investigation-1",
		ActionCardID:    "card-1",
		Recipe:          RemediationRecipeRef{ID: "sherlock.requeue", Version: "1.0.0", Digest: ChecksumSHA256([]byte("forward"))},
		Tier:            TierSherlockOwnedRepair,
		Privilege:       PrivilegeSherlockInternal,
		Assurance:       AssuranceSimulated,
		Targets:         targets,
		TargetSetDigest: RemediationTargetSetDigest(targets),
		Arguments: TypedArguments{
			{Name: "priority", Type: ParameterEnum, Enum: "NORMAL"},
			{Name: "requeue_reason", Type: ParameterEnum, Enum: "STALE_STREAM"},
		},
		MaxTargets:     4,
		MaxConcurrency: 1,
		CanaryTargets:  1,
		MaxAttempts:    2,
		ProposedAt:     now,
		ExpiresAt:      now.Add(time.Hour),
	}
	if withRollback {
		plan.Rollback = RemediationRecipeRef{ID: "sherlock.restore", Version: "1.0.0", Digest: ChecksumSHA256([]byte("rollback"))}
	}
	return plan
}

func runInState(t *testing.T, state RemediationState, withRollback bool) RemediationRun {
	t.Helper()
	run, err := ReconstituteRemediationRun(validRemediationPlan(withRollback), state, 7, RemediationProgress{})
	if err != nil {
		t.Fatalf("reconstitute %s: %v", state, err)
	}
	return run
}

// expectedLegalRemediationTransitions is written out by hand, deliberately.
//
// The earlier version of this test used the production transition map as its
// own oracle while Transition consulted that same map, so for most of the 289
// cells it compared the code with itself and proved nothing about the table's
// content. A wrong edge that preserved the total count would have passed
// silently. This literal is the independent statement of what the state machine
// is allowed to do; if the production table and this list disagree, one of them
// is wrong and the test says so.
var expectedLegalRemediationTransitions = map[RemediationState][]RemediationState{
	RemediationProposed:        {RemediationPolicyCheck, RemediationCancelled, RemediationExpired},
	RemediationPolicyCheck:     {RemediationPreflight, RemediationPolicyBlocked, RemediationCancelled, RemediationExpired},
	RemediationPreflight:       {RemediationReady, RemediationPreflightFailed, RemediationCancelled, RemediationExpired},
	RemediationReady:           {RemediationCanaryExecuting, RemediationPolicyBlocked, RemediationPreflightFailed, RemediationCancelled, RemediationExpired},
	RemediationCanaryExecuting: {RemediationVerifying, RemediationRollingBack, RemediationContained, RemediationFailed},
	RemediationVerifying:       {RemediationRollingOut, RemediationSucceeded, RemediationRollingBack, RemediationContained, RemediationFailed},
	RemediationRollingOut:      {RemediationVerifying, RemediationRollingBack, RemediationContained, RemediationFailed},
	RemediationRollingBack:     {RemediationRolledBack, RemediationRollbackFailed, RemediationContained},
}

func expectedLegal(from, to RemediationState) bool {
	return slices.Contains(expectedLegalRemediationTransitions[from], to)
}

func TestRemediationTransitionCrossProduct(t *testing.T) {
	now := remediationInstant()
	states := AllRemediationStates()
	if len(states) != 17 {
		t.Fatalf("state count = %d, want 17", len(states))
	}
	legal := 0
	for _, from := range states {
		for _, to := range states {
			// The expectation comes from the hand-written list above, never from
			// the production map the code under test consults.
			want := expectedLegal(from, to)
			if want != LegalRemediationTransition(from, to) {
				t.Fatalf("production table and the independent list disagree on %s -> %s", from, to)
			}
			run := runInState(t, from, true)
			advanced, err := run.Transition(to, now)
			if want {
				legal++
				if err != nil {
					t.Fatalf("legal transition %s -> %s: %v", from, to, err)
				}
				if advanced.State() != to {
					t.Fatalf("state = %s, want %s", advanced.State(), to)
				}
				if advanced.Version() != run.Version()+1 {
					t.Fatalf("version = %d, want %d", advanced.Version(), run.Version()+1)
				}
				if !advanced.UpdatedAt().Equal(now) {
					t.Fatalf("updatedAt = %s, want %s", advanced.UpdatedAt(), now)
				}
				continue
			}
			var conflict TransitionConflictError
			if !errors.As(err, &conflict) {
				t.Fatalf("illegal transition %s -> %s returned %v, want conflict", from, to, err)
			}
			if conflict.From != string(from) {
				t.Fatalf("conflict from = %s, want %s", conflict.From, from)
			}
		}
	}
	if legal != LegalRemediationTransitionCount() {
		t.Fatalf("walked %d legal edges, table declares %d", legal, LegalRemediationTransitionCount())
	}
	if legal != 32 {
		t.Fatalf("legal edge count = %d, want 32", legal)
	}
}

// TestRemediationTransitionRefusesNonMonotonicInstant is the regression test for
// the D7 fix. It had none: every fixture leaves updatedAt at its zero value, so
// the guard's branch was never taken by any test in the suite.
func TestRemediationTransitionRefusesNonMonotonicInstant(t *testing.T) {
	now := remediationInstant()
	run := runInState(t, RemediationProposed, true)
	advanced, err := run.Transition(RemediationPolicyCheck, now)
	if err != nil {
		t.Fatalf("first transition: %v", err)
	}
	if _, err := advanced.Transition(RemediationPreflight, now.Add(-time.Second)); err == nil {
		t.Fatal("a transition instant earlier than the previous transition must be refused")
	}
	// The same instant is fine: two transitions can share a server-causal read.
	if _, err := advanced.Transition(RemediationPreflight, now); err != nil {
		t.Fatalf("an equal instant must be accepted: %v", err)
	}
}

// TestRemediationRollingBackReachesContainment covers the edge added because a
// rollback whose own outcome is unknown had nowhere definite to go.
func TestRemediationRollingBackReachesContainment(t *testing.T) {
	now := remediationInstant()
	if !LegalRemediationTransition(RemediationRollingBack, RemediationContained) {
		t.Fatal("ROLLING_BACK must be able to reach CONTAINED")
	}
	if LegalRemediationTransition(RemediationRollbackFailed, RemediationContained) {
		t.Fatal("ROLLBACK_FAILED is terminal and must have no successor")
	}
	cases := []struct {
		name   string
		report RemediationExecutionReport
		want   RemediationState
	}{
		{name: "unknown rollback outcome", report: RemediationExecutionReport{Outcome: ExecutionUnknown}, want: RemediationContained},
		{name: "lease lost during rollback", report: RemediationExecutionReport{Outcome: ExecutionExecuted, LeaseLost: true}, want: RemediationContained},
		{name: "rollback refused", report: RemediationExecutionReport{Outcome: ExecutionRefused}, want: RemediationRollbackFailed},
		{name: "rollback failed", report: RemediationExecutionReport{Outcome: ExecutionFailed}, want: RemediationRollbackFailed},
		{name: "rollback timed out", report: RemediationExecutionReport{Outcome: ExecutionTimedOut}, want: RemediationRollbackFailed},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			run := runInState(t, RemediationRollingBack, true)
			advanced, err := run.RecordRollbackExecution(testCase.report, now)
			if err != nil {
				t.Fatal(err)
			}
			if advanced.State() != testCase.want {
				t.Fatalf("state = %s, want %s", advanced.State(), testCase.want)
			}
		})
	}
	run := runInState(t, RemediationRollingBack, true)
	pending, err := run.RecordRollbackExecution(RemediationExecutionReport{Outcome: ExecutionExecuted}, now)
	if err != nil {
		t.Fatal(err)
	}
	if pending.State() != RemediationRollingBack {
		t.Fatalf("an executed rollback still awaits verification, got %s", pending.State())
	}
	for _, state := range AllRemediationStates() {
		if state == RemediationRollingBack {
			continue
		}
		other := runInState(t, state, true)
		if _, err := other.RecordRollbackExecution(RemediationExecutionReport{Outcome: ExecutionExecuted}, now); err == nil {
			t.Fatalf("rollback execution from %s should be refused", state)
		}
	}
}

func TestRemediationTerminalStatesHaveNoSuccessors(t *testing.T) {
	terminal := []RemediationState{
		RemediationSucceeded, RemediationPolicyBlocked, RemediationPreflightFailed,
		RemediationRolledBack, RemediationRollbackFailed, RemediationContained,
		RemediationFailed, RemediationCancelled, RemediationExpired,
	}
	for _, state := range terminal {
		if !state.Terminal() {
			t.Fatalf("%s should be terminal", state)
		}
	}
	nonTerminal := []RemediationState{
		RemediationProposed, RemediationPolicyCheck, RemediationPreflight, RemediationReady,
		RemediationCanaryExecuting, RemediationVerifying, RemediationRollingOut, RemediationRollingBack,
	}
	for _, state := range nonTerminal {
		if state.Terminal() {
			t.Fatalf("%s should not be terminal", state)
		}
	}
}

// TestRemediationCancellationAndExpiryArePreDispatchOnly proves the rule that
// once a mutation may have happened the operator path is containment or
// rollback, never "cancel and forget".
func TestRemediationCancellationAndExpiryArePreDispatchOnly(t *testing.T) {
	now := remediationInstant()
	executing := []RemediationState{
		RemediationCanaryExecuting, RemediationVerifying, RemediationRollingOut, RemediationRollingBack,
	}
	for _, state := range executing {
		run := runInState(t, state, true)
		if _, err := run.Cancel(now); err == nil {
			t.Fatalf("cancel from %s should be refused", state)
		}
		if _, err := run.Expire(now); err == nil {
			t.Fatalf("expire from %s should be refused", state)
		}
	}
	for _, state := range []RemediationState{RemediationProposed, RemediationPolicyCheck, RemediationPreflight, RemediationReady} {
		run := runInState(t, state, true)
		if _, err := run.Cancel(now); err != nil {
			t.Fatalf("cancel from %s: %v", state, err)
		}
		if _, err := run.Expire(now); err != nil {
			t.Fatalf("expire from %s: %v", state, err)
		}
	}
}

func TestRemediationVerificationRefusesUnearnedSuccess(t *testing.T) {
	now := remediationInstant()
	full := []RemediationTarget{"stream-1", "stream-2"}
	cases := []struct {
		name         string
		verification RemediationVerification
		wantCode     string
	}{
		{
			name:         "no postcondition observed at all",
			verification: RemediationVerification{ExecutedTargets: full},
			wantCode:     VerificationPostconditionsMissing,
		},
		{
			name: "postcondition unsatisfied",
			verification: RemediationVerification{
				Postconditions:  []RemediationConditionResult{{ConditionID: "stream-fresh", Result: ConditionUnsatisfied}},
				ExecutedTargets: full,
			},
			wantCode: VerificationUnsatisfied,
		},
		{
			name: "postcondition never observed",
			verification: RemediationVerification{
				Postconditions:  []RemediationConditionResult{{ConditionID: "stream-fresh", Result: ConditionUnobserved}},
				ExecutedTargets: full,
			},
			wantCode: VerificationUnobserved,
		},
		{
			name: "executed targets are a proper subset of the resolved set",
			verification: RemediationVerification{
				Postconditions:  []RemediationConditionResult{{ConditionID: "stream-fresh", Result: ConditionSatisfied}},
				ExecutedTargets: []RemediationTarget{"stream-1"},
			},
			wantCode: VerificationCoverageIncomplete,
		},
		{
			name: "executed targets exceed the resolved set",
			verification: RemediationVerification{
				Postconditions:  []RemediationConditionResult{{ConditionID: "stream-fresh", Result: ConditionSatisfied}},
				ExecutedTargets: []RemediationTarget{"stream-1", "stream-2", "stream-3"},
			},
			wantCode: VerificationCoverageIncomplete,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			run := runInState(t, RemediationVerifying, true)
			_, err := run.RecordVerification(testCase.verification, now)
			var refusal RemediationVerificationError
			if !errors.As(err, &refusal) {
				t.Fatalf("err = %v, want verification refusal", err)
			}
			if refusal.Code != testCase.wantCode {
				t.Fatalf("code = %s, want %s", refusal.Code, testCase.wantCode)
			}
		})
	}

	run := runInState(t, RemediationVerifying, true)
	succeeded, err := run.RecordVerification(RemediationVerification{
		Postconditions:  []RemediationConditionResult{{ConditionID: "stream-fresh", Result: ConditionSatisfied}},
		ExecutedTargets: full,
	}, now)
	if err != nil {
		t.Fatalf("full coverage with satisfied postconditions: %v", err)
	}
	if succeeded.State() != RemediationSucceeded {
		t.Fatalf("state = %s, want SUCCEEDED", succeeded.State())
	}
}

func TestRemediationVerificationIsUnreachableOutsideVerifying(t *testing.T) {
	now := remediationInstant()
	for _, state := range AllRemediationStates() {
		if state == RemediationVerifying {
			continue
		}
		run := runInState(t, state, true)
		_, err := run.RecordVerification(RemediationVerification{
			Postconditions:  []RemediationConditionResult{{ConditionID: "stream-fresh", Result: ConditionSatisfied}},
			ExecutedTargets: []RemediationTarget{"stream-1", "stream-2"},
		}, now)
		var conflict TransitionConflictError
		if !errors.As(err, &conflict) {
			t.Fatalf("verification from %s returned %v, want conflict", state, err)
		}
	}
}

func TestRemediationRollbackRequiresADefinition(t *testing.T) {
	now := remediationInstant()
	for _, state := range []RemediationState{RemediationCanaryExecuting, RemediationVerifying, RemediationRollingOut} {
		run := runInState(t, state, false)
		_, err := run.BeginRollback(now)
		var undefined RemediationRollbackUndefinedError
		if !errors.As(err, &undefined) {
			t.Fatalf("rollback from %s returned %v, want undefined-rollback error", state, err)
		}
		contained, err := run.Contain(now)
		if err != nil {
			t.Fatalf("containment from %s: %v", state, err)
		}
		if contained.State() != RemediationContained {
			t.Fatalf("state = %s, want CONTAINED", contained.State())
		}
	}
	run := runInState(t, RemediationCanaryExecuting, true)
	rolling, err := run.BeginRollback(now)
	if err != nil {
		t.Fatalf("rollback with a definition: %v", err)
	}
	if rolling.State() != RemediationRollingBack || rolling.Progress().RollbackAttempt != 1 {
		t.Fatalf("state = %s attempt = %d", rolling.State(), rolling.Progress().RollbackAttempt)
	}
}

func TestRemediationRolloutAndRollbackBudgetsAreBounded(t *testing.T) {
	now := remediationInstant()
	plan := validRemediationPlan(true)
	// Two resolved targets, one of them the canary, one worker at a time: one
	// wave covers the remainder.
	if plan.MaxRolloutWaves() != 1 {
		t.Fatalf("max rollout waves = %d, want 1", plan.MaxRolloutWaves())
	}

	run, err := ReconstituteRemediationRun(plan, RemediationVerifying, 9, RemediationProgress{RolloutWave: plan.MaxRolloutWaves()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = run.BeginRollout(now)
	var budget RemediationBudgetError
	if !errors.As(err, &budget) || budget.Budget != BudgetRolloutWaves {
		t.Fatalf("err = %v, want rollout wave budget exhaustion", err)
	}

	run, err = ReconstituteRemediationRun(plan, RemediationVerifying, 9, RemediationProgress{RolloutWave: plan.MaxRolloutWaves() - 1})
	if err != nil {
		t.Fatal(err)
	}
	rolling, err := run.BeginRollout(now)
	if err != nil {
		t.Fatalf("rollout inside budget: %v", err)
	}
	if rolling.Progress().RolloutWave != plan.MaxRolloutWaves() {
		t.Fatalf("rollout wave = %d, want %d", rolling.Progress().RolloutWave, plan.MaxRolloutWaves())
	}

	run, err = ReconstituteRemediationRun(plan, RemediationVerifying, 9, RemediationProgress{RollbackAttempt: plan.MaxAttempts})
	if err != nil {
		t.Fatal(err)
	}
	_, err = run.BeginRollback(now)
	if !errors.As(err, &budget) || budget.Budget != BudgetRollbackAttempts {
		t.Fatalf("err = %v, want rollback attempt budget exhaustion", err)
	}

	// The per-stage budgets are not the only bound: the whole run has one too,
	// so canary retries plus waves plus rollbacks cannot combine into an
	// unbounded repair loop.
	run, err = ReconstituteRemediationRun(plan, RemediationVerifying, 9, RemediationProgress{TotalAttempts: MaxTotalRemediationAttempts})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.BeginRollout(now); !errors.As(err, &budget) || budget.Budget != BudgetTotalAttempts {
		t.Fatalf("err = %v, want total attempt budget exhaustion", err)
	}
	if _, err := run.BeginRollback(now); !errors.As(err, &budget) || budget.Budget != BudgetTotalAttempts {
		t.Fatalf("err = %v, want total attempt budget exhaustion", err)
	}

	if _, err := ReconstituteRemediationRun(plan, RemediationVerifying, 9, RemediationProgress{RolloutWave: plan.MaxRolloutWaves() + 1}); err == nil {
		t.Fatal("expected an out-of-budget rollout wave to be refused at reconstitution")
	}
	if _, err := ReconstituteRemediationRun(plan, RemediationVerifying, 9, RemediationProgress{TotalAttempts: MaxTotalRemediationAttempts + 1}); err == nil {
		t.Fatal("expected an out-of-budget attempt count to be refused at reconstitution")
	}
}

// TestRemediationRestartsInEveryNonTerminalState proves a crashed worker can
// reload any in-flight run without losing its bounded budgets, and that there
// is no constructor which silently refills them.
func TestRemediationRestartsInEveryNonTerminalState(t *testing.T) {
	plan := validRemediationPlan(true)
	progress := RemediationProgress{RolloutWave: 1, RollbackAttempt: 1, TotalAttempts: 2}
	for _, state := range AllRemediationStates() {
		run, err := ReconstituteRemediationRun(plan, state, 4, progress)
		if err != nil {
			t.Fatalf("reconstitute %s: %v", state, err)
		}
		if run.State() != state || run.Version() != 4 || run.Progress() != progress {
			t.Fatalf("restored run for %s lost state", state)
		}
	}
}

func TestRemediationRunLifecycleHappyPath(t *testing.T) {
	now := remediationInstant()
	run, err := NewRemediationRun(validRemediationPlan(true))
	if err != nil {
		t.Fatal(err)
	}
	if run.State() != RemediationProposed || run.Version() != 1 {
		t.Fatalf("state = %s version = %d", run.State(), run.Version())
	}
	allow := RemediationPolicyOutcome{Allowed: true, Code: "ALLOWED", PolicyID: "policy-1", PolicyVersion: 3, DecidedAt: now}

	run, err = run.BeginPolicyCheck(now)
	if err != nil {
		t.Fatal(err)
	}
	run, err = run.BeginPreflight(allow, now)
	if err != nil {
		t.Fatal(err)
	}
	run, err = run.RecordPreflight(RemediationPreflightResult{
		Preconditions:   []RemediationConditionResult{{ConditionID: "stream-stale", Result: ConditionSatisfied}},
		TargetSetDigest: run.Plan().TargetSetDigest,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if run.State() != RemediationReady {
		t.Fatalf("state = %s, want READY", run.State())
	}
	run, err = run.Dispatch(RemediationDispatchRevalidation{
		Policy: allow, Recipe: run.Plan().Recipe, RecipeExpiresAt: now.Add(time.Hour),
		TargetSetDigest: run.Plan().TargetSetDigest, RolePopulation: 8, PinnedPopulation: 8, LeaseHeld: true,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if run.State() != RemediationCanaryExecuting {
		t.Fatalf("state = %s, want CANARY_EXECUTING", run.State())
	}
	if run.Progress().TotalAttempts != 1 {
		t.Fatalf("dispatch must consume one attempt, got %d", run.Progress().TotalAttempts)
	}
	run, err = run.RecordCanaryOutcome(RemediationExecutionReport{
		Outcome: ExecutionExecuted, ExecutedTargets: []RemediationTarget{"stream-1"},
		PerTarget: []RemediationTargetOutcome{{Target: "stream-1", Outcome: ExecutionExecuted}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	run, err = run.BeginRollout(now)
	if err != nil {
		t.Fatal(err)
	}
	run, err = run.RecordRolloutOutcome(RemediationExecutionReport{
		Outcome: ExecutionExecuted, ExecutedTargets: []RemediationTarget{"stream-1", "stream-2"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	run, err = run.RecordVerification(RemediationVerification{
		Postconditions:  []RemediationConditionResult{{ConditionID: "stream-fresh", Result: ConditionSatisfied}},
		ExecutedTargets: []RemediationTarget{"stream-1", "stream-2"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if run.State() != RemediationSucceeded {
		t.Fatalf("state = %s, want SUCCEEDED", run.State())
	}
}

func TestRemediationPolicyDecisionRouting(t *testing.T) {
	now := remediationInstant()
	deny := RemediationPolicyOutcome{Code: "POLICY_REVOKED", PolicyID: "policy-1", PolicyVersion: 2, DecidedAt: now}
	allow := RemediationPolicyOutcome{Allowed: true, Code: "ALLOWED", PolicyID: "policy-1", PolicyVersion: 2, DecidedAt: now}

	run := runInState(t, RemediationPolicyCheck, true)
	blocked, err := run.RecordPolicyDecision(deny, now)
	if err != nil {
		t.Fatal(err)
	}
	if blocked.State() != RemediationPolicyBlocked {
		t.Fatalf("state = %s, want POLICY_BLOCKED", blocked.State())
	}
	if _, err := run.RecordPolicyDecision(allow, now); err == nil {
		t.Fatal("an allowing decision must not be recorded as a block")
	}
	if _, err := run.BeginPreflight(deny, now); err == nil {
		t.Fatal("preflight must require an allowing decision")
	}
	if _, err := run.BeginPreflight(RemediationPolicyOutcome{Allowed: true}, now); err == nil {
		t.Fatal("a zero-identity policy outcome must be refused")
	}
}

func TestRemediationDispatchRevalidatesEveryPrecondition(t *testing.T) {
	now := remediationInstant()
	plan := validRemediationPlan(true)
	allow := RemediationPolicyOutcome{Allowed: true, Code: "ALLOWED", PolicyID: "policy-1", PolicyVersion: 1, DecidedAt: now}
	base := RemediationDispatchRevalidation{
		Policy: allow, Recipe: plan.Recipe, RecipeExpiresAt: now.Add(time.Hour),
		TargetSetDigest: plan.TargetSetDigest, RolePopulation: 8, PinnedPopulation: 8, LeaseHeld: true,
	}
	cases := []struct {
		name   string
		mutate func(RemediationDispatchRevalidation) RemediationDispatchRevalidation
		wantTo RemediationState
	}{
		{
			name: "policy revoked between preflight and dispatch",
			mutate: func(r RemediationDispatchRevalidation) RemediationDispatchRevalidation {
				r.Policy.Allowed = false
				return r
			},
			wantTo: RemediationPolicyBlocked,
		},
		{
			name: "recipe digest altered between preflight and dispatch",
			mutate: func(r RemediationDispatchRevalidation) RemediationDispatchRevalidation {
				r.Recipe.Digest = ChecksumSHA256([]byte("tampered"))
				return r
			},
			wantTo: RemediationPreflightFailed,
		},
		{
			name: "recipe expired between preflight and dispatch",
			mutate: func(r RemediationDispatchRevalidation) RemediationDispatchRevalidation {
				r.RecipeExpiresAt = now.Add(-time.Second)
				return r
			},
			wantTo: RemediationPreflightFailed,
		},
		{
			name: "target added after proposal",
			mutate: func(r RemediationDispatchRevalidation) RemediationDispatchRevalidation {
				r.TargetSetDigest = RemediationTargetSetDigest(resolvedRemediationTargets("stream-1", "stream-2", "stream-3"))
				return r
			},
			wantTo: RemediationPreflightFailed,
		},
		{
			name: "role population inflated after preflight",
			mutate: func(r RemediationDispatchRevalidation) RemediationDispatchRevalidation {
				r.RolePopulation = 40
				return r
			},
			wantTo: RemediationPreflightFailed,
		},
		{
			name: "role population unobserved at dispatch",
			mutate: func(r RemediationDispatchRevalidation) RemediationDispatchRevalidation {
				r.RolePopulation = 0
				r.PinnedPopulation = 0
				return r
			},
			wantTo: RemediationPreflightFailed,
		},
		{
			name:   "lease lost before dispatch",
			mutate: func(r RemediationDispatchRevalidation) RemediationDispatchRevalidation { r.LeaseHeld = false; return r },
			wantTo: RemediationPreflightFailed,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			run := runInState(t, RemediationReady, true)
			advanced, err := run.Dispatch(testCase.mutate(base), now)
			if err != nil {
				t.Fatal(err)
			}
			if advanced.State() != testCase.wantTo {
				t.Fatalf("state = %s, want %s", advanced.State(), testCase.wantTo)
			}
		})
	}
	for _, state := range AllRemediationStates() {
		if state == RemediationReady {
			continue
		}
		run := runInState(t, state, true)
		if _, err := run.Dispatch(base, now); err == nil {
			t.Fatalf("dispatch from %s should be refused", state)
		}
	}
	exhausted, err := ReconstituteRemediationRun(plan, RemediationReady, 3, RemediationProgress{TotalAttempts: MaxTotalRemediationAttempts})
	if err != nil {
		t.Fatal(err)
	}
	var budget RemediationBudgetError
	if _, err := exhausted.Dispatch(base, now); !errors.As(err, &budget) || budget.Budget != BudgetTotalAttempts {
		t.Fatalf("err = %v, want total attempt budget exhaustion", err)
	}
}

func TestRemediationExecutionReportRouting(t *testing.T) {
	now := remediationInstant()
	cases := []struct {
		name         string
		report       RemediationExecutionReport
		withRollback bool
		want         RemediationState
	}{
		{name: "executed advances to verification", report: RemediationExecutionReport{Outcome: ExecutionExecuted}, withRollback: true, want: RemediationVerifying},
		{name: "unknown outcome is contained never retried", report: RemediationExecutionReport{Outcome: ExecutionUnknown}, withRollback: true, want: RemediationContained},
		{name: "lease lost after dispatch is contained", report: RemediationExecutionReport{Outcome: ExecutionExecuted, LeaseLost: true}, withRollback: true, want: RemediationContained},
		{name: "refusal fails the run", report: RemediationExecutionReport{Outcome: ExecutionRefused}, withRollback: true, want: RemediationFailed},
		{name: "failure rolls back when a rollback exists", report: RemediationExecutionReport{Outcome: ExecutionFailed}, withRollback: true, want: RemediationRollingBack},
		{name: "failure is contained without a rollback", report: RemediationExecutionReport{Outcome: ExecutionFailed}, withRollback: false, want: RemediationContained},
		{name: "timeout is contained without a rollback", report: RemediationExecutionReport{Outcome: ExecutionTimedOut}, withRollback: false, want: RemediationContained},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			run := runInState(t, RemediationCanaryExecuting, testCase.withRollback)
			advanced, err := run.RecordCanaryOutcome(testCase.report, now)
			if err != nil {
				t.Fatal(err)
			}
			if advanced.State() != testCase.want {
				t.Fatalf("state = %s, want %s", advanced.State(), testCase.want)
			}
		})
	}
	// An UNKNOWN outcome must reach containment from every executing stage, not
	// only the canary.
	for _, state := range []RemediationState{RemediationCanaryExecuting, RemediationRollingOut} {
		run := runInState(t, state, true)
		var advanced RemediationRun
		var err error
		if state == RemediationCanaryExecuting {
			advanced, err = run.RecordCanaryOutcome(RemediationExecutionReport{Outcome: ExecutionUnknown}, now)
		} else {
			advanced, err = run.RecordRolloutOutcome(RemediationExecutionReport{Outcome: ExecutionUnknown}, now)
		}
		if err != nil {
			t.Fatal(err)
		}
		if advanced.State() != RemediationContained {
			t.Fatalf("unknown outcome from %s reached %s, want CONTAINED", state, advanced.State())
		}
	}
}

func TestRemediationRollbackOutcome(t *testing.T) {
	now := remediationInstant()
	run := runInState(t, RemediationRollingBack, true)
	restored, err := run.RecordRollback(RemediationVerification{
		Postconditions: []RemediationConditionResult{{ConditionID: "schedule-restored", Result: ConditionSatisfied}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if restored.State() != RemediationRolledBack {
		t.Fatalf("state = %s, want ROLLED_BACK", restored.State())
	}
	failed, err := run.RecordRollback(RemediationVerification{
		Postconditions: []RemediationConditionResult{{ConditionID: "schedule-restored", Result: ConditionUnobserved}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if failed.State() != RemediationRollbackFailed {
		t.Fatalf("state = %s, want ROLLBACK_FAILED", failed.State())
	}
	empty, err := run.RecordRollback(RemediationVerification{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if empty.State() != RemediationRollbackFailed {
		t.Fatalf("an unverified rollback must not be recorded as rolled back, got %s", empty.State())
	}
}

func TestRemediationPreflightFailsOnDriftOrUnsatisfiedPreconditions(t *testing.T) {
	now := remediationInstant()
	plan := validRemediationPlan(true)
	cases := []struct {
		name   string
		result RemediationPreflightResult
		want   RemediationState
	}{
		{
			name:   "all preconditions satisfied",
			result: RemediationPreflightResult{Preconditions: []RemediationConditionResult{{ConditionID: "stream-stale", Result: ConditionSatisfied}}, TargetSetDigest: plan.TargetSetDigest},
			want:   RemediationReady,
		},
		{
			name:   "missing precondition",
			result: RemediationPreflightResult{TargetSetDigest: plan.TargetSetDigest},
			want:   RemediationPreflightFailed,
		},
		{
			name: "partial preconditions",
			result: RemediationPreflightResult{Preconditions: []RemediationConditionResult{
				{ConditionID: "no-active-run", Result: ConditionSatisfied},
				{ConditionID: "stream-stale", Result: ConditionUnobserved},
			}, TargetSetDigest: plan.TargetSetDigest},
			want: RemediationPreflightFailed,
		},
		{
			name:   "target drift",
			result: RemediationPreflightResult{Preconditions: []RemediationConditionResult{{ConditionID: "stream-stale", Result: ConditionSatisfied}}, TargetSetDigest: RemediationTargetSetDigest(resolvedRemediationTargets("stream-9"))},
			want:   RemediationPreflightFailed,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			run := runInState(t, RemediationPreflight, true)
			advanced, err := run.RecordPreflight(testCase.result, now)
			if err != nil {
				t.Fatal(err)
			}
			if advanced.State() != testCase.want {
				t.Fatalf("state = %s, want %s", advanced.State(), testCase.want)
			}
		})
	}
}

func TestRemediationPlanValidationBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(RemediationPlan) RemediationPlan
	}{
		{name: "unknown run identifier charset", mutate: func(p RemediationPlan) RemediationPlan { p.RunID = "run 1"; return p }},
		{name: "missing cluster", mutate: func(p RemediationPlan) RemediationPlan { p.ClusterID = ""; return p }},
		{name: "missing recipe digest", mutate: func(p RemediationPlan) RemediationPlan { p.Recipe.Digest = SHA256{}; return p }},
		{name: "rollback equals forward recipe", mutate: func(p RemediationPlan) RemediationPlan {
			p.Rollback = p.Recipe
			return p
		}},
		{name: "rollback reference without a digest", mutate: func(p RemediationPlan) RemediationPlan {
			p.Rollback.Digest = SHA256{}
			return p
		}},
		{name: "rollback reference without a version", mutate: func(p RemediationPlan) RemediationPlan {
			p.Rollback.Version = ""
			return p
		}},
		{name: "tier above the implemented maximum", mutate: func(p RemediationPlan) RemediationPlan { p.Tier = TierWorkloadContainment; return p }},
		{name: "unset tier", mutate: func(p RemediationPlan) RemediationPlan { p.Tier = TierReadOnly; return p }},
		{name: "unknown tier", mutate: func(p RemediationPlan) RemediationPlan { p.Tier = AutonomyTier(9); return p }},
		{name: "unset privilege", mutate: func(p RemediationPlan) RemediationPlan { p.Privilege = ""; return p }},
		{name: "privilege above the implemented maximum", mutate: func(p RemediationPlan) RemediationPlan {
			p.Privilege = PrivilegeClusterMutate
			return p
		}},
		{name: "assurance above the implemented maximum", mutate: func(p RemediationPlan) RemediationPlan {
			p.Assurance = AssuranceLive
			return p
		}},
		{name: "zero targets", mutate: func(p RemediationPlan) RemediationPlan {
			p.Targets = nil
			p.TargetSetDigest = RemediationTargetSetDigest(nil)
			return p
		}},
		{name: "unordered targets", mutate: func(p RemediationPlan) RemediationPlan {
			p.Targets = resolvedRemediationTargets("stream-2", "stream-1")
			return p
		}},
		{name: "duplicate targets", mutate: func(p RemediationPlan) RemediationPlan {
			p.Targets = resolvedRemediationTargets("stream-1", "stream-1")
			p.TargetSetDigest = RemediationTargetSetDigest(p.Targets)
			return p
		}},
		{name: "target from another cluster", mutate: func(p RemediationPlan) RemediationPlan {
			p.Targets[1].ClusterID = "cluster-2"
			p.TargetSetDigest = RemediationTargetSetDigest(p.Targets)
			return p
		}},
		{name: "target with an unknown source relation", mutate: func(p RemediationPlan) RemediationPlan {
			p.Targets[0].Source = "SSH"
			p.TargetSetDigest = RemediationTargetSetDigest(p.Targets)
			return p
		}},
		{name: "digest does not cover targets", mutate: func(p RemediationPlan) RemediationPlan {
			p.TargetSetDigest = ChecksumSHA256([]byte("other"))
			return p
		}},
		{name: "unordered arguments", mutate: func(p RemediationPlan) RemediationPlan {
			p.Arguments = TypedArguments{
				{Name: "requeue_reason", Type: ParameterEnum, Enum: "STALE_STREAM"},
				{Name: "priority", Type: ParameterEnum, Enum: "NORMAL"},
			}
			return p
		}},
		{name: "argument value outside the token charset", mutate: func(p RemediationPlan) RemediationPlan {
			p.Arguments[0].Enum = "NORMAL; rm -rf /"
			return p
		}},
		{name: "concurrency above maximum targets", mutate: func(p RemediationPlan) RemediationPlan { p.MaxConcurrency = 5; return p }},
		{name: "zero concurrency", mutate: func(p RemediationPlan) RemediationPlan { p.MaxConcurrency = 0; return p }},
		{name: "canary above maximum targets", mutate: func(p RemediationPlan) RemediationPlan { p.CanaryTargets = 5; return p }},
		{name: "zero canary", mutate: func(p RemediationPlan) RemediationPlan { p.CanaryTargets = 0; return p }},
		{name: "attempts above three", mutate: func(p RemediationPlan) RemediationPlan { p.MaxAttempts = 4; return p }},
		{name: "expiry before proposal", mutate: func(p RemediationPlan) RemediationPlan {
			p.ExpiresAt = p.ProposedAt.Add(-time.Second)
			return p
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := testCase.mutate(validRemediationPlan(true)).Validate(); err == nil {
				t.Fatal("expected the plan to be refused")
			}
		})
	}
	if err := validRemediationPlan(true).Validate(); err != nil {
		t.Fatalf("baseline plan: %v", err)
	}
}

func TestRemediationIdempotencyKeyIsDeterministicAndDistinguishing(t *testing.T) {
	plan := validRemediationPlan(true)
	baseInput := RemediationIdempotencyInput{
		RunID: plan.RunID, ClusterID: plan.ClusterID, Stage: RemediationStageCanary, AttemptNumber: 1,
		RecipeDigest: plan.Recipe.Digest, TargetSetDigest: plan.TargetSetDigest,
		ArgumentsDigest:  plan.Arguments.Digest(),
		WaveTargetDigest: RemediationWaveTargetDigest([]RemediationTarget{"stream-1"}),
	}
	base := RemediationIdempotencyKey(baseInput)
	if base != RemediationIdempotencyKey(baseInput) {
		t.Fatal("the same inputs must produce the same key")
	}
	if len(base) != 64 {
		t.Fatalf("key length = %d, want 64", len(base))
	}
	mutated := map[string]func(RemediationIdempotencyInput) RemediationIdempotencyInput{
		"stage": func(i RemediationIdempotencyInput) RemediationIdempotencyInput {
			i.Stage = RemediationStageRollout
			return i
		},
		"attempt": func(i RemediationIdempotencyInput) RemediationIdempotencyInput { i.AttemptNumber = 2; return i },
		"recipe": func(i RemediationIdempotencyInput) RemediationIdempotencyInput {
			i.RecipeDigest = ChecksumSHA256([]byte("other"))
			return i
		},
		"targets": func(i RemediationIdempotencyInput) RemediationIdempotencyInput {
			i.TargetSetDigest = RemediationTargetSetDigest(resolvedRemediationTargets("stream-1"))
			return i
		},
		// Without the arguments digest a mutated arguments row would reuse the
		// receipt recorded for the values that were actually authorized.
		"arguments": func(i RemediationIdempotencyInput) RemediationIdempotencyInput {
			i.ArgumentsDigest = TypedArguments{{Name: "priority", Type: ParameterEnum, Enum: "ELEVATED"}}.Digest()
			return i
		},
		// Without the wave digest two rollout waves would differ only by attempt
		// number, and nothing would stop a wave re-executing the canary.
		"wave": func(i RemediationIdempotencyInput) RemediationIdempotencyInput {
			i.WaveTargetDigest = RemediationWaveTargetDigest([]RemediationTarget{"stream-2"})
			return i
		},
		"cluster": func(i RemediationIdempotencyInput) RemediationIdempotencyInput { i.ClusterID = "cluster-2"; return i },
		"run":     func(i RemediationIdempotencyInput) RemediationIdempotencyInput { i.RunID = "run-2"; return i },
		"boundaries": func(i RemediationIdempotencyInput) RemediationIdempotencyInput {
			i.RunID = "run"
			i.ClusterID = "1cluster-1"
			return i
		},
	}
	for name, mutate := range mutated {
		if RemediationIdempotencyKey(mutate(baseInput)) == base {
			t.Fatalf("%s variant must not collide with the base key", name)
		}
	}
}

func TestRemediationTargetSetDigestCoversClusterAndRole(t *testing.T) {
	forward := RemediationTargetSetDigest(resolvedRemediationTargets("stream-1", "stream-2"))
	reversed := RemediationTargetSetDigest(resolvedRemediationTargets("stream-2", "stream-1"))
	if forward != reversed {
		t.Fatal("target-set digest must not depend on input order")
	}
	joined := RemediationTargetSetDigest(resolvedRemediationTargets("stream-1stream-2"))
	if forward == joined {
		t.Fatal("a shifted field boundary must not produce the same digest")
	}
	// A same-named stream in another cluster must not digest identically, or the
	// dispatch drift check would accept a cross-cluster substitution.
	crossCluster := resolvedRemediationTargets("stream-1", "stream-2")
	crossCluster[1].ClusterID = "cluster-2"
	if forward == RemediationTargetSetDigest(crossCluster) {
		t.Fatal("target-set digest must cover the cluster of each target")
	}
	// A role changed between preflight and dispatch must move the digest too.
	rerole := resolvedRemediationTargets("stream-1", "stream-2")
	rerole[0].Role = "SHERLOCK_SOMETHING_ELSE"
	if forward == RemediationTargetSetDigest(rerole) {
		t.Fatal("target-set digest must cover the role of each target")
	}
}

func TestRemediationAttemptDerivesItsOwnIdempotencyKeyAndWave(t *testing.T) {
	now := remediationInstant()
	plan := validRemediationPlan(true)
	wave := []RemediationTarget{"stream-1"}
	attempt, err := NewRemediationAttempt("attempt-1", plan, RemediationStageCanary, 1, wave, "worker-1", now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	expected := RemediationIdempotencyKey(RemediationIdempotencyInput{
		RunID: plan.RunID, ClusterID: plan.ClusterID, Stage: RemediationStageCanary, AttemptNumber: 1,
		RecipeDigest: plan.Recipe.Digest, TargetSetDigest: plan.TargetSetDigest,
		ArgumentsDigest: plan.Arguments.Digest(), WaveTargetDigest: RemediationWaveTargetDigest(wave),
	})
	if attempt.IdempotencyKey != expected {
		t.Fatal("attempt key must be derived from the run, its arguments and its wave")
	}
	if attempt.WaveTargetDigest != RemediationWaveTargetDigest(wave) {
		t.Fatal("attempt must carry the digest of its own wave")
	}
	if _, err := NewRemediationAttempt("attempt-2", plan, RemediationStageCanary, 3, wave, "worker-1", now, now.Add(time.Minute)); err == nil {
		t.Fatal("an attempt beyond the budget must be refused")
	}
	// A wave outside the persisted resolved set would act on a target the run
	// was never authorized for.
	if _, err := NewRemediationAttempt("attempt-3", plan, RemediationStageCanary, 1, []RemediationTarget{"stream-9"}, "worker-1", now, now.Add(time.Minute)); err == nil {
		t.Fatal("a wave target outside the resolved set must be refused")
	}
	if _, err := NewRemediationAttempt("attempt-4", plan, RemediationStageCanary, 1, nil, "worker-1", now, now.Add(time.Minute)); err == nil {
		t.Fatal("an empty wave must be refused")
	}
	forged := attempt
	forged.IdempotencyKey = "forged-key"
	if err := forged.Validate(plan); err == nil {
		t.Fatal("a supplied idempotency key must be refused")
	}
	widened := attempt
	widened.WaveTargets = []RemediationTarget{"stream-1", "stream-2"}
	if err := widened.Validate(plan); err == nil {
		t.Fatal("a wave widened after the key was derived must be refused")
	}
	if !attempt.LeaseValid("worker-1", now) || attempt.LeaseValid("worker-2", now) || attempt.LeaseValid("worker-1", now.Add(2*time.Minute)) {
		t.Fatal("lease validity must depend on owner and expiry")
	}
}

func TestRemediationReceiptRejections(t *testing.T) {
	now := remediationInstant()
	plan := validRemediationPlan(true)
	attempt, err := NewRemediationAttempt("attempt-1", plan, RemediationStageCanary, 1, []RemediationTarget{"stream-1"}, "worker-1", now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	receipt := RemediationReceipt{
		ID: "receipt-1", RunID: plan.RunID, AttemptID: attempt.ID, ClusterID: plan.ClusterID,
		IdempotencyKey: attempt.IdempotencyKey, Stage: RemediationStageCanary,
		// A canary receipt speaks only about the canary's own wave, never about
		// the whole resolved set the run will eventually cover.
		Targets:   attempt.WaveTargets,
		PerTarget: []RemediationTargetOutcome{{Target: "stream-1", Outcome: ExecutionExecuted}},
		Outcome:   ExecutionExecuted, ObservedAt: now,
	}
	receipt.Digest = receipt.ComputeDigest()
	if err := receipt.ValidateFor(attempt, "worker-1", now); err != nil {
		t.Fatalf("valid receipt: %v", err)
	}

	cases := []struct {
		name     string
		mutate   func(RemediationReceipt) RemediationReceipt
		owner    string
		at       time.Time
		wantCode string
	}{
		{
			name:   "receipt replay under another attempt",
			mutate: func(r RemediationReceipt) RemediationReceipt { r.AttemptID = "attempt-9"; return r },
			owner:  "worker-1", at: now, wantCode: ReceiptReplay,
		},
		{
			name:   "idempotency key does not match the attempt",
			mutate: func(r RemediationReceipt) RemediationReceipt { r.IdempotencyKey = "b7"; return r },
			owner:  "worker-1", at: now, wantCode: ReceiptReplay,
		},
		{
			name:   "lease owned by someone else",
			mutate: func(r RemediationReceipt) RemediationReceipt { return r },
			owner:  "worker-2", at: now, wantCode: ReceiptLeaseLost,
		},
		{
			name:   "lease expired",
			mutate: func(r RemediationReceipt) RemediationReceipt { return r },
			owner:  "worker-1", at: now.Add(2 * time.Minute), wantCode: ReceiptLeaseLost,
		},
		{
			name:   "digest does not cover the receipt",
			mutate: func(r RemediationReceipt) RemediationReceipt { r.Outcome = ExecutionFailed; return r },
			owner:  "worker-1", at: now, wantCode: ReceiptDigestFailed,
		},
		{
			name: "per-target detail altered after signing",
			mutate: func(r RemediationReceipt) RemediationReceipt {
				r.PerTarget = []RemediationTargetOutcome{{Target: "stream-1", Outcome: ExecutionFailed}}
				return r
			},
			owner: "worker-1", at: now, wantCode: ReceiptDigestFailed,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.mutate(receipt).ValidateFor(attempt, testCase.owner, testCase.at)
			var rejection RemediationReceiptRejection
			if !errors.As(err, &rejection) {
				t.Fatalf("err = %v, want a receipt rejection", err)
			}
			if rejection.Code != testCase.wantCode {
				t.Fatalf("code = %s, want %s", rejection.Code, testCase.wantCode)
			}
		})
	}
}

func TestRemediationEnumValidation(t *testing.T) {
	if err := RemediationState("SHIPPED").Validate(); err == nil {
		t.Fatal("expected an unknown state to be refused")
	}
	if err := RemediationStage("SHELL").Validate(); err == nil {
		t.Fatal("expected an unknown stage to be refused")
	}
	if err := ConditionResult("MAYBE").Validate(); err == nil {
		t.Fatal("expected an unknown condition result to be refused")
	}
	if err := ExecutionOutcome("OK").Validate(); err == nil {
		t.Fatal("expected an unknown execution outcome to be refused")
	}
	if err := AutonomyTier(5).Validate(); err == nil {
		t.Fatal("expected an unknown tier to be refused")
	}
	if err := RemediationPrivilege("ROOT").Validate(); err == nil {
		t.Fatal("expected an unknown privilege to be refused")
	}
	if err := AssuranceClass("REAL").Validate(); err == nil {
		t.Fatal("expected an unknown assurance class to be refused")
	}
	if err := TargetRole("NODE").Validate(); err == nil {
		t.Fatal("expected an unknown target role to be refused")
	}
	if err := TargetSourceRelation("SSH_HOSTS").Validate(); err == nil {
		t.Fatal("expected an unknown target source relation to be refused")
	}
	if err := ParameterType("STRING").Validate(); err == nil {
		t.Fatal("expected a free-text parameter type to be refused")
	}
	// The zero tier mutates nothing, so it is not a weaker permission but an
	// unstated one, and it must not be executable.
	for tier, implemented := range map[AutonomyTier]bool{
		TierReadOnly: false, TierSherlockOwnedRepair: true,
		TierSingleTargetMonitor: false, TierWorkloadContainment: false, TierDestructive: false,
	} {
		if tier.Implemented() != implemented {
			t.Fatalf("tier %d implemented = %v, want %v", int(tier), tier.Implemented(), implemented)
		}
	}
	for privilege, implemented := range map[RemediationPrivilege]bool{
		PrivilegeSherlockInternal: true, PrivilegeClusterRead: false, PrivilegeClusterMutate: false, "": false,
	} {
		if privilege.Implemented() != implemented {
			t.Fatalf("privilege %q implemented = %v, want %v", privilege, privilege.Implemented(), implemented)
		}
	}
	if PrivilegeSherlockInternal.Rank() >= PrivilegeClusterRead.Rank() ||
		PrivilegeClusterRead.Rank() >= PrivilegeClusterMutate.Rank() ||
		RemediationPrivilege("ROOT").Rank() <= PrivilegeClusterMutate.Rank() {
		t.Fatal("privilege ranks must be ordered and an unknown value must rank highest")
	}
	for assurance, implemented := range map[AssuranceClass]bool{
		AssuranceSimulated: true, AssuranceRecorded: false, AssuranceLive: false, "": false,
	} {
		if assurance.Implemented() != implemented {
			t.Fatalf("assurance %q implemented = %v, want %v", assurance, assurance.Implemented(), implemented)
		}
	}
}

func TestRemediationTransitionRequiresAServerInstant(t *testing.T) {
	run := runInState(t, RemediationProposed, true)
	if _, err := run.Transition(RemediationPolicyCheck, time.Time{}); err == nil {
		t.Fatal("a transition without a server-supplied instant must be refused")
	}
}

func TestRemediationPlanIsClonedAcrossTheAggregateBoundary(t *testing.T) {
	run, err := NewRemediationRun(validRemediationPlan(true))
	if err != nil {
		t.Fatal(err)
	}
	exported := run.Plan()
	exported.Targets[0].Target = "stream-hijacked"
	exported.Arguments[0].Enum = "ELEVATED"
	if run.Plan().Targets[0].Target != "stream-1" {
		t.Fatal("mutating an exported plan must not reach the aggregate")
	}
	if run.Plan().Arguments[0].Enum != "NORMAL" {
		t.Fatal("mutating exported arguments must not reach the aggregate")
	}
}

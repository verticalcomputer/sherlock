package remediation

import (
	"slices"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func policyEvidence(now time.Time) []EvidenceFact {
	return []EvidenceFact{{
		LedgerEntryID: "ledger-1", Class: EvidenceClassCollectionFreshness,
		ClusterID: "cluster-1", InvestigationID: "investigation-1",
		ObservedEnd: now.Add(-time.Minute), RecordedAt: now.Add(-time.Minute), Coverage: 100,
	}}
}

func allowingPolicyInput() PolicyInput {
	now := testInstant()
	recipe := forwardRecipe()
	rollback := rollbackRecipe()
	lastRunEnded := now.Add(-2 * time.Hour)
	return PolicyInput{
		Now:                  now,
		StateObservedAt:      now.Add(-time.Second),
		PopulationObservedAt: now.Add(-time.Second),
		Policy: StandingPolicy{
			ID: "policy-1", Version: 3, ClusterID: "cluster-1",
			RecipeID: recipe.ID, RecipeVersion: recipe.Version,
			MaxTier: domain.TierSherlockOwnedRepair, IncidentKinds: []string{IncidentKindEvidenceStreamStale},
			MaxTargets: 4, MaxConcurrentRuns: 2, Cooldown: 30 * time.Minute,
			EvidenceMaxAge: 15 * time.Minute, MinEvidenceCoverage: 100,
			RequireRollback: true,
			NotBefore:       now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		},
		Recipe:          recipe,
		RollbackRecipe:  &rollback,
		Stage:           domain.RemediationStageCanary,
		ClusterID:       "cluster-1",
		InvestigationID: "investigation-1",
		IncidentKind:    IncidentKindEvidenceStreamStale,
		ResolvedTargets: []domain.ResolvedTarget{
			{Target: "stream-1", Role: domain.RoleManagedCollectionStream, ClusterID: "cluster-1", ResolvedAt: now, Source: domain.SourceCollectionJobs},
		},
		RolePopulation:            4,
		PinnedRolePopulation:      4,
		Evidence:                  policyEvidence(now),
		ActiveRuns:                0,
		NoActiveEquivalentRun:     true,
		AttemptsUsed:              0,
		LastRunEndedAt:            &lastRunEnded,
		RemediationEnabledGlobal:  true,
		RemediationEnabledCluster: true,
	}
}

func TestEvaluateAllowsAWellFormedTier1Request(t *testing.T) {
	decision := Evaluate(allowingPolicyInput())
	if !decision.Allowed || decision.Code != PolicyAllowed {
		t.Fatalf("decision = %+v, want allowed", decision)
	}
	if decision.PolicyID != "policy-1" || decision.PolicyVersion != 3 {
		t.Fatal("decision must carry the deciding policy identity and version")
	}
	if !decision.DecidedAt.Equal(testInstant()) {
		t.Fatalf("decidedAt = %s", decision.DecidedAt)
	}
	outcome := decision.Outcome()
	if !outcome.Allowed || outcome.Code != string(PolicyAllowed) {
		t.Fatal("outcome must mirror the decision")
	}
	if err := outcome.Validate(); err != nil {
		t.Fatalf("outcome: %v", err)
	}
}

func TestPolicyWindowBudgetAllowsRemainingCapacityAndPreservesRollback(t *testing.T) {
	input := allowingPolicyInput()
	input.Policy.MaxForwardAttempts = 3
	used := 2
	input.ForwardAttemptsInWindow = &used
	if d := Evaluate(input); !d.Allowed {
		t.Fatalf("remaining reservation refused: %+v", d)
	}
	used = 3
	if d := Evaluate(input); d.Code != PolicyWindowBudgetExceeded {
		t.Fatalf("exhausted reservation: %+v", d)
	}
	input.Stage = domain.RemediationStageRollback
	if d := Evaluate(input); d.Code == PolicyWindowBudgetExceeded {
		t.Fatal("forward limit blocked rollback")
	}
}

// TestEvaluateIsDefaultDeny proves the zero input denies. With enablement
// phrased positively, the zero value of the very first check is "remediation is
// switched off" rather than "nothing has killed it yet".
func TestEvaluateIsDefaultDeny(t *testing.T) {
	decision := Evaluate(PolicyInput{})
	if decision.Allowed {
		t.Fatal("the zero policy input must deny")
	}
	if decision.Code != PolicyGlobalDisabled {
		t.Fatalf("code = %s, want %s", decision.Code, PolicyGlobalDisabled)
	}
}

// TestEvaluateDeniesOnEveryZeroedField is the per-field proof of default-deny:
// starting from an input that is allowed, zeroing any single field must change
// the answer. The two exceptions are counters of consumption, where zero is the
// strictly safer direction and is asserted to stay allowed on purpose.
func TestEvaluateDeniesOnEveryZeroedField(t *testing.T) {
	cases := []struct {
		field      string
		zero       func(PolicyInput) PolicyInput
		stillAllow bool
		wantCode   PolicyCode
	}{
		{field: "Now", zero: func(i PolicyInput) PolicyInput { i.Now = time.Time{}; return i }, wantCode: PolicyNotYetEffective},
		{field: "StateObservedAt", zero: func(i PolicyInput) PolicyInput { i.StateObservedAt = time.Time{}; return i }, wantCode: PolicyStateUnavailable},
		{field: "PopulationObservedAt", zero: func(i PolicyInput) PolicyInput { i.PopulationObservedAt = time.Time{}; return i }, wantCode: PolicyStateUnavailable},
		{field: "Policy", zero: func(i PolicyInput) PolicyInput { i.Policy = StandingPolicy{}; return i }, wantCode: PolicyNotYetEffective},
		{field: "Recipe", zero: func(i PolicyInput) PolicyInput { i.Recipe = Recipe{}; return i }, wantCode: PolicyRecipeMismatch},
		{field: "RollbackRecipe", zero: func(i PolicyInput) PolicyInput { i.RollbackRecipe = nil; return i }, wantCode: PolicyRollbackUnavailable},
		{field: "Stage", zero: func(i PolicyInput) PolicyInput { i.Stage = ""; return i }, wantCode: PolicyStageNotPermitted},
		{field: "ClusterID", zero: func(i PolicyInput) PolicyInput { i.ClusterID = ""; return i }, wantCode: PolicyClusterMismatch},
		{field: "InvestigationID", zero: func(i PolicyInput) PolicyInput { i.InvestigationID = ""; return i }, wantCode: PolicyEvidenceClusterMismatch},
		{field: "IncidentKind", zero: func(i PolicyInput) PolicyInput { i.IncidentKind = ""; return i }, wantCode: PolicyIncidentKindNotPermitted},
		{field: "ResolvedTargets", zero: func(i PolicyInput) PolicyInput { i.ResolvedTargets = nil; return i }, wantCode: PolicyTargetCountExceeded},
		{field: "RolePopulation", zero: func(i PolicyInput) PolicyInput { i.RolePopulation = 0; return i }, wantCode: PolicyBlastRadiusExceeded},
		{field: "PinnedRolePopulation", zero: func(i PolicyInput) PolicyInput { i.PinnedRolePopulation = 0; return i }, wantCode: PolicyPopulationDrift},
		{field: "Evidence", zero: func(i PolicyInput) PolicyInput { i.Evidence = nil; return i }, wantCode: PolicyEvidenceClassMissing},
		{field: "NoActiveEquivalentRun", zero: func(i PolicyInput) PolicyInput { i.NoActiveEquivalentRun = false; return i }, wantCode: PolicyActiveRunConflict},
		{field: "LastRunEndedAt", zero: func(i PolicyInput) PolicyInput { i.LastRunEndedAt = nil; return i }, wantCode: PolicyCooldownActive},
		{field: "RemediationEnabledGlobal", zero: func(i PolicyInput) PolicyInput { i.RemediationEnabledGlobal = false; return i }, wantCode: PolicyGlobalDisabled},
		{field: "RemediationEnabledCluster", zero: func(i PolicyInput) PolicyInput { i.RemediationEnabledCluster = false; return i }, wantCode: PolicyClusterDisabled},
		// ActiveRuns and AttemptsUsed count consumption. Their zero value means
		// "nothing consumed yet", which is strictly more restrictive than any
		// larger value, so it must not deny.
		{field: "ActiveRuns", zero: func(i PolicyInput) PolicyInput { i.ActiveRuns = 0; return i }, stillAllow: true},
		{field: "AttemptsUsed", zero: func(i PolicyInput) PolicyInput { i.AttemptsUsed = 0; return i }, stillAllow: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.field, func(t *testing.T) {
			decision := Evaluate(testCase.zero(allowingPolicyInput()))
			if testCase.stillAllow {
				if !decision.Allowed {
					t.Fatalf("zeroing %s denied with %s; a consumed-budget counter at zero is the safe direction", testCase.field, decision.Code)
				}
				return
			}
			if decision.Allowed {
				t.Fatalf("zeroing %s still allowed the run", testCase.field)
			}
			if decision.Code != testCase.wantCode {
				t.Fatalf("code = %s, want %s", decision.Code, testCase.wantCode)
			}
		})
	}
}

func TestEvaluateProducesEveryDenyCode(t *testing.T) {
	now := testInstant()
	revoked := now.Add(-time.Minute)
	recent := now.Add(-time.Minute)
	cases := []struct {
		name   string
		mutate func(PolicyInput) PolicyInput
		want   PolicyCode
	}{
		{name: "unobserved window budget", mutate: func(i PolicyInput) PolicyInput { i.Policy.MaxForwardAttempts = 3; return i }, want: PolicyWindowBudgetExceeded},
		{
			name:   "global remediation disabled",
			mutate: func(i PolicyInput) PolicyInput { i.RemediationEnabledGlobal = false; return i },
			want:   PolicyGlobalDisabled,
		},
		{
			name: "ambiguous policy even when selected row disabled",
			mutate: func(i PolicyInput) PolicyInput {
				i.Policy.Ambiguous = true
				i.RemediationEnabledCluster = false
				return i
			},
			want: PolicyAmbiguous,
		},
		{
			name:   "cluster remediation disabled",
			mutate: func(i PolicyInput) PolicyInput { i.RemediationEnabledCluster = false; return i },
			want:   PolicyClusterDisabled,
		},
		{
			name:   "policy revoked before dispatch",
			mutate: func(i PolicyInput) PolicyInput { i.Policy.RevokedAt = &revoked; return i },
			want:   PolicyRevoked,
		},
		{
			name:   "policy not yet effective",
			mutate: func(i PolicyInput) PolicyInput { i.Policy.NotBefore = now.Add(time.Hour); return i },
			want:   PolicyNotYetEffective,
		},
		{
			name:   "policy expired",
			mutate: func(i PolicyInput) PolicyInput { i.Policy.NotAfter = now.Add(-time.Second); return i },
			want:   PolicyExpired,
		},
		{
			name:   "observed state older than the maximum age",
			mutate: func(i PolicyInput) PolicyInput { i.StateObservedAt = now.Add(-MaxStateAge - time.Second); return i },
			want:   PolicyStateUnavailable,
		},
		{
			name:   "observed state from the future",
			mutate: func(i PolicyInput) PolicyInput { i.StateObservedAt = now.Add(time.Second); return i },
			want:   PolicyStateUnavailable,
		},
		{
			name:   "unknown stage",
			mutate: func(i PolicyInput) PolicyInput { i.Stage = "SHELL"; return i },
			want:   PolicyStageNotPermitted,
		},
		{
			name:   "policy belongs to another cluster",
			mutate: func(i PolicyInput) PolicyInput { i.Policy.ClusterID = "cluster-2"; return i },
			want:   PolicyClusterMismatch,
		},
		{
			name:   "policy names another recipe",
			mutate: func(i PolicyInput) PolicyInput { i.Policy.RecipeID = "sherlock.other"; return i },
			want:   PolicyRecipeMismatch,
		},
		{
			// The unset tier is below every ceiling, so it passes the operator's
			// limit and is caught only by the build-capability check.
			name:   "recipe tier is not implemented",
			mutate: func(i PolicyInput) PolicyInput { i.Recipe.Tier = domain.TierReadOnly; return i },
			want:   PolicyTierNotImplemented,
		},
		{
			name: "recipe tier above the policy ceiling",
			mutate: func(i PolicyInput) PolicyInput {
				i.Recipe.Tier = domain.TierWorkloadContainment
				i.Policy.MaxTier = domain.TierSherlockOwnedRepair
				return i
			},
			want: PolicyTierNotPermitted,
		},
		{
			name:   "assurance above the implemented class",
			mutate: func(i PolicyInput) PolicyInput { i.Recipe.Assurance = domain.AssuranceLive; return i },
			want:   PolicyAssuranceNotPermitted,
		},
		{
			name:   "privilege above the implemented class",
			mutate: func(i PolicyInput) PolicyInput { i.Recipe.Privilege = domain.PrivilegeClusterMutate; return i },
			want:   PolicyPrivilegeNotPermitted,
		},
		{
			name:   "recipe expired between preflight and dispatch",
			mutate: func(i PolicyInput) PolicyInput { i.Recipe.ExpiresAt = now.Add(-time.Second); return i },
			want:   PolicyRecipeExpired,
		},
		{
			name:   "incident kind not permitted",
			mutate: func(i PolicyInput) PolicyInput { i.IncidentKind = "GPU_FALLEN_OFF_THE_BUS"; return i },
			want:   PolicyIncidentKindNotPermitted,
		},
		{
			name:   "rollback required but unresolved",
			mutate: func(i PolicyInput) PolicyInput { i.RollbackRecipe = nil; return i },
			want:   PolicyRollbackUnavailable,
		},
		{
			name: "rollback outranks the forward recipe",
			mutate: func(i PolicyInput) PolicyInput {
				rollback := rollbackRecipe()
				rollback.Privilege = domain.PrivilegeClusterMutate
				i.RollbackRecipe = &rollback
				return i
			},
			want: PolicyRollbackTierExceeded,
		},
		{
			name: "rollback may touch a role the forward recipe may not",
			mutate: func(i PolicyInput) PolicyInput {
				rollback := rollbackRecipe()
				rollback.PermittedTargetRoles = []domain.TargetRole{domain.RoleManagedCollectionStream, "SHERLOCK_OTHER_ROLE"}
				i.RollbackRecipe = &rollback
				return i
			},
			want: PolicyRollbackRoleExceeded,
		},
		{
			name:   "target count above the policy ceiling",
			mutate: func(i PolicyInput) PolicyInput { i.Policy.MaxTargets = 0; return i },
			want:   PolicyTargetCountExceeded,
		},
		{
			// Counting the targets is not judging them. ResolveTargets is the only
			// correct producer of this list, and the policy core must not depend on
			// that being true of whoever assembled the input.
			name: "resolved target carrying a role the recipe does not permit",
			mutate: func(i PolicyInput) PolicyInput {
				targets := slices.Clone(i.ResolvedTargets)
				targets[0].Role = "SHERLOCK_OTHER_ROLE"
				i.ResolvedTargets = targets
				return i
			},
			want: PolicyTargetNotPermitted,
		},
		{
			name: "resolved target belonging to another cluster",
			mutate: func(i PolicyInput) PolicyInput {
				targets := slices.Clone(i.ResolvedTargets)
				targets[0].ClusterID = "cluster-2"
				i.ResolvedTargets = targets
				return i
			},
			want: PolicyClusterMismatch,
		},
		{
			name: "the same resolved target counted twice",
			mutate: func(i PolicyInput) PolicyInput {
				targets := slices.Clone(i.ResolvedTargets)
				duplicate := targets[0]
				i.ResolvedTargets = append(targets, duplicate)
				i.Policy.MaxTargets = len(i.ResolvedTargets)
				return i
			},
			want: PolicyTargetNotPermitted,
		},
		{
			name: "role population moved between preflight and dispatch",
			mutate: func(i PolicyInput) PolicyInput {
				i.RolePopulation = 40
				return i
			},
			want: PolicyPopulationDrift,
		},
		{
			name: "blast radius exceeded",
			mutate: func(i PolicyInput) PolicyInput {
				i.ResolvedTargets = append(i.ResolvedTargets, domain.ResolvedTarget{
					Target: "stream-2", Role: domain.RoleManagedCollectionStream, ClusterID: "cluster-1",
					ResolvedAt: now, Source: domain.SourceCollectionJobs,
				})
				return i
			},
			want: PolicyBlastRadiusExceeded,
		},
		{
			name:   "required evidence class absent",
			mutate: func(i PolicyInput) PolicyInput { i.Evidence[0].Class = "SOMETHING_ELSE"; return i },
			want:   PolicyEvidenceClassMissing,
		},
		{
			name:   "evidence from another cluster",
			mutate: func(i PolicyInput) PolicyInput { i.Evidence[0].ClusterID = "cluster-2"; return i },
			want:   PolicyEvidenceClusterMismatch,
		},
		{
			name:   "evidence from another investigation",
			mutate: func(i PolicyInput) PolicyInput { i.Evidence[0].InvestigationID = "investigation-2"; return i },
			want:   PolicyEvidenceClusterMismatch,
		},
		{
			name:   "evidence superseded",
			mutate: func(i PolicyInput) PolicyInput { i.Evidence[0].Superseded = true; return i },
			want:   PolicyEvidenceSuperseded,
		},
		{
			name:   "evidence stale",
			mutate: func(i PolicyInput) PolicyInput { i.Evidence[0].ObservedEnd = now.Add(-time.Hour); return i },
			want:   PolicyEvidenceStale,
		},
		{
			name:   "evidence observed in the future",
			mutate: func(i PolicyInput) PolicyInput { i.Evidence[0].ObservedEnd = now.Add(time.Minute); return i },
			want:   PolicyEvidenceStale,
		},
		{
			name:   "evidence coverage insufficient",
			mutate: func(i PolicyInput) PolicyInput { i.Evidence[0].Coverage = 40; return i },
			want:   PolicyEvidenceCoverageInsufficient,
		},
		{
			name:   "concurrency exceeded",
			mutate: func(i PolicyInput) PolicyInput { i.ActiveRuns = 2; return i },
			want:   PolicyConcurrencyExceeded,
		},
		{
			name:   "an equivalent run is already in flight",
			mutate: func(i PolicyInput) PolicyInput { i.NoActiveEquivalentRun = false; return i },
			want:   PolicyActiveRunConflict,
		},
		{
			name:   "repair budget exhausted",
			mutate: func(i PolicyInput) PolicyInput { i.AttemptsUsed = domain.MaxTotalRemediationAttempts; return i },
			want:   PolicyRepairBudgetExhausted,
		},
		{
			name:   "cooldown active",
			mutate: func(i PolicyInput) PolicyInput { i.LastRunEndedAt = &recent; return i },
			want:   PolicyCooldownActive,
		},
		{
			name: "outside every maintenance window",
			mutate: func(i PolicyInput) PolicyInput {
				i.Policy.MaintenanceWindows = []MaintenanceWindow{{Start: now.Add(time.Hour), End: now.Add(2 * time.Hour)}}
				return i
			},
			want: PolicyOutsideMaintenanceWindow,
		},
	}
	produced := map[PolicyCode]bool{PolicyAllowed: true}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			decision := Evaluate(testCase.mutate(allowingPolicyInput()))
			if decision.Allowed {
				t.Fatal("expected a denial")
			}
			if decision.Code != testCase.want {
				t.Fatalf("code = %s, want %s", decision.Code, testCase.want)
			}
			if err := decision.Code.Validate(); err != nil {
				t.Fatalf("deny code: %v", err)
			}
			produced[decision.Code] = true
		})
	}
	for _, code := range AllPolicyCodes() {
		if !produced[code] {
			t.Fatalf("deny code %s is unreachable from any tested input", code)
		}
	}
}

func TestEvaluateDeniesEveryTierAboveTheImplementedMaximum(t *testing.T) {
	for _, tier := range []domain.AutonomyTier{
		domain.TierReadOnly, domain.TierSingleTargetMonitor,
		domain.TierWorkloadContainment, domain.TierDestructive,
	} {
		input := allowingPolicyInput()
		input.Recipe.Tier = tier
		input.Policy.MaxTier = domain.TierDestructive
		decision := Evaluate(input)
		if decision.Allowed || decision.Code != PolicyTierNotImplemented {
			t.Fatalf("tier %d decision = %+v, want TIER_NOT_IMPLEMENTED", int(tier), decision)
		}
	}
}

// TestEvaluateBlastRadiusFloorsToZero covers the rule that a percentage of a
// tiny population is allowed to reach zero and deny, rather than being rounded
// up to one target.
func TestEvaluateBlastRadiusFloorsToZero(t *testing.T) {
	input := allowingPolicyInput()
	input.RolePopulation = 3
	input.PinnedRolePopulation = 3
	decision := Evaluate(input)
	if decision.Allowed || decision.Code != PolicyBlastRadiusExceeded {
		t.Fatalf("decision = %+v, want a blast-radius denial at 25%% of 3 streams", decision)
	}
	input.RolePopulation = 4
	input.PinnedRolePopulation = 4
	if !Evaluate(input).Allowed {
		t.Fatal("25% of 4 streams permits exactly one target")
	}
}

func TestEvaluateIsPureAndDeterministic(t *testing.T) {
	input := allowingPolicyInput()
	first := Evaluate(input)
	second := Evaluate(input)
	if first != second {
		t.Fatal("the same input must produce the same decision")
	}
	if len(input.ResolvedTargets) != 1 || input.RolePopulation != 4 {
		t.Fatal("evaluation must not mutate its input")
	}
}

func TestMaintenanceWindowContainment(t *testing.T) {
	now := testInstant()
	window := MaintenanceWindow{Start: now, End: now.Add(time.Hour)}
	if !window.Contains(now) {
		t.Fatal("the window is half-open and includes its start")
	}
	if window.Contains(now.Add(time.Hour)) {
		t.Fatal("the window is half-open and excludes its end")
	}
	if window.Contains(now.Add(-time.Second)) {
		t.Fatal("an instant before the window is outside it")
	}
	if (MaintenanceWindow{}).Contains(now) {
		t.Fatal("a zero window contains nothing")
	}
	if (MaintenanceWindow{Start: now.Add(time.Hour), End: now}).Contains(now) {
		t.Fatal("an inverted window contains nothing")
	}
}

func TestEvaluateHonoursTheLongerOfPolicyAndRecipeCooldown(t *testing.T) {
	now := testInstant()
	input := allowingPolicyInput()
	input.Policy.Cooldown = time.Minute
	// The recipe's own 30 minute cooldown is longer and must win.
	ended := now.Add(-10 * time.Minute)
	input.LastRunEndedAt = &ended
	decision := Evaluate(input)
	if decision.Allowed || decision.Code != PolicyCooldownActive {
		t.Fatalf("decision = %+v, want the longer cooldown to apply", decision)
	}
	ended = now.Add(-31 * time.Minute)
	input.LastRunEndedAt = &ended
	if !Evaluate(input).Allowed {
		t.Fatal("a run past both cooldowns should be permitted")
	}
}

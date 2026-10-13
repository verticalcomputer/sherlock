package remediation

import (
	"fmt"
	"slices"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// PolicyCode is the closed set of verdicts Evaluate can return. Every deny code
// is produced by at least one input in the tests, so a policy failure is always
// explainable to an operator by a single stable code.
type PolicyCode string

const (
	PolicyAllowed PolicyCode = "ALLOWED"
	// PolicyGlobalDisabled and PolicyClusterDisabled are stated as enablement
	// rather than as kill switches on purpose. A boolean named "kill switch"
	// reads as "not killed" at its zero value, so a failed read or a partially
	// populated input silently disarmed both switches at once.
	PolicyGlobalDisabled       PolicyCode = "GLOBAL_REMEDIATION_DISABLED"
	PolicyClusterDisabled      PolicyCode = "CLUSTER_REMEDIATION_DISABLED"
	PolicyAmbiguous            PolicyCode = "POLICY_SELECTION_AMBIGUOUS"
	PolicyWindowBudgetExceeded PolicyCode = "POLICY_WINDOW_BUDGET_EXCEEDED"
	PolicyRevoked              PolicyCode = "POLICY_REVOKED"
	PolicyNotYetEffective      PolicyCode = "POLICY_NOT_YET_EFFECTIVE"
	PolicyExpired              PolicyCode = "POLICY_EXPIRED"
	// PolicyStateUnavailable is returned when the observed counters that the
	// decision depends on are missing or stale. Their zero values are not
	// "nothing is running" and "the last run was long ago"; they are "nobody
	// looked", which is a denial.
	PolicyStateUnavailable             PolicyCode = "AUTHORITATIVE_STATE_UNAVAILABLE"
	PolicyStageNotPermitted            PolicyCode = "STAGE_NOT_PERMITTED"
	PolicyClusterMismatch              PolicyCode = "POLICY_CLUSTER_MISMATCH"
	PolicyRecipeMismatch               PolicyCode = "POLICY_RECIPE_MISMATCH"
	PolicyTierNotImplemented           PolicyCode = "TIER_NOT_IMPLEMENTED"
	PolicyTierNotPermitted             PolicyCode = "TIER_NOT_PERMITTED"
	PolicyAssuranceNotPermitted        PolicyCode = "ASSURANCE_NOT_PERMITTED"
	PolicyPrivilegeNotPermitted        PolicyCode = "PRIVILEGE_NOT_PERMITTED"
	PolicyRecipeExpired                PolicyCode = "RECIPE_EXPIRED"
	PolicyIncidentKindNotPermitted     PolicyCode = "INCIDENT_KIND_NOT_PERMITTED"
	PolicyRollbackUnavailable          PolicyCode = "ROLLBACK_UNAVAILABLE"
	PolicyRollbackTierExceeded         PolicyCode = "ROLLBACK_TIER_EXCEEDED"
	PolicyRollbackRoleExceeded         PolicyCode = "ROLLBACK_ROLE_EXCEEDED"
	PolicyTargetCountExceeded          PolicyCode = "TARGET_COUNT_EXCEEDED"
	PolicyTargetNotPermitted           PolicyCode = "TARGET_NOT_PERMITTED"
	PolicyPopulationDrift              PolicyCode = "POPULATION_DRIFT"
	PolicyBlastRadiusExceeded          PolicyCode = "BLAST_RADIUS_EXCEEDED"
	PolicyEvidenceClassMissing         PolicyCode = "EVIDENCE_CLASS_MISSING"
	PolicyEvidenceClusterMismatch      PolicyCode = "EVIDENCE_CLUSTER_MISMATCH"
	PolicyEvidenceSuperseded           PolicyCode = "EVIDENCE_SUPERSEDED"
	PolicyEvidenceStale                PolicyCode = "EVIDENCE_STALE"
	PolicyEvidenceCoverageInsufficient PolicyCode = "EVIDENCE_COVERAGE_INSUFFICIENT"
	PolicyConcurrencyExceeded          PolicyCode = "CONCURRENCY_EXCEEDED"
	PolicyActiveRunConflict            PolicyCode = "ACTIVE_RUN_CONFLICT"
	PolicyRepairBudgetExhausted        PolicyCode = "REPAIR_BUDGET_EXHAUSTED"
	PolicyCooldownActive               PolicyCode = "COOLDOWN_ACTIVE"
	PolicyOutsideMaintenanceWindow     PolicyCode = "OUTSIDE_MAINTENANCE_WINDOW"
)

// AllPolicyCodes lists the closed set exactly once, so a test can prove every
// code is reachable rather than trusting that the switch below is exhaustive.
func AllPolicyCodes() []PolicyCode {
	return []PolicyCode{
		PolicyAllowed, PolicyGlobalDisabled, PolicyClusterDisabled, PolicyAmbiguous, PolicyWindowBudgetExceeded, PolicyRevoked,
		PolicyNotYetEffective, PolicyExpired, PolicyStateUnavailable, PolicyStageNotPermitted,
		PolicyClusterMismatch, PolicyRecipeMismatch, PolicyTierNotImplemented, PolicyTierNotPermitted,
		PolicyAssuranceNotPermitted, PolicyPrivilegeNotPermitted, PolicyRecipeExpired,
		PolicyIncidentKindNotPermitted, PolicyRollbackUnavailable, PolicyRollbackTierExceeded,
		PolicyRollbackRoleExceeded, PolicyTargetCountExceeded, PolicyTargetNotPermitted,
		PolicyPopulationDrift,
		PolicyBlastRadiusExceeded, PolicyEvidenceClassMissing, PolicyEvidenceClusterMismatch,
		PolicyEvidenceSuperseded, PolicyEvidenceStale, PolicyEvidenceCoverageInsufficient,
		PolicyConcurrencyExceeded, PolicyActiveRunConflict, PolicyRepairBudgetExhausted,
		PolicyCooldownActive, PolicyOutsideMaintenanceWindow,
	}
}

func (c PolicyCode) Validate() error {
	if slices.Contains(AllPolicyCodes(), c) {
		return nil
	}
	return fmt.Errorf("unknown remediation policy code %q", c)
}

// MaxStateAge bounds how old the observed run counters may be. Beyond it the
// decision would be made on facts that no longer describe the cluster.
const MaxStateAge = 60 * time.Second

// MaintenanceWindow is a half-open interval [Start, End) in which remediation
// is permitted.
type MaintenanceWindow struct {
	Start time.Time
	End   time.Time
}

func (w MaintenanceWindow) Contains(instant time.Time) bool {
	if w.Start.IsZero() || w.End.IsZero() || !w.End.After(w.Start) {
		return false
	}
	return !instant.Before(w.Start) && instant.Before(w.End)
}

// EvidenceFact is one durable ledger row the decision rests on. It replaces the
// bare age and coverage scalars an earlier draft used: those let a buggy or
// hostile caller satisfy freshness by passing zeros, and made the cross-cluster
// and superseded-evidence rules impossible to test at all.
//
// The key is the ledger entry, not the evidence identifier: evidence_id is
// nullable and unique only within an investigation, while ledger_entry_id is
// the real key that citations already join on.
type EvidenceFact struct {
	LedgerEntryID   string
	Class           string
	ClusterID       domain.ClusterID
	InvestigationID domain.InvestigationID
	ObservedEnd     time.Time
	RecordedAt      time.Time
	Coverage        int
	Superseded      bool
}

// StandingPolicy is the operator-authored grant. It is versioned and revocable,
// and it is re-read inside the dispatch transaction so a revocation between
// policy check and dispatch still blocks the dispatch.
type StandingPolicy struct {
	// Ambiguous means multiple policies share the highest applicable version.
	Ambiguous           bool
	MaxForwardAttempts  int
	ID                  domain.RemediationPolicyID
	Version             int
	ClusterID           domain.ClusterID
	RecipeID            domain.RecipeID
	RecipeVersion       string
	MaxTier             domain.AutonomyTier
	IncidentKinds       []string
	MaxTargets          int
	MaxConcurrentRuns   int
	Cooldown            time.Duration
	MaintenanceWindows  []MaintenanceWindow
	EvidenceMaxAge      time.Duration
	MinEvidenceCoverage int
	RequireRollback     bool
	NotBefore           time.Time
	NotAfter            time.Time
	RevokedAt           *time.Time
}

// PolicyInput is every fact the decision depends on. Nothing is fetched inside
// Evaluate, and Now is server-causal (read from PostgreSQL by the caller), so
// the same input always produces the same decision.
//
// Every boolean is phrased so that its zero value is the safe direction, and
// every observed fact carries the instant it was observed. A field whose zero
// value would read as permission is either inverted or made a pointer.
type PolicyInput struct {
	Now                  time.Time
	StateObservedAt      time.Time
	PopulationObservedAt time.Time
	Policy               StandingPolicy
	Recipe               Recipe
	// RollbackRecipe is the resolved, digest-checked rollback definition, or nil
	// when the forward recipe declares none. Policy is evaluated before every
	// dispatch, rollback dispatches included, so the rollback's own tier,
	// privilege and role set are constrained on the path that uses them.
	RollbackRecipe            *Recipe
	Stage                     domain.RemediationStage
	ClusterID                 domain.ClusterID
	InvestigationID           domain.InvestigationID
	IncidentKind              string
	ResolvedTargets           []domain.ResolvedTarget
	RolePopulation            int
	PinnedRolePopulation      int
	Evidence                  []EvidenceFact
	ActiveRuns                int
	NoActiveEquivalentRun     bool
	AttemptsUsed              int
	ForwardAttemptsInWindow   *int
	LastRunEndedAt            *time.Time
	RemediationEnabledGlobal  bool
	RemediationEnabledCluster bool
}

type PolicyDecision struct {
	Allowed       bool
	Code          PolicyCode
	PolicyID      domain.RemediationPolicyID
	PolicyVersion int
	DecidedAt     time.Time
}

// Outcome narrows the decision to what the domain aggregate needs. The policy
// engine's own types stay outside the domain.
func (d PolicyDecision) Outcome() domain.RemediationPolicyOutcome {
	return domain.RemediationPolicyOutcome{
		Allowed: d.Allowed, Code: string(d.Code),
		PolicyID: d.PolicyID, PolicyVersion: d.PolicyVersion, DecidedAt: d.DecidedAt,
	}
}

// Evaluate is pure and total: no I/O, no clock, no goroutines, no error return.
// It is default-deny, and the checks run in a fixed order so any given input
// yields exactly one deterministic code. The zero PolicyInput denies, and so
// does an otherwise-complete input with any single field zeroed.
func Evaluate(input PolicyInput) PolicyDecision {
	decision := PolicyDecision{
		PolicyID: input.Policy.ID, PolicyVersion: input.Policy.Version, DecidedAt: input.Now.UTC(),
	}
	decision.Code = denyCode(input)
	decision.Allowed = decision.Code == PolicyAllowed
	return decision
}

func denyCode(input PolicyInput) PolicyCode {
	policy := input.Policy
	recipe := input.Recipe
	now := input.Now

	if !input.RemediationEnabledGlobal {
		return PolicyGlobalDisabled
	}
	if policy.Ambiguous {
		return PolicyAmbiguous
	}
	if !input.RemediationEnabledCluster {
		return PolicyClusterDisabled
	}
	if policy.RevokedAt != nil {
		return PolicyRevoked
	}
	// A zero Now or a policy with no start instant has never become effective.
	if now.IsZero() || policy.NotBefore.IsZero() || now.Before(policy.NotBefore) {
		return PolicyNotYetEffective
	}
	if policy.NotAfter.IsZero() || !now.Before(policy.NotAfter) {
		return PolicyExpired
	}
	if !observedRecently(input.StateObservedAt, now) || !observedRecently(input.PopulationObservedAt, now) {
		return PolicyStateUnavailable
	}
	if input.Stage.Validate() != nil {
		return PolicyStageNotPermitted
	}
	if policy.ClusterID == "" || input.ClusterID == "" || policy.ClusterID != input.ClusterID {
		return PolicyClusterMismatch
	}
	if policy.RecipeID != recipe.ID || policy.RecipeVersion != recipe.Version || recipe.ID == "" {
		return PolicyRecipeMismatch
	}
	// The operator's own ceiling is answered first, so an operator who granted
	// less than the build implements sees their own limit named rather than a
	// build-capability message that does not describe their policy.
	if recipe.Tier > policy.MaxTier {
		return PolicyTierNotPermitted
	}
	if !recipe.Tier.Implemented() || !policy.MaxTier.Implemented() {
		return PolicyTierNotImplemented
	}
	if !recipe.Assurance.Implemented() && !isCollectionRequestRecipe(recipe) {
		return PolicyAssuranceNotPermitted
	}
	if !recipe.Privilege.Implemented() {
		return PolicyPrivilegeNotPermitted
	}
	if recipe.ExpiresAt.IsZero() || !recipe.ExpiresAt.After(now) {
		return PolicyRecipeExpired
	}
	if input.IncidentKind == "" ||
		!slices.Contains(policy.IncidentKinds, input.IncidentKind) ||
		!slices.Contains(recipe.AppliesToIncidentKinds, input.IncidentKind) {
		return PolicyIncidentKindNotPermitted
	}
	if code := rollbackCode(input); code != PolicyAllowed {
		return code
	}
	targets := len(input.ResolvedTargets)
	if targets < 1 || policy.MaxTargets < 1 || targets > policy.MaxTargets || targets > recipe.MaxTargets {
		return PolicyTargetCountExceeded
	}
	// Counting the targets without inspecting them makes every guarantee about
	// cluster scope and target role rest on ResolveTargets being the only
	// producer of this list. Dispatch re-reads inventory inside its own
	// transaction, and a later reader that assembled this input from persisted
	// run rows instead would be silently authorized. Deny on the facts here too.
	if code := targetCode(input); code != PolicyAllowed {
		return code
	}
	// The numerator is pinned by the target-set digest. The denominator has to
	// be pinned too, or extra inventory rows appearing between preflight and
	// dispatch widen the absolute permitted count without changing any digest.
	if input.RolePopulation < 1 {
		return PolicyBlastRadiusExceeded
	}
	if input.PinnedRolePopulation != input.RolePopulation {
		return PolicyPopulationDrift
	}
	if targets > permittedTargetCount(input.RolePopulation, recipe, policy) {
		return PolicyBlastRadiusExceeded
	}
	if code := evidenceCode(input); code != PolicyAllowed {
		return code
	}
	if policy.MaxConcurrentRuns < 1 || input.ActiveRuns < 0 || input.ActiveRuns >= policy.MaxConcurrentRuns {
		return PolicyConcurrencyExceeded
	}
	// Two concurrent equivalent incidents must not produce two repairs. The
	// observation is phrased positively so an unpopulated input denies.
	if !input.NoActiveEquivalentRun {
		return PolicyActiveRunConflict
	}
	if input.AttemptsUsed < 0 || input.AttemptsUsed >= domain.MaxTotalRemediationAttempts {
		return PolicyRepairBudgetExhausted
	}
	if policy.MaxForwardAttempts < 0 {
		return PolicyWindowBudgetExceeded
	}
	if policy.MaxForwardAttempts > 0 && input.Stage != domain.RemediationStageRollback {
		if input.ForwardAttemptsInWindow == nil || *input.ForwardAttemptsInWindow < 0 || *input.ForwardAttemptsInWindow >= policy.MaxForwardAttempts {
			return PolicyWindowBudgetExceeded
		}
	}
	// A nil LastRunEndedAt means nobody observed the previous run's end. That is
	// not "the cooldown is long satisfied"; it is an unobserved cooldown.
	if input.LastRunEndedAt == nil {
		return PolicyCooldownActive
	}
	cooldown := policy.Cooldown
	if recipe.Cooldown > cooldown {
		cooldown = recipe.Cooldown
	}
	if !input.LastRunEndedAt.IsZero() && cooldown > 0 && now.Before(input.LastRunEndedAt.Add(cooldown)) {
		return PolicyCooldownActive
	}
	if len(policy.MaintenanceWindows) > 0 && !slices.ContainsFunc(policy.MaintenanceWindows, func(window MaintenanceWindow) bool {
		return window.Contains(now)
	}) {
		return PolicyOutsideMaintenanceWindow
	}
	return PolicyAllowed
}

// observedRecently rejects an unobserved instant, one from the future, and one
// older than MaxStateAge.
func observedRecently(observedAt, now time.Time) bool {
	if observedAt.IsZero() || observedAt.After(now) {
		return false
	}
	return now.Sub(observedAt) <= MaxStateAge
}

// rollbackCode constrains what a rollback may do relative to the forward action
// it undoes. A Tier 1 forward action with a Tier 3 rollback would let an
// operator reach further by failing than by succeeding, and a rollback able to
// touch a role the forward action could not is a forward mutation in disguise.
func rollbackCode(input PolicyInput) PolicyCode {
	rollback := input.RollbackRecipe
	if rollback == nil {
		if input.Policy.RequireRollback || input.Stage == domain.RemediationStageRollback ||
			input.Recipe.HasRollback() {
			return PolicyRollbackUnavailable
		}
		return PolicyAllowed
	}
	if !input.Recipe.HasRollback() || !rollback.Ref().Matches(input.Recipe.RollbackRecipe) {
		return PolicyRollbackUnavailable
	}
	if rollback.Tier > input.Recipe.Tier || !rollback.Tier.Implemented() ||
		rollback.Privilege.Rank() > input.Recipe.Privilege.Rank() ||
		rollback.Assurance != input.Recipe.Assurance {
		return PolicyRollbackTierExceeded
	}
	if rollback.MaxTargets > input.Recipe.MaxTargets {
		return PolicyRollbackRoleExceeded
	}
	for _, role := range rollback.PermittedTargetRoles {
		if !slices.Contains(input.Recipe.PermittedTargetRoles, role) {
			return PolicyRollbackRoleExceeded
		}
	}
	return PolicyAllowed
}

// permittedTargetCount is the smallest of the recipe ceiling, the policy
// ceiling and the blast-radius fraction of the observed population. The
// fraction floors and is never rounded up to one: a percentage of a tiny
// population must be allowed to reach zero and deny, or "25% of 3 streams"
// silently becomes "one stream".
func permittedTargetCount(population int, recipe Recipe, policy StandingPolicy) int {
	fraction := population * recipe.BlastRadiusPercent / 100
	permitted := fraction
	if recipe.MaxTargets < permitted {
		permitted = recipe.MaxTargets
	}
	if policy.MaxTargets < permitted {
		permitted = policy.MaxTargets
	}
	return permitted
}

// evidenceCode checks each declared evidence requirement against the durable
// ledger rows the caller read, deriving age from Now rather than trusting a
// supplied duration.
func evidenceCode(input PolicyInput) PolicyCode {
	for _, requirement := range input.Recipe.RequiredEvidence {
		matched := 0
		for _, fact := range input.Evidence {
			if fact.Class != requirement.Class {
				continue
			}
			if !validRemediationToken(fact.LedgerEntryID) || !validRemediationToken(fact.Class) {
				return PolicyEvidenceClassMissing
			}
			if fact.ClusterID == "" || fact.ClusterID != input.ClusterID ||
				fact.InvestigationID == "" || fact.InvestigationID != input.InvestigationID {
				return PolicyEvidenceClusterMismatch
			}
			if fact.Superseded {
				return PolicyEvidenceSuperseded
			}
			maxAge := requirement.MaxAge
			if input.Policy.EvidenceMaxAge > 0 && input.Policy.EvidenceMaxAge < maxAge {
				maxAge = input.Policy.EvidenceMaxAge
			}
			if input.Policy.EvidenceMaxAge <= 0 || fact.ObservedEnd.IsZero() ||
				fact.ObservedEnd.After(input.Now) || input.Now.Sub(fact.ObservedEnd) > maxAge {
				return PolicyEvidenceStale
			}
			minCoverage := requirement.MinCoverage
			if input.Policy.MinEvidenceCoverage > minCoverage {
				minCoverage = input.Policy.MinEvidenceCoverage
			}
			if input.Policy.MinEvidenceCoverage < 1 || input.Policy.MinEvidenceCoverage > 100 ||
				fact.Coverage < minCoverage {
				return PolicyEvidenceCoverageInsufficient
			}
			matched++
		}
		if matched == 0 {
			return PolicyEvidenceClassMissing
		}
	}
	return PolicyAllowed
}

// targetCode judges the resolved targets themselves rather than only their
// number. Every element must belong to the authenticated cluster, carry a role
// the recipe permits, be individually well-formed, and appear once.
func targetCode(input PolicyInput) PolicyCode {
	seen := make(map[domain.RemediationTarget]struct{}, len(input.ResolvedTargets))
	for _, target := range input.ResolvedTargets {
		if target.Validate() != nil {
			return PolicyTargetNotPermitted
		}
		if target.ClusterID != input.ClusterID {
			return PolicyClusterMismatch
		}
		if !slices.Contains(input.Recipe.PermittedTargetRoles, target.Role) {
			return PolicyTargetNotPermitted
		}
		if _, exists := seen[target.Target]; exists {
			return PolicyTargetNotPermitted
		}
		seen[target.Target] = struct{}{}
	}
	return PolicyAllowed
}

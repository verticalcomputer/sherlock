package domain

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"time"
)

// RemediationSchemaVersion identifies the shape of the persisted remediation
// aggregate. It is also the domain separator of the deterministic idempotency
// key, so a future schema can never collide with a v1 key.
const RemediationSchemaVersion = 1

const remediationIdempotencyDomain = "sherlock.remediation.v1"

type RemediationRunID string
type RemediationAttemptID string
type RemediationReceiptID string
type RemediationPolicyID string
type RecipeID string
type RemediationTarget string

// ValidRemediationToken validates security identifiers (actors, recipes, attempts,
// and receipts). Opaque collection-job targets use ValidRemediationTarget instead.
func ValidRemediationToken(value string) bool { return validDiagnosticToken(value) }

// AutonomyTier ranks how much authority a repair carries. The tier is
// rederived by Sherlock from the catalog recipe; a proposal never states one.
type AutonomyTier int

const (
	// TierReadOnly is investigation only: no mutation of anything.
	TierReadOnly AutonomyTier = 0
	// TierSherlockOwnedRepair is reversible and confined to resources Sherlock
	// itself owns, such as its own collection streams.
	TierSherlockOwnedRepair AutonomyTier = 1
	// TierSingleTargetMonitor repairs monitoring on a single customer target.
	TierSingleTargetMonitor AutonomyTier = 2
	// TierWorkloadContainment affects running customer workload.
	TierWorkloadContainment AutonomyTier = 3
	// TierDestructive is hard or impossible to reverse.
	TierDestructive AutonomyTier = 4
)

// MaxImplementedTier is the highest tier this build can execute. It is also the
// only tier this build can execute: TierReadOnly mutates nothing, so an unset
// tier is not a weaker permission but an unstated one, and Implemented refuses
// it rather than admitting the zero value.
const MaxImplementedTier = TierSherlockOwnedRepair

func (t AutonomyTier) Validate() error {
	switch t {
	case TierReadOnly, TierSherlockOwnedRepair, TierSingleTargetMonitor, TierWorkloadContainment, TierDestructive:
		return nil
	default:
		return fmt.Errorf("unknown autonomy tier %d", int(t))
	}
}

// Implemented reports whether this build may execute the tier at all. Only
// TierSherlockOwnedRepair qualifies: a "<= MaxImplementedTier" comparison would
// admit the unset zero tier, which no recipe ever declared on purpose.
func (t AutonomyTier) Implemented() bool { return t == MaxImplementedTier }

// RemediationPrivilege is the privilege class a repair runs with. It is
// deliberately not DiagnosticPrivilege: that enum belongs to the diagnostic
// runner path, and reusing it would imply a remote execution route M14 does not
// have. The values are ordered, so a rollback can be required to hold no more
// privilege than the forward action it undoes.
type RemediationPrivilege string

const (
	// PrivilegeSherlockInternal touches only state Sherlock itself owns.
	PrivilegeSherlockInternal RemediationPrivilege = "SHERLOCK_INTERNAL"
	// PrivilegeClusterRead reads customer cluster state.
	PrivilegeClusterRead RemediationPrivilege = "CLUSTER_READ"
	// PrivilegeClusterMutate mutates customer cluster state.
	PrivilegeClusterMutate RemediationPrivilege = "CLUSTER_MUTATE"
)

// MaxImplementedPrivilege is the only privilege class this build permits.
const MaxImplementedPrivilege = PrivilegeSherlockInternal

func (p RemediationPrivilege) Validate() error {
	switch p {
	case PrivilegeSherlockInternal, PrivilegeClusterRead, PrivilegeClusterMutate:
		return nil
	default:
		return fmt.Errorf("unknown remediation privilege %q", p)
	}
}

// Rank orders the privilege classes. An unknown value ranks above every known
// one so a comparison against it fails closed.
func (p RemediationPrivilege) Rank() int {
	switch p {
	case PrivilegeSherlockInternal:
		return 0
	case PrivilegeClusterRead:
		return 1
	case PrivilegeClusterMutate:
		return 2
	default:
		return 3
	}
}

func (p RemediationPrivilege) Implemented() bool { return p == MaxImplementedPrivilege }

// AssuranceClass records how much of the world a recipe actually touches. M14
// permits SIMULATED only; RECORDED and LIVE exist so a later milestone's
// promotion is an explicit reviewable change rather than the silent appearance
// of a new capability.
type AssuranceClass string

const (
	AssuranceSimulated AssuranceClass = "SIMULATED"
	AssuranceRecorded  AssuranceClass = "RECORDED"
	AssuranceLive      AssuranceClass = "LIVE"
)

// MaxImplementedAssurance is the strongest assurance class this build permits.
const MaxImplementedAssurance = AssuranceSimulated

func (a AssuranceClass) Validate() error {
	switch a {
	case AssuranceSimulated, AssuranceRecorded, AssuranceLive:
		return nil
	default:
		return fmt.Errorf("unknown assurance class %q", a)
	}
}

func (a AssuranceClass) Implemented() bool { return a == MaxImplementedAssurance }

// TargetRole is a closed enum of the kinds of thing a recipe may act on. M14
// contains exactly one, and it names a resource Sherlock owns rather than any
// customer host.
type TargetRole string

const RoleManagedCollectionStream TargetRole = "SHERLOCK_MANAGED_COLLECTION_STREAM"

func (r TargetRole) Validate() error {
	switch r {
	case RoleManagedCollectionStream:
		return nil
	default:
		return fmt.Errorf("unknown target role %q", r)
	}
}

// TargetSourceRelation names the durable relation a resolved target was read
// from. It is a closed enum rather than a string so a row can never claim an
// unreviewed provenance, and so provenance cannot carry free text into a log.
type TargetSourceRelation string

const SourceCollectionJobs TargetSourceRelation = "COLLECTION_JOBS"

func (s TargetSourceRelation) Validate() error {
	switch s {
	case SourceCollectionJobs:
		return nil
	default:
		return fmt.Errorf("unknown target source relation %q", s)
	}
}

// ParameterType is closed and contains no free-text member. A shell fragment,
// path, URL or credential is therefore not representable as a recipe argument.
type ParameterType string

const (
	ParameterEnum     ParameterType = "ENUM"
	ParameterInteger  ParameterType = "INTEGER"
	ParameterDuration ParameterType = "DURATION"
	ParameterBoolean  ParameterType = "BOOLEAN"
)

func (t ParameterType) Validate() error {
	switch t {
	case ParameterEnum, ParameterInteger, ParameterDuration, ParameterBoolean:
		return nil
	default:
		return fmt.Errorf("unknown parameter type %q", t)
	}
}

// TypedArgument is a parsed, bounds-checked value. Exactly one of the value
// fields is meaningful, selected by Type. There is no string member other than
// Enum, whose value must be byte-equal to a declared allowed token, so a shell
// fragment or a path has nowhere to live.
type TypedArgument struct {
	Name     string
	Type     ParameterType
	Enum     string
	Integer  int64
	Duration time.Duration
	Boolean  bool
}

func (a TypedArgument) Validate() error {
	if !ValidRemediationToken(a.Name) {
		return fmt.Errorf("remediation argument name is invalid")
	}
	if err := a.Type.Validate(); err != nil {
		return err
	}
	if a.Type == ParameterEnum && !ValidRemediationToken(a.Enum) {
		return fmt.Errorf("remediation enum argument value is invalid")
	}
	if a.Type != ParameterEnum && a.Enum != "" {
		return fmt.Errorf("remediation argument carries a value of the wrong type")
	}
	return nil
}

// TypedArguments is the admitted argument list in canonical name order.
type TypedArguments []TypedArgument

func (a TypedArguments) Lookup(name string) (TypedArgument, bool) {
	index := slices.IndexFunc(a, func(argument TypedArgument) bool { return argument.Name == name })
	if index < 0 {
		return TypedArgument{}, false
	}
	return a[index], true
}

func (a TypedArguments) Validate() error {
	previous := ""
	for _, argument := range a {
		if err := argument.Validate(); err != nil {
			return err
		}
		if argument.Name <= previous {
			return fmt.Errorf("remediation arguments must be unique and canonically ordered")
		}
		previous = argument.Name
	}
	return nil
}

// RemediationArgumentsDigest covers the canonical argument list. It enters the
// idempotency key preimage so a mutated arguments row cannot reuse a receipt
// recorded for the values that were actually authorized.
func (a TypedArguments) Digest() SHA256 {
	payload := make([]byte, 0, 64*len(a)+8)
	payload = appendRemediationField(payload, []byte("sherlock.remediation-arguments.v1"))
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(a)))
	for _, argument := range a {
		payload = appendRemediationField(payload, []byte(argument.Name))
		payload = appendRemediationField(payload, []byte(argument.Type))
		payload = appendRemediationField(payload, []byte(argument.Enum))
		payload = binary.BigEndian.AppendUint64(payload, uint64(argument.Integer))
		payload = binary.BigEndian.AppendUint64(payload, uint64(argument.Duration))
		if argument.Boolean {
			payload = binary.BigEndian.AppendUint64(payload, 1)
		} else {
			payload = binary.BigEndian.AppendUint64(payload, 0)
		}
	}
	return ChecksumSHA256(payload)
}

type RemediationState string

const (
	RemediationProposed        RemediationState = "PROPOSED"
	RemediationPolicyCheck     RemediationState = "POLICY_CHECK"
	RemediationPreflight       RemediationState = "PREFLIGHT"
	RemediationReady           RemediationState = "READY"
	RemediationCanaryExecuting RemediationState = "CANARY_EXECUTING"
	RemediationVerifying       RemediationState = "VERIFYING"
	RemediationRollingOut      RemediationState = "ROLLING_OUT"
	RemediationSucceeded       RemediationState = "SUCCEEDED"
	RemediationPolicyBlocked   RemediationState = "POLICY_BLOCKED"
	RemediationPreflightFailed RemediationState = "PREFLIGHT_FAILED"
	RemediationRollingBack     RemediationState = "ROLLING_BACK"
	RemediationRolledBack      RemediationState = "ROLLED_BACK"
	RemediationRollbackFailed  RemediationState = "ROLLBACK_FAILED"
	RemediationContained       RemediationState = "CONTAINED"
	RemediationFailed          RemediationState = "FAILED"
	RemediationCancelled       RemediationState = "CANCELLED"
	RemediationExpired         RemediationState = "EXPIRED"
)

// AllRemediationStates lists every state exactly once. Tests walk the full
// cross-product against legalRemediationTransitions so the table and the state
// set cannot drift apart.
func AllRemediationStates() []RemediationState {
	return []RemediationState{
		RemediationProposed, RemediationPolicyCheck, RemediationPreflight, RemediationReady,
		RemediationCanaryExecuting, RemediationVerifying, RemediationRollingOut, RemediationSucceeded,
		RemediationPolicyBlocked, RemediationPreflightFailed, RemediationRollingBack, RemediationRolledBack,
		RemediationRollbackFailed, RemediationContained, RemediationFailed, RemediationCancelled,
		RemediationExpired,
	}
}

func (s RemediationState) Validate() error {
	if _, known := legalRemediationTransitions[s]; known {
		return nil
	}
	return fmt.Errorf("unknown remediation state %q", s)
}

func (s RemediationState) Terminal() bool {
	successors, known := legalRemediationTransitions[s]
	return known && len(successors) == 0
}

// legalRemediationTransitions is the whole state machine as data. Nothing else
// in this file decides whether an edge exists.
//
// Three properties are enforced here rather than described in prose:
// CANCELLED and EXPIRED are reachable only before dispatch, because once a
// mutation may have happened the operator path is containment or rollback and
// never "cancel and forget"; READY re-enters failure, because a policy
// revocation or target drift discovered at the dispatch instant must block the
// dispatch rather than be discovered afterwards; and ROLLING_BACK can reach
// CONTAINED, because a rollback whose own outcome is unknown must still reach a
// definite state instead of being recorded as a clean failure.
//
// ROLLBACK_FAILED stays terminal. It already means a human must look, and an
// edge out of a terminal state would weaken the terminal invariant for no gain;
// the operator handle is the run's attention flag, not another transition.
var legalRemediationTransitions = map[RemediationState][]RemediationState{
	RemediationProposed:    {RemediationPolicyCheck, RemediationCancelled, RemediationExpired},
	RemediationPolicyCheck: {RemediationPreflight, RemediationPolicyBlocked, RemediationCancelled, RemediationExpired},
	RemediationPreflight:   {RemediationReady, RemediationPreflightFailed, RemediationCancelled, RemediationExpired},
	RemediationReady: {
		RemediationCanaryExecuting, RemediationPolicyBlocked, RemediationPreflightFailed,
		RemediationCancelled, RemediationExpired,
	},
	RemediationCanaryExecuting: {RemediationVerifying, RemediationRollingBack, RemediationContained, RemediationFailed},
	RemediationVerifying: {
		RemediationRollingOut, RemediationSucceeded, RemediationRollingBack,
		RemediationContained, RemediationFailed,
	},
	RemediationRollingOut:      {RemediationVerifying, RemediationRollingBack, RemediationContained, RemediationFailed},
	RemediationRollingBack:     {RemediationRolledBack, RemediationRollbackFailed, RemediationContained},
	RemediationSucceeded:       {},
	RemediationPolicyBlocked:   {},
	RemediationPreflightFailed: {},
	RemediationRolledBack:      {},
	RemediationRollbackFailed:  {},
	RemediationContained:       {},
	RemediationFailed:          {},
	RemediationCancelled:       {},
	RemediationExpired:         {},
}

// LegalRemediationTransitionCount is derived from the table, never written down
// twice. A test asserts the expected total against it so an edge cannot be
// added or removed without the count moving.
func LegalRemediationTransitionCount() int {
	total := 0
	for _, successors := range legalRemediationTransitions {
		total += len(successors)
	}
	return total
}

// LegalRemediationTransition reports whether the edge exists. Exported so tests
// can drive the exhaustive cross-product from the same table the code uses.
func LegalRemediationTransition(from, to RemediationState) bool {
	successors, known := legalRemediationTransitions[from]
	return known && slices.Contains(successors, to)
}

type RemediationStage string

const (
	RemediationStageCanary   RemediationStage = "CANARY"
	RemediationStageRollout  RemediationStage = "ROLLOUT"
	RemediationStageRollback RemediationStage = "ROLLBACK"
)

func (s RemediationStage) Validate() error {
	switch s {
	case RemediationStageCanary, RemediationStageRollout, RemediationStageRollback:
		return nil
	default:
		return fmt.Errorf("unknown remediation stage %q", s)
	}
}

// ConditionResult is the observed state of one pre- or postcondition.
// UNOBSERVED is deliberately distinct from UNSATISFIED: not having looked is
// not evidence that a condition holds, and neither may support success.
type ConditionResult string

const (
	ConditionSatisfied   ConditionResult = "SATISFIED"
	ConditionUnsatisfied ConditionResult = "UNSATISFIED"
	ConditionUnobserved  ConditionResult = "UNOBSERVED"
)

func (r ConditionResult) Validate() error {
	switch r {
	case ConditionSatisfied, ConditionUnsatisfied, ConditionUnobserved:
		return nil
	default:
		return fmt.Errorf("unknown condition result %q", r)
	}
}

type RemediationConditionResult struct {
	ConditionID string
	Result      ConditionResult
}

// ConditionObservation is one independently observed fact about one target. It
// is produced by querying durable relations, never by an executor describing
// its own work.
type ConditionObservation struct {
	ReadAt      time.Time
	AttemptID   RemediationAttemptID
	EvidenceID  string
	Source      string
	ConditionID string
	Target      RemediationTarget
	Result      ConditionResult
	ObservedAt  time.Time
}

// ExecutionOutcome is what an executor may claim about an attempt. It cannot
// claim success of the repair; only independent verification decides that.
type ExecutionOutcome string

const (
	ExecutionExecuted ExecutionOutcome = "EXECUTED"
	ExecutionRefused  ExecutionOutcome = "REFUSED"
	ExecutionFailed   ExecutionOutcome = "FAILED"
	ExecutionTimedOut ExecutionOutcome = "TIMED_OUT"
	// ExecutionUnknown means the mutation may or may not have happened. It is
	// never auto-retried and never treated as a failure.
	ExecutionUnknown ExecutionOutcome = "UNKNOWN"
)

func (o ExecutionOutcome) Validate() error {
	switch o {
	case ExecutionExecuted, ExecutionRefused, ExecutionFailed, ExecutionTimedOut, ExecutionUnknown:
		return nil
	default:
		return fmt.Errorf("unknown execution outcome %q", o)
	}
}

// RemediationTargetOutcome is what happened to one target. The per-target
// outcomes are persisted alongside the collapsed attempt outcome: the collapse
// is deliberately pessimistic, and a human containing a run still needs to see
// which targets actually executed.
type RemediationTargetOutcome struct {
	Target  RemediationTarget
	Outcome ExecutionOutcome
}

func (o RemediationTargetOutcome) Validate() error {
	if !ValidRemediationTarget(string(o.Target)) {
		return fmt.Errorf("remediation target outcome names an invalid target")
	}
	return o.Outcome.Validate()
}

// RemediationRecipeRef pins the exact recipe a run was authorized against.
// Every later stage re-resolves the recipe by (ID, Version) and requires the
// digest to match, so an altered catalog fails closed.
//
// The digest is a change-detection and binding device between a persisted run
// and a compiled catalog entry. It is not a trust root: anyone who can alter
// the catalog can recompute it. In M14 the trust boundary is the compiled
// source tree, and signature verification is required before any assurance
// class above SIMULATED.
type RemediationRecipeRef struct {
	ID      RecipeID
	Version string
	Digest  SHA256
}

func (r RemediationRecipeRef) IsZero() bool {
	return r.ID == "" && r.Version == "" && r.Digest == SHA256{}
}

func (r RemediationRecipeRef) Validate() error {
	if !ValidRemediationToken(string(r.ID)) || !ValidRemediationToken(r.Version) {
		return fmt.Errorf("remediation recipe identity is invalid")
	}
	if r.Digest == (SHA256{}) {
		return fmt.Errorf("remediation recipe digest is required")
	}
	return nil
}

func (r RemediationRecipeRef) Matches(other RemediationRecipeRef) bool {
	return r.ID == other.ID && r.Version == other.Version && r.Digest == other.Digest
}

// ResolvedTarget is one target the durable inventory authorized, carrying the
// relation it was read from. Resolution is a pure function of inventory rows
// and the proposal; nothing here originates from a model.
type ResolvedTarget struct {
	Target     RemediationTarget
	Role       TargetRole
	ClusterID  ClusterID
	ResolvedAt time.Time
	Source     TargetSourceRelation
}

func (t ResolvedTarget) Validate() error {
	if !ValidRemediationTarget(string(t.Target)) {
		return fmt.Errorf("resolved remediation target is invalid")
	}
	if t.ClusterID == "" {
		return fmt.Errorf("resolved remediation target must carry a cluster")
	}
	if err := t.Role.Validate(); err != nil {
		return err
	}
	if err := t.Source.Validate(); err != nil {
		return err
	}
	if t.ResolvedAt.IsZero() {
		return fmt.Errorf("resolved remediation target must carry a resolution instant")
	}
	return nil
}

// MaxRemediationTargets bounds any single run regardless of recipe.
const MaxRemediationTargets = 64

// MaxTotalRemediationAttempts bounds every stage of one run taken together, so
// canary retries plus rollout waves plus rollback attempts cannot combine into
// an unbounded repair loop.
const MaxTotalRemediationAttempts = 6

// RemediationPlan is the server-derived, fully resolved description of what a
// run may do. Nothing in it originates from a model: the proposal supplies only
// a recipe coordinate, argument values and candidate targets, and every field
// here is rederived from the compiled catalog and durable inventory.
type RemediationPlan struct {
	RunID           RemediationRunID
	ClusterID       ClusterID
	IncidentID      IncidentID
	InvestigationID InvestigationID
	ActionCardID    ActionCardID
	Recipe          RemediationRecipeRef
	// Rollback is the zero ref when no rollback recipe resolved. Entering
	// ROLLING_BACK without it is a typed error; the run is contained instead.
	// It is a full ref rather than a bare identifier so the rollback is
	// digest-pinned exactly like the forward recipe: an ID alone would let a
	// different version, with a different tier and a different role set, answer
	// to the same name.
	Rollback        RemediationRecipeRef
	Tier            AutonomyTier
	Privilege       RemediationPrivilege
	Assurance       AssuranceClass
	Targets         []ResolvedTarget
	TargetSetDigest SHA256
	Arguments       TypedArguments
	MaxTargets      int
	MaxConcurrency  int
	CanaryTargets   int
	MaxAttempts     int
	ProposedAt      time.Time
	ExpiresAt       time.Time
}

func (p RemediationPlan) HasRollback() bool { return !p.Rollback.IsZero() }

// TargetList returns the resolved targets as plain identifiers, in the same
// canonical order the target-set digest covers.
func (p RemediationPlan) TargetList() []RemediationTarget {
	targets := make([]RemediationTarget, len(p.Targets))
	for index, resolved := range p.Targets {
		targets[index] = resolved.Target
	}
	return targets
}

// MaxRolloutWaves bounds VERIFYING -> ROLLING_OUT -> VERIFYING so the cycle in
// the transition table cannot spin forever. It is the number of concurrency
// sized waves needed to cover whatever the canary did not, computed from the
// actually resolved target set rather than from the recipe's ceiling.
func (p RemediationPlan) MaxRolloutWaves() int {
	remaining := len(p.Targets) - p.CanaryTargets
	if remaining <= 0 {
		return 0
	}
	concurrency := p.MaxConcurrency
	if concurrency < 1 {
		concurrency = 1
	}
	return (remaining + concurrency - 1) / concurrency
}

func (p RemediationPlan) Validate() error {
	if !ValidRemediationToken(string(p.RunID)) || p.ClusterID == "" ||
		!ValidRemediationToken(string(p.IncidentID)) || !ValidRemediationToken(string(p.InvestigationID)) {
		return fmt.Errorf("remediation plan identifiers are invalid")
	}
	if p.ActionCardID != "" && !ValidRemediationToken(string(p.ActionCardID)) {
		return fmt.Errorf("remediation plan action card identifier is invalid")
	}
	if err := p.Recipe.Validate(); err != nil {
		return err
	}
	if !p.Rollback.IsZero() {
		if err := p.Rollback.Validate(); err != nil {
			return err
		}
		if p.Rollback.ID == p.Recipe.ID {
			return fmt.Errorf("remediation rollback recipe cannot be the forward recipe")
		}
	}
	if err := p.Tier.Validate(); err != nil {
		return err
	}
	if !p.Tier.Implemented() {
		return fmt.Errorf("remediation tier %d is not implemented", int(p.Tier))
	}
	if err := p.Privilege.Validate(); err != nil {
		return err
	}
	if !p.Privilege.Implemented() {
		return fmt.Errorf("remediation privilege %q is not permitted in this build", p.Privilege)
	}
	if err := p.Assurance.Validate(); err != nil {
		return err
	}
	if !p.Assurance.Implemented() && !(p.Assurance == AssuranceLive && p.Recipe.ID == "sherlock.evidence-collection-requeue" && p.Recipe.Version == "2.0.0" && p.Rollback.ID == "sherlock.evidence-collection-restore" && p.Rollback.Version == "2.0.0" && p.MaxTargets == 1 && p.MaxConcurrency == 1 && p.CanaryTargets == 1) {
		return fmt.Errorf("assurance class %q is not permitted in this build", p.Assurance)
	}
	if p.MaxTargets < 1 || p.MaxTargets > MaxRemediationTargets {
		return fmt.Errorf("remediation plan maximum targets must be between 1 and %d", MaxRemediationTargets)
	}
	if p.MaxConcurrency < 1 || p.MaxConcurrency > p.MaxTargets {
		return fmt.Errorf("remediation plan concurrency must be between 1 and its maximum target count")
	}
	if p.CanaryTargets < 1 || p.CanaryTargets > p.MaxTargets {
		return fmt.Errorf("remediation plan canary targets must be between 1 and the maximum target count")
	}
	if p.MaxAttempts < 1 || p.MaxAttempts > 3 {
		return fmt.Errorf("remediation plan maximum attempts must be between 1 and 3")
	}
	if len(p.Targets) < 1 || len(p.Targets) > p.MaxTargets {
		return fmt.Errorf("remediation plan must resolve between 1 and %d targets", p.MaxTargets)
	}
	previous := RemediationTarget("")
	for _, target := range p.Targets {
		if err := target.Validate(); err != nil {
			return err
		}
		if target.ClusterID != p.ClusterID {
			return fmt.Errorf("remediation plan target belongs to another cluster")
		}
		if target.Target <= previous {
			return fmt.Errorf("remediation targets must be unique and canonically ordered")
		}
		previous = target.Target
	}
	if p.TargetSetDigest != RemediationTargetSetDigest(p.Targets) {
		return fmt.Errorf("remediation target-set digest does not cover the resolved targets")
	}
	if err := p.Arguments.Validate(); err != nil {
		return err
	}
	if p.ProposedAt.IsZero() || p.ExpiresAt.IsZero() || !p.ExpiresAt.After(p.ProposedAt) {
		return fmt.Errorf("remediation plan validity interval is invalid")
	}
	return nil
}

// RemediationTargetSetDigest covers the sorted canonical target list together
// with each target's cluster and role. Name alone is not enough: a same-named
// stream in another cluster, or a role changed between preflight and dispatch,
// would otherwise produce an identical digest and pass the drift check.
func RemediationTargetSetDigest(targets []ResolvedTarget) SHA256 {
	sorted := slices.Clone(targets)
	slices.SortFunc(sorted, func(left, right ResolvedTarget) int {
		switch {
		case left.Target < right.Target:
			return -1
		case left.Target > right.Target:
			return 1
		default:
			return 0
		}
	})
	payload := make([]byte, 0, 96*len(sorted)+8)
	payload = appendRemediationField(payload, []byte("sherlock.remediation-target-set.v1"))
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(sorted)))
	for _, target := range sorted {
		payload = appendRemediationField(payload, []byte(target.ClusterID))
		payload = appendRemediationField(payload, []byte(target.Target))
		payload = appendRemediationField(payload, []byte(target.Role))
	}
	return ChecksumSHA256(payload)
}

// RemediationWaveTargetDigest covers the subset of targets one attempt acts on.
// Without it two rollout waves would differ only by attempt number, and nothing
// would stop a later wave re-executing the canary's targets.
func RemediationWaveTargetDigest(targets []RemediationTarget) SHA256 {
	sorted := slices.Clone(targets)
	slices.Sort(sorted)
	payload := make([]byte, 0, 48*len(sorted)+8)
	payload = appendRemediationField(payload, []byte("sherlock.remediation-wave.v1"))
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(sorted)))
	for _, target := range sorted {
		payload = appendRemediationField(payload, []byte(target))
	}
	return ChecksumSHA256(payload)
}

// RemediationIdempotencyInput is the full preimage of an idempotency key.
type RemediationIdempotencyInput struct {
	RunID            RemediationRunID
	ClusterID        ClusterID
	Stage            RemediationStage
	AttemptNumber    int
	RecipeDigest     SHA256
	TargetSetDigest  SHA256
	ArgumentsDigest  SHA256
	WaveTargetDigest SHA256
}

// RemediationIdempotencyKey is deterministic in run, cluster, stage, attempt,
// recipe digest, resolved target set, arguments and wave targets, so a
// duplicate dispatch after an acknowledgement loss collides on the unique index
// and returns the recorded receipt instead of mutating twice — while a changed
// argument or a different wave is a different key rather than a silent replay.
func RemediationIdempotencyKey(input RemediationIdempotencyInput) string {
	payload := make([]byte, 0, 320)
	payload = appendRemediationField(payload, []byte(remediationIdempotencyDomain))
	payload = appendRemediationField(payload, []byte(input.RunID))
	payload = appendRemediationField(payload, []byte(input.ClusterID))
	payload = appendRemediationField(payload, []byte(input.Stage))
	payload = appendRemediationField(payload, []byte(fmt.Sprintf("%d", input.AttemptNumber)))
	payload = appendRemediationField(payload, input.RecipeDigest[:])
	payload = appendRemediationField(payload, input.TargetSetDigest[:])
	payload = appendRemediationField(payload, input.ArgumentsDigest[:])
	payload = appendRemediationField(payload, input.WaveTargetDigest[:])
	digest := ChecksumSHA256(payload)
	return hex.EncodeToString(digest[:])
}

// RemediationRun is the aggregate. Its state is never assignable by a caller:
// every change flows through Transition, which consults the table above.
type RemediationRun struct {
	plan      RemediationPlan
	state     RemediationState
	version   int
	progress  RemediationProgress
	updatedAt time.Time
}

// RemediationProgress is the bounded-loop budget a run has already consumed.
// It is persisted state rather than in-memory progress: a restart that reset
// these counters would hand the run a fresh repair budget on every crash.
type RemediationProgress struct {
	RolloutWave     int
	RollbackAttempt int
	TotalAttempts   int
}

func NewRemediationRun(plan RemediationPlan) (RemediationRun, error) {
	if err := plan.Validate(); err != nil {
		return RemediationRun{}, err
	}
	return RemediationRun{plan: cloneRemediationPlan(plan), state: RemediationProposed, version: 1}, nil
}

// ReconstituteRemediationRun restores a run together with the counters that
// bound its rollout and rollback loops. There is deliberately no constructor
// that omits the progress: a caller that could leave it out would silently
// restore a run with its budgets refilled.
func ReconstituteRemediationRun(plan RemediationPlan, state RemediationState, version int, progress RemediationProgress) (RemediationRun, error) {
	if err := plan.Validate(); err != nil {
		return RemediationRun{}, err
	}
	if err := state.Validate(); err != nil {
		return RemediationRun{}, err
	}
	if version < 1 {
		return RemediationRun{}, fmt.Errorf("remediation run version must be positive")
	}
	if progress.RolloutWave < 0 || progress.RolloutWave > plan.MaxRolloutWaves() {
		return RemediationRun{}, fmt.Errorf("remediation rollout wave is outside its budget")
	}
	if progress.RollbackAttempt < 0 || progress.RollbackAttempt > plan.MaxAttempts {
		return RemediationRun{}, fmt.Errorf("remediation rollback attempt is outside its budget")
	}
	if progress.TotalAttempts < 0 || progress.TotalAttempts > MaxTotalRemediationAttempts {
		return RemediationRun{}, fmt.Errorf("remediation attempt budget is outside its bound")
	}
	return RemediationRun{
		plan: cloneRemediationPlan(plan), state: state, version: version, progress: progress,
	}, nil
}

func (r RemediationRun) Plan() RemediationPlan         { return cloneRemediationPlan(r.plan) }
func (r RemediationRun) State() RemediationState       { return r.state }
func (r RemediationRun) Version() int                  { return r.version }
func (r RemediationRun) Progress() RemediationProgress { return r.progress }
func (r RemediationRun) UpdatedAt() time.Time          { return r.updatedAt }

// Transition is the single choke point for state change. Intent-named methods
// add their own preconditions and then call it; nothing bypasses it.
func (r RemediationRun) Transition(to RemediationState, now time.Time) (RemediationRun, error) {
	if err := to.Validate(); err != nil {
		return RemediationRun{}, err
	}
	if now.IsZero() {
		return RemediationRun{}, fmt.Errorf("remediation transition requires a server-supplied instant")
	}
	if !LegalRemediationTransition(r.state, to) {
		return RemediationRun{}, transitionConflict("transition remediation run to "+string(to), string(r.state))
	}
	// Transitions are ordered by server-causal time. Accepting an instant
	// earlier than the previous transition would let a reconstructed history
	// disagree with the order the transitions actually committed in.
	if !r.updatedAt.IsZero() && now.UTC().Before(r.updatedAt) {
		return RemediationRun{}, fmt.Errorf("remediation transition instant precedes the previous transition")
	}
	r.state = to
	r.version++
	r.updatedAt = now.UTC()
	return r, nil
}

// RemediationPolicyOutcome is the domain-visible summary of a policy
// evaluation. The policy engine lives outside the domain; only its verdict,
// identity and code cross the boundary.
type RemediationPolicyOutcome struct {
	Allowed       bool
	Code          string
	PolicyID      RemediationPolicyID
	PolicyVersion int
	DecidedAt     time.Time
}

func (o RemediationPolicyOutcome) Validate() error {
	if !ValidRemediationToken(string(o.PolicyID)) || o.PolicyVersion < 1 {
		return fmt.Errorf("remediation policy identity is invalid")
	}
	if !ValidRemediationToken(o.Code) {
		return fmt.Errorf("remediation policy code is invalid")
	}
	if o.DecidedAt.IsZero() {
		return fmt.Errorf("remediation policy decision instant is required")
	}
	return nil
}

func (r RemediationRun) BeginPolicyCheck(now time.Time) (RemediationRun, error) {
	return r.Transition(RemediationPolicyCheck, now)
}

// RecordPolicyDecision records a denial. An allowing decision advances through
// BeginPreflight instead, so a caller cannot accidentally treat an unchecked
// zero-valued decision as permission to proceed.
func (r RemediationRun) RecordPolicyDecision(outcome RemediationPolicyOutcome, now time.Time) (RemediationRun, error) {
	if err := outcome.Validate(); err != nil {
		return RemediationRun{}, err
	}
	if outcome.Allowed {
		return RemediationRun{}, fmt.Errorf("an allowing policy decision advances a remediation run through preflight")
	}
	return r.Transition(RemediationPolicyBlocked, now)
}

func (r RemediationRun) BeginPreflight(outcome RemediationPolicyOutcome, now time.Time) (RemediationRun, error) {
	if err := outcome.Validate(); err != nil {
		return RemediationRun{}, err
	}
	if !outcome.Allowed {
		return RemediationRun{}, fmt.Errorf("remediation preflight requires an allowing policy decision")
	}
	return r.Transition(RemediationPreflight, now)
}

// RemediationPreflightResult is the observed outcome of preflight: the
// precondition results and the target set actually resolved from inventory.
type RemediationPreflightResult struct {
	Preconditions   []RemediationConditionResult
	TargetSetDigest SHA256
	FailureCode     string
}

func (r RemediationRun) RecordPreflight(result RemediationPreflightResult, now time.Time) (RemediationRun, error) {
	if err := validateConditionResults(result.Preconditions); err != nil {
		return RemediationRun{}, err
	}
	satisfied := len(result.Preconditions) > 0
	for _, condition := range result.Preconditions {
		if condition.Result != ConditionSatisfied {
			satisfied = false
		}
	}
	if !satisfied || result.TargetSetDigest != r.plan.TargetSetDigest {
		return r.Transition(RemediationPreflightFailed, now)
	}
	return r.Transition(RemediationReady, now)
}

// RemediationDispatchRevalidation is the set of facts re-read inside the
// dispatch transaction. A run never dispatches on a decision older than the
// dispatch instant, so policy, recipe expiry, target set, role population and
// lease are all checked again here.
type RemediationDispatchRevalidation struct {
	Policy           RemediationPolicyOutcome
	Recipe           RemediationRecipeRef
	RecipeExpiresAt  time.Time
	TargetSetDigest  SHA256
	RolePopulation   int
	PinnedPopulation int
	LeaseHeld        bool
}

func (r RemediationRun) Dispatch(revalidation RemediationDispatchRevalidation, now time.Time) (RemediationRun, error) {
	if err := revalidation.Policy.Validate(); err != nil {
		return RemediationRun{}, err
	}
	if now.IsZero() {
		return RemediationRun{}, fmt.Errorf("remediation dispatch requires a server-supplied instant")
	}
	if r.state != RemediationReady {
		return RemediationRun{}, transitionConflict("dispatch remediation run", string(r.state))
	}
	if r.progress.TotalAttempts >= MaxTotalRemediationAttempts {
		return RemediationRun{}, RemediationBudgetError{Budget: BudgetTotalAttempts}
	}
	// Expiry has to bind here, not only in whatever sweeper is supposed to move
	// expired runs along. EXPIRED being pre-dispatch-only by the transition
	// table means nothing if a run that outlived its plan can still dispatch
	// because the sweeper lost a race.
	if !r.plan.ExpiresAt.IsZero() && !now.Before(r.plan.ExpiresAt) {
		return r.Transition(RemediationExpired, now)
	}
	if !revalidation.Policy.Allowed {
		return r.Transition(RemediationPolicyBlocked, now)
	}
	if !revalidation.Recipe.Matches(r.plan.Recipe) {
		return r.Transition(RemediationPreflightFailed, now)
	}
	if revalidation.RecipeExpiresAt.IsZero() || !revalidation.RecipeExpiresAt.After(now) {
		return r.Transition(RemediationPreflightFailed, now)
	}
	if revalidation.TargetSetDigest != r.plan.TargetSetDigest {
		return r.Transition(RemediationPreflightFailed, now)
	}
	// The numerator is pinned by the target-set digest; the denominator has to
	// be pinned separately, or extra inventory rows appearing between preflight
	// and dispatch widen the absolute permitted count without changing a digest.
	if revalidation.RolePopulation < 1 || revalidation.RolePopulation != revalidation.PinnedPopulation {
		return r.Transition(RemediationPreflightFailed, now)
	}
	if !revalidation.LeaseHeld {
		return r.Transition(RemediationPreflightFailed, now)
	}
	dispatched, err := r.Transition(RemediationCanaryExecuting, now)
	if err != nil {
		return RemediationRun{}, err
	}
	dispatched.progress.TotalAttempts++
	return dispatched, nil
}

// RemediationExecutionReport is what an attempt reports back. It states what
// the executor observed about its own call, never whether the repair worked.
type RemediationExecutionReport struct {
	Outcome         ExecutionOutcome
	LeaseLost       bool
	ExecutedTargets []RemediationTarget
	PerTarget       []RemediationTargetOutcome
}

func (report RemediationExecutionReport) Validate() error {
	if err := report.Outcome.Validate(); err != nil {
		return err
	}
	previous := RemediationTarget("")
	for _, target := range report.ExecutedTargets {
		if !ValidRemediationTarget(string(target)) {
			return fmt.Errorf("executed remediation target is invalid")
		}
		if target <= previous {
			return fmt.Errorf("executed remediation targets must be unique and canonically ordered")
		}
		previous = target
	}
	for _, outcome := range report.PerTarget {
		if err := outcome.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (report RemediationExecutionReport) validateAgainstPlan(plan RemediationPlan) error {
	resolved := plan.TargetList()
	for _, target := range report.ExecutedTargets {
		if !slices.Contains(resolved, target) {
			return fmt.Errorf("executed remediation target is not in the resolved target set")
		}
	}
	for _, outcome := range report.PerTarget {
		if !slices.Contains(resolved, outcome.Target) {
			return fmt.Errorf("reported remediation target is not in the resolved target set")
		}
	}
	return nil
}

// recordExecutionReport maps one attempt's report onto the state machine.
// Losing the lease after dispatch means the mutation's outcome is unknown, so
// the run is contained rather than retried or declared successful. An UNKNOWN
// outcome is treated identically: containment means a human must look, which is
// the only correct response to an ambiguous mutation.
func (r RemediationRun) recordExecutionReport(report RemediationExecutionReport, now time.Time) (RemediationRun, error) {
	if err := report.Validate(); err != nil {
		return RemediationRun{}, err
	}
	// A report may only speak about targets the plan resolved. Coverage equality
	// already guards SUCCEEDED, but an unresolved target here would still steer
	// containment and rollback routing and would reach the receipt.
	if err := report.validateAgainstPlan(r.plan); err != nil {
		return RemediationRun{}, err
	}
	if report.LeaseLost || report.Outcome == ExecutionUnknown {
		return r.Transition(RemediationContained, now)
	}
	switch report.Outcome {
	case ExecutionExecuted:
		return r.Transition(RemediationVerifying, now)
	case ExecutionRefused:
		return r.Transition(RemediationFailed, now)
	default:
		if r.plan.HasRollback() {
			return r.BeginRollback(now)
		}
		return r.Transition(RemediationContained, now)
	}
}

func (r RemediationRun) RecordCanaryOutcome(report RemediationExecutionReport, now time.Time) (RemediationRun, error) {
	if r.state != RemediationCanaryExecuting {
		return RemediationRun{}, transitionConflict("record remediation canary outcome", string(r.state))
	}
	return r.recordExecutionReport(report, now)
}

func (r RemediationRun) RecordRolloutOutcome(report RemediationExecutionReport, now time.Time) (RemediationRun, error) {
	if r.state != RemediationRollingOut {
		return RemediationRun{}, transitionConflict("record remediation rollout outcome", string(r.state))
	}
	return r.recordExecutionReport(report, now)
}

// RecordRollbackExecution maps a rollback attempt's own execution report onto
// the state machine, before any verification. An unknown rollback outcome or a
// lost lease reaches CONTAINED rather than being recorded as a clean rollback
// failure: "the undo may or may not have happened" is a different fact from
// "the undo failed", and only the first requires a human to establish the truth.
func (r RemediationRun) RecordRollbackExecution(report RemediationExecutionReport, now time.Time) (RemediationRun, error) {
	if r.state != RemediationRollingBack {
		return RemediationRun{}, transitionConflict("record remediation rollback execution", string(r.state))
	}
	if err := report.Validate(); err != nil {
		return RemediationRun{}, err
	}
	if report.LeaseLost || report.Outcome == ExecutionUnknown {
		return r.Transition(RemediationContained, now)
	}
	if report.Outcome != ExecutionExecuted {
		return r.Transition(RemediationRollbackFailed, now)
	}
	// An executed rollback still has to be verified independently, so the run
	// stays in ROLLING_BACK until RecordRollback observes the restoration.
	return r, nil
}

// RemediationVerification is an independent observation of the postconditions
// plus the target set actually executed. It is never assembled from an
// executor's own claim of success.
type RemediationVerification struct {
	Postconditions  []RemediationConditionResult
	ExecutedTargets []RemediationTarget
}

// RemediationVerificationError explains why SUCCEEDED was refused. Its code is
// a closed set so tests can assert the exact reason.
type RemediationVerificationError struct {
	Code string
}

func (e RemediationVerificationError) Error() string {
	return fmt.Sprintf("remediation verification is insufficient for success: %s", e.Code)
}

const (
	VerificationPostconditionsMissing = "POSTCONDITIONS_MISSING"
	VerificationUnsatisfied           = "POSTCONDITION_UNSATISFIED"
	VerificationUnobserved            = "POSTCONDITION_UNOBSERVED"
	VerificationCoverageIncomplete    = "TARGET_COVERAGE_INCOMPLETE"
)

// RecordVerification is the only path to SUCCEEDED. Success requires every
// declared postcondition to have been observed and satisfied and the executed
// target set to equal the resolved target set exactly. A postcondition nobody
// looked at is not satisfied, and a partially covered target set is a rollout
// in progress, not a success.
func (r RemediationRun) RecordVerification(verification RemediationVerification, now time.Time) (RemediationRun, error) {
	if r.state != RemediationVerifying {
		return RemediationRun{}, transitionConflict("record remediation verification", string(r.state))
	}
	if err := validateConditionResults(verification.Postconditions); err != nil {
		return RemediationRun{}, err
	}
	if len(verification.Postconditions) == 0 {
		return RemediationRun{}, RemediationVerificationError{Code: VerificationPostconditionsMissing}
	}
	for _, condition := range verification.Postconditions {
		switch condition.Result {
		case ConditionUnsatisfied:
			return RemediationRun{}, RemediationVerificationError{Code: VerificationUnsatisfied}
		case ConditionUnobserved:
			return RemediationRun{}, RemediationVerificationError{Code: VerificationUnobserved}
		}
	}
	executed := slices.Clone(verification.ExecutedTargets)
	slices.Sort(executed)
	executed = slices.Compact(executed)
	if !slices.Equal(executed, r.plan.TargetList()) {
		return RemediationRun{}, RemediationVerificationError{Code: VerificationCoverageIncomplete}
	}
	return r.Transition(RemediationSucceeded, now)
}

// RemediationBudgetError reports an exhausted bounded loop. Budget is a closed
// set of names so the exact bound that stopped the run is assertable.
type RemediationBudgetError struct {
	Budget string
}

func (e RemediationBudgetError) Error() string {
	return fmt.Sprintf("remediation budget %s is exhausted", e.Budget)
}

const (
	BudgetRolloutWaves     = "ROLLOUT_WAVES"
	BudgetRollbackAttempts = "ROLLBACK_ATTEMPTS"
	BudgetTotalAttempts    = "TOTAL_ATTEMPTS"
)

// NextRolloutWave returns the targets the next rollout wave should cover: the
// resolved targets that carry no executed receipt yet, in canonical order,
// capped at the plan's concurrency.
//
// The canary already covered the first CanaryTargets, so this is what remains.
// Selecting by "not yet executed" rather than by wave index means a wave can
// never re-execute a target, however the waves were interleaved or retried.
func (plan RemediationPlan) NextRolloutWave(executed []RemediationTarget) []RemediationTarget {
	concurrency := plan.MaxConcurrency
	if concurrency < 1 {
		concurrency = 1
	}
	remaining := make([]RemediationTarget, 0, concurrency)
	for _, target := range plan.TargetList() {
		if slices.Contains(executed, target) {
			continue
		}
		remaining = append(remaining, target)
		if len(remaining) == concurrency {
			break
		}
	}
	return remaining
}

// BeginRollout consumes one wave of the bounded rollout budget so the
// VERIFYING -> ROLLING_OUT -> VERIFYING cycle terminates.
func (r RemediationRun) BeginRollout(now time.Time) (RemediationRun, error) {
	if r.state != RemediationVerifying {
		return RemediationRun{}, transitionConflict("begin remediation rollout", string(r.state))
	}
	if r.progress.RolloutWave >= r.plan.MaxRolloutWaves() {
		return RemediationRun{}, RemediationBudgetError{Budget: BudgetRolloutWaves}
	}
	if r.progress.TotalAttempts >= MaxTotalRemediationAttempts {
		return RemediationRun{}, RemediationBudgetError{Budget: BudgetTotalAttempts}
	}
	advanced, err := r.Transition(RemediationRollingOut, now)
	if err != nil {
		return RemediationRun{}, err
	}
	advanced.progress.RolloutWave++
	advanced.progress.TotalAttempts++
	return advanced, nil
}

// RemediationRollbackUndefinedError is returned when a run would enter
// ROLLING_BACK with no resolved rollback recipe. The run must be contained
// instead: attempting an undefined rollback is worse than admitting the state
// is unknown.
type RemediationRollbackUndefinedError struct {
	RunID RemediationRunID
}

func (e RemediationRollbackUndefinedError) Error() string {
	return "remediation run has no resolved rollback recipe"
}

func (r RemediationRun) BeginRollback(now time.Time) (RemediationRun, error) {
	if !r.plan.HasRollback() {
		return RemediationRun{}, RemediationRollbackUndefinedError{RunID: r.plan.RunID}
	}
	if r.progress.RollbackAttempt >= r.plan.MaxAttempts {
		return RemediationRun{}, RemediationBudgetError{Budget: BudgetRollbackAttempts}
	}
	if r.progress.TotalAttempts >= MaxTotalRemediationAttempts {
		return RemediationRun{}, RemediationBudgetError{Budget: BudgetTotalAttempts}
	}
	advanced := r
	if r.state != RemediationRollingBack {
		var err error
		advanced, err = r.Transition(RemediationRollingBack, now)
		if err != nil {
			return RemediationRun{}, err
		}
	} else {
		advanced.version++
		advanced.updatedAt = now
	}
	advanced.progress.RollbackAttempt++
	advanced.progress.TotalAttempts++
	return advanced, nil
}

// RecordRollback closes out a rollback attempt on independently observed
// verification. A failed rollback is terminal and requires a human; it never
// loops back into execution.
func (r RemediationRun) RecordRollback(verification RemediationVerification, now time.Time) (RemediationRun, error) {
	if r.state != RemediationRollingBack {
		return RemediationRun{}, transitionConflict("record remediation rollback", string(r.state))
	}
	if err := validateConditionResults(verification.Postconditions); err != nil {
		return RemediationRun{}, err
	}
	restored := len(verification.Postconditions) > 0
	for _, condition := range verification.Postconditions {
		if condition.Result != ConditionSatisfied {
			restored = false
		}
	}
	if !restored {
		return r.Transition(RemediationRollbackFailed, now)
	}
	return r.Transition(RemediationRolledBack, now)
}

// Contain parks a run whose effect on the world is unknown or unsafe to undo.
func (r RemediationRun) Contain(now time.Time) (RemediationRun, error) {
	return r.Transition(RemediationContained, now)
}

func (r RemediationRun) Fail(now time.Time) (RemediationRun, error) {
	return r.Transition(RemediationFailed, now)
}

// Cancel is pre-dispatch only; the transition table makes it unreachable from
// every executing state.
func (r RemediationRun) Cancel(now time.Time) (RemediationRun, error) {
	return r.Transition(RemediationCancelled, now)
}

// Expire is pre-dispatch only, for the same reason as Cancel.
func (r RemediationRun) Expire(now time.Time) (RemediationRun, error) {
	return r.Transition(RemediationExpired, now)
}

// RemediationAttempt is one leased execution of one stage of a run, acting on
// one wave of the resolved target set.
type RemediationAttempt struct {
	ID               RemediationAttemptID
	RunID            RemediationRunID
	ClusterID        ClusterID
	AttemptNumber    int
	Stage            RemediationStage
	WaveTargets      []RemediationTarget
	WaveTargetDigest SHA256
	IdempotencyKey   string
	LeaseOwner       string
	LeaseExpiresAt   time.Time
	CreatedAt        time.Time
}

// NewRemediationAttempt derives the idempotency key rather than accepting one,
// so a caller cannot weaken duplicate-suppression by supplying its own.
func NewRemediationAttempt(id RemediationAttemptID, plan RemediationPlan, stage RemediationStage, attemptNumber int, waveTargets []RemediationTarget, leaseOwner string, createdAt, leaseExpiresAt time.Time) (RemediationAttempt, error) {
	wave := slices.Clone(waveTargets)
	slices.Sort(wave)
	attempt := RemediationAttempt{
		ID: id, RunID: plan.RunID, ClusterID: plan.ClusterID, AttemptNumber: attemptNumber,
		Stage: stage, WaveTargets: wave, WaveTargetDigest: RemediationWaveTargetDigest(wave),
		LeaseOwner: leaseOwner, CreatedAt: createdAt, LeaseExpiresAt: leaseExpiresAt,
	}
	attempt.IdempotencyKey = RemediationIdempotencyKey(attempt.idempotencyInput(plan))
	if err := attempt.Validate(plan); err != nil {
		return RemediationAttempt{}, err
	}
	return attempt, nil
}

// idempotencyInput pins the digest of the recipe this attempt actually runs.
// A rollback attempt runs the rollback recipe, so keying it on the forward
// digest would make two different rollback definitions collide and let a
// receipt recorded for one be replayed for the other.
func (a RemediationAttempt) idempotencyInput(plan RemediationPlan) RemediationIdempotencyInput {
	recipeDigest := plan.Recipe.Digest
	if a.Stage == RemediationStageRollback {
		recipeDigest = plan.Rollback.Digest
	}
	return RemediationIdempotencyInput{
		RunID: plan.RunID, ClusterID: plan.ClusterID, Stage: a.Stage, AttemptNumber: a.AttemptNumber,
		RecipeDigest: recipeDigest, TargetSetDigest: plan.TargetSetDigest,
		ArgumentsDigest: plan.Arguments.Digest(), WaveTargetDigest: a.WaveTargetDigest,
	}
}

func (a RemediationAttempt) Validate(plan RemediationPlan) error {
	if !ValidRemediationToken(string(a.ID)) || !ValidRemediationToken(a.LeaseOwner) {
		return fmt.Errorf("remediation attempt identity is invalid")
	}
	if a.RunID != plan.RunID || a.ClusterID != plan.ClusterID {
		return fmt.Errorf("remediation attempt does not belong to its run")
	}
	if err := a.Stage.Validate(); err != nil {
		return err
	}
	if a.AttemptNumber < 1 || a.AttemptNumber > plan.MaxAttempts {
		return fmt.Errorf("remediation attempt number is outside the permitted budget")
	}
	// A wave that is not a subset of the persisted resolved set would let an
	// attempt act on a target the run was never authorized for.
	resolved := plan.TargetList()
	if len(a.WaveTargets) < 1 || len(a.WaveTargets) > len(resolved) {
		return fmt.Errorf("remediation attempt wave must name between 1 and the resolved target count")
	}
	previous := RemediationTarget("")
	for _, target := range a.WaveTargets {
		if !slices.Contains(resolved, target) {
			return fmt.Errorf("remediation attempt wave target is not in the resolved target set")
		}
		if target <= previous {
			return fmt.Errorf("remediation attempt wave targets must be unique and canonically ordered")
		}
		previous = target
	}
	if a.WaveTargetDigest != RemediationWaveTargetDigest(a.WaveTargets) {
		return fmt.Errorf("remediation attempt wave digest does not cover its targets")
	}
	if !ValidRemediationToken(a.IdempotencyKey) {
		return fmt.Errorf("remediation attempt idempotency key is invalid")
	}
	if a.IdempotencyKey != RemediationIdempotencyKey(a.idempotencyInput(plan)) {
		return fmt.Errorf("remediation attempt idempotency key is not derived from its run")
	}
	if a.CreatedAt.IsZero() || a.LeaseExpiresAt.IsZero() || !a.LeaseExpiresAt.After(a.CreatedAt) {
		return fmt.Errorf("remediation attempt lease interval is invalid")
	}
	return nil
}

// LeaseValid reports whether the named owner still holds the attempt at now.
func (a RemediationAttempt) LeaseValid(owner string, now time.Time) bool {
	return a.LeaseOwner == owner && a.LeaseExpiresAt.After(now)
}

// RemediationReceipt is an immutable, append-only record of one attempt's
// observed outcome, including the per-target detail. The collapsed outcome is
// pessimistic by design, so the per-target rows are what let a human see which
// targets actually executed before the run was contained.
type RemediationReceipt struct {
	ID             RemediationReceiptID
	RunID          RemediationRunID
	AttemptID      RemediationAttemptID
	ClusterID      ClusterID
	IdempotencyKey string
	Stage          RemediationStage
	Targets        []RemediationTarget
	PerTarget      []RemediationTargetOutcome
	Outcome        ExecutionOutcome
	ObservedAt     time.Time
	Digest         SHA256
}

// RemediationReceiptRejection names why a receipt was refused. RECEIPT_REPLAY
// and LEASE_LOST are distinct because they demand different operator responses.
type RemediationReceiptRejection struct {
	Code string
}

func (e RemediationReceiptRejection) Error() string {
	return fmt.Sprintf("remediation receipt rejected: %s", e.Code)
}

const (
	ReceiptReplay       = "RECEIPT_REPLAY"
	ReceiptLeaseLost    = "LEASE_LOST"
	ReceiptDigestFailed = "RECEIPT_DIGEST_MISMATCH"
	// ReceiptTimeImplausible marks an observation instant that precedes its own
	// attempt or postdates the reader.
	ReceiptTimeImplausible = "RECEIPT_TIME_IMPLAUSIBLE"
	// ReceiptTargetNotDispatched marks a receipt speaking about a target its
	// attempt was never dispatched against.
	ReceiptTargetNotDispatched = "RECEIPT_TARGET_NOT_DISPATCHED"
)

// CanonicalBytes encodes every receipt field except Digest with length-prefixed
// segments, so no two distinct receipts share an encoding.
func (r RemediationReceipt) CanonicalBytes() []byte {
	payload := make([]byte, 0, 256)
	payload = appendRemediationField(payload, []byte("sherlock.remediation-receipt.v1"))
	payload = appendRemediationField(payload, []byte(r.ID))
	payload = appendRemediationField(payload, []byte(r.RunID))
	payload = appendRemediationField(payload, []byte(r.AttemptID))
	payload = appendRemediationField(payload, []byte(r.ClusterID))
	payload = appendRemediationField(payload, []byte(r.IdempotencyKey))
	payload = appendRemediationField(payload, []byte(r.Stage))
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(r.Targets)))
	for _, target := range r.Targets {
		payload = appendRemediationField(payload, []byte(target))
	}
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(r.PerTarget)))
	for _, outcome := range r.PerTarget {
		payload = appendRemediationField(payload, []byte(outcome.Target))
		payload = appendRemediationField(payload, []byte(outcome.Outcome))
	}
	payload = appendRemediationField(payload, []byte(r.Outcome))
	payload = binary.BigEndian.AppendUint64(payload, uint64(r.ObservedAt.UTC().UnixNano()))
	return payload
}

func (r RemediationReceipt) ComputeDigest() SHA256 { return ChecksumSHA256(r.CanonicalBytes()) }

// ValidateFor refuses a receipt that does not belong to its attempt, that
// replays another attempt's idempotency key, or that arrives from an owner who
// no longer holds the lease.
func (r RemediationReceipt) ValidateFor(attempt RemediationAttempt, leaseOwner string, now time.Time) error {
	if !ValidRemediationToken(string(r.ID)) {
		return fmt.Errorf("remediation receipt identity is invalid")
	}
	if err := r.Outcome.Validate(); err != nil {
		return err
	}
	for _, outcome := range r.PerTarget {
		if err := outcome.Validate(); err != nil {
			return err
		}
	}
	if r.RunID != attempt.RunID || r.AttemptID != attempt.ID || r.ClusterID != attempt.ClusterID || r.Stage != attempt.Stage {
		return RemediationReceiptRejection{Code: ReceiptReplay}
	}
	if r.IdempotencyKey != attempt.IdempotencyKey {
		return RemediationReceiptRejection{Code: ReceiptReplay}
	}
	if !attempt.LeaseValid(leaseOwner, now) {
		return RemediationReceiptRejection{Code: ReceiptLeaseLost}
	}
	if r.ObservedAt.IsZero() {
		return fmt.Errorf("remediation receipt observation instant is required")
	}
	// An observation cannot precede the attempt that produced it or postdate the
	// instant we are reading it at. The write path overwrites this with database
	// time, but the domain must not accept an implausible instant in the
	// meantime: it is the field an operator reads when reconstructing what
	// happened, and a receipt is immutable once accepted.
	if r.ObservedAt.Before(attempt.CreatedAt) || r.ObservedAt.After(now) {
		return RemediationReceiptRejection{Code: ReceiptTimeImplausible}
	}
	// A receipt may only speak about the targets its attempt was dispatched
	// against. Per-target rows drive containment routing and later supply the
	// executed set a rollback is authorized against, so a receipt naming an
	// untouched target would widen a rollback's reach.
	if err := validateReceiptTargets(r, attempt); err != nil {
		return err
	}
	if r.Digest != r.ComputeDigest() {
		return RemediationReceiptRejection{Code: ReceiptDigestFailed}
	}
	return nil
}

func validateReceiptTargets(r RemediationReceipt, attempt RemediationAttempt) error {
	previous := RemediationTarget("")
	for index, target := range r.Targets {
		if index > 0 && target <= previous {
			return fmt.Errorf("remediation receipt targets must be unique and canonically ordered")
		}
		previous = target
		if !slices.Contains(attempt.WaveTargets, target) {
			return RemediationReceiptRejection{Code: ReceiptTargetNotDispatched}
		}
	}
	for _, outcome := range r.PerTarget {
		if !slices.Contains(attempt.WaveTargets, outcome.Target) {
			return RemediationReceiptRejection{Code: ReceiptTargetNotDispatched}
		}
	}
	return nil
}

func validateConditionResults(results []RemediationConditionResult) error {
	previous := ""
	for _, condition := range results {
		if !ValidRemediationToken(condition.ConditionID) {
			return fmt.Errorf("remediation condition identifier is invalid")
		}
		if condition.ConditionID <= previous {
			return fmt.Errorf("remediation condition results must be unique and canonically ordered")
		}
		previous = condition.ConditionID
		if err := condition.Result.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func cloneRemediationPlan(plan RemediationPlan) RemediationPlan {
	plan.Targets = slices.Clone(plan.Targets)
	plan.Arguments = slices.Clone(plan.Arguments)
	plan.ProposedAt = plan.ProposedAt.UTC()
	plan.ExpiresAt = plan.ExpiresAt.UTC()
	return plan
}

// appendRemediationField writes one length-prefixed segment. A fixed-width
// length prefix, rather than a delimiter, is what makes the encoding
// unambiguous: no shift of a field boundary can produce identical bytes.
func appendRemediationField(into, field []byte) []byte {
	into = binary.BigEndian.AppendUint32(into, uint32(len(field)))
	return append(into, field...)
}

// RecipeOperation is the entire executable vocabulary of the system. There is
// deliberately no operation value meaning "run this string": adding one is a
// reviewed code change, and a model can never introduce one.
//
// It lives in the domain rather than beside the recipe schema because the
// execution unit carries it, and the application layer must be able to name an
// execution without importing an adapter package.
type RecipeOperation string

const (
	OperationEvidenceCollectionRequeue RecipeOperation = "SHERLOCK_EVIDENCE_COLLECTION_REQUEUE"
	OperationEvidenceCollectionRestore RecipeOperation = "SHERLOCK_EVIDENCE_COLLECTION_RESTORE"
)

func (o RecipeOperation) Validate() error {
	switch o {
	case OperationEvidenceCollectionRequeue, OperationEvidenceCollectionRestore:
		return nil
	default:
		return fmt.Errorf("unknown recipe operation %q", o)
	}
}

// ExecutionUnit is everything an executor is told. By type it carries no
// command, path, environment, credential or free text: Operation is a member of
// a closed enum, Arguments are already parsed and bounds-checked, and Targets
// were resolved from durable inventory. There is no field an executor could
// interpret as something to run.
type ExecutionUnit struct {
	Recipe         RemediationRecipeRef
	RunID          RemediationRunID
	AttemptID      RemediationAttemptID
	ClusterID      ClusterID
	Operation      RecipeOperation
	Arguments      TypedArguments
	Targets        []ResolvedTarget
	Stage          RemediationStage
	IdempotencyKey string
	Deadline       time.Time
}

func (u ExecutionUnit) Validate() error {
	if !ValidRemediationToken(string(u.RunID)) || !ValidRemediationToken(string(u.AttemptID)) || u.ClusterID == "" {
		return fmt.Errorf("execution unit identity is invalid")
	}
	if err := u.Operation.Validate(); err != nil {
		return err
	}
	if err := u.Stage.Validate(); err != nil {
		return err
	}
	if !ValidRemediationToken(u.IdempotencyKey) {
		return fmt.Errorf("execution unit idempotency key is invalid")
	}
	if err := u.Arguments.Validate(); err != nil {
		return err
	}
	if len(u.Targets) < 1 || len(u.Targets) > MaxRemediationTargets {
		return fmt.Errorf("execution unit must name between 1 and %d targets", MaxRemediationTargets)
	}
	for _, target := range u.Targets {
		if err := target.Validate(); err != nil {
			return err
		}
		if target.ClusterID != u.ClusterID {
			return fmt.Errorf("execution unit target belongs to another cluster")
		}
	}
	if u.Deadline.IsZero() {
		return fmt.Errorf("execution unit deadline is required")
	}
	return nil
}

// ExecutionResult is the executor's report about its own call. It cannot claim
// the repair worked: verification is an independent observation elsewhere.
//
// It carries closed enums and an instant, and nothing else. A message string or
// an output buffer here would recreate the untrusted-output-to-log path the
// coding standard forbids, and would give a compromised executor a channel into
// operator screens and model context.
type ExecutionResult struct {
	Outcome    ExecutionOutcome
	PerTarget  []RemediationTargetOutcome
	ObservedAt time.Time
}

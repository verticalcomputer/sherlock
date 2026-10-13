package application

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediation"
)

var (
	ErrRemediationNotFound     = errors.New("remediation run not found")
	ErrRemediationConflict     = errors.New("remediation state conflicts with the requested operation")
	ErrRemediationForbidden    = errors.New("remediation action is forbidden")
	ErrRemediationLeaseInvalid = errors.New("remediation lease is invalid")
	// ErrRemediationPlanUnauthorized is returned when a plan describes something
	// the compiled catalog would not itself authorize. It is distinct from a
	// policy denial: a policy denial means an operator said no, while this means
	// the plan and the catalog disagree about what the recipe is.
	ErrRemediationPlanUnauthorized = errors.New("remediation plan is not authorized by the compiled catalog")
	// ErrRemediationExecutorUnsafe refuses construction against an executor that
	// does not report the SIMULATED assurance class.
	ErrRemediationExecutorUnsafe = errors.New("remediation executor does not report the SIMULATED assurance class")
)

// RemediationDeniedError carries the closed policy or rejection code that
// stopped a run, so a caller can assert the exact reason without parsing a
// message. It never echoes an offending value.
type RemediationDeniedError struct {
	Code string
}

func (e RemediationDeniedError) Error() string {
	return fmt.Sprintf("remediation denied: %s", e.Code)
}

// RemediationExecutor is the entire mutation surface of the system, declared
// here at its consumer and matching DiagnosticExecutor.
//
// Assurance is part of the port rather than a property of one adapter:
// NewRemediationService refuses to construct unless the bound executor reports
// SIMULATED, so wiring cannot substitute a different implementation for the
// injectable port and silently obtain a live path.
type RemediationExecutor interface {
	Execute(ctx context.Context, unit domain.ExecutionUnit, now time.Time) (domain.ExecutionResult, error)
	Assurance() domain.AssuranceClass
}

type RemediationAuthorizationAction string

const (
	RemediationActionPropose  RemediationAuthorizationAction = "PROPOSE"
	RemediationActionDispatch RemediationAuthorizationAction = "DISPATCH"
	RemediationActionRollback RemediationAuthorizationAction = "ROLLBACK"
	RemediationActionContain  RemediationAuthorizationAction = "CONTAIN"
	RemediationActionCancel   RemediationAuthorizationAction = "CANCEL"
)

// RemediationAuthorizationRequest describes the concrete action, the
// authenticated cluster, the entity and the privilege class. Capability
// checking lives here, where a real principal exists, rather than inside the
// pure policy core.
type RemediationAuthorizationRequest struct {
	Action    RemediationAuthorizationAction
	ActorID   string
	ClusterID domain.ClusterID
	RunID     domain.RemediationRunID
	Recipe    domain.RemediationRecipeRef
	Tier      domain.AutonomyTier
	Privilege domain.RemediationPrivilege
	Stage     domain.RemediationStage
	Targets   []domain.RemediationTarget
}

type RemediationAuthorizationDecision struct {
	Allowed    bool
	ReasonCode string
}

type RemediationAuthorizer interface {
	AuthorizeRemediation(context.Context, RemediationAuthorizationRequest) (RemediationAuthorizationDecision, error)
}

type RemediationAuditKind string

const (
	RemediationAuditProposal      RemediationAuditKind = "PROPOSAL"
	RemediationAuditPolicy        RemediationAuditKind = "POLICY_DECISION"
	RemediationAuditPreflight     RemediationAuditKind = "PREFLIGHT"
	RemediationAuditDispatch      RemediationAuditKind = "DISPATCH"
	RemediationAuditReceipt       RemediationAuditKind = "RECEIPT"
	RemediationAuditVerification  RemediationAuditKind = "VERIFICATION"
	RemediationAuditRollback      RemediationAuditKind = "ROLLBACK"
	RemediationAuditContainment   RemediationAuditKind = "CONTAINMENT"
	RemediationAuditCancellation  RemediationAuditKind = "CANCELLATION"
	RemediationAuditExpiry        RemediationAuditKind = "EXPIRY"
	remediationAuditOutcomeOK                          = "ALLOWED"
	remediationAuditOutcomeDenied                      = "DENIED"
)

// RemediationAuditEvent records who, what, where, when and the outcome. It
// carries bounded attribution and closed codes only: no argument value, no
// rationale and no executor output has a field here.
type RemediationAuditEvent struct {
	EventID         string
	Kind            RemediationAuditKind
	ClusterID       domain.ClusterID
	RunID           domain.RemediationRunID
	AttemptID       domain.RemediationAttemptID
	ActorID         string
	Outcome         string
	ReasonCode      string
	OccurredAt      time.Time
	RecipeDigest    domain.SHA256
	TargetSetDigest domain.SHA256
}

// RemediationRecipeRecord is the audit-only recipe reference written on first
// use. It is never read back to authorize anything.
type RemediationRecipeRecord struct {
	Ref       domain.RemediationRecipeRef
	Tier      domain.AutonomyTier
	Operation string
	ExpiresAt time.Time
}

// RemediationConditionPhase names which set of conditions a result belongs to.
type RemediationConditionPhase string

const (
	RemediationPhasePreflight      RemediationConditionPhase = "PREFLIGHT"
	RemediationPhaseVerify         RemediationConditionPhase = "VERIFY"
	RemediationPhaseRollbackVerify RemediationConditionPhase = "ROLLBACK_VERIFY"
)

// RemediationObservationSource is the durable relation an observation was read
// from. It is a closed enum so a persisted result can never claim an unreviewed
// provenance, and so provenance cannot carry free text into a log.
type RemediationObservationSource string

const (
	RemediationObservedFromCollectionRuns RemediationObservationSource = "COLLECTION_RUNS"
	RemediationObservedFromCollectionJobs RemediationObservationSource = "COLLECTION_JOBS"
)

type RemediationConditionRecord struct {
	ConditionID string
	Result      domain.ConditionResult
	Source      RemediationObservationSource
}

// RemediationPolicyRecord is the decision that authorized a write. The decision
// instant is deliberately absent: the database sets it with clock_timestamp(),
// and a caller-supplied value is ignored.
type RemediationPolicyRecord struct {
	PolicyID domain.RemediationPolicyID
	Version  int
	Code     string
}

// RemediationStageAttempts is how many attempts one stage has already consumed.
// It is a slice rather than a map so the application API stays free of
// unordered, untyped containers.
type RemediationStageAttempts struct {
	Stage domain.RemediationStage
	Used  int
}

// LoadedRemediationRun is the run reconstructed entirely from durable rows,
// together with the facts a later stage must not take from a request field.
type LoadedRemediationRun struct {
	LatestAttemptID  domain.RemediationAttemptID
	LatestStage      domain.RemediationStage
	LatestTargets    []domain.RemediationTarget
	LatestReceipt    bool
	WaveVerified     bool
	Run              domain.RemediationRun
	PinnedPopulation int
	// ExecutedTargets are the targets that carry an EXECUTED receipt. A rollback
	// may touch nothing else: undoing a target that was never mutated is an
	// unreviewed forward action, not a safe no-op.
	ExecutedTargets []domain.RemediationTarget
	LedgerEntryIDs  []string
	StageAttempts   []RemediationStageAttempts
	DeadlineAt      time.Time
	ContainedReason string
}

// Attempts reports how many attempts a stage has consumed.
func (loaded LoadedRemediationRun) Attempts(stage domain.RemediationStage) int {
	index := slices.IndexFunc(loaded.StageAttempts, func(entry RemediationStageAttempts) bool {
		return entry.Stage == stage
	})
	if index < 0 {
		return 0
	}
	return loaded.StageAttempts[index].Used
}

type CreateRemediationRunInput struct {
	Run              domain.RemediationRun
	Recipe           RemediationRecipeRecord
	Rollback         *RemediationRecipeRecord
	PinnedPopulation int
	LedgerEntryIDs   []string
	DeadlineAt       time.Time
}

// RemediationTransition is one non-dispatch state change plus the observed
// evidence that justified it.
type RemediationTransition struct {
	Observations      []domain.ConditionObservation
	ClusterID         domain.ClusterID
	Run               domain.RemediationRun
	ExpectedVersion   int
	Phase             RemediationConditionPhase
	Conditions        []RemediationConditionRecord
	Policy            *RemediationPolicyRecord
	AttemptNumber     int
	ContainedReason   string
	AttentionRequired bool
	NextAttemptAt     time.Time
	DeadlineAt        time.Time
}

// RemediationDispatchInput is transaction 2 of the transaction contract. The
// lease token travels here in plaintext and is hashed at the store boundary; it
// is never persisted, never logged, and never placed in an error.
type RemediationDispatchInput struct {
	Recipe           remediation.Recipe
	RollbackRecipe   *remediation.Recipe
	ClusterID        domain.ClusterID
	Run              domain.RemediationRun
	ExpectedVersion  int
	Attempt          domain.RemediationAttempt
	LeaseToken       string
	MaxLeaseLifetime time.Duration
	Policy           RemediationPolicyRecord
	PinnedPopulation int
	TargetSetDigest  domain.SHA256
	DeadlineAt       time.Time
}

type RemediationReceiptInput struct {
	ClusterID         domain.ClusterID
	AttemptID         domain.RemediationAttemptID
	LeaseToken        string
	Receipt           domain.RemediationReceipt
	Run               domain.RemediationRun
	ExpectedVersion   int
	ContainedReason   string
	AttentionRequired bool
}

type RemediationReceiptOutcome struct {
	Receipt            domain.RemediationReceipt
	Run                domain.RemediationRun
	PreviouslyRecorded bool
}

// RemediationRunStore owns the three transaction boundaries. The executor is
// never called inside any of them.
type RemediationRunStore interface {
	// CreateRemediationRun writes the run, its resolved targets, its typed
	// arguments, its cited ledger entries, the audit-only recipe references and
	// the audit event in one transaction. An equivalent run that is still
	// non-terminal collides on the active-repair index and is reported as a
	// conflict rather than becoming a second repair.
	CreateRemediationRun(context.Context, CreateRemediationRunInput, RemediationAuditEvent) (domain.RemediationRun, bool, error)
	LoadRemediationRun(context.Context, domain.ClusterID, domain.RemediationRunID) (LoadedRemediationRun, bool, error)
	RecordRemediationTransition(context.Context, RemediationTransition, RemediationAuditEvent) error
	// DispatchRemediationAttempt commits before Executor.Execute is called. A
	// crash after Execute must not leave a mutation with no durable attempt row,
	// or authority is later reconstructed as "never dispatched".
	DispatchRemediationAttempt(context.Context, RemediationDispatchInput, RemediationAuditEvent) (domain.RemediationAttempt, error)
	RecordRemediationReceipt(context.Context, RemediationReceiptInput, RemediationAuditEvent) (RemediationReceiptOutcome, error)
}

// RemediationFactQuery names the run whose authorizing facts are wanted. Every
// answer is read from durable rows at one server-causal instant.
type RemediationFactQuery struct {
	ClusterID       domain.ClusterID
	IncidentID      domain.IncidentID
	InvestigationID domain.InvestigationID
	RunID           domain.RemediationRunID
	RecipeID        domain.RecipeID
	RecipeVersion   string
	TargetSetDigest domain.SHA256
}

// RemediationFacts is everything a policy decision rests on, read together so a
// decision is never assembled from instants that disagree.
type RemediationFacts struct {
	Now                     time.Time
	StateObservedAt         time.Time
	PopulationObservedAt    time.Time
	EnabledGlobal           bool
	EnabledCluster          bool
	Policy                  remediation.StandingPolicy
	IncidentKind            string
	Inventory               []remediation.InventoryRow
	Evidence                []remediation.EvidenceFact
	ActiveRuns              int
	NoActiveEquivalentRun   bool
	LastRunEndedAt          *time.Time
	ForwardAttemptsInWindow *int
}

type RemediationObservationQuery struct {
	AttemptID  domain.RemediationAttemptID
	Simulation bool
	ClusterID  domain.ClusterID
	RunID      domain.RemediationRunID
	Targets    []domain.RemediationTarget
	Window     time.Duration
	Conditions []string
}

type RemediationFactStore interface {
	ReadRemediationFacts(context.Context, RemediationFactQuery) (RemediationFacts, error)
	// ReadRemediationObservations answers postconditions from collection_runs and
	// preconditions from collection_jobs. Verification is an independent
	// observation; the executor never asserts it.
	ReadRemediationObservations(context.Context, RemediationObservationQuery) ([]domain.ConditionObservation, error)
}

// MaxRemediationLease bounds a single lease grant, and MaxRemediationLeaseLifetime
// bounds the total span renewals may cover, so a lease cannot be extended
// indefinitely by a holder that keeps renewing it.
const (
	MaxRemediationLease         = 5 * time.Minute
	MaxRemediationLeaseLifetime = 30 * time.Minute
)

// ResolveRemediationRecipes re-resolves both the forward reference and the
// rollback reference through the compiled catalog and returns the definitions
// the references name.
//
// The rollback is resolved here rather than trusted from the caller because
// only Recipe.Validate enforces the rollback containment relation — tier,
// privilege, role subset, target ceiling and assurance. A plan that carried an
// arbitrary rollback reference would otherwise satisfy its own well-formedness
// check and turn a Tier 1 repair into an escalation on the failure path.
func ResolveRemediationRecipes(catalog *remediation.Catalog, forwardRef, rollbackRef domain.RemediationRecipeRef, now time.Time) (remediation.Recipe, *remediation.Recipe, error) {
	if catalog == nil || !catalog.ExecutableAt(now) {
		return remediation.Recipe{}, nil, ErrRemediationPlanUnauthorized
	}
	forward, err := catalog.Resolve(forwardRef)
	if err != nil {
		return remediation.Recipe{}, nil, fmt.Errorf("%w: %v", ErrRemediationPlanUnauthorized, err)
	}
	var rollback *remediation.Recipe
	switch {
	case rollbackRef.IsZero() && forward.HasRollback():
		// Dropping the rollback the catalog declares would let a run reach
		// ROLLING_BACK with nothing to run, or dispatch a forward mutation that
		// policy believed was reversible.
		return remediation.Recipe{}, nil, ErrRemediationPlanUnauthorized
	case rollbackRef.IsZero():
	default:
		// The rollback a run pins must be exactly the rollback the forward recipe
		// declares. Any other reference is a rollback nobody validated against
		// this forward action.
		if !forward.HasRollback() || !forward.RollbackRecipe.Matches(rollbackRef) {
			return remediation.Recipe{}, nil, ErrRemediationPlanUnauthorized
		}
		resolved, err := catalog.ResolveRollback(forward)
		if err != nil {
			return remediation.Recipe{}, nil, fmt.Errorf("%w: %v", ErrRemediationPlanUnauthorized, err)
		}
		rollback = &resolved
	}
	// Validate with the resolved rollback in hand: this is the check that
	// enforces the whole containment relation between the two definitions.
	if err := forward.Validate(now, rollback); err != nil {
		return remediation.Recipe{}, nil, fmt.Errorf("%w: %v", ErrRemediationPlanUnauthorized, err)
	}
	return forward, rollback, nil
}

// AuthorizeRemediationPlan refuses any plan whose derived authority does not
// come from the catalog definition it names. It is called on the construction
// path and again at every later stage, so a persisted plan can never carry a
// tier, privilege, ceiling, role or rollback the catalog would reject.
func AuthorizeRemediationPlan(catalog *remediation.Catalog, plan domain.RemediationPlan, now time.Time) (remediation.Recipe, *remediation.Recipe, error) {
	if err := plan.Validate(); err != nil {
		return remediation.Recipe{}, nil, fmt.Errorf("%w: %v", ErrRemediationPlanUnauthorized, err)
	}
	forward, rollback, err := ResolveRemediationRecipes(catalog, plan.Recipe, plan.Rollback, now)
	if err != nil {
		return remediation.Recipe{}, nil, err
	}
	if plan.Tier != forward.Tier || plan.Privilege != forward.Privilege || plan.Assurance != forward.Assurance ||
		plan.MaxTargets != forward.MaxTargets || plan.MaxConcurrency != forward.MaxConcurrency ||
		plan.CanaryTargets != forward.CanaryTargets || plan.MaxAttempts != forward.MaxAttempts {
		return remediation.Recipe{}, nil, ErrRemediationPlanUnauthorized
	}
	for _, target := range plan.Targets {
		if !slices.Contains(forward.PermittedTargetRoles, target.Role) {
			return remediation.Recipe{}, nil, ErrRemediationPlanUnauthorized
		}
	}
	return forward, rollback, nil
}

type RemediationService struct {
	runs       RemediationRunStore
	facts      RemediationFactStore
	catalog    *remediation.Catalog
	executor   RemediationExecutor
	authorizer RemediationAuthorizer
	clock      Clock
	ids        IDGenerator
	leaseFor   time.Duration
}

// NewRemediationService refuses to construct against an executor that does not
// report SIMULATED. Without this check, wiring could bind any implementation to
// the injectable port and obtain a live mutation path without a code review of
// the milestone's scope boundary.
func NewRemediationService(runs RemediationRunStore, facts RemediationFactStore, catalog *remediation.Catalog, executor RemediationExecutor, authorizer RemediationAuthorizer, clock Clock, ids IDGenerator, leaseFor time.Duration) (*RemediationService, error) {
	return newRemediationService(runs, facts, catalog, executor, authorizer, clock, ids, leaseFor, false)
}

// NewLiveRemediationService is reserved for the reviewed Tier 1 adapter. The
// separate constructor makes promotion from simulation an explicit composition
// decision.
func NewLiveRemediationService(runs RemediationRunStore, facts RemediationFactStore, catalog *remediation.Catalog, executor RemediationExecutor, authorizer RemediationAuthorizer, clock Clock, ids IDGenerator, leaseFor time.Duration) (*RemediationService, error) {
	return newRemediationService(runs, facts, catalog, executor, authorizer, clock, ids, leaseFor, true)
}

func newRemediationService(runs RemediationRunStore, facts RemediationFactStore, catalog *remediation.Catalog, executor RemediationExecutor, authorizer RemediationAuthorizer, clock Clock, ids IDGenerator, leaseFor time.Duration, allowLive bool) (*RemediationService, error) {
	if runs == nil || facts == nil || executor == nil || authorizer == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("remediation service dependencies are required")
	}
	if catalog == nil || catalog.Len() == 0 || !catalog.Verified() {
		return nil, fmt.Errorf("remediation service requires a verified recipe catalog")
	}
	if leaseFor <= 0 || leaseFor > MaxRemediationLease {
		return nil, fmt.Errorf("remediation lease must be positive and at most %s", MaxRemediationLease)
	}
	if executor.Assurance() != domain.AssuranceSimulated && !(allowLive && executor.Assurance() == domain.AssuranceLive) {
		return nil, ErrRemediationExecutorUnsafe
	}
	return &RemediationService{
		runs: runs, facts: facts, catalog: catalog, executor: executor,
		authorizer: authorizer, clock: clock, ids: ids, leaseFor: leaseFor,
	}, nil
}

type ProposeRemediationInput struct {
	ActorID         string
	ClusterID       domain.ClusterID
	IncidentID      domain.IncidentID
	InvestigationID domain.InvestigationID
	ActionCardID    domain.ActionCardID
	Proposal        remediation.RemediationProposal
	ValidFor        time.Duration
}

type ProposeRemediationOutcome struct {
	Run     domain.RemediationRun
	Created bool
}

// ProposeRemediation admits a proposal derived from the existing Action Card
// this investigation already published, resolves its targets against durable
// inventory, and creates the run. It is transaction 1 of the transaction
// contract: run, targets, arguments, citations, recipe references and audit
// commit together.
//
// The proposal supplies only a recipe coordinate, argument values and candidate
// targets. Cluster, incident, investigation and action card come from the
// authenticated caller and the durable rows; the incident kind is read from the
// incident row rather than accepted as a request field.
func (service *RemediationService) ProposeRemediation(ctx context.Context, input ProposeRemediationInput) (ProposeRemediationOutcome, error) {
	if input.ClusterID == "" || input.IncidentID == "" || input.InvestigationID == "" || input.ActorID == "" {
		return ProposeRemediationOutcome{}, ErrRemediationForbidden
	}
	if input.ValidFor <= 0 {
		return ProposeRemediationOutcome{}, fmt.Errorf("remediation proposal validity must be positive")
	}
	facts, err := service.facts.ReadRemediationFacts(ctx, RemediationFactQuery{
		ClusterID: input.ClusterID, IncidentID: input.IncidentID, InvestigationID: input.InvestigationID,
		RecipeID: input.Proposal.RecipeID, RecipeVersion: input.Proposal.RecipeVersion,
	})
	if err != nil {
		return ProposeRemediationOutcome{}, fmt.Errorf("read remediation facts: %w", err)
	}
	if facts.Now.IsZero() || facts.IncidentKind == "" {
		return ProposeRemediationOutcome{}, RemediationDeniedError{Code: string(remediation.PolicyStateUnavailable)}
	}
	arguments, err := remediation.AdmitProposal(service.catalog, input.ClusterID, input.Proposal)
	if err != nil {
		return ProposeRemediationOutcome{}, err
	}
	forwardRef, err := service.catalogRef(input.Proposal.RecipeID, input.Proposal.RecipeVersion)
	if err != nil {
		return ProposeRemediationOutcome{}, err
	}
	forward, rollback, err := ResolveRemediationRecipes(service.catalog, forwardRef, service.rollbackRef(forwardRef), facts.Now)
	if err != nil {
		return ProposeRemediationOutcome{}, err
	}
	resolution, err := remediation.ResolveTargets(remediation.ResolutionInput{
		ClusterID: input.ClusterID, IncidentID: input.IncidentID, Recipe: forward,
		Inventory: facts.Inventory, Proposed: remediation.AdmittedTargets(input.Proposal), Now: facts.Now,
	})
	if err != nil {
		return ProposeRemediationOutcome{}, err
	}
	decision, err := service.authorizer.AuthorizeRemediation(ctx, RemediationAuthorizationRequest{
		Action: RemediationActionPropose, ActorID: input.ActorID, ClusterID: input.ClusterID,
		Recipe: forward.Ref(), Tier: forward.Tier, Privilege: forward.Privilege,
		Stage: domain.RemediationStageCanary, Targets: resolution.TargetList(),
	})
	if err != nil {
		return ProposeRemediationOutcome{}, fmt.Errorf("authorize remediation proposal: %w", err)
	}
	if !decision.Allowed {
		return ProposeRemediationOutcome{}, ErrRemediationForbidden
	}
	runValue, err := service.ids.NewID()
	if err != nil {
		return ProposeRemediationOutcome{}, fmt.Errorf("create remediation run identifier: %w", err)
	}
	plan := domain.RemediationPlan{
		RunID: domain.RemediationRunID(runValue), ClusterID: input.ClusterID, IncidentID: input.IncidentID,
		InvestigationID: input.InvestigationID, ActionCardID: input.ActionCardID,
		Recipe: forward.Ref(), Tier: forward.Tier, Privilege: forward.Privilege, Assurance: forward.Assurance,
		Targets: resolution.Targets, TargetSetDigest: resolution.Digest, Arguments: arguments,
		MaxTargets: forward.MaxTargets, MaxConcurrency: forward.MaxConcurrency,
		CanaryTargets: forward.CanaryTargets, MaxAttempts: forward.MaxAttempts,
		ProposedAt: facts.Now, ExpiresAt: facts.Now.Add(input.ValidFor),
	}
	if rollback != nil {
		plan.Rollback = rollback.Ref()
	}
	// The plan was built from the catalog, and it is checked against the catalog
	// again before a run exists, so the two paths cannot drift apart.
	if _, _, err := AuthorizeRemediationPlan(service.catalog, plan, facts.Now); err != nil {
		return ProposeRemediationOutcome{}, err
	}
	run, err := domain.NewRemediationRun(plan)
	if err != nil {
		return ProposeRemediationOutcome{}, fmt.Errorf("create remediation run: %w", err)
	}
	audit, err := service.newAudit(RemediationAuditEvent{
		Kind: RemediationAuditProposal, ClusterID: input.ClusterID, RunID: plan.RunID, ActorID: input.ActorID,
		Outcome: remediationAuditOutcomeOK, ReasonCode: decision.ReasonCode,
		RecipeDigest: plan.Recipe.Digest, TargetSetDigest: plan.TargetSetDigest,
	})
	if err != nil {
		return ProposeRemediationOutcome{}, err
	}
	create := CreateRemediationRunInput{
		Run: run, Recipe: recipeRecord(forward), PinnedPopulation: resolution.Population,
		LedgerEntryIDs: slices.Clone(input.Proposal.LedgerEntryIDs),
		DeadlineAt:     facts.Now.Add(input.ValidFor),
	}
	if rollback != nil {
		record := recipeRecord(*rollback)
		create.Rollback = &record
	}
	stored, created, err := service.runs.CreateRemediationRun(ctx, create, audit)
	if err != nil {
		return ProposeRemediationOutcome{}, err
	}
	return ProposeRemediationOutcome{Run: stored, Created: created}, nil
}

// EvaluateRemediationPolicy moves PROPOSED to PREFLIGHT on an allowing decision
// and to POLICY_BLOCKED otherwise.
func (service *RemediationService) EvaluateRemediationPolicy(ctx context.Context, clusterID domain.ClusterID, runID domain.RemediationRunID, actorID string) (domain.RemediationRun, error) {
	loaded, plan, forward, rollback, facts, err := service.stage(ctx, clusterID, runID)
	if err != nil {
		return domain.RemediationRun{}, err
	}
	checking, err := loaded.Run.BeginPolicyCheck(facts.Now)
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("%w: %v", ErrRemediationConflict, err)
	}
	decision := service.evaluate(facts, forward, rollback, plan, domain.RemediationStageCanary, loaded)
	record := RemediationPolicyRecord{PolicyID: decision.PolicyID, Version: decision.PolicyVersion, Code: string(decision.Code)}
	var advanced domain.RemediationRun
	if decision.Allowed {
		advanced, err = checking.BeginPreflight(decision.Outcome(), facts.Now)
	} else {
		advanced, err = checking.RecordPolicyDecision(decision.Outcome(), facts.Now)
	}
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("%w: %v", ErrRemediationConflict, err)
	}
	outcome := remediationAuditOutcomeOK
	if !decision.Allowed {
		outcome = remediationAuditOutcomeDenied
	}
	audit, err := service.newAudit(RemediationAuditEvent{
		Kind: RemediationAuditPolicy, ClusterID: clusterID, RunID: runID, ActorID: actorID,
		Outcome: outcome, ReasonCode: string(decision.Code),
		RecipeDigest: plan.Recipe.Digest, TargetSetDigest: plan.TargetSetDigest,
	})
	if err != nil {
		return domain.RemediationRun{}, err
	}
	if err := service.runs.RecordRemediationTransition(ctx, RemediationTransition{
		ClusterID: clusterID, Run: advanced, ExpectedVersion: loaded.Run.Version(), Policy: &record,
		DeadlineAt: loaded.DeadlineAt,
	}, audit); err != nil {
		return domain.RemediationRun{}, err
	}
	if !decision.Allowed {
		return advanced, RemediationDeniedError{Code: string(decision.Code)}
	}
	return advanced, nil
}

// PreflightRemediation evaluates the preconditions and pins the target set,
// moving PREFLIGHT to READY or PREFLIGHT_FAILED. Target and population drift
// are discovered here and again inside the dispatch transaction.
func (service *RemediationService) PreflightRemediation(ctx context.Context, clusterID domain.ClusterID, runID domain.RemediationRunID, actorID string) (domain.RemediationRun, error) {
	loaded, plan, forward, _, facts, err := service.stage(ctx, clusterID, runID)
	if err != nil {
		return domain.RemediationRun{}, err
	}
	result := domain.RemediationPreflightResult{TargetSetDigest: plan.TargetSetDigest}
	conditions := []RemediationConditionRecord{}
	resolution, resolveErr := remediation.ResolveTargets(remediation.ResolutionInput{
		ClusterID: clusterID, IncidentID: plan.IncidentID, Recipe: forward,
		Inventory: facts.Inventory, Proposed: plan.TargetList(), Now: facts.Now,
	})
	failureCode := ""
	switch {
	case resolveErr != nil:
		failureCode = resolveErr.Error()
	default:
		if driftErr := remediation.DetectDrift(plan.TargetSetDigest, loaded.PinnedPopulation, resolution); driftErr != nil {
			failureCode = driftErr.Error()
		}
	}
	if failureCode == "" {
		observations, err := service.facts.ReadRemediationObservations(ctx, RemediationObservationQuery{
			ClusterID: clusterID, RunID: runID, Targets: plan.TargetList(),
			Window: forward.ObservationWindow, Conditions: conditionIDs(forward.Preconditions),
		})
		if err != nil {
			return domain.RemediationRun{}, fmt.Errorf("read remediation preconditions: %w", err)
		}
		evaluated := remediation.EvaluateConditions(forward.Preconditions, resolution.Targets, observations, remediationObservationTime(facts.Now, observations))
		result.Preconditions = evaluated
		for _, condition := range evaluated {
			conditions = append(conditions, RemediationConditionRecord{
				ConditionID: condition.ConditionID, Result: condition.Result,
				Source: RemediationObservedFromCollectionJobs,
			})
		}
	} else {
		// A drifted or unresolvable target set is not an unsatisfied condition; it
		// is an unobserved one, and the run fails preflight either way.
		for _, spec := range forward.Preconditions {
			result.Preconditions = append(result.Preconditions, domain.RemediationConditionResult{
				ConditionID: spec.ID, Result: domain.ConditionUnobserved,
			})
			conditions = append(conditions, RemediationConditionRecord{
				ConditionID: spec.ID, Result: domain.ConditionUnobserved,
				Source: RemediationObservedFromCollectionJobs,
			})
		}
		result.TargetSetDigest = domain.SHA256{}
	}
	advanced, err := loaded.Run.RecordPreflight(result, facts.Now)
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("%w: %v", ErrRemediationConflict, err)
	}
	outcome := remediationAuditOutcomeOK
	if advanced.State() != domain.RemediationReady {
		outcome = remediationAuditOutcomeDenied
	}
	audit, err := service.newAudit(RemediationAuditEvent{
		Kind: RemediationAuditPreflight, ClusterID: clusterID, RunID: runID, ActorID: actorID,
		Outcome: outcome, RecipeDigest: plan.Recipe.Digest, TargetSetDigest: plan.TargetSetDigest,
	})
	if err != nil {
		return domain.RemediationRun{}, err
	}
	if err := service.runs.RecordRemediationTransition(ctx, RemediationTransition{
		ClusterID: clusterID, Run: advanced, ExpectedVersion: loaded.Run.Version(),
		Phase: RemediationPhasePreflight, Conditions: conditions,
		AttentionRequired: advanced.State() == domain.RemediationPreflightFailed,
		DeadlineAt:        loaded.DeadlineAt,
	}, audit); err != nil {
		return domain.RemediationRun{}, err
	}
	if advanced.State() != domain.RemediationReady {
		return advanced, RemediationDeniedError{Code: string(remediation.RejectTargetDrift)}
	}
	return advanced, nil
}

// DispatchRemediation is the whole dispatch sequence, in the order the
// transaction contract requires: everything re-read and compared inside one
// transaction that commits the attempt and its lease hash, then the executor
// call outside any transaction, then the receipt ingested in a third.
//
// Policy is evaluated inside the dispatching transaction, not only at
// POLICY_CHECK: a run never dispatches on a decision older than the dispatch
// instant.
func (service *RemediationService) DispatchRemediation(ctx context.Context, clusterID domain.ClusterID, runID domain.RemediationRunID, actorID, leaseOwner string) (domain.RemediationRun, error) {
	loaded, plan, forward, rollback, facts, err := service.stage(ctx, clusterID, runID)
	if err != nil {
		return domain.RemediationRun{}, err
	}
	if leaseOwner == "" || !domain.ValidRemediationToken(leaseOwner) {
		return domain.RemediationRun{}, ErrRemediationLeaseInvalid
	}
	decision := service.evaluate(facts, forward, rollback, plan, domain.RemediationStageCanary, loaded)
	resolution, resolveErr := remediation.ResolveTargets(remediation.ResolutionInput{
		ClusterID: clusterID, IncidentID: plan.IncidentID, Recipe: forward,
		Inventory: facts.Inventory, Proposed: plan.TargetList(), Now: facts.Now,
	})
	revalidation := domain.RemediationDispatchRevalidation{
		Policy: decision.Outcome(), Recipe: forward.Ref(), RecipeExpiresAt: forward.ExpiresAt,
		PinnedPopulation: loaded.PinnedPopulation, LeaseHeld: true,
	}
	if resolveErr == nil {
		revalidation.TargetSetDigest = resolution.Digest
		revalidation.RolePopulation = resolution.Population
	}
	authorization, err := service.authorizer.AuthorizeRemediation(ctx, RemediationAuthorizationRequest{
		Action: RemediationActionDispatch, ActorID: actorID, ClusterID: clusterID, RunID: runID,
		Recipe: plan.Recipe, Tier: plan.Tier, Privilege: plan.Privilege,
		Stage: domain.RemediationStageCanary, Targets: plan.TargetList(),
	})
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("authorize remediation dispatch: %w", err)
	}
	if !authorization.Allowed {
		return domain.RemediationRun{}, ErrRemediationForbidden
	}
	dispatched, err := loaded.Run.Dispatch(revalidation, facts.Now)
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("%w: %v", ErrRemediationConflict, err)
	}
	if dispatched.State() != domain.RemediationCanaryExecuting {
		audit, auditErr := service.newAudit(RemediationAuditEvent{
			Kind: RemediationAuditDispatch, ClusterID: clusterID, RunID: runID, ActorID: actorID,
			Outcome: remediationAuditOutcomeDenied, ReasonCode: string(decision.Code),
			RecipeDigest: plan.Recipe.Digest, TargetSetDigest: plan.TargetSetDigest,
		})
		if auditErr != nil {
			return domain.RemediationRun{}, auditErr
		}
		if err := service.runs.RecordRemediationTransition(ctx, RemediationTransition{
			ClusterID: clusterID, Run: dispatched, ExpectedVersion: loaded.Run.Version(),
			AttentionRequired: true, DeadlineAt: loaded.DeadlineAt,
		}, audit); err != nil {
			return domain.RemediationRun{}, err
		}
		return dispatched, RemediationDeniedError{Code: string(decision.Code)}
	}
	attemptValue, err := service.ids.NewID()
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("create remediation attempt identifier: %w", err)
	}
	leaseToken, err := service.ids.NewID()
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("create remediation lease token: %w", err)
	}
	wave := plan.TargetList()
	if len(wave) > plan.CanaryTargets {
		wave = wave[:plan.CanaryTargets]
	}
	attempt, err := domain.NewRemediationAttempt(
		domain.RemediationAttemptID(attemptValue), plan, domain.RemediationStageCanary,
		loaded.Attempts(domain.RemediationStageCanary)+1, wave, leaseOwner,
		facts.Now, facts.Now.Add(service.leaseFor))
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("%w: %v", ErrRemediationConflict, err)
	}
	audit, err := service.newAudit(RemediationAuditEvent{
		Kind: RemediationAuditDispatch, ClusterID: clusterID, RunID: runID, AttemptID: attempt.ID,
		ActorID: actorID, Outcome: remediationAuditOutcomeOK, ReasonCode: string(decision.Code),
		RecipeDigest: plan.Recipe.Digest, TargetSetDigest: plan.TargetSetDigest,
	})
	if err != nil {
		return domain.RemediationRun{}, err
	}
	// Transaction 2 commits here, before the executor is called.
	committed, err := service.runs.DispatchRemediationAttempt(ctx, RemediationDispatchInput{
		Recipe: forward, RollbackRecipe: rollback,
		ClusterID: clusterID, Run: dispatched, ExpectedVersion: loaded.Run.Version(), Attempt: attempt,
		LeaseToken: leaseToken, MaxLeaseLifetime: MaxRemediationLeaseLifetime,
		Policy:           RemediationPolicyRecord{PolicyID: decision.PolicyID, Version: decision.PolicyVersion, Code: string(decision.Code)},
		PinnedPopulation: loaded.PinnedPopulation, TargetSetDigest: plan.TargetSetDigest,
		DeadlineAt: facts.Now.Add(forward.ObservationWindow),
	}, audit)
	if err != nil {
		return domain.RemediationRun{}, err
	}
	return service.execute(ctx, clusterID, plan, forward, committed, dispatched, leaseToken, actorID, committed.CreatedAt)
}

// execute performs the executor call outside every transaction and ingests the
// resulting receipt. A lost lease or an unknown outcome contains the run: after
// dispatch, "the mutation may or may not have happened" is not retryable.
func (service *RemediationService) execute(ctx context.Context, clusterID domain.ClusterID, plan domain.RemediationPlan, forward remediation.Recipe, attempt domain.RemediationAttempt, run domain.RemediationRun, leaseToken, actorID string, now time.Time) (domain.RemediationRun, error) {
	unit := domain.ExecutionUnit{
		Recipe: forward.Ref(),
		RunID:  plan.RunID, AttemptID: attempt.ID, ClusterID: clusterID, Operation: forward.Operation,
		Arguments: recipeArguments(forward, plan.Arguments), Targets: waveTargets(plan, attempt.WaveTargets),
		Stage: attempt.Stage, IdempotencyKey: attempt.IdempotencyKey,
		Deadline: now.Add(forward.ObservationWindow),
	}
	report := domain.RemediationExecutionReport{Outcome: domain.ExecutionUnknown}
	result, err := service.executor.Execute(ctx, unit, now)
	if err == nil {
		report.Outcome = result.Outcome
		report.PerTarget = result.PerTarget
		report.ExecutedTargets = executedTargets(result.PerTarget)
	}
	receiptValue, idErr := service.ids.NewID()
	if idErr != nil {
		return domain.RemediationRun{}, fmt.Errorf("create remediation receipt identifier: %w", idErr)
	}
	receipt := domain.RemediationReceipt{
		ID: domain.RemediationReceiptID(receiptValue), RunID: plan.RunID, AttemptID: attempt.ID,
		ClusterID: clusterID, IdempotencyKey: attempt.IdempotencyKey, Stage: attempt.Stage,
		Targets: slices.Clone(attempt.WaveTargets), PerTarget: report.PerTarget,
		Outcome: report.Outcome, ObservedAt: now,
	}
	receipt.Digest = receipt.ComputeDigest()
	outcome, err := service.IngestRemediationReceipt(ctx, IngestRemediationReceiptInput{
		ClusterID: clusterID, RunID: plan.RunID, AttemptID: attempt.ID, LeaseToken: leaseToken,
		ActorID: actorID, Receipt: receipt, Report: report, Run: run, Now: now,
	})
	if err != nil {
		return domain.RemediationRun{}, err
	}
	return outcome.Run, nil
}

type IngestRemediationReceiptInput struct {
	ClusterID domain.ClusterID
	RunID     domain.RemediationRunID
	AttemptID domain.RemediationAttemptID
	// LeaseToken is plaintext and lives only in memory for the duration of this
	// call. The store compares its hash in constant time and it never reaches a
	// row, a log or an error.
	LeaseToken string
	ActorID    string
	Receipt    domain.RemediationReceipt
	Report     domain.RemediationExecutionReport
	Run        domain.RemediationRun
	Now        time.Time
}

// IngestRemediationReceipt is transaction 3: the receipt, its per-target
// outcomes, the run transition and the audit event commit together. Idempotency
// key equality, lease ownership by constant-time hash comparison and the
// authenticated cluster are all checked at the store boundary.
func (service *RemediationService) IngestRemediationReceipt(ctx context.Context, input IngestRemediationReceiptInput) (RemediationReceiptOutcome, error) {
	if input.ClusterID == "" || input.AttemptID == "" || input.LeaseToken == "" {
		return RemediationReceiptOutcome{}, ErrRemediationLeaseInvalid
	}
	// The immutable receipt is the sole execution outcome. A separate caller
	// report must never steer the state differently from persisted per-target rows.
	input.Report = domain.RemediationExecutionReport{Outcome: input.Receipt.Outcome, PerTarget: slices.Clone(input.Receipt.PerTarget), ExecutedTargets: executedTargets(input.Receipt.PerTarget)}
	now := input.Now
	if now.IsZero() {
		now = service.clock.Now().UTC()
	}
	var advanced domain.RemediationRun
	var err error
	switch input.Run.State() {
	case domain.RemediationCanaryExecuting:
		advanced, err = input.Run.RecordCanaryOutcome(input.Report, now)
	case domain.RemediationRollingOut:
		advanced, err = input.Run.RecordRolloutOutcome(input.Report, now)
	case domain.RemediationRollingBack:
		advanced, err = input.Run.RecordRollbackExecution(input.Report, now)
	default:
		return RemediationReceiptOutcome{}, ErrRemediationConflict
	}
	if err != nil {
		return RemediationReceiptOutcome{}, fmt.Errorf("%w: %v", ErrRemediationConflict, err)
	}
	contained := ""
	if advanced.State() == domain.RemediationContained {
		contained = "UNKNOWN_OUTCOME"
		if input.Report.LeaseLost {
			contained = "LEASE_LOST"
		}
	}
	audit, err := service.newAudit(RemediationAuditEvent{
		Kind: RemediationAuditReceipt, ClusterID: input.ClusterID, RunID: input.RunID,
		AttemptID: input.AttemptID, ActorID: input.ActorID, Outcome: string(input.Receipt.Outcome),
		RecipeDigest: input.Run.Plan().Recipe.Digest, TargetSetDigest: input.Run.Plan().TargetSetDigest,
	})
	if err != nil {
		return RemediationReceiptOutcome{}, err
	}
	return service.runs.RecordRemediationReceipt(ctx, RemediationReceiptInput{
		ClusterID: input.ClusterID, AttemptID: input.AttemptID, LeaseToken: input.LeaseToken,
		Receipt: input.Receipt, Run: advanced, ExpectedVersion: input.Run.Version(),
		ContainedReason: contained, AttentionRequired: contained != "",
	}, audit)
}

// VerifyRemediation reads the independent postcondition observation from
// collection_runs and decides what VERIFYING becomes. Success requires every
// declared postcondition satisfied and the executed target set equal to the
// resolved set; partial coverage after a canary is a rollout, not a failure.
func (service *RemediationService) VerifyRemediation(ctx context.Context, clusterID domain.ClusterID, runID domain.RemediationRunID, actorID string) (domain.RemediationRun, error) {
	loaded, plan, forward, _, facts, err := service.stage(ctx, clusterID, runID)
	if err != nil {
		return domain.RemediationRun{}, err
	}
	if loaded.Run.State() != domain.RemediationVerifying {
		return domain.RemediationRun{}, ErrRemediationConflict
	}
	observations, err := service.facts.ReadRemediationObservations(ctx, RemediationObservationQuery{
		ClusterID: clusterID, RunID: runID, AttemptID: loaded.LatestAttemptID, Targets: verificationTargets(loaded),
		Window: forward.ObservationWindow, Conditions: conditionIDs(forward.Postconditions),
	})
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("read remediation postconditions: %w", err)
	}
	// Postconditions are judged over the targets that actually executed, not over
	// the whole resolved set. A canary in a multi-target run has legitimately not
	// touched the remaining targets, and evaluating them would report UNOBSERVED
	// and send a healthy canary to rollback. Coverage is a separate question,
	// answered by RecordVerification comparing executed against resolved.
	postconditions := remediation.EvaluateConditions(forward.Postconditions, waveTargets(plan, verificationTargets(loaded)), observations, remediationObservationTime(facts.Now, observations))
	for _, condition := range postconditions {
		if condition.Result != domain.ConditionSatisfied {
			if !loaded.DeadlineAt.IsZero() && !facts.Now.Before(loaded.DeadlineAt) {
				return service.beginRollbackOrContain(ctx, clusterID, loaded, plan, actorID, facts.Now)
			}
			return loaded.Run, nil
		}
	}
	conditions := make([]RemediationConditionRecord, 0, len(postconditions))
	for _, condition := range postconditions {
		conditions = append(conditions, RemediationConditionRecord{
			ConditionID: condition.ConditionID, Result: condition.Result,
			Source: RemediationObservedFromCollectionRuns,
		})
	}
	verification := domain.RemediationVerification{
		Postconditions: postconditions, ExecutedTargets: slices.Clone(loaded.ExecutedTargets),
	}
	advanced, verifyErr := loaded.Run.RecordVerification(verification, facts.Now)
	if verifyErr != nil {
		var insufficient domain.RemediationVerificationError
		if errors.As(verifyErr, &insufficient) && insufficient.Code == domain.VerificationCoverageIncomplete {
			// The wave covered part of the resolved set. That is a rollout in
			// progress, not a failure. The run stays in VERIFYING and the
			// observed conditions are still recorded; DispatchRemediationWave
			// consumes a wave of the bounded budget and moves it to ROLLING_OUT
			// under a fresh policy decision, exactly as the rollback path does.
			// Transitioning here instead would leave the run in ROLLING_OUT with
			// nothing that ever dispatches a wave, which is a stall.
			advanced = loaded.Run
		} else {
			return service.beginRollbackOrContain(ctx, clusterID, loaded, plan, actorID, facts.Now)
		}
	}
	audit, err := service.newAudit(RemediationAuditEvent{
		Kind: RemediationAuditVerification, ClusterID: clusterID, RunID: runID, ActorID: actorID,
		Outcome: string(advanced.State()), RecipeDigest: plan.Recipe.Digest, TargetSetDigest: plan.TargetSetDigest,
	})
	if err != nil {
		return domain.RemediationRun{}, err
	}
	if err := service.runs.RecordRemediationTransition(ctx, RemediationTransition{
		ClusterID: clusterID, Run: advanced, ExpectedVersion: loaded.Run.Version(),
		Phase: RemediationPhaseVerify, Conditions: conditions, Observations: observations, AttemptNumber: loaded.Run.Progress().TotalAttempts, DeadlineAt: loaded.DeadlineAt,
	}, audit); err != nil {
		return domain.RemediationRun{}, err
	}
	return advanced, nil
}

// DispatchRemediationWave dispatches the next rollout wave for a run whose
// canary succeeded but whose resolved set is not yet fully covered.
//
// It exists because a verified canary is not a finished repair. Without it a
// multi-target run reaches ROLLING_OUT and stops there forever, since nothing
// else in the system creates a ROLLOUT-stage attempt.
//
// Policy is evaluated again here, with the rollout stage, because a kill switch
// flipped or a policy revoked after the canary must stop the remaining waves.
// The wave's targets, recipe digest, target-set digest and role population are
// all revalidated immediately before the attempt is committed, and the attempt
// commits before the executor is called.
func (service *RemediationService) DispatchRemediationWave(ctx context.Context, clusterID domain.ClusterID, runID domain.RemediationRunID, actorID, leaseOwner string) (domain.RemediationRun, error) {
	loaded, plan, forward, rollback, facts, err := service.stage(ctx, clusterID, runID)
	if err != nil {
		return domain.RemediationRun{}, err
	}
	if loaded.Run.State() != domain.RemediationVerifying {
		return domain.RemediationRun{}, ErrRemediationConflict
	}
	if leaseOwner == "" || !domain.ValidRemediationToken(leaseOwner) {
		return domain.RemediationRun{}, ErrRemediationLeaseInvalid
	}
	if loaded.LatestAttemptID != "" && !loaded.WaveVerified {
		return domain.RemediationRun{}, ErrRemediationConflict
	}
	wave := plan.NextRolloutWave(loaded.ExecutedTargets)
	if len(wave) == 0 {
		// Nothing is left to cover. Verification, not a wave, decides success.
		return domain.RemediationRun{}, ErrRemediationConflict
	}
	decision := service.evaluate(facts, forward, rollback, plan, domain.RemediationStageRollout, loaded)
	if !decision.Allowed {
		return domain.RemediationRun{}, RemediationDeniedError{Code: string(decision.Code)}
	}
	resolution, resolveErr := remediation.ResolveTargets(remediation.ResolutionInput{
		ClusterID: clusterID, IncidentID: plan.IncidentID, Recipe: forward,
		Inventory: facts.Inventory, Proposed: plan.TargetList(), Now: facts.Now,
	})
	if resolveErr != nil || resolution.Digest != plan.TargetSetDigest ||
		resolution.Population != loaded.PinnedPopulation {
		return service.finish(ctx, clusterID, loaded, plan, domain.RemediationContained, "TARGET_DRIFT", true, actorID, facts.Now)
	}
	if forward.ExpiresAt.IsZero() || !forward.ExpiresAt.After(facts.Now) {
		return service.finish(ctx, clusterID, loaded, plan, domain.RemediationContained, "RECIPE_EXPIRED", true, actorID, facts.Now)
	}
	authorization, err := service.authorizer.AuthorizeRemediation(ctx, RemediationAuthorizationRequest{
		Action: RemediationActionDispatch, ActorID: actorID, ClusterID: clusterID, RunID: runID,
		Recipe: plan.Recipe, Tier: plan.Tier, Privilege: plan.Privilege,
		Stage: domain.RemediationStageRollout, Targets: wave,
	})
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("authorize remediation rollout: %w", err)
	}
	if !authorization.Allowed {
		return domain.RemediationRun{}, ErrRemediationForbidden
	}
	rollingOut, err := loaded.Run.BeginRollout(facts.Now)
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("%w: %v", ErrRemediationConflict, err)
	}
	attemptValue, err := service.ids.NewID()
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("create remediation attempt identifier: %w", err)
	}
	leaseToken, err := service.ids.NewID()
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("create remediation lease token: %w", err)
	}
	attempt, err := domain.NewRemediationAttempt(
		domain.RemediationAttemptID(attemptValue), plan, domain.RemediationStageRollout,
		loaded.Attempts(domain.RemediationStageRollout)+1, wave, leaseOwner,
		facts.Now, facts.Now.Add(service.leaseFor))
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("%w: %v", ErrRemediationConflict, err)
	}
	audit, err := service.newAudit(RemediationAuditEvent{
		Kind: RemediationAuditDispatch, ClusterID: clusterID, RunID: runID, AttemptID: attempt.ID,
		ActorID: actorID, Outcome: remediationAuditOutcomeOK, ReasonCode: string(decision.Code),
		RecipeDigest: plan.Recipe.Digest, TargetSetDigest: plan.TargetSetDigest,
	})
	if err != nil {
		return domain.RemediationRun{}, err
	}
	// The attempt commits before the executor is called, exactly as the canary
	// and rollback paths do.
	committed, err := service.runs.DispatchRemediationAttempt(ctx, RemediationDispatchInput{
		Recipe: forward, RollbackRecipe: rollback,
		ClusterID: clusterID, Run: rollingOut, ExpectedVersion: loaded.Run.Version(), Attempt: attempt,
		LeaseToken: leaseToken, MaxLeaseLifetime: MaxRemediationLeaseLifetime,
		Policy:           RemediationPolicyRecord{PolicyID: decision.PolicyID, Version: decision.PolicyVersion, Code: string(decision.Code)},
		PinnedPopulation: loaded.PinnedPopulation, TargetSetDigest: plan.TargetSetDigest,
		DeadlineAt: facts.Now.Add(forward.ObservationWindow),
	}, audit)
	if err != nil {
		return domain.RemediationRun{}, err
	}
	return service.execute(ctx, clusterID, plan, forward, committed, rollingOut, leaseToken, actorID, committed.CreatedAt)
}

// RollbackRemediation restricts the rollback to targets that are both in the
// persisted resolved set and known to have executed, then dispatches the
// rollback recipe under a fresh policy evaluation.
func (service *RemediationService) RollbackRemediation(ctx context.Context, clusterID domain.ClusterID, runID domain.RemediationRunID, actorID, leaseOwner string) (domain.RemediationRun, error) {
	loaded, plan, forward, rollback, facts, err := service.stage(ctx, clusterID, runID)
	if err != nil {
		return domain.RemediationRun{}, err
	}
	if rollback == nil {
		return service.finish(ctx, clusterID, loaded, plan, domain.RemediationContained, "ROLLBACK_UNAVAILABLE", true, actorID, facts.Now)
	}
	if len(loaded.ExecutedTargets) == 0 {
		return service.finish(ctx, clusterID, loaded, plan, domain.RemediationContained, "ROLLBACK_UNAVAILABLE", true, actorID, facts.Now)
	}
	authorized, err := remediation.AuthorizeRollbackTargets(plan.Targets, loaded.ExecutedTargets, loaded.ExecutedTargets)
	if err != nil {
		return domain.RemediationRun{}, err
	}
	decision := service.evaluate(facts, forward, rollback, plan, domain.RemediationStageRollback, loaded)
	if !decision.Allowed {
		return domain.RemediationRun{}, RemediationDeniedError{Code: string(decision.Code)}
	}
	authorization, err := service.authorizer.AuthorizeRemediation(ctx, RemediationAuthorizationRequest{
		Action: RemediationActionRollback, ActorID: actorID, ClusterID: clusterID, RunID: runID,
		Recipe: plan.Rollback, Tier: rollback.Tier, Privilege: rollback.Privilege,
		Stage: domain.RemediationStageRollback, Targets: resolvedTargetList(authorized),
	})
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("authorize remediation rollback: %w", err)
	}
	if !authorization.Allowed {
		return domain.RemediationRun{}, ErrRemediationForbidden
	}
	rollingBack, err := loaded.Run.BeginRollback(facts.Now)
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("%w: %v", ErrRemediationConflict, err)
	}
	attemptValue, err := service.ids.NewID()
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("create remediation attempt identifier: %w", err)
	}
	leaseToken, err := service.ids.NewID()
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("create remediation lease token: %w", err)
	}
	attempt, err := domain.NewRemediationAttempt(
		domain.RemediationAttemptID(attemptValue), plan, domain.RemediationStageRollback,
		loaded.Attempts(domain.RemediationStageRollback)+1, resolvedTargetList(authorized), leaseOwner,
		facts.Now, facts.Now.Add(service.leaseFor))
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("%w: %v", ErrRemediationConflict, err)
	}
	audit, err := service.newAudit(RemediationAuditEvent{
		Kind: RemediationAuditRollback, ClusterID: clusterID, RunID: runID, AttemptID: attempt.ID,
		ActorID: actorID, Outcome: remediationAuditOutcomeOK, ReasonCode: string(decision.Code),
		RecipeDigest: plan.Recipe.Digest, TargetSetDigest: plan.TargetSetDigest,
	})
	if err != nil {
		return domain.RemediationRun{}, err
	}
	committed, err := service.runs.DispatchRemediationAttempt(ctx, RemediationDispatchInput{
		Recipe: forward, RollbackRecipe: rollback,
		ClusterID: clusterID, Run: rollingBack, ExpectedVersion: loaded.Run.Version(), Attempt: attempt,
		LeaseToken: leaseToken, MaxLeaseLifetime: MaxRemediationLeaseLifetime,
		Policy:           RemediationPolicyRecord{PolicyID: decision.PolicyID, Version: decision.PolicyVersion, Code: string(decision.Code)},
		PinnedPopulation: loaded.PinnedPopulation, TargetSetDigest: plan.TargetSetDigest,
		DeadlineAt: facts.Now.Add(rollback.ObservationWindow),
	}, audit)
	if err != nil {
		return domain.RemediationRun{}, err
	}
	return service.execute(ctx, clusterID, plan, *rollback, committed, rollingBack, leaseToken, actorID, committed.CreatedAt)
}

// ContainRemediation parks a run whose effect on the world is unknown or unsafe
// to undo, and flags it for a human.
func (service *RemediationService) ContainRemediation(ctx context.Context, clusterID domain.ClusterID, runID domain.RemediationRunID, actorID, reason string) (domain.RemediationRun, error) {
	loaded, found, err := service.runs.LoadRemediationRun(ctx, clusterID, runID)
	if err != nil {
		return domain.RemediationRun{}, err
	}
	if !found {
		return domain.RemediationRun{}, ErrRemediationNotFound
	}
	originalVersion := loaded.Run.Version()
	plan := loaded.Run.Plan()
	decision, err := service.authorizer.AuthorizeRemediation(ctx, RemediationAuthorizationRequest{Action: RemediationActionContain, ActorID: actorID, ClusterID: clusterID, RunID: runID, Recipe: plan.Recipe, Tier: plan.Tier, Privilege: plan.Privilege})
	if err != nil {
		return domain.RemediationRun{}, err
	}
	if !decision.Allowed {
		return domain.RemediationRun{}, ErrRemediationForbidden
	}
	facts, err := service.facts.ReadRemediationFacts(ctx, RemediationFactQuery{ClusterID: clusterID, RunID: runID, RecipeID: plan.Recipe.ID, RecipeVersion: plan.Recipe.Version})
	if err != nil {
		return domain.RemediationRun{}, err
	}
	if reason == "" {
		reason = "OPERATOR_CONTAINED"
	}
	state := domain.RemediationContained
	if loaded.Run.Progress().TotalAttempts == 0 {
		if !plan.ExpiresAt.After(facts.Now) {
			state = domain.RemediationExpired
		} else {
			switch loaded.Run.State() {
			case domain.RemediationProposed:
				checking, e := loaded.Run.BeginPolicyCheck(facts.Now)
				if e != nil {
					return domain.RemediationRun{}, e
				}
				loaded.Run = checking
				state = domain.RemediationPolicyBlocked
			case domain.RemediationPolicyCheck, domain.RemediationReady:
				state = domain.RemediationPolicyBlocked
			case domain.RemediationPreflight:
				state = domain.RemediationPreflightFailed
			}
		}
	}
	advanced, err := loaded.Run.Transition(state, facts.Now)
	if err != nil {
		return domain.RemediationRun{}, err
	}
	audit, err := service.newAudit(RemediationAuditEvent{Kind: RemediationAuditContainment, ClusterID: clusterID, RunID: runID, ActorID: actorID, Outcome: string(state), ReasonCode: reason, RecipeDigest: plan.Recipe.Digest, TargetSetDigest: plan.TargetSetDigest})
	if err != nil {
		return domain.RemediationRun{}, err
	}
	err = service.runs.RecordRemediationTransition(ctx, RemediationTransition{ClusterID: clusterID, Run: advanced, ExpectedVersion: originalVersion, ContainedReason: reason, AttentionRequired: true, DeadlineAt: loaded.DeadlineAt}, audit)
	return advanced, err
}

// CancelRemediation cancels pre-dispatch plans. A LIVE effect that may already
// have executed is durably cancellation-fenced and contained for reconciliation;
// its immutable samples are never represented as undone.
func (service *RemediationService) CancelRemediation(ctx context.Context, clusterID domain.ClusterID, runID domain.RemediationRunID, actorID string) (domain.RemediationRun, error) {
	loaded, plan, _, _, facts, err := service.stage(ctx, clusterID, runID)
	if err != nil {
		return domain.RemediationRun{}, err
	}
	decision, err := service.authorizer.AuthorizeRemediation(ctx, RemediationAuthorizationRequest{
		Action: RemediationActionCancel, ActorID: actorID, ClusterID: clusterID, RunID: runID,
		Recipe: plan.Recipe, Tier: plan.Tier, Privilege: plan.Privilege, Targets: plan.TargetList(),
	})
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("authorize remediation cancellation: %w", err)
	}
	if !decision.Allowed {
		return domain.RemediationRun{}, ErrRemediationForbidden
	}
	if plan.Assurance == domain.AssuranceLive && loaded.Run.Progress().TotalAttempts > 0 && !loaded.Run.State().Terminal() {
		cancellation, ok := service.runs.(interface {
			RequestRemediationCancellation(context.Context, domain.ClusterID, domain.RemediationRunID, string) error
		})
		if !ok {
			return domain.RemediationRun{}, ErrRemediationForbidden
		}
		if err := cancellation.RequestRemediationCancellation(ctx, clusterID, runID, actorID); err != nil {
			return domain.RemediationRun{}, err
		}
		return service.ContainRemediation(ctx, clusterID, runID, actorID, "OPERATOR_CONTAINED")
	}
	return service.finish(ctx, clusterID, loaded, plan, domain.RemediationCancelled, "", false, actorID, facts.Now)
}

// ExpireRemediation is pre-dispatch only, for the same reason as cancellation.
func (service *RemediationService) ExpireRemediation(ctx context.Context, clusterID domain.ClusterID, runID domain.RemediationRunID, actorID string) (domain.RemediationRun, error) {
	loaded, plan, _, _, facts, err := service.stage(ctx, clusterID, runID)
	if err != nil {
		return domain.RemediationRun{}, err
	}
	if plan.ExpiresAt.After(facts.Now) {
		return domain.RemediationRun{}, ErrRemediationConflict
	}
	return service.finish(ctx, clusterID, loaded, plan, domain.RemediationExpired, "", false, actorID, facts.Now)
}

func (service *RemediationService) beginRollbackOrContain(ctx context.Context, clusterID domain.ClusterID, loaded LoadedRemediationRun, plan domain.RemediationPlan, actorID string, now time.Time) (domain.RemediationRun, error) {
	if !plan.HasRollback() {
		return service.finish(ctx, clusterID, loaded, plan, domain.RemediationContained, "ROLLBACK_UNAVAILABLE", true, actorID, now)
	}
	rollingBack, err := loaded.Run.Transition(domain.RemediationRollingBack, now)
	if err != nil {
		return service.finish(ctx, clusterID, loaded, plan, domain.RemediationContained, "ROLLBACK_UNAVAILABLE", true, actorID, now)
	}
	audit, err := service.newAudit(RemediationAuditEvent{
		Kind: RemediationAuditRollback, ClusterID: clusterID, RunID: plan.RunID, ActorID: actorID,
		Outcome: string(rollingBack.State()), RecipeDigest: plan.Recipe.Digest, TargetSetDigest: plan.TargetSetDigest,
	})
	if err != nil {
		return domain.RemediationRun{}, err
	}
	if err := service.runs.RecordRemediationTransition(ctx, RemediationTransition{
		ClusterID: clusterID, Run: rollingBack, ExpectedVersion: loaded.Run.Version(),
		AttentionRequired: true, DeadlineAt: loaded.DeadlineAt,
	}, audit); err != nil {
		return domain.RemediationRun{}, err
	}
	return rollingBack, nil
}

func (service *RemediationService) finish(ctx context.Context, clusterID domain.ClusterID, loaded LoadedRemediationRun, plan domain.RemediationPlan, state domain.RemediationState, reason string, attention bool, actorID string, now time.Time) (domain.RemediationRun, error) {
	advanced, err := loaded.Run.Transition(state, now)
	if err != nil {
		return domain.RemediationRun{}, fmt.Errorf("%w: %v", ErrRemediationConflict, err)
	}
	kind := RemediationAuditContainment
	switch state {
	case domain.RemediationCancelled:
		kind = RemediationAuditCancellation
	case domain.RemediationExpired:
		kind = RemediationAuditExpiry
	}
	audit, err := service.newAudit(RemediationAuditEvent{
		Kind: kind, ClusterID: clusterID, RunID: plan.RunID, ActorID: actorID,
		Outcome: string(state), ReasonCode: reason,
		RecipeDigest: plan.Recipe.Digest, TargetSetDigest: plan.TargetSetDigest,
	})
	if err != nil {
		return domain.RemediationRun{}, err
	}
	if err := service.runs.RecordRemediationTransition(ctx, RemediationTransition{
		ClusterID: clusterID, Run: advanced, ExpectedVersion: loaded.Run.Version(),
		ContainedReason: reason, AttentionRequired: attention, DeadlineAt: loaded.DeadlineAt,
	}, audit); err != nil {
		return domain.RemediationRun{}, err
	}
	return advanced, nil
}

// stage loads a run from durable rows and re-resolves its recipes through the
// catalog. Every use case starts here, so no stage ever proceeds on a plan the
// catalog would no longer authorize.
func (service *RemediationService) stage(ctx context.Context, clusterID domain.ClusterID, runID domain.RemediationRunID) (LoadedRemediationRun, domain.RemediationPlan, remediation.Recipe, *remediation.Recipe, RemediationFacts, error) {
	if clusterID == "" || runID == "" {
		return LoadedRemediationRun{}, domain.RemediationPlan{}, remediation.Recipe{}, nil, RemediationFacts{}, ErrRemediationNotFound
	}
	loaded, found, err := service.runs.LoadRemediationRun(ctx, clusterID, runID)
	if err != nil {
		return LoadedRemediationRun{}, domain.RemediationPlan{}, remediation.Recipe{}, nil, RemediationFacts{}, fmt.Errorf("load remediation run: %w", err)
	}
	if !found {
		return LoadedRemediationRun{}, domain.RemediationPlan{}, remediation.Recipe{}, nil, RemediationFacts{}, ErrRemediationNotFound
	}
	plan := loaded.Run.Plan()
	if plan.ClusterID != clusterID {
		// A run that answers to another cluster is reported as absent rather than
		// as forbidden, so the identifier itself does not leak across clusters.
		return LoadedRemediationRun{}, domain.RemediationPlan{}, remediation.Recipe{}, nil, RemediationFacts{}, ErrRemediationNotFound
	}
	facts, err := service.facts.ReadRemediationFacts(ctx, RemediationFactQuery{
		ClusterID: clusterID, IncidentID: plan.IncidentID, InvestigationID: plan.InvestigationID,
		RunID: runID, RecipeID: plan.Recipe.ID, RecipeVersion: plan.Recipe.Version,
		TargetSetDigest: plan.TargetSetDigest,
	})
	if err != nil {
		return LoadedRemediationRun{}, domain.RemediationPlan{}, remediation.Recipe{}, nil, RemediationFacts{}, fmt.Errorf("read remediation facts: %w", err)
	}
	forward, rollback, err := AuthorizeRemediationPlan(service.catalog, plan, facts.Now)
	if err != nil {
		return LoadedRemediationRun{}, domain.RemediationPlan{}, remediation.Recipe{}, nil, RemediationFacts{}, err
	}
	return loaded, plan, forward, rollback, facts, nil
}

// evaluate assembles the policy input from durable facts only. It is called
// before every attempt — the canary, each rollout wave and each rollback — not
// only at POLICY_CHECK and READY.
func (service *RemediationService) evaluate(facts RemediationFacts, forward remediation.Recipe, rollback *remediation.Recipe, plan domain.RemediationPlan, stage domain.RemediationStage, loaded LoadedRemediationRun) remediation.PolicyDecision {
	return remediation.Evaluate(remediation.PolicyInput{
		Now: facts.Now, StateObservedAt: facts.StateObservedAt, PopulationObservedAt: facts.PopulationObservedAt,
		Policy: facts.Policy, Recipe: forward, RollbackRecipe: rollback, Stage: stage,
		ClusterID: plan.ClusterID, InvestigationID: plan.InvestigationID, IncidentKind: facts.IncidentKind,
		ResolvedTargets: plan.Targets, RolePopulation: loaded.PinnedPopulation,
		PinnedRolePopulation: loaded.PinnedPopulation, Evidence: facts.Evidence,
		ActiveRuns: facts.ActiveRuns, NoActiveEquivalentRun: facts.NoActiveEquivalentRun,
		AttemptsUsed: loaded.Run.Progress().TotalAttempts, LastRunEndedAt: facts.LastRunEndedAt,
		ForwardAttemptsInWindow:  facts.ForwardAttemptsInWindow,
		RemediationEnabledGlobal: facts.EnabledGlobal, RemediationEnabledCluster: facts.EnabledCluster,
	})
}

func (service *RemediationService) catalogRef(id domain.RecipeID, version string) (domain.RemediationRecipeRef, error) {
	recipe, found := service.catalog.Lookup(id, version)
	if !found {
		return domain.RemediationRecipeRef{}, RemediationDeniedError{Code: string(remediation.RejectUnknownRecipe)}
	}
	return recipe.Ref(), nil
}

func (service *RemediationService) rollbackRef(forward domain.RemediationRecipeRef) domain.RemediationRecipeRef {
	recipe, found := service.catalog.Lookup(forward.ID, forward.Version)
	if !found {
		return domain.RemediationRecipeRef{}
	}
	return recipe.RollbackRecipe
}

func (service *RemediationService) newAudit(event RemediationAuditEvent) (RemediationAuditEvent, error) {
	eventID, err := service.ids.NewID()
	if err != nil {
		return RemediationAuditEvent{}, fmt.Errorf("create remediation audit identifier: %w", err)
	}
	event.EventID = eventID
	event.OccurredAt = service.clock.Now().UTC()
	return event, nil
}

func recipeRecord(recipe remediation.Recipe) RemediationRecipeRecord {
	return RemediationRecipeRecord{
		Ref: recipe.Ref(), Tier: recipe.Tier,
		Operation: string(recipe.Operation), ExpiresAt: recipe.ExpiresAt.UTC(),
	}
}

func conditionIDs(specs []remediation.ConditionSpec) []string {
	ids := make([]string, 0, len(specs))
	for _, spec := range specs {
		ids = append(ids, spec.ID)
	}
	return ids
}

func resolvedTargetList(resolved []domain.ResolvedTarget) []domain.RemediationTarget {
	targets := make([]domain.RemediationTarget, len(resolved))
	for index, entry := range resolved {
		targets[index] = entry.Target
	}
	return targets
}

// waveTargets narrows the plan's resolved targets to the wave, preserving the
// resolved metadata. A wave is always a subset of what the run was authorized
// for, so nothing here can widen it.
func waveTargets(plan domain.RemediationPlan, wave []domain.RemediationTarget) []domain.ResolvedTarget {
	targets := make([]domain.ResolvedTarget, 0, len(wave))
	for _, resolved := range plan.Targets {
		if slices.Contains(wave, resolved.Target) {
			targets = append(targets, resolved)
		}
	}
	return targets
}

func executedTargets(perTarget []domain.RemediationTargetOutcome) []domain.RemediationTarget {
	targets := make([]domain.RemediationTarget, 0, len(perTarget))
	for _, outcome := range perTarget {
		if outcome.Outcome == domain.ExecutionExecuted {
			targets = append(targets, outcome.Target)
		}
	}
	slices.Sort(targets)
	return slices.Compact(targets)
}

func recipeArguments(recipe remediation.Recipe, args domain.TypedArguments) domain.TypedArguments {
	var out domain.TypedArguments
	for _, a := range args {
		for _, p := range recipe.Parameters {
			if a.Name == p.Name {
				out = append(out, a)
			}
		}
	}
	return out
}

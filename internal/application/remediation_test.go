package application_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediation"
	"github.com/verticalcomputer/sherlock/internal/remediationrunner"
)

const (
	remediationCluster       = domain.ClusterID("remediation-cluster")
	remediationIncident      = domain.IncidentID("remediation-incident")
	remediationInvestigation = domain.InvestigationID("remediation-investigation")
	remediationTarget        = domain.RemediationTarget("collection-job-1")
)

func remediationNow() time.Time { return time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC) }

// remediationCatalog builds the shipped Tier 1 pair plus one extra Tier 1
// recipe that no forward recipe declares as its rollback. The extra recipe is
// the "foreign rollback": it is a perfectly valid catalog member, which is what
// makes it the right adversary — the plan check must refuse it on identity, not
// on the rollback happening to be over-broad.
func remediationCatalog(t *testing.T) (*remediation.Catalog, remediation.Recipe, remediation.Recipe, remediation.Recipe) {
	t.Helper()
	now := remediationNow()
	expiresAt := now.Add(365 * 24 * time.Hour)
	builtin := remediation.BuiltinRecipes(expiresAt)
	forward, rollback := builtin[0], builtin[1]
	foreign := rollback
	foreign.ID = domain.RecipeID("sherlock.evidence-collection-foreign")
	foreign = foreign.WithComputedDigest()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release, err := remediation.SignRecipeRelease([]remediation.Recipe{forward, rollback, foreign}, "test-root", priv)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := remediation.NewRecipeTrustStore([]remediation.RecipeTrustRoot{{ID: "test-root", Issuer: "test", PublicKey: pub, ActivatesAt: now.Add(-time.Hour), RetiresAt: expiresAt}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := trust.Verify(release, now)
	if err != nil {
		t.Fatalf("build catalog: %v", err)
	}
	return catalog, forward, rollback, foreign
}

func remediationPlan(t *testing.T, forward, rollback remediation.Recipe) domain.RemediationPlan {
	t.Helper()
	now := remediationNow()
	targets := []domain.ResolvedTarget{{
		Target: remediationTarget, Role: domain.RoleManagedCollectionStream,
		ClusterID: remediationCluster, ResolvedAt: now, Source: domain.SourceCollectionJobs,
	}}
	plan := domain.RemediationPlan{
		RunID: "remediation-run-1", ClusterID: remediationCluster, IncidentID: remediationIncident,
		InvestigationID: remediationInvestigation, ActionCardID: "action-card-1",
		Recipe: forward.Ref(), Rollback: rollback.Ref(), Tier: forward.Tier,
		Privilege: forward.Privilege, Assurance: forward.Assurance,
		Targets: targets, TargetSetDigest: domain.RemediationTargetSetDigest(targets),
		Arguments: domain.TypedArguments{
			{Name: "priority", Type: domain.ParameterEnum, Enum: "NORMAL"},
			{Name: "requeue_reason", Type: domain.ParameterEnum, Enum: "STALE_STREAM"},
		},
		MaxTargets: forward.MaxTargets, MaxConcurrency: forward.MaxConcurrency,
		CanaryTargets: forward.CanaryTargets, MaxAttempts: forward.MaxAttempts,
		ProposedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("fixture plan is invalid: %v", err)
	}
	return plan
}

// TestAuthorizeRemediationPlanRefusesUnauthorizedRollback is the regression
// test for the carry-over defect: RemediationPlan.Validate checks only
// well-formedness, so a plan could pin any rollback reference at all. Only
// Recipe.Validate enforces the rollback containment relation, and it is reached
// solely by resolving both references through the catalog.
func TestAuthorizeRemediationPlanRefusesUnauthorizedRollback(t *testing.T) {
	catalog, forward, rollback, foreign := remediationCatalog(t)
	now := remediationNow()

	tests := []struct {
		name    string
		mutate  func(domain.RemediationPlan) domain.RemediationPlan
		refused bool
	}{
		{
			name:   "catalog derived plan is authorized",
			mutate: func(plan domain.RemediationPlan) domain.RemediationPlan { return plan },
		},
		{
			// The foreign recipe is Tier 1, SIMULATED and SHERLOCK_INTERNAL, so
			// nothing about its contents is objectionable. It is refused purely
			// because the forward recipe never declared it, which is the property
			// that also refuses a rollback that *is* over-broad.
			name: "rollback the forward recipe never declared is refused",
			mutate: func(plan domain.RemediationPlan) domain.RemediationPlan {
				plan.Rollback = foreign.Ref()
				return plan
			},
			refused: true,
		},
		{
			name: "rollback with an altered digest is refused",
			mutate: func(plan domain.RemediationPlan) domain.RemediationPlan {
				plan.Rollback.Digest = domain.ChecksumSHA256([]byte("altered"))
				return plan
			},
			refused: true,
		},
		{
			name: "rollback at an undeclared version is refused",
			mutate: func(plan domain.RemediationPlan) domain.RemediationPlan {
				plan.Rollback.Version = "9.9.9"
				return plan
			},
			refused: true,
		},
		{
			name: "dropping the declared rollback is refused",
			mutate: func(plan domain.RemediationPlan) domain.RemediationPlan {
				plan.Rollback = domain.RemediationRecipeRef{}
				return plan
			},
			refused: true,
		},
		{
			name: "forward recipe with an altered digest is refused",
			mutate: func(plan domain.RemediationPlan) domain.RemediationPlan {
				plan.Recipe.Digest = domain.ChecksumSHA256([]byte("altered"))
				return plan
			},
			refused: true,
		},
		{
			name: "unknown forward recipe is refused",
			mutate: func(plan domain.RemediationPlan) domain.RemediationPlan {
				plan.Recipe.ID = "sherlock.fabricated"
				return plan
			},
			refused: true,
		},
		{
			name: "a ceiling wider than the catalog declares is refused",
			mutate: func(plan domain.RemediationPlan) domain.RemediationPlan {
				plan.MaxTargets = forward.MaxTargets + 1
				return plan
			},
			refused: true,
		},
		{
			name: "a canary count the catalog does not declare is refused",
			mutate: func(plan domain.RemediationPlan) domain.RemediationPlan {
				plan.CanaryTargets = forward.CanaryTargets + 1
				return plan
			},
			refused: true,
		},
		{
			name: "an attempt budget wider than the catalog declares is refused",
			mutate: func(plan domain.RemediationPlan) domain.RemediationPlan {
				plan.MaxAttempts = 3
				return plan
			},
			refused: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := test.mutate(remediationPlan(t, forward, rollback))
			_, resolved, err := application.AuthorizeRemediationPlan(catalog, plan, now)
			switch {
			case test.refused && !errors.Is(err, application.ErrRemediationPlanUnauthorized):
				t.Fatalf("expected the plan to be refused as unauthorized, got %v", err)
			case !test.refused && err != nil:
				t.Fatalf("expected the plan to be authorized, got %v", err)
			case !test.refused && (resolved == nil || !resolved.Ref().Matches(rollback.Ref())):
				t.Fatal("an authorized plan must resolve the rollback the catalog declares")
			}
		})
	}
}

// TestNewRemediationServiceRefusesNonSimulatedExecutor proves the constructor
// closes the injectable-port hole: binding any executor that does not report
// SIMULATED never yields a service at all.
func TestNewRemediationServiceRefusesNonSimulatedExecutor(t *testing.T) {
	catalog, _, _, _ := remediationCatalog(t)
	tests := []struct {
		name      string
		assurance domain.AssuranceClass
		refused   bool
	}{
		{name: "simulated executor is accepted", assurance: domain.AssuranceSimulated},
		{name: "recorded executor is refused", assurance: domain.AssuranceRecorded, refused: true},
		{name: "live executor is refused", assurance: domain.AssuranceLive, refused: true},
		{name: "unset assurance is refused", assurance: "", refused: true},
		{name: "unknown assurance is refused", assurance: "SOMETHING_ELSE", refused: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := application.NewRemediationService(
				&fakeRemediationRunStore{}, &fakeRemediationFactStore{}, catalog,
				assuranceExecutor{assurance: test.assurance}, allowRemediation{},
				fixedRemediationClock{}, &sequentialIDs{}, time.Minute)
			if test.refused && !errors.Is(err, application.ErrRemediationExecutorUnsafe) {
				t.Fatalf("expected the executor to be refused, got %v", err)
			}
			if !test.refused && err != nil {
				t.Fatalf("expected the service to construct, got %v", err)
			}
		})
	}
}

// TestDispatchRemediationCommitsBeforeExecuting pins the transaction contract:
// the attempt and its lease hash are committed before the executor is called,
// and the executor is never invoked inside a transaction. A crash after Execute
// must never leave a mutation whose authority is later reconstructed as "never
// dispatched".
func TestDispatchRemediationCommitsBeforeExecuting(t *testing.T) {
	catalog, forward, rollback, _ := remediationCatalog(t)
	plan := remediationPlan(t, forward, rollback)
	runs := &fakeRemediationRunStore{}
	run, err := domain.ReconstituteRemediationRun(plan, domain.RemediationReady, 4, domain.RemediationProgress{})
	if err != nil {
		t.Fatal(err)
	}
	runs.loaded = application.LoadedRemediationRun{
		Run: run, PinnedPopulation: 4, DeadlineAt: remediationNow().Add(15 * time.Minute),
	}
	executor, err := remediationrunner.NewSimulatedExecutor([]remediationrunner.ScriptedOutcome{
		{Operation: forward.Operation, Target: remediationTarget, Outcome: domain.ExecutionExecuted},
	})
	if err != nil {
		t.Fatal(err)
	}
	facts := &fakeRemediationFactStore{facts: allowingRemediationFacts(forward)}
	service, err := application.NewRemediationService(runs, facts, catalog,
		recordingExecutor{executor: executor, log: runs}, allowRemediation{},
		fixedRemediationClock{}, &sequentialIDs{}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	advanced, err := service.DispatchRemediation(context.Background(), remediationCluster, plan.RunID, "operator-1", "worker-1")
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if want := []string{"dispatch-committed", "execute", "receipt"}; !slices.Equal(runs.log, want) {
		t.Fatalf("expected the executor to run between the dispatch and receipt transactions, got %v", runs.log)
	}
	if advanced.State() != domain.RemediationVerifying {
		t.Fatalf("expected an executed canary to reach VERIFYING, got %s", advanced.State())
	}
	// The lease token reaches the store and nothing else: it is not in the
	// attempt, and it is not in the audit record.
	if runs.dispatch.LeaseToken == "" {
		t.Fatal("the dispatch transaction must receive a lease token to hash")
	}
	if runs.dispatchAudit.ReasonCode != string(remediation.PolicyAllowed) {
		t.Fatalf("expected the dispatch audit to record the allowing policy code, got %q", runs.dispatchAudit.ReasonCode)
	}
	if runs.dispatch.Attempt.AttemptNumber != 1 || runs.dispatch.Attempt.Stage != domain.RemediationStageCanary {
		t.Fatalf("expected the first canary attempt, got %d/%s", runs.dispatch.Attempt.AttemptNumber, runs.dispatch.Attempt.Stage)
	}
	if len(runs.dispatch.Attempt.WaveTargets) != plan.CanaryTargets {
		t.Fatalf("expected the canary wave to hold %d targets, got %d", plan.CanaryTargets, len(runs.dispatch.Attempt.WaveTargets))
	}
}

// TestDispatchRemediationDeniesOnStaleFacts proves policy is evaluated inside
// the dispatching path rather than only at POLICY_CHECK: each field whose zero
// value would read as permission blocks the dispatch on its own.
func TestDispatchRemediationDeniesOnStaleFacts(t *testing.T) {
	catalog, forward, rollback, _ := remediationCatalog(t)
	plan := remediationPlan(t, forward, rollback)
	tests := []struct {
		name   string
		mutate func(application.RemediationFacts) application.RemediationFacts
		code   remediation.PolicyCode
	}{
		{
			name: "global enablement unread",
			mutate: func(facts application.RemediationFacts) application.RemediationFacts {
				facts.EnabledGlobal = false
				return facts
			},
			code: remediation.PolicyGlobalDisabled,
		},
		{
			name: "cluster enablement unread",
			mutate: func(facts application.RemediationFacts) application.RemediationFacts {
				facts.EnabledCluster = false
				return facts
			},
			code: remediation.PolicyClusterDisabled,
		},
		{
			name: "policy revoked between the check and the dispatch",
			mutate: func(facts application.RemediationFacts) application.RemediationFacts {
				revoked := remediationNow()
				facts.Policy.RevokedAt = &revoked
				return facts
			},
			code: remediation.PolicyRevoked,
		},
		{
			name: "observed counters are stale",
			mutate: func(facts application.RemediationFacts) application.RemediationFacts {
				facts.StateObservedAt = facts.Now.Add(-2 * remediation.MaxStateAge)
				return facts
			},
			code: remediation.PolicyStateUnavailable,
		},
		{
			name: "an equivalent repair is already running",
			mutate: func(facts application.RemediationFacts) application.RemediationFacts {
				facts.NoActiveEquivalentRun = false
				return facts
			},
			code: remediation.PolicyActiveRunConflict,
		},
		{
			name: "the cited evidence was superseded",
			mutate: func(facts application.RemediationFacts) application.RemediationFacts {
				facts.Evidence[0].Superseded = true
				return facts
			},
			code: remediation.PolicyEvidenceSuperseded,
		},
		{
			name: "the cited evidence belongs to another cluster",
			mutate: func(facts application.RemediationFacts) application.RemediationFacts {
				facts.Evidence[0].ClusterID = "another-cluster"
				return facts
			},
			code: remediation.PolicyEvidenceClusterMismatch,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			run, err := domain.ReconstituteRemediationRun(plan, domain.RemediationReady, 4, domain.RemediationProgress{})
			if err != nil {
				t.Fatal(err)
			}
			runs := &fakeRemediationRunStore{loaded: application.LoadedRemediationRun{
				Run: run, PinnedPopulation: 4, DeadlineAt: remediationNow().Add(15 * time.Minute),
			}}
			facts := &fakeRemediationFactStore{facts: test.mutate(allowingRemediationFacts(forward))}
			executor, err := remediationrunner.NewSimulatedExecutor(nil)
			if err != nil {
				t.Fatal(err)
			}
			service, err := application.NewRemediationService(runs, facts, catalog,
				recordingExecutor{executor: executor, log: runs}, allowRemediation{},
				fixedRemediationClock{}, &sequentialIDs{}, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.DispatchRemediation(context.Background(), remediationCluster, plan.RunID, "operator-1", "worker-1")
			var denied application.RemediationDeniedError
			if !errors.As(err, &denied) || denied.Code != string(test.code) {
				t.Fatalf("expected deny code %s, got %v", test.code, err)
			}
			if slices.Contains(runs.log, "execute") {
				t.Fatal("a denied dispatch must never reach the executor")
			}
			if slices.Contains(runs.log, "dispatch-committed") {
				t.Fatal("a denied dispatch must never commit an attempt")
			}
		})
	}
}

// TestRemediationRunsAreClusterScoped proves a run identifier from another
// cluster resolves to nothing rather than to somebody else's run.
func TestRemediationRunsAreClusterScoped(t *testing.T) {
	catalog, forward, rollback, _ := remediationCatalog(t)
	plan := remediationPlan(t, forward, rollback)
	run, err := domain.ReconstituteRemediationRun(plan, domain.RemediationReady, 4, domain.RemediationProgress{})
	if err != nil {
		t.Fatal(err)
	}
	runs := &fakeRemediationRunStore{loaded: application.LoadedRemediationRun{Run: run, PinnedPopulation: 4}}
	executor, err := remediationrunner.NewSimulatedExecutor(nil)
	if err != nil {
		t.Fatal(err)
	}
	service, err := application.NewRemediationService(runs, &fakeRemediationFactStore{facts: allowingRemediationFacts(forward)},
		catalog, executor, allowRemediation{}, fixedRemediationClock{}, &sequentialIDs{}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"dispatch", "cancel", "verify"} {
		var actionErr error
		switch action {
		case "dispatch":
			_, actionErr = service.DispatchRemediation(context.Background(), "another-cluster", plan.RunID, "operator-1", "worker-1")
		case "cancel":
			_, actionErr = service.CancelRemediation(context.Background(), "another-cluster", plan.RunID, "operator-1")
		case "verify":
			_, actionErr = service.VerifyRemediation(context.Background(), "another-cluster", plan.RunID, "operator-1")
		}
		if !errors.Is(actionErr, application.ErrRemediationNotFound) {
			t.Fatalf("%s from another cluster: expected the run to be absent, got %v", action, actionErr)
		}
	}
}

func allowingRemediationFacts(forward remediation.Recipe) application.RemediationFacts {
	now := remediationNow()
	epoch := time.Unix(0, 0).UTC()
	inventory := make([]remediation.InventoryRow, 0, 4)
	for index := 1; index <= 4; index++ {
		inventory = append(inventory, remediation.InventoryRow{
			Target:    domain.RemediationTarget(fmt.Sprintf("collection-job-%d", index)),
			Role:      domain.RoleManagedCollectionStream,
			ClusterID: remediationCluster, IncidentID: remediationIncident,
			Source: domain.SourceCollectionJobs,
		})
	}
	return application.RemediationFacts{
		Now: now, StateObservedAt: now, PopulationObservedAt: now,
		EnabledGlobal: true, EnabledCluster: true,
		Policy: remediation.StandingPolicy{
			ID: "remediation-policy-1", Version: 1, ClusterID: remediationCluster,
			RecipeID: forward.ID, RecipeVersion: forward.Version, MaxTier: domain.TierSherlockOwnedRepair,
			IncidentKinds: []string{remediation.IncidentKindEvidenceStreamStale},
			MaxTargets:    4, MaxConcurrentRuns: 1, Cooldown: 0,
			EvidenceMaxAge: 15 * time.Minute, MinEvidenceCoverage: 100, RequireRollback: true,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		},
		IncidentKind: remediation.IncidentKindEvidenceStreamStale,
		Inventory:    inventory,
		Evidence: []remediation.EvidenceFact{{
			LedgerEntryID: "ledger-entry-1", Class: remediation.EvidenceClassCollectionFreshness,
			ClusterID: remediationCluster, InvestigationID: remediationInvestigation,
			ObservedEnd: now.Add(-time.Minute), RecordedAt: now, Coverage: 100,
		}},
		ActiveRuns: 0, NoActiveEquivalentRun: true, LastRunEndedAt: &epoch,
	}
}

type fakeRemediationRunStore struct {
	loaded        application.LoadedRemediationRun
	log           []string
	dispatch      application.RemediationDispatchInput
	dispatchAudit application.RemediationAuditEvent
	transitions   []application.RemediationTransition
}

func (store *fakeRemediationRunStore) record(event string) { store.log = append(store.log, event) }

func (store *fakeRemediationRunStore) CreateRemediationRun(context.Context, application.CreateRemediationRunInput, application.RemediationAuditEvent) (domain.RemediationRun, bool, error) {
	store.record("create")
	return store.loaded.Run, true, nil
}

func (store *fakeRemediationRunStore) LoadRemediationRun(_ context.Context, clusterID domain.ClusterID, runID domain.RemediationRunID) (application.LoadedRemediationRun, bool, error) {
	plan := store.loaded.Run.Plan()
	if plan.ClusterID != clusterID || plan.RunID != runID {
		return application.LoadedRemediationRun{}, false, nil
	}
	return store.loaded, true, nil
}

func (store *fakeRemediationRunStore) RecordRemediationTransition(_ context.Context, transition application.RemediationTransition, _ application.RemediationAuditEvent) error {
	store.record("transition")
	store.transitions = append(store.transitions, transition)
	return nil
}

func (store *fakeRemediationRunStore) DispatchRemediationAttempt(_ context.Context, input application.RemediationDispatchInput, audit application.RemediationAuditEvent) (domain.RemediationAttempt, error) {
	store.dispatch, store.dispatchAudit = input, audit
	store.record("dispatch-committed")
	return input.Attempt, nil
}

func (store *fakeRemediationRunStore) RecordRemediationReceipt(_ context.Context, input application.RemediationReceiptInput, _ application.RemediationAuditEvent) (application.RemediationReceiptOutcome, error) {
	store.record("receipt")
	return application.RemediationReceiptOutcome{Receipt: input.Receipt, Run: input.Run}, nil
}

type fakeRemediationFactStore struct {
	facts application.RemediationFacts
}

func (store *fakeRemediationFactStore) ReadRemediationFacts(context.Context, application.RemediationFactQuery) (application.RemediationFacts, error) {
	return store.facts, nil
}

func (store *fakeRemediationFactStore) ReadRemediationObservations(_ context.Context, query application.RemediationObservationQuery) ([]domain.ConditionObservation, error) {
	observations := make([]domain.ConditionObservation, 0, len(query.Targets)*len(query.Conditions))
	for _, target := range query.Targets {
		for _, conditionID := range query.Conditions {
			observations = append(observations, domain.ConditionObservation{
				ConditionID: conditionID, Target: target,
				Result: domain.ConditionSatisfied, ObservedAt: remediationNow(),
			})
		}
	}
	return observations, nil
}

// assuranceExecutor reports whatever assurance class a test asks for. It cannot
// execute: a test that needed it to would be exercising a path the constructor
// is supposed to make unreachable.
type assuranceExecutor struct{ assurance domain.AssuranceClass }

func (e assuranceExecutor) Execute(context.Context, remediationrunner.ExecutionUnit, time.Time) (remediationrunner.ExecutionResult, error) {
	return remediationrunner.ExecutionResult{}, errors.New("this executor must never be reached")
}

func (e assuranceExecutor) Assurance() domain.AssuranceClass { return e.assurance }

type recordingExecutor struct {
	executor *remediationrunner.SimulatedExecutor
	log      *fakeRemediationRunStore
}

func (e recordingExecutor) Execute(ctx context.Context, unit remediationrunner.ExecutionUnit, now time.Time) (remediationrunner.ExecutionResult, error) {
	e.log.record("execute")
	return e.executor.Execute(ctx, unit, now)
}

func (e recordingExecutor) Assurance() domain.AssuranceClass { return e.executor.Assurance() }

type allowRemediation struct{}

func (allowRemediation) AuthorizeRemediation(context.Context, application.RemediationAuthorizationRequest) (application.RemediationAuthorizationDecision, error) {
	return application.RemediationAuthorizationDecision{Allowed: true, ReasonCode: "ALLOWED"}, nil
}

type fixedRemediationClock struct{}

func (fixedRemediationClock) Now() time.Time { return remediationNow() }

type sequentialIDs struct{ counter int }

func (ids *sequentialIDs) NewID() (string, error) {
	ids.counter++
	return fmt.Sprintf("generated-id-%d", ids.counter), nil
}

// statefulRemediationRunStore actually advances, unlike the fixed fake above.
// A multi-wave rollout cannot be tested against a store that always returns the
// same run: the whole point is that state moves forward across many calls.
type statefulRemediationRunStore struct {
	loaded   application.LoadedRemediationRun
	attempts map[domain.RemediationStage]int
	executed []domain.RemediationTarget
	waves    [][]domain.RemediationTarget
}

func (store *statefulRemediationRunStore) CreateRemediationRun(context.Context, application.CreateRemediationRunInput, application.RemediationAuditEvent) (domain.RemediationRun, bool, error) {
	return store.loaded.Run, true, nil
}

func (store *statefulRemediationRunStore) LoadRemediationRun(_ context.Context, clusterID domain.ClusterID, runID domain.RemediationRunID) (application.LoadedRemediationRun, bool, error) {
	plan := store.loaded.Run.Plan()
	if plan.ClusterID != clusterID || plan.RunID != runID {
		return application.LoadedRemediationRun{}, false, nil
	}
	current := store.loaded
	current.ExecutedTargets = slices.Clone(store.executed)
	current.StageAttempts = nil
	for stage, count := range store.attempts {
		current.StageAttempts = append(current.StageAttempts, application.RemediationStageAttempts{Stage: stage, Used: count})
	}
	return current, true, nil
}

func (store *statefulRemediationRunStore) RecordRemediationTransition(_ context.Context, transition application.RemediationTransition, _ application.RemediationAuditEvent) error {
	store.loaded.Run = transition.Run
	return nil
}

func (store *statefulRemediationRunStore) DispatchRemediationAttempt(_ context.Context, input application.RemediationDispatchInput, _ application.RemediationAuditEvent) (domain.RemediationAttempt, error) {
	store.loaded.Run = input.Run
	if store.attempts == nil {
		store.attempts = map[domain.RemediationStage]int{}
	}
	store.attempts[input.Attempt.Stage]++
	store.waves = append(store.waves, slices.Clone(input.Attempt.WaveTargets))
	return input.Attempt, nil
}

func (store *statefulRemediationRunStore) RecordRemediationReceipt(_ context.Context, input application.RemediationReceiptInput, _ application.RemediationAuditEvent) (application.RemediationReceiptOutcome, error) {
	store.loaded.Run = input.Run
	for _, outcome := range input.Receipt.PerTarget {
		if outcome.Outcome == domain.ExecutionExecuted && !slices.Contains(store.executed, outcome.Target) {
			store.executed = append(store.executed, outcome.Target)
		}
	}
	slices.Sort(store.executed)
	return application.RemediationReceiptOutcome{Receipt: input.Receipt, Run: input.Run}, nil
}

// TestMultiTargetRunReachesSuccessThroughEveryRolloutWave is the regression test
// for the rollout stall. Before DispatchRemediationWave existed, nothing in the
// repository ever created a ROLLOUT-stage attempt: VerifyRemediation moved a
// partially covered run to ROLLING_OUT and it stayed there forever. Every
// earlier test used a single target, so the canary always achieved full
// coverage and the gap was invisible.
//
// This drives a three-target run all the way to SUCCEEDED and asserts that
// every resolved target executed exactly once.
func TestMultiTargetRunReachesSuccessThroughEveryRolloutWave(t *testing.T) {
	now := remediationNow()
	catalog, forward, rollback, _ := remediationCatalog(t)

	// The blast radius is a percentage of the role population, so a three-target
	// wave needs a population that permits three: floor(12 * 25 / 100) == 3.
	inventory := make([]remediation.InventoryRow, 0, 12)
	for index := 1; index <= 12; index++ {
		inventory = append(inventory, remediation.InventoryRow{
			Target:    domain.RemediationTarget(fmt.Sprintf("collection-job-%02d", index)),
			Role:      domain.RoleManagedCollectionStream,
			ClusterID: remediationCluster, IncidentID: remediationIncident,
			Source: domain.SourceCollectionJobs,
		})
	}
	proposed := []domain.RemediationTarget{"collection-job-01", "collection-job-02", "collection-job-03"}
	resolution, err := remediation.ResolveTargets(remediation.ResolutionInput{
		ClusterID: remediationCluster, IncidentID: remediationIncident, Recipe: forward,
		Inventory: inventory, Proposed: proposed, Now: now,
	})
	if err != nil {
		t.Fatalf("resolve targets: %v", err)
	}

	plan := remediationPlan(t, forward, rollback)
	plan.Targets = resolution.Targets
	plan.TargetSetDigest = resolution.Digest
	if err := plan.Validate(); err != nil {
		t.Fatalf("multi-target plan is invalid: %v", err)
	}
	run, err := domain.NewRemediationRun(plan)
	if err != nil {
		t.Fatalf("new run: %v", err)
	}

	facts := allowingRemediationFacts(forward)
	facts.Inventory = inventory
	runs := &statefulRemediationRunStore{
		loaded: application.LoadedRemediationRun{Run: run, PinnedPopulation: resolution.Population},
	}
	executor, err := remediationrunner.NewSimulatedExecutor(scriptFor(forward, resolution.TargetList()))
	if err != nil {
		t.Fatalf("new simulated executor: %v", err)
	}
	service, err := application.NewRemediationService(
		runs, &fakeRemediationFactStore{facts: facts}, catalog, executor,
		allowRemediation{}, fixedRemediationClock{}, &sequentialIDs{}, time.Minute)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	ctx := context.Background()
	if _, err := service.EvaluateRemediationPolicy(ctx, remediationCluster, plan.RunID, "operator-1"); err != nil {
		t.Fatalf("policy check: %v", err)
	}
	if _, err := service.PreflightRemediation(ctx, remediationCluster, plan.RunID, "operator-1"); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if _, err := service.DispatchRemediation(ctx, remediationCluster, plan.RunID, "operator-1", "worker-1"); err != nil {
		t.Fatalf("canary dispatch: %v", err)
	}

	// Verify, then roll out, until the run terminates. The bound is deliberately
	// generous: the assertion that matters is that the loop ends in SUCCEEDED,
	// not that it ends quickly. Before the fix this loop never terminated.
	for step := 0; step < 12; step++ {
		state := runs.loaded.Run.State()
		if state.Terminal() {
			break
		}
		switch state {
		case domain.RemediationVerifying:
			advanced, err := service.VerifyRemediation(ctx, remediationCluster, plan.RunID, "operator-1")
			if err != nil {
				t.Fatalf("verify at step %d: %v", step, err)
			}
			if advanced.State() == domain.RemediationVerifying {
				// Partial coverage. The remaining targets are a rollout.
				if _, err := service.DispatchRemediationWave(ctx, remediationCluster, plan.RunID, "operator-1", "worker-1"); err != nil {
					t.Fatalf("rollout wave at step %d: %v", step, err)
				}
			}
		default:
			t.Fatalf("run reached unexpected non-terminal state %s at step %d", state, step)
		}
	}

	final := runs.loaded.Run
	if final.State() != domain.RemediationSucceeded {
		t.Fatalf("final state = %s, want SUCCEEDED (a stalled rollout is the defect this test exists for)", final.State())
	}
	if !slices.Equal(runs.executed, resolution.TargetList()) {
		t.Fatalf("executed = %v, want every resolved target %v", runs.executed, resolution.TargetList())
	}
	// One canary wave plus the rollout waves, and no target covered twice.
	seen := map[domain.RemediationTarget]int{}
	for _, wave := range runs.waves {
		for _, target := range wave {
			seen[target]++
		}
	}
	for target, count := range seen {
		if count != 1 {
			t.Fatalf("target %s was dispatched %d times; a wave must never re-execute a target", target, count)
		}
	}
	if len(runs.waves) < 2 {
		t.Fatalf("waves = %d; a three-target run with a one-target canary must roll out", len(runs.waves))
	}
	if got := runs.loaded.Run.Progress().RolloutWave; got != len(runs.waves)-1 {
		t.Fatalf("rollout wave counter = %d, want %d", got, len(runs.waves)-1)
	}
}

// scriptFor makes every named target execute successfully for both the forward
// operation and its rollback, so the test exercises the control flow rather
// than a particular failure.
func scriptFor(forward remediation.Recipe, targets []domain.RemediationTarget) []remediationrunner.ScriptedOutcome {
	outcomes := make([]remediationrunner.ScriptedOutcome, 0, len(targets))
	for _, target := range targets {
		outcomes = append(outcomes, remediationrunner.ScriptedOutcome{
			Operation: forward.Operation, Target: target, Outcome: domain.ExecutionExecuted,
		})
	}
	return outcomes
}

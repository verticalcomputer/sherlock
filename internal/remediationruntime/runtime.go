// Package remediationruntime composes the default-off durable supervisor. Its
// explicit LIVE mode is limited to one-time Sherlock collection requests; the
// historical default remains the isolated simulation.
package remediationruntime

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	"github.com/verticalcomputer/sherlock/internal/remediation"
	"github.com/verticalcomputer/sherlock/internal/remediationlive"
	"github.com/verticalcomputer/sherlock/internal/remediationrunner"
	"github.com/verticalcomputer/sherlock/internal/scheduleinvestigation"
	"github.com/verticalcomputer/sherlock/internal/store/postgres"
	"log/slog"
	"time"
)

type Config struct {
	Enabled      bool
	Live         bool
	ClusterID    domain.ClusterID
	Owner        string
	PollInterval time.Duration
	Lease        time.Duration
	Batch        int
	Observer     Observer
}

// Observer receives only closed outcome codes and elapsed durations. Durable
// state remains in PostgreSQL; telemetry never supplies execution authority.
type Observer interface {
	RecordFailure(string)
	RecordIteration(time.Duration, string)
}
type Runtime struct {
	store   *postgres.RemediationStore
	service *application.RemediationService
	cfg     Config
	logger  *slog.Logger
}

func New(pool *pgxpool.Pool, catalog *remediation.Catalog, cfg Config, logger *slog.Logger) (*Runtime, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if pool == nil || catalog == nil || !catalog.Verified() || logger == nil || !domain.ValidRemediationToken(string(cfg.ClusterID)) || !domain.ValidRemediationToken(cfg.Owner) || cfg.PollInterval < 10*time.Millisecond || cfg.PollInterval > time.Minute || cfg.Lease < time.Second || cfg.Lease > application.MaxRemediationLease || cfg.Batch < 1 || cfg.Batch > 32 {
		return nil, fmt.Errorf("invalid remediation runtime configuration")
	}
	if cfg.Live {
		if _, found := catalog.Lookup(remediation.RecipeEvidenceCollectionRequeue, remediation.CollectionRequestRecipeVersion); !found {
			return nil, fmt.Errorf("live remediation requires the versioned collection-request recipe")
		}
	}
	store, err := postgres.NewRemediationStore(pool)
	if err != nil {
		return nil, err
	}
	var service *application.RemediationService
	if cfg.Live {
		executor, executorErr := remediationlive.New(catalog, store)
		if executorErr != nil {
			return nil, executorErr
		}
		service, err = application.NewLiveRemediationService(store, store, catalog, executor, runtimeAuthorizer{cfg.ClusterID}, platform.SystemClock{}, platform.RandomIDGenerator{}, cfg.Lease)
	} else {
		service, err = application.NewRemediationService(store, simulationFacts{store}, catalog, simulationExecutor{store, catalog}, runtimeAuthorizer{cfg.ClusterID}, platform.SystemClock{}, platform.RandomIDGenerator{}, cfg.Lease)
	}
	if err != nil {
		return nil, err
	}
	return &Runtime{store, service, cfg, logger}, nil
}

type simulationFacts struct{ *postgres.RemediationStore }

func (f simulationFacts) ReadRemediationObservations(ctx context.Context, q application.RemediationObservationQuery) ([]domain.ConditionObservation, error) {
	q.Simulation = true
	return f.RemediationStore.ReadRemediationObservations(ctx, q)
}

type simulationExecutor struct {
	store   *postgres.RemediationStore
	catalog *remediation.Catalog
}

func (e simulationExecutor) Assurance() domain.AssuranceClass { return domain.AssuranceSimulated }
func (e simulationExecutor) Execute(ctx context.Context, u domain.ExecutionUnit, now time.Time) (domain.ExecutionResult, error) {
	if err := remediationrunner.ValidateExecutionUnit(e.catalog, u, now); err != nil {
		return domain.ExecutionResult{}, err
	}
	return e.store.SimulateRemediation(ctx, e.catalog, u, now)
}

type runtimeAuthorizer struct{ cluster domain.ClusterID }

func (a runtimeAuthorizer) AuthorizeRemediation(_ context.Context, r application.RemediationAuthorizationRequest) (application.RemediationAuthorizationDecision, error) {
	return application.RemediationAuthorizationDecision{Allowed: r.ClusterID == a.cluster && r.ActorID == "sherlock-remediator" && r.Tier == domain.MaxImplementedTier && r.Privilege == domain.MaxImplementedPrivilege, ReasonCode: "RUNTIME_IDENTITY"}, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	timer := time.NewTicker(r.cfg.PollInterval)
	defer timer.Stop()
	for {
		if _, err := r.RunOnce(ctx); err != nil {
			r.logger.Error("remediation.iteration_failed", "code", "ITERATION_FAILED")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func (r *Runtime) RunOnce(ctx context.Context) (progressed bool, runErr error) {
	started := time.Now()
	defer func() {
		if r.cfg.Observer != nil {
			code := iterationOutcome(runErr)
			if runErr != nil {
				r.cfg.Observer.RecordFailure(code)
			}
			r.cfg.Observer.RecordIteration(time.Since(started), code)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, r.cfg.Lease)
	defer cancel()
	var err error
	var cards []application.ProposeRemediationInput
	if r.cfg.Live {
		if err = r.store.ReconcilePendingCollectionRequests(ctx, r.cfg.ClusterID, r.cfg.Batch); err != nil {
			return false, err
		}
		if err = r.advanceScheduleInvestigations(ctx); err != nil {
			return false, err
		}
		cards, err = r.store.DiscoverLiveRemediationCards(ctx, r.cfg.ClusterID, r.cfg.Batch)
	} else {
		cards, err = r.store.DiscoverRemediationCards(ctx, r.cfg.ClusterID, r.cfg.Batch)
	}
	if err != nil {
		return false, err
	}
	for _, card := range cards {
		if _, err := r.service.ProposeRemediation(ctx, card); err != nil {
			if r.cfg.Observer != nil {
				r.cfg.Observer.RecordFailure(iterationOutcome(err))
			}
			r.logger.Warn("remediation.proposal_blocked", "action_card_id", card.ActionCardID, "code", "ADMISSION_DENIED")
		}
	}
	claim, err := r.store.ClaimRemediation(ctx, r.cfg.ClusterID, r.cfg.Owner, r.cfg.Lease)
	if err != nil || claim.RunID == "" {
		return false, err
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = r.store.ReleaseRemediation(releaseCtx, r.cfg.ClusterID, claim, r.cfg.PollInterval)
	}()
	current, err := r.store.RemediationClaimCurrent(ctx, r.cfg.ClusterID, claim)
	if err != nil {
		return false, err
	}
	if !current {
		return false, application.ErrRemediationLeaseInvalid
	}
	ctx = postgres.ContextWithRemediationSupervisorClaim(ctx, claim)
	id := claim.RunID
	loaded, found, err := r.store.LoadRemediationRun(ctx, r.cfg.ClusterID, id)
	if err != nil || !found {
		return false, err
	}
	if r.cfg.Live && loaded.LatestAttemptID != "" && !loaded.LatestReceipt &&
		(loaded.Run.State() == domain.RemediationCanaryExecuting || loaded.Run.State() == domain.RemediationRollingOut ||
			(loaded.Run.State() == domain.RemediationRollingBack && loaded.LatestStage == domain.RemediationStageRollback)) {
		if recovered, ok, recoverErr := r.store.RecoverCommittedLiveEffect(ctx, r.cfg.ClusterID, id, loaded.LatestAttemptID); recoverErr != nil {
			return false, recoverErr
		} else if ok {
			r.logger.Info("remediation.effect_recovered", "run_id", id, "state", recovered.State(), "attempt_id", loaded.LatestAttemptID)
			return true, nil
		}
	}
	if r.cfg.Live && loaded.LatestAttemptID != "" &&
		(loaded.Run.State() == domain.RemediationVerifying ||
			(loaded.Run.State() == domain.RemediationRollingBack && loaded.LatestStage != domain.RemediationStageRollback)) {
		if err := r.store.ReconcileCollectionRequest(ctx, r.cfg.ClusterID, id, loaded.LatestAttemptID); err != nil {
			return false, err
		}
	}
	actor := "sherlock-remediator"
	var result domain.RemediationRun
	switch loaded.Run.State() {
	case domain.RemediationProposed, domain.RemediationPolicyCheck:
		result, err = r.service.EvaluateRemediationPolicy(ctx, r.cfg.ClusterID, id, actor)
	case domain.RemediationPreflight:
		result, err = r.service.PreflightRemediation(ctx, r.cfg.ClusterID, id, actor)
	case domain.RemediationReady:
		result, err = r.service.DispatchRemediation(ctx, r.cfg.ClusterID, id, actor, r.cfg.Owner)
	case domain.RemediationVerifying:
		if loaded.WaveVerified && len(loaded.Run.Plan().NextRolloutWave(loaded.ExecutedTargets)) > 0 {
			result, err = r.service.DispatchRemediationWave(ctx, r.cfg.ClusterID, id, actor, r.cfg.Owner)
		} else {
			result, err = r.service.VerifyRemediation(ctx, r.cfg.ClusterID, id, actor)
		}
	case domain.RemediationRollingBack:
		if loaded.LatestStage == domain.RemediationStageRollback {
			if loaded.LatestReceipt {
				result, err = r.service.VerifyRemediationRollback(ctx, r.cfg.ClusterID, id, actor)
			} else {
				result, err = r.service.ContainRemediation(ctx, r.cfg.ClusterID, id, actor, "UNKNOWN_OUTCOME")
			}
		} else {
			result, err = r.service.RollbackRemediation(ctx, r.cfg.ClusterID, id, actor, r.cfg.Owner)
		}
	case domain.RemediationCanaryExecuting, domain.RemediationRollingOut:
		result, err = r.service.ContainRemediation(ctx, r.cfg.ClusterID, id, actor, "UNKNOWN_OUTCOME")
	default:
		return false, nil
	}
	if err != nil {
		var denied application.RemediationDeniedError
		if errors.As(err, &denied) || errors.Is(err, application.ErrRemediationForbidden) || errors.Is(err, application.ErrRemediationPlanUnauthorized) {
			if result.State().Terminal() {
				err = nil
			} else {
				result, err = r.service.ContainRemediation(ctx, r.cfg.ClusterID, id, actor, "AUTHORITY_REVOKED")
			}
		}
	}
	if err == nil {
		r.logger.Info("remediation.advanced", "run_id", id, "state", result.State(), "attempt_id", loaded.LatestAttemptID)
	}
	return true, err
}

func iterationOutcome(err error) string {
	if err == nil {
		return "ok"
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
		return "lock_timeout"
	}
	if errors.Is(err, postgres.ErrRemediationAuthorityBusy) {
		return "lock_timeout"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, application.ErrRemediationLeaseInvalid) {
		return "lease_fence"
	}
	if errors.Is(err, application.ErrRemediationConflict) {
		return "state_fence"
	}
	if errors.Is(err, application.ErrRemediationPlanUnauthorized) {
		return "signature_authority"
	}
	var denied application.RemediationDeniedError
	if errors.As(err, &denied) || errors.Is(err, application.ErrRemediationForbidden) {
		return "authority_refused"
	}
	return "iteration_error"
}

// advanceScheduleInvestigations uses the real persisted investigation controller;
// the deterministic planner can only read detector evidence and has no provider.
func (r *Runtime) advanceScheduleInvestigations(ctx context.Context) error {
	if err := r.store.DetectScheduleRepair(ctx, r.cfg.ClusterID, r.cfg.Batch); err != nil {
		return err
	}
	requests, err := r.store.PendingScheduleInvestigations(ctx, r.cfg.ClusterID, r.cfg.Batch)
	if err != nil {
		return err
	}
	planner, err := scheduleinvestigation.New(r.store)
	if err != nil {
		return err
	}
	controllerStore := r.store.InvestigationStore()
	controller, err := application.NewInvestigationController(controllerStore, planner, planner, platform.SystemClock{}, platform.RandomIDGenerator{})
	if err != nil {
		return err
	}
	for _, request := range requests {
		snapshot, _, err := controller.Start(ctx, application.StartInvestigationInput{Request: request})
		if err != nil {
			return err
		}
		if !snapshot.Investigation.Status().Terminal() {
			if _, err = controller.Advance(ctx, request.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

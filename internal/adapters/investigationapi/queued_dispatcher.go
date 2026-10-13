package investigationapi

import (
	"context"
	"fmt"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// DiagnosticRunEnqueuer creates a run and its work item. Creation is
// idempotent on the request's idempotency key: an exact replay returns the
// existing run rather than queueing a second execution, which is what makes
// re-dispatch after an investigator crash safe.
type DiagnosticRunEnqueuer interface {
	CreateDiagnosticRun(context.Context, domain.DiagnosticRun, domain.DiagnosticWorkID, application.DiagnosticAuditEvent) (domain.DiagnosticRun, bool, error)
}

// QueuedDispatcher is the join between the investigation loop and the pull
// transport. It enqueues a reviewed invocation and then reports the work as
// outstanding until the head node has recorded its result.
//
// Nothing here waits. Blocking would hold an investigator lease for the whole
// remote execution; instead the first call queues and returns the pending
// sentinel, the controller parks the investigation in AWAITING_EVIDENCE, and a
// later lease claim finds the finished result.
type QueuedDispatcher struct {
	runs        DiagnosticRunEnqueuer
	projections application.DiagnosticProjectionReader
	clock       application.Clock
	ids         application.IDGenerator
}

func NewQueuedDispatcher(runs DiagnosticRunEnqueuer, projections application.DiagnosticProjectionReader, clock application.Clock, ids application.IDGenerator) (*QueuedDispatcher, error) {
	if runs == nil || projections == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("queued diagnostic dispatcher dependencies are required")
	}
	return &QueuedDispatcher{runs: runs, projections: projections, clock: clock, ids: ids}, nil
}

func (dispatcher *QueuedDispatcher) DispatchDiagnostic(ctx context.Context, idempotencyKey string, request domain.DiagnosticRequest, plan commandpack.ExecutionPlan) (domain.DiagnosticAttemptResult, error) {
	if plan.RequiresPrivilege() {
		return domain.DiagnosticAttemptResult{}, fmt.Errorf("queued dispatcher cannot grant privilege")
	}
	// Look first. After a restart the run already exists, and re-creating it
	// would be a wasted write on every poll while the work is outstanding.
	projection, found, err := dispatcher.projections.GetDiagnosticRunProjection(ctx, request.ClusterID, request.RunID)
	if err != nil {
		return domain.DiagnosticAttemptResult{}, fmt.Errorf("read diagnostic run: %w", err)
	}
	if !found {
		if err := dispatcher.enqueue(ctx, request); err != nil {
			return domain.DiagnosticAttemptResult{}, err
		}
		return domain.DiagnosticAttemptResult{}, application.ErrInvestigationExecutionPending
	}
	if !projection.Status.Terminal() {
		return domain.DiagnosticAttemptResult{}, application.ErrInvestigationExecutionPending
	}
	return finishedAttempt(projection, request)
}

func (dispatcher *QueuedDispatcher) enqueue(ctx context.Context, request domain.DiagnosticRequest) error {
	// An unprivileged reviewed diagnostic needs no approval; that is what makes
	// the ECC gap closable without a privilege adapter.
	run, err := domain.NewDiagnosticRun(request, false)
	if err != nil {
		return fmt.Errorf("build diagnostic run: %w", err)
	}
	workValue, err := dispatcher.ids.NewID()
	if err != nil {
		return err
	}
	eventID, err := dispatcher.ids.NewID()
	if err != nil {
		return err
	}
	audit := application.DiagnosticAuditEvent{
		EventID: eventID, Kind: application.DiagnosticAuditStart, RunID: request.RunID, ClusterID: request.ClusterID,
		ActorID: request.RequestedBy, Outcome: "ALLOWED", DefinitionDigest: request.Definition.DefinitionDigest,
		TargetDigest: domain.DiagnosticTargetsDigest(request.Targets), OccurredAt: dispatcher.clock.Now().UTC(),
	}
	if _, _, err := dispatcher.runs.CreateDiagnosticRun(ctx, run, domain.DiagnosticWorkID("diagnostic-work-"+workValue), audit); err != nil {
		return fmt.Errorf("queue diagnostic run: %w", err)
	}
	return nil
}

// finishedAttempt rebuilds the attempt the head node recorded. The last attempt
// that carries a completion time is the outcome: earlier ones were retried.
func finishedAttempt(projection application.DiagnosticRunProjection, request domain.DiagnosticRequest) (domain.DiagnosticAttemptResult, error) {
	for index := len(projection.Attempts) - 1; index >= 0; index-- {
		attempt := projection.Attempts[index]
		if attempt.CompletedAt == nil || attempt.StartedAt == nil || attempt.PlanDigest == nil || len(attempt.Targets) == 0 {
			continue
		}
		result := domain.DiagnosticAttemptResult{
			WorkID: projection.WorkID, RunID: projection.RunID, Attempt: attempt.Attempt, RunnerID: attempt.RunnerID,
			PlanDigest: *attempt.PlanDigest, StartedAt: attempt.StartedAt.UTC(), CompletedAt: attempt.CompletedAt.UTC(),
			Targets: attempt.Targets,
		}
		if err := result.Validate(request.Targets); err != nil {
			return domain.DiagnosticAttemptResult{}, fmt.Errorf("stored diagnostic attempt does not cover the requested targets: %w", err)
		}
		return result, nil
	}
	// A terminal run with no usable attempt cannot be turned into evidence, and
	// silently reporting it as pending would park the investigation forever.
	return domain.DiagnosticAttemptResult{}, fmt.Errorf("diagnostic run %s reached %s with no recorded attempt", projection.RunID, projection.Status)
}

var _ DiagnosticDispatcher = (*QueuedDispatcher)(nil)

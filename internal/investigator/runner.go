// Package investigator runs durable AI investigations outside the HTTP API.
package investigator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/contextbudget"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationcontext"
)

type Lease struct {
	InvestigationID domain.InvestigationID
	Owner           string
	TokenHash       domain.SHA256
	Epoch           int64
}

type LeaseStore interface {
	Claim(context.Context, string, time.Time, time.Duration, int, int) (Lease, bool, error)
	Heartbeat(context.Context, Lease, time.Time, time.Duration) error
	// Release returns the claim at now and makes it claimable again at availableAt.
	Release(ctx context.Context, lease Lease, now, availableAt time.Time) error
}

type Advancer interface {
	Advance(context.Context, domain.InvestigationID) (application.InvestigationSnapshot, error)
	StopAfterFailure(context.Context, domain.InvestigationID, error) (application.InvestigationSnapshot, error)
}

type MemoryProjector interface {
	ProjectInvestigation(context.Context, domain.InvestigationID) error
}

type MemoryProjectionFailureRecorder interface {
	RecordProjectionFailure(context.Context, domain.InvestigationID, string, time.Time) error
}

type Config struct {
	WorkerID      string
	PollInterval  time.Duration
	LeaseDuration time.Duration
	MaxConcurrent int
	MaxGlobal     int
	MaxPerCluster int
	// FailureRetryDelay defers the next claim after a failure could not be
	// recorded durably, so a persistent defect does not become a hot loop.
	// Zero selects defaultFailureRetryDelay.
	FailureRetryDelay time.Duration
}

const defaultFailureRetryDelay = 30 * time.Second

type Runner struct {
	store      LeaseStore
	controller Advancer
	clock      application.Clock
	logger     *slog.Logger
	config     Config
	projector  MemoryProjector
}

func New(store LeaseStore, controller Advancer, clock application.Clock, config Config, loggers ...*slog.Logger) (*Runner, error) {
	if store == nil || controller == nil || clock == nil || config.WorkerID == "" || config.PollInterval <= 0 || config.LeaseDuration < 3*config.PollInterval || config.MaxConcurrent < 1 || config.MaxConcurrent > 128 || config.MaxGlobal < config.MaxConcurrent || config.MaxGlobal > 1024 || config.MaxPerCluster < 1 || config.MaxPerCluster > config.MaxGlobal {
		return nil, fmt.Errorf("investigator runner configuration is invalid")
	}
	if config.FailureRetryDelay < 0 || config.FailureRetryDelay > time.Hour {
		return nil, fmt.Errorf("investigator runner configuration is invalid")
	}
	if config.FailureRetryDelay == 0 {
		config.FailureRetryDelay = defaultFailureRetryDelay
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if len(loggers) > 0 && loggers[0] != nil {
		logger = loggers[0]
	}
	return &Runner{store: store, controller: controller, clock: clock, logger: logger, config: config}, nil
}

func (runner *Runner) ConfigureMemoryProjection(projector MemoryProjector) error {
	if runner == nil || projector == nil {
		return fmt.Errorf("memory projector is required")
	}
	runner.projector = projector
	return nil
}

func (runner *Runner) Run(ctx context.Context) error {
	ticker := time.NewTicker(runner.config.PollInterval)
	defer ticker.Stop()
	completed := make(chan struct{}, runner.config.MaxConcurrent)
	var workers sync.WaitGroup
	active := 0
	defer workers.Wait()
	for {
		for active < runner.config.MaxConcurrent {
			lease, ok, err := runner.store.Claim(ctx, runner.config.WorkerID, runner.clock.Now(), runner.config.LeaseDuration, runner.config.MaxGlobal, runner.config.MaxPerCluster)
			if err != nil {
				return fmt.Errorf("claim investigation: %w", err)
			}
			if !ok {
				break
			}
			active++
			workers.Add(1)
			go func() { defer workers.Done(); runner.advance(ctx, lease); completed <- struct{}{} }()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case <-completed:
			active--
		}
	}
}

// advanceFailureReason classifies why an advance failed using only fixed
// enums that are already safe for durable audit. Without it every failure logs
// the same code, so an operator cannot separate a provider outage from a budget
// stop or a store failure, and cannot alert on a rising rejection rate.
func advanceFailureReason(err error) string {
	type safeReason interface{ SafeReasonCode() string }
	var classified safeReason
	if errors.As(err, &classified) {
		if reason := classified.SafeReasonCode(); reason != "" {
			return reason
		}
	}
	// Context admission failures are the ones live runs actually hit, and they
	// reported UNCLASSIFIED until an operator attached a debugger. Each sentinel
	// below is already a fixed reason code safe for durable audit.
	//
	// Evidence selection and provider preflight both spell their overflow
	// REQUIRED_CONTEXT_EXCEEDS_ALLOWANCE, so matching on text would conflate two
	// different failures with different fixes. Match the sentinel values and
	// report distinct codes: one means mandatory evidence outgrew the engine's
	// evidence allowance, the other that the assembled request outgrew the
	// provider input allowance.
	if errors.Is(err, investigationcontext.ErrRequiredContextTooLarge) {
		return "REQUIRED_EVIDENCE_EXCEEDS_ALLOWANCE"
	}
	for _, sentinel := range []error{
		contextbudget.ErrRequiredContextExceeded,
		contextbudget.ErrProspectiveRunBudget,
		contextbudget.ErrEstimatorUnderrun,
		investigationcontext.ErrContextTooLarge,
		investigationcontext.ErrCheckpointMismatch,
		investigationcontext.ErrEvidenceContextUnusable,
	} {
		if errors.Is(err, sentinel) {
			return sentinel.Error()
		}
	}
	if errors.Is(err, contextbudget.ErrAllowanceExceeded) {
		return "PROVIDER_INPUT_EXCEEDS_ALLOWANCE"
	}
	if errors.Is(err, domain.ErrInvestigationBudgetExceeded) {
		return "BUDGET_EXCEEDED"
	}
	if errors.Is(err, application.ErrInvestigationNotFound) {
		return "INVESTIGATION_NOT_FOUND"
	}
	return "UNCLASSIFIED"
}

// advanceFailureStage reports the safe workflow stage and durable state a
// failed transition carried, so a log line localizes the failure without
// exposing the underlying error text.
func advanceFailureStage(err error) (string, string) {
	var advance *application.InvestigationAdvanceError
	if errors.As(err, &advance) {
		return string(advance.Stage), string(advance.State)
	}
	return "", ""
}

func (runner *Runner) advance(ctx context.Context, lease Lease) {
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(runner.config.LeaseDuration / 3)
		defer ticker.Stop()
		for {
			select {
			case <-workCtx.Done():
				return
			case <-ticker.C:
				if err := runner.store.Heartbeat(workCtx, lease, runner.clock.Now(), runner.config.LeaseDuration); err != nil {
					if workCtx.Err() != nil {
						return
					}
					runner.logger.Error("investigator.heartbeat_failed", "investigation_id", lease.InvestigationID, "error_code", "LEASE_HEARTBEAT_FAILED")
					cancel()
					return
				}
			}
		}
	}()
	snapshot, err := runner.controller.Advance(workCtx, lease.InvestigationID)
	projectSnapshot := err == nil
	retryDelay := time.Duration(0)
	if err != nil && !errors.Is(err, application.ErrInvestigationConflict) && workCtx.Err() == nil {
		stage, state := advanceFailureStage(err)
		runner.logger.Error("investigator.advance_failed", "investigation_id", lease.InvestigationID, "error_code", "ADVANCE_FAILED", "reason_code", advanceFailureReason(err), "stage", stage, "durable_state", state)
		classified := application.ClassifyInvestigationFailure(err, advanceFailureReason(err))
		stopped, stopErr := runner.controller.StopAfterFailure(workCtx, lease.InvestigationID, classified)
		if stopErr != nil && !errors.Is(stopErr, application.ErrInvestigationConflict) {
			// The investigation is still non-terminal, so the next claim would hit
			// the same failure immediately. Defer it rather than spinning.
			retryDelay = runner.config.FailureRetryDelay
			runner.logger.Error("investigator.failure_record_failed", "investigation_id", lease.InvestigationID, "error_code", "FAILURE_RECORD_FAILED", "reason_code", advanceFailureReason(stopErr), "retry_after_seconds", int(retryDelay/time.Second))
		} else if stopErr == nil {
			snapshot = stopped
			projectSnapshot = true
		}
	}
	if projectSnapshot && snapshot.Investigation.Status().Terminal() && runner.projector != nil && workCtx.Err() == nil {
		if projectionErr := runner.projector.ProjectInvestigation(workCtx, lease.InvestigationID); projectionErr != nil {
			runner.logger.Error("investigator.memory_projection_failed", "investigation_id", lease.InvestigationID, "error_code", "MEMORY_PROJECTION_FAILED")
			if recorder, ok := runner.projector.(MemoryProjectionFailureRecorder); ok {
				if recordErr := recorder.RecordProjectionFailure(workCtx, lease.InvestigationID, "MEMORY_PROJECTION_FAILED", runner.clock.Now()); recordErr != nil {
					runner.logger.Error("investigator.memory_projection_failure_record_failed", "investigation_id", lease.InvestigationID, "error_code", "MEMORY_PROJECTION_FAILURE_RECORD_FAILED")
				}
			}
		}
	}
	cancel()
	<-heartbeatDone
	releaseCtx, releaseCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer releaseCancel()
	now := runner.clock.Now()
	if err := runner.store.Release(releaseCtx, lease, now, now.Add(retryDelay)); err != nil {
		runner.logger.Error("investigator.release_failed", "investigation_id", lease.InvestigationID, "error_code", "LEASE_RELEASE_FAILED")
	}
}

package collectorruntime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// CredentialTestExecutor runs the fixed head check. The fetch function
// retrieves the sudo password on demand; the executor calls it only after
// its own unprivileged and passwordless pre-checks have passed, and is
// responsible for clearing both its copy and the slice fetch returns.
type CredentialTestExecutor interface {
	Check(context.Context, domain.CredentialAccessTestPlan, int, func(context.Context) ([]byte, error)) domain.CredentialAccessTestResult
}

type CredentialTestWorkerConfig struct {
	CollectorID    domain.CollectorID
	ClaimWait      time.Duration
	RenewInterval  time.Duration
	BackoffMinimum time.Duration
	BackoffMaximum time.Duration
	Logger         *slog.Logger
}

// CredentialTestWorker is a separate claim loop for credential access tests.
// It has no journal on purpose: nothing about a test is worth replaying, and a
// lost result simply lets the lease expire so the control plane can retry or
// expire the test. It never writes the secret anywhere but the executor call.
type CredentialTestWorker struct {
	cfg      CredentialTestWorkerConfig
	client   CredentialTestControlClient
	executor CredentialTestExecutor
	clock    Clock
}

func NewCredentialTestWorker(cfg CredentialTestWorkerConfig, client CredentialTestControlClient, executor CredentialTestExecutor, clock Clock) (*CredentialTestWorker, error) {
	if cfg.CollectorID == "" || client == nil || executor == nil || clock == nil {
		return nil, fmt.Errorf("credential test worker dependencies are required")
	}
	if cfg.ClaimWait <= 0 || cfg.ClaimWait > 30*time.Second || cfg.RenewInterval <= 0 || cfg.RenewInterval > time.Minute || cfg.BackoffMinimum <= 0 || cfg.BackoffMaximum < cfg.BackoffMinimum {
		return nil, fmt.Errorf("credential test worker timing configuration is invalid")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &CredentialTestWorker{cfg: cfg, client: client, executor: executor, clock: clock}, nil
}

func (w *CredentialTestWorker) Run(ctx context.Context) error {
	backoff := w.cfg.BackoffMinimum
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		lease, err := w.client.ClaimCredentialTest(ctx, w.cfg.ClaimWait)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			w.cfg.Logger.Warn("collector.credential_test.claim_failed", "reason", "control plane claim failed")
			if err := wait(ctx, backoff); err != nil {
				return err
			}
			backoff = doubled(backoff, w.cfg.BackoffMaximum)
			continue
		}
		backoff = w.cfg.BackoffMinimum
		if lease == nil {
			continue
		}
		if err := w.process(ctx, *lease); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := wait(ctx, backoff); err != nil {
				return err
			}
			backoff = doubled(backoff, w.cfg.BackoffMaximum)
		}
	}
}

// process executes one leased test. Every step revalidates through the
// control plane: start, delivery and submission each carry the lease token,
// and delivery carries the plan digest computed locally from the claimed plan.
func (w *CredentialTestWorker) process(ctx context.Context, lease collectorcontrol.CredentialAccessTestLease) error {
	plan := lease.Plan
	ref := collectorcontrol.CredentialAccessTestRef{TestID: lease.TestID, Attempt: lease.Attempt, LeaseToken: lease.LeaseToken}
	logger := w.cfg.Logger.With("test_id", lease.TestID, "attempt", lease.Attempt, "credential_version", plan.CredentialVersion)
	if err := domain.ValidateCredentialAccessTestPlan(plan); err != nil || plan.TestID != lease.TestID {
		logger.Warn("collector.credential_test.plan_invalid")
		return errors.New("invalid credential test claim")
	}
	digest, err := domain.CredentialAccessTestPlanDigest(plan)
	if err != nil {
		return err
	}
	if _, err := w.client.StartCredentialTest(ctx, ref); err != nil {
		logger.Warn("collector.credential_test.start_failed", "lease_lost", errors.Is(err, ErrLeaseLost))
		return err
	}
	deadline := plan.Deadline
	execution, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	renewed := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(w.cfg.RenewInterval)
		defer ticker.Stop()
		for {
			select {
			case <-execution.Done():
				renewed <- nil
				return
			case <-ticker.C:
				if _, err := w.client.RenewCredentialTest(execution, ref); err != nil {
					cancel()
					renewed <- err
					return
				}
			}
		}
	}()
	started := w.clock.Now().UTC()
	// fetchErr captures the terminal cause of a failed fetch so the worker
	// can distinguish a lost lease (no result submitted, delivery refused)
	// from any other fetch failure (which the executor turns into a
	// CREDENTIAL_UNAVAILABLE result that is submitted normally). The
	// executor calls this closure only after its own pre-checks pass; it
	// owns clearing both its copy and the slice this returns.
	var fetchErr error
	fetch := func(fetchCtx context.Context) ([]byte, error) {
		delivery, err := w.fetchCredential(fetchCtx, ref, digest)
		if err != nil {
			fetchErr = err
			return nil, err
		}
		if delivery.Username != plan.Username || (delivery.Host != "" && delivery.Host != plan.Host) || delivery.CredentialVersion != plan.CredentialVersion {
			delivery.Destroy()
			err := errors.New("delivered credential metadata did not match the claimed plan")
			fetchErr = err
			return nil, err
		}
		return delivery.SudoPassword, nil
	}
	result := w.executor.Check(execution, plan, lease.Attempt, fetch)
	cancel()
	renewErr := <-renewed
	if errors.Is(fetchErr, ErrLeaseLost) {
		logger.Warn("collector.credential_test.delivery_refused")
		return fetchErr
	}
	if renewErr != nil {
		logger.Warn("collector.credential_test.lease_lost_during_execution")
		return renewErr
	}
	if err := domain.ValidateCredentialAccessTestResultForPlan(result, plan, lease.Attempt); err != nil {
		result = w.failed(plan, lease.Attempt, digest, started, domain.CredentialAccessInternal, "The head produced a result that failed local contract validation.")
	}
	completion, err := w.submit(ctx, ref, result)
	if err != nil {
		logger.Warn("collector.credential_test.submit_failed", "outcome", string(result.Outcome), "lease_lost", errors.Is(err, ErrLeaseLost))
		return err
	}
	logger.Info("collector.credential_test.completed", "outcome", string(result.Outcome), "status", string(completion.Status), "rejected", completion.Rejected, "duration_ms", w.clock.Now().Sub(started).Milliseconds())
	return nil
}

func (w *CredentialTestWorker) fetchCredential(ctx context.Context, ref collectorcontrol.CredentialAccessTestRef, digest domain.SHA256) (*CredentialDelivery, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		delivery, err := w.client.FetchCredential(ctx, ref, digest)
		if err == nil {
			return delivery, nil
		}
		lastErr = err
		if errors.Is(err, ErrLeaseLost) || ctx.Err() != nil {
			return nil, err
		}
		if err := wait(ctx, w.cfg.BackoffMinimum); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func (w *CredentialTestWorker) submit(ctx context.Context, ref collectorcontrol.CredentialAccessTestRef, result domain.CredentialAccessTestResult) (collectorcontrol.CredentialTestCompletion, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		completion, err := w.client.SubmitCredentialTestResult(ctx, ref, result)
		if err == nil {
			return completion, nil
		}
		lastErr = err
		if errors.Is(err, ErrLeaseLost) || ctx.Err() != nil {
			return collectorcontrol.CredentialTestCompletion{}, err
		}
		if err := wait(ctx, w.cfg.BackoffMinimum); err != nil {
			return collectorcontrol.CredentialTestCompletion{}, err
		}
	}
	return collectorcontrol.CredentialTestCompletion{}, lastErr
}

func (w *CredentialTestWorker) failed(plan domain.CredentialAccessTestPlan, attempt int, digest domain.SHA256, started time.Time, outcome domain.CredentialAccessOutcome, summary string) domain.CredentialAccessTestResult {
	completed := w.clock.Now().UTC()
	if completed.Before(started) {
		completed = started
	}
	return domain.CredentialAccessTestResult{SchemaVersion: domain.CredentialAccessTestSchemaVersion, TestID: plan.TestID, Attempt: attempt, PlanDigest: digest.String(), Outcome: outcome, Summary: domain.SanitizeCredentialAccessText(summary, domain.CredentialAccessTestMaxSummary), StartedAt: started, CompletedAt: completed, Checks: []domain.CredentialAccessCheck{}}
}

package collectorruntime

import (
	"context"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// TypedControlClient shares heartbeat identity and durable lease authority
// with v1. It exposes no diagnostic, command-pack or repair execution methods.
type TypedControlClient interface {
	ClaimTyped(context.Context, ClaimRequest) (*domain.TypedWorkLease, error)
	StartTyped(context.Context, LeaseRef) error
	RenewTyped(context.Context, LeaseRef) (time.Time, error)
	SubmitTyped(context.Context, LeaseRef, domain.TypedCollectorResult) error
}

func (r *Runtime) processTyped(ctx context.Context, lease domain.TypedWorkLease) error {
	if r.typedExecutor == nil || r.typedClient == nil {
		return fmt.Errorf("typed receipt requires configured typed runtime")
	}
	if err := domain.ValidateTypedWorkLease(lease); err != nil || lease.Lease.CollectorID != r.cfg.CollectorID {
		return fmt.Errorf("invalid typed claim")
	}
	entry, existed, err := r.journal.beginTyped(lease)
	if err != nil {
		return err
	}
	if entry.TypedResult != nil {
		return r.deliverTyped(ctx, lease, *entry.TypedResult)
	}
	var result domain.TypedCollectorResult
	if existed && entry.State == journalStarted {
		result = application.FailedTypedCollection(lease, r.clock.Now(), domain.FailureInternal, "collector restarted after typed execution began; result unavailable")
	} else {
		ref := leaseReference(lease.Lease)
		if err := r.typedClient.StartTyped(ctx, ref); err != nil {
			return err
		}
		if err := r.journal.markStarted(lease.Plan.RunID); err != nil {
			return err
		}
		execution, cancel := context.WithDeadline(ctx, lease.Plan.Deadline)
		renewed := make(chan error, 1)
		go func() {
			ticker := time.NewTicker(r.cfg.RenewInterval)
			defer ticker.Stop()
			for {
				select {
				case <-execution.Done():
					renewed <- nil
					return
				case <-ticker.C:
					if _, err := r.typedClient.RenewTyped(execution, ref); err != nil {
						cancel()
						renewed <- err
						return
					}
				}
			}
		}()
		result = r.typedExecutor.ExecuteTyped(execution, lease)
		cancel()
		err = <-renewed
	}
	if validation := domain.ValidateTypedResultForLease(result, lease); validation != nil {
		result = application.FailedTypedCollection(lease, r.clock.Now(), domain.FailureInternal, "typed collection result failed local validation")
	}
	if storeErr := r.journal.storeTypedResult(result); storeErr != nil {
		return storeErr
	}
	if err != nil {
		return err
	}
	return r.deliverTyped(ctx, lease, result)
}

func (r *Runtime) deliverTyped(ctx context.Context, lease domain.TypedWorkLease, result domain.TypedCollectorResult) error {
	if err := domain.ValidateTypedResultForLease(result, lease); err != nil {
		return fmt.Errorf("typed journal result does not match lease")
	}
	if err := r.typedClient.SubmitTyped(ctx, leaseReference(lease.Lease), result); err != nil {
		return err
	}
	return r.journal.markFinalized(lease.Plan.RunID)
}

func pendingTypedLease(collector domain.CollectorID, entry journalEntry) domain.TypedWorkLease {
	lease := pendingLease(collector, entry)
	lease.LeaseExpires = entry.Task.Deadline
	return domain.TypedWorkLease{Lease: lease, Plan: *entry.TypedPlan}
}

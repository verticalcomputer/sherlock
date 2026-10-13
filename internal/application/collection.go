package application

import (
	"context"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type Clock interface {
	Now() time.Time
}

type IDGenerator interface {
	NewID() (string, error)
}

type CollectionExecutor interface {
	Execute(context.Context, domain.CollectionTask) domain.CollectionResult
}

// CollectionOperationRegistry routes v1 work only to reviewed operations that
// were selected in local configuration. It is intentionally vendor-neutral:
// composition roots provide source-specific executors.
type CollectionOperationRegistry struct {
	executors map[domain.CollectionOperationID]CollectionExecutor
	clock     Clock
}

func NewCollectionOperationRegistry(operations []domain.CollectionOperationID, adapters map[domain.CollectionSourceKind]CollectionExecutor, clock Clock) (*CollectionOperationRegistry, error) {
	if len(operations) == 0 || clock == nil {
		return nil, fmt.Errorf("collection operations and clock are required")
	}
	executors := make(map[domain.CollectionOperationID]CollectionExecutor, len(operations))
	for _, id := range operations {
		operation, ok := domain.ReviewedCollectionOperation(id)
		if !ok {
			return nil, fmt.Errorf("unknown collection operation %q", id)
		}
		if _, duplicate := executors[id]; duplicate {
			return nil, fmt.Errorf("duplicate collection operation %q", id)
		}
		executor := adapters[operation.Source]
		if executor == nil {
			return nil, fmt.Errorf("collection operation %q has no locally configured %s adapter", id, operation.Source)
		}
		executors[id] = executor
	}
	return &CollectionOperationRegistry{executors: executors, clock: clock}, nil
}

func (r *CollectionOperationRegistry) Execute(ctx context.Context, task domain.CollectionTask) domain.CollectionResult {
	operation, ok := domain.CollectionOperationForQuery(task.Query)
	if ok {
		if executor := r.executors[operation.ID]; executor != nil {
			return executor.Execute(ctx, task)
		}
	}
	now := r.clock.Now().UTC()
	return domain.CollectionResult{
		Task: task, Status: domain.ResultFailed, StartedAt: now, CompletedAt: now,
		Coverage: domain.Coverage{Complete: false},
		Failures: []domain.CollectionFailure{{Code: domain.FailureInvalidArgument, Message: "collection operation is not locally enabled"}},
	}
}

type CollectionStore interface {
	RecordResult(context.Context, domain.CollectionResult) (bool, error)
}

type Collector struct {
	executor   CollectionExecutor
	store      CollectionStore
	clock      Clock
	maxRetries int
	backoff    time.Duration
}

func NewCollector(executor CollectionExecutor, store CollectionStore, clock Clock, maxRetries int, backoff time.Duration) (*Collector, error) {
	if executor == nil || store == nil || clock == nil {
		return nil, fmt.Errorf("collector dependencies are required")
	}
	if maxRetries < 0 || maxRetries > 2 {
		return nil, fmt.Errorf("maximum retries must be between 0 and 2")
	}
	if backoff < 0 {
		return nil, fmt.Errorf("retry backoff cannot be negative")
	}
	return &Collector{executor: executor, store: store, clock: clock, maxRetries: maxRetries, backoff: backoff}, nil
}

type CollectOutcome struct {
	Result             domain.CollectionResult
	Attempts           int
	PreviouslyRecorded bool
}

func (c *Collector) Collect(ctx context.Context, task domain.CollectionTask) (CollectOutcome, error) {
	if err := validateTask(task); err != nil {
		return CollectOutcome{}, err
	}
	var result domain.CollectionResult
	attempts := 0
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		// Preserve the original failure when the shared deadline leaves no retry
		// budget. A new execution would only replace it with an expired-task error.
		if attempt > 0 && !task.Deadline.After(c.clock.Now()) {
			break
		}
		result = c.executor.Execute(ctx, task)
		attempts++
		if !shouldRetry(result) || attempt == c.maxRetries {
			break
		}
		delay := c.backoff * time.Duration(attempt+1)
		if !task.Deadline.After(c.clock.Now().Add(delay)) {
			break
		}
		if err := wait(ctx, delay); err != nil {
			return CollectOutcome{}, err
		}
	}
	inserted, err := c.store.RecordResult(ctx, result)
	if err != nil {
		return CollectOutcome{}, fmt.Errorf("record collection result for run %s: %w", task.RunID, err)
	}
	return CollectOutcome{Result: result, Attempts: attempts, PreviouslyRecorded: !inserted}, nil
}

func validateTask(task domain.CollectionTask) error {
	if task.RunID == "" || task.ClusterID == "" || task.SourceID == "" || task.IdempotencyKey == "" {
		return fmt.Errorf("collection task requires run, cluster, source, and idempotency identifiers")
	}
	if err := task.Query.Validate(); err != nil {
		return err
	}
	if task.MaxSeries < 1 || task.MaxSeries > 10_000 || task.MaxBytes < 1 || task.MaxBytes > 10<<20 {
		return fmt.Errorf("collection task limits are invalid")
	}
	if !task.Deadline.After(task.ScheduledFor) {
		return fmt.Errorf("collection deadline must be after its scheduled time")
	}
	if task.Range != nil {
		if task.Range.Start.IsZero() || task.Range.End.IsZero() || !task.Range.End.After(task.Range.Start) {
			return fmt.Errorf("collection range end must be after its start")
		}
		if task.Range.End.Sub(task.Range.Start) > 24*time.Hour || task.Range.Step < time.Second || task.Range.Step > time.Hour {
			return fmt.Errorf("collection range exceeds its duration or step bounds")
		}
	}
	return nil
}

func shouldRetry(result domain.CollectionResult) bool {
	if result.Status != domain.ResultFailed || len(result.Failures) == 0 {
		return false
	}
	for _, failure := range result.Failures {
		if !failure.Retryable {
			return false
		}
	}
	return true
}

func wait(ctx context.Context, delay time.Duration) error {
	if delay == 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

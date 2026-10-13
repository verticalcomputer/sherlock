package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type RemoteCollectionStore interface {
	EnqueueCollectionWork(context.Context, domain.CollectorWork) (bool, error)
	LoadFinalizedResultByRun(context.Context, domain.RunID) (domain.CollectionResult, bool, error)
}

// RemoteCollectionExecutor preserves the M1 CollectionExecutor contract while
// moving execution behind the durable outbound collector queue.
type RemoteCollectionExecutor struct {
	store        RemoteCollectionStore
	clock        Clock
	pollInterval time.Duration
}

func NewRemoteCollectionExecutor(store RemoteCollectionStore, clock Clock, pollInterval time.Duration) (*RemoteCollectionExecutor, error) {
	if store == nil || clock == nil {
		return nil, fmt.Errorf("remote collection dependencies are required")
	}
	if pollInterval < 10*time.Millisecond || pollInterval > time.Second {
		return nil, fmt.Errorf("remote collection poll interval must be between 10 milliseconds and one second")
	}
	return &RemoteCollectionExecutor{store: store, clock: clock, pollInterval: pollInterval}, nil
}

func (e *RemoteCollectionExecutor) Execute(ctx context.Context, task domain.CollectionTask) domain.CollectionResult {
	startedAt := e.clock.Now().UTC()
	if !task.Deadline.After(startedAt) {
		return remoteFailure(task, startedAt, startedAt, domain.FailureDeadlineExceeded, "collection deadline elapsed before collector assignment")
	}
	work := domain.CollectorWork{
		WorkID:        remoteWorkID(task),
		Task:          task,
		Status:        domain.WorkAvailable,
		AvailableAt:   startedAt,
		WorkExpiresAt: task.Deadline.UTC(),
	}
	if _, err := e.store.EnqueueCollectionWork(ctx, work); err != nil {
		return remoteFailure(task, startedAt, e.clock.Now().UTC(), domain.FailureCollectorUnavailable, "collector work could not be queued")
	}
	deadlineTimer := time.NewTimer(task.Deadline.Sub(startedAt))
	defer deadlineTimer.Stop()
	ticker := time.NewTicker(e.pollInterval)
	defer ticker.Stop()
	for {
		result, found, err := e.store.LoadFinalizedResultByRun(ctx, task.RunID)
		if err != nil {
			return remoteFailure(task, startedAt, e.clock.Now().UTC(), domain.FailureCollectorUnavailable, "collector result could not be read")
		}
		if found {
			return result
		}
		select {
		case <-ctx.Done():
			if result, found := e.loadAfterCancellation(task.RunID); found {
				return result
			}
			return remoteFailure(task, startedAt, e.clock.Now().UTC(), domain.FailureCollectorUnavailable, "collector result was not finalized before cancellation")
		case <-deadlineTimer.C:
			if result, found := e.loadAfterCancellation(task.RunID); found {
				return result
			}
			return remoteFailure(task, startedAt, e.clock.Now().UTC(), domain.FailureCollectorUnavailable, "collector result was not finalized before the deadline")
		case <-ticker.C:
		}
	}
}

func remoteWorkID(task domain.CollectionTask) domain.WorkID {
	digest := sha256.Sum256([]byte(string(task.RunID) + "\x00" + task.IdempotencyKey))
	return domain.WorkID("collection-" + hex.EncodeToString(digest[:]))
}

func (e *RemoteCollectionExecutor) loadAfterCancellation(runID domain.RunID) (domain.CollectionResult, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), e.pollInterval)
	defer cancel()
	result, found, err := e.store.LoadFinalizedResultByRun(ctx, runID)
	return result, found && err == nil
}

func remoteFailure(task domain.CollectionTask, startedAt, completedAt time.Time, code domain.FailureCode, message string) domain.CollectionResult {
	if completedAt.Before(startedAt) {
		completedAt = startedAt
	}
	return domain.CollectionResult{
		Task: task, Status: domain.ResultFailed, StartedAt: startedAt.UTC(), CompletedAt: completedAt.UTC(),
		Coverage: domain.Coverage{Complete: false},
		Failures: []domain.CollectionFailure{{Code: code, Retryable: code == domain.FailureCollectorUnavailable, Message: message}},
	}
}

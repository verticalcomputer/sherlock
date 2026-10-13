package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type remoteStoreStub struct {
	work       domain.CollectorWork
	inserted   bool
	enqueueErr error
	result     domain.CollectionResult
	found      bool
}

func (s *remoteStoreStub) EnqueueCollectionWork(_ context.Context, work domain.CollectorWork) (bool, error) {
	s.work = work
	return s.inserted, s.enqueueErr
}

func (s *remoteStoreStub) LoadFinalizedResultByRun(_ context.Context, _ domain.RunID) (domain.CollectionResult, bool, error) {
	return s.result, s.found, nil
}

func TestRemoteCollectionExecutorReturnsFinalizedResult(t *testing.T) {
	now := time.Now().UTC()
	task := validTask()
	task.ScheduledFor = now
	task.Deadline = now.Add(time.Minute)
	want := domain.CollectionResult{Task: task, Status: domain.ResultNoData, StartedAt: now, CompletedAt: now.Add(time.Second), Coverage: domain.Coverage{Complete: true}}
	store := &remoteStoreStub{inserted: true, result: want, found: true}
	executor, err := NewRemoteCollectionExecutor(store, fixedClock{now: now}, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	got := executor.Execute(context.Background(), task)
	if got.Status != want.Status || got.CompletedAt != want.CompletedAt {
		t.Fatalf("result=%+v", got)
	}
	if store.work.Task != task || store.work.WorkID != remoteWorkID(task) {
		t.Fatalf("queued work=%+v", store.work)
	}
}

func TestRemoteCollectionExecutorDoesNotReportDisconnectAsSourceFailure(t *testing.T) {
	now := time.Now().UTC()
	task := validTask()
	task.ScheduledFor = now
	task.Deadline = now.Add(time.Minute)
	store := &remoteStoreStub{enqueueErr: errors.New("database unavailable")}
	executor, _ := NewRemoteCollectionExecutor(store, fixedClock{now: now}, 10*time.Millisecond)
	result := executor.Execute(context.Background(), task)
	if result.Status != domain.ResultFailed || len(result.Failures) != 1 || result.Failures[0].Code != domain.FailureCollectorUnavailable || !result.Failures[0].Retryable {
		t.Fatalf("result=%+v", result)
	}
}

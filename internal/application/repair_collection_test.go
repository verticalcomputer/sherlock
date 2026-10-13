package application

import (
	"context"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type repairStoreStub struct {
	claim             RepairCollectionClaim
	claimed, finished int
}

func (s *repairStoreStub) ClaimRepairCollection(_ context.Context, _ domain.ClusterID, _ domain.SourceID, _ string, _ time.Duration) (RepairCollectionClaim, bool, error) {
	s.claimed++
	return s.claim, s.claimed == 1, nil
}
func (s *repairStoreStub) FinishRepairCollection(_ context.Context, claim RepairCollectionClaim, _ string) error {
	s.finished++
	if claim.RequestID != s.claim.RequestID {
		return context.Canceled
	}
	return nil
}

type repairExecutorStub struct{}

func (repairExecutorStub) Execute(_ context.Context, task domain.CollectionTask) domain.CollectionResult {
	return domain.CollectionResult{Task: task, Status: domain.ResultSucceeded, StartedAt: task.ScheduledFor, CompletedAt: task.ScheduledFor.Add(time.Second), Coverage: domain.Coverage{Complete: true}}
}

type repairResultStoreStub struct{}

func (repairResultStoreStub) RecordResult(context.Context, domain.CollectionResult) (bool, error) {
	return true, nil
}

func TestRepairCollectionWorkerUsesBoundTaskOnce(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	task := domain.CollectionTask{RunID: "repair-run", ClusterID: "cluster", SourceID: "source", Query: domain.QueryGPUUtilization, ScheduledFor: now, Deadline: now.Add(time.Minute), MaxSeries: 1, MaxBytes: 1, IdempotencyKey: "repair-key"}
	collector, err := NewCollector(repairExecutorStub{}, repairResultStoreStub{}, fixedClock{}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	store := &repairStoreStub{claim: RepairCollectionClaim{RequestID: "request", Task: task}}
	worker, err := NewRepairCollectionWorker(store, collector, "cluster", "source", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if progressed, err := worker.RunOnce(context.Background()); err != nil || !progressed {
		t.Fatalf("progressed=%v err=%v", progressed, err)
	}
	if store.finished != 1 {
		t.Fatalf("finished=%d", store.finished)
	}
	if progressed, err := worker.RunOnce(context.Background()); err != nil || progressed {
		t.Fatalf("replayed request: progressed=%v err=%v", progressed, err)
	}
}

package application

import (
	"context"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestCollectionOperationRegistryRoutesOnlyLocallyEnabledReviewedOperations(t *testing.T) {
	task := validTask()
	executor := &sequenceExecutor{results: []domain.CollectionResult{{Task: task, Status: domain.ResultSucceeded}}}
	registry, err := NewCollectionOperationRegistry(
		[]domain.CollectionOperationID{domain.OperationPrometheusSourceHealth},
		map[domain.CollectionSourceKind]CollectionExecutor{domain.CollectionSourcePrometheus: executor},
		fixedClock{now: task.ScheduledFor},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result := registry.Execute(context.Background(), task); result.Status != domain.ResultSucceeded || executor.calls != 1 {
		t.Fatalf("enabled operation result=%+v calls=%d", result, executor.calls)
	}
	task.Query = domain.QueryGPUXID
	result := registry.Execute(context.Background(), task)
	if result.Status != domain.ResultFailed || len(result.Failures) != 1 || result.Failures[0].Code != domain.FailureInvalidArgument || executor.calls != 1 {
		t.Fatalf("disabled operation result=%+v calls=%d", result, executor.calls)
	}
}

func TestCollectionOperationRegistryRejectsUnreviewedOrUnconfiguredAdapters(t *testing.T) {
	clock := fixedClock{now: time.Now().UTC()}
	if _, err := NewCollectionOperationRegistry([]domain.CollectionOperationID{"not-reviewed"}, map[domain.CollectionSourceKind]CollectionExecutor{}, clock); err == nil {
		t.Fatal("unreviewed operation was accepted")
	}
	if _, err := NewCollectionOperationRegistry([]domain.CollectionOperationID{domain.OperationPrometheusGPUXID}, map[domain.CollectionSourceKind]CollectionExecutor{}, clock); err == nil {
		t.Fatal("operation without local adapter was accepted")
	}
}

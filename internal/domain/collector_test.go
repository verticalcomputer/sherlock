package domain

import (
	"testing"
	"time"
)

func TestValidateCollectorWork(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	work := CollectorWork{
		WorkID: "work-1", Status: WorkAvailable, AvailableAt: now, WorkExpiresAt: now.Add(time.Minute),
		Task: CollectionTask{
			RunID: "run-1", ClusterID: "cluster-1", SourceID: "source-1",
			Query: QuerySourceHealth, ScheduledFor: now, Deadline: now.Add(10 * time.Second),
			MaxSeries: 10_000, MaxBytes: 10 << 20, IdempotencyKey: "collection/run-1",
		},
	}
	if err := ValidateCollectorWork(work); err != nil {
		t.Fatal(err)
	}
	work.WorkExpiresAt = now
	if err := ValidateCollectorWork(work); err == nil {
		t.Fatal("expected invalid work expiry")
	}
	work.WorkExpiresAt = now.Add(time.Minute)
	work.WorkID = "unsafe/work"
	if err := ValidateCollectorWork(work); err == nil {
		t.Fatal("expected a path-unsafe work identifier to be rejected")
	}
}

func TestCollectorStatesAreClosed(t *testing.T) {
	if err := CollectorStatus("CONNECTED").Validate(); err == nil {
		t.Fatal("expected unknown collector status to fail")
	}
	if !WorkSucceeded.Terminal() || WorkLeased.Terminal() {
		t.Fatal("unexpected work terminal classification")
	}
	if !AttemptExpired.Terminal() || AttemptStarted.Terminal() {
		t.Fatal("unexpected attempt terminal classification")
	}
}

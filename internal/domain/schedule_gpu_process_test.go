package domain

import (
	"testing"
	"time"
)

func TestGPUProcessScheduleRequiresPayloadByteBudget(t *testing.T) {
	base := DesiredSchedule{ScheduleKey: ScheduleKey{ClusterID: "cluster", SourceID: "source", Operation: OperationGPUProcessObservations}, Enabled: true, Mode: SchedulingDurable, Interval: 5 * time.Minute, Timeout: 2 * time.Minute, MaxTargets: 16, MaxBytes: 1 << 20}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bytes := range []int64{1, (1 << 20) - 1, (2 << 20) + 1} {
		candidate := base
		candidate.MaxBytes = bytes
		if err := candidate.Validate(); err == nil {
			t.Fatalf("GPU process byte budget %d accepted", bytes)
		}
	}
	for _, targets := range []int{GPUProcessMaxRecords + 1, 10000} {
		candidate := base
		candidate.MaxTargets = targets
		candidate.MaxBytes = 2 << 20
		if err := candidate.Validate(); err == nil {
			t.Fatalf("GPU process record budget %d accepted", targets)
		}
	}
	underBudget := base
	underBudget.MaxTargets = 4096
	underBudget.MaxBytes = GPUProcessBaseBytes + GPUProcessBytesPerRecord*int64(underBudget.MaxTargets) - 1
	if err := underBudget.Validate(); err == nil {
		t.Fatal("GPU process schedule accepted an under-sized byte budget")
	}
	exactBudget := underBudget
	exactBudget.MaxBytes++
	if err := exactBudget.Validate(); err != nil {
		t.Fatalf("exact GPU process byte budget rejected: %v", err)
	}
}

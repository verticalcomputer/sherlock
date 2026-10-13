package application

import (
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestEvaluateProgressWindow(t *testing.T) {
	start := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	job := domain.JobIdentity{SchedulerNamespace: "slurm", JobID: "42", SubmitAt: start.Add(-time.Hour), Attempt: 1}
	sample := func(at time.Time, value float64, epoch string, run string) ProgressSampleRecord {
		return ProgressSampleRecord{TemplateID: "trainer.images", TemplateRevision: 1,
			Observation: domain.ProgressObservation{SchemaVersion: 1, ClusterID: "cluster", SourceID: "source", Job: job,
				Cohort: "resnet", State: domain.ProgressMeasured, Unit: "images", Committed: &value, ResetEpoch: domain.ProgressResetEpoch(epoch),
				SourceAt: at, EffectiveAt: at, ObservedAt: at}, Receipts: []ProgressReceipt{{RunID: run, ObservedAt: at}}}
	}
	allocation := func(from, to time.Time, count int, key string) ProgressAllocationInterval {
		return ProgressAllocationInterval{ClusterID: "cluster", SourceID: "scheduler", Job: job, SnapshotKey: key, ObservedAt: from, Start: from, End: to,
			State: domain.AllocationRunning, GPUCount: count}
	}
	base := ProgressWindowInput{ClusterID: "cluster", SourceID: "source", AllocationSourceID: "scheduler", Job: job, Start: start, End: start.Add(2 * time.Minute), MaxGap: time.Minute,
		Samples:     []ProgressSampleRecord{sample(start, 10, "a", "run-1"), sample(start.Add(time.Minute), 20, "a", "run-2"), sample(start.Add(2*time.Minute), 30, "a", "run-3")},
		Allocations: []ProgressAllocationInterval{allocation(start, start.Add(2*time.Minute), 2, "alloc-1")}}
	t.Run("measured and replay receipts", func(t *testing.T) {
		input := base
		input.Samples = append([]ProgressSampleRecord(nil), base.Samples...)
		input.Samples[0].Receipts = []ProgressReceipt{{RunID: "run-1b", ObservedAt: start}, {RunID: "run-1", ObservedAt: start}}
		result, err := EvaluateProgressWindow(input)
		if err != nil || result.Efficiency == nil || *result.Efficiency != 20.0/240.0 || *result.KnownDelta != 20 || *result.GPUSeconds != 240 || len(result.DeltaEvidence) != 2 || len(result.DeltaEvidence[0].FromRunIDs) != 2 || len(result.Quality) != 0 {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("stalled despite external utilization", func(t *testing.T) {
		input := base
		input.Samples = []ProgressSampleRecord{sample(start, 10, "a", "run-1"), sample(start.Add(time.Minute), 10, "a", "run-2"), sample(start.Add(2*time.Minute), 10, "a", "run-3")}
		result, err := EvaluateProgressWindow(input)
		if err != nil || result.Efficiency == nil || *result.Efficiency != 0 || !hasProgressQuality(result, ProgressStalled) {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("reset excludes crossing delta", func(t *testing.T) {
		input := base
		input.Samples = []ProgressSampleRecord{sample(start, 10, "a", "run-1"), sample(start.Add(time.Minute), 2, "b", "run-2"), sample(start.Add(2*time.Minute), 5, "b", "run-3")}
		result, err := EvaluateProgressWindow(input)
		if err != nil || result.Efficiency != nil || result.KnownDelta == nil || *result.KnownDelta != 3 || !hasProgressQuality(result, ProgressCounterReset) {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("rollback not negative work", func(t *testing.T) {
		input := base
		input.Samples = []ProgressSampleRecord{sample(start, 10, "a", "run-1"), sample(start.Add(time.Minute), 5, "a", "run-2"), sample(start.Add(2*time.Minute), 8, "a", "run-3")}
		result, err := EvaluateProgressWindow(input)
		if err != nil || result.Efficiency != nil || result.KnownDelta == nil || *result.KnownDelta != 3 || !hasProgressQuality(result, ProgressRollback) {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("missing interval refuses rate", func(t *testing.T) {
		input := base
		input.Samples = []ProgressSampleRecord{sample(start, 10, "a", "run-1"), sample(start.Add(2*time.Minute), 30, "a", "run-3")}
		result, err := EvaluateProgressWindow(input)
		if err != nil || result.Efficiency != nil || !hasProgressQuality(result, ProgressMissingInterval) {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("allocation changes are weighted", func(t *testing.T) {
		input := base
		input.Allocations = []ProgressAllocationInterval{allocation(start, start.Add(time.Minute), 2, "alloc-1"), allocation(start.Add(time.Minute), start.Add(2*time.Minute), 4, "alloc-2")}
		result, err := EvaluateProgressWindow(input)
		if err != nil || result.GPUSeconds == nil || *result.GPUSeconds != 360 || result.Efficiency == nil || !hasProgressQuality(result, ProgressAllocationChanged) || len(result.GPUEvidence) != 2 {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("allocation gap refuses denominator", func(t *testing.T) {
		input := base
		input.Allocations = []ProgressAllocationInterval{allocation(start, start.Add(time.Minute), 2, "alloc-1")}
		result, err := EvaluateProgressWindow(input)
		if err != nil || result.GPUSeconds != nil || result.Efficiency != nil || !hasProgressQuality(result, ProgressAllocationUnknown) {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("stale open allocation is not extrapolated", func(t *testing.T) {
		input := base
		input.End = start.Add(20 * time.Minute)
		input.MaxGap = 30 * time.Minute
		input.Samples = []ProgressSampleRecord{sample(start, 10, "a", "run-1"), sample(input.End, 30, "a", "run-2")}
		input.Allocations = []ProgressAllocationInterval{allocation(start, input.End, 2, "alloc-1")}
		result, err := EvaluateProgressWindow(input)
		if err != nil || result.GPUSeconds != nil || result.Efficiency != nil || !hasProgressQuality(result, ProgressAllocationUnknown) ||
			len(result.GPUEvidence) != 1 || !result.GPUEvidence[0].To.Equal(start.Add(ProgressAllocationFreshFor)) {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("unmeasured without instrumentation", func(t *testing.T) {
		input := base
		input.Samples = nil
		result, err := EvaluateProgressWindow(input)
		if err != nil || result.State != domain.ProgressUnmeasured || result.Efficiency != nil || !hasProgressQuality(result, ProgressMissingSamples) {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("mixed units and templates are refused", func(t *testing.T) {
		input := base
		input.Samples = append([]ProgressSampleRecord(nil), base.Samples...)
		input.Samples[1].TemplateRevision = 2
		input.Samples[1].Observation.Unit = "tokens"
		result, err := EvaluateProgressWindow(input)
		if err != nil || result.Efficiency != nil || !hasProgressQuality(result, ProgressIncompatibleSeries) {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
}

func hasProgressQuality(result ProgressWindowResult, quality ProgressQuality) bool {
	for _, flag := range result.Quality {
		if flag == quality {
			return true
		}
	}
	return false
}

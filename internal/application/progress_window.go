package application

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ProgressQuality records why a window cannot support an efficiency claim.
// Flags are retained even when a conservative partial numerator is available.
type ProgressQuality string

const (
	ProgressMissingSamples     ProgressQuality = "MISSING_SAMPLES"
	ProgressMissingInterval    ProgressQuality = "MISSING_INTERVAL"
	ProgressCounterReset       ProgressQuality = "COUNTER_RESET"
	ProgressRollback           ProgressQuality = "CHECKPOINT_ROLLBACK"
	ProgressIncompatibleSeries ProgressQuality = "INCOMPATIBLE_SERIES"
	ProgressAllocationUnknown  ProgressQuality = "ALLOCATION_UNKNOWN"
	ProgressAllocationChanged  ProgressQuality = "ALLOCATION_CHANGED"
	ProgressStalled            ProgressQuality = "STALLED"
)

// A five-minute scheduler snapshot cadence needs a bounded grace interval;
// an open-ended validity row is not proof that the job still owns GPUs.
const ProgressAllocationFreshFor = 10 * time.Minute

// ProgressAllocationInterval is the source-qualified allocation valid for a
// bounded interval. GPUCount counts distinct physical GPUs, not processes.
type ProgressAllocationInterval struct {
	ClusterID           domain.ClusterID
	SourceID            domain.SourceID
	Job                 domain.JobIdentity
	SnapshotKey         string
	InventoryRevisionID domain.InventoryRevisionID
	ObservedAt          time.Time
	Start               time.Time
	End                 time.Time
	State               domain.AllocationState
	GPUCount            int
}

type ProgressWindowInput struct {
	ClusterID          domain.ClusterID
	SourceID           domain.SourceID
	AllocationSourceID domain.SourceID
	Job                domain.JobIdentity
	Start              time.Time
	End                time.Time
	MaxGap             time.Duration
	Samples            []ProgressSampleRecord
	Allocations        []ProgressAllocationInterval
}

type ProgressDeltaProvenance struct {
	FromRunIDs []string  `json:"from_run_ids"`
	ToRunIDs   []string  `json:"to_run_ids"`
	From       time.Time `json:"from"`
	To         time.Time `json:"to"`
	Delta      float64   `json:"delta"`
}

type ProgressAllocationProvenance struct {
	SnapshotKey         string                     `json:"snapshot_key"`
	InventoryRevisionID domain.InventoryRevisionID `json:"inventory_revision_id,omitempty"`
	From                time.Time                  `json:"from"`
	To                  time.Time                  `json:"to"`
	GPUCount            int                        `json:"gpu_count"`
}

// ProgressWindowResult does not turn unknown time into zero work. Efficiency
// is present only when both progress and allocation cover the entire window.
type ProgressWindowResult struct {
	State         domain.ProgressState           `json:"state"`
	Cohort        domain.ProgressCohort          `json:"cohort,omitempty"`
	Unit          domain.ProgressUnit            `json:"unit,omitempty"`
	KnownDelta    *float64                       `json:"known_delta,omitempty"`
	GPUSeconds    *float64                       `json:"gpu_seconds,omitempty"`
	Efficiency    *float64                       `json:"committed_per_gpu_second,omitempty"`
	Quality       []ProgressQuality              `json:"quality"`
	DeltaEvidence []ProgressDeltaProvenance      `json:"delta_evidence"`
	GPUEvidence   []ProgressAllocationProvenance `json:"gpu_evidence"`
}

func EvaluateProgressWindow(input ProgressWindowInput) (ProgressWindowResult, error) {
	if input.ClusterID == "" || input.SourceID == "" || input.Start.IsZero() || !input.End.After(input.Start) ||
		input.End.Sub(input.Start) > 24*time.Hour || input.MaxGap <= 0 || input.MaxGap > time.Hour {
		return ProgressWindowResult{}, fmt.Errorf("invalid progress window or sampling gap")
	}
	job, err := domain.CreateJobIdentity(input.Job)
	if err != nil {
		return ProgressWindowResult{}, err
	}
	result := ProgressWindowResult{State: domain.ProgressUnmeasured, Quality: []ProgressQuality{}, DeltaEvidence: []ProgressDeltaProvenance{}, GPUEvidence: []ProgressAllocationProvenance{}}
	flags := map[ProgressQuality]bool{}
	addFlag := func(flag ProgressQuality) { flags[flag] = true }
	samples := append([]ProgressSampleRecord(nil), input.Samples...)
	sort.Slice(samples, func(i, j int) bool {
		return samples[i].Observation.EffectiveAt.Before(samples[j].Observation.EffectiveAt)
	})
	progressComplete := len(samples) >= 2
	if !progressComplete {
		addFlag(ProgressMissingSamples)
	}
	var templateID string
	var templateRevision int
	for index, sample := range samples {
		o, err := domain.CreateProgressObservation(sample.Observation)
		if err != nil || o.ClusterID != input.ClusterID || o.SourceID != input.SourceID || o.Job != job ||
			o.EffectiveAt.Before(input.Start) || o.EffectiveAt.After(input.End) || len(sample.Receipts) == 0 {
			return ProgressWindowResult{}, fmt.Errorf("progress sample lies outside its source, attempt, or window")
		}
		if index == 0 {
			result.Cohort, result.Unit = o.Cohort, o.Unit
			templateID, templateRevision = sample.TemplateID, sample.TemplateRevision
		}
		if sample.TemplateID != templateID || sample.TemplateRevision != templateRevision || o.Cohort != result.Cohort ||
			(index > 0 && o.EffectiveAt.Equal(samples[index-1].Observation.EffectiveAt)) {
			addFlag(ProgressIncompatibleSeries)
			progressComplete = false
		}
		if o.State != domain.ProgressMeasured || (index > 0 && o.Unit != result.Unit) {
			addFlag(ProgressMissingSamples)
			progressComplete = false
		}
	}
	if len(samples) > 0 && (!samples[0].Observation.EffectiveAt.Equal(input.Start) || !samples[len(samples)-1].Observation.EffectiveAt.Equal(input.End)) {
		addFlag(ProgressMissingInterval)
		progressComplete = false
	}
	known := 0.0
	for index := 1; index < len(samples); index++ {
		previous, current := samples[index-1].Observation, samples[index].Observation
		if !current.EffectiveAt.After(previous.EffectiveAt) || current.EffectiveAt.Sub(previous.EffectiveAt) > input.MaxGap {
			addFlag(ProgressMissingInterval)
			progressComplete = false
			continue
		}
		if previous.State != domain.ProgressMeasured || current.State != domain.ProgressMeasured || flags[ProgressIncompatibleSeries] {
			continue
		}
		if previous.ResetEpoch != current.ResetEpoch {
			addFlag(ProgressCounterReset)
			progressComplete = false
			continue
		}
		if *current.Committed < *previous.Committed {
			addFlag(ProgressRollback)
			progressComplete = false
			continue
		}
		delta := *current.Committed - *previous.Committed
		if math.IsInf(delta, 0) || math.IsNaN(delta) {
			return ProgressWindowResult{}, fmt.Errorf("progress delta exceeds finite range")
		}
		known += delta
		if math.IsInf(known, 0) || math.IsNaN(known) {
			return ProgressWindowResult{}, fmt.Errorf("progress window total exceeds finite range")
		}
		result.DeltaEvidence = append(result.DeltaEvidence, ProgressDeltaProvenance{
			FromRunIDs: progressRunIDs(samples[index-1].Receipts), ToRunIDs: progressRunIDs(samples[index].Receipts),
			From: previous.EffectiveAt, To: current.EffectiveAt, Delta: delta,
		})
	}
	if len(result.DeltaEvidence) > 0 {
		result.State = domain.ProgressMeasured
		result.KnownDelta = &known
	}
	if progressComplete && known == 0 {
		addFlag(ProgressStalled)
	}
	allocations := append([]ProgressAllocationInterval(nil), input.Allocations...)
	sort.Slice(allocations, func(i, j int) bool { return allocations[i].Start.Before(allocations[j].Start) })
	allocationComplete := len(allocations) > 0
	cursor := input.Start
	gpuSeconds := 0.0
	lastCount := -1
	for _, allocation := range allocations {
		if input.AllocationSourceID == "" || allocation.ClusterID != input.ClusterID || allocation.SourceID != input.AllocationSourceID || allocation.Job != job || allocation.SnapshotKey == "" || allocation.ObservedAt.IsZero() ||
			allocation.Start.Before(input.Start) || allocation.End.After(input.End) || !allocation.End.After(allocation.Start) ||
			allocation.GPUCount < 0 {
			return ProgressWindowResult{}, fmt.Errorf("invalid allocation interval")
		}
		if !allocation.Start.Equal(cursor) {
			allocationComplete = false
			addFlag(ProgressAllocationUnknown)
		}
		effectiveEnd := allocation.End
		if freshnessEnd := allocation.ObservedAt.Add(ProgressAllocationFreshFor); effectiveEnd.After(freshnessEnd) {
			effectiveEnd = freshnessEnd
			allocationComplete = false
			addFlag(ProgressAllocationUnknown)
		}
		if !effectiveEnd.After(allocation.Start) {
			allocationComplete = false
			addFlag(ProgressAllocationUnknown)
			continue
		}
		cursor = effectiveEnd
		if allocation.State != domain.AllocationRunning || allocation.GPUCount == 0 {
			allocationComplete = false
			addFlag(ProgressAllocationUnknown)
			continue
		}
		if lastCount >= 0 && lastCount != allocation.GPUCount {
			addFlag(ProgressAllocationChanged)
		}
		lastCount = allocation.GPUCount
		gpuSeconds += effectiveEnd.Sub(allocation.Start).Seconds() * float64(allocation.GPUCount)
		result.GPUEvidence = append(result.GPUEvidence, ProgressAllocationProvenance{
			SnapshotKey: allocation.SnapshotKey, InventoryRevisionID: allocation.InventoryRevisionID,
			From: allocation.Start, To: effectiveEnd, GPUCount: allocation.GPUCount,
		})
	}
	if !cursor.Equal(input.End) {
		allocationComplete = false
		addFlag(ProgressAllocationUnknown)
	}
	if allocationComplete && !math.IsInf(gpuSeconds, 0) && gpuSeconds > 0 {
		result.GPUSeconds = &gpuSeconds
	}
	if progressComplete && allocationComplete && result.KnownDelta != nil && result.GPUSeconds != nil {
		value := known / gpuSeconds
		result.Efficiency = &value
	}
	for flag := range flags {
		result.Quality = append(result.Quality, flag)
	}
	sort.Slice(result.Quality, func(i, j int) bool { return result.Quality[i] < result.Quality[j] })
	return result, nil
}

func progressRunIDs(receipts []ProgressReceipt) []string {
	ids := make([]string, len(receipts))
	for i, receipt := range receipts {
		ids[i] = receipt.RunID
	}
	sort.Strings(ids)
	return ids
}

package domain

import (
	"errors"
	"fmt"
	"time"
)

type SchedulingMode string

const (
	SchedulingLegacy  SchedulingMode = "legacy"
	SchedulingDurable SchedulingMode = "durable"
)

var ErrScheduleRevision = errors.New("desired schedule revision conflict")

type ScheduleKey struct {
	ClusterID ClusterID
	SourceID  SourceID
	Operation CollectionOperationID
}

// DesiredSchedule describes revisioned intent. Durable admission additionally
// requires exact execution configuration and current collector readiness.
type DesiredSchedule struct {
	ScheduleKey
	Enabled    bool
	Mode       SchedulingMode
	Interval   time.Duration
	Timeout    time.Duration
	Jitter     time.Duration
	MaxTargets int
	MaxBytes   int64
	Priority   int
	Revision   int64
}

func (s DesiredSchedule) Validate() error {
	if s.ClusterID == "" || s.SourceID == "" {
		return fmt.Errorf("schedule requires cluster and source")
	}
	op, ok := ReviewedCollectionOperation(s.Operation)
	if !ok {
		return fmt.Errorf("schedule requires a reviewed operation")
	}
	if s.Mode != SchedulingLegacy && s.Mode != SchedulingDurable {
		return fmt.Errorf("schedule mode must be legacy or durable")
	}
	if s.Mode == SchedulingLegacy && op.Query == "" {
		return fmt.Errorf("legacy schedules require a Prometheus operation")
	}
	if s.Interval <= 0 || s.Interval%time.Second != 0 || s.Interval/time.Second > 2147483647 ||
		s.Timeout <= 0 || s.Timeout%time.Millisecond != 0 || s.Timeout > s.Interval ||
		s.Jitter < 0 || s.Jitter%time.Millisecond != 0 || s.Jitter >= s.Interval {
		return fmt.Errorf("invalid schedule interval, timeout or jitter")
	}
	if s.MaxTargets < 1 || s.MaxTargets > 10000 || s.MaxBytes < 1 || s.MaxBytes > 10<<20 || s.Priority < 0 || s.Priority > 100 || s.Revision < 0 {
		return fmt.Errorf("invalid schedule limits, priority or revision")
	}
	if s.Operation == OperationGPUProcessObservations && (s.Interval < 5*time.Minute || s.Timeout > 2*time.Minute || s.MaxBytes < 1<<20 || s.MaxBytes > 2<<20 || s.MaxTargets > GPUProcessMaxRecords) {
		return fmt.Errorf("GPU process polling requires a five-minute minimum interval, two-minute maximum occurrence and bounded output")
	}
	if s.Operation == OperationGPUProcessObservations && validateGPUProcessLimits(s.MaxTargets, s.MaxBytes) != nil {
		return fmt.Errorf("GPU process polling requires a bounded record and byte budget")
	}
	return nil
}

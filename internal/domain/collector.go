package domain

import (
	"fmt"
	"time"
)

type CollectorID string
type WorkID string

type CollectorStatus string

const (
	CollectorPending         CollectorStatus = "PENDING"
	CollectorActive          CollectorStatus = "ACTIVE"
	CollectorUpgradeRequired CollectorStatus = "UPGRADE_REQUIRED"
	CollectorRevoked         CollectorStatus = "REVOKED"
)

func (s CollectorStatus) Validate() error {
	switch s {
	case CollectorPending, CollectorActive, CollectorUpgradeRequired, CollectorRevoked:
		return nil
	default:
		return fmt.Errorf("unknown collector status %q", s)
	}
}

type WorkStatus string

const (
	WorkAvailable WorkStatus = "AVAILABLE"
	WorkLeased    WorkStatus = "LEASED"
	WorkSucceeded WorkStatus = "SUCCEEDED"
	WorkFailed    WorkStatus = "FAILED"
	WorkCancelled WorkStatus = "CANCELLED"
)

func (s WorkStatus) Terminal() bool {
	return s == WorkSucceeded || s == WorkFailed || s == WorkCancelled
}

func (s WorkStatus) Validate() error {
	switch s {
	case WorkAvailable, WorkLeased, WorkSucceeded, WorkFailed, WorkCancelled:
		return nil
	default:
		return fmt.Errorf("unknown work status %q", s)
	}
}

type AttemptStatus string

const (
	AttemptClaimed   AttemptStatus = "CLAIMED"
	AttemptStarted   AttemptStatus = "STARTED"
	AttemptSucceeded AttemptStatus = "SUCCEEDED"
	AttemptFailed    AttemptStatus = "FAILED"
	AttemptExpired   AttemptStatus = "EXPIRED"
	AttemptRejected  AttemptStatus = "REJECTED"
)

func (s AttemptStatus) Terminal() bool {
	return s == AttemptSucceeded || s == AttemptFailed || s == AttemptExpired || s == AttemptRejected
}

func (s AttemptStatus) Validate() error {
	switch s {
	case AttemptClaimed, AttemptStarted, AttemptSucceeded, AttemptFailed, AttemptExpired, AttemptRejected:
		return nil
	default:
		return fmt.Errorf("unknown attempt status %q", s)
	}
}

// CollectorWork is the transport-neutral form of work assigned to a cluster collector.
// CollectionTask remains unchanged so local and remote executors share its semantics.
type CollectorWork struct {
	WorkID        WorkID
	Task          CollectionTask
	Status        WorkStatus
	AvailableAt   time.Time
	WorkExpiresAt time.Time
}

type WorkLease struct {
	Work         CollectorWork
	CollectorID  CollectorID
	Attempt      int
	LeaseToken   string
	LeaseExpires time.Time
}

func ValidateCollectorWork(work CollectorWork) error {
	if !ValidCollectorWorkID(string(work.WorkID)) {
		return fmt.Errorf("collector work identifier is required")
	}
	if err := work.Status.Validate(); err != nil {
		return err
	}
	if work.AvailableAt.IsZero() || work.WorkExpiresAt.IsZero() || !work.WorkExpiresAt.After(work.AvailableAt) {
		return fmt.Errorf("collector work expiry must be after availability")
	}
	if work.Task.RunID == "" || work.Task.ClusterID == "" || work.Task.SourceID == "" || work.Task.IdempotencyKey == "" {
		return fmt.Errorf("collector work task identifiers are required")
	}
	if err := work.Task.Query.Validate(); err != nil {
		return err
	}
	if !work.Task.Deadline.After(work.Task.ScheduledFor) {
		return fmt.Errorf("collector work deadline must be after its scheduled time")
	}
	if work.Task.Range != nil {
		queryRange := work.Task.Range
		if queryRange.Start.IsZero() || queryRange.End.IsZero() || !queryRange.End.After(queryRange.Start) {
			return fmt.Errorf("collector work range end must be after its start")
		}
		if queryRange.End.Sub(queryRange.Start) > 24*time.Hour || queryRange.Step < time.Second || queryRange.Step > time.Hour {
			return fmt.Errorf("collector work range exceeds its duration or step bounds")
		}
	}
	if work.Task.MaxSeries < 1 || work.Task.MaxSeries > 10_000 || work.Task.MaxBytes < 1 || work.Task.MaxBytes > 10<<20 {
		return fmt.Errorf("collector work result limits are invalid")
	}
	return nil
}

func validControlID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '.' && character != '_' &&
			character != ':' && character != '-' {
			return false
		}
	}
	return true
}

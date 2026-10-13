// Package events provides the durable, cluster-scoped event stream consumed by
// the public API. PostgreSQL is the source of truth; callers may use WaitAfter
// to reduce empty reads, but correctness never depends on a notification.
package events

import (
	"context"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	CollectionUpdatedType = "collection.updated"
	SourceUpdatedType     = "source.updated"
	PayloadSchemaV1       = 1

	MaxPageSize = 100
	MaxWait     = 30 * time.Second
)

type ID uint64

// Payload is a closed set of versioned event payloads.
type Payload interface {
	eventType() string
	schemaVersion() int
	validate() error
}

type CollectionUpdatedV1 struct {
	RunID            domain.RunID        `json:"run_id"`
	SourceID         domain.SourceID     `json:"source_id"`
	Status           domain.ResultStatus `json:"status"`
	CompletedAt      time.Time           `json:"completed_at"`
	CoverageComplete bool                `json:"coverage_complete"`
}

func (CollectionUpdatedV1) eventType() string  { return CollectionUpdatedType }
func (CollectionUpdatedV1) schemaVersion() int { return PayloadSchemaV1 }
func (p CollectionUpdatedV1) validate() error {
	if p.RunID == "" || p.SourceID == "" {
		return fmt.Errorf("collection event run and source identifiers are required")
	}
	switch p.Status {
	case domain.ResultSucceeded, domain.ResultNoData, domain.ResultPartial, domain.ResultFailed:
	default:
		return fmt.Errorf("collection event status %q is invalid", p.Status)
	}
	if p.CompletedAt.IsZero() {
		return fmt.Errorf("collection event completion time is required")
	}
	return nil
}

type SourceAvailability string

const (
	SourceUnknown     SourceAvailability = "UNKNOWN"
	SourceAvailable   SourceAvailability = "AVAILABLE"
	SourceUnavailable SourceAvailability = "UNAVAILABLE"
)

type SourceUpdatedV1 struct {
	SourceID        domain.SourceID     `json:"source_id"`
	Availability    SourceAvailability  `json:"availability"`
	LastAttemptAt   time.Time           `json:"last_attempt_at"`
	LastSuccessAt   *time.Time          `json:"last_success_at,omitempty"`
	LastFailureCode *domain.FailureCode `json:"last_failure_code,omitempty"`
}

func (SourceUpdatedV1) eventType() string  { return SourceUpdatedType }
func (SourceUpdatedV1) schemaVersion() int { return PayloadSchemaV1 }
func (p SourceUpdatedV1) validate() error {
	if p.SourceID == "" || p.LastAttemptAt.IsZero() {
		return fmt.Errorf("source event identifier and attempt time are required")
	}
	switch p.Availability {
	case SourceUnknown, SourceAvailable, SourceUnavailable:
	default:
		return fmt.Errorf("source availability %q is invalid", p.Availability)
	}
	if p.LastSuccessAt != nil && p.LastSuccessAt.IsZero() {
		return fmt.Errorf("source last success time cannot be zero")
	}
	return nil
}

type Event struct {
	ClusterID     domain.ClusterID
	ID            ID
	Type          string
	SchemaVersion int
	CreatedAt     time.Time
	Payload       Payload
}

type Page struct {
	Events      []Event
	NextAfterID ID
	HasMore     bool
}

// Reader is the narrow API/SSE dependency. after is the Last-Event-ID and is
// exclusive. WaitAfter always performs a durable read before and after waits.
type Reader interface {
	ListAfter(context.Context, domain.ClusterID, ID, int) (Page, error)
	WaitAfter(context.Context, domain.ClusterID, ID, int, time.Duration) (Page, error)
}

// Appender is used by state-transition paths that do not already own a SQL
// transaction. Transactional paths should use Store.AppendTx.
type Appender interface {
	Append(context.Context, domain.ClusterID, Payload) (Event, error)
}

func validateRead(clusterID domain.ClusterID, limit int) error {
	if clusterID == "" {
		return fmt.Errorf("event cluster identifier is required")
	}
	if limit < 1 || limit > MaxPageSize {
		return fmt.Errorf("event page limit must be between 1 and %d", MaxPageSize)
	}
	return nil
}

package application

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ProgressOperation is reserved for reviewed, opt-in application counters.
// There is no runtime executor or production enrollment for it yet.
const ProgressOperation = "application.progress.v1"

// ProgressEvidence binds a source sample (or an explicit lack of one) to the
// exact collection run and reviewed template revision that produced it.
type ProgressEvidence struct {
	RunID            string
	TemplateID       string
	TemplateRevision int
	Observation      domain.ProgressObservation
}

func ValidateProgressEvidence(evidence ProgressEvidence) (ProgressEvidence, error) {
	if !validProgressIdentifier(evidence.RunID, 256) || !validProgressIdentifier(evidence.TemplateID, 128) || evidence.TemplateRevision < 1 {
		return ProgressEvidence{}, fmt.Errorf("progress run and template identity are required")
	}
	observation, err := domain.CreateProgressObservation(evidence.Observation)
	if err != nil {
		return ProgressEvidence{}, err
	}
	// PostgreSQL timestamptz stores microseconds. Canonicalizing at the
	// boundary makes a replay after a database round trip byte-identical.
	observation.Job.SubmitAt = observation.Job.SubmitAt.Truncate(time.Microsecond)
	observation.SourceAt = observation.SourceAt.Truncate(time.Microsecond)
	observation.EffectiveAt = observation.EffectiveAt.Truncate(time.Microsecond)
	observation.ObservedAt = observation.ObservedAt.Truncate(time.Microsecond)
	evidence.Observation = observation
	return evidence, nil
}

func validProgressIdentifier(value string, maxLength int) bool {
	if len(value) == 0 || len(value) > maxLength {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-", character) {
			return false
		}
	}
	return true
}

// ProgressSampleRecord is one canonical sample plus the runs that observed it.
// The result is a fact, not a goodput or allocation-efficiency calculation.
type ProgressSampleRecord struct {
	TemplateID       string
	TemplateRevision int
	Observation      domain.ProgressObservation
	Receipts         []ProgressReceipt
}

// ProgressReceipt preserves the time and run of each independent observation.
type ProgressReceipt struct {
	RunID      string    `json:"run_id"`
	ObservedAt time.Time `json:"observed_at"`
}

type ProgressStore interface {
	RecordProgressEvidence(context.Context, ProgressEvidence) (newSample bool, err error)
	ListProgressSamples(context.Context, domain.ClusterID, domain.SourceID, domain.JobIdentity, int) ([]ProgressSampleRecord, bool, error)
	ListProgressWindowSamples(context.Context, domain.ClusterID, domain.SourceID, domain.JobIdentity, time.Time, time.Time) ([]ProgressSampleRecord, error)
	ListProgressAllocationIntervals(context.Context, domain.ClusterID, domain.SourceID, domain.SourceID, domain.JobIdentity, time.Time, time.Time) ([]ProgressAllocationInterval, error)
}

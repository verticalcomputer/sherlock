package application

import (
	"context"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ProgressReader is deliberately read-only. A caller chooses both sources
// explicitly; a progress source cannot silently borrow another scheduler's
// most recent allocation for a similarly named job.
type ProgressReader interface {
	ListProgressWindowSamples(context.Context, domain.ClusterID, domain.SourceID, domain.JobIdentity, time.Time, time.Time) ([]ProgressSampleRecord, error)
	ListProgressAllocationIntervals(context.Context, domain.ClusterID, domain.SourceID, domain.SourceID, domain.JobIdentity, time.Time, time.Time) ([]ProgressAllocationInterval, error)
}

type ProgressQuery struct {
	ClusterID          domain.ClusterID
	SourceID           domain.SourceID
	AllocationSourceID domain.SourceID
	InventorySourceID  domain.SourceID
	Job                domain.JobIdentity
	Start              time.Time
	End                time.Time
	MaxGap             time.Duration
}

type ProgressService struct{ reader ProgressReader }

func NewProgressService(reader ProgressReader) (*ProgressService, error) {
	if reader == nil {
		return nil, fmt.Errorf("progress reader is required")
	}
	return &ProgressService{reader: reader}, nil
}

func (service *ProgressService) Evaluate(ctx context.Context, query ProgressQuery) (ProgressWindowResult, error) {
	if query.ClusterID == "" || query.SourceID == "" || query.AllocationSourceID == "" || query.InventorySourceID == "" || query.Start.IsZero() ||
		!query.End.After(query.Start) || query.End.Sub(query.Start) > 24*time.Hour || query.MaxGap <= 0 || query.MaxGap > time.Hour {
		return ProgressWindowResult{}, fmt.Errorf("invalid progress query")
	}
	job, err := domain.CreateJobIdentity(query.Job)
	if err != nil {
		return ProgressWindowResult{}, err
	}
	samples, err := service.reader.ListProgressWindowSamples(ctx, query.ClusterID, query.SourceID, job, query.Start, query.End)
	if err != nil {
		return ProgressWindowResult{}, err
	}
	allocations, err := service.reader.ListProgressAllocationIntervals(ctx, query.ClusterID, query.AllocationSourceID, query.InventorySourceID, job, query.Start, query.End)
	if err != nil {
		return ProgressWindowResult{}, err
	}
	return EvaluateProgressWindow(ProgressWindowInput{
		ClusterID: query.ClusterID, SourceID: query.SourceID, AllocationSourceID: query.AllocationSourceID,
		Job: job, Start: query.Start, End: query.End, MaxGap: query.MaxGap, Samples: samples, Allocations: allocations,
	})
}

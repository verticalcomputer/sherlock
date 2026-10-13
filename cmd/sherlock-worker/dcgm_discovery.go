package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// discoverDCGM is an explicit one-shot enrollment command. Collection follows
// the configured executor (including remote queue/lease); recurrence belongs
// exclusively to the existing revisioned scheduling authority.
func (r *runtime) discoverDCGM(ctx context.Context) error {
	for _, query := range domain.ExpandedDCGMQueries() {
		summary, err := r.collectOnce(ctx, query)
		if err != nil {
			return err
		}
		op, _ := domain.CollectionOperationForQuery(query)
		seed := domain.DesiredSchedule{ScheduleKey: domain.ScheduleKey{ClusterID: domain.ClusterID(r.cfg.ClusterID), SourceID: domain.SourceID(r.cfg.SourceID), Operation: op.ID}, Enabled: true, Mode: domain.SchedulingMode(r.cfg.SchedulingMode), Interval: r.cfg.CollectionInterval, Timeout: r.cfg.QueryTimeout, MaxTargets: r.cfg.MaxSeries, MaxBytes: r.cfg.MaxBytes}
		enrolled, err := r.store.EnrollDiscoveredDCGM(ctx, summary.RunID, seed, r.clock.Now())
		if err != nil {
			return err
		}
		_, coverage, err := r.store.DCGMCollectionState(ctx, domain.ClusterID(r.cfg.ClusterID), domain.SourceID(r.cfg.SourceID), summary.RunID)
		if err != nil {
			return err
		}
		counts := map[string]int{"SUPPORTED": 0, "UNKNOWN": 0, "NOT_SUPPORTED": 0}
		for _, field := range coverage.MetricFields {
			counts[field.State]++
		}
		if err = json.NewEncoder(os.Stdout).Encode(struct {
			safeSummary
			Enrolled bool           `json:"enrolled"`
			Fields   map[string]int `json:"field_assessments"`
		}{summary, enrolled, counts}); err != nil {
			return err
		}
	}
	return nil
}

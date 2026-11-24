package postgres

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
)

// Selecting the publication first prevents an older band from resurfacing when
// the newest snapshot lacks that GPU or load. Both timestamps fence hindsight.
const historicalBandSQL = `SELECT r.cutoff, b.median_c, b.p95_c, b.days, b.periods, b.samples, b.last_at
FROM (SELECT enrollment_id,cutoff FROM cooling_history.refresh JOIN cooling_history.available_refresh USING (enrollment_id,cutoff)
      WHERE enrollment_id=$1 AND cluster_id=$2 AND source_id=$3
        AND available_at <= $4 AND published_at <= $4 AND cutoff <= $4 ORDER BY cutoff DESC LIMIT 1) r
LEFT JOIN cooling_history.temperature_band b ON b.enrollment_id=r.enrollment_id
  AND b.cutoff=r.cutoff AND b.asset=$5 AND b.power_w=$6`

// UseDatabaseWarmingProfiles registers the optional reader without acquiring
// a connection. Historical data cannot delay urgent evaluation at startup.
func (s *ProductionAssessmentStore) UseDatabaseWarmingProfiles() {
	s.SetWarmingProfileLookup(s.databaseWarmingProfile)
}

func (s *ProductionAssessmentStore) databaseWarmingProfile(ctx context.Context, asset string, at time.Time, c cooling.WarmingContext) *cooling.HistoricalProfile {
	out := &cooling.HistoricalProfile{Status: "unavailable"}
	if c.ComparableLoad == nil || at.IsZero() {
		return out
	}
	w := c.ComparableLoad.PowerW
	if math.IsNaN(w) || math.IsInf(w, 0) || w <= 0 || w > 2000 {
		return out
	}
	out.CenterW = int(math.Round(w/25)) * 25
	ctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	cfg := s.config.Assessment
	var cutoff time.Time
	var last *time.Time
	var median, p95 *float64
	var days, periods, samples *int
	err := s.pool.QueryRow(ctx, historicalBandSQL, cfg.RunID, cfg.ClusterID, cfg.SourceID, at, asset, out.CenterW).Scan(&cutoff, &median, &p95, &days, &periods, &samples, &last)
	if errors.Is(err, pgx.ErrNoRows) {
		return out
	}
	if err != nil {
		out.Status = "lookup_error"
		return out
	}
	out.CutoffAgeDays = at.Sub(cutoff).Hours() / 24
	if median == nil {
		out.Status = "no_matching_band"
		return out
	}
	out.Days, out.Periods, out.Samples = *days, *periods, *samples
	out.LastAgeDays = at.Sub(*last).Hours() / 24
	switch {
	case out.Days < 3 || out.Periods < 3:
		out.Status = "sparse"
	case out.LastAgeDays > 7:
		out.Status = "stale"
	default:
		out.Status = "qualified"
		out.MedianC, out.P95C = median, p95
	}
	return out
}

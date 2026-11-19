package postgres

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"time"
)

type ProductionAssessmentStatus struct {
	EnrollmentID         string                            `json:"enrollment_id"`
	ClusterID            string                            `json:"cluster_id"`
	Revision             int64                             `json:"revision"`
	NotificationsEnabled bool                              `json:"notifications_enabled"`
	EnabledAt            *time.Time                        `json:"enabled_at,omitempty"`
	RetainedEvents       int64                             `json:"retained_events"`
	RetainedBytes        int64                             `json:"retained_bytes"`
	Assets               []ProductionAssessmentAssetStatus `json:"assets"`
}
type ProductionAssessmentAssetStatus struct {
	Asset         string     `json:"asset"`
	Revision      int64      `json:"revision"`
	NextDue       *time.Time `json:"next_due_at,omitempty"`
	LastAttempt   *time.Time `json:"last_attempt_at,omitempty"`
	LastFailure   string     `json:"last_failure_code"`
	LastFailureAt *time.Time `json:"last_failure_at,omitempty"`
	FailureCount  int64      `json:"failure_count"`
}

func ReadProductionAssessmentStatus(ctx context.Context, pool *pgxpool.Pool, cluster, enrollment string) (ProductionAssessmentStatus, error) {
	var s ProductionAssessmentStatus
	if pool == nil || !a.ValidID(cluster, 128) || !a.ValidID(enrollment, 128) {
		return s, a.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := pool.QueryRow(ctx, `SELECT enrollment_id,cluster_id,revision,notifications_enabled,notifications_enabled_at,retained_events,retained_bytes FROM production_assessment_enrollments WHERE cluster_id=$1 AND enrollment_id=$2`, cluster, enrollment).Scan(&s.EnrollmentID, &s.ClusterID, &s.Revision, &s.NotificationsEnabled, &s.EnabledAt, &s.RetainedEvents, &s.RetainedBytes)
	if err != nil {
		return s, err
	}
	rows, err := pool.Query(ctx, `SELECT asset,revision,next_due_at,last_attempt_at,last_failure_code,last_failure_at,failure_count FROM production_assessment_states WHERE cluster_id=$1 AND enrollment_id=$2 ORDER BY asset LIMIT 9`, cluster, enrollment)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	for rows.Next() {
		var x ProductionAssessmentAssetStatus
		if err = rows.Scan(&x.Asset, &x.Revision, &x.NextDue, &x.LastAttempt, &x.LastFailure, &x.LastFailureAt, &x.FailureCount); err != nil {
			return s, err
		}
		s.Assets = append(s.Assets, x)
	}
	if len(s.Assets) > 8 {
		return ProductionAssessmentStatus{}, a.ErrInvalid
	}
	return s, rows.Err()
}

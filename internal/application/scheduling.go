package application

import (
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// LegacyPrometheusSchedules is the four-query compatibility import contract.
// MaxTargets is the legacy series cap for these Prometheus operations.
func LegacyPrometheusSchedules(cluster domain.ClusterID, source domain.SourceID, mode domain.SchedulingMode, interval, timeout time.Duration, maxTargets int, maxBytes int64) []domain.DesiredSchedule {
	queries := []domain.QueryKind{domain.QuerySourceHealth, domain.QueryGPUIdentity, domain.QueryGPUUtilization, domain.QueryGPUXID}
	schedules := make([]domain.DesiredSchedule, 0, len(queries))
	for _, query := range queries {
		op, _ := domain.CollectionOperationForQuery(query)
		schedules = append(schedules, domain.DesiredSchedule{ScheduleKey: domain.ScheduleKey{ClusterID: cluster, SourceID: source, Operation: op.ID}, Enabled: true, Mode: mode, Interval: interval, Timeout: timeout, MaxTargets: maxTargets, MaxBytes: maxBytes})
	}
	return schedules
}

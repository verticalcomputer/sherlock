package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ReadDurableScheduleSnapshot returns a consistent schedule-state view for the
// explicitly enrolled schedules: the stored next-due timestamp, cumulative
// coalesced-interval count and dropped-interval count per schedule, plus one
// database observation timestamp. Only enabled durable schedules in
// non-removed clusters with an execution grant for their current revision are
// returned; missing, disabled, legacy-mode, removed-cluster and stale-grant
// schedules are omitted.
//
// This is a schedule-state view, not an eligibility or health projection: it
// deliberately does not gate on heartbeat freshness or source reachability.
// Timestamp and rows come from a single statement over one database snapshot.
// The read takes no row locks, mutates nothing and advances no cursors.
func (s *CollectionStore) ReadDurableScheduleSnapshot(ctx context.Context, keys []domain.ScheduleKey) (domain.DurableSchedulerSnapshot, error) {
	var out domain.DurableSchedulerSnapshot
	if err := domain.ValidateDurableSchedulerSnapshotKeys(keys); err != nil {
		return out, err
	}
	clusters := make([]string, 0, len(keys))
	sources := make([]string, 0, len(keys))
	operations := make([]string, 0, len(keys))
	for _, key := range keys {
		clusters = append(clusters, string(key.ClusterID))
		sources = append(sources, string(key.SourceID))
		operations = append(operations, string(key.Operation))
	}
	// The materialized observation timestamp is evaluated once per statement.
	// The outer join preserves it even when no enrolled schedule has a row, so
	// empty inputs and empty results still carry a database timestamp.
	// The dropped-interval count projects retained occurrence/work records:
	// one per admitted occurrence whose work terminated unclaimed, across
	// that schedule's revisions, excluding its coalesced-interval accounting.
	rows, err := s.pool.Query(ctx, `
 WITH obs AS MATERIALIZED (SELECT clock_timestamp() AS now)
 SELECT o.now, s.cluster_id, s.source_id, s.operation, s.next_due_at, s.coalesced_intervals, s.dropped_intervals
 FROM obs o
 LEFT JOIN LATERAL (
  SELECT d.cluster_id, d.source_id, d.operation, st.next_due_at, st.coalesced_intervals, (
   SELECT count(*)
   FROM durable_schedule_occurrences oc
   JOIN collector_work_items w ON w.work_id = oc.work_id
   WHERE oc.cluster_id = d.cluster_id AND oc.source_id = d.source_id AND oc.operation = d.operation
    AND w.status IN ('FAILED','CANCELLED')
    AND w.next_attempt = 1
    AND NOT EXISTS (SELECT 1 FROM collector_work_attempts a WHERE a.work_id = oc.work_id)
  ) AS dropped_intervals
  FROM desired_schedules d
  JOIN durable_schedule_state st USING (cluster_id, source_id, operation)
  JOIN durable_schedule_executions e USING (cluster_id, source_id, operation, revision)
  JOIN clusters cl ON cl.cluster_id = d.cluster_id
  JOIN UNNEST($1::text[], $2::text[], $3::text[]) AS k(cluster_id, source_id, operation)
   ON k.cluster_id = d.cluster_id AND k.source_id = d.source_id AND k.operation = d.operation
  WHERE d.enabled AND d.mode = 'durable' AND cl.removed_at IS NULL
 ) s ON true
 ORDER BY s.cluster_id, s.source_id, s.operation`, clusters, sources, operations)
	if err != nil {
		return domain.DurableSchedulerSnapshot{}, fmt.Errorf("read durable schedule snapshot: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var observedAt time.Time
		var clusterID, sourceID, operation *string
		var nextDue *time.Time
		var coalesced, dropped *int64
		if err := rows.Scan(&observedAt, &clusterID, &sourceID, &operation, &nextDue, &coalesced, &dropped); err != nil {
			return domain.DurableSchedulerSnapshot{}, fmt.Errorf("scan durable schedule snapshot: %w", err)
		}
		if out.ObservedAt.IsZero() {
			out.ObservedAt = observedAt.UTC()
		}
		if clusterID == nil {
			continue
		}
		out.Rows = append(out.Rows, domain.DurableSchedulerSnapshotRow{
			Key: domain.ScheduleKey{
				ClusterID: domain.ClusterID(*clusterID),
				SourceID:  domain.SourceID(*sourceID),
				Operation: domain.CollectionOperationID(*operation),
			},
			NextDue:            nextDue.UTC(),
			CoalescedIntervals: *coalesced,
			DroppedIntervals:   *dropped,
		})
	}
	if err := rows.Err(); err != nil {
		return domain.DurableSchedulerSnapshot{}, fmt.Errorf("read durable schedule snapshot: %w", err)
	}
	return out, nil
}

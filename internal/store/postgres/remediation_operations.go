package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/remediationops"
)

// RemediationOperations is a bounded read-only aggregation for the private
// remediator metrics endpoint. It returns categories only: no run, target,
// source, evidence, owner, or lease token is exposed.
func (s *RemediationStore) RemediationOperations(ctx context.Context, cluster string, limit int) (remediationops.Snapshot, error) {
	if cluster == "" || limit < 1 || limit > remediationops.MaxBuckets {
		return remediationops.Snapshot{}, fmt.Errorf("invalid remediation operations scope")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	out := remediationops.Snapshot{At: time.Now().UTC()}
	read := func(query string, dest *[]remediationops.Bucket) error {
		rows, err := s.pool.Query(ctx, query, cluster, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b remediationops.Bucket
			if err := rows.Scan(&b.Class, &b.Count); err != nil {
				return err
			}
			*dest = append(*dest, b)
		}
		return rows.Err()
	}
	if err := read(`SELECT state,count(*) FROM remediation_runs WHERE cluster_id=$1 GROUP BY state ORDER BY state LIMIT $2`, &out.RunStates); err != nil {
		return out, err
	}
	if err := read(`SELECT status,count(*) FROM collection_repair_requests WHERE cluster_id=$1 GROUP BY status ORDER BY status LIMIT $2`, &out.RequestStates); err != nil {
		return out, err
	}
	if err := read(`SELECT code,count(*) FROM schedule_repair_decisions WHERE cluster_id=$1 GROUP BY code ORDER BY code LIMIT $2`, &out.DecisionCodes); err != nil {
		return out, err
	}
	if err := read(`WITH active AS (
 SELECT r.configuration_revision<>j.configuration_revision AS configuration_changed,
 r.schedule_revision<>j.schedule_revision AS schedule_changed,
 r.lease_expires_at<=clock_timestamp() AS worker_expired,
 mr.supervisor_until<=clock_timestamp() AS supervisor_expired
 FROM collection_repair_requests r JOIN collection_jobs j ON j.cluster_id=r.cluster_id AND j.job_id=r.job_id
 JOIN remediation_runs mr ON mr.cluster_id=r.cluster_id AND mr.run_id=r.run_id
 WHERE r.cluster_id=$1 AND r.status IN ('REQUESTED','CLAIMED','CANCEL_REQUESTED')
), counts AS (
 SELECT 'configuration_revision_mismatch' AS kind,count(*) FILTER (WHERE configuration_changed) AS n FROM active
 UNION ALL SELECT 'schedule_revision_mismatch',count(*) FILTER (WHERE schedule_changed) FROM active
 UNION ALL SELECT 'worker_lease_expired',count(*) FILTER (WHERE worker_expired) FROM active
 UNION ALL SELECT 'supervisor_lease_expired',count(*) FILTER (WHERE supervisor_expired) FROM active
) SELECT kind,n FROM counts ORDER BY kind LIMIT $2`, &out.FenceStates); err != nil {
		return out, err
	}
	err := s.pool.QueryRow(ctx, `SELECT
  count(*) FILTER (WHERE supervisor_until>clock_timestamp()),
  (SELECT count(*) FROM collection_repair_requests WHERE cluster_id=$1 AND lease_expires_at>clock_timestamp()),
  (SELECT count(*) FROM collector_work_attempts a JOIN collector_work_items w ON w.work_id=a.work_id WHERE w.cluster_id=$1 AND a.status IN ('CLAIMED','STARTED') AND a.lease_expires_at>clock_timestamp()),
  count(*) FILTER (WHERE state='VERIFYING'),
  count(*) FILTER (WHERE completed_at IS NOT NULL),
  (SELECT count(*) FROM collection_repair_requests WHERE cluster_id=$1),
  (SELECT count(*) FROM collection_repair_requests WHERE cluster_id=$1 AND status IN ('REQUESTED','CLAIMED','CANCEL_REQUESTED')),
  COALESCE((SELECT avg(EXTRACT(EPOCH FROM (v.recorded_at-r.created_at))) FROM collection_repair_requests r JOIN remediation_verification_evidence v ON v.cluster_id=r.cluster_id AND v.run_id=r.run_id AND v.attempt_id=r.attempt_id AND v.target=r.job_id AND v.condition_id='stream-fresh' WHERE r.cluster_id=$1 AND v.recorded_at>=r.created_at),0)
 FROM remediation_runs WHERE cluster_id=$1`, cluster).Scan(&out.ActiveSupervisorLeases, &out.ActiveRequestLeases, &out.ActiveWorkLeases, &out.PendingVerification, &out.TerminalRuns, &out.RepairEffects, &out.ActiveReservations, &out.EffectLatencySeconds)
	return out, err
}

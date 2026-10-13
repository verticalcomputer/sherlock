package postgres

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ConfigureCollectionDispatch enrolls an exact collector. Repeated startup
// preserves its cursor; conflicting replicas cannot rewrite the policy.
// Disabling worker enrollment does not erase an already persisted reservation.
func (s *CollectionStore) ConfigureCollectionDispatch(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, policy domain.CollectionDispatchPolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	command, err := s.pool.Exec(ctx, `UPDATE collectors SET collection_dispatch_floor=$3,collection_dispatch_period=$4
 WHERE cluster_id=$1 AND collector_id=$2 AND status='ACTIVE'
 AND (collection_dispatch_period=0 OR (collection_dispatch_floor=$3 AND collection_dispatch_period=$4))`, cluster, collector, policy.Floor, policy.Period)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("collection dispatch enrollment missing or conflicts with persisted policy")
	}
	return nil
}

// claimReservedCollection serializes only this collector's v1 grants. v2
// typed collection has no repair competitors and never resets the v1 cursor.
// Each successful grant consumes a turn, including reclaim and borrowing.
// No empty poll, failed transaction, renewal or completion consumes a turn.
func (s *CollectorControlStore) claimReservedCollection(ctx context.Context, tx pgx.Tx, collector domain.CollectorID, token string, duration time.Duration) (domain.WorkLease, bool, error) {
	var cluster domain.ClusterID
	var policy domain.CollectionDispatchPolicy
	var turn int
	err := tx.QueryRow(ctx, `SELECT cluster_id,collection_dispatch_floor,collection_dispatch_period,collection_dispatch_turn
 FROM collectors WHERE collector_id=$1 AND status='ACTIVE' FOR UPDATE`, collector).Scan(&cluster, &policy.Floor, &policy.Period, &turn)
	if err != nil {
		return domain.WorkLease{}, false, err
	}
	if err = policy.Validate(); err != nil {
		return domain.WorkLease{}, false, err
	}
	preferRepair := turn >= policy.Floor
	var work domain.WorkID
	var attempt int
	for _, repair := range []bool{preferRepair, !preferRepair} {
		if repair {
			// A busy repair authority must not delay ordinary collection. This
			// is the same transaction-scoped authority key as LockRepairAuthority.
			var locked bool
			if err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('m15-repair:'||$1::text,0))`, cluster).Scan(&locked); err != nil {
				return domain.WorkLease{}, false, err
			}
			if !locked {
				continue
			}
		}
		err = tx.QueryRow(ctx, `SELECT w.work_id,w.next_attempt FROM collector_work_items w
 JOIN collectors c ON c.cluster_id=w.cluster_id
 JOIN collector_capabilities cap ON cap.collector_id=c.collector_id AND cap.capability=w.query_kind
 WHERE c.collector_id=$1 AND c.status='ACTIVE' AND w.typed_plan IS NULL
 AND ($2 OR NOT w.remediation_runtime_managed) AND durable_work_claimable(w.work_id,c.collector_id)
 AND w.status IN ('AVAILABLE','LEASED') AND w.available_at<=clock_timestamp()
 AND w.work_expires_at>clock_timestamp() AND w.deadline>clock_timestamp()
 AND NOT EXISTS(SELECT 1 FROM collector_work_attempts a WHERE a.work_id=w.work_id
   AND a.status IN ('CLAIMED','STARTED') AND a.lease_expires_at>clock_timestamp())
 AND EXISTS(SELECT 1 FROM collection_repair_requests r WHERE r.work_id=w.work_id)=$2
 AND (NOT $2 OR EXISTS (
   SELECT 1 FROM collection_repair_requests repair
   JOIN remediation_runs rr ON rr.cluster_id=repair.cluster_id AND rr.run_id=repair.run_id
   JOIN remediation_attempts ra ON ra.cluster_id=repair.cluster_id AND ra.attempt_id=repair.attempt_id AND ra.run_id=repair.run_id
   JOIN remediation_policies p ON p.cluster_id=repair.cluster_id AND p.policy_id=ra.policy_id AND p.version=ra.policy_version
   JOIN collection_jobs j ON j.cluster_id=repair.cluster_id AND j.job_id=repair.job_id
   JOIN collector_source_health h ON h.collector_id=c.collector_id AND h.source_id=w.source_id
   CROSS JOIN remediation_global_state gs
   WHERE repair.work_id=w.work_id AND repair.cluster_id=w.cluster_id
     AND repair.status IN ('REQUESTED','CLAIMED')
     AND repair.deadline_at>clock_timestamp() AND rr.cancellation_requested_at IS NULL
     AND rr.state IN ('CANARY_EXECUTING','ROLLING_OUT','VERIFYING')
     AND gs.remediation_enabled AND p.enabled AND p.revoked_at IS NULL
     AND p.recipe_id=rr.recipe_id AND p.recipe_version=rr.recipe_version
     AND p.not_before<=clock_timestamp() AND p.not_after>clock_timestamp()
     AND j.active AND j.configuration_revision=repair.configuration_revision
     AND j.schedule_revision=repair.schedule_revision
     AND c.identity_not_after>clock_timestamp()
     AND c.last_heartbeat_at BETWEEN clock_timestamp()-interval '2 minutes' AND clock_timestamp()
     AND h.availability='AVAILABLE'
     AND h.checked_at BETWEEN clock_timestamp()-interval '2 minutes' AND clock_timestamp()
 )) ORDER BY w.available_at,w.work_id LIMIT 1 FOR UPDATE OF w SKIP LOCKED`, collector, repair).Scan(&work, &attempt)
		if err == pgx.ErrNoRows {
			continue
		}
		if err != nil {
			return domain.WorkLease{}, false, err
		}
		break
	}
	if work == "" {
		return domain.WorkLease{}, false, tx.Commit(ctx)
	}
	// A renewal that committed while candidate selection waited for the work
	// lock must be visible before reclaim. Lock attempts NOWAIT to avoid the
	// legacy expiry path's attempt->work lock inversion.
	rows, err := tx.Query(ctx, `SELECT attempt FROM collector_work_attempts WHERE work_id=$1
 AND status IN ('CLAIMED','STARTED') FOR UPDATE NOWAIT`, work)
	if err != nil {
		return domain.WorkLease{}, false, err
	}
	for rows.Next() {
		var ignored int
		if err = rows.Scan(&ignored); err != nil {
			break
		}
	}
	rowErr := rows.Err()
	rows.Close()
	if err != nil {
		return domain.WorkLease{}, false, err
	}
	if rowErr != nil {
		return domain.WorkLease{}, false, rowErr
	}
	var live bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM collector_work_attempts WHERE work_id=$1
 AND status IN ('CLAIMED','STARTED') AND lease_expires_at>clock_timestamp())`, work).Scan(&live); err != nil {
		return domain.WorkLease{}, false, err
	}
	if live {
		return domain.WorkLease{}, false, tx.Commit(ctx)
	}
	if _, err = tx.Exec(ctx, `UPDATE collector_work_attempts SET status='EXPIRED',completed_at=clock_timestamp()
 WHERE work_id=$1 AND status IN ('CLAIMED','STARTED') AND lease_expires_at<=clock_timestamp()`, work); err != nil {
		return domain.WorkLease{}, false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE collector_work_items SET status='LEASED',next_attempt=next_attempt+1 WHERE work_id=$1`, work); err != nil {
		return domain.WorkLease{}, false, err
	}
	var lease domain.WorkLease
	hash := sha256.Sum256([]byte(token))
	if err = tx.QueryRow(ctx, `INSERT INTO collector_work_attempts(work_id,attempt,collector_id,lease_token_hash,lease_expires_at)
 VALUES($1,$2,$3,$4,clock_timestamp()+($5*interval '1 millisecond')) RETURNING lease_expires_at`, work, attempt, collector, hash[:], duration.Milliseconds()).Scan(&lease.LeaseExpires); err != nil {
		return domain.WorkLease{}, false, err
	}
	lease.Work.WorkID, lease.Attempt, lease.CollectorID, lease.LeaseToken = work, attempt, collector, token
	var start, end *time.Time
	var step *float64
	if err = tx.QueryRow(ctx, `SELECT run_id,cluster_id,source_id,query_kind,node_filter,
 range_start,range_end,range_step_seconds,scheduled_for,deadline,max_series,max_bytes,idempotency_key,status,available_at,work_expires_at
 FROM collector_work_items WHERE work_id=$1`, work).Scan(&lease.Work.Task.RunID, &lease.Work.Task.ClusterID,
		&lease.Work.Task.SourceID, &lease.Work.Task.Query, &lease.Work.Task.Node, &start, &end, &step,
		&lease.Work.Task.ScheduledFor, &lease.Work.Task.Deadline, &lease.Work.Task.MaxSeries, &lease.Work.Task.MaxBytes,
		&lease.Work.Task.IdempotencyKey, &lease.Work.Status, &lease.Work.AvailableAt, &lease.Work.WorkExpiresAt); err != nil {
		return domain.WorkLease{}, false, err
	}
	if start != nil {
		lease.Work.Task.Range = &domain.CollectionRange{Start: start.UTC(), End: end.UTC(), Step: time.Duration(*step * float64(time.Second))}
	}
	lease.LeaseExpires = lease.LeaseExpires.UTC()
	lease.Work.AvailableAt = lease.Work.AvailableAt.UTC()
	lease.Work.WorkExpiresAt = lease.Work.WorkExpiresAt.UTC()
	lease.Work.Task.ScheduledFor = lease.Work.Task.ScheduledFor.UTC()
	lease.Work.Task.Deadline = lease.Work.Task.Deadline.UTC()
	if _, err = tx.Exec(ctx, `UPDATE collectors SET collection_dispatch_turn=(collection_dispatch_turn+1)%collection_dispatch_period WHERE collector_id=$1`, collector); err != nil {
		return domain.WorkLease{}, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return domain.WorkLease{}, false, err
	}
	return lease, true, nil
}

package postgres

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"time"
)

func loadRemediationBoundary(ctx context.Context, q remediationQuerier, cluster domain.ClusterID, id domain.RemediationRunID, l *application.LoadedRemediationRun) error {
	err := q.QueryRow(ctx, `SELECT a.attempt_id,a.stage,EXISTS(SELECT 1 FROM remediation_receipts r WHERE r.cluster_id=a.cluster_id AND r.attempt_id=a.attempt_id),
 EXISTS(SELECT 1 FROM remediation_attempt_targets t WHERE t.cluster_id=a.cluster_id AND t.attempt_id=a.attempt_id) AND NOT EXISTS(SELECT 1 FROM remediation_attempt_targets t WHERE t.cluster_id=a.cluster_id AND t.attempt_id=a.attempt_id AND NOT EXISTS(SELECT 1 FROM remediation_verification_evidence v WHERE v.cluster_id=a.cluster_id AND v.run_id=a.run_id AND v.attempt_id=a.attempt_id AND v.target=t.target AND v.condition_id='stream-fresh'))
 FROM remediation_attempts a WHERE a.cluster_id=$1 AND a.run_id=$2 ORDER BY a.created_at DESC,a.attempt_id DESC LIMIT 1`, cluster, id).Scan(&l.LatestAttemptID, &l.LatestStage, &l.LatestReceipt, &l.WaveVerified)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	rows, err := q.Query(ctx, `SELECT target FROM remediation_attempt_targets WHERE cluster_id=$1 AND attempt_id=$2 ORDER BY ordinal`, cluster, l.LatestAttemptID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var target domain.RemediationTarget
		if err := rows.Scan(&target); err != nil {
			return err
		}
		l.LatestTargets = append(l.LatestTargets, target)
	}
	return rows.Err()
}

func prepareRemediationSchedule(ctx context.Context, tx pgx.Tx, input application.RemediationDispatchInput) error {
	if input.Attempt.Stage == domain.RemediationStageRollback {
		return nil
	}
	for _, target := range input.Attempt.WaveTargets {
		_, err := tx.Exec(ctx, `INSERT INTO remediation_schedule_snapshots(cluster_id,run_id,target,prior_active,prior_interval,prior_next,prior_revision,prior_configuration_revision)
 SELECT cluster_id,$2,job_id,active,interval_seconds,next_run_at,schedule_revision,configuration_revision FROM collection_jobs WHERE cluster_id=$1 AND job_id=$3
 ON CONFLICT DO NOTHING`, input.ClusterID, input.Run.Plan().RunID, target)
		if err != nil {
			return err
		}
		if input.Run.Plan().Assurance == domain.AssuranceLive {
			continue
		}
		_, err = tx.Exec(ctx, `INSERT INTO remediation_simulation_state(cluster_id,run_id,target,active,interval_seconds,next_run_at,revision)
 SELECT cluster_id,run_id,target,prior_active,prior_interval,prior_next,prior_revision FROM remediation_schedule_snapshots WHERE cluster_id=$1 AND run_id=$2 AND target=$3 ON CONFLICT DO NOTHING`, input.ClusterID, input.Run.Plan().RunID, target)
		if err != nil {
			return err
		}
	}
	return nil
}

func persistRemediationObservations(ctx context.Context, tx pgx.Tx, t application.RemediationTransition) error {
	for _, o := range t.Observations {
		if o.Result != domain.ConditionSatisfied || o.AttemptID == "" || o.EvidenceID == "" {
			continue
		}
		_, err := tx.Exec(ctx, `INSERT INTO remediation_verification_evidence(cluster_id,run_id,attempt_id,target,condition_id,evidence_id,source,observed_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, t.ClusterID, t.Run.Plan().RunID, o.AttemptID, o.Target, o.ConditionID, o.EvidenceID, o.Source, o.ObservedAt)
		if err != nil {
			return err
		}
	}
	return nil
}

// ReadRemediationObservations uses a fixed durable attempt boundary. Collection
// samples, not completion timestamps, establish that recovery was observed later.
func (s *RemediationStore) ReadRemediationObservations(ctx context.Context, q application.RemediationObservationQuery) ([]domain.ConditionObservation, error) {
	if q.ClusterID == "" || q.Window <= 0 {
		return nil, nil
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	var out []domain.ConditionObservation
	for _, target := range q.Targets {
		for _, condition := range q.Conditions {
			o := domain.ConditionObservation{ReadAt: now, ConditionID: condition, Target: target, Result: domain.ConditionUnobserved, ObservedAt: now, AttemptID: q.AttemptID}
			if condition == "stream-stale" {
				var live bool
				if q.RunID != "" {
					err = tx.QueryRow(ctx, `SELECT assurance='LIVE' FROM remediation_runs WHERE cluster_id=$1 AND run_id=$2`, q.ClusterID, q.RunID).Scan(&live)
					if err != nil && err != pgx.ErrNoRows {
						return nil, err
					}
				}
				if live {
					var stale bool
					err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM remediation_runs mr JOIN schedule_repair_detections d ON d.cluster_id=mr.cluster_id AND d.incident_id=mr.incident_id AND d.investigation_id=mr.investigation_id JOIN collection_jobs j ON j.cluster_id=d.cluster_id AND j.job_id=d.job_id AND j.configuration_revision=d.configuration_revision AND j.schedule_revision=d.schedule_revision WHERE mr.cluster_id=$1 AND mr.run_id=$2 AND j.job_id=$3 AND j.active AND j.next_run_at>$4::timestamptz+make_interval(secs=>j.interval_seconds) AND (SELECT max(v.observed_at) FROM collection_runs r JOIN observations v ON v.run_id=r.run_id AND v.cluster_id=r.cluster_id WHERE r.cluster_id=j.cluster_id AND r.job_id=j.job_id AND r.source_id=j.source_id)<$4::timestamptz-make_interval(secs=>3*j.interval_seconds))`, q.ClusterID, q.RunID, target, now).Scan(&stale)
					if err != nil {
						return nil, err
					}
					o.Result = remediationConditionFrom(stale)
					o.Source = "SCHEDULE_REPAIR_DETECTIONS"
					out = append(out, o)
					continue
				}
				var fresh bool
				err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM collection_runs WHERE cluster_id=$1 AND job_id=$2 AND status='SUCCEEDED' AND coverage_complete AND completed_at BETWEEN $3::timestamptz-($4*interval '1 millisecond') AND $3)`, q.ClusterID, target, now, q.Window.Milliseconds()).Scan(&fresh)
				if err != nil {
					return nil, err
				}
				o.Result = remediationConditionFrom(!fresh)
				o.Source = "COLLECTION_JOBS"
				out = append(out, o)
				continue
			}
			var boundary, deadline time.Time
			err = tx.QueryRow(ctx, `SELECT CASE WHEN $5::text='schedule-restored' THEN a.created_at ELSE GREATEST(a.created_at,receipt.observed_at) END,r.deadline_at FROM remediation_attempts a JOIN remediation_receipts receipt ON receipt.cluster_id=a.cluster_id AND receipt.run_id=a.run_id AND receipt.attempt_id=a.attempt_id AND receipt.stage=a.stage AND receipt.outcome='EXECUTED' JOIN remediation_attempt_targets t ON t.cluster_id=a.cluster_id AND t.attempt_id=a.attempt_id AND t.run_id=a.run_id JOIN remediation_runs r ON r.cluster_id=a.cluster_id AND r.run_id=a.run_id WHERE a.cluster_id=$1 AND a.run_id=$2 AND a.attempt_id=$3 AND t.target=$4`, q.ClusterID, q.RunID, q.AttemptID, target, condition).Scan(&boundary, &deadline)
			if err == pgx.ErrNoRows {
				out = append(out, o)
				continue
			}
			if err != nil {
				return nil, err
			}
			var live bool
			if !q.Simulation {
				err = tx.QueryRow(ctx, `SELECT assurance='LIVE' FROM remediation_runs WHERE cluster_id=$1 AND run_id=$2`, q.ClusterID, q.RunID).Scan(&live)
				if err != nil && err != pgx.ErrNoRows {
					return nil, err
				}
			}
			if live {
				observation, err := readLiveRepairObservation(ctx, tx, q, target, condition, now, deadline)
				if err != nil {
					return nil, err
				}
				out = append(out, observation)
				continue
			}
			if condition == "stream-fresh" {
				if q.Simulation {
					err = tx.QueryRow(ctx, `SELECT evidence_id,observed_end FROM remediation_simulation_observations WHERE cluster_id=$1 AND run_id=$2 AND attempt_id=$3 AND target=$4 AND complete AND observed_start >= $5 AND observed_end <= LEAST($6::timestamptz,$7::timestamptz) AND recorded_at <= LEAST($6::timestamptz,$7::timestamptz) ORDER BY observed_end DESC LIMIT 1`, q.ClusterID, q.RunID, q.AttemptID, target, boundary, now, deadline).Scan(&o.EvidenceID, &o.ObservedAt)
					o.Source = "SIMULATION_OBSERVATIONS"
				} else {
					err = tx.QueryRow(ctx, `SELECT r.run_id,max(v.observed_at) FROM collection_runs r JOIN observations v ON v.run_id=r.run_id AND v.cluster_id=r.cluster_id AND v.source_id=r.source_id
 WHERE r.cluster_id=$1 AND r.job_id=$2 AND r.status='SUCCEEDED' AND r.coverage_complete AND r.started_at >= $3 AND r.scheduled_for >= $3 AND r.completed_at >= r.started_at AND r.completed_at <= LEAST($4::timestamptz,$5::timestamptz) AND r.created_at <= LEAST($4::timestamptz,$5::timestamptz)
 GROUP BY r.run_id HAVING min(v.observed_at) >= $3 AND max(v.observed_at) <= LEAST($4::timestamptz,$5::timestamptz) AND bool_and(v.collected_at>=v.observed_at AND v.collected_at<=LEAST($4::timestamptz,$5::timestamptz)) ORDER BY max(v.observed_at) DESC LIMIT 1`, q.ClusterID, target, boundary, now, deadline).Scan(&o.EvidenceID, &o.ObservedAt)
					o.Source = "COLLECTION_RUNS"
				}
				if err == nil {
					o.Result = domain.ConditionSatisfied
				} else if err != pgx.ErrNoRows {
					return nil, fmt.Errorf("read remediation recovery: %w", err)
				}
			} else if condition == "schedule-restored" {
				var restored bool
				if q.Simulation {
					err = tx.QueryRow(ctx, `SELECT COALESCE(s.restored_revision IS NOT NULL AND ROW(s.active,s.interval_seconds,s.next_run_at)=ROW(p.prior_active,p.prior_interval,p.prior_next) AND s.restored_revision=s.revision AND s.last_attempt_id=$4 AND s.updated_at >= $5,false)
 FROM remediation_schedule_snapshots p JOIN remediation_simulation_state s USING(cluster_id,run_id,target) WHERE p.cluster_id=$1 AND p.run_id=$2 AND p.target=$3`, q.ClusterID, q.RunID, target, q.AttemptID, boundary).Scan(&restored)
					o.Source = "SIMULATION_SCHEDULE"
				} else {
					// A future live adapter must set an explicit restoration fence; a matching
					// unchanged schedule alone cannot attest that rollback occurred.
					err = tx.QueryRow(ctx, `SELECT COALESCE(p.live_restored_attempt_id IS NOT NULL AND ROW(j.active,j.interval_seconds,j.next_run_at)=ROW(p.prior_active,p.prior_interval,p.prior_next) AND p.live_restored_attempt_id=$4 AND p.live_forward_revision=p.prior_revision+1 AND p.live_restored_revision=p.live_forward_revision+1 AND j.schedule_revision=p.live_restored_revision, false)
 FROM remediation_schedule_snapshots p JOIN collection_jobs j ON j.cluster_id=p.cluster_id AND j.job_id=p.target WHERE p.cluster_id=$1 AND p.run_id=$2 AND p.target=$3`, q.ClusterID, q.RunID, target, q.AttemptID).Scan(&restored)
					o.Source = "COLLECTION_JOBS"
				}
				if err == nil {
					o.Result = remediationConditionFrom(restored)
					o.EvidenceID = string(q.RunID) + ":" + string(target) + ":" + string(q.AttemptID)
				} else if err != pgx.ErrNoRows {
					return nil, err
				}
			}
			out = append(out, o)
		}
	}
	return out, tx.Commit(ctx)
}

// readLiveRepairObservation never falls back to a recent unrelated collection.
// The effect's database instant is the timing boundary even after acknowledgement
// loss; receipt creation/ingestion latency cannot move that boundary forward.
func readLiveRepairObservation(ctx context.Context, tx pgx.Tx, q application.RemediationObservationQuery, target domain.RemediationTarget, condition string, now, deadline time.Time) (domain.ConditionObservation, error) {
	o := domain.ConditionObservation{ReadAt: now, ConditionID: condition, Target: target, Result: domain.ConditionUnobserved, ObservedAt: now, AttemptID: q.AttemptID, Source: "COLLECTION_REPAIR_REQUESTS"}
	var err error
	if condition == "stream-fresh" {
		err = tx.QueryRow(ctx, `SELECT e.evidence_id,max(v.observed_at)
 FROM collection_repair_requests p
 JOIN collector_work_items w ON w.work_id=p.work_id AND w.cluster_id=p.cluster_id AND w.run_id=p.request_id AND w.idempotency_key=p.idempotency_key
 JOIN collection_run_jobs b ON b.run_id=w.run_id AND b.cluster_id=p.cluster_id AND b.job_id=p.job_id AND b.configuration_revision=p.configuration_revision AND b.source_id=w.source_id AND b.query_kind=w.query_kind AND b.node_filter=w.node_filter
 JOIN collection_runs r ON r.run_id=b.run_id AND r.cluster_id=b.cluster_id AND r.job_id=b.job_id AND r.source_id=b.source_id AND r.query_kind=b.query_kind AND r.idempotency_key=p.idempotency_key
 JOIN collector_result_ingestions ing ON ing.work_id=w.work_id AND ing.run_id=r.run_id AND ing.result_status='SUCCEEDED'
 JOIN collector_work_attempts wa ON wa.work_id=ing.work_id AND wa.attempt=ing.attempt AND wa.collector_id=ing.collector_id AND wa.status='SUCCEEDED'
 JOIN observations v ON v.run_id=r.run_id AND v.cluster_id=r.cluster_id AND v.source_id=r.source_id
 JOIN evidence_envelopes e ON e.run_id=r.run_id AND e.cluster_id=r.cluster_id AND e.source_id=r.source_id AND e.status='COMPLETE' AND e.artifact_availability IN ('NONE','AVAILABLE')
 WHERE p.cluster_id=$1 AND p.run_id=$2 AND p.attempt_id=$3 AND p.job_id=$4 AND p.status='COMPLETED' AND w.status='SUCCEEDED'
 AND r.status='SUCCEEDED' AND r.coverage_complete AND r.series_expected>0 AND r.series_returned=r.series_expected
 AND r.scheduled_for=b.scheduled_for AND r.scheduled_for>=w.scheduled_for AND r.started_at>=w.scheduled_for AND wa.claimed_at>=w.scheduled_for
 AND r.completed_at>=r.started_at AND r.completed_at<=LEAST($5::timestamptz,$6::timestamptz,p.deadline_at)
 AND r.created_at<=LEAST($5::timestamptz,$6::timestamptz,p.deadline_at)
 AND ing.finalized_at>=w.scheduled_for AND ing.finalized_at<=LEAST($5::timestamptz,$6::timestamptz,p.deadline_at)
 AND e.observed_start>=w.scheduled_for AND e.observed_end<=LEAST($5::timestamptz,$6::timestamptz,p.deadline_at)
 AND e.collected_at>=e.observed_end AND e.created_at<=LEAST($5::timestamptz,$6::timestamptz,p.deadline_at)
 GROUP BY e.evidence_id,w.scheduled_for,p.deadline_at
 HAVING min(v.observed_at)>=GREATEST(w.scheduled_for,$7::timestamptz) AND max(v.observed_at)<=LEAST($5::timestamptz,$6::timestamptz,p.deadline_at)
 AND bool_and(v.collected_at>=v.observed_at AND v.collected_at<=LEAST($5::timestamptz,$6::timestamptz,p.deadline_at))
 ORDER BY max(v.observed_at) DESC LIMIT 1`, q.ClusterID, q.RunID, q.AttemptID, target, now, deadline, now.Add(-q.Window)).Scan(&o.EvidenceID, &o.ObservedAt)
	} else if condition == "schedule-restored" {
		err = tx.QueryRow(ctx, `SELECT p.request_id,p.completed_at FROM collection_repair_requests p JOIN collector_work_items w ON w.work_id=p.work_id AND w.cluster_id=p.cluster_id WHERE p.cluster_id=$1 AND p.run_id=$2 AND p.job_id=$3 AND p.cancellation_attempt_id=$4 AND p.status='CANCELLED' AND w.status='CANCELLED' AND p.completed_at<=LEAST($5::timestamptz,$6::timestamptz) AND NOT EXISTS(SELECT 1 FROM collection_runs r WHERE r.run_id=w.run_id AND r.cluster_id=p.cluster_id)`, q.ClusterID, q.RunID, target, q.AttemptID, now, deadline).Scan(&o.EvidenceID, &o.ObservedAt)
	} else {
		return o, nil
	}
	if err == nil {
		o.Result = domain.ConditionSatisfied
	} else if err != pgx.ErrNoRows {
		return o, fmt.Errorf("read exact live repair evidence: %w", err)
	}
	return o, nil
}

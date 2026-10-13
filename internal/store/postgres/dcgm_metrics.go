package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// DCGMCollectionState reads the committed assessment, not the executor's
// pre-ingestion claim of completeness.
func (s *CollectionStore) DCGMCollectionState(ctx context.Context, cluster domain.ClusterID, source domain.SourceID, run domain.RunID) (domain.ResultStatus, domain.Coverage, error) {
	var status domain.ResultStatus
	var coverage domain.Coverage
	var encoded []byte
	err := s.pool.QueryRow(ctx, `SELECT status,series_expected,series_returned,bytes_read,coverage_complete,metric_fields FROM collection_runs WHERE cluster_id=$1 AND source_id=$2 AND run_id=$3`, cluster, source, run).Scan(&status, &coverage.SeriesExpected, &coverage.SeriesReturned, &coverage.BytesRead, &coverage.Complete, &encoded)
	if err != nil {
		return status, coverage, err
	}
	err = json.Unmarshal(encoded, &coverage.MetricFields)
	return status, coverage, err
}

func normalizeDCGMResult(ctx context.Context, tx pgx.Tx, result domain.CollectionResult) (domain.CollectionResult, error) {
	if len(domain.DCGMFields(result.Task.Query)) == 0 {
		return result, nil
	}
	if result.Task.Range != nil {
		return domain.NormalizeDCGMCollection(result, nil), nil
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('dcgm-metrics:'||$1||':'||$2,0))`, result.Task.ClusterID, result.Task.SourceID); err != nil {
		return result, err
	}
	// An operator-seeded expected revision is the mapping authority. An observed
	// metric label cannot create that authority. Historical effective time avoids
	// mapping delayed results against a later revision.
	rows, err := tx.Query(ctx, `SELECT e.entity_kind,e.stable_node_id,e.physical_gpu_uuid,e.mig_identity
 FROM goodput_inventory_revision_entities e WHERE e.cluster_id=$1 AND e.revision_id=(
 SELECT revision_id FROM goodput_inventory_revisions WHERE cluster_id=$1 AND source_id=$2 AND inventory_class='EXPECTED'
 AND effective_at<=$3 AND observed_at<=$4 ORDER BY effective_at DESC,observed_at DESC,source_at DESC,revision_id DESC LIMIT 1)
 ORDER BY e.entity_kind,e.stable_node_id,e.physical_gpu_uuid,e.mig_identity LIMIT 1025`, result.Task.ClusterID, result.Task.SourceID, result.Task.ScheduledFor, result.CompletedAt)
	if err != nil {
		return result, err
	}
	var entities []domain.EntityIdentity
	for rows.Next() {
		e := domain.EntityIdentity{ClusterID: result.Task.ClusterID}
		if err = rows.Scan(&e.Kind, &e.NodeID, &e.PhysicalGPUUUID, &e.MIGIdentity); err != nil {
			rows.Close()
			return result, err
		}
		entities = append(entities, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	if len(entities) > 1024 {
		entities = nil
	}
	result = domain.NormalizeDCGMCollection(result, entities)
	for i := range result.Observations {
		o := &result.Observations[i]
		if o.Semantics.Kind != "counter" {
			continue
		}
		var previous float64
		err = tx.QueryRow(ctx, `SELECT o.value FROM current_projections p JOIN observations o USING(observation_id)
 WHERE p.cluster_id=$1 AND p.source_id=$2 AND p.entity_key=$3 AND p.metric=$4 AND p.observed_at<$5`, o.ClusterID, o.SourceID, o.EntityKey, o.Metric, o.ObservedAt).Scan(&previous)
		if err != nil && err != pgx.ErrNoRows {
			return result, err
		}
		if err == nil && o.Value < previous {
			o.Semantics.ResetObserved = true
		}
	}
	return result, nil
}

// EnrollDiscoveredDCGM atomically gives an explicitly requested, fresh committed
// discovery run one existing revisioned schedule. A persisted schedule always
// wins, including disabled/revised schedules. No collector capability is support.
func (s *CollectionStore) EnrollDiscoveredDCGM(ctx context.Context, run domain.RunID, seed domain.DesiredSchedule, first time.Time) (bool, error) {
	if err := seed.Validate(); err != nil {
		return false, err
	}
	op, ok := domain.ReviewedCollectionOperation(seed.Operation)
	if !ok || len(domain.DCGMFields(op.Query)) == 0 || seed.Revision != 0 || !seed.Enabled {
		return false, fmt.Errorf("DCGM enrollment requires an expanded operation and revision zero")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var kind string
	if err = tx.QueryRow(ctx, `SELECT kind FROM sources WHERE cluster_id=$1 AND source_id=$2 FOR UPDATE`, seed.ClusterID, seed.SourceID).Scan(&kind); err != nil {
		return false, err
	}
	if kind != "prometheus" {
		return false, fmt.Errorf("DCGM enrollment requires a Prometheus source")
	}
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM desired_schedules WHERE cluster_id=$1 AND source_id=$2 AND operation=$3)`, seed.ClusterID, seed.SourceID, seed.Operation).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, tx.Commit(ctx)
	}
	var fieldsJSON []byte
	err = tx.QueryRow(ctx, `SELECT metric_fields FROM collection_runs WHERE run_id=$1 AND cluster_id=$2 AND source_id=$3 AND query_kind=$4
 AND status IN ('SUCCEEDED','PARTIAL') AND range_start IS NULL
 AND completed_at BETWEEN clock_timestamp()-interval '2 minutes' AND clock_timestamp()
 AND scheduled_for BETWEEN clock_timestamp()-interval '2 minutes' AND clock_timestamp()
 AND EXISTS(SELECT 1 FROM observations o WHERE o.run_id=collection_runs.run_id
 AND o.observed_at BETWEEN clock_timestamp()-interval '2 minutes' AND clock_timestamp()+interval '1 second')`, run, seed.ClusterID, seed.SourceID, op.Query).Scan(&fieldsJSON)
	if err == pgx.ErrNoRows {
		return false, tx.Commit(ctx)
	}
	if err != nil {
		return false, err
	}
	var fields []domain.DCGMFieldEvidence
	if err = json.Unmarshal(fieldsJSON, &fields); err != nil {
		return false, err
	}
	supported := false
	for _, f := range fields {
		if f.State == "SUPPORTED" {
			supported = true
		}
	}
	if !supported {
		return false, tx.Commit(ctx)
	}
	// Importing pre-existing unowned/manual jobs would silently change their
	// authority. This narrow enrollment only creates a genuinely new owner.
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM collection_jobs WHERE source_id=$1 AND query_kind=$2)`, seed.SourceID, op.Query).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, fmt.Errorf("DCGM enrollment conflicts with an existing unowned collection job")
	}
	jobID := "m1/" + string(seed.SourceID) + "/" + string(op.Query)
	if _, err = tx.Exec(ctx, `INSERT INTO collection_jobs(job_id,cluster_id,source_id,query_kind,interval_seconds,next_run_at,active) VALUES($1,$2,$3,$4,$5,$6,$7)`, jobID, seed.ClusterID, seed.SourceID, op.Query, int64(seed.Interval/time.Second), first.UTC(), seed.Mode == domain.SchedulingLegacy); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO desired_schedules (`+scheduleColumns+`,legacy_query_kind,legacy_job_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1,$12,$13)`, seed.ClusterID, seed.SourceID, seed.Operation, seed.Enabled, seed.Mode, int64(seed.Interval/time.Second), seed.Timeout.Milliseconds(), seed.Jitter.Milliseconds(), seed.MaxTargets, seed.MaxBytes, seed.Priority, op.Query, jobID); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

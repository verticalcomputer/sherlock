package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type RetentionResult struct {
	ObservationsDeleted int64
	RunsDeleted         int64
	EventsDeleted       int64
	Batches             int64
}

const retentionBatchSize = 1000
const retentionBatchPause = 10 * time.Millisecond
const retentionStatementTimeout = "5s"
const retentionLockTimeout = "250ms"

// Keep mutation and read-only backlog measurement on the same ownership rules.
// These expressions use fixed, internal SQL aliases; no caller text is included.
const retentionObservationEligible = `
 NOT EXISTS (SELECT 1 FROM current_projections p WHERE p.observation_id=o.observation_id)
 AND NOT EXISTS (SELECT 1 FROM goodput_metric_nodes n WHERE n.observation_id=o.observation_id)
 AND NOT EXISTS (SELECT 1 FROM collector_work_items w WHERE w.run_id=o.run_id AND w.status IN ('AVAILABLE','LEASED'))
 AND NOT EXISTS (
   SELECT 1 FROM collection_run_jobs b JOIN collection_jobs j ON j.job_id=b.job_id
   WHERE b.run_id=o.run_id AND b.configuration_revision=j.configuration_revision
     AND b.scheduled_for=j.next_run_at AND b.cluster_id=j.cluster_id
     AND b.source_id=j.source_id AND b.query_kind=j.query_kind AND b.node_filter=j.node_filter
     AND j.active)`

const retentionEventEligible = `
 NOT EXISTS (SELECT 1 FROM observations o WHERE o.run_id=r.run_id)
 AND NOT EXISTS (SELECT 1 FROM collector_result_ingestions i WHERE i.run_id=r.run_id)
 AND NOT EXISTS (SELECT 1 FROM collector_typed_result_ingestions i WHERE i.run_id=r.run_id)
 AND NOT EXISTS (SELECT 1 FROM collector_work_items w WHERE w.run_id=r.run_id AND w.status IN ('AVAILABLE','LEASED'))
 AND NOT EXISTS (
   SELECT 1 FROM collection_run_jobs b JOIN collection_jobs j ON j.job_id=b.job_id
   WHERE b.run_id=r.run_id AND b.configuration_revision=j.configuration_revision
     AND b.scheduled_for=j.next_run_at AND b.cluster_id=j.cluster_id
     AND b.source_id=j.source_id AND b.query_kind=j.query_kind AND b.node_filter=j.node_filter
     AND j.active)`

const retentionRunEligible = retentionEventEligible + `
 AND NOT EXISTS (SELECT 1 FROM collection_events e WHERE e.run_id=r.run_id)`

func validateRetentionDurations(observationRetention, runRetention time.Duration) error {
	if observationRetention <= 0 || runRetention <= 0 || runRetention < observationRetention {
		return fmt.Errorf("retention durations must be positive and run retention cannot be shorter than observation retention")
	}
	return nil
}

func (s *CollectionStore) ApplyRetention(ctx context.Context, now time.Time, observationRetention, runRetention time.Duration) (RetentionResult, error) {
	if err := validateRetentionDurations(observationRetention, runRetention); err != nil {
		return RetentionResult{}, err
	}
	// Keep an explicit, stable cutoff across batches, but never let an ahead-of-
	// database worker clock make future evidence eligible for deletion.
	var cutoffTime time.Time
	if err := s.pool.QueryRow(ctx, `SELECT LEAST($1::timestamptz, clock_timestamp())`, now.UTC()).Scan(&cutoffTime); err != nil {
		return RetentionResult{}, fmt.Errorf("read retention cutoff: %w", err)
	}
	observationCutoff := cutoffTime.Add(-observationRetention)
	runCutoff := cutoffTime.Add(-runRetention)
	var total RetentionResult
	for {
		batch, err := s.applyRetentionBatch(ctx, observationCutoff, runCutoff)
		if err != nil {
			return total, err
		}
		total.ObservationsDeleted += batch.ObservationsDeleted
		total.RunsDeleted += batch.RunsDeleted
		total.EventsDeleted += batch.EventsDeleted
		if batch.ObservationsDeleted+batch.RunsDeleted+batch.EventsDeleted == 0 {
			return total, nil
		}
		total.Batches++
		// Allow concurrent claims and writes to acquire database resources
		// between short delete transactions, even during a large backlog.
		timer := time.NewTimer(retentionBatchPause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return total, ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *CollectionStore) applyRetentionBatch(ctx context.Context, observationCutoff, runCutoff time.Time) (RetentionResult, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return RetentionResult{}, fmt.Errorf("begin retention: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout',$1,true), set_config('lock_timeout',$2,true)`, retentionStatementTimeout, retentionLockTimeout); err != nil {
		return RetentionResult{}, fmt.Errorf("bound retention transaction: %w", err)
	}

	var result RetentionResult
	// A retry reuses its first immutable collection_run_jobs binding while the
	// job's lease_generation advances. Pin an unfinished current occurrence by
	// configuration and scope, including between expiry and reclaim. Lease expiry
	// is not completion; only advancement/invalidation releases the occurrence.
	command, err := tx.Exec(ctx, `
		WITH victims AS (
		  SELECT o.observation_id FROM observations o
		  WHERE o.collected_at < $1
		    AND `+retentionObservationEligible+`
		  ORDER BY o.collected_at,o.observation_id LIMIT $2 FOR UPDATE OF o SKIP LOCKED
		)
		DELETE FROM observations o USING victims v WHERE o.observation_id=v.observation_id`, observationCutoff, retentionBatchSize)
	if err != nil {
		return RetentionResult{}, fmt.Errorf("delete expired observations: %w", err)
	}
	result.ObservationsDeleted = command.RowsAffected()

	// Finalized ingestion receipts are replay authority, not disposable cache.
	// There is no independently approved receipt expiration policy. Preserve
	// their runs (and publication events) rather than cascading away receipts,
	// typed source cursors, coverage, allocations or event provenance. Ordinary
	// evidence envelopes already retain their contents via ON DELETE SET NULL.
	command, err = tx.Exec(ctx, `
		WITH victims AS (
		  SELECT e.event_id FROM collection_events e JOIN collection_runs r ON r.run_id=e.run_id
		  WHERE r.completed_at < $1
		    AND `+retentionEventEligible+`
		  ORDER BY r.completed_at,e.event_id LIMIT $2 FOR UPDATE OF e SKIP LOCKED
		)
		DELETE FROM collection_events e USING victims v WHERE e.event_id=v.event_id`, runCutoff, retentionBatchSize)
	if err != nil {
		return RetentionResult{}, fmt.Errorf("delete expired collection events: %w", err)
	}
	result.EventsDeleted = command.RowsAffected()

	command, err = tx.Exec(ctx, `
		WITH victims AS (
		  SELECT r.run_id FROM collection_runs r
		  WHERE r.completed_at < $1
		    AND `+retentionRunEligible+`
		  ORDER BY r.completed_at,r.run_id LIMIT $2 FOR UPDATE OF r SKIP LOCKED
		)
		DELETE FROM collection_runs r USING victims v WHERE r.run_id=v.run_id`, runCutoff, retentionBatchSize)
	if err != nil {
		return RetentionResult{}, fmt.Errorf("delete expired collection runs: %w", err)
	}
	result.RunsDeleted = command.RowsAffected()

	if err := tx.Commit(ctx); err != nil {
		return RetentionResult{}, fmt.Errorf("commit retention: %w", err)
	}
	return result, nil
}

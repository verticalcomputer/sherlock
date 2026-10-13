package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// RetentionBacklog is a read-only, repeatable-read snapshot. MeasuredAt is the
// database transaction timestamp, independent of the worker's clock.
type RetentionBacklog struct {
	MeasuredAt   time.Time
	Observations RetentionBacklogClass
	Runs         RetentionBacklogClass
	Events       RetentionBacklogClass
}

// RetentionBacklogClass describes the oldest at most 1000 expired rows.
// When Truncated is true, ExpiredRows and EligibleRows are lower bounds, with
// EligibleRows counting only eligible rows in that oldest sampled prefix.
// Eligibility is evaluated against this snapshot, not a forecast after other
// classes are deleted. OldestExpiredAt is zero when the class has no expired rows.
type RetentionBacklogClass struct {
	ExpiredRows     int64
	EligibleRows    int64
	Truncated       bool
	OldestExpiredAt time.Time
}

const retentionBacklogTimeout = 2 * time.Second
const retentionBacklogStatementTimeout = "1s"

// MeasureRetentionBacklog samples expired rows without locking or modifying
// them. The row cap bounds sampled ownership checks, not planner scans/sorts:
// a large relation can hit the deadline, returning an error rather than a
// misleading zero or complete count. Mutation and measurement share predicates.
func (s *CollectionStore) MeasureRetentionBacklog(ctx context.Context, now time.Time, observationRetention, runRetention time.Duration) (RetentionBacklog, error) {
	if err := validateRetentionDurations(observationRetention, runRetention); err != nil {
		return RetentionBacklog{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, retentionBacklogTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return RetentionBacklog{}, fmt.Errorf("begin retention backlog snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout',$1,true), set_config('lock_timeout',$2,true)`, retentionBacklogStatementTimeout, retentionLockTimeout); err != nil {
		return RetentionBacklog{}, fmt.Errorf("bound retention backlog snapshot: %w", err)
	}
	var result RetentionBacklog
	var cutoffTime time.Time
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp(),LEAST($1::timestamptz,transaction_timestamp())`, now.UTC()).Scan(&result.MeasuredAt, &cutoffTime); err != nil {
		return RetentionBacklog{}, fmt.Errorf("read retention backlog snapshot time: %w", err)
	}
	result.Observations, err = measureRetentionClass(ctx, tx, `/* retention backlog observations */
		WITH expired AS MATERIALIZED (
		  SELECT observation_id,run_id,collected_at AS expired_at FROM observations
		  WHERE collected_at<$1 ORDER BY collected_at,observation_id LIMIT $2+1
		), prefix AS (SELECT * FROM expired ORDER BY expired_at,observation_id LIMIT $2)
		SELECT count(*),count(*) FILTER (WHERE `+retentionObservationEligible+`),
		       (SELECT count(*) FROM expired)>$2,min(expired_at) FROM prefix o`, cutoffTime.Add(-observationRetention))
	if err != nil {
		return RetentionBacklog{}, fmt.Errorf("measure observation retention backlog: %w", err)
	}
	result.Runs, err = measureRetentionClass(ctx, tx, `/* retention backlog runs */
		WITH expired AS MATERIALIZED (
		  SELECT run_id,completed_at AS expired_at FROM collection_runs
		  WHERE completed_at<$1 ORDER BY completed_at,run_id LIMIT $2+1
		), prefix AS (SELECT * FROM expired ORDER BY expired_at,run_id LIMIT $2)
		SELECT count(*),count(*) FILTER (WHERE `+retentionRunEligible+`),
		       (SELECT count(*) FROM expired)>$2,min(expired_at) FROM prefix r`, cutoffTime.Add(-runRetention))
	if err != nil {
		return RetentionBacklog{}, fmt.Errorf("measure run retention backlog: %w", err)
	}
	result.Events, err = measureRetentionClass(ctx, tx, `/* retention backlog events */
		WITH expired AS MATERIALIZED (
		  SELECT e.event_id,r.run_id,r.completed_at AS expired_at
		  FROM collection_events e JOIN collection_runs r ON r.run_id=e.run_id
		  WHERE r.completed_at<$1 ORDER BY r.completed_at,e.event_id LIMIT $2+1
		), prefix AS (SELECT * FROM expired ORDER BY expired_at,event_id LIMIT $2)
		SELECT count(*),count(*) FILTER (WHERE `+retentionEventEligible+`),
		       (SELECT count(*) FROM expired)>$2,min(expired_at) FROM prefix r`, cutoffTime.Add(-runRetention))
	if err != nil {
		return RetentionBacklog{}, fmt.Errorf("measure event retention backlog: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return RetentionBacklog{}, fmt.Errorf("commit retention backlog snapshot: %w", err)
	}
	return result, nil
}

func measureRetentionClass(ctx context.Context, tx pgx.Tx, query string, cutoff time.Time) (RetentionBacklogClass, error) {
	var result RetentionBacklogClass
	var oldest *time.Time
	if err := tx.QueryRow(ctx, query, cutoff, retentionBatchSize).Scan(&result.ExpiredRows, &result.EligibleRows, &result.Truncated, &oldest); err != nil {
		return RetentionBacklogClass{}, err
	}
	if oldest != nil {
		result.OldestExpiredAt = oldest.UTC()
	}
	return result, nil
}

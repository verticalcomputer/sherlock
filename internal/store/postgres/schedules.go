package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const scheduleColumns = `cluster_id,source_id,operation,enabled,mode,interval_seconds,timeout_ms,jitter_ms,max_targets,max_bytes,priority,revision`

func scanSchedule(row pgx.Row) (domain.DesiredSchedule, error) {
	var s domain.DesiredSchedule
	var interval, timeout, jitter int64
	err := row.Scan(&s.ClusterID, &s.SourceID, &s.Operation, &s.Enabled, &s.Mode, &interval, &timeout, &jitter, &s.MaxTargets, &s.MaxBytes, &s.Priority, &s.Revision)
	s.Interval, s.Timeout, s.Jitter = time.Duration(interval)*time.Second, time.Duration(timeout)*time.Millisecond, time.Duration(jitter)*time.Millisecond
	return s, err
}

func (s *CollectionStore) DesiredSchedule(ctx context.Context, key domain.ScheduleKey) (domain.DesiredSchedule, error) {
	return scanSchedule(s.pool.QueryRow(ctx, `SELECT `+scheduleColumns+` FROM desired_schedules WHERE cluster_id=$1 AND source_id=$2 AND operation=$3`, key.ClusterID, key.SourceID, key.Operation))
}

// UpdateDesiredSchedule uses the caller's observed revision as a compare-and-swap.
// The database atomically fences unbound claims and mirrors legacy job state.
// Work already bound before this transaction may finish; this is not cancellation.
func (s *CollectionStore) UpdateDesiredSchedule(ctx context.Context, desired domain.DesiredSchedule) (domain.DesiredSchedule, error) {
	if err := desired.Validate(); err != nil {
		return domain.DesiredSchedule{}, err
	}
	if desired.Revision < 1 {
		return domain.DesiredSchedule{}, domain.ErrScheduleRevision
	}
	updated, err := scanSchedule(s.pool.QueryRow(ctx, `UPDATE desired_schedules SET enabled=$5,mode=$6,interval_seconds=$7,timeout_ms=$8,jitter_ms=$9,max_targets=$10,max_bytes=$11,priority=$12
	 WHERE cluster_id=$1 AND source_id=$2 AND operation=$3 AND revision=$4 RETURNING `+scheduleColumns,
		desired.ClusterID, desired.SourceID, desired.Operation, desired.Revision, desired.Enabled, desired.Mode,
		int64(desired.Interval/time.Second), desired.Timeout.Milliseconds(), desired.Jitter.Milliseconds(), desired.MaxTargets, desired.MaxBytes, desired.Priority))
	if err == pgx.ErrNoRows {
		return domain.DesiredSchedule{}, domain.ErrScheduleRevision
	}
	return updated, err
}

// CreateDesiredSchedule records typed desired work without admitting any work.
// Prometheus ownership must enter through the atomic legacy import below.
func (s *CollectionStore) CreateDesiredSchedule(ctx context.Context, desired domain.DesiredSchedule) (domain.DesiredSchedule, error) {
	if err := desired.Validate(); err != nil {
		return domain.DesiredSchedule{}, err
	}
	op, _ := domain.ReviewedCollectionOperation(desired.Operation)
	if desired.Revision != 0 || desired.Mode != domain.SchedulingDurable || op.Query != "" {
		return domain.DesiredSchedule{}, fmt.Errorf("new typed schedules require revision zero and durable mode; Prometheus schedules require legacy import")
	}
	return scanSchedule(s.pool.QueryRow(ctx, `INSERT INTO desired_schedules (`+scheduleColumns+`) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1
	 FROM sources WHERE cluster_id=$1 AND source_id=$2 AND kind=$12 RETURNING `+scheduleColumns,
		desired.ClusterID, desired.SourceID, desired.Operation, desired.Enabled, desired.Mode, int64(desired.Interval/time.Second), desired.Timeout.Milliseconds(), desired.Jitter.Milliseconds(), desired.MaxTargets, desired.MaxBytes, desired.Priority, op.Source))
}

// ImportLegacyPrometheusSchedules imports exactly the existing four-query set in
// one transaction. Persisted schedules always win over restart configuration.
// A source row lock serializes imports and EnsureJob; targeted legacy jobs cannot
// be represented by one operation cadence and require an explicit later migration.
func (s *CollectionStore) ImportLegacyPrometheusSchedules(ctx context.Context, seeds []domain.DesiredSchedule, firstRun time.Time) error {
	if len(seeds) != 4 {
		return fmt.Errorf("legacy import requires exactly four schedules")
	}
	expected := map[domain.CollectionOperationID]bool{domain.OperationPrometheusSourceHealth: true, domain.OperationPrometheusGPUIdentity: true, domain.OperationPrometheusGPUUtilization: true, domain.OperationPrometheusGPUXID: true}
	for _, seed := range seeds {
		if err := seed.Validate(); err != nil {
			return err
		}
		if !expected[seed.Operation] || seed.Revision != 0 || seed.ClusterID != seeds[0].ClusterID || seed.SourceID != seeds[0].SourceID {
			return fmt.Errorf("invalid legacy import scope or operation")
		}
		delete(expected, seed.Operation)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var kind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM sources WHERE cluster_id=$1 AND source_id=$2 FOR UPDATE`, seeds[0].ClusterID, seeds[0].SourceID).Scan(&kind); err != nil {
		return fmt.Errorf("legacy import source scope: %w", err)
	}
	if kind != "prometheus" {
		return fmt.Errorf("legacy import requires a Prometheus source")
	}
	for _, seed := range seeds {
		op, _ := domain.ReviewedCollectionOperation(seed.Operation)
		var targeted bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM collection_jobs WHERE source_id=$1 AND query_kind=$2 AND (cluster_id<>$3 OR node_filter<>''))`, seed.SourceID, op.Query, seed.ClusterID).Scan(&targeted); err != nil {
			return err
		}
		if targeted {
			return fmt.Errorf("legacy import cannot represent targeted or cross-cluster jobs for %s", seed.Operation)
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM desired_schedules WHERE cluster_id=$1 AND source_id=$2 AND operation=$3)`, seed.ClusterID, seed.SourceID, seed.Operation).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		jobID := "m1/" + string(seed.SourceID) + "/" + string(op.Query)
		if _, err := tx.Exec(ctx, `INSERT INTO collection_jobs(job_id,cluster_id,source_id,query_kind,interval_seconds,next_run_at,active)
		 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(source_id,query_kind,node_filter) DO NOTHING`, jobID, seed.ClusterID, seed.SourceID, op.Query, int64(seed.Interval/time.Second), firstRun.UTC(), seed.Enabled); err != nil {
			return err
		}
		var seconds int64
		if err := tx.QueryRow(ctx, `SELECT job_id,interval_seconds,active FROM collection_jobs WHERE cluster_id=$1 AND source_id=$2 AND query_kind=$3 AND node_filter='' FOR UPDATE`, seed.ClusterID, seed.SourceID, op.Query).Scan(&jobID, &seconds, &seed.Enabled); err != nil {
			return err
		}
		seed.Interval = time.Duration(seconds) * time.Second
		// Keep the persisted cadence even when startup defaults specify a longer
		// timeout. A timeout can safely shrink to that cadence during import.
		if seed.Timeout > seed.Interval {
			seed.Timeout = seed.Interval
		}
		if err := seed.Validate(); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO desired_schedules (`+scheduleColumns+`,legacy_query_kind,legacy_job_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1,$12,$13)`,
			seed.ClusterID, seed.SourceID, seed.Operation, seed.Enabled, seed.Mode, seconds, seed.Timeout.Milliseconds(), seed.Jitter.Milliseconds(), seed.MaxTargets, seed.MaxBytes, seed.Priority, op.Query, jobID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

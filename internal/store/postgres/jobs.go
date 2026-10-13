package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ErrCollectionClaimSuperseded is an expected configuration/lease race. It
// never represents an operational database error and is safe to skip/reclaim.
var ErrCollectionClaimSuperseded = errors.New("collection claim was superseded")

type ClaimedJob struct {
	JobID                 string
	ClusterID             domain.ClusterID
	SourceID              domain.SourceID
	Query                 domain.QueryKind
	Node                  string
	ScheduledFor          time.Time
	Interval              time.Duration
	Attempt               int
	ConfigurationRevision int64
	LeaseGeneration       int64
	DesiredRevision       int64
	Timeout               time.Duration
	MaxTargets            int
	MaxBytes              int64
}

func (s *CollectionStore) EnsureJob(ctx context.Context, jobID string, clusterID domain.ClusterID, sourceID domain.SourceID, query domain.QueryKind, node string, interval time.Duration, firstRun time.Time) error {
	if interval <= 0 || interval%time.Second != 0 {
		return fmt.Errorf("job interval must be a positive whole number of seconds")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var source domain.SourceID
	if err := tx.QueryRow(ctx, `SELECT source_id FROM sources WHERE cluster_id=$1 AND source_id=$2 FOR UPDATE`, clusterID, sourceID).Scan(&source); err != nil {
		return fmt.Errorf("collection job source scope: %w", err)
	}
	var ownedJob string
	err = tx.QueryRow(ctx, `SELECT legacy_job_id FROM desired_schedules WHERE cluster_id=$1 AND source_id=$2 AND legacy_query_kind=$3`, clusterID, sourceID, query).Scan(&ownedJob)
	if err == nil {
		if ownedJob != jobID || node != "" {
			return fmt.Errorf("collection operation is owned by a desired schedule")
		}
		return tx.Commit(ctx)
	}
	if err != pgx.ErrNoRows {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO collection_jobs (job_id, cluster_id, source_id, query_kind, node_filter, interval_seconds, next_run_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (source_id, query_kind, node_filter) DO NOTHING`,
		jobID, clusterID, sourceID, query, node, int(interval/time.Second), firstRun.UTC())
	if err != nil {
		return fmt.Errorf("ensure collection job %s: %w", jobID, err)
	}
	return tx.Commit(ctx)
}

func (s *CollectionStore) ClaimDueJob(ctx context.Context, owner string, leaseFor time.Duration) (ClaimedJob, bool, error) {
	return s.claimDueJob(ctx, owner, leaseFor, nil, nil)
}

func (s *CollectionStore) ClaimDueSourceJob(ctx context.Context, owner string, leaseFor time.Duration, sourceID domain.SourceID) (ClaimedJob, bool, error) {
	if sourceID == "" {
		return ClaimedJob{}, false, fmt.Errorf("source identifier is required")
	}
	return s.claimDueJob(ctx, owner, leaseFor, &sourceID, nil)
}

func (s *CollectionStore) ClaimDueClusterSourceJob(ctx context.Context, owner string, leaseFor time.Duration, clusterID domain.ClusterID, sourceID domain.SourceID) (ClaimedJob, bool, error) {
	if clusterID == "" || sourceID == "" {
		return ClaimedJob{}, false, fmt.Errorf("cluster and source identifiers are required")
	}
	return s.claimDueJob(ctx, owner, leaseFor, &sourceID, &clusterID)
}

func (s *CollectionStore) claimDueJob(ctx context.Context, owner string, leaseFor time.Duration, sourceID *domain.SourceID, clusterID *domain.ClusterID) (ClaimedJob, bool, error) {
	if owner == "" || leaseFor <= 0 {
		return ClaimedJob{}, false, fmt.Errorf("lease owner and positive duration are required")
	}
	var job ClaimedJob
	var intervalSeconds int
	var sourceFilter any
	var clusterFilter any
	var timeoutMS int64
	if sourceID != nil {
		sourceFilter = string(*sourceID)
	}
	if clusterID != nil {
		clusterFilter = string(*clusterID)
	}
	// Decide eligibility at statement start so PostgreSQL can use the due-time
	// index. A job becoming due during this statement waits for the next poll;
	// lease assignment still uses the actual database clock below.
	err := s.pool.QueryRow(ctx, `
		WITH candidate AS (
			SELECT j.job_id,j.desired_revision,COALESCE(d.timeout_ms,0) AS timeout_ms,
			 COALESCE(d.max_targets,0) AS max_targets,COALESCE(d.max_bytes,0) AS max_bytes
			FROM collection_jobs j LEFT JOIN desired_schedules d ON d.cluster_id=j.cluster_id AND d.legacy_job_id=j.job_id
			WHERE j.active AND j.next_run_at <= statement_timestamp()
			  AND ($3::text IS NULL OR j.source_id=$3::text)
			  AND ($4::text IS NULL OR j.cluster_id=$4::text)
			  AND (j.desired_revision=0 OR (d.revision=j.desired_revision AND d.enabled AND d.mode='legacy'))
			  AND (j.lease_expires_at IS NULL OR j.lease_expires_at < statement_timestamp())
			ORDER BY j.next_run_at, j.job_id
			FOR UPDATE OF j SKIP LOCKED LIMIT 1
		)
		UPDATE collection_jobs j SET
			lease_owner=$1,
			lease_expires_at=clock_timestamp() + (GREATEST($2,candidate.timeout_ms*2) * interval '1 millisecond'),
			lease_generation=j.lease_generation + 1,
			attempt_count=j.attempt_count + 1
		FROM candidate WHERE j.job_id=candidate.job_id AND j.desired_revision=candidate.desired_revision
		RETURNING j.job_id, j.cluster_id, j.source_id, j.query_kind, j.node_filter,
		          j.next_run_at, j.interval_seconds, j.attempt_count, j.configuration_revision, j.lease_generation,
		          j.desired_revision,candidate.timeout_ms,candidate.max_targets,candidate.max_bytes`,
		owner, leaseFor.Milliseconds(), sourceFilter, clusterFilter).Scan(&job.JobID, &job.ClusterID, &job.SourceID, &job.Query,
		&job.Node, &job.ScheduledFor, &intervalSeconds, &job.Attempt, &job.ConfigurationRevision, &job.LeaseGeneration,
		&job.DesiredRevision, &timeoutMS, &job.MaxTargets, &job.MaxBytes)
	if err == pgx.ErrNoRows {
		return ClaimedJob{}, false, nil
	}
	if err != nil {
		return ClaimedJob{}, false, fmt.Errorf("claim due collection job: %w", err)
	}
	job.ScheduledFor = job.ScheduledFor.UTC()
	job.Interval = time.Duration(intervalSeconds) * time.Second
	job.Timeout = time.Duration(timeoutMS) * time.Millisecond
	return job, true, nil
}

// CompleteJob coalesces missed periodic ticks after recording the claimed run.
// The next tick stays on the original cadence and moves beyond completion time;
// historical results and any concurrently postponed schedule are preserved.
func (s *CollectionStore) CompleteJob(ctx context.Context, job ClaimedJob, owner string) error {
	command, err := s.pool.Exec(ctx, `
		UPDATE collection_jobs SET
			next_run_at=GREATEST(next_run_at,$3::timestamptz +
                GREATEST(1, floor(extract(epoch FROM (statement_timestamp()-$3::timestamptz))/$4)+1)
                * ($4 * interval '1 second')),
			lease_owner=NULL, lease_expires_at=NULL, attempt_count=0
		WHERE job_id=$1 AND lease_owner=$2 AND lease_generation=$5 AND configuration_revision=$6
		AND cluster_id=$7 AND source_id=$8 AND desired_revision=$9 AND active
		AND lease_expires_at>clock_timestamp()`, job.JobID, owner, job.ScheduledFor.UTC(), int64(job.Interval/time.Second), job.LeaseGeneration, job.ConfigurationRevision, job.ClusterID, job.SourceID, job.DesiredRevision)
	if err != nil {
		return fmt.Errorf("complete collection job %s: %w", job.JobID, err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("%w: collection job %s lease is no longer owned by %s", ErrCollectionClaimSuperseded, job.JobID, owner)
	}
	return nil
}

// BindCollectionJob commits authoritative run provenance before collection I/O.
// A reused owner cannot bind work from an expired or superseded claim.
func (s *CollectionStore) BindCollectionJob(ctx context.Context, job ClaimedJob, owner string, runID domain.RunID) (domain.RunID, error) {
	if runID == "" || owner == "" || job.LeaseGeneration <= 0 {
		return "", fmt.Errorf("collection run binding requires a current claim")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var valid bool
	err = tx.QueryRow(ctx, `SELECT active AND lease_owner=$3 AND lease_generation=$4
		AND configuration_revision=$5 AND lease_expires_at>clock_timestamp()
		AND source_id=$6 AND query_kind=$7 AND node_filter=$8 AND next_run_at=$9 AND desired_revision=$10
		FROM collection_jobs WHERE job_id=$1 AND cluster_id=$2 FOR UPDATE`, job.JobID, job.ClusterID, owner,
		job.LeaseGeneration, job.ConfigurationRevision, job.SourceID, job.Query, job.Node, job.ScheduledFor.UTC(), job.DesiredRevision).Scan(&valid)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("read collection claim for binding: %w", err)
	}
	if errors.Is(err, pgx.ErrNoRows) || !valid {
		return "", fmt.Errorf("%w: collection run binding requires a current claim", ErrCollectionClaimSuperseded)
	}
	_, err = tx.Exec(ctx, `INSERT INTO collection_run_jobs
		(run_id,job_id,cluster_id,source_id,query_kind,node_filter,scheduled_for,configuration_revision,lease_generation)
		SELECT $1,job_id,cluster_id,source_id,query_kind,node_filter,$5,configuration_revision,lease_generation
		FROM collection_jobs WHERE job_id=$2 AND cluster_id=$3 AND lease_owner=$4
		AND lease_generation=$6 AND configuration_revision=$7 AND lease_expires_at>clock_timestamp()
		AND source_id=$8 AND query_kind=$9 AND node_filter=$10 AND next_run_at=$5 AND active
		ON CONFLICT (cluster_id,job_id,scheduled_for,configuration_revision) DO NOTHING`, runID, job.JobID, job.ClusterID, owner, job.ScheduledFor.UTC(),
		job.LeaseGeneration, job.ConfigurationRevision, job.SourceID, job.Query, job.Node)
	if err != nil {
		return "", fmt.Errorf("bind scheduled collection run: %w", err)
	}
	var canonical domain.RunID
	err = tx.QueryRow(ctx, `SELECT run_id FROM collection_run_jobs WHERE cluster_id=$1 AND job_id=$2
		AND scheduled_for=$3 AND configuration_revision=$4 AND source_id=$5 AND query_kind=$6 AND node_filter=$7`,
		job.ClusterID, job.JobID, job.ScheduledFor.UTC(), job.ConfigurationRevision, job.SourceID, job.Query, job.Node).Scan(&canonical)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("%w: claim expired before occurrence binding", ErrCollectionClaimSuperseded)
	}
	if err != nil {
		return "", fmt.Errorf("read canonical collection occurrence: %w", err)
	}
	return canonical, tx.Commit(ctx)
}

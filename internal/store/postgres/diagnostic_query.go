package postgres

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type DiagnosticQueryStore struct {
	pool *pgxpool.Pool
}

func NewDiagnosticQueryStore(pool *pgxpool.Pool) (*DiagnosticQueryStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	return &DiagnosticQueryStore{pool: pool}, nil
}

func (store *DiagnosticQueryStore) GetDiagnosticRunProjection(ctx context.Context, clusterID domain.ClusterID, runID domain.DiagnosticRunID) (application.DiagnosticRunProjection, bool, error) {
	if clusterID == "" || runID == "" {
		return application.DiagnosticRunProjection{}, false, fmt.Errorf("cluster and diagnostic run identifiers are required")
	}
	var projection application.DiagnosticRunProjection
	var definitionDigest []byte
	err := store.pool.QueryRow(ctx, `
		SELECT r.run_id, r.cluster_id, r.pack_id, r.pack_version, r.definition_id, r.definition_version,
		       r.definition_digest, r.privilege, r.status, r.requested_by,
		       r.requested_at, r.deadline, r.completed_at, r.version, w.work_id
		FROM diagnostic_runs r
		JOIN diagnostic_work_items w ON w.run_id=r.run_id
		WHERE r.cluster_id=$1 AND r.run_id=$2`, clusterID, runID).Scan(
		&projection.RunID, &projection.ClusterID, &projection.Definition.PackID,
		&projection.Definition.PackVersion, &projection.Definition.DefinitionID,
		&projection.Definition.DefinitionVersion, &definitionDigest, &projection.Privilege, &projection.Status,
		&projection.RequestedBy, &projection.RequestedAt, &projection.Deadline,
		&projection.CompletedAt, &projection.Version, &projection.WorkID)
	if err == pgx.ErrNoRows {
		return application.DiagnosticRunProjection{}, false, nil
	}
	if err != nil {
		return application.DiagnosticRunProjection{}, false, fmt.Errorf("load diagnostic run projection: %w", err)
	}
	if len(definitionDigest) != sha256.Size {
		return application.DiagnosticRunProjection{}, false, fmt.Errorf("stored diagnostic definition digest is invalid")
	}
	copy(projection.Definition.DefinitionDigest[:], definitionDigest)
	projection.RequestedAt = projection.RequestedAt.UTC()
	projection.Deadline = projection.Deadline.UTC()
	projection.CompletedAt = utcTimePointer(projection.CompletedAt)

	rows, err := store.pool.Query(ctx, `
		SELECT a.attempt, a.runner_id, a.status, a.lease_expires_at, a.plan_digest,
		       a.started_at, a.completed_at
		FROM diagnostic_work_attempts a
		JOIN diagnostic_work_items w ON w.work_id=a.work_id
		JOIN diagnostic_runs r ON r.run_id=w.run_id
		WHERE r.cluster_id=$1 AND r.run_id=$2 AND a.work_id=$3
		ORDER BY a.attempt`, clusterID, runID, projection.WorkID)
	if err != nil {
		return application.DiagnosticRunProjection{}, false, fmt.Errorf("load diagnostic attempts: %w", err)
	}
	for rows.Next() {
		var attempt application.DiagnosticAttemptProjection
		var planDigest []byte
		if err := rows.Scan(&attempt.Attempt, &attempt.RunnerID, &attempt.Status,
			&attempt.LeaseExpires, &planDigest, &attempt.StartedAt, &attempt.CompletedAt); err != nil {
			rows.Close()
			return application.DiagnosticRunProjection{}, false, fmt.Errorf("scan diagnostic attempt: %w", err)
		}
		if planDigest != nil {
			if len(planDigest) != sha256.Size {
				rows.Close()
				return application.DiagnosticRunProjection{}, false, fmt.Errorf("stored diagnostic plan digest is invalid")
			}
			var digest domain.SHA256
			copy(digest[:], planDigest)
			attempt.PlanDigest = &digest
		}
		attempt.LeaseExpires = attempt.LeaseExpires.UTC()
		attempt.StartedAt = utcTimePointer(attempt.StartedAt)
		attempt.CompletedAt = utcTimePointer(attempt.CompletedAt)
		projection.Attempts = append(projection.Attempts, attempt)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return application.DiagnosticRunProjection{}, false, fmt.Errorf("load diagnostic attempts: %w", err)
	}
	rows.Close()

	attemptIndexes := make(map[int]int, len(projection.Attempts))
	for index, attempt := range projection.Attempts {
		attemptIndexes[attempt.Attempt] = index
	}
	targetRows, err := store.pool.Query(ctx, `
		SELECT t.attempt, t.target, t.status, t.retryable, t.exit_code, t.signal,
		       t.timed_out, t.stdout_truncated, t.stderr_truncated,
		       t.stdout_bytes, t.stderr_bytes, t.stdout_sha256, t.stderr_sha256,
		       t.error_code, t.stdout_excerpt, t.stdout_transformation_state
		FROM diagnostic_target_results t
		JOIN diagnostic_work_items w ON w.work_id=t.work_id
		JOIN diagnostic_runs r ON r.run_id=w.run_id
		WHERE r.cluster_id=$1 AND r.run_id=$2 AND t.work_id=$3
		ORDER BY t.attempt, t.target`, clusterID, runID, projection.WorkID)
	if err != nil {
		return application.DiagnosticRunProjection{}, false, fmt.Errorf("load diagnostic target results: %w", err)
	}
	defer targetRows.Close()
	for targetRows.Next() {
		var attemptNumber int
		var result domain.DiagnosticTargetResult
		var stdoutDigest, stderrDigest []byte
		if err := targetRows.Scan(&attemptNumber, &result.Target, &result.Status,
			&result.Retryable, &result.ExitCode, &result.Signal, &result.TimedOut,
			&result.StdoutTruncated, &result.StderrTruncated, &result.StdoutBytes,
			&result.StderrBytes, &stdoutDigest, &stderrDigest, &result.ErrorCode, &result.StdoutExcerpt, &result.StdoutTransformationState); err != nil {
			return application.DiagnosticRunProjection{}, false, fmt.Errorf("scan diagnostic target result: %w", err)
		}
		index, exists := attemptIndexes[attemptNumber]
		if !exists {
			return application.DiagnosticRunProjection{}, false, fmt.Errorf("diagnostic target result has no attributable attempt")
		}
		if len(stdoutDigest) != sha256.Size || len(stderrDigest) != sha256.Size {
			return application.DiagnosticRunProjection{}, false, fmt.Errorf("stored diagnostic output digest is invalid")
		}
		copy(result.StdoutSHA256[:], stdoutDigest)
		copy(result.StderrSHA256[:], stderrDigest)
		projection.Attempts[index].Targets = append(projection.Attempts[index].Targets, result)
	}
	if err := targetRows.Err(); err != nil {
		return application.DiagnosticRunProjection{}, false, fmt.Errorf("load diagnostic target results: %w", err)
	}
	return projection, true, nil
}

func utcTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	utc := value.UTC()
	return &utc
}

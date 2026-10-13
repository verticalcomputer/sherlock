package postgres

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type CollectorControlStore struct {
	pool *pgxpool.Pool
}

func NewCollectorControlStore(pool *pgxpool.Pool) (*CollectorControlStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	return &CollectorControlStore{pool: pool}, nil
}

func (s *CollectorControlStore) ConsumeCollectorRequestNonce(ctx context.Context, fingerprint [32]byte, correlationID string, expiresAt time.Time) error {
	if fingerprint == ([32]byte{}) || correlationID == "" || len(correlationID) > 128 || expiresAt.IsZero() {
		return fmt.Errorf("collector request nonce is invalid")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin collector request nonce consumption: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM collector_request_nonces WHERE expires_at <= clock_timestamp()`); err != nil {
		return fmt.Errorf("expire collector request nonces: %w", err)
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO collector_request_nonces (
			certificate_fingerprint, correlation_id, expires_at
		) VALUES ($1,$2,$3)
		ON CONFLICT (certificate_fingerprint, correlation_id) DO NOTHING`,
		fingerprint[:], correlationID, expiresAt.UTC())
	if err != nil {
		return fmt.Errorf("consume collector request nonce: %w", err)
	}
	if command.RowsAffected() != 1 {
		return collectorcontrol.ErrRequestReplay
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit collector request nonce consumption: %w", err)
	}
	return nil
}

type CollectorRegistration struct {
	CollectorID     domain.CollectorID
	ClusterID       domain.ClusterID
	DisplayName     string
	Version         string
	BuildCommit     string
	ProtocolMin     int
	ProtocolMax     int
	OperatingSystem string
	Architecture    string
}

func (s *CollectorControlStore) RegisterCollector(ctx context.Context, registration CollectorRegistration) error {
	if registration.CollectorID == "" || registration.ClusterID == "" || registration.DisplayName == "" || registration.Version == "" {
		return fmt.Errorf("collector identity, cluster, display name, and version are required")
	}
	if registration.ProtocolMin < 1 || registration.ProtocolMax < registration.ProtocolMin {
		return fmt.Errorf("collector protocol range is invalid")
	}
	if registration.OperatingSystem == "" || registration.Architecture == "" {
		return fmt.Errorf("collector operating system and architecture are required")
	}
	command, err := s.pool.Exec(ctx, `
		INSERT INTO collectors (
			collector_id, cluster_id, display_name, status, version, build_commit,
			protocol_min, protocol_max, operating_system, architecture
		) VALUES ($1,$2,$3,'ACTIVE',$4,$5,$6,$7,$8,$9)
		ON CONFLICT (collector_id) DO UPDATE SET
			display_name=EXCLUDED.display_name,
			version=EXCLUDED.version,
			build_commit=EXCLUDED.build_commit,
			protocol_min=EXCLUDED.protocol_min,
			protocol_max=EXCLUDED.protocol_max,
			operating_system=EXCLUDED.operating_system,
			architecture=EXCLUDED.architecture
		WHERE collectors.cluster_id=EXCLUDED.cluster_id AND collectors.status <> 'REVOKED'`,
		registration.CollectorID, registration.ClusterID, registration.DisplayName,
		registration.Version, registration.BuildCommit, registration.ProtocolMin,
		registration.ProtocolMax, registration.OperatingSystem, registration.Architecture)
	if err != nil {
		return fmt.Errorf("register collector %s: %w", registration.CollectorID, err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("collector %s is revoked or belongs to another cluster", registration.CollectorID)
	}
	return nil
}

func (s *CollectorControlStore) ReplaceCapabilities(ctx context.Context, collectorID domain.CollectorID, capabilities map[string]string) error {
	if collectorID == "" {
		return fmt.Errorf("collector identifier is required")
	}
	if len(capabilities) == 0 || len(capabilities) > 100 {
		return fmt.Errorf("collector must report between 1 and 100 capabilities")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin capability replacement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var active bool
	if err := tx.QueryRow(ctx, `SELECT status='ACTIVE' FROM collectors WHERE collector_id=$1 FOR UPDATE`, collectorID).Scan(&active); err != nil {
		return fmt.Errorf("load collector %s: %w", collectorID, err)
	}
	if !active {
		return fmt.Errorf("collector %s is not active", collectorID)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM collector_capabilities WHERE collector_id=$1`, collectorID); err != nil {
		return fmt.Errorf("clear capabilities for collector %s: %w", collectorID, err)
	}
	for capability, version := range capabilities {
		if capability == "" || version == "" {
			return fmt.Errorf("collector capability and version are required")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO collector_capabilities (collector_id, capability, version) VALUES ($1,$2,$3)`, collectorID, capability, version); err != nil {
			return fmt.Errorf("record capability for collector %s: %w", collectorID, err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE collectors SET last_heartbeat_at=clock_timestamp() WHERE collector_id=$1`, collectorID); err != nil {
		return fmt.Errorf("record heartbeat for collector %s: %w", collectorID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit capabilities for collector %s: %w", collectorID, err)
	}
	return nil
}

func (s *CollectorControlStore) EnqueueCollectionWork(ctx context.Context, work domain.CollectorWork) (bool, error) {
	if err := domain.ValidateCollectorWork(work); err != nil {
		return false, err
	}
	if work.Status != domain.WorkAvailable {
		return false, fmt.Errorf("new collector work must be available")
	}
	command, err := s.pool.Exec(ctx, `
		INSERT INTO collector_work_items (
			work_id, run_id, cluster_id, source_id, query_kind, node_filter,
			range_start, range_end, range_step_seconds, scheduled_for, deadline,
			max_series, max_bytes, idempotency_key, available_at, work_expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (idempotency_key) DO NOTHING`,
		work.WorkID, work.Task.RunID, work.Task.ClusterID, work.Task.SourceID, work.Task.Query,
		work.Task.Node, rangeStart(work.Task.Range), rangeEnd(work.Task.Range), rangeStep(work.Task.Range),
		work.Task.ScheduledFor.UTC(), work.Task.Deadline.UTC(), work.Task.MaxSeries, work.Task.MaxBytes,
		work.Task.IdempotencyKey, work.AvailableAt.UTC(), work.WorkExpiresAt.UTC())
	if err != nil {
		return false, fmt.Errorf("enqueue collector work %s: %w", work.WorkID, err)
	}
	return command.RowsAffected() == 1, nil
}

func (s *CollectorControlStore) ClaimWork(ctx context.Context, collectorID domain.CollectorID, leaseToken string, leaseFor time.Duration) (domain.WorkLease, bool, error) {
	if collectorID == "" || leaseToken == "" || leaseFor <= 0 {
		return domain.WorkLease{}, false, fmt.Errorf("collector, lease token, and positive lease duration are required")
	}
	if leaseFor > 5*time.Minute {
		return domain.WorkLease{}, false, fmt.Errorf("collector work lease cannot exceed five minutes")
	}
	tokenHash := sha256.Sum256([]byte(leaseToken))
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.WorkLease{}, false, fmt.Errorf("begin collector work claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var cluster domain.ClusterID
	var dispatchPeriod int
	if err = tx.QueryRow(ctx, `SELECT cluster_id,collection_dispatch_period FROM collectors WHERE collector_id=$1`, collectorID).Scan(&cluster, &dispatchPeriod); err != nil {
		return domain.WorkLease{}, false, fmt.Errorf("load collector cluster: %w", err)
	}
	if dispatchPeriod > 0 {
		return s.claimReservedCollection(ctx, tx, collectorID, leaseToken, leaseFor)
	}
	// Ordinary collector polling must not take the live-repair authority lock:
	// doing so would make unrelated inventory writers spuriously fail their
	// fail-fast population fence. A repair is only selectable after this probe;
	// if none existed in the probe snapshot, the claim query excludes repairs
	// and leaves a concurrently inserted one for the next poll.
	var repairSelectable bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM collection_repair_requests r
		JOIN collector_work_items w ON w.work_id=r.work_id
		WHERE r.cluster_id=$1 AND r.status IN ('REQUESTED','CLAIMED')
		  AND w.status IN ('AVAILABLE','LEASED') AND r.deadline_at>clock_timestamp()
	)`, cluster).Scan(&repairSelectable); err != nil {
		return domain.WorkLease{}, false, fmt.Errorf("inspect repair work: %w", err)
	}
	if repairSelectable {
		if err = LockRepairAuthority(ctx, tx, cluster); err != nil {
			return domain.WorkLease{}, false, fmt.Errorf("lock repair authority: %w", err)
		}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE collector_work_attempts a SET status='EXPIRED', completed_at=clock_timestamp()
		FROM collector_work_items w
		WHERE a.work_id=w.work_id AND w.cluster_id=(SELECT cluster_id FROM collectors WHERE collector_id=$1)
		  AND a.status IN ('CLAIMED','STARTED') AND a.lease_expires_at <= clock_timestamp()`, collectorID); err != nil {
		return domain.WorkLease{}, false, fmt.Errorf("expire collector work leases: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE collector_work_items w SET status='AVAILABLE'
		WHERE w.cluster_id=(SELECT cluster_id FROM collectors WHERE collector_id=$1)
		  AND w.status='LEASED'
		  AND NOT EXISTS (
			SELECT 1 FROM collector_work_attempts a
			WHERE a.work_id=w.work_id AND a.status IN ('CLAIMED','STARTED')
		  )`, collectorID); err != nil {
		return domain.WorkLease{}, false, fmt.Errorf("release expired collector work: %w", err)
	}

	// Drain terminal ordinary work in bounded batches. Do not touch repair work
	// or any attempt that could still finalize; those retain their own fences.
	if _, err := tx.Exec(ctx, `
        WITH expired AS (
            SELECT w.work_id FROM collector_work_items w
            WHERE w.cluster_id=$1 AND w.status IN ('AVAILABLE','LEASED')
              AND (w.work_expires_at<=clock_timestamp() OR w.deadline<=clock_timestamp())
              AND NOT w.remediation_runtime_managed
              AND NOT EXISTS (SELECT 1 FROM collection_repair_requests r WHERE r.work_id=w.work_id)
              AND NOT EXISTS (SELECT 1 FROM collector_work_attempts a WHERE a.work_id=w.work_id
                AND a.status IN ('CLAIMED','STARTED'))
            ORDER BY w.work_expires_at,w.work_id
            LIMIT 256 FOR UPDATE OF w SKIP LOCKED
        )
        UPDATE collector_work_items w SET status='FAILED',completed_at=clock_timestamp()
        FROM expired e WHERE w.work_id=e.work_id`, cluster); err != nil {
		return domain.WorkLease{}, false, fmt.Errorf("reconcile expired ordinary collector work: %w", err)
	}

	var lease domain.WorkLease
	var query domain.QueryKind
	var rangeStartAt, rangeEndAt *time.Time
	var rangeStepSeconds *float64
	err = tx.QueryRow(ctx, `
		WITH candidate AS (
			SELECT w.work_id, w.next_attempt
			FROM collector_work_items w
			JOIN collectors c ON c.cluster_id=w.cluster_id
			JOIN collector_capabilities cap ON cap.collector_id=c.collector_id AND cap.capability=w.query_kind
			WHERE c.collector_id=$1 AND c.status='ACTIVE'
			  AND w.typed_plan IS NULL
			  AND durable_work_claimable(w.work_id,c.collector_id)
			  AND w.status='AVAILABLE' AND w.available_at <= clock_timestamp()
			  AND w.work_expires_at > clock_timestamp() AND w.deadline > clock_timestamp()
			  AND ($4 OR NOT EXISTS (SELECT 1 FROM collection_repair_requests repair WHERE repair.work_id=w.work_id))
			  AND (
			    NOT EXISTS (SELECT 1 FROM collection_repair_requests repair WHERE repair.work_id=w.work_id)
			    OR EXISTS (
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
			    )
			  )
			ORDER BY w.available_at, w.work_id
			FOR UPDATE OF w SKIP LOCKED LIMIT 1
		), claimed AS (
			UPDATE collector_work_items w SET status='LEASED', next_attempt=w.next_attempt + 1
			FROM candidate WHERE w.work_id=candidate.work_id
			RETURNING w.*, candidate.next_attempt AS claimed_attempt
		)
		INSERT INTO collector_work_attempts (
			work_id, attempt, collector_id, lease_token_hash, lease_expires_at
		)
		SELECT work_id, claimed_attempt, $1, $2, clock_timestamp() + ($3 * interval '1 millisecond')
		FROM claimed
		RETURNING work_id, attempt, collector_id, lease_expires_at`,
		collectorID, tokenHash[:], leaseFor.Milliseconds(), repairSelectable).Scan(
		&lease.Work.WorkID, &lease.Attempt, &lease.CollectorID, &lease.LeaseExpires)
	if err == pgx.ErrNoRows {
		if err := tx.Commit(ctx); err != nil {
			return domain.WorkLease{}, false, fmt.Errorf("commit empty collector work claim: %w", err)
		}
		return domain.WorkLease{}, false, nil
	}
	if err != nil {
		return domain.WorkLease{}, false, fmt.Errorf("claim work for collector %s: %w", collectorID, err)
	}
	if err := tx.QueryRow(ctx, `
		SELECT run_id, cluster_id, source_id, query_kind, node_filter,
		       range_start, range_end, range_step_seconds, scheduled_for, deadline,
		       max_series, max_bytes, idempotency_key, status, available_at, work_expires_at
		FROM collector_work_items WHERE work_id=$1`, lease.Work.WorkID).Scan(
		&lease.Work.Task.RunID, &lease.Work.Task.ClusterID, &lease.Work.Task.SourceID, &query,
		&lease.Work.Task.Node, &rangeStartAt, &rangeEndAt, &rangeStepSeconds,
		&lease.Work.Task.ScheduledFor, &lease.Work.Task.Deadline, &lease.Work.Task.MaxSeries,
		&lease.Work.Task.MaxBytes, &lease.Work.Task.IdempotencyKey, &lease.Work.Status,
		&lease.Work.AvailableAt, &lease.Work.WorkExpiresAt); err != nil {
		return domain.WorkLease{}, false, fmt.Errorf("load claimed collector work %s: %w", lease.Work.WorkID, err)
	}
	lease.Work.Task.Query = query
	if rangeStartAt != nil {
		lease.Work.Task.Range = &domain.CollectionRange{
			Start: rangeStartAt.UTC(), End: rangeEndAt.UTC(), Step: time.Duration(*rangeStepSeconds * float64(time.Second)),
		}
	}
	lease.LeaseToken = leaseToken
	lease.LeaseExpires = lease.LeaseExpires.UTC()
	lease.Work.AvailableAt = lease.Work.AvailableAt.UTC()
	lease.Work.WorkExpiresAt = lease.Work.WorkExpiresAt.UTC()
	lease.Work.Task.ScheduledFor = lease.Work.Task.ScheduledFor.UTC()
	lease.Work.Task.Deadline = lease.Work.Task.Deadline.UTC()
	if err := tx.Commit(ctx); err != nil {
		return domain.WorkLease{}, false, fmt.Errorf("commit collector work claim: %w", err)
	}
	return lease, true, nil
}

func (s *CollectorControlStore) AcknowledgeWorkStart(ctx context.Context, collectorID domain.CollectorID, workID domain.WorkID, attempt int, leaseToken string) error {
	return s.updateLease(ctx, collectorID, workID, attempt, leaseToken, 0, true)
}

func (s *CollectorControlStore) RenewWorkLease(ctx context.Context, collectorID domain.CollectorID, workID domain.WorkID, attempt int, leaseToken string, leaseFor time.Duration) error {
	if leaseFor <= 0 || leaseFor > 5*time.Minute {
		return fmt.Errorf("renewal duration must be between zero and five minutes")
	}
	return s.updateLease(ctx, collectorID, workID, attempt, leaseToken, leaseFor, false)
}

func (s *CollectorControlStore) updateLease(ctx context.Context, collectorID domain.CollectorID, workID domain.WorkID, attempt int, leaseToken string, leaseFor time.Duration, start bool) error {
	if collectorID == "" || workID == "" || attempt < 1 || leaseToken == "" {
		return fmt.Errorf("collector, work, attempt, and lease token are required")
	}
	tokenHash := sha256.Sum256([]byte(leaseToken))
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin collector work lease update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var cluster domain.ClusterID
	var repairWork bool
	if err = tx.QueryRow(ctx, `SELECT w.cluster_id FROM collector_work_attempts a
		JOIN collector_work_items w ON w.work_id=a.work_id
		WHERE a.work_id=$1 AND a.attempt=$2 AND a.collector_id=$3`, workID, attempt, collectorID).Scan(&cluster); err != nil {
		return fmt.Errorf("%w: work %s attempt %d", collectorcontrol.ErrWorkLeaseInvalid, workID, attempt)
	}
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM collection_repair_requests WHERE work_id=$1)`, workID).Scan(&repairWork); err != nil {
		return fmt.Errorf("inspect repair work lease: %w", err)
	}
	if repairWork {
		if err = LockRepairAuthority(ctx, tx, cluster); err != nil {
			return fmt.Errorf("lock repair authority: %w", err)
		}
	}
	// Claims and finalization already hold the work row. Start/renew must share
	// that authority lock so expiry reconciliation cannot free capacity while
	// a lease extension remains uncommitted. Preserve repair -> work ordering.
	var leased bool
	if err = tx.QueryRow(ctx, `SELECT status='LEASED' FROM collector_work_items WHERE work_id=$1 FOR UPDATE`, workID).Scan(&leased); err != nil || !leased {
		return fmt.Errorf("%w: work %s is not leased", collectorcontrol.ErrWorkLeaseInvalid, workID)
	}
	// Existing ordinary claim cleanup locks expired attempts before work. Fail
	// fast here if it owns this attempt, avoiding a work/attempt lock cycle.
	var lockedAttempt int
	if err = tx.QueryRow(ctx, `SELECT attempt FROM collector_work_attempts WHERE work_id=$1 AND attempt=$2 FOR UPDATE NOWAIT`, workID, attempt).Scan(&lockedAttempt); err != nil {
		return fmt.Errorf("lock collector attempt for lease update: %w", err)
	}
	var command string
	var arguments []any
	if start {
		command = `UPDATE collector_work_attempts SET status='STARTED', started_at=COALESCE(started_at, clock_timestamp())
			WHERE work_id=$1 AND attempt=$2 AND collector_id=$3 AND lease_token_hash=$4
			  AND status IN ('CLAIMED','STARTED') AND lease_expires_at > clock_timestamp()`
		arguments = []any{workID, attempt, collectorID, tokenHash[:]}
	} else {
		command = `UPDATE collector_work_attempts
			SET lease_expires_at=clock_timestamp() + ($5 * interval '1 millisecond')
			WHERE work_id=$1 AND attempt=$2 AND collector_id=$3 AND lease_token_hash=$4
			  AND status IN ('CLAIMED','STARTED') AND lease_expires_at > clock_timestamp()`
		arguments = []any{workID, attempt, collectorID, tokenHash[:], leaseFor.Milliseconds()}
	}
	result, err := tx.Exec(ctx, command, arguments...)
	if err != nil {
		return fmt.Errorf("update collector work lease %s attempt %d: %w", workID, attempt, err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("%w: work %s attempt %d", collectorcontrol.ErrWorkLeaseInvalid, workID, attempt)
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit collector work lease update: %w", err)
	}
	return nil
}

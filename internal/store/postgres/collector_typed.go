package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

var _ collectorcontrol.TypedCollectionOperations = (*CollectorControlStore)(nil)

// EnqueueTypedCollectionWork uses the existing queue and idempotency namespace.
// The operation ID occupies query_kind; v1 claims explicitly exclude typed plans.
func (s *CollectorControlStore) EnqueueTypedCollectionWork(ctx context.Context, workID domain.WorkID, plan domain.CollectionPlan, availableAt, expiresAt time.Time) (bool, error) {
	if err := domain.ValidateCollectionPlan(plan); err != nil {
		return false, err
	}
	if !domain.ValidCollectorWorkID(string(workID)) || availableAt.IsZero() || !expiresAt.After(availableAt) {
		return false, fmt.Errorf("typed work identity or availability interval is invalid")
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return false, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, fmt.Errorf("begin typed work enqueue: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var sourceID domain.SourceID
	if err := tx.QueryRow(ctx, `SELECT source_id FROM sources WHERE cluster_id=$1 AND source_id=$2 AND kind=$3 FOR SHARE`, plan.ClusterID, plan.SourceID, plan.SourceKind).Scan(&sourceID); err != nil {
		return false, fmt.Errorf("typed work source is not configured for its cluster and kind: %w", err)
	}
	command, err := tx.Exec(ctx, `INSERT INTO collector_work_items
		(work_id, run_id, cluster_id, source_id, query_kind, scheduled_for, deadline,
		 max_series, max_bytes, idempotency_key, available_at, work_expires_at, typed_plan)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (idempotency_key) DO NOTHING`, workID, plan.RunID, plan.ClusterID, plan.SourceID,
		plan.Operation, plan.ScheduledFor, plan.Deadline, plan.Limits.MaxRecords, plan.Limits.MaxBytes,
		plan.IdempotencyKey, availableAt, expiresAt, encoded)
	if err != nil {
		return false, fmt.Errorf("enqueue typed collection work: %w", err)
	}
	if command.RowsAffected() == 0 {
		var identical bool
		if err := tx.QueryRow(ctx, `SELECT work_id=$2 AND typed_plan=$3::jsonb AND available_at=$4 AND work_expires_at=$5
			FROM collector_work_items WHERE idempotency_key=$1`, plan.IdempotencyKey, workID, encoded, availableAt, expiresAt).Scan(&identical); err != nil {
			return false, fmt.Errorf("read existing typed work: %w", err)
		}
		if !identical {
			return false, resultConflict("typed work idempotency key conflicts with its stored plan")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit typed work enqueue: %w", err)
	}
	return command.RowsAffected() == 1, nil
}

func (s *CollectorControlStore) ClaimTypedWork(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, token string, leaseFor time.Duration, sources []domain.SourceID) (domain.TypedWorkLease, bool, error) {
	if err := domain.ValidateCollectionClaimSources(sources); err != nil {
		return domain.TypedWorkLease{}, false, invalidResultLease("typed claim source selection is invalid")
	}
	sourceIDs := make([]string, 0, len(sources))
	for _, source := range sources {
		sourceIDs = append(sourceIDs, string(source))
	}
	if clusterID == "" || collectorID == "" || len(token) < 32 || len(token) > 256 || leaseFor <= 0 || leaseFor > 5*time.Minute {
		return domain.TypedWorkLease{}, false, invalidResultLease("typed claim identity or lease bounds are invalid")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.TypedWorkLease{}, false, fmt.Errorf("begin typed work claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockTypedCollector(ctx, tx, clusterID, collectorID); err != nil {
		return domain.TypedWorkLease{}, false, err
	}
	var workID domain.WorkID
	var attempt int
	err = tx.QueryRow(ctx, `SELECT w.work_id, w.next_attempt FROM collector_work_items w
		JOIN collector_capabilities cap ON cap.collector_id=$2 AND cap.capability=w.query_kind AND cap.version='1'
		WHERE w.cluster_id=$1 AND w.typed_plan IS NOT NULL AND w.source_id=ANY($3)
		  AND durable_work_claimable(w.work_id,$2)
		  AND w.status IN ('AVAILABLE','LEASED') AND w.available_at<=clock_timestamp()
		  AND w.work_expires_at>clock_timestamp() AND w.deadline>clock_timestamp()
		  AND NOT w.remediation_runtime_managed
		  AND NOT EXISTS (SELECT 1 FROM collection_repair_requests r WHERE r.work_id=w.work_id)
		  AND NOT EXISTS (SELECT 1 FROM collector_work_attempts a WHERE a.work_id=w.work_id
		    AND a.status IN ('CLAIMED','STARTED') AND a.lease_expires_at>clock_timestamp())
		ORDER BY w.available_at,w.work_id FOR UPDATE OF w SKIP LOCKED LIMIT 1`, clusterID, collectorID, sourceIDs).Scan(&workID, &attempt)
	if err == pgx.ErrNoRows {
		if err := tx.Commit(ctx); err != nil {
			return domain.TypedWorkLease{}, false, err
		}
		return domain.TypedWorkLease{}, false, nil
	}
	if err != nil {
		return domain.TypedWorkLease{}, false, fmt.Errorf("select typed work: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE collector_work_attempts SET status='EXPIRED', completed_at=clock_timestamp()
		WHERE work_id=$1 AND status IN ('CLAIMED','STARTED') AND lease_expires_at<=clock_timestamp()`, workID); err != nil {
		return domain.TypedWorkLease{}, false, fmt.Errorf("expire typed attempt: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE collector_work_items SET status='LEASED',next_attempt=next_attempt+1 WHERE work_id=$1`, workID); err != nil {
		return domain.TypedWorkLease{}, false, fmt.Errorf("claim typed work: %w", err)
	}
	tokenHash := sha256.Sum256([]byte(token))
	if _, err := tx.Exec(ctx, `INSERT INTO collector_work_attempts (work_id,attempt,collector_id,lease_token_hash,lease_expires_at)
		VALUES ($1,$2,$3,$4,clock_timestamp()+($5*interval '1 millisecond'))`, workID, attempt, collectorID, tokenHash[:], leaseFor.Milliseconds()); err != nil {
		return domain.TypedWorkLease{}, false, fmt.Errorf("insert typed attempt: %w", err)
	}
	state, err := lockResultLease(ctx, tx, workID, attempt)
	if err != nil {
		return domain.TypedWorkLease{}, false, err
	}
	lease, err := typedLease(state, token)
	if err != nil {
		return domain.TypedWorkLease{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.TypedWorkLease{}, false, fmt.Errorf("commit typed work claim: %w", err)
	}
	return lease, true, nil
}

// Keep collector revocation and cluster reassignment serialized with claims and
// finalization. Transport authentication supplies identity; it never supplies plan authority.
func lockTypedCollector(ctx context.Context, tx pgx.Tx, clusterID domain.ClusterID, collectorID domain.CollectorID) error {
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT cluster_id=$2 AND status='ACTIVE' AND protocol_min<=2 AND protocol_max>=2
		FROM collectors WHERE collector_id=$1 FOR SHARE`, collectorID, clusterID).Scan(&allowed)
	if err == pgx.ErrNoRows || (err == nil && !allowed) {
		return invalidResultLease("collector is inactive, outside the authenticated cluster, or incompatible with v2")
	}
	if err != nil {
		return fmt.Errorf("lock typed collector identity: %w", err)
	}
	return nil
}

func typedLease(state resultLeaseState, token string) (domain.TypedWorkLease, error) {
	var plan domain.CollectionPlan
	if len(state.typedPlan) == 0 {
		return domain.TypedWorkLease{}, resultConflict("work has no typed collection plan")
	}
	if err := json.Unmarshal(state.typedPlan, &plan); err != nil {
		return domain.TypedWorkLease{}, resultConflict("stored typed collection plan is invalid: %v", err)
	}
	lease := domain.TypedWorkLease{Plan: plan, Lease: domain.WorkLease{Work: state.work,
		CollectorID: state.collectorID, Attempt: state.attempt, LeaseToken: token, LeaseExpires: state.leaseExpires}}
	if err := domain.ValidateTypedWorkLease(lease); err != nil {
		return domain.TypedWorkLease{}, resultConflict("stored typed lease is invalid: %v", err)
	}
	return lease, nil
}

func (s *CollectorControlStore) SubmitTypedResult(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, ref collectorcontrol.LeaseRef, result domain.TypedCollectorResult, checksum string) (collectorcontrol.FinalizeOutcome, error) {
	if clusterID == "" || collectorID == "" || !domain.ValidCollectorWorkID(string(ref.WorkID)) || ref.Attempt < 1 || len(ref.LeaseToken) < 32 || len(ref.LeaseToken) > 256 {
		return collectorcontrol.FinalizeOutcome{}, invalidResultLease("typed result lease reference is invalid")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("begin typed finalization: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockTypedCollector(ctx, tx, clusterID, collectorID); err != nil {
		return collectorcontrol.FinalizeOutcome{}, err
	}
	state, err := lockResultLease(ctx, tx, ref.WorkID, ref.Attempt)
	if err != nil {
		return collectorcontrol.FinalizeOutcome{}, err
	}
	tokenHash := sha256.Sum256([]byte(ref.LeaseToken))
	if state.work.Task.ClusterID != clusterID || state.collectorID != collectorID || subtle.ConstantTimeCompare(tokenHash[:], state.tokenHash) != 1 {
		return collectorcontrol.FinalizeOutcome{}, invalidResultLease("typed result does not belong to authenticated collector, cluster or lease")
	}
	lease, err := typedLease(state, ref.LeaseToken)
	if err != nil {
		return collectorcontrol.FinalizeOutcome{}, err
	}
	if err := domain.ValidateTypedResultForLease(result, lease); err != nil {
		return collectorcontrol.FinalizeOutcome{}, resultConflict("%v", err)
	}
	encoded, err := domain.EncodeTypedCollectorResult(result)
	if err != nil {
		return collectorcontrol.FinalizeOutcome{}, resultConflict("%v", err)
	}
	digest := sha256.Sum256(encoded)
	if checksum != hex.EncodeToString(digest[:]) {
		return collectorcontrol.FinalizeOutcome{}, resultConflict("typed result canonical SHA-256 does not match")
	}
	var storedChecksum, storedDocument []byte
	outcome := collectorcontrol.FinalizeOutcome{RunID: result.Plan.RunID, Status: result.Status, SHA256: checksum}
	err = tx.QueryRow(ctx, `SELECT sha256,document FROM collector_typed_result_ingestions WHERE work_id=$1 AND attempt=$2`, ref.WorkID, ref.Attempt).Scan(&storedChecksum, &storedDocument)
	if err == nil {
		if subtle.ConstantTimeCompare(digest[:], storedChecksum) != 1 || !bytes.Equal(encoded, storedDocument) {
			return collectorcontrol.FinalizeOutcome{}, resultConflict("typed finalization conflicts with its immutable prior outcome")
		}
		if err := tx.Commit(ctx); err != nil {
			return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("commit typed result replay: %w", err)
		}
		outcome.PreviouslyFinalized = true
		return outcome, nil
	}
	if err != pgx.ErrNoRows {
		return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("read typed result replay identity: %w", err)
	}
	if err := validateActiveResultLease(state); err != nil {
		return collectorcontrol.FinalizeOutcome{}, err
	}
	if state.finalized {
		return collectorcontrol.FinalizeOutcome{}, resultConflict("work was finalized through another protocol")
	}
	if err := recordTypedResultTx(ctx, tx, collectorID, result, encoded, digest); err != nil {
		return collectorcontrol.FinalizeOutcome{}, err
	}
	attemptStatus, workStatus := domain.AttemptSucceeded, domain.WorkSucceeded
	if result.Status == domain.ResultFailed {
		attemptStatus, workStatus = domain.AttemptFailed, domain.WorkFailed
	}
	if _, err := tx.Exec(ctx, `UPDATE collector_work_attempts SET status=$3,completed_at=clock_timestamp() WHERE work_id=$1 AND attempt=$2`, ref.WorkID, ref.Attempt, attemptStatus); err != nil {
		return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("complete typed work attempt: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE collector_work_items SET status=$2,completed_at=clock_timestamp() WHERE work_id=$1`, ref.WorkID, workStatus); err != nil {
		return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("complete typed work: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("commit typed result: %w", err)
	}
	return outcome, nil
}

func recordTypedResultTx(ctx context.Context, tx pgx.Tx, collectorID domain.CollectorID, result domain.TypedCollectorResult, encoded []byte, digest [sha256.Size]byte) error {
	p, c := result.Plan, result.Coverage
	// Typed runs retain their reviewed operation and explicit coverage. They do
	// not pass through v1 result translation, target inventory or health inference.
	if _, err := tx.Exec(ctx, `INSERT INTO collection_runs
		(run_id,cluster_id,source_id,query_kind,idempotency_key,status,scheduled_for,started_at,completed_at,
		 series_expected,series_returned,bytes_read,coverage_complete)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, p.RunID, p.ClusterID, p.SourceID, p.Operation,
		p.IdempotencyKey, result.Status, p.ScheduledFor, result.StartedAt, result.CompletedAt,
		c.Expected, c.Observed, len(encoded), c.State == domain.SourceCoverageComplete); err != nil {
		return fmt.Errorf("insert typed collection run: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO collector_typed_result_ingestions
		(work_id,attempt,collector_id,run_id,cluster_id,source_id,operation,payload_schema,result_status,document,sha256)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, result.WorkID, result.Attempt, collectorID, p.RunID,
		p.ClusterID, p.SourceID, p.Operation, p.PayloadSchema, result.Status, encoded, digest[:]); err != nil {
		return fmt.Errorf("insert typed result artifact: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO goodput_source_coverage
		(run_id,cluster_id,source_id,schema_version,scope,state,expected,observed,source_at,effective_at,observed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, p.RunID, c.ClusterID, c.SourceID, c.SchemaVersion,
		c.Scope, c.State, c.Expected, c.Observed, c.SourceAt, c.EffectiveAt, c.ObservedAt); err != nil {
		return fmt.Errorf("insert typed source coverage: %w", err)
	}
	for _, failure := range result.Failures {
		if _, err := tx.Exec(ctx, `INSERT INTO collection_failures (run_id,code,retryable,target,safe_message)
			VALUES ($1,$2,$3,$4,$5)`, p.RunID, failure.Code, failure.Retryable, failure.Target, failure.Message); err != nil {
			return fmt.Errorf("insert typed collection failure: %w", err)
		}
	}
	switch result.Payload.Kind {
	case domain.CollectionPayloadMetrics:
		for _, metric := range result.Payload.Metrics.Observations {
			if err := recordTypedMetricTx(ctx, tx, p.RunID, result.CompletedAt, metric); err != nil {
				return err
			}
		}
	case domain.CollectionPayloadInventory:
		for _, revision := range result.Payload.Inventory.Revisions {
			if _, err := recordInventoryRevisionTx(ctx, tx, application.InventoryObserved, revision); err != nil {
				return err
			}
		}
	case domain.CollectionPayloadAllocation:
		for _, snapshot := range result.Payload.Allocation.Snapshots {
			if _, err := recordAllocationSnapshotTx(ctx, tx, snapshot); err != nil {
				return err
			}
		}
	case domain.CollectionPayloadEvents:
		for _, event := range result.Payload.Events.Events {
			if err := recordTypedEventTx(ctx, tx, p, event); err != nil {
				return err
			}
		}
	case domain.CollectionPayloadSlurmSnapshot:
		if err := recordSlurmSnapshotTx(ctx, tx, p.RunID, *result.Payload.SlurmSnapshot); err != nil {
			return err
		}
	}
	if result.NextCursor != "" {
		if err := advanceTypedCursorTx(ctx, tx, p, result.NextCursor); err != nil {
			return err
		}
	}
	return nil
}

func recordTypedMetricTx(ctx context.Context, tx pgx.Tx, runID domain.RunID, completedAt time.Time, metric domain.CollectionMetric) error {
	o := metric.Observation
	labels, err := json.Marshal(o.Labels)
	if err != nil {
		return err
	}
	fingerprint := sampleFingerprint(o)
	if _, err := tx.Exec(ctx, `INSERT INTO observations
		(observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,observed_at,collected_at,source_reference,sample_fingerprint)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, o.ID, runID, o.ClusterID, o.SourceID,
		o.SchemaVersion, o.Kind, o.EntityKey, o.Metric, labels, o.Value, o.Unit, o.ObservedAt, o.CollectedAt, o.SourceReference, fingerprint[:]); err != nil {
		return fmt.Errorf("insert typed metric observation: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO current_projections
		(cluster_id,source_id,entity_key,metric,observation_id,observed_at,last_success_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
		ON CONFLICT (cluster_id,source_id,entity_key,metric) DO UPDATE SET observation_id=EXCLUDED.observation_id,
		 observed_at=EXCLUDED.observed_at,last_success_at=EXCLUDED.last_success_at,updated_at=EXCLUDED.updated_at
		WHERE current_projections.observed_at<=EXCLUDED.observed_at`, o.ClusterID, o.SourceID, o.EntityKey, o.Metric, o.ID, o.ObservedAt, completedAt); err != nil {
		return fmt.Errorf("update typed metric projection: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO goodput_metric_nodes (observation_id,run_id,cluster_id,source_id,stable_node_id)
		VALUES ($1,$2,$3,$4,$5)`, o.ID, runID, o.ClusterID, o.SourceID, metric.NodeID); err != nil {
		return fmt.Errorf("insert typed metric node binding: %w", err)
	}
	return nil
}

func recordTypedEventTx(ctx context.Context, tx pgx.Tx, p domain.CollectionPlan, event domain.CollectionEvent) error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	command, err := tx.Exec(ctx, `INSERT INTO goodput_collection_events
		(cluster_id,source_id,event_id,run_id,stable_node_id,scheduler_namespace,scheduler_job_id,submit_at,attempt,allocation_state,occurred_at,sha256)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (cluster_id,source_id,event_id) DO NOTHING`,
		p.ClusterID, p.SourceID, event.ID, p.RunID, event.NodeID, event.Job.SchedulerNamespace, event.Job.JobID,
		event.Job.SubmitAt, event.Job.Attempt, event.State, event.OccurredAt, digest[:])
	if err != nil {
		return fmt.Errorf("insert typed collection event: %w", err)
	}
	if command.RowsAffected() == 0 {
		var stored []byte
		if err := tx.QueryRow(ctx, `SELECT sha256 FROM goodput_collection_events WHERE cluster_id=$1 AND source_id=$2 AND event_id=$3`, p.ClusterID, p.SourceID, event.ID).Scan(&stored); err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(stored, digest[:]) != 1 {
			return resultConflict("event ID conflicts with an immutable event from this source")
		}
	}
	return nil
}

func collectionScopeDigest(scope domain.CollectionScope) [sha256.Size]byte {
	nodes := slices.Clone(scope.Nodes)
	slices.Sort(nodes)
	encoded, _ := json.Marshal(nodes)
	return sha256.Sum256(encoded)
}

func advanceTypedCursorTx(ctx context.Context, tx pgx.Tx, p domain.CollectionPlan, next string) error {
	scope := collectionScopeDigest(p.Scope)
	// The unique key serializes concurrent first commits too. A stale cursor
	// fails the entire result transaction, including all earlier inserted facts.
	command, err := tx.Exec(ctx, `INSERT INTO collector_source_cursors
		(cluster_id,source_id,operation,scope_sha256,cursor,run_id) VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (cluster_id,source_id,operation,scope_sha256) DO UPDATE SET cursor=EXCLUDED.cursor,run_id=EXCLUDED.run_id
		WHERE collector_source_cursors.cursor=$7`, p.ClusterID, p.SourceID, p.Operation, scope[:], next, p.RunID, p.Cursor)
	if err != nil {
		return fmt.Errorf("advance typed source cursor: %w", err)
	}
	if command.RowsAffected() != 1 {
		return resultConflict("source cursor changed since the stored plan was created")
	}
	return nil
}

func (s *CollectorControlStore) LoadFinalizedTypedResult(ctx context.Context, clusterID domain.ClusterID, workID domain.WorkID) (domain.TypedCollectorResult, bool, error) {
	var encoded, checksum []byte
	err := s.pool.QueryRow(ctx, `SELECT document,sha256 FROM collector_typed_result_ingestions WHERE cluster_id=$1 AND work_id=$2`, clusterID, workID).Scan(&encoded, &checksum)
	if err == pgx.ErrNoRows {
		return domain.TypedCollectorResult{}, false, nil
	}
	if err != nil {
		return domain.TypedCollectorResult{}, false, fmt.Errorf("load typed result: %w", err)
	}
	digest := sha256.Sum256(encoded)
	if subtle.ConstantTimeCompare(checksum, digest[:]) != 1 {
		return domain.TypedCollectorResult{}, false, resultConflict("stored typed result checksum is invalid")
	}
	result, err := domain.DecodeTypedCollectorResult(encoded)
	return result, err == nil, err
}

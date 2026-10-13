package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ConfigureDurableExecution is an immutable, revision-bound grant. An old
// startup configuration cannot overwrite an operator's newer desired revision.
func (s *CollectionStore) ConfigureDurableExecution(ctx context.Context, g domain.DurableExecution) error {
	if err := g.Validate(); err != nil {
		return err
	}
	op, _ := domain.ReviewedCollectionOperation(g.Operation)
	nodes := g.Nodes
	if nodes == nil {
		nodes = []domain.StableNodeID{}
	}
	encoded, _ := json.Marshal(nodes)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var valid bool
	err = tx.QueryRow(ctx, `SELECT d.revision=$4 AND d.mode='durable' AND c.cluster_id=d.cluster_id AND s.kind=$6 AND jsonb_array_length($7::jsonb)<=d.max_targets
 AND (d.legacy_query_kind IS NOT NULL OR (d.interval_seconds<=86400 AND d.timeout_ms<=86400000))
 FROM desired_schedules d JOIN sources s USING(cluster_id,source_id) JOIN collectors c ON c.collector_id=$5
 WHERE d.cluster_id=$1 AND d.source_id=$2 AND d.operation=$3 FOR SHARE OF d,s,c`, g.ClusterID, g.SourceID, g.Operation, g.Revision, g.CollectorID, op.Source, encoded).Scan(&valid)
	if err == pgx.ErrNoRows || (err == nil && !valid) {
		return domain.ErrScheduleRevision
	}
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `INSERT INTO durable_schedule_executions(cluster_id,source_id,operation,revision,collector_id,nodes)
 VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, g.ClusterID, g.SourceID, g.Operation, g.Revision, g.CollectorID, encoded)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		if err := tx.QueryRow(ctx, `SELECT collector_id=$5 AND nodes=$6::jsonb FROM durable_schedule_executions WHERE cluster_id=$1 AND source_id=$2 AND operation=$3 AND revision=$4`, g.ClusterID, g.SourceID, g.Operation, g.Revision, g.CollectorID, encoded).Scan(&valid); err != nil {
			return err
		}
		if !valid {
			return fmt.Errorf("durable execution is immutable; revise desired schedule first")
		}
	}
	return tx.Commit(ctx)
}

// liveOrdinaryWork includes pre-existing ordinary queue work, but does not
// grant this scheduler authority over manual/legacy producers. Expiry is only
// released after locking and reconciling the work row: an uncommitted claim
// may own that row while its attempt is still invisible to this transaction.
const liveOrdinaryWork = `SELECT w.cluster_id,w.source_id,w.work_id FROM collector_work_items w
 WHERE w.status IN ('AVAILABLE','LEASED') AND NOT w.remediation_runtime_managed
 AND NOT EXISTS(SELECT 1 FROM collection_repair_requests r WHERE r.work_id=w.work_id)`

// AdmitDueSchedule serializes only admission turns. No process owns a queue or
// quota counter. Terminal result commits release capacity by changing existing
// work state; expired attempts release it according to their persisted lease.
func (s *CollectionStore) AdmitDueSchedule(ctx context.Context, policy domain.DurableAdmissionPolicy) (domain.ScheduleAdmission, bool, error) {
	var out domain.ScheduleAdmission
	if err := policy.Validate(); err != nil {
		return out, false, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return out, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `INSERT INTO durable_admission_state(singleton,global_limit,cluster_limit) VALUES(true,$1,$2) ON CONFLICT DO NOTHING`, policy.GlobalLimit, policy.ClusterLimit); err != nil {
		return out, false, err
	}
	var cursor string
	var configured domain.DurableAdmissionPolicy
	if err = tx.QueryRow(ctx, `SELECT global_limit,cluster_limit,last_cluster FROM durable_admission_state WHERE singleton FOR UPDATE`).Scan(&configured.GlobalLimit, &configured.ClusterLimit, &cursor); err != nil {
		return out, false, err
	}
	if configured != policy {
		return out, false, fmt.Errorf("durable admission quota configuration conflicts with persisted policy")
	}
	// Never discount a work row using only an MVCC snapshot of its attempts.
	// Claims hold this same row lock until their new attempt commits. Busy rows
	// remain in the conservative count, including across their work deadline.
	rows, err := tx.Query(ctx, `
 SELECT w.work_id FROM collector_work_items w
 WHERE w.status IN ('AVAILABLE','LEASED') AND NOT w.remediation_runtime_managed
 AND NOT EXISTS(SELECT 1 FROM collection_repair_requests r WHERE r.work_id=w.work_id)
 AND (w.work_expires_at<=clock_timestamp() OR w.deadline<=clock_timestamp()
 OR EXISTS(SELECT 1 FROM durable_schedule_occurrences o JOIN desired_schedules d USING(cluster_id,source_id,operation)
 WHERE o.work_id=w.work_id AND (NOT d.enabled OR d.mode<>'durable' OR d.revision<>o.revision)))
 AND NOT EXISTS(SELECT 1 FROM collector_work_attempts a WHERE a.work_id=w.work_id
 AND a.status IN ('CLAIMED','STARTED') AND a.lease_expires_at>clock_timestamp())
 ORDER BY w.work_expires_at,w.work_id LIMIT 256 FOR UPDATE OF w SKIP LOCKED`)
	if err != nil {
		return out, false, fmt.Errorf("lock expired admission work: %w", err)
	}
	var expiredIDs []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return out, false, err
		}
		expiredIDs = append(expiredIDs, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, false, err
	}
	// A fresh statement sees any attempt that committed between the candidate
	// snapshot and acquiring its work lock. Holding that lock now excludes a
	// later claim until reconciliation and admission commit.
	if len(expiredIDs) > 0 {
		if _, err = tx.Exec(ctx, `UPDATE collector_work_items w SET status='FAILED',completed_at=clock_timestamp()
 WHERE w.work_id=ANY($1) AND w.status IN ('AVAILABLE','LEASED') AND NOT EXISTS(SELECT 1 FROM collector_work_attempts a
 WHERE a.work_id=w.work_id AND a.status IN ('CLAIMED','STARTED') AND a.lease_expires_at>clock_timestamp())`, expiredIDs); err != nil {
			return out, false, fmt.Errorf("reconcile durable admission capacity: %w", err)
		}
	}
	var d domain.DesiredSchedule
	var interval, timeout, jitter int64
	var due time.Time
	var occurrence int64
	var nodes []byte
	var rejection string
	// Cluster round robin precedes oldest-due order. Unsupported or unavailable
	// schedules never enter the eligible set, so cannot consume another turn.
	// Source reachability is an observation, not execution authority: an
	// installed collector must be able to report failures and recover from them.
	columns := "d." + strings.ReplaceAll(scheduleColumns, ",", ",d.")
	err = tx.QueryRow(ctx, `WITH live AS MATERIALIZED (`+liveOrdinaryWork+`)
 SELECT `+columns+`,st.next_due_at,st.occurrence,e.nodes,quota.reason
 FROM desired_schedules d JOIN durable_schedule_state st USING(cluster_id,source_id,operation)
 JOIN durable_schedule_executions e USING(cluster_id,source_id,operation,revision)
 JOIN clusters cl ON cl.cluster_id=d.cluster_id JOIN sources src ON src.cluster_id=d.cluster_id AND src.source_id=d.source_id
 JOIN collectors c ON c.collector_id=e.collector_id AND c.cluster_id=d.cluster_id
 JOIN collector_capabilities cap ON cap.collector_id=c.collector_id AND cap.capability=COALESCE(d.legacy_query_kind,d.operation) AND cap.version='1'
 CROSS JOIN LATERAL (SELECT CASE
 WHEN (SELECT count(*) FROM live)>=$2 THEN 'global'
 WHEN (SELECT count(*) FROM live WHERE cluster_id=d.cluster_id)>=$3 THEN 'cluster'
 WHEN EXISTS(SELECT 1 FROM live WHERE cluster_id=d.cluster_id AND source_id=d.source_id) THEN 'source'
 ELSE '' END AS reason) quota
 WHERE d.enabled AND d.mode='durable' AND st.next_due_at<=clock_timestamp() AND cl.removed_at IS NULL
 AND ((d.legacy_query_kind IS NOT NULL AND src.kind='prometheus' AND c.protocol_min<=1 AND c.protocol_max>=1)
 OR (d.operation IN ('slurm.inventory.v1','slurm.snapshot.v1') AND src.kind='slurm' AND c.protocol_min<=2 AND c.protocol_max>=2 AND jsonb_array_length(e.nodes) BETWEEN 1 AND d.max_targets)
 OR (d.operation='gpu.process_observations.v1' AND src.kind='gpu_process' AND c.protocol_min<=2 AND c.protocol_max>=2 AND jsonb_array_length(e.nodes) BETWEEN 1 AND LEAST(d.max_targets,16)))
 AND c.status='ACTIVE' AND c.last_heartbeat_at>clock_timestamp()-interval '2 minutes'
 AND (c.identity_not_after IS NULL OR c.identity_not_after>clock_timestamp())
 AND (d.legacy_query_kind IS NULL OR d.source_id=ANY(c.reported_source_ids))
 AND (d.legacy_query_kind IS NOT NULL OR (d.interval_seconds<=86400 AND d.timeout_ms<=86400000))
 ORDER BY (quota.reason<>''),(d.cluster_id<=$1),d.cluster_id,st.next_due_at,d.source_id,d.operation
 LIMIT 1 FOR UPDATE OF st SKIP LOCKED FOR SHARE OF cl,d,src,e,c,cap SKIP LOCKED`, cursor, policy.GlobalLimit, policy.ClusterLimit).Scan(
		&d.ClusterID, &d.SourceID, &d.Operation, &d.Enabled, &d.Mode, &interval, &timeout, &jitter, &d.MaxTargets, &d.MaxBytes, &d.Priority, &d.Revision, &due, &occurrence, &nodes, &rejection)
	if err == pgx.ErrNoRows {
		return out, false, tx.Commit(ctx)
	}
	if err != nil {
		return out, false, fmt.Errorf("select durable schedule: %w", err)
	}
	if rejection != "" {
		if err = tx.Commit(ctx); err != nil {
			return out, false, err
		}
		return domain.ScheduleAdmission{ScheduleKey: d.ScheduleKey, Revision: d.Revision, QuotaRejection: rejection}, false, nil
	}
	d.Interval = time.Duration(interval) * time.Second
	d.Timeout = time.Duration(timeout) * time.Millisecond
	d.Jitter = time.Duration(jitter) * time.Millisecond
	if err = d.Validate(); err != nil {
		return out, false, err
	}
	op, ok := domain.ReviewedCollectionOperation(d.Operation)
	if !ok || (op.Query == "" && d.Operation != domain.OperationSlurmInventory && d.Operation != domain.OperationSlurmSnapshot && d.Operation != domain.OperationGPUProcessObservations) {
		return out, false, fmt.Errorf("durable operation is not executable")
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return out, false, err
	}
	coalesced := int64(0)
	scheduled := due
	if op.Payload == domain.CollectionPayloadMetrics {
		coalesced = int64(now.Sub(due) / d.Interval)
		scheduled = due.Add(time.Duration(coalesced) * d.Interval)
	}
	next := scheduled.Add(d.Interval)
	// Inventory keeps each due interval. Its bounded source slot prevents queue
	// growth. Event operations are unavailable and their cursor/gaps stay intact.
	identity := fmt.Sprintf("%s/%s/%s/%d/%d", d.ClusterID, d.SourceID, d.Operation, d.Revision, occurrence+1)
	hash := sha256.Sum256([]byte(identity))
	id := hex.EncodeToString(hash[:])
	identity = "schedule/" + id
	if d.Jitter > 0 {
		next = next.Add(time.Duration(binary.BigEndian.Uint64(hash[:8]) % uint64(d.Jitter)))
	}
	workID := domain.WorkID("schedule-" + id)
	runID := domain.RunID("schedule-" + id)
	deadline := now.Add(d.Timeout)
	var typed []byte
	query := string(op.Query)
	if op.Query == "" {
		var scope []domain.StableNodeID
		if err = json.Unmarshal(nodes, &scope); err != nil {
			return out, false, err
		}
		// Execution time and historical collection interval are separate; old
		// inventory intervals never force an already-expired execution deadline.
		plan := domain.CollectionPlan{SchemaVersion: 2, RunID: runID, ClusterID: d.ClusterID, SourceID: d.SourceID, SourceKind: op.Source, Operation: d.Operation, PayloadSchema: op.Schema,
			Scope: domain.CollectionScope{Nodes: scope}, Interval: &domain.CollectionInterval{Start: due.Add(-d.Interval), End: due}, ScheduledFor: now, Deadline: deadline,
			Limits: domain.CollectionLimits{MaxRecords: d.MaxTargets, MaxBytes: d.MaxBytes}, IdempotencyKey: identity}
		if err = domain.ValidateCollectionPlan(plan); err != nil {
			return out, false, err
		}
		typed, err = json.Marshal(plan)
		if err != nil {
			return out, false, err
		}
		query = string(d.Operation)
		scheduled = now
	}
	if _, err = tx.Exec(ctx, `INSERT INTO collector_work_items(work_id,run_id,cluster_id,source_id,query_kind,scheduled_for,deadline,max_series,max_bytes,idempotency_key,available_at,work_expires_at,typed_plan)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$7,$12)`, workID, runID, d.ClusterID, d.SourceID, query, scheduled, deadline, d.MaxTargets, d.MaxBytes, identity, now, typed); err != nil {
		return out, false, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO durable_schedule_occurrences(work_id,cluster_id,source_id,operation,revision,occurrence,due_at,coalesced_intervals) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, workID, d.ClusterID, d.SourceID, d.Operation, d.Revision, occurrence+1, due, coalesced); err != nil {
		return out, false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE durable_schedule_state SET next_due_at=$4,occurrence=occurrence+1,coalesced_intervals=coalesced_intervals+$5 WHERE cluster_id=$1 AND source_id=$2 AND operation=$3`, d.ClusterID, d.SourceID, d.Operation, next, coalesced); err != nil {
		return out, false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE durable_admission_state SET last_cluster=$1 WHERE singleton`, d.ClusterID); err != nil {
		return out, false, err
	}
	out = domain.ScheduleAdmission{ScheduleKey: d.ScheduleKey, Revision: d.Revision, Occurrence: occurrence + 1, CoalescedIntervals: coalesced, DueAt: due, NextDueAt: next, WorkID: workID}
	if err = tx.Commit(ctx); err != nil {
		return domain.ScheduleAdmission{}, false, err
	}
	return out, true, nil
}

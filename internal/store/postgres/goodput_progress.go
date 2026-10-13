package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

var _ application.ProgressStore = (*GoodputStore)(nil)

// RecordProgressEvidence stores a canonical fact and one immutable run
// receipt. No runtime calls this until a reviewed progress template and
// collector operation are installed. The run check prevents existing DCGM
// or Slurm results from becoming application progress by reinterpretation.
func (store *GoodputStore) RecordProgressEvidence(ctx context.Context, evidence application.ProgressEvidence) (bool, error) {
	validated, err := application.ValidateProgressEvidence(evidence)
	if err != nil {
		return false, err
	}
	observation := validated.Observation
	identity := struct {
		ClusterID        domain.ClusterID
		SourceID         domain.SourceID
		TemplateID       string
		TemplateRevision int
		Job              domain.JobIdentity
		EffectiveAt      time.Time
		ResetEpoch       domain.ProgressResetEpoch
	}{observation.ClusterID, observation.SourceID, validated.TemplateID, validated.TemplateRevision,
		observation.Job, observation.EffectiveAt, observation.ResetEpoch}
	identityJSON, err := json.Marshal(identity)
	if err != nil {
		return false, fmt.Errorf("encode progress sample identity: %w", err)
	}
	key := sha256.Sum256(identityJSON)
	content := struct {
		Identity any
		State    domain.ProgressState
		Cohort   domain.ProgressCohort
		Unit     domain.ProgressUnit
		Value    *float64
		SourceAt time.Time
	}{identity, observation.State, observation.Cohort, observation.Unit, observation.Committed, observation.SourceAt}
	contentJSON, err := json.Marshal(content)
	if err != nil {
		return false, fmt.Errorf("encode progress sample content: %w", err)
	}
	digest := sha256.Sum256(contentJSON)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, fmt.Errorf("begin progress evidence: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var clusterID domain.ClusterID
	var sourceID domain.SourceID
	var operation, status string
	var sourceKind string
	if err := tx.QueryRow(ctx, `SELECT r.cluster_id,r.source_id,r.query_kind,r.status,s.kind
		FROM collection_runs r JOIN sources s ON s.source_id=r.source_id
		WHERE r.run_id=$1 FOR SHARE OF r,s`, validated.RunID).Scan(&clusterID, &sourceID, &operation, &status, &sourceKind); err != nil {
		return false, fmt.Errorf("load progress collection run: %w", err)
	}
	if clusterID != observation.ClusterID || sourceID != observation.SourceID || sourceKind != "prometheus" || operation != application.ProgressOperation ||
		(status != "SUCCEEDED" && status != "PARTIAL" && status != "NO_DATA") ||
		(status == "NO_DATA" && observation.State == domain.ProgressMeasured) {
		return false, fmt.Errorf("collection run is not eligible progress evidence")
	}
	var templateCohort domain.ProgressCohort
	var templateUnit domain.ProgressUnit
	var templateNamespace domain.SchedulerNamespace
	if err := tx.QueryRow(ctx, `SELECT cohort,unit,scheduler_namespace FROM goodput_progress_templates
		WHERE cluster_id=$1 AND source_id=$2 AND template_id=$3 AND template_revision=$4
		AND revoked_at IS NULL FOR SHARE`, observation.ClusterID, observation.SourceID,
		validated.TemplateID, validated.TemplateRevision).Scan(&templateCohort, &templateUnit, &templateNamespace); err != nil {
		return false, fmt.Errorf("progress template is not approved and active: %w", err)
	}
	if templateCohort != observation.Cohort || templateNamespace != observation.Job.SchedulerNamespace ||
		(observation.State == domain.ProgressMeasured && templateUnit != observation.Unit) {
		return false, fmt.Errorf("progress sample does not match approved namespace, cohort or unit")
	}
	command, err := tx.Exec(ctx, `INSERT INTO goodput_progress_samples
		(sample_key,cluster_id,source_id,template_id,template_revision,schema_version,
		 scheduler_namespace,scheduler_job_id,submit_at,attempt,cohort,state,unit,committed,
		 reset_epoch,source_at,effective_at,content_sha256)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		ON CONFLICT (sample_key) DO NOTHING`,
		key[:], observation.ClusterID, observation.SourceID, validated.TemplateID, validated.TemplateRevision,
		observation.SchemaVersion, observation.Job.SchedulerNamespace, observation.Job.JobID,
		observation.Job.SubmitAt, observation.Job.Attempt, observation.Cohort, observation.State,
		observation.Unit, observation.Committed, observation.ResetEpoch, observation.SourceAt,
		observation.EffectiveAt, digest[:])
	if err != nil {
		return false, fmt.Errorf("insert progress sample: %w", err)
	}
	inserted := command.RowsAffected() == 1
	if !inserted {
		var existing []byte
		if err := tx.QueryRow(ctx, `SELECT content_sha256 FROM goodput_progress_samples WHERE sample_key=$1`, key[:]).Scan(&existing); err != nil {
			return false, fmt.Errorf("load existing progress sample: %w", err)
		}
		if subtle.ConstantTimeCompare(existing, digest[:]) != 1 {
			return false, fmt.Errorf("progress sample conflicts with immutable content")
		}
	}
	receipt, err := tx.Exec(ctx, `INSERT INTO goodput_progress_sample_receipts
		(sample_key,run_id,observed_at) VALUES ($1,$2,$3) ON CONFLICT (sample_key,run_id) DO NOTHING`,
		key[:], validated.RunID, observation.ObservedAt)
	if err != nil {
		return false, fmt.Errorf("insert progress receipt: %w", err)
	}
	if receipt.RowsAffected() == 0 {
		var priorObservedAt time.Time
		if err := tx.QueryRow(ctx, `SELECT observed_at FROM goodput_progress_sample_receipts
			WHERE sample_key=$1 AND run_id=$2`, key[:], validated.RunID).Scan(&priorObservedAt); err != nil {
			return false, fmt.Errorf("load existing progress receipt: %w", err)
		}
		if !priorObservedAt.Equal(observation.ObservedAt) {
			return false, fmt.Errorf("progress receipt conflicts with immutable observation time")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit progress evidence: %w", err)
	}
	return inserted, nil
}

func (store *GoodputStore) ListProgressSamples(ctx context.Context, clusterID domain.ClusterID, sourceID domain.SourceID, job domain.JobIdentity, limit int) ([]application.ProgressSampleRecord, bool, error) {
	if err := application.ValidateGoodputLimit(limit); err != nil {
		return nil, false, err
	}
	return store.listProgressSamples(ctx, clusterID, sourceID, job, nil, nil, limit)
}

func (store *GoodputStore) ListProgressWindowSamples(ctx context.Context, clusterID domain.ClusterID, sourceID domain.SourceID, job domain.JobIdentity, start, end time.Time) ([]application.ProgressSampleRecord, error) {
	if start.IsZero() || !end.After(start) || end.Sub(start) > 24*time.Hour {
		return nil, fmt.Errorf("invalid progress sample window")
	}
	items, more, err := store.listProgressSamples(ctx, clusterID, sourceID, job, &start, &end, 10000)
	if err != nil {
		return nil, err
	}
	if more {
		return nil, fmt.Errorf("progress sample window exceeds bound")
	}
	return items, nil
}

func (store *GoodputStore) listProgressSamples(ctx context.Context, clusterID domain.ClusterID, sourceID domain.SourceID, job domain.JobIdentity, start, end *time.Time, limit int) ([]application.ProgressSampleRecord, bool, error) {
	if clusterID == "" || sourceID == "" {
		return nil, false, fmt.Errorf("progress cluster and source are required")
	}
	validatedJob, err := domain.CreateJobIdentity(job)
	if err != nil {
		return nil, false, err
	}
	var startArg, endArg any
	if start != nil {
		startArg = *start
	}
	if end != nil {
		endArg = *end
	}
	rows, err := store.pool.Query(ctx, `WITH selected AS (
		SELECT * FROM goodput_progress_samples WHERE cluster_id=$1 AND source_id=$2
		AND scheduler_namespace=$3 AND scheduler_job_id=$4 AND submit_at=$5 AND attempt=$6
		AND ($7::timestamptz IS NULL OR effective_at >= $7)
		AND ($8::timestamptz IS NULL OR effective_at <= $8)
		ORDER BY effective_at DESC, sample_key DESC LIMIT $9
	)
	SELECT s.template_id,s.template_revision,s.schema_version,s.cluster_id,s.source_id,
		s.scheduler_namespace,s.scheduler_job_id,s.submit_at,s.attempt,s.cohort,s.state,
		s.unit,s.committed,s.reset_epoch,s.source_at,s.effective_at,
		r.observed_at,r.receipts
	FROM selected s CROSS JOIN LATERAL (
		SELECT min(observed_at) observed_at,
			jsonb_agg(jsonb_build_object('run_id',run_id,'observed_at',observed_at) ORDER BY run_id) receipts
		FROM goodput_progress_sample_receipts WHERE sample_key=s.sample_key
	) r ORDER BY s.effective_at DESC,s.sample_key DESC`,
		clusterID, sourceID, validatedJob.SchedulerNamespace, validatedJob.JobID,
		validatedJob.SubmitAt.Truncate(time.Microsecond), validatedJob.Attempt, startArg, endArg, limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("list progress samples: %w", err)
	}
	defer rows.Close()
	values := make([]application.ProgressSampleRecord, 0, limit+1)
	for rows.Next() {
		var item application.ProgressSampleRecord
		var value *float64
		var receiptJSON []byte
		o := &item.Observation
		if err := rows.Scan(&item.TemplateID, &item.TemplateRevision, &o.SchemaVersion,
			&o.ClusterID, &o.SourceID, &o.Job.SchedulerNamespace, &o.Job.JobID,
			&o.Job.SubmitAt, &o.Job.Attempt, &o.Cohort, &o.State, &o.Unit, &value,
			&o.ResetEpoch, &o.SourceAt, &o.EffectiveAt, &o.ObservedAt, &receiptJSON); err != nil {
			return nil, false, fmt.Errorf("scan progress sample: %w", err)
		}
		o.Committed = value
		validated, err := domain.CreateProgressObservation(*o)
		if err != nil {
			return nil, false, fmt.Errorf("stored progress sample is invalid: %w", err)
		}
		item.Observation = validated
		if err := json.Unmarshal(receiptJSON, &item.Receipts); err != nil {
			return nil, false, fmt.Errorf("decode progress receipts: %w", err)
		}
		values = append(values, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("list progress samples: %w", err)
	}
	more := len(values) > limit
	if more {
		values = values[:limit]
	}
	return values, more, nil
}

// ListProgressAllocationIntervals clips immutable scheduler snapshots to the
// requested window. The validity projection, not the latest allocation row,
// decides which allocation applies at each progress instant. Expected inventory
// describes node capacity, not the GPUs granted to a job, so node-only facts
// cannot supply a GPU-seconds denominator.
func (store *GoodputStore) ListProgressAllocationIntervals(ctx context.Context, clusterID domain.ClusterID, sourceID, inventorySourceID domain.SourceID, job domain.JobIdentity, start, end time.Time) ([]application.ProgressAllocationInterval, error) {
	if clusterID == "" || sourceID == "" || inventorySourceID == "" || start.IsZero() || !end.After(start) || end.Sub(start) > 24*time.Hour {
		return nil, fmt.Errorf("invalid progress allocation query")
	}
	validatedJob, err := domain.CreateJobIdentity(job)
	if err != nil {
		return nil, err
	}
	rows, err := store.pool.Query(ctx, `SELECT s.snapshot_key,s.allocation_state,s.observed_at,
		GREATEST(v.valid_from,COALESCE(inv.valid_from,v.valid_from),$8),
		LEAST(COALESCE(v.valid_to,$9),COALESCE(inv.valid_to,$9),$9),
		COALESCE(inv.revision_id,''),
		(SELECT count(DISTINCT e.physical_gpu_uuid) FROM goodput_allocation_snapshot_entities e
		 WHERE e.cluster_id=s.cluster_id AND e.snapshot_key=s.snapshot_key AND e.entity_kind='GPU'),
		(SELECT count(DISTINCT e.stable_node_id) FROM goodput_allocation_snapshot_entities e
		 WHERE e.cluster_id=s.cluster_id AND e.snapshot_key=s.snapshot_key AND e.entity_kind='NODE')
		FROM goodput_allocation_snapshots s JOIN goodput_allocation_snapshot_validity v
		ON v.cluster_id=s.cluster_id AND v.snapshot_key=s.snapshot_key
		LEFT JOIN (
		 SELECT iv.cluster_id,iv.revision_id,iv.valid_from,iv.valid_to
		 FROM goodput_inventory_revision_validity iv JOIN goodput_inventory_revisions ir
		 ON ir.cluster_id=iv.cluster_id AND ir.revision_id=iv.revision_id
		 WHERE ir.source_id=$3 AND ir.inventory_class='EXPECTED'
		) inv ON inv.cluster_id=s.cluster_id AND inv.valid_from<COALESCE(v.valid_to,$9)
		AND (inv.valid_to IS NULL OR inv.valid_to>v.valid_from)
		AND inv.valid_from<$9 AND (inv.valid_to IS NULL OR inv.valid_to>$8)
		WHERE s.cluster_id=$1 AND s.source_id=$2 AND s.scheduler_namespace=$4 AND s.scheduler_job_id=$5
		AND s.submit_at=$6 AND s.attempt=$7 AND v.valid_from<$9 AND (v.valid_to IS NULL OR v.valid_to>$8)
		ORDER BY GREATEST(v.valid_from,COALESCE(inv.valid_from,v.valid_from),$8),s.snapshot_key,inv.revision_id
		LIMIT 1001`, clusterID, sourceID, inventorySourceID, validatedJob.SchedulerNamespace,
		validatedJob.JobID, validatedJob.SubmitAt.Truncate(time.Microsecond), validatedJob.Attempt, start, end)
	if err != nil {
		return nil, fmt.Errorf("list progress allocation history: %w", err)
	}
	defer rows.Close()
	intervals := make([]application.ProgressAllocationInterval, 0)
	for rows.Next() {
		var item application.ProgressAllocationInterval
		var directGPUCount, nodeCount int64
		if err := rows.Scan(&item.SnapshotKey, &item.State, &item.ObservedAt, &item.Start, &item.End,
			&item.InventoryRevisionID, &directGPUCount, &nodeCount); err != nil {
			return nil, fmt.Errorf("scan progress allocation history: %w", err)
		}
		if directGPUCount > 10000 {
			return nil, fmt.Errorf("progress allocation GPU count exceeds bound")
		}
		if !item.End.After(item.Start) {
			continue
		}
		item.ClusterID, item.SourceID, item.Job = clusterID, sourceID, validatedJob
		if nodeCount == 0 && directGPUCount > 0 {
			item.GPUCount = int(directGPUCount)
			item.InventoryRevisionID = ""
		}
		intervals = append(intervals, item)
		if len(intervals) > 1000 {
			return nil, fmt.Errorf("progress allocation history exceeds bound")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list progress allocation history: %w", err)
	}
	return intervals, nil
}

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// Assessment uses an ordinary snapshot. It never acquires monitoring's source
// row/advisory locks or claims authority extending beyond that snapshot.
type assessmentAuthority struct {
	monitoringAuthority
	upload *domain.CoolingUploadProfile
}

func validateAssessmentAuthority(ctx context.Context, tx pgx.Tx, c a.Config, asset a.Asset, b a.Binding, at time.Time) (assessmentAuthority, error) {
	op, ok := domain.ReviewedCollectionOperation(domain.CollectionOperationID(b.Operation))
	if !ok || op.Source != domain.CollectionSourcePrometheus {
		return assessmentAuthority{}, ErrMonitoringAuthority
	}
	if !slices.ContainsFunc(domain.DCGMFields(op.Query), func(field domain.DCGMField) bool { return field.Name == b.Metric }) &&
		!(op.Query == domain.QueryGPUUtilization && b.Metric == "DCGM_FI_DEV_GPU_UTIL") {
		return assessmentAuthority{}, ErrMonitoringAuthority
	}
	authority := assessmentAuthority{monitoringAuthority: monitoringAuthority{query: op.Query}}
	if b.UploadProfileID != "" {
		profile, err := loadAssessmentUploadProfile(ctx, tx, c, asset, b, op.Query, at)
		authority.upload = &profile
		return authority, err
	}
	var kind string
	var removed *time.Time
	var enabled bool
	var revision int64
	var job, node *string
	var active *bool
	var configuration, desired *int64
	var nodes []byte
	err := tx.QueryRow(ctx, `SELECT s.kind,k.removed_at,d.enabled,d.revision,d.mode,d.legacy_job_id,j.node_filter,j.active,j.configuration_revision,j.desired_revision,e.nodes FROM sources s JOIN clusters k ON k.cluster_id=s.cluster_id JOIN desired_schedules d ON d.cluster_id=s.cluster_id AND d.source_id=s.source_id AND d.operation=$3 LEFT JOIN collection_jobs j ON j.job_id=d.legacy_job_id AND j.cluster_id=d.cluster_id AND j.source_id=d.source_id AND j.query_kind=$4 LEFT JOIN durable_schedule_executions e ON e.cluster_id=d.cluster_id AND e.source_id=d.source_id AND e.operation=d.operation AND e.revision=d.revision WHERE s.cluster_id=$1 AND s.source_id=$2`, c.ClusterID, c.SourceID, b.Operation, op.Query).Scan(&kind, &removed, &enabled, &revision, &authority.mode, &job, &node, &active, &configuration, &desired, &nodes)
	if err != nil {
		return authority, err
	}
	if kind != "prometheus" || removed != nil || !enabled || revision != b.ScheduleRevision {
		return authority, ErrMonitoringAuthority
	}
	switch authority.mode {
	case domain.SchedulingLegacy:
		if job == nil || node == nil || *node != "" || active == nil || !*active || configuration == nil || desired == nil || *desired != revision || len(b.ScopeNodes) != 0 {
			return authority, ErrMonitoringAuthority
		}
		authority.jobID = *job
		authority.configurationRevision = *configuration
	case domain.SchedulingDurable:
		var scope []string
		if json.Unmarshal(nodes, &scope) != nil {
			return authority, ErrMonitoringAuthority
		}
		slices.Sort(scope)
		if !slices.Equal(scope, b.ScopeNodes) {
			return authority, ErrMonitoringAuthority
		}
	default:
		return authority, ErrMonitoringAuthority
	}
	if len(b.ScopeNodes) > 0 && !slices.Contains(b.ScopeNodes, asset.NodeID) {
		return authority, ErrMonitoringAuthority
	}
	var current string
	var sourceAt time.Time
	err = tx.QueryRow(ctx, `SELECT revision_id,source_at FROM goodput_inventory_revisions WHERE cluster_id=$1 AND source_id=$2 AND inventory_class='EXPECTED' AND effective_at<=$3 AND observed_at<=$3 ORDER BY effective_at DESC,observed_at DESC,source_at DESC,revision_id DESC LIMIT 1`, c.ClusterID, c.SourceID, at).Scan(&current, &sourceAt)
	if err != nil {
		return authority, err
	}
	if current != c.InventoryRevision || sourceAt.After(at) {
		return authority, ErrMonitoringAuthority
	}
	var exact, ambiguous bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM goodput_inventory_revision_entities WHERE cluster_id=$1 AND revision_id=$2 AND entity_kind='GPU' AND stable_node_id=$3 AND physical_gpu_uuid=$4),EXISTS(SELECT 1 FROM goodput_inventory_revision_entities WHERE cluster_id=$1 AND revision_id=$2 AND physical_gpu_uuid=$4 AND (entity_kind='MIG' OR entity_kind='GPU' AND stable_node_id<>$3))`, c.ClusterID, current, asset.NodeID, asset.GPUUUID).Scan(&exact, &ambiguous)
	if err != nil {
		return authority, err
	}
	if !exact || ambiguous {
		return authority, ErrMonitoringAuthority
	}
	return authority, nil
}

func loadAssessmentUploadProfile(ctx context.Context, tx pgx.Tx, c a.Config, asset a.Asset, b a.Binding, query domain.QueryKind, at time.Time) (domain.CoolingUploadProfile, error) {
	if c.Production() {
		return loadProductionUploadProfile(ctx, tx, c, asset, b, query, at)
	}
	var profile domain.CoolingUploadProfile
	if field, ok := domain.CoolingUploadField(query); !ok || field.Name != b.Metric {
		return profile, ErrMonitoringAuthority
	}
	var body []byte
	var collector domain.CollectorID
	var starts, ends time.Time
	err := tx.QueryRow(ctx, `SELECT p.profile,p.collector_id,p.starts_at,p.ends_at
 FROM public.prometheus_cooling_upload_profiles p
 JOIN sources s ON s.cluster_id=p.cluster_id AND s.source_id=p.source_id
 JOIN clusters k ON k.cluster_id=p.cluster_id
 WHERE p.profile_id=$1 AND p.revision=$2 AND p.profile_hash=$3 AND p.cluster_id=$4 AND p.source_id=$5
 AND p.inventory_revision=$6 AND p.registered_at<=$7 AND p.revoked_at IS NULL
 AND s.kind='prometheus' AND k.removed_at IS NULL`, b.UploadProfileID, b.ScheduleRevision, b.UploadProfileHash, c.ClusterID, c.SourceID, c.InventoryRevision, at).Scan(&body, &collector, &starts, &ends)
	if errors.Is(err, pgx.ErrNoRows) {
		return profile, ErrMonitoringAuthority
	}
	if err != nil {
		return profile, err
	}
	if a.DecodeStrict(body, &profile, domain.CoolingUploadProductionProfileMaxBytes) != nil || profile.Validate() != nil ||
		(profile.Version == domain.CoolingUploadVersion && len(body) > 16<<10) ||
		profile.ProfileID != b.UploadProfileID || profile.Revision != b.ScheduleRevision || profile.CollectorID != collector || string(collector) != b.UploadCollectorID ||
		string(profile.ClusterID) != c.ClusterID || string(profile.SourceID) != c.SourceID || profile.InventoryRevision != c.InventoryRevision ||
		!profile.StartsAt.Equal(starts) || !profile.EndsAt.Equal(ends) {
		return profile, ErrMonitoringAuthority
	}
	nodes := make([]string, 0, len(profile.Assets))
	for _, scoped := range profile.Assets {
		nodes = append(nodes, string(scoped.NodeID))
	}
	if !slices.Equal(slices.Compact(nodes), b.ScopeNodes) || !slices.Contains(profile.Assets, domain.CoolingUploadAsset{NodeID: domain.StableNodeID(asset.NodeID), GPUUUID: domain.PhysicalGPUUUID(asset.GPUUUID)}) {
		return profile, ErrMonitoringAuthority
	}
	var current string
	var sourceAt time.Time
	err = tx.QueryRow(ctx, `SELECT revision_id,source_at FROM goodput_inventory_revisions WHERE cluster_id=$1 AND source_id=$2 AND inventory_class='EXPECTED' AND effective_at<=$3 AND observed_at<=$3 ORDER BY effective_at DESC,observed_at DESC,source_at DESC,revision_id DESC LIMIT 1`, c.ClusterID, c.SourceID, at).Scan(&current, &sourceAt)
	if err != nil {
		return profile, err
	}
	if current != c.InventoryRevision || sourceAt.After(at) {
		return profile, ErrMonitoringAuthority
	}
	err = requireCoolingUploadAssets(ctx, tx, profile)
	if errors.Is(err, collectorcontrol.ErrCoolingUploadRejected) {
		err = ErrMonitoringAuthority
	}
	return profile, err
}
func assessmentCoverage(c a.Config, asset a.Asset, metric, code, record string, from, through, at time.Time) (a.Fact, error) {
	return a.NewFact(c.Category, c.RunID, asset.EntityKey, "COVERAGE", at, a.Coverage{Metric: metric, From: from, Through: through, Code: code, SourceRecord: record})
}

// Selection is bounded before projecting source metadata. The lateral lookup
// applies the same historical inventory order to each selected occurrence in
// one statement, without acquiring production source or inventory locks.
const assessmentAttemptSQL = `
WITH attempts AS MATERIALIZED (
 SELECT r.run_id,r.scheduled_for,r.completed_at,r.status,r.coverage_complete,r.metric_fields,
        coalesce(j.job_id,''),coalesce(j.configuration_revision,0),coalesce(w.work_id,''),coalesce(e.collector_id,''),e.nodes
 FROM collection_runs r
 LEFT JOIN collection_run_jobs j ON $6='legacy' AND j.run_id=r.run_id AND j.cluster_id=r.cluster_id AND j.source_id=r.source_id
 LEFT JOIN collector_work_items w ON $6='durable' AND w.run_id=r.run_id AND w.cluster_id=r.cluster_id AND w.source_id=r.source_id
 LEFT JOIN durable_schedule_occurrences o ON o.work_id=w.work_id AND o.cluster_id=w.cluster_id AND o.source_id=w.source_id
 LEFT JOIN durable_schedule_executions e ON e.cluster_id=o.cluster_id AND e.source_id=o.source_id AND e.operation=o.operation AND e.revision=o.revision
 WHERE r.cluster_id=$1 AND r.source_id=$2 AND r.query_kind IN ($3,$4) AND r.range_start IS NULL AND r.completed_at>=$5
 AND (($6='legacy' AND j.job_id=$7 AND j.configuration_revision=$8 AND j.node_filter='' AND j.query_kind=$3)
   OR ($6='durable' AND o.operation=$4 AND o.revision=$9 AND w.query_kind=$3 AND w.typed_plan IS NULL AND w.node_filter='' AND w.status IN ('SUCCEEDED','FAILED')
       AND EXISTS(SELECT 1 FROM collector_result_ingestions i WHERE i.work_id=w.work_id AND i.run_id=w.run_id AND i.collector_id=e.collector_id)))
 ORDER BY r.completed_at DESC,r.run_id DESC LIMIT 257
)
SELECT r.run_id,r.completed_at,r.status,r.coverage_complete,
       CASE WHEN octet_length(r.metric_fields::text)<=262144 THEN r.metric_fields END,
       CASE WHEN octet_length(r.nodes::text)<=8192 THEN r.nodes END,
       r.job_id,r.configuration_revision,r.work_id,r.collector_id,i.revision_id,i.source_at
FROM attempts r(run_id,scheduled_for,completed_at,status,coverage_complete,metric_fields,job_id,configuration_revision,work_id,collector_id,nodes)
LEFT JOIN LATERAL (
 SELECT revision_id,source_at FROM goodput_inventory_revisions
 WHERE cluster_id=$1 AND source_id=$2 AND inventory_class='EXPECTED' AND effective_at<=r.scheduled_for AND observed_at<=r.completed_at
 ORDER BY effective_at DESC,observed_at DESC,source_at DESC,revision_id DESC LIMIT 1
) i ON true ORDER BY r.completed_at DESC,r.run_id DESC`

// Both clocks must be within the acquisition cutoff. Keeping collector
// completion separate lets assessment preserve the original sensor timeline.
const assessmentUploadAttemptSQL = `
WITH attempts AS MATERIALIZED (
 SELECT r.run_id,r.scheduled_for,r.completed_at,r.status,r.coverage_complete,r.metric_fields,u.received_at
 FROM public.prometheus_cooling_upload_receipts u
 JOIN public.prometheus_cooling_upload_profiles p ON p.profile_id=u.profile_id AND p.revision=u.profile_revision
   AND p.profile_hash=u.profile_hash AND p.collector_id=u.collector_id
 JOIN collection_runs r ON r.run_id=u.run_id AND r.cluster_id=p.cluster_id AND r.source_id=p.source_id
 WHERE p.cluster_id=$1 AND p.source_id=$2 AND r.query_kind=$3 AND r.range_start IS NULL AND r.job_id IS NULL
 AND r.idempotency_key='prometheus-cooling-report-v2-' || u.payload_hash
 AND u.received_at BETWEEN $4 AND $5 AND r.completed_at<=$5
 AND p.profile_id=$6 AND p.revision=$7 AND p.profile_hash=$8 AND p.collector_id=$9 AND p.revoked_at IS NULL
 AND r.scheduled_for>=p.starts_at AND r.scheduled_for<p.ends_at AND p.registered_at<r.scheduled_for AND r.scheduled_for<=u.received_at
 ORDER BY u.received_at DESC,r.run_id DESC LIMIT 257
)
SELECT r.run_id,r.scheduled_for,r.completed_at,r.received_at,r.status,r.coverage_complete,
       CASE WHEN octet_length(r.metric_fields::text)<=16384 THEN r.metric_fields END,i.revision_id,i.source_at
FROM attempts r
LEFT JOIN LATERAL (
 SELECT revision_id,source_at FROM goodput_inventory_revisions
 WHERE cluster_id=$1 AND source_id=$2 AND inventory_class='EXPECTED' AND effective_at<=r.scheduled_for AND observed_at<=r.completed_at
 ORDER BY effective_at DESC,observed_at DESC,source_at DESC,revision_id DESC LIMIT 1
) i ON true ORDER BY r.received_at DESC,r.run_id DESC`

const assessmentObservationColumnsSQL = `
SELECT observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,
       CASE WHEN octet_length(labels::text)<=16384 THEN labels END,value,unit,observed_at,collected_at,
       CASE WHEN metric_semantics IS NULL THEN 'null'::jsonb
            WHEN octet_length(metric_semantics::text)<=16384 THEN metric_semantics END,
       coalesce(source_reference=$6,false)`

const assessmentObservationScopeSQL = `
 WHERE cluster_id=$1 AND source_id=$2
 AND (metric=$4 OR $4='DCGM_FI_DEV_ROW_REMAP_FAILURE' AND metric='DCGM_FI_DEV_ROW_REMAP_FAILED')`

const assessmentObservationOrderSQL = ` ORDER BY observed_at DESC,observation_id DESC LIMIT 257`

const assessmentObservationSQL = assessmentObservationColumnsSQL + `
 FROM observations` + assessmentObservationScopeSQL + `
 AND run_id=ANY($3::text[]) AND (entity_key=$5 OR entity_key=$7 OR labels @> $8::jsonb OR labels @> $9::jsonb)` + assessmentObservationOrderSQL

// Start with the run IDs admitted by the receipt selector. Keep both lateral
// lookups parameterized so even a generic plan fetches evidence by its primary
// key instead of scanning retained observations by run or by GPU. Recheck raw
// scope before the global ordering and 257th-row truncation sentinel.
const productionUploadObservationSQL = assessmentObservationColumnsSQL + `
 FROM (SELECT DISTINCT unnest($3::text[]) AS selected_run) ids
 CROSS JOIN LATERAL (
  SELECT observation_id AS selected_id FROM public.prometheus_cooling_receipt_observations
  WHERE run_id=ids.selected_run AND entity_key=$5 OFFSET 0
 ) refs
 CROSS JOIN LATERAL (
  SELECT * FROM public.observations WHERE observation_id=refs.selected_id OFFSET 0
 ) o` + assessmentObservationScopeSQL + `
 AND o.run_id=ids.selected_run AND o.entity_key=$5
 AND starts_with(ids.selected_run,'` + domain.CoolingUploadRunPrefix + `')` + assessmentObservationOrderSQL

type assessmentAttempt struct {
	completed  time.Time
	scheduled  time.Time
	usable     bool
	provenance a.Provenance
}

func loadAssessmentAttempts(ctx context.Context, tx pgx.Tx, c a.Config, asset a.Asset, b a.Binding, auth assessmentAuthority, from, at time.Time) (map[string]assessmentAttempt, []string, bool, error) {
	if auth.upload != nil {
		return loadAssessmentUploadAttempts(ctx, tx, c, asset, b, auth.query, *auth.upload, from, at)
	}
	rows, err := tx.Query(ctx, assessmentAttemptSQL, c.ClusterID, c.SourceID, auth.query, b.Operation, from, auth.mode, auth.jobID, auth.configurationRevision, b.ScheduleRevision)
	if err != nil {
		return nil, nil, false, err
	}
	defer rows.Close()
	attempts := make(map[string]assessmentAttempt)
	ids := make([]string, 0, 256)
	identity := domain.GPUObservationIdentity{EntityKey: asset.EntityKey, NodeID: domain.StableNodeID(asset.NodeID), PhysicalGPUUUID: domain.PhysicalGPUUUID(asset.GPUUUID), Canonical: true}
	seen := 0
	truncated := false
	for rows.Next() {
		seen++
		if seen > 256 {
			truncated = true
			break
		}
		var id, job, work, collector string
		var revision int64
		var inventory *string
		var inventoryAt *time.Time
		var stamp time.Time
		var status domain.ResultStatus
		var complete bool
		var fieldBody, nodes []byte
		if err := rows.Scan(&id, &stamp, &status, &complete, &fieldBody, &nodes, &job, &revision, &work, &collector, &inventory, &inventoryAt); err != nil {
			return nil, nil, false, err
		}
		stamp = stamp.UTC()
		var fields []domain.DCGMFieldEvidence
		fieldOK := len(fieldBody) > 0 && json.Unmarshal(fieldBody, &fields) == nil && monitoringFieldState(fields, identity, b.Metric) == "SUPPORTED"
		p := a.Provenance{Mode: string(auth.mode), CollectionRunID: id, Operation: b.Operation, ScheduleRevision: b.ScheduleRevision, InventoryRevision: c.InventoryRevision}
		provenanceOK := false
		if auth.mode == domain.SchedulingLegacy {
			p.JobID, p.ConfigurationRevision = job, &revision
			provenanceOK = job == auth.jobID && revision == auth.configurationRevision
		} else {
			p.WorkID, p.CollectorID = work, collector
			var scope []string
			if len(nodes) > 0 && json.Unmarshal(nodes, &scope) == nil {
				slices.Sort(scope)
				provenanceOK = slices.Equal(scope, b.ScopeNodes) && work != "" && collector != ""
			}
		}
		_, duplicate := attempts[id]
		if duplicate {
			return nil, nil, false, a.ErrInvalid
		}
		ids = append(ids, id)
		attempts[id] = assessmentAttempt{completed: stamp, provenance: p, usable: status == domain.ResultSucceeded && complete && fieldOK && provenanceOK && inventory != nil && *inventory == c.InventoryRevision && inventoryAt != nil && !inventoryAt.After(stamp)}
	}
	return attempts, ids, truncated, rows.Err()
}

func loadAssessmentUploadAttempts(ctx context.Context, tx pgx.Tx, c a.Config, asset a.Asset, b a.Binding, query domain.QueryKind, profile domain.CoolingUploadProfile, from, at time.Time) (map[string]assessmentAttempt, []string, bool, error) {
	if c.Production() {
		return loadProductionUploadAttempts(ctx, tx, c, asset, b, query, from, at)
	}
	rows, err := tx.Query(ctx, assessmentUploadAttemptSQL, c.ClusterID, c.SourceID, query, from, at, profile.ProfileID, profile.Revision, b.UploadProfileHash, profile.CollectorID)
	if err != nil {
		return nil, nil, false, err
	}
	defer rows.Close()
	attempts := make(map[string]assessmentAttempt)
	ids := make([]string, 0, 256)
	identity := domain.GPUObservationIdentity{EntityKey: asset.EntityKey, NodeID: domain.StableNodeID(asset.NodeID), PhysicalGPUUUID: domain.PhysicalGPUUUID(asset.GPUUUID), Canonical: true}
	seen := 0
	for rows.Next() {
		seen++
		if seen > 256 {
			return attempts, ids, true, nil
		}
		var id string
		var slot, completed, received time.Time
		var status domain.ResultStatus
		var complete bool
		var fieldBody []byte
		var inventory *string
		var inventoryAt *time.Time
		if err := rows.Scan(&id, &slot, &completed, &received, &status, &complete, &fieldBody, &inventory, &inventoryAt); err != nil {
			return nil, nil, false, err
		}
		slot, completed = slot.UTC(), completed.UTC()
		task := profile.Task(query, slot)
		if string(task.RunID) != id || !slot.Equal(slot.Truncate(domain.CoolingUploadInterval)) || completed.Before(slot) || completed.After(task.Deadline) || received.After(at) {
			continue
		}
		var fields []domain.DCGMFieldEvidence
		fieldOK := len(fieldBody) > 0 && json.Unmarshal(fieldBody, &fields) == nil && monitoringFieldState(fields, identity, b.Metric) == "SUPPORTED"
		provenance := a.Provenance{Mode: "upload", CollectionRunID: id, Operation: b.Operation, ScheduleRevision: profile.Revision, InventoryRevision: profile.InventoryRevision,
			CollectorID: string(profile.CollectorID), UploadProfileID: profile.ProfileID, UploadProfileHash: b.UploadProfileHash}
		ids = append(ids, id)
		attempts[id] = assessmentAttempt{completed: completed, scheduled: slot, provenance: provenance, usable: status == domain.ResultSucceeded && complete && fieldOK && inventory != nil && *inventory == c.InventoryRevision && inventoryAt != nil && !inventoryAt.After(completed)}
	}
	return attempts, ids, false, rows.Err()
}

func loadAssessmentSamples(ctx context.Context, tx pgx.Tx, c a.Config, asset a.Asset, b a.Binding, query domain.QueryKind, from, at time.Time, attempts map[string]assessmentAttempt, ids []string, known map[string]a.Sample) ([]a.Fact, bool, error) {
	if len(ids) == 0 {
		return nil, false, nil
	}
	legacyKey := "node/" + asset.NodeID + "/gpu/" + asset.GPUUUID
	uuid, _ := json.Marshal([]domain.Label{{Name: "UUID", Value: asset.GPUUUID}})
	lowerUUID, _ := json.Marshal([]domain.Label{{Name: "uuid", Value: asset.GPUUUID}})
	sourceContract := domain.DCGMSourceReference(query)
	statement := assessmentObservationSQL
	args := []any{c.ClusterID, c.SourceID, ids, b.Metric, asset.EntityKey, sourceContract}
	if c.Production() && b.UploadProfileID != "" {
		statement = productionUploadObservationSQL
	} else {
		args = append(args, legacyKey, uuid, lowerUUID)
	}
	rows, err := tx.Query(ctx, statement, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []a.Fact
	seen := 0
	truncated := false
	for rows.Next() {
		seen++
		if seen > 256 {
			truncated = true
			break
		}
		var o domain.Observation
		var run string
		var labels, semantics []byte
		var sourceClockQualified bool
		if err := rows.Scan(&o.ID, &run, &o.ClusterID, &o.SourceID, &o.SchemaVersion, &o.Kind, &o.EntityKey, &o.Metric, &labels, &o.Value, &o.Unit, &o.ObservedAt, &o.CollectedAt, &semantics, &sourceClockQualified); err != nil {
			return nil, false, err
		}
		attempt := attempts[run]
		if !attempt.usable {
			continue
		}
		if string(labels) == "{}" || string(labels) == "null" {
			labels = []byte("[]")
		}
		if len(labels) == 0 || len(semantics) == 0 || json.Unmarshal(labels, &o.Labels) != nil || json.Unmarshal(semantics, &o.Semantics) != nil {
			truncated = true
			continue
		}
		i, ok := domain.ResolveGPUObservationIdentity(domain.ClusterID(c.ClusterID), domain.SourceID(c.SourceID), o)
		if sourceClockQualified {
			o.SourceReference = sourceContract
		}
		upload := attempt.provenance.Mode == "upload"
		if upload && (!sourceClockQualified || o.EntityKey != asset.EntityKey || !o.ObservedAt.After(attempt.scheduled.Add(-domain.CoolingUploadInterval)) || o.ObservedAt.After(attempt.scheduled) || !domain.CoolingUploadValueValid(query, o.Value)) {
			continue
		}
		// A valid original DCGM clock may lead its completed collection by one
		// second. Preserve that fact at admission, but only source eligibility
		// (derived from its original timestamp) permits later category use.
		validateAt := at
		if o.ObservedAt.After(at) {
			validateAt = o.ObservedAt
		}
		if !ok || !i.Canonical || i.EntityKey != asset.EntityKey || o.ObservedAt.Before(from) || attempt.completed.After(at) ||
			!monitoringValidOperationObservation(query, o, validateAt, attempt.completed, 900*time.Second, !upload) {
			continue
		}
		p := attempt.provenance
		p.SourceRecord = string(o.ID)
		sensor, _ := domain.GPUHealthSensor(o.Metric)
		sample := a.Sample{Metric: o.Metric, Unit: sensor.Unit, SourceAt: o.ObservedAt.UTC(), CollectedAt: o.CollectedAt.UTC(), CompletedAt: attempt.completed, Value: o.Value, SourceRecord: p.SourceRecord, Provenance: p}
		if previous, ok := known[p.SourceRecord]; ok && sameAssessmentSample(previous, sample) {
			continue
		}
		f, err := a.NewFact(c.Category, c.RunID, asset.EntityKey, "SAMPLE", at, sample)
		if err != nil {
			return nil, false, err
		}
		out = append(out, f)
	}
	return out, truncated, rows.Err()
}

func sameAssessmentSample(previous, current a.Sample) bool {
	left, right := previous.Provenance.ConfigurationRevision, current.Provenance.ConfigurationRevision
	if (left == nil) != (right == nil) || left != nil && *left != *right {
		return false
	}
	previous.Provenance.ConfigurationRevision, current.Provenance.ConfigurationRevision = nil, nil
	return previous == current
}

func loadAssessmentInput(ctx context.Context, tx pgx.Tx, c a.Config, asset a.Asset, at time.Time, admitted ...map[string]a.Fact) ([]a.Fact, error) {
	out := []a.Fact{}
	// An equivalent repeat already has canonical bytes and first availability
	// in this immutable snapshot. Still recheck the source attempt, inventory,
	// identity and sensor semantics before considering it a repeat below.
	var known map[string]a.Sample
	if len(admitted) > 0 {
		known = make(map[string]a.Sample)
		for _, f := range admitted[0] {
			if f.Run != c.RunID || f.Asset != asset.EntityKey || f.Kind != "SAMPLE" {
				continue
			}
			var sample a.Sample
			if err := json.Unmarshal(f.Body, &sample); err != nil {
				return nil, err
			}
			known[sample.SourceRecord] = sample
		}
	}
	from := at.Add(-900 * time.Second)
	for _, binding := range c.Bindings {
		authority, err := validateAssessmentAuthority(ctx, tx, c, asset, binding, at)
		if err != nil {
			if errors.Is(err, ErrMonitoringAuthority) || errors.Is(err, pgx.ErrNoRows) {
				return nil, fmt.Errorf("AUTHORITY_LOST: %w", err)
			}
			return nil, err
		}
		started := time.Now()
		attempts, ids, truncated, err := loadAssessmentAttempts(ctx, tx, c, asset, binding, authority, from, at)
		if err != nil {
			if c.Production() && binding.UploadProfileID != "" {
				err = assessmentTransactionError("production.input.receipts", started, err, "not_attempted")
			}
			return nil, err
		}
		started = time.Now()
		samples, sampleTruncated, err := loadAssessmentSamples(ctx, tx, c, asset, binding, authority.query, from, at, attempts, ids, known)
		if err != nil {
			if c.Production() && binding.UploadProfileID != "" {
				err = assessmentTransactionError("production.input.samples", started, err, "not_attempted")
			}
			return nil, err
		}
		out = append(out, samples...)
		if truncated || sampleTruncated {
			f, err := assessmentCoverage(c, asset, binding.Metric, "TRUNCATED", "history", from, at, at)
			if err != nil {
				return nil, err
			}
			out = append(out, f)
		}
		for _, id := range ids {
			attempt := attempts[id]
			if attempt.usable {
				continue
			}
			f, err := assessmentCoverage(c, asset, binding.Metric, "UNSUPPORTED", id, attempt.completed, attempt.completed, at)
			if err != nil {
				return nil, err
			}
			out = append(out, f)
		}
	}
	qualified, err := loadAssessmentQualified(ctx, tx, c, asset, at, admitted...)
	if err != nil {
		return nil, err
	}
	out = append(out, qualified...)
	if len(out) > a.MaxFacts {
		return nil, ErrAssessmentCapacity
	}
	// The type-specific body caps and total fact count bound all per-asset
	// copies. Check exact wire bytes without reparsing each canonical fact body.
	b, err := json.Marshal(out)
	if err != nil || len(b) > a.MaxInputBytes {
		return nil, ErrAssessmentCapacity
	}
	return out, nil
}

// Active OPENs and recoveries of an OPEN already admitted in this run are
// the only eligible transitions. A long history of unrelated closed episodes
// cannot consume the current qualification budget or create a late preview.
const assessmentQualifiedSQL = `
WITH scope AS MATERIALIZED (
 SELECT policy_id,cluster_id,rule_id,rule_version,enrollment_revision
 FROM gp09_monitor_enrollments WHERE cluster_id=$1 AND source_id=$2 AND entity_key=$3
  AND enabled AND rule_version=1 AND rule_id IN ('gpu_thermal','hbm_thermal','telemetry_loss')
), retained AS MATERIALIZED (
 SELECT q.body->>'policy_id' AS policy_id,(q.body->>'occurrence')::bigint AS occurrence,
        q.body->>'rule' AS rule_id,(q.body->>'rule_version')::bigint AS rule_version,
        (q.body->>'enrollment_revision')::bigint AS enrollment_revision
 FROM assessment_facts f
 CROSS JOIN LATERAL (SELECT convert_from(f.body,'UTF8')::jsonb->'body' AS body) q
 WHERE f.run_id=$4 AND f.asset=$3 AND f.kind='QUALIFIED' AND f.available_at<=$5
 GROUP BY 1,2,3,4,5
 HAVING bool_or(q.body->>'transition'='OPEN') AND NOT bool_or(q.body->>'transition'='RECOVER')
 UNION
 SELECT q.policy_id,q.occurrence,q.rule_id,q.rule_version,q.enrollment_revision
 FROM jsonb_to_recordset($6::jsonb) q(policy_id text,occurrence bigint,rule_id text,rule_version bigint,enrollment_revision bigint)
), transitions AS (
 SELECT n.policy_id,e.occurrence,t.transition,n.rule_id,n.rule_version,n.enrollment_revision,e.severity,t.occurred_at,t.snapshot
 FROM scope n
 JOIN gp09_monitor_episodes e ON e.cluster_id=n.cluster_id AND e.policy_id=n.policy_id AND e.enrollment_revision=n.enrollment_revision AND e.closed_at IS NULL
 JOIN gp09_monitor_transitions t ON t.cluster_id=e.cluster_id AND t.policy_id=e.policy_id AND t.occurrence=e.occurrence AND t.transition='OPEN'
 UNION ALL
 SELECT n.policy_id,e.occurrence,t.transition,n.rule_id,n.rule_version,n.enrollment_revision,e.severity,t.occurred_at,t.snapshot
 FROM retained r JOIN scope n USING (policy_id,rule_id,rule_version,enrollment_revision)
 JOIN gp09_monitor_episodes e ON e.cluster_id=n.cluster_id AND e.policy_id=n.policy_id AND e.enrollment_revision=n.enrollment_revision AND e.occurrence=r.occurrence
 JOIN gp09_monitor_transitions t ON t.cluster_id=e.cluster_id AND t.policy_id=e.policy_id AND t.occurrence=e.occurrence AND t.transition='RECOVER'
)
SELECT policy_id,occurrence,transition,rule_id,rule_version,enrollment_revision,severity,occurred_at,
       CASE WHEN octet_length(snapshot::text)<=65536 THEN snapshot END
FROM transitions
ORDER BY CASE WHEN transition='OPEN' AND severity='CRITICAL' THEN 0 WHEN transition='OPEN' THEN 1 ELSE 2 END,
         occurred_at,policy_id,occurrence,transition LIMIT 33`

func loadAssessmentQualified(ctx context.Context, tx pgx.Tx, c a.Config, asset a.Asset, at time.Time, admitted ...map[string]a.Fact) ([]a.Fact, error) {
	retained := []map[string]any{}
	if c.Production() && len(admitted) > 0 {
		for _, f := range admitted[0] {
			if f.Asset == asset.EntityKey && f.Kind == "QUALIFIED" {
				var q a.Qualified
				if json.Unmarshal(f.Body, &q) == nil && q.Transition == "OPEN" {
					retained = append(retained, map[string]any{"policy_id": q.PolicyID, "occurrence": q.Occurrence, "rule_id": q.Rule, "rule_version": q.RuleVersion, "enrollment_revision": q.EnrollmentRevision})
				}
			}
		}
	}
	body, _ := json.Marshal(retained)
	query := assessmentQualifiedSQL
	if c.Production() {
		query = strings.Replace(query, "FROM assessment_facts f", "FROM (SELECT NULL::text AS run_id,NULL::text AS asset,NULL::text AS kind,NULL::timestamptz AS available_at,NULL::bytea AS body WHERE false) f", 1)
	}
	rows, err := tx.Query(ctx, query, c.ClusterID, c.SourceID, asset.EntityKey, c.RunID, at, body)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []a.Fact{}
	for rows.Next() {
		var q a.Qualified
		var snapshot []byte
		if err = rows.Scan(&q.PolicyID, &q.Occurrence, &q.Transition, &q.Rule, &q.RuleVersion, &q.EnrollmentRevision, &q.Severity, &q.QualifiedAt, &snapshot); err != nil {
			return nil, err
		}
		if len(out) >= 32 {
			return nil, ErrAssessmentCapacity
		}
		q.Snapshot = []a.SnapshotEntry{}
		var raw []MonitoringEvidenceSnapshot
		if json.Unmarshal(snapshot, &raw) != nil || len(raw) > 32 {
			continue
		}
		for _, s := range raw {
			support := "UNKNOWN"
			if s.Supported {
				support = "SUPPORTED"
			}
			q.Snapshot = append(q.Snapshot, a.SnapshotEntry{Metric: s.Metric, SourceAt: s.Reference.ObservedAt, Value: s.Value, Unit: s.Unit, Support: support})
		}
		f, err := a.NewFact(c.Category, c.RunID, asset.EntityKey, "QUALIFIED", at, q)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

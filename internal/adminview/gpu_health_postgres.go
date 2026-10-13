package adminview

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// A health read is a bounded snapshot, not inventory enrollment. In particular,
// an older current projection cannot fill a gap in the latest applicable run.
type gpuHealthRun struct {
	id        string
	source    domain.SourceID
	query     domain.QueryKind
	nodes     []string
	finite    bool
	completed time.Time
	status    domain.ResultStatus
	complete  bool
	fields    []domain.DCGMFieldEvidence
}
type gpuHealthSample struct {
	observation domain.Observation
	runID       string
	query       domain.QueryKind
	lastSuccess time.Time
}
type gpuHealthDevice struct {
	identity domain.GPUObservationIdentity
	source   domain.SourceID
	expected bool
	samples  []gpuHealthSample
}

// LoadGPUHealthSummaries supplies both public and private views with identical
// original observations, latest operation assessments and expected placeholders.
// All identities, expected revisions and run selection remain source scoped.
func (store *PostgresStore) LoadGPUHealthSummaries(ctx context.Context, clusterID string, at time.Time, freshFor time.Duration) ([]application.GPUSummaryProjection, error) {
	return store.loadGPUHealthSummaries(ctx, clusterID, at, freshFor, nil)
}

func (store *PostgresStore) loadGPUHealthSummaries(ctx context.Context, clusterID string, at time.Time, freshFor time.Duration, support map[string][]domain.DCGMFieldEvidence) ([]application.GPUSummaryProjection, error) {
	if clusterID == "" || at.IsZero() || freshFor <= 0 {
		return nil, fmt.Errorf("GPU health requires exact cluster, evaluation time and positive freshness")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var tx pgx.Tx
	var err error
	ownsSnapshot := store.gpuSnapshot == nil
	if ownsSnapshot {
		tx, err = store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			return nil, fmt.Errorf("begin GPU health snapshot: %w", err)
		}
		defer rollbackGPUHealthSnapshot(tx)
		if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='250ms'`); err != nil {
			return nil, err
		}
	} else {
		tx = store.gpuSnapshot
	}
	devices := map[string]*gpuHealthDevice{}
	device := func(source domain.SourceID, identity domain.GPUObservationIdentity) *gpuHealthDevice {
		key := string(source) + "\x00" + identity.EntityKey
		if devices[key] == nil {
			devices[key] = &gpuHealthDevice{identity: identity, source: source}
		}
		return devices[key]
	}
	// Choose governing expected inventory independently for every enrolled source.
	rows, err := tx.Query(ctx, `WITH revisions AS (
 SELECT DISTINCT ON (r.source_id) r.source_id,r.revision_id FROM goodput_inventory_revisions r
 JOIN sources s ON s.source_id=r.source_id AND s.cluster_id=r.cluster_id
 WHERE r.cluster_id=$1 AND s.kind='prometheus' AND r.inventory_class='EXPECTED'
 AND r.effective_at<=$2 AND r.observed_at<=$2
 ORDER BY r.source_id,r.effective_at DESC,r.observed_at DESC,r.source_at DESC,r.revision_id DESC)
 SELECT r.source_id,e.stable_node_id,e.physical_gpu_uuid FROM revisions r
 JOIN goodput_inventory_revision_entities e ON e.revision_id=r.revision_id AND e.cluster_id=$1
 WHERE e.entity_kind='GPU' ORDER BY r.source_id,e.stable_node_id,e.physical_gpu_uuid LIMIT 4097`, clusterID, at)
	if err != nil {
		return nil, fmt.Errorf("read expected GPU health inventory: %w", err)
	}
	count := 0
	for rows.Next() {
		var source domain.SourceID
		var node domain.StableNodeID
		var gpu domain.PhysicalGPUUUID
		if err = rows.Scan(&source, &node, &gpu); err != nil {
			rows.Close()
			return nil, err
		}
		count++
		entity, e := domain.CreateEntityIdentity(domain.EntityIdentity{ClusterID: domain.ClusterID(clusterID), Kind: domain.EntityGPU, NodeID: node, PhysicalGPUUUID: gpu})
		if e != nil {
			rows.Close()
			return nil, e
		}
		identity, ok := domain.ResolveGPUObservationIdentity(domain.ClusterID(clusterID), source, domain.Observation{ClusterID: domain.ClusterID(clusterID), SourceID: source, EntityKey: entity.Key()})
		if !ok {
			rows.Close()
			return nil, fmt.Errorf("expected GPU has unsupported identity")
		}
		device(source, identity).expected = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if count > 4096 {
		return nil, fmt.Errorf("GPU health expected inventory exceeds snapshot bound")
	}
	// Partition latest runs by exact durable scope. A node-only attempt must not
	// supersede another node's collection. Typed finite scopes remain finite.
	// Future-dated attempts are retained as UNKNOWN; they cannot uncover an
	// older apparent success while the private field page reports clock skew.
	rows, err = tx.Query(ctx, `WITH scoped AS (
 SELECT r.run_id,r.source_id,r.query_kind,r.completed_at,r.status,r.coverage_complete,r.metric_fields,w.typed_plan IS NOT NULL AS finite,
 CASE WHEN w.typed_plan IS NOT NULL AND w.typed_plan->'scope'->'nodes' IS NOT NULL
 THEN w.typed_plan->'scope'->'nodes'
 ELSE CASE WHEN coalesce(j.node_filter,w.node_filter,'')='' THEN '[]'::jsonb
 ELSE jsonb_build_array(coalesce(j.node_filter,w.node_filter)) END END AS nodes
 FROM collection_runs r JOIN sources s ON s.source_id=r.source_id AND s.cluster_id=r.cluster_id
 LEFT JOIN collection_run_jobs j ON j.run_id=r.run_id
 LEFT JOIN collector_work_items w ON w.run_id=r.run_id
 WHERE r.cluster_id=$1 AND s.kind='prometheus' AND r.range_start IS NULL
 ), ranked AS (SELECT *,row_number() OVER(PARTITION BY source_id,query_kind,nodes,finite ORDER BY completed_at DESC,run_id DESC) AS rank FROM scoped)
 SELECT run_id,source_id,query_kind,completed_at,status,coverage_complete,metric_fields,nodes,finite
 FROM ranked WHERE rank=1 ORDER BY source_id,query_kind,nodes LIMIT 4097`, clusterID)
	if err != nil {
		return nil, fmt.Errorf("read scoped GPU health attempts: %w", err)
	}
	runs := []gpuHealthRun{}
	count = 0
	for rows.Next() {
		var run gpuHealthRun
		var query string
		var fields, nodes []byte
		if err = rows.Scan(&run.id, &run.source, &query, &run.completed, &run.status, &run.complete, &fields, &nodes, &run.finite); err != nil {
			rows.Close()
			return nil, err
		}
		count++
		run.query = gpuHealthQuery(query)
		if !run.query.IsGPU() {
			continue
		}
		if err = json.Unmarshal(nodes, &run.nodes); err != nil {
			rows.Close()
			return nil, err
		}
		if len(fields) > 0 {
			if err = json.Unmarshal(fields, &run.fields); err != nil {
				rows.Close()
				return nil, err
			}
		}
		runs = append(runs, run)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if count > 4096 {
		return nil, fmt.Errorf("GPU health operation scopes exceed snapshot bound")
	}
	rows, err = tx.Query(ctx, `SELECT o.observation_id,o.run_id,o.cluster_id,o.source_id,o.schema_version,
 o.kind,o.entity_key,o.metric,o.labels,o.value,o.unit,o.observed_at,o.collected_at,o.source_reference,o.metric_semantics,p.last_success_at,r.query_kind
 FROM current_projections p JOIN observations o ON o.observation_id=p.observation_id
 AND o.cluster_id=p.cluster_id AND o.source_id=p.source_id AND o.entity_key=p.entity_key AND o.metric=p.metric
 JOIN collection_runs r ON r.run_id=o.run_id AND r.cluster_id=o.cluster_id AND r.source_id=o.source_id
 JOIN sources s ON s.source_id=p.source_id AND s.cluster_id=p.cluster_id
 WHERE p.cluster_id=$1 AND s.kind='prometheus' AND o.observed_at<=$2 AND o.collected_at<=$2 AND r.completed_at<=$2 AND r.range_start IS NULL
 ORDER BY p.source_id,p.entity_key,p.metric LIMIT 20001`, clusterID, at)
	if err != nil {
		return nil, fmt.Errorf("read GPU health observations: %w", err)
	}
	count = 0
	for rows.Next() {
		var sample gpuHealthSample
		var labels, semantics []byte
		var query string
		o := &sample.observation
		if err = rows.Scan(&o.ID, &sample.runID, &o.ClusterID, &o.SourceID, &o.SchemaVersion, &o.Kind, &o.EntityKey, &o.Metric, &labels, &o.Value, &o.Unit, &o.ObservedAt, &o.CollectedAt, &o.SourceReference, &semantics, &sample.lastSuccess, &query); err != nil {
			rows.Close()
			return nil, err
		}
		count++
		sample.query = gpuHealthQuery(query)
		if !sample.query.IsGPU() {
			continue
		}
		if string(labels) == "{}" || string(labels) == "null" {
			labels = []byte("[]")
		}
		if err = json.Unmarshal(labels, &o.Labels); err != nil {
			rows.Close()
			return nil, err
		}
		if len(semantics) > 0 && string(semantics) != "null" {
			if err = json.Unmarshal(semantics, &o.Semantics); err != nil {
				rows.Close()
				return nil, err
			}
		}
		identity, ok := domain.ResolveGPUObservationIdentity(domain.ClusterID(clusterID), o.SourceID, *o)
		if !ok {
			continue
		}
		device(o.SourceID, identity).samples = append(device(o.SourceID, identity).samples, sample)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if count > 20000 {
		return nil, fmt.Errorf("GPU health observations exceed snapshot bound")
	}
	if ownsSnapshot {
		if err = tx.Commit(ctx); err != nil {
			return nil, err
		}
	}
	summaries := make([]application.GPUSummaryProjection, 0, len(devices))
	for _, d := range devices {
		var fields []domain.DCGMFieldEvidence
		summary, e := projectGPUHealthDeviceWithSupport(domain.ClusterID(clusterID), d, runs, at, freshFor, &fields)
		if support != nil {
			support[string(d.source)+"\x00"+d.identity.EntityKey] = fields
		}
		if e != nil {
			return nil, e
		}
		summaries = append(summaries, summary)
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].EntityKey != summaries[j].EntityKey {
			return summaries[i].EntityKey < summaries[j].EntityKey
		}
		return summaries[i].SourceID < summaries[j].SourceID
	})
	return summaries, nil
}

func gpuHealthQuery(value string) domain.QueryKind {
	switch value {
	case "DCGM_GPU_IDENTITY":
		value = string(domain.QueryGPUIdentity)
	case "DCGM_GPU_UTILIZATION":
		value = string(domain.QueryGPUUtilization)
	case "DCGM_GPU_XID":
		value = string(domain.QueryGPUXID)
	}
	q := domain.QueryKind(value)
	if q.IsGPU() {
		return q
	}
	operation, ok := domain.ReviewedCollectionOperation(domain.CollectionOperationID(value))
	if ok && operation.Query.IsGPU() {
		return operation.Query
	}
	return ""
}
func latestGPUHealthRun(runs []gpuHealthRun, source domain.SourceID, node domain.StableNodeID, query domain.QueryKind) *gpuHealthRun {
	var latest *gpuHealthRun
	for i := range runs {
		r := &runs[i]
		if r.source != source || r.query != query {
			continue
		}
		applies := len(r.nodes) == 0 && !r.finite
		for _, n := range r.nodes {
			if n == string(node) {
				applies = true
			}
		}
		if applies && (latest == nil || r.completed.After(latest.completed) || r.completed.Equal(latest.completed) && r.id > latest.id) {
			latest = r
		}
	}
	return latest
}
func gpuHealthMetrics(query domain.QueryKind) []string {
	if query == domain.QueryGPUUtilization {
		return []string{"DCGM_FI_DEV_GPU_UTIL"}
	}
	if query == domain.QueryGPUXID {
		return []string{"DCGM_FI_DEV_XID_ERRORS"}
	}
	names := []string{}
	for _, field := range domain.DCGMFields(query) {
		names = append(names, field.Name)
	}
	return names
}
func projectGPUHealthDevice(cluster domain.ClusterID, d *gpuHealthDevice, runs []gpuHealthRun, at time.Time, freshFor time.Duration) (application.GPUSummaryProjection, error) {
	return projectGPUHealthDeviceWithSupport(cluster, d, runs, at, freshFor, nil)
}
func projectGPUHealthDeviceWithSupport(cluster domain.ClusterID, d *gpuHealthDevice, runs []gpuHealthRun, at time.Time, freshFor time.Duration, support *[]domain.DCGMFieldEvidence) (application.GPUSummaryProjection, error) {
	summary := application.GPUSummaryProjection{EntityKey: d.identity.EntityKey, SourceID: d.source, Freshness: domain.FreshnessUnknown, Observations: []domain.Observation{}}
	result := domain.CollectionResult{Task: domain.CollectionTask{ClusterID: cluster, SourceID: d.source}, Status: domain.ResultPartial, Coverage: domain.Coverage{Complete: d.expected}}
	fields := map[string]domain.DCGMFieldEvidence{}
	queries := append([]domain.QueryKind{domain.QueryGPUUtilization, domain.QueryGPUXID}, domain.ExpandedDCGMQueries()...)
	for _, query := range queries {
		run := latestGPUHealthRun(runs, d.source, d.identity.NodeID, query)
		for _, metric := range gpuHealthMetrics(query) {
			field := domain.DCGMFieldEvidence{NodeID: d.identity.NodeID, GPU: d.identity.PhysicalGPUUUID, Metric: metric, State: "UNKNOWN", Reason: "missing_or_unavailable"}
			if run != nil {
				if !run.completed.After(at) && run.completed.After(result.CompletedAt) {
					result.CompletedAt = run.completed
				}
				if run.completed.After(at) {
					field.Reason = "future_collection"
				} else if run.status == domain.ResultFailed {
					field.Reason = "collection_failed"
				} else {
					for _, assessment := range run.fields {
						if assessment.NodeID == field.NodeID && assessment.GPU == field.GPU && assessment.Metric == metric {
							field = assessment
							break
						}
					}
				}
				if !run.complete || run.status != domain.ResultSucceeded {
					result.Coverage.Complete = false
				}
			}
			fields[metric] = field
		}
	}
	// Retain same-timestamp conflicts for the projector to report UNKNOWN. Read
	// deduplication collapses only equal evidence or strictly older alias samples.
	admitted := map[string][]gpuHealthSample{}
	for _, sample := range d.samples {
		o := sample.observation
		allowed := sample.query == domain.QueryGPUIdentity && o.Metric == string(domain.QueryGPUIdentity)
		for _, metric := range gpuHealthMetrics(sample.query) {
			if metric == o.Metric {
				allowed = true
			}
		}
		if !allowed {
			continue
		}
		run := latestGPUHealthRun(runs, d.source, d.identity.NodeID, sample.query)
		if run == nil || run.id != sample.runID || run.status == domain.ResultFailed || run.completed.After(at) {
			continue
		}
		field, known := fields[o.Metric]
		expanded := len(domain.DCGMFields(sample.query)) > 0
		if expanded && (!known || field.State != "SUPPORTED") {
			continue
		}
		if !expanded && known && (run.status == domain.ResultSucceeded || run.status == domain.ResultPartial) {
			field.State = "SUPPORTED"
			field.Reason = ""
			fields[o.Metric] = field
		}
		prior := admitted[o.Metric]
		if len(prior) == 0 || o.ObservedAt.After(prior[0].observation.ObservedAt) {
			admitted[o.Metric] = []gpuHealthSample{sample}
			continue
		}
		if o.ObservedAt.Equal(prior[0].observation.ObservedAt) {
			equal := false
			for _, old := range prior {
				if old.observation.Value == o.Value && old.observation.Unit == o.Unit && gpuHealthSemanticsEqual(old.observation.Semantics, o.Semantics) {
					equal = true
					break
				}
			}
			if !equal {
				admitted[o.Metric] = append(prior, sample)
			}
		}
	}
	metrics := make([]string, 0, len(admitted))
	for metric := range admitted {
		metrics = append(metrics, metric)
	}
	sort.Strings(metrics)
	var oldest *time.Time
	for _, metric := range metrics {
		for _, sample := range admitted[metric] {
			o := sample.observation
			summary.Observations = append(summary.Observations, o)
			if oldest == nil || o.ObservedAt.Before(*oldest) {
				t := o.ObservedAt
				oldest = &t
			}
			if sample.lastSuccess.After(summary.LastSuccessAt) {
				summary.LastSuccessAt = sample.lastSuccess
			}
		}
	}
	if support != nil {
		for _, query := range queries {
			if latestGPUHealthRun(runs, d.source, d.identity.NodeID, query) == nil {
				continue
			}
			for _, metric := range gpuHealthMetrics(query) {
				*support = append(*support, fields[metric])
			}
		}
	}
	// Exact expected physical devices carry every independently assessed field.
	// Legacy index-only evidence remains evaluable but cannot claim UUID coverage.
	if d.identity.Canonical {
		for _, query := range queries {
			for _, metric := range gpuHealthMetrics(query) {
				field := fields[metric]
				result.Coverage.MetricFields = append(result.Coverage.MetricFields, field)
				if field.State != "SUPPORTED" || len(admitted[metric]) == 0 {
					result.Coverage.Complete = false
				}
			}
		}
	}
	expected := len(result.Coverage.MetricFields)
	result.Coverage.SeriesExpected = &expected
	result.Coverage.SeriesReturned = len(summary.Observations)
	if d.expected {
		result.Coverage.ExpectedTargets = []domain.EvidenceTarget{{Kind: domain.EvidenceTargetNode, ID: domain.EvidenceTargetID(d.identity.NodeID)}, {Kind: domain.EvidenceTargetGPU, ID: domain.EvidenceTargetID(d.identity.PhysicalGPUUUID)}}
	}
	if result.Coverage.Complete {
		result.Status = domain.ResultSucceeded
	}
	result.Observations = summary.Observations
	summary.Freshness = domain.FreshnessAt(oldest, at, freshFor)
	var err error
	thresholds := application.DefaultGPUHealthThresholds()
	thresholds.FreshFor = freshFor
	summary.Signals, err = application.ProjectGPUHealth(result, at, thresholds)
	return summary, err
}

func gpuHealthSemanticsEqual(a, b *domain.MetricSemantics) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// LoadGPUMetricsWithHealth prevents a commit between private value/support
// reads and health assembly from mixing different operation attempts. Public
// summaries and private conditions still use the identical health assembler.
func (store *PostgresStore) LoadGPUMetricsWithHealth(ctx context.Context, clusterID string, at time.Time, freshFor time.Duration) (GPUMetricsSnapshot, error) {
	if clusterID == "" || at.IsZero() || freshFor <= 0 {
		return GPUMetricsSnapshot{}, fmt.Errorf("GPU metrics snapshot requires exact cluster, evaluation time and positive freshness")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return GPUMetricsSnapshot{}, fmt.Errorf("begin GPU metrics health snapshot: %w", err)
	}
	defer rollbackGPUHealthSnapshot(tx)
	if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='250ms'`); err != nil {
		return GPUMetricsSnapshot{}, err
	}
	reader := *store
	reader.gpuSnapshot = tx
	snapshot, err := reader.LoadGPUMetrics(ctx, clusterID)
	if err != nil {
		return GPUMetricsSnapshot{}, err
	}
	support := map[string][]domain.DCGMFieldEvidence{}
	summaries, err := reader.loadGPUHealthSummaries(ctx, clusterID, at, freshFor, support)
	if err != nil {
		return GPUMetricsSnapshot{}, err
	}
	attachGPUMetricsConditions(&snapshot, summaries)
	attachGPUMetricsValues(&snapshot, summaries, support)
	if err = tx.Commit(ctx); err != nil {
		return GPUMetricsSnapshot{}, err
	}
	return snapshot, nil
}

func rollbackGPUHealthSnapshot(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

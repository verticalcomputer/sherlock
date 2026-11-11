package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// PrometheusUploadSourceAllowed checks server-selected source ownership without
// trusting collector-reported source health or request payload scope.
func (s *CollectionStore) PrometheusUploadSourceAllowed(ctx context.Context, cluster domain.ClusterID, source domain.SourceID) (bool, error) {
	var allowed bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (
 SELECT 1 FROM sources WHERE cluster_id=$1 AND source_id=$2 AND kind='prometheus')`, cluster, source).Scan(&allowed)
	return allowed, err
}

// RecordPrometheusReport commits one scheduled slot without creating work or
// leases. The run ID identifies the slot and the existing idempotency column
// binds the exact accepted payload. Both are committed with the evidence.
func (s *CollectionStore) RecordPrometheusReport(ctx context.Context, report domain.PrometheusReport) (bool, error) {
	r := report.Result
	encoded, err := json.Marshal(report)
	if err != nil {
		return false, err
	}
	r.Task.IdempotencyKey = "prometheus-report-v1-" + domain.ChecksumSHA256(encoded).String()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", r.Task.RunID); err != nil {
		return false, err
	}
	var prior string
	err = tx.QueryRow(ctx, "SELECT idempotency_key FROM collection_runs WHERE run_id=$1", r.Task.RunID).Scan(&prior)
	if err == nil {
		return prior == r.Task.IdempotencyKey, nil
	}
	if err != pgx.ErrNoRows {
		return false, err
	}
	var sourceKind string
	if err := tx.QueryRow(ctx, "SELECT kind FROM sources WHERE cluster_id=$1 AND source_id=$2", r.Task.ClusterID, r.Task.SourceID).Scan(&sourceKind); err != nil {
		return false, err
	}
	if sourceKind != "prometheus" {
		return false, fmt.Errorf("scheduled collection source is not Prometheus")
	}
	if err := lockGoodputFactStream(ctx, tx, "inventory", r.Task.ClusterID, r.Task.SourceID, "EXPECTED"); err != nil {
		return false, err
	}
	if err := applyPrometheusReportCoverage(ctx, tx, &r); err != nil {
		return false, err
	}
	jobID, err := collectionResultJobID(ctx, tx, r.Task)
	if err != nil {
		return false, err
	}
	inserted, err := persistCollectionResultTx(ctx, tx, r, jobID, advancePrometheusSourceStatus)
	if err != nil || !inserted {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func applyPrometheusReportCoverage(ctx context.Context, tx pgx.Tx, r *domain.CollectionResult) error {
	rows, err := tx.Query(ctx, `SELECT e.entity_kind,e.stable_node_id,e.physical_gpu_uuid
 FROM goodput_inventory_revision_entities e WHERE e.cluster_id=$1 AND e.revision_id=(
 SELECT revision_id FROM goodput_inventory_revisions
 WHERE cluster_id=$1 AND source_id=$2 AND inventory_class='EXPECTED'
   AND effective_at<=$3 AND observed_at<=$3
 ORDER BY effective_at DESC,observed_at DESC,source_at DESC,revision_id DESC LIMIT 1)
 ORDER BY e.entity_kind,e.stable_node_id,e.physical_gpu_uuid LIMIT 2049`,
		r.Task.ClusterID, r.Task.SourceID, r.Task.ScheduledFor)
	if err != nil {
		return err
	}
	defer rows.Close()
	nodes := map[string]bool{}
	gpus := map[string]string{}
	for rows.Next() {
		var kind domain.EntityKind
		var node, gpu string
		if err := rows.Scan(&kind, &node, &gpu); err != nil {
			return err
		}
		switch kind {
		case domain.EntityNode:
			nodes[node] = true
		case domain.EntityGPU:
			if _, duplicate := gpus[gpu]; duplicate {
				return fmt.Errorf("ambiguous expected GPU ownership")
			}
			gpus[gpu] = node
		default:
			return fmt.Errorf("scheduled Prometheus profile requires physical GPUs")
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(nodes) == 0 || len(gpus) == 0 || len(gpus) > r.Task.MaxSeries || len(nodes) > len(gpus) {
		return fmt.Errorf("scheduled Prometheus profile requires bounded expected inventory")
	}
	nodeHasGPU := map[string]bool{}
	for gpu, node := range gpus {
		if !nodes[node] {
			return fmt.Errorf("expected GPU has no expected node")
		}
		nodeHasGPU[node] = true
		r.Coverage.ExpectedTargets = append(r.Coverage.ExpectedTargets, domain.EvidenceTarget{Kind: domain.EvidenceTargetGPU, ID: domain.EvidenceTargetID(gpu)})
	}
	if len(nodeHasGPU) != len(nodes) {
		return fmt.Errorf("expected node has no expected GPU")
	}
	for node := range nodes {
		r.Coverage.ExpectedTargets = append(r.Coverage.ExpectedTargets, domain.EvidenceTarget{Kind: domain.EvidenceTargetNode, ID: domain.EvidenceTargetID(node)})
	}
	fields := domain.PrometheusUploadFields(r.Task.Query)
	expected := len(gpus) * max(1, len(fields))
	if expected > r.Task.MaxSeries {
		return fmt.Errorf("scheduled Prometheus profile exceeds the bounded series limit")
	}
	r.Coverage.SeriesExpected = &expected
	r.Coverage.MetricFields = nil
	if r.Status == domain.ResultFailed {
		return nil
	}

	// Discard ambiguous or unexpected samples before writing observations and
	// projections. A matching count alone never proves coverage.
	accepted := make(map[string]domain.Observation, expected)
	seen := map[string]bool{}
	for _, o := range r.Observations {
		node, gpu, valid := domain.DCGMIdentity(o.Labels, r.Task)
		key := gpu
		if len(fields) > 0 {
			key += "\x00" + o.Metric
		}
		if seen[key] {
			delete(accepted, key)
			continue
		}
		seen[key] = true
		if !valid || gpus[gpu] != node || !scheduledMetric(r.Task.Query, o) {
			continue
		}
		o.ID = domain.ObservationID("prom-sample-" + domain.ChecksumSHA256([]byte(string(r.Task.RunID)+"\x00"+key)).String())
		labels := map[string]string{"Hostname": node, "UUID": gpu}
		// Retain the existing projection key where a numeric exporter index
		// was supplied. UUID and node remain the coverage identity.
		index := gpu
		for _, label := range o.Labels {
			if label.Name == "gpu" && len(label.Value) > 0 && len(label.Value) <= 8 &&
				strings.Trim(label.Value, "0123456789") == "" {
				index = label.Value
				labels["gpu"] = index
			}
		}
		o.Labels = domain.SortedLabels(labels)
		o.EntityKey = "node/" + node + "/gpu/" + index
		o.SourceReference = "prometheus:" + string(r.Task.Query)
		accepted[key] = o
	}
	indexUse := make(map[string]int, len(accepted))
	for _, o := range accepted {
		indexUse[o.EntityKey+"\x00"+o.Metric]++
	}
	r.Observations = make([]domain.Observation, 0, len(accepted))
	for _, o := range accepted {
		if indexUse[o.EntityKey+"\x00"+o.Metric] == 1 {
			r.Observations = append(r.Observations, o)
		}
	}
	// Derive support from the same observations that can be persisted. Missing
	// or ambiguous pairs remain unknown, even if other pairs in the run succeed.
	for _, gpu := range slices.Sorted(maps.Keys(gpus)) {
		for _, field := range fields {
			assessment := domain.DCGMFieldEvidence{
				NodeID: domain.StableNodeID(gpus[gpu]), GPU: domain.PhysicalGPUUUID(gpu),
				Metric: field.Name, State: "UNKNOWN", Reason: "missing_or_unavailable",
			}
			if o, ok := accepted[gpu+"\x00"+field.Name]; ok && indexUse[o.EntityKey+"\x00"+o.Metric] == 1 {
				assessment.State = "SUPPORTED"
				assessment.Reason = "fresh_sample"
			}
			r.Coverage.MetricFields = append(r.Coverage.MetricFields, assessment)
		}
	}
	if r.Status != domain.ResultSucceeded || !r.Coverage.Complete || len(r.Observations) != expected || r.Coverage.SeriesReturned != expected {
		r.Coverage.Complete = false
		r.Status = domain.ResultPartial
		r.Failures = []domain.CollectionFailure{{Code: domain.FailurePartialData, Message: "scheduled Prometheus coverage is incomplete"}}
	}
	return nil
}

func scheduledMetric(query domain.QueryKind, o domain.Observation) bool {
	switch query {
	case domain.QueryGPUIdentity:
		return o.Kind == "gpu_identity" && o.Metric == string(query) && o.Unit == "count" && o.Value == 1
	case domain.QueryGPUUtilization:
		return o.Kind == "gpu_utilization" && o.Metric == "DCGM_FI_DEV_GPU_UTIL" && o.Unit == "percent" && o.Value >= 0 && o.Value <= 100
	case domain.QueryGPUXID:
		return o.Kind == "gpu_xid" && o.Metric == "DCGM_FI_DEV_XID_ERRORS" && o.Unit == "xid_code" &&
			o.Value >= 0 && o.Value <= math.MaxUint32 && math.Trunc(o.Value) == o.Value
	}
	kind := map[domain.QueryKind]string{
		domain.QueryGPUTemperature: "gpu_temperature", domain.QueryGPUPower: "gpu_power",
		domain.QueryGPUMemory: "gpu_memory", domain.QueryGPUECC: "gpu_ecc",
	}[query]
	if kind == "" || o.Kind != kind {
		return false
	}
	for _, field := range domain.PrometheusUploadFields(query) {
		if o.Metric == field.Name && o.Unit == field.Unit {
			// DCGM reserves large numeric sentinels for unsupported fields.
			// The finite bounds also exclude NaN and infinities.
			minimum := 0.0
			if query == domain.QueryGPUTemperature {
				minimum = -273.15
			}
			return o.Value >= minimum && o.Value < 140737488355328 &&
				(field.Double || math.Trunc(o.Value) == o.Value)
		}
	}
	return false
}

// A delayed spool replay can fill historical coverage, but cannot replace a
// newer source health assessment or move its success timestamp backward.
func advancePrometheusSourceStatus(ctx context.Context, tx pgx.Tx, r domain.CollectionResult, responded bool) error {
	success := responded && r.Status != domain.ResultFailed
	availability, failure := "UNAVAILABLE", domain.FailureInternal
	if responded {
		availability = "AVAILABLE"
	}
	if len(r.Failures) != 0 {
		failure = r.Failures[0].Code
	}
	_, err := tx.Exec(ctx, `UPDATE sources SET
 availability=CASE WHEN last_attempt_at IS NULL OR last_attempt_at <= $3 THEN $4 ELSE availability END,
 last_failure_code=CASE WHEN last_attempt_at IS NULL OR last_attempt_at <= $3
  THEN CASE WHEN $5 THEN NULL ELSE $6 END ELSE last_failure_code END,
 last_success_at=CASE WHEN $5 THEN greatest(last_success_at,$3) ELSE last_success_at END,
 last_attempt_at=greatest(last_attempt_at,$3)
 WHERE cluster_id=$1 AND source_id=$2`, r.Task.ClusterID, r.Task.SourceID, r.CompletedAt.UTC(), availability, success, failure)
	return err
}

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
)

var errMonitoringHistoryTruncated = errors.New("monitoring history prefix unavailable")

// Input comes only from immutable committed rows with proven schedule lineage.
// Neither source availability nor collector heartbeats are collection evidence.
func loadMonitoringInput(ctx context.Context, tx pgx.Tx, policy monitoring.Policy, state monitoring.State, authority monitoringAuthority, at time.Time, history *MonitoringHistoryCoverage) (monitoring.Input, []MonitoringEvidenceSnapshot, error) {
	input := monitoring.Input{At: at, AuthorityValid: true}
	truncated := false
	start := policy.EnrolledAt.Add(-time.Duration(policy.FreshForSeconds) * time.Second)
	if policy.Rule != monitoring.RuleTelemetryLoss && state.SourceCursor != nil && state.SourceCursor.CompletedAt.After(start) {
		start = state.SourceCursor.CompletedAt
	}
	if state.RunCursor != nil && state.RunCursor.CompletedAt.After(start) {
		start = state.RunCursor.CompletedAt
	}
	// Read the newest256 exact attempts plus an overflow sentinel. A missing
	// prefix resets confirmation sequences and persists a separate history gap;
	// latest failed/unsupported attempts remain present as recovery barriers.
	rows, err := tx.Query(ctx, `SELECT r.run_id,r.scheduled_for,r.completed_at,r.status,r.coverage_complete,r.metric_fields,
 coalesce(j.configuration_revision,-1),coalesce(j.job_id,''),coalesce(j.node_filter,''),
 coalesce(o.revision,-1),coalesce(o.operation,''),coalesce(e.nodes,'[]'::jsonb)
 FROM collection_runs r LEFT JOIN collection_run_jobs j ON j.run_id=r.run_id AND j.cluster_id=r.cluster_id AND j.source_id=r.source_id
 LEFT JOIN collector_work_items w ON w.run_id=r.run_id AND w.cluster_id=r.cluster_id AND w.source_id=r.source_id
 LEFT JOIN durable_schedule_occurrences o ON o.work_id=w.work_id AND o.cluster_id=w.cluster_id AND o.source_id=w.source_id
 LEFT JOIN durable_schedule_executions e ON e.cluster_id=o.cluster_id AND e.source_id=o.source_id AND e.operation=o.operation AND e.revision=o.revision
 WHERE r.cluster_id=$1 AND r.source_id=$2 AND r.query_kind IN ($3,$4) AND r.range_start IS NULL AND r.completed_at>=$5
 AND (($6='legacy' AND j.job_id=$7 AND j.configuration_revision=$8 AND j.node_filter='' AND j.query_kind=$3) OR ($6='durable' AND o.operation=$4 AND o.revision=$9 AND w.query_kind=$3 AND w.typed_plan IS NULL AND w.node_filter='' AND w.status IN ('SUCCEEDED','FAILED') AND EXISTS(SELECT 1 FROM collector_result_ingestions i WHERE i.work_id=w.work_id AND i.run_id=r.run_id AND i.collector_id=e.collector_id)))
 ORDER BY r.completed_at DESC,r.run_id DESC LIMIT 257`, policy.ClusterID, policy.SourceID, authority.query, policy.Binding.Operation, start, authority.mode, authority.jobID, authority.configurationRevision, policy.Binding.ScheduleRevision)
	if err != nil {
		return input, nil, err
	}
	runFields := map[domain.RunID][]domain.DCGMFieldEvidence{}
	ids := []string{}
	for rows.Next() {
		var run monitoring.RunEvidence
		var scheduled time.Time
		var fields, nodes []byte
		var config, revision int64
		var job, node, op string
		if err = rows.Scan(&run.RunID, &scheduled, &run.CompletedAt, &run.Status, &run.CoverageComplete, &fields, &config, &job, &node, &revision, &op, &nodes); err != nil {
			rows.Close()
			return input, nil, err
		}
		run.ClusterID = policy.ClusterID
		run.SourceID = policy.SourceID
		run.Binding = policy.Binding
		// Both installed Prometheus paths use the original v1 result contract:
		// exact legacy job binding, or durable occurrence with typed_plan NULL.
		run.LegacySourceClockTolerance = true
		if authority.mode == domain.SchedulingDurable {
			var actual domain.CollectionScope
			if err = json.Unmarshal(nodes, &actual.Nodes); err != nil {
				rows.Close()
				return input, nil, err
			}
			actual = monitoringScope(actual)
			if monitoringScopeKey(actual) != monitoringScopeKey(policy.Binding.Scope) {
				continue
			}
			run.Binding.Scope = actual
		}
		if len(fields) > 0 && string(fields) != "null" {
			var parsed []domain.DCGMFieldEvidence
			if err = json.Unmarshal(fields, &parsed); err != nil {
				rows.Close()
				return input, nil, err
			}
			runFields[run.RunID] = parsed
		}
		// Historical expected authority must have governed this exact occurrence,
		// rather than being fabricated from today's enrollment document.
		_ = scheduled
		input.Runs = append(input.Runs, run)
		ids = append(ids, string(run.RunID))
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return input, nil, err
	}
	if len(input.Runs) > 256 {
		input.Runs = input.Runs[:256]
		ids = ids[:256]
		truncated = true
		*history = MonitoringHistoryCoverage{MeasuredAt: at, From: start, Through: input.Runs[len(input.Runs)-1].CompletedAt, OmittedAttemptsLowerBound: 1}
	}
	if len(ids) == 0 {
		return input, nil, nil
	}
	if policy.Binding.InventoryRevisionID != "" {
		for i := range input.Runs {
			run := &input.Runs[i]
			var governing string
			var inventorySourceAt time.Time
			err = tx.QueryRow(ctx, `SELECT i.revision_id,i.source_at FROM goodput_inventory_revisions i JOIN collection_runs r ON r.run_id=$3 AND r.cluster_id=i.cluster_id AND r.source_id=i.source_id WHERE i.cluster_id=$1 AND i.source_id=$2 AND i.inventory_class='EXPECTED' AND i.effective_at<=r.scheduled_for AND i.observed_at<=r.completed_at ORDER BY i.effective_at DESC,i.observed_at DESC,i.source_at DESC,i.revision_id DESC LIMIT 1`, policy.ClusterID, policy.SourceID, run.RunID).Scan(&governing, &inventorySourceAt)
			if err == pgx.ErrNoRows || err == nil && (governing != policy.Binding.InventoryRevisionID || inventorySourceAt.After(run.CompletedAt)) {
				run.Binding.InventoryRevisionID = ""
				continue
			}
			if err != nil {
				return input, nil, err
			}
		}
	}
	// Physical history only needs the enrolled exact sensor; telemetry validates
	// actual observations for the reviewed operation, never series_returned alone.
	metric := policy.Metric
	identity, _ := domain.ResolveGPUObservationIdentity(policy.ClusterID, policy.SourceID, domain.Observation{ClusterID: policy.ClusterID, SourceID: policy.SourceID, EntityKey: policy.EntityKey})
	uuidLabel, _ := json.Marshal([]domain.Label{{Name: "UUID", Value: string(identity.PhysicalGPUUUID)}})
	lowerUUIDLabel, _ := json.Marshal([]domain.Label{{Name: "uuid", Value: string(identity.PhysicalGPUUUID)}})
	columns := `observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,observed_at,collected_at,source_reference,metric_semantics`
	if policy.Rule == monitoring.RuleTelemetryLoss {
		// Contact needs a validated fresh witness, not a full fleet scan. Read at
		// most33 fresh operation candidates per run. If none validates at the cap,
		// preserve explicit history uncertainty instead of claiming full coverage.
		metrics := []string{}
		for _, f := range domain.DCGMFields(authority.query) {
			metrics = append(metrics, f.Name)
		}
		switch authority.query {
		case domain.QueryGPUIdentity:
			metrics = append(metrics, string(domain.QueryGPUIdentity))
		case domain.QueryGPUUtilization:
			metrics = append(metrics, "DCGM_FI_DEV_GPU_UTIL")
		case domain.QueryGPUXID:
			metrics = append(metrics, "DCGM_FI_DEV_XID_ERRORS")
		}
		if authority.query == domain.QueryGPUECC {
			metrics = append(metrics, "DCGM_FI_DEV_ROW_REMAP_FAILED")
		}
		rows, err = tx.Query(ctx, `SELECT `+columns+` FROM unnest($3::text[]) id CROSS JOIN LATERAL(SELECT * FROM observations WHERE cluster_id=$1 AND source_id=$2 AND run_id=id AND metric=ANY($6::text[]) AND observed_at<=$4 AND collected_at<=$4 AND observed_at>$4::timestamptz-make_interval(secs=>$5) AND collected_at>$4::timestamptz-make_interval(secs=>$5) ORDER BY observed_at DESC,observation_id LIMIT 33) witness ORDER BY observed_at,observation_id`, policy.ClusterID, policy.SourceID, ids, at, float64(policy.FreshForSeconds), metrics)
	} else {
		rows, err = tx.Query(ctx, `SELECT `+columns+` FROM observations WHERE cluster_id=$1 AND source_id=$2 AND run_id=ANY($3::text[]) AND (metric=$4 OR $4='DCGM_FI_DEV_ROW_REMAP_FAILURE' AND metric='DCGM_FI_DEV_ROW_REMAP_FAILED') AND (entity_key=$5 OR entity_key=$6 OR labels @> $7::jsonb OR labels @> $8::jsonb) ORDER BY observed_at DESC,observation_id DESC LIMIT 257`, policy.ClusterID, policy.SourceID, ids, metric, policy.EntityKey, "node/"+string(identity.NodeID)+"/gpu/"+string(identity.PhysicalGPUUUID), uuidLabel, lowerUUIDLabel)
	}
	if err != nil {
		return input, nil, err
	}
	samples := []monitoring.Sample{}
	scanned := 0
	witnessCandidates := map[domain.RunID]int{}
	for rows.Next() {
		scanned++
		if policy.Rule != monitoring.RuleTelemetryLoss && scanned > 256 {
			truncated = true
			if history.MeasuredAt.IsZero() {
				*history = MonitoringHistoryCoverage{MeasuredAt: at, From: start, Through: at}
			}
			history.OmittedObservationsLowerBound = 1
			break
		}
		var sample monitoring.Sample
		var labels, semantics []byte
		o := &sample.Observation
		if err = rows.Scan(&o.ID, &sample.RunID, &o.ClusterID, &o.SourceID, &o.SchemaVersion, &o.Kind, &o.EntityKey, &o.Metric, &labels, &o.Value, &o.Unit, &o.ObservedAt, &o.CollectedAt, &o.SourceReference, &semantics); err != nil {
			rows.Close()
			return input, nil, err
		}
		witnessCandidates[sample.RunID]++
		if string(labels) == "{}" || string(labels) == "null" {
			labels = []byte("[]")
		}
		if err = json.Unmarshal(labels, &o.Labels); err != nil {
			rows.Close()
			return input, nil, err
		}
		if len(semantics) > 0 && string(semantics) != "null" {
			if err = json.Unmarshal(semantics, &o.Semantics); err != nil {
				rows.Close()
				return input, nil, err
			}
		}
		identity, ok := domain.ResolveGPUObservationIdentity(policy.ClusterID, policy.SourceID, *o)
		if !ok || !identity.Canonical {
			continue
		}
		if len(policy.Binding.Scope.Nodes) > 0 {
			found := false
			for _, n := range policy.Binding.Scope.Nodes {
				if n == identity.NodeID {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		if policy.Rule != monitoring.RuleTelemetryLoss && identity.EntityKey != policy.EntityKey {
			continue
		}
		o.EntityKey = identity.EntityKey
		for i := range input.Runs {
			run := &input.Runs[i]
			if run.RunID != sample.RunID {
				continue
			}
			sample.CollectionCompletedAt = run.CompletedAt
			sample.Status = run.Status
			sample.CoverageComplete = run.CoverageComplete
			state := monitoringFieldState(runFields[run.RunID], identity, o.Metric)
			sample.Supported = state == "SUPPORTED"
			// Legacy base metrics have no expanded field assessment; admit their actual
			// scoped identity/value under the reviewed sensor registry only.
			if policy.Rule == monitoring.RuleTelemetryLoss && (authority.query == domain.QueryGPUIdentity || authority.query == domain.QueryGPUUtilization || authority.query == domain.QueryGPUXID) {
				sample.Supported = true
			}
			if sample.Supported && monitoringValidOperationObservation(authority.query, *o, at, run.CompletedAt, time.Duration(policy.FreshForSeconds)*time.Second, run.LegacySourceClockTolerance) {
				run.Count++
			}
		}
		if policy.Rule != monitoring.RuleTelemetryLoss {
			samples = append(samples, sample)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return input, nil, err
	}
	if len(samples) > 256 {
		return input, nil, fmt.Errorf("monitoring observation input exceeds bound")
	}
	for i := range input.Runs {
		run := &input.Runs[i]
		if policy.Rule != monitoring.RuleTelemetryLoss {
			identity, _ := domain.ResolveGPUObservationIdentity(policy.ClusterID, policy.SourceID, domain.Observation{ClusterID: policy.ClusterID, SourceID: policy.SourceID, EntityKey: policy.EntityKey})
			run.FieldState = monitoringFieldState(runFields[run.RunID], identity, policy.Metric)
		}
	}
	if policy.Rule == monitoring.RuleTelemetryLoss {
		for _, run := range input.Runs {
			if run.Count == 0 && witnessCandidates[run.RunID] >= 33 && run.Status == domain.ResultSucceeded {
				truncated = true
				if history.MeasuredAt.IsZero() {
					*history = MonitoringHistoryCoverage{MeasuredAt: at, From: start, Through: at}
				}
				history.OmittedObservationsLowerBound++
			}
		}
	}
	input.Samples = samples
	cache := []MonitoringEvidenceSnapshot{}
	for _, run := range input.Runs {
		ref := monitoring.EvidenceRef{RunID: run.RunID, CompletedAt: run.CompletedAt}
		cache = append(cache, MonitoringEvidenceSnapshot{Reference: ref, Status: run.Status, Supported: run.Count > 0, CoverageComplete: run.CoverageComplete, QualifyingObservationsLowerBound: run.Count, LegacySourceClockTolerance: run.LegacySourceClockTolerance})
	}
	for _, s := range samples {
		legacyTolerance := false
		for _, r := range input.Runs {
			if r.RunID == s.RunID {
				legacyTolerance = r.LegacySourceClockTolerance
			}
		}
		sourceContract := ""
		if s.Observation.SourceReference == domain.DCGMSourceReference(authority.query) {
			sourceContract = s.Observation.SourceReference
		}
		v := s.Observation.Value
		ref := monitoring.EvidenceRef{ObservationID: s.Observation.ID, RunID: s.RunID, ObservedAt: s.Observation.ObservedAt, CollectedAt: s.Observation.CollectedAt, CompletedAt: s.CollectionCompletedAt}
		cache = append(cache, MonitoringEvidenceSnapshot{Reference: ref, LegacySourceClockTolerance: legacyTolerance, SourceClockContract: sourceContract, Metric: s.Observation.Metric, Value: &v, Unit: s.Observation.Unit, Semantics: s.Observation.Semantics, Status: s.Status, Supported: s.Supported, CoverageComplete: s.CoverageComplete})
	}
	if truncated {
		return input, cache, errMonitoringHistoryTruncated
	}
	return input, cache, nil
}
func monitoringFieldState(fields []domain.DCGMFieldEvidence, id domain.GPUObservationIdentity, metric string) string {
	if metric == "DCGM_FI_DEV_ROW_REMAP_FAILED" {
		metric = "DCGM_FI_DEV_ROW_REMAP_FAILURE"
	}
	state := "UNKNOWN"
	found := false
	for _, f := range fields {
		if f.NodeID != id.NodeID || f.GPU != id.PhysicalGPUUUID || !(f.Metric == metric || metric == "DCGM_FI_DEV_ROW_REMAP_FAILURE" && f.Metric == "DCGM_FI_DEV_ROW_REMAP_FAILED") {
			continue
		}
		if found && state != f.State {
			return "UNKNOWN"
		}
		state = f.State
		found = true
	}
	return state
}
func monitoringValidOperationObservation(query domain.QueryKind, o domain.Observation, at, completed time.Time, freshFor time.Duration, legacyTolerance bool) bool {
	if o.ObservedAt.IsZero() || o.CollectedAt.IsZero() || o.ObservedAt.After(at) || o.CollectedAt.After(at) || completed.After(at) || at.Sub(o.ObservedAt) >= freshFor || at.Sub(o.CollectedAt) >= freshFor {
		return false
	}
	if !o.CollectedAt.Equal(completed) {
		return false
	}
	tolerance := time.Duration(0)
	if legacyTolerance && o.SourceReference == domain.DCGMSourceReference(query) {
		tolerance = time.Second
	}
	if o.ObservedAt.After(o.CollectedAt.Add(tolerance)) {
		return false
	}
	if query == domain.QueryGPUIdentity {
		return o.Metric == string(domain.QueryGPUIdentity) && o.Unit == "count" && o.Value >= 1 && o.Value <= 10000
	}
	owned := query == domain.QueryGPUUtilization && o.Metric == "DCGM_FI_DEV_GPU_UTIL" || query == domain.QueryGPUXID && o.Metric == "DCGM_FI_DEV_XID_ERRORS"
	for _, field := range domain.DCGMFields(query) {
		owned = owned || field.Name == o.Metric || field.Name == "DCGM_FI_DEV_ROW_REMAP_FAILURE" && o.Metric == "DCGM_FI_DEV_ROW_REMAP_FAILED"
	}
	return owned && domain.ValidGPUHealthObservation(o)
}

func monitoringStateCache(state monitoring.State, previous, current []MonitoringEvidenceSnapshot) ([]MonitoringEvidenceSnapshot, error) {
	index := map[string]MonitoringEvidenceSnapshot{}
	for _, s := range append(previous, current...) {
		index[monitoringRefKey(s.Reference)] = s
	}
	refs := append(append([]monitoring.EvidenceRef{}, state.Pending...), state.RecoveryPending...)
	for _, ref := range []*monitoring.EvidenceRef{state.FirstQualifying, state.LastQualifying, state.SourceCursor, state.RunCursor} {
		if ref != nil {
			refs = append(refs, *ref)
		}
	}
	keys := map[string]bool{}
	out := []MonitoringEvidenceSnapshot{}
	for _, ref := range refs {
		key := monitoringRefKey(ref)
		if keys[key] {
			continue
		}
		s, ok := index[key]
		if !ok || !monitoringRefsEqual(s.Reference, ref) {
			return nil, fmt.Errorf("monitoring state evidence unavailable")
		}
		keys[key] = true
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return monitoringRefKey(out[i].Reference) < monitoringRefKey(out[j].Reference) })
	body, err := json.Marshal(out)
	if err != nil || len(out) > 64 || len(body) > 131072 {
		return nil, fmt.Errorf("monitoring state evidence exceeds bound")
	}
	return out, nil
}

// Reinsert only an already-admitted cursor fact when a later immutable alias
// arrives at the same source time after raw retention. This is preserved
// evidence, not a manufactured observation or an additional confirmation.
func monitoringCursorTieInput(policy monitoring.Policy, state monitoring.State, input *monitoring.Input, cache []MonitoringEvidenceSnapshot) error {
	if policy.Rule == monitoring.RuleTelemetryLoss || state.SourceCursor == nil {
		return nil
	}
	matchingTime := false
	for _, sample := range input.Samples {
		if sample.Observation.ID == state.SourceCursor.ObservationID {
			return nil
		}
		matchingTime = matchingTime || sample.Observation.ObservedAt.Equal(state.SourceCursor.ObservedAt)
	}
	if !matchingTime {
		return nil
	}
	for _, snapshot := range cache {
		if !monitoringRefsEqual(snapshot.Reference, *state.SourceCursor) || snapshot.Value == nil {
			continue
		}
		ref := snapshot.Reference
		sample := monitoring.Sample{Observation: domain.Observation{ID: ref.ObservationID, SchemaVersion: 1, ClusterID: policy.ClusterID, SourceID: policy.SourceID, EntityKey: policy.EntityKey, Metric: snapshot.Metric, Value: *snapshot.Value, Unit: snapshot.Unit, Semantics: snapshot.Semantics, SourceReference: snapshot.SourceClockContract, ObservedAt: ref.ObservedAt, CollectedAt: ref.CollectedAt}, RunID: ref.RunID, CollectionCompletedAt: ref.CompletedAt, Status: snapshot.Status, Supported: snapshot.Supported, CoverageComplete: snapshot.CoverageComplete}
		runFound := false
		for i := range input.Runs {
			run := &input.Runs[i]
			if run.RunID == ref.RunID {
				runFound = true
				if run.CompletedAt.Equal(ref.CompletedAt) && run.Status == snapshot.Status && run.CoverageComplete == snapshot.CoverageComplete && run.FieldState == "SUPPORTED" && snapshot.Supported {
					run.Count = max(run.Count, 1)
				}
			}
		}
		if !runFound {
			input.Runs = append(input.Runs, monitoring.RunEvidence{RunID: ref.RunID, ClusterID: policy.ClusterID, SourceID: policy.SourceID, Binding: policy.Binding, CompletedAt: ref.CompletedAt, Status: snapshot.Status, CoverageComplete: snapshot.CoverageComplete, Count: 1, FieldState: "SUPPORTED", LegacySourceClockTolerance: snapshot.LegacySourceClockTolerance})
		}
		input.Samples = append(input.Samples, sample)
		if len(input.Runs) > monitoring.MaxInputEvidence || len(input.Samples) > monitoring.MaxInputEvidence {
			return fmt.Errorf("monitoring cursor tie exceeds evidence bound")
		}
		return nil
	}
	return fmt.Errorf("monitoring cursor tie evidence unavailable")
}

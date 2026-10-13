package adminview

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type gpuMetricsQueryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (store *PostgresStore) gpuMetricsQuerier() gpuMetricsQueryer {
	if store.gpuSnapshot != nil {
		return store.gpuSnapshot
	}
	return store.pool
}

// Every statement below is bounded and scoped by cluster_id, and the inventory
// revision is additionally scoped by source_id, so one cluster's projection can
// never read another cluster's evidence.
const (
	gpuMetricsEntityLimit     = 4097
	gpuMetricsProjectionLimit = 20001
	gpuMetricsScheduleLimit   = 512
)

type gpuMetricsCell struct{ node, gpu, metric string }

type gpuMetricsRunRow struct {
	run         GPUMetricsRun
	assessments []domain.DCGMFieldEvidence
}

// LoadGPUMetrics reads the committed expanded-DCGM evidence for one cluster.
// It assigns only the states that do not depend on the evaluation instant;
// freshness and staleness are derived afterwards by the service.
func (store *PostgresStore) LoadGPUMetrics(ctx context.Context, clusterID string) (GPUMetricsSnapshot, error) {
	snapshot := GPUMetricsSnapshot{
		ClusterID: clusterID, Fields: reviewedGPUMetricsFields(),
		OtherSources: []GPUMetricsOtherSource{},
	}
	sources, sourcesTruncated, err := store.loadGPUMetricsSources(ctx, clusterID)
	if err != nil {
		return GPUMetricsSnapshot{}, err
	}
	snapshot.SourcesTruncated = sourcesTruncated
	if len(sources) == 0 {
		snapshot.Sources = []GPUMetricsSource{}
		snapshot.GPUs = []GPUMetricsRow{}
		snapshot.Inventory = emptyGPUMetricsInventory()
		return snapshot, nil
	}
	ids := make([]string, 0, len(sources))
	for _, source := range sources {
		ids = append(ids, source.SourceID)
	}
	schedules, err := store.loadGPUMetricsSchedules(ctx, clusterID, ids)
	if err != nil {
		return GPUMetricsSnapshot{}, err
	}
	runs, err := store.loadGPUMetricsRuns(ctx, clusterID, ids)
	if err != nil {
		return GPUMetricsSnapshot{}, err
	}
	revisions, err := store.loadGPUMetricsRevisions(ctx, clusterID, ids)
	if err != nil {
		return GPUMetricsSnapshot{}, err
	}
	for index := range sources {
		source := &sources[index]
		for _, query := range domain.ExpandedDCGMQueries() {
			source.Operations = append(source.Operations,
				buildGPUMetricsOperation(query, schedules[source.SourceID+"\x00"+string(query)], runs[source.SourceID+"\x00"+string(query)]))
		}
	}
	primary := primaryGPUMetricsSource(sources, revisions)
	sources[primary].Primary = true
	snapshot.Sources = sources

	sourceID := sources[primary].SourceID
	revision := revisions[sourceID]
	inventory := emptyGPUMetricsInventory()
	inventory.SourceID = sourceID
	expectedGPUs := map[gpuMetricsEntity]bool{}
	expectedNodes := map[string]bool{}
	migs := []gpuMetricsEntityRow{}
	if revision != nil {
		inventory.HasExpectedRevision = true
		inventory.RevisionID = revision.RevisionID
		inventory.EffectiveAt, inventory.SourceAt, inventory.ObservedAt = revision.EffectiveAt, revision.SourceAt, revision.ObservedAt
		entities, truncated, err := store.loadGPUMetricsEntities(ctx, clusterID, revision.RevisionID)
		if err != nil {
			return GPUMetricsSnapshot{}, err
		}
		inventory.Truncated = inventory.Truncated || truncated
		for _, entity := range entities {
			switch entity.kind {
			case string(domain.EntityNode):
				expectedNodes[entity.node] = true
			case string(domain.EntityGPU):
				expectedNodes[entity.node] = true
				expectedGPUs[gpuMetricsEntity{entity.node, entity.gpu}] = true
			case string(domain.EntityMIG):
				inventory.MIGCount++
				migs = append(migs, entity)
			}
		}
		inventory.ExpectedNodes, inventory.ExpectedGPUs = len(expectedNodes), len(expectedGPUs)
	}
	observedGPUs, observedNodes, truncated, err := store.loadGPUMetricsObserved(ctx, clusterID, sourceID)
	if err != nil {
		return GPUMetricsSnapshot{}, err
	}
	inventory.Truncated = inventory.Truncated || truncated
	inventory.ObservedNodes, inventory.ObservedGPUs = len(observedNodes), len(observedGPUs)
	// The service, not this query, decides coverage: the target cache is never
	// pruned, so only the observation instant can distinguish a scraped target
	// from a record that merely survives.
	inventory.Observations = gpuMetricsObservations(expectedNodes, expectedGPUs, observedNodes, observedGPUs)

	others, err := store.loadGPUMetricsOtherSources(ctx, clusterID, sources, sourceID)
	if err != nil {
		return GPUMetricsSnapshot{}, err
	}
	snapshot.OtherSources = others

	projections, truncated, err := store.loadGPUMetricsProjections(ctx, clusterID, sourceID, runs)
	if err != nil {
		return GPUMetricsSnapshot{}, err
	}
	snapshot.Truncated = snapshot.Truncated || truncated
	assessments := map[gpuMetricsCell]string{}
	assessed := map[domain.QueryKind]string{}
	for _, query := range domain.ExpandedDCGMQueries() {
		row, ok := runs[sourceID+"\x00"+string(query)]
		if !ok {
			continue
		}
		assessed[query] = row.run.RunID
		if !gpuMetricsRunYieldsEvidence(row.run.Status) {
			continue
		}
		for _, evidence := range row.assessments {
			assessments[gpuMetricsCell{string(evidence.NodeID), string(evidence.GPU), evidence.Metric}] = evidence.State
		}
	}
	snapshot.GPUs, truncated = buildGPUMetricsRows(sourceID, expectedGPUs, migs, observedGPUs, assessments, assessed, projections)
	snapshot.Truncated = snapshot.Truncated || truncated
	snapshot.Inventory = inventory
	return snapshot, nil
}

type gpuMetricsEntity struct{ node, gpu string }

// gpuMetricsRowKey identifies a projected row. A non-empty MIG identity makes
// the row an expected MIG entity rather than a physical GPU.
type gpuMetricsRowKey struct{ node, gpu, mig string }

type gpuMetricsRevision struct {
	RevisionID                        string
	EffectiveAt, SourceAt, ObservedAt *time.Time
}

type gpuMetricsSchedule struct {
	Enabled         bool
	Mode            string
	IntervalSeconds int64
	Revision        int64
}

type gpuMetricsEntityRow struct{ kind, node, gpu, mig string }

type gpuMetricsProjection struct {
	runID         string
	conflicting   bool
	value         float64
	unit          string
	semantics     string
	observedAt    time.Time
	resetObserved bool
}

func emptyGPUMetricsInventory() GPUMetricsInventory {
	return GPUMetricsInventory{
		ExpectedNotObserved: []GPUMetricsEntityRef{},
		ObservedNotExpected: []GPUMetricsEntityRef{},
	}
}

func reviewedGPUMetricsFields() []GPUMetricsFieldRef {
	fields := []GPUMetricsFieldRef{}
	for _, query := range domain.ExpandedDCGMQueries() {
		operation, _ := domain.CollectionOperationForQuery(query)
		for _, field := range domain.DCGMFields(query) {
			fields = append(fields, GPUMetricsFieldRef{
				Name: field.Name, Unit: field.Unit, Semantics: field.Kind, Operation: string(operation.ID),
			})
		}
	}
	return fields
}

func reviewedGPUMetricsFieldNames() []string {
	names := []string{}
	for _, query := range domain.ExpandedDCGMQueries() {
		for _, field := range domain.DCGMFields(query) {
			names = append(names, field.Name)
		}
	}
	return names
}

// loadGPUMetricsSources reads one more source than the bound so an over-bound
// cluster can be stated as truncated instead of appearing complete.
func (store *PostgresStore) loadGPUMetricsSources(ctx context.Context, clusterID string) ([]GPUMetricsSource, bool, error) {
	rows, err := store.gpuMetricsQuerier().Query(ctx, `
		SELECT source_id, coalesce(display_name,'')
		FROM sources WHERE cluster_id=$1 AND kind='prometheus'
		ORDER BY source_id LIMIT $2`, clusterID, GPUMetricsSourceLimit+1)
	if err != nil {
		return nil, false, fmt.Errorf("list GPU metric sources: %w", err)
	}
	defer rows.Close()
	sources := []GPUMetricsSource{}
	for rows.Next() {
		var source GPUMetricsSource
		if err := rows.Scan(&source.SourceID, &source.DisplayName); err != nil {
			return nil, false, fmt.Errorf("scan GPU metric source: %w", err)
		}
		sources = append(sources, source)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate GPU metric sources: %w", err)
	}
	if len(sources) > GPUMetricsSourceLimit {
		return sources[:GPUMetricsSourceLimit], true, nil
	}
	return sources, false, nil
}

func (store *PostgresStore) loadGPUMetricsSchedules(ctx context.Context, clusterID string, ids []string) (map[string]*gpuMetricsSchedule, error) {
	operations := make([]string, 0, len(domain.ExpandedDCGMQueries()))
	for _, query := range domain.ExpandedDCGMQueries() {
		operation, _ := domain.CollectionOperationForQuery(query)
		operations = append(operations, string(operation.ID))
	}
	rows, err := store.gpuMetricsQuerier().Query(ctx, `
		SELECT source_id, operation, enabled, mode, interval_seconds, revision
		FROM desired_schedules
		WHERE cluster_id=$1 AND source_id=ANY($2::text[]) AND operation=ANY($3::text[])
		ORDER BY source_id, operation LIMIT $4`, clusterID, ids, operations, gpuMetricsScheduleLimit)
	if err != nil {
		return nil, fmt.Errorf("load GPU metric schedules: %w", err)
	}
	defer rows.Close()
	schedules := map[string]*gpuMetricsSchedule{}
	for rows.Next() {
		var sourceID, operation string
		schedule := &gpuMetricsSchedule{}
		if err := rows.Scan(&sourceID, &operation, &schedule.Enabled, &schedule.Mode, &schedule.IntervalSeconds, &schedule.Revision); err != nil {
			return nil, fmt.Errorf("scan GPU metric schedule: %w", err)
		}
		reviewed, ok := domain.ReviewedCollectionOperation(domain.CollectionOperationID(operation))
		if !ok {
			continue
		}
		schedules[sourceID+"\x00"+string(reviewed.Query)] = schedule
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate GPU metric schedules: %w", err)
	}
	return schedules, nil
}

// loadGPUMetricsRuns reads the newest committed instant run per source and
// query kind. Range runs are excluded: this packet's assessments are defined
// for instant collection only.
func (store *PostgresStore) loadGPUMetricsRuns(ctx context.Context, clusterID string, ids []string) (map[string]gpuMetricsRunRow, error) {
	kinds := make([]string, 0, 4)
	for _, query := range domain.ExpandedDCGMQueries() {
		kinds = append(kinds, string(query))
	}
	rows, err := store.gpuMetricsQuerier().Query(ctx, `
		SELECT DISTINCT ON (source_id, query_kind)
			source_id, query_kind, run_id, status, scheduled_for, completed_at, coverage_complete, metric_fields
		FROM collection_runs
		WHERE cluster_id=$1 AND source_id=ANY($2::text[]) AND query_kind=ANY($3::text[]) AND range_start IS NULL
		ORDER BY source_id, query_kind, completed_at DESC, run_id DESC
		LIMIT $4`, clusterID, ids, kinds, GPUMetricsSourceLimit*len(kinds))
	if err != nil {
		return nil, fmt.Errorf("load GPU metric runs: %w", err)
	}
	defer rows.Close()
	runs := map[string]gpuMetricsRunRow{}
	for rows.Next() {
		var sourceID, queryKind string
		var encoded []byte
		var row gpuMetricsRunRow
		if err := rows.Scan(&sourceID, &queryKind, &row.run.RunID, &row.run.Status,
			&row.run.ScheduledFor, &row.run.CompletedAt, &row.run.CoverageComplete, &encoded); err != nil {
			return nil, fmt.Errorf("scan GPU metric run: %w", err)
		}
		row.run.ScheduledFor, row.run.CompletedAt = row.run.ScheduledFor.UTC(), row.run.CompletedAt.UTC()
		if len(encoded) > 0 {
			if err := json.Unmarshal(encoded, &row.assessments); err != nil {
				return nil, fmt.Errorf("decode GPU metric field assessments: %w", err)
			}
		}
		runs[sourceID+"\x00"+queryKind] = row
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate GPU metric runs: %w", err)
	}
	return runs, nil
}

func (store *PostgresStore) loadGPUMetricsRevisions(ctx context.Context, clusterID string, ids []string) (map[string]*gpuMetricsRevision, error) {
	rows, err := store.gpuMetricsQuerier().Query(ctx, `
		SELECT DISTINCT ON (source_id) source_id, revision_id, effective_at, source_at, observed_at
		FROM goodput_inventory_revisions
		WHERE cluster_id=$1 AND source_id=ANY($2::text[]) AND inventory_class='EXPECTED'
		ORDER BY source_id, effective_at DESC, observed_at DESC, source_at DESC, revision_id DESC
		LIMIT $3`, clusterID, ids, GPUMetricsSourceLimit)
	if err != nil {
		return nil, fmt.Errorf("load GPU metric inventory revisions: %w", err)
	}
	defer rows.Close()
	revisions := map[string]*gpuMetricsRevision{}
	for rows.Next() {
		var sourceID string
		revision := &gpuMetricsRevision{}
		if err := rows.Scan(&sourceID, &revision.RevisionID, &revision.EffectiveAt, &revision.SourceAt, &revision.ObservedAt); err != nil {
			return nil, fmt.Errorf("scan GPU metric inventory revision: %w", err)
		}
		normalizeTime(&revision.EffectiveAt)
		normalizeTime(&revision.SourceAt)
		normalizeTime(&revision.ObservedAt)
		revisions[sourceID] = revision
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate GPU metric inventory revisions: %w", err)
	}
	return revisions, nil
}

func (store *PostgresStore) loadGPUMetricsEntities(ctx context.Context, clusterID, revisionID string) ([]gpuMetricsEntityRow, bool, error) {
	rows, err := store.gpuMetricsQuerier().Query(ctx, `
		SELECT entity_kind, stable_node_id, physical_gpu_uuid, coalesce(mig_identity,'')
		FROM goodput_inventory_revision_entities
		WHERE cluster_id=$1 AND revision_id=$2
		ORDER BY entity_kind, stable_node_id, physical_gpu_uuid
		LIMIT $3`, clusterID, revisionID, gpuMetricsEntityLimit)
	if err != nil {
		return nil, false, fmt.Errorf("load GPU metric expected entities: %w", err)
	}
	defer rows.Close()
	entities := []gpuMetricsEntityRow{}
	for rows.Next() {
		var entity gpuMetricsEntityRow
		if err := rows.Scan(&entity.kind, &entity.node, &entity.gpu, &entity.mig); err != nil {
			return nil, false, fmt.Errorf("scan GPU metric expected entity: %w", err)
		}
		entities = append(entities, entity)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate GPU metric expected entities: %w", err)
	}
	return entities, len(entities) >= gpuMetricsEntityLimit, nil
}

// loadGPUMetricsObserved reads the never-pruned target cache with each entry's
// newest observation instant. Presence is not coverage, so the instant is
// carried out of the store rather than collapsed to a boolean.
func (store *PostgresStore) loadGPUMetricsObserved(ctx context.Context, clusterID, sourceID string) (map[gpuMetricsEntity]time.Time, map[string]time.Time, bool, error) {
	rows, err := store.gpuMetricsQuerier().Query(ctx, `
		SELECT target_kind, target_id, node_id, last_observed_at
		FROM collection_target_inventory
		WHERE cluster_id=$1 AND source_id=$2 AND target_kind IN ('NODE','GPU')
		ORDER BY target_kind, target_id LIMIT $3`, clusterID, sourceID, gpuMetricsEntityLimit)
	if err != nil {
		return nil, nil, false, fmt.Errorf("load GPU metric observed inventory: %w", err)
	}
	defer rows.Close()
	gpus := map[gpuMetricsEntity]time.Time{}
	nodes := map[string]time.Time{}
	count := 0
	for rows.Next() {
		var kind, target, node string
		var observedAt time.Time
		if err := rows.Scan(&kind, &target, &node, &observedAt); err != nil {
			return nil, nil, false, fmt.Errorf("scan GPU metric observed inventory: %w", err)
		}
		count++
		switch kind {
		case string(domain.EntityNode):
			gpuMetricsKeepNewest(nodes, target, observedAt.UTC())
		case string(domain.EntityGPU):
			gpuMetricsKeepNewest(nodes, node, observedAt.UTC())
			gpus[gpuMetricsEntity{node, target}] = observedAt.UTC()
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, false, fmt.Errorf("iterate GPU metric observed inventory: %w", err)
	}
	return gpus, nodes, count >= gpuMetricsEntityLimit, nil
}

// loadGPUMetricsProjections reads the newest current projection per entity and
// reviewed metric, exactly as the dashboard resource summary reads current
// telemetry, restricted to the reviewed expanded field names.
func (store *PostgresStore) loadGPUMetricsProjections(ctx context.Context, clusterID, sourceID string, runs map[string]gpuMetricsRunRow) (map[gpuMetricsCell]gpuMetricsProjection, bool, error) {
	rows, err := store.gpuMetricsQuerier().Query(ctx, `
		SELECT o.entity_key, o.metric, o.value, o.unit, o.observed_at, o.metric_semantics,
		       o.run_id, o.cluster_id, o.source_id, o.labels
		FROM current_projections p
		JOIN observations o ON o.observation_id=p.observation_id
		 AND o.cluster_id=p.cluster_id AND o.source_id=p.source_id
		 AND o.entity_key=p.entity_key AND o.metric=p.metric
		WHERE p.cluster_id=$1 AND p.source_id=$2 AND p.metric=ANY($3::text[])
		ORDER BY p.entity_key, p.metric LIMIT $4`,
		clusterID, sourceID, reviewedGPUMetricsFieldNames(), gpuMetricsProjectionLimit)
	if err != nil {
		return nil, false, fmt.Errorf("load GPU metric projections: %w", err)
	}
	defer rows.Close()
	projections := map[gpuMetricsCell]gpuMetricsProjection{}
	latestRuns := map[string]string{}
	for _, query := range domain.ExpandedDCGMQueries() {
		for _, field := range domain.DCGMFields(query) {
			latestRuns[field.Name] = runs[sourceID+"\x00"+string(query)].run.RunID
		}
	}
	count := 0
	for rows.Next() {
		var entityKey, metric string
		var encoded, labelsJSON []byte
		var observation domain.Observation
		var projection gpuMetricsProjection
		if err := rows.Scan(&entityKey, &metric, &projection.value, &projection.unit, &projection.observedAt, &encoded,
			&projection.runID, &observation.ClusterID, &observation.SourceID, &labelsJSON); err != nil {
			return nil, false, fmt.Errorf("scan GPU metric projection: %w", err)
		}
		count++
		if projection.runID != latestRuns[metric] {
			continue
		}
		projection.observedAt = projection.observedAt.UTC()
		if len(encoded) > 0 {
			var semantics domain.MetricSemantics
			if err := json.Unmarshal(encoded, &semantics); err != nil {
				return nil, false, fmt.Errorf("decode GPU metric semantics: %w", err)
			}
			projection.semantics, projection.resetObserved = semantics.Kind, semantics.ResetObserved
		}
		observation.EntityKey = entityKey
		// Legacy storage fixtures used the empty JSON object for no labels.
		// Actual labels are persisted as the domain's ordered label array.
		if string(labelsJSON) != "{}" && len(labelsJSON) > 0 {
			if err := json.Unmarshal(labelsJSON, &observation.Labels); err != nil {
				return nil, false, fmt.Errorf("decode GPU metric labels: %w", err)
			}
		}
		identity, ok := domain.ResolveGPUObservationIdentity(domain.ClusterID(clusterID), domain.SourceID(sourceID), observation)
		if !ok || !identity.Canonical {
			continue
		}
		cell := gpuMetricsCell{string(identity.NodeID), string(identity.PhysicalGPUUUID), metric}
		// Canonical and UUID-proven legacy keys can coexist during migration.
		// Keep their newest actual sample, never lexical key ordering.
		if current, exists := projections[cell]; !exists || projection.observedAt.After(current.observedAt) {
			projections[cell] = projection
		} else if projection.observedAt.Equal(current.observedAt) &&
			(projection.value != current.value || projection.unit != current.unit || projection.semantics != current.semantics || projection.resetObserved != current.resetObserved) {
			current.conflicting = true
			projections[cell] = current
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate GPU metric projections: %w", err)
	}
	return projections, count >= gpuMetricsProjectionLimit, nil
}

func buildGPUMetricsOperation(query domain.QueryKind, schedule *gpuMetricsSchedule, run gpuMetricsRunRow) GPUMetricsOperation {
	reviewed, _ := domain.CollectionOperationForQuery(query)
	operation := GPUMetricsOperation{
		OperationID: string(reviewed.ID), QueryKind: string(query),
		Fields: []GPUMetricsFieldColumn{}, FieldSummaries: []GPUMetricsFieldSummary{},
	}
	for _, field := range domain.DCGMFields(query) {
		operation.Fields = append(operation.Fields, GPUMetricsFieldColumn{Name: field.Name, Unit: field.Unit, Semantics: field.Kind})
	}
	if schedule != nil {
		operation.Enrolled = true
		operation.Enabled, operation.Mode = schedule.Enabled, schedule.Mode
		operation.IntervalSeconds, operation.Revision = schedule.IntervalSeconds, schedule.Revision
	}
	if run.run.RunID != "" {
		committed := run.run
		operation.LastRun = &committed
	}
	summaries := map[string]*GPUMetricsFieldSummary{}
	for index := range operation.Fields {
		summary := &GPUMetricsFieldSummary{Field: operation.Fields[index].Name}
		summaries[summary.Field] = summary
	}
	// Assessed counts distinct targets so the page can state the assessment's
	// own denominator instead of implying the run covered the whole fleet.
	seen := map[gpuMetricsCell]bool{}
	for _, evidence := range run.assessments {
		if !gpuMetricsRunYieldsEvidence(run.run.Status) {
			break
		}
		summary, ok := summaries[evidence.Metric]
		if !ok {
			continue
		}
		cell := gpuMetricsCell{string(evidence.NodeID), string(evidence.GPU), evidence.Metric}
		if seen[cell] {
			continue
		}
		seen[cell] = true
		summary.Assessed++
		switch evidence.State {
		case string(GPUMetricSupported):
			summary.Supported++
		case string(GPUMetricNotSupported):
			summary.NotSupported++
		default:
			summary.Unknown++
		}
	}
	for index := range operation.Fields {
		summary := *summaries[operation.Fields[index].Name]
		summary.Dominant = DominantFieldState(summary)
		operation.FieldSummaries = append(operation.FieldSummaries, summary)
	}
	return operation
}

// primaryGPUMetricsSource selects the source whose expected inventory revision
// governs the GPU table. Expected inventory is scoped per source, so mixing
// sources would invent a coverage claim no revision makes.
func primaryGPUMetricsSource(sources []GPUMetricsSource, revisions map[string]*gpuMetricsRevision) int {
	primary, best := 0, (*gpuMetricsRevision)(nil)
	for index := range sources {
		revision := revisions[sources[index].SourceID]
		if revision == nil {
			continue
		}
		if best == nil || gpuMetricsRevisionNewer(revision, best) {
			primary, best = index, revision
		}
	}
	return primary
}

func gpuMetricsRevisionNewer(candidate, current *gpuMetricsRevision) bool {
	if candidate.EffectiveAt == nil || current.EffectiveAt == nil {
		return current.EffectiveAt == nil && candidate.EffectiveAt != nil
	}
	return candidate.EffectiveAt.After(*current.EffectiveAt)
}

func gpuMetricsKeepNewest(instants map[string]time.Time, key string, observed time.Time) {
	if current, ok := instants[key]; ok && current.After(observed) {
		return
	}
	instants[key] = observed
}

// gpuMetricsObservations flattens the expected revision and the observed cache
// into one raw list. It records presence and instant only; whether an entity is
// covered is the service's time-relative decision.
func gpuMetricsObservations(expectedNodes map[string]bool, expectedGPUs map[gpuMetricsEntity]bool,
	observedNodes map[string]time.Time, observedGPUs map[gpuMetricsEntity]time.Time) []GPUMetricsObservation {
	observations := make([]GPUMetricsObservation, 0, len(expectedNodes)+len(expectedGPUs)+len(observedNodes)+len(observedGPUs))
	for node := range expectedNodes {
		observations = append(observations, GPUMetricsObservation{
			NodeID: node, Expected: true, ObservedAt: gpuMetricsInstant(observedNodes, node),
		})
	}
	for node, observed := range observedNodes {
		if expectedNodes[node] {
			continue
		}
		instant := observed
		observations = append(observations, GPUMetricsObservation{NodeID: node, ObservedAt: &instant})
	}
	for entity := range expectedGPUs {
		var instant *time.Time
		if observed, ok := observedGPUs[entity]; ok {
			moment := observed
			instant = &moment
		}
		observations = append(observations, GPUMetricsObservation{
			NodeID: entity.node, GPUUUID: entity.gpu, Expected: true, ObservedAt: instant,
		})
	}
	for entity, observed := range observedGPUs {
		if expectedGPUs[entity] {
			continue
		}
		instant := observed
		observations = append(observations, GPUMetricsObservation{NodeID: entity.node, GPUUUID: entity.gpu, ObservedAt: &instant})
	}
	sort.Slice(observations, func(a, b int) bool {
		if observations[a].NodeID != observations[b].NodeID {
			return observations[a].NodeID < observations[b].NodeID
		}
		return observations[a].GPUUUID < observations[b].GPUUUID
	})
	return observations
}

func gpuMetricsInstant(instants map[string]time.Time, key string) *time.Time {
	observed, ok := instants[key]
	if !ok {
		return nil
	}
	return &observed
}

// loadGPUMetricsOtherSources counts the observed targets of every Prometheus
// source the governing expected revision does not cover, so the per-GPU table's
// single-source scope is stated instead of silently omitting those GPUs.
func (store *PostgresStore) loadGPUMetricsOtherSources(ctx context.Context, clusterID string,
	sources []GPUMetricsSource, primaryID string) ([]GPUMetricsOtherSource, error) {
	others := []GPUMetricsOtherSource{}
	ids := make([]string, 0, len(sources))
	for _, source := range sources {
		if source.SourceID == primaryID {
			continue
		}
		ids = append(ids, source.SourceID)
		others = append(others, GPUMetricsOtherSource{SourceID: source.SourceID, DisplayName: source.DisplayName})
	}
	if len(ids) == 0 {
		return others, nil
	}
	rows, err := store.gpuMetricsQuerier().Query(ctx, `
		SELECT source_id,
			count(*) FILTER (WHERE target_kind='NODE'),
			count(*) FILTER (WHERE target_kind='GPU')
		FROM collection_target_inventory
		WHERE cluster_id=$1 AND source_id=ANY($2::text[]) AND target_kind IN ('NODE','GPU')
		GROUP BY source_id ORDER BY source_id LIMIT $3`, clusterID, ids, GPUMetricsSourceLimit)
	if err != nil {
		return nil, fmt.Errorf("count GPU metric secondary source targets: %w", err)
	}
	defer rows.Close()
	counts := map[string][2]int{}
	for rows.Next() {
		var sourceID string
		var nodes, gpus int
		if err := rows.Scan(&sourceID, &nodes, &gpus); err != nil {
			return nil, fmt.Errorf("scan GPU metric secondary source targets: %w", err)
		}
		counts[sourceID] = [2]int{nodes, gpus}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate GPU metric secondary source targets: %w", err)
	}
	for index := range others {
		count := counts[others[index].SourceID]
		others[index].ObservedNodes, others[index].ObservedGPUs = count[0], count[1]
	}
	return others, nil
}

// buildGPUMetricsRows projects one row per physical GPU and one row per
// expected MIG entity. A MIG identity is not a physical GPU identity, so its
// row carries AMBIGUOUS_MIG in every field instead of borrowing the physical
// GPU's evidence, and the MIG count on the page is backed by visible rows.
func buildGPUMetricsRows(sourceID string, expectedGPUs map[gpuMetricsEntity]bool, migs []gpuMetricsEntityRow,
	observedGPUs map[gpuMetricsEntity]time.Time, assessments map[gpuMetricsCell]string,
	assessed map[domain.QueryKind]string, projections map[gpuMetricsCell]gpuMetricsProjection) ([]GPUMetricsRow, bool) {
	keys := map[gpuMetricsRowKey]bool{}
	for entity := range expectedGPUs {
		keys[gpuMetricsRowKey{entity.node, entity.gpu, ""}] = true
	}
	for entity := range observedGPUs {
		keys[gpuMetricsRowKey{entity.node, entity.gpu, ""}] = true
	}
	for _, mig := range migs {
		keys[gpuMetricsRowKey{mig.node, mig.gpu, mig.mig}] = true
	}
	ordered := make([]gpuMetricsRowKey, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Slice(ordered, func(a, b int) bool {
		if ordered[a].node != ordered[b].node {
			return ordered[a].node < ordered[b].node
		}
		if ordered[a].gpu != ordered[b].gpu {
			return ordered[a].gpu < ordered[b].gpu
		}
		return ordered[a].mig < ordered[b].mig
	})
	truncated := len(ordered) > GPUMetricsRowLimit
	if truncated {
		ordered = ordered[:GPUMetricsRowLimit]
	}
	rows := make([]GPUMetricsRow, 0, len(ordered))
	for _, key := range ordered {
		entity := gpuMetricsEntity{key.node, key.gpu}
		row := GPUMetricsRow{
			SourceID: sourceID, NodeID: key.node, GPUUUID: key.gpu, MIGIdentity: key.mig,
			Values: map[string]GPUMetricValue{},
		}
		if key.mig != "" {
			row.Expected = true
			for _, query := range domain.ExpandedDCGMQueries() {
				for _, field := range domain.DCGMFields(query) {
					row.Values[field.Name] = GPUMetricValue{
						State: GPUMetricAmbiguousMIG, Unit: field.Unit, Semantics: field.Kind,
					}
				}
			}
			rows = append(rows, row)
			continue
		}
		row.Expected = expectedGPUs[entity]
		if observedAt, ok := observedGPUs[entity]; ok {
			row.Observed = true
			instant := observedAt
			row.ObservedAt = &instant
		}
		for _, query := range domain.ExpandedDCGMQueries() {
			for _, field := range domain.DCGMFields(query) {
				row.Values[field.Name] = gpuMetricsValue(entity, field, query, assessments, assessed, projections)
			}
		}
		rows = append(rows, row)
	}
	return rows, truncated
}

// gpuMetricsValue assigns the instant-independent state. The newest committed
// run's exact assessment and run binding decide first. Missing, UNKNOWN and
// NOT_SUPPORTED assessments cannot be contradicted by an older number. Only a
// SUPPORTED assessment paired with an observation from that run supplies a
// number; a missing cell is UNKNOWN or NO_DATA, never zero.
func gpuMetricsValue(entity gpuMetricsEntity, field domain.DCGMField, query domain.QueryKind,
	assessments map[gpuMetricsCell]string, assessed map[domain.QueryKind]string,
	projections map[gpuMetricsCell]gpuMetricsProjection) GPUMetricValue {
	cell := gpuMetricsCell{entity.node, entity.gpu, field.Name}
	value := GPUMetricValue{Unit: field.Unit, Semantics: field.Kind}
	state, hasAssessment := assessments[cell]
	if hasAssessment && state != string(GPUMetricSupported) {
		value.State = GPUMetricUnknown
		if state == string(GPUMetricNotSupported) {
			value.State = GPUMetricNotSupported
		}
		return value
	}
	if projection, ok := projections[cell]; ok && hasAssessment && state == string(GPUMetricSupported) &&
		projection.runID == assessed[query] {
		if projection.conflicting {
			value.State = GPUMetricUnknown
			return value
		}
		observation := domain.Observation{Metric: field.Name, Value: projection.value, Unit: projection.unit}
		if projection.semantics != "" {
			observation.Semantics = &domain.MetricSemantics{Kind: projection.semantics}
		}
		if !domain.ValidGPUHealthObservation(observation) {
			value.State = GPUMetricUnknown
			return value
		}
		observed := projection.observedAt
		number := projection.value
		value.State, value.Value, value.ObservedAt, value.ResetObserved = GPUMetricSupported, &number, &observed, projection.resetObserved
		if projection.unit != "" {
			value.Unit = projection.unit
		}
		if projection.semantics != "" {
			value.Semantics = projection.semantics
		}
		return value
	}
	if hasAssessment || assessed[query] != "" {
		value.State = GPUMetricUnknown
		return value
	}
	value.State = GPUMetricNoData
	return value
}

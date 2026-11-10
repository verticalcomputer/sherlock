package adminview

import (
	"sort"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type gpuMetricsCell struct{ node, gpu, metric string }

type gpuMetricsRunRow struct {
	run         GPUMetricsRun
	assessments []domain.DCGMFieldEvidence
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

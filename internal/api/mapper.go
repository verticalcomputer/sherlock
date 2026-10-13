package api

import (
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/events"
	contract "github.com/verticalcomputer/sherlock/sdk/go"
)

func mapCoverage(value domain.Coverage, failures int) contract.Coverage {
	requested := value.SeriesReturned + failures
	if value.SeriesExpected != nil {
		requested = *value.SeriesExpected
	}
	return contract.Coverage{Requested: requested, Successful: value.SeriesReturned, Failed: failures, Complete: value.Complete, SeriesExpected: value.SeriesExpected, SeriesReturned: value.SeriesReturned, BytesRead: value.BytesRead}
}

func responseMeta(requestID string, at time.Time, status domain.ResultStatus, freshness domain.Freshness, count int, next string) contract.ResponseMeta {
	return contract.ResponseMeta{RequestID: requestID, GeneratedAt: at.UTC(), CollectionStatus: contract.CollectionStatus(status), Freshness: contract.Freshness(freshness), Coverage: contract.Coverage{Requested: count, Successful: count, Complete: true}, Warnings: []string{}, NextPageToken: next}
}

func stateMetadata(observedAt, collectedAt time.Time, freshness domain.Freshness, status domain.ResultStatus, coverage domain.Coverage, failures int) contract.StateMetadata {
	return contract.StateMetadata{ObservedAt: observedAt.UTC(), CollectedAt: collectedAt.UTC(), Freshness: contract.Freshness(freshness), CollectionStatus: contract.CollectionStatus(status), Coverage: mapCoverage(coverage, failures)}
}

func mapCluster(item application.ClusterProjection, health application.HealthProjection, capabilities []auth.Capability) contract.Cluster {
	values := make([]string, len(capabilities))
	for index, capability := range capabilities {
		values[index] = string(capability)
	}
	status := health.CollectionStatus
	if status == "" {
		status = domain.ResultNoData
	}
	at := health.GeneratedAt
	if at.IsZero() {
		at = item.CreatedAt
	}
	return contract.Cluster{ClusterID: string(item.ID), Name: item.DisplayName, Capabilities: values, StateMetadata: stateMetadata(at, at, health.Freshness, status, health.Coverage, 0)}
}

func mapSource(item application.SourceProjection) contract.Source {
	status := contract.SourceStatus(item.Availability)
	if item.Availability == "AVAILABLE" && item.LastFailureCode != nil {
		status = "DEGRADED"
	}
	collectionStatus := domain.ResultSucceeded
	if item.Availability == "UNKNOWN" {
		collectionStatus = domain.ResultNoData
	}
	if item.Availability == "UNAVAILABLE" {
		collectionStatus = domain.ResultFailed
	}
	at := time.Time{}
	if item.LastAttemptAt != nil {
		at = *item.LastAttemptAt
	} else if item.LastSuccessAt != nil {
		at = *item.LastSuccessAt
	}
	result := contract.Source{SourceID: string(item.ID), Kind: strings.ToUpper(item.Kind), Status: status, LastSuccessAt: item.LastSuccessAt, StateMetadata: stateMetadata(at, at, item.Freshness, collectionStatus, domain.Coverage{Complete: collectionStatus == domain.ResultSucceeded}, 0)}
	if item.LastFailureCode != nil {
		result.LastError = &contract.CollectionError{Code: string(*item.LastFailureCode), SourceID: string(item.ID), Retryable: false}
	}
	return result
}

func mapObservation(item application.ObservationProjection, now time.Time, freshFor time.Duration) contract.Observation {
	observation := item.Observation
	freshness := domain.FreshnessAt(&observation.CollectedAt, now, freshFor)
	labels := make([]contract.Label, 0, len(observation.Labels))
	for _, label := range observation.Labels {
		labels = append(labels, contract.Label{Name: label.Name, Value: label.Value})
	}
	return contract.Observation{ObservationID: string(observation.ID), SchemaVersion: observation.SchemaVersion, ClusterID: string(observation.ClusterID), SourceID: string(observation.SourceID), Kind: observation.Kind, EntityKey: observation.EntityKey, Metric: observation.Metric, Labels: labels, Value: observation.Value, Unit: observation.Unit, SourceReference: observation.SourceReference, StateMetadata: stateMetadata(observation.ObservedAt, observation.CollectedAt, freshness, domain.ResultSucceeded, domain.Coverage{SeriesReturned: 1, Complete: true}, 0)}
}

func mapHealth(item application.HealthProjection) contract.HealthSummary {
	state, severity := domain.HealthSignalNoData, domain.HealthSeverityUnknown
	signals := make([]contract.HealthSignal, 0, len(item.Signals))
	for _, signal := range item.Signals {
		signals = append(signals, mapSignal(signal))
		if severityRank(signal.Severity) > severityRank(severity) {
			severity = signal.Severity
			state = signal.Type
		} else if state == domain.HealthSignalNoData {
			state = signal.Type
		}
	}
	at := item.GeneratedAt
	for _, signal := range item.Signals {
		if signal.ObservedAt.After(at) {
			at = signal.ObservedAt
		}
	}
	result := contract.HealthSummary{ClusterID: string(item.ClusterID), State: contract.HealthState(state), Severity: contract.HealthSeverity(severity), Signals: signals, Errors: []contract.CollectionError{}, StateMetadata: stateMetadata(at, item.GeneratedAt, item.Freshness, item.CollectionStatus, item.Coverage, 0)}
	if item.Shared != nil {
		view := item.Shared
		result.Shared = &contract.ClusterHealthView{SchemaVersion: view.SchemaVersion, ClusterID: string(view.ClusterID),
			GeneratedAt: view.GeneratedAt, WindowStart: view.WindowStart, WindowEnd: view.WindowEnd,
			Capacity: contract.ClusterCapacityView{Condition: string(view.Capacity.Condition),
				ExpectedNodes: view.Capacity.ExpectedNodes, ExpectedGPUs: view.Capacity.ExpectedGPUs,
				ObservedNodes: view.Capacity.ObservedNodes, ObservedGPUs: view.Capacity.ObservedGPUs,
				ExpectedRevisionID: view.Capacity.ExpectedRevisionID, ObservedRevisionID: view.Capacity.ObservedRevisionID},
			Monitoring: contract.ClusterMonitoringView{CollectorCondition: string(view.Monitoring.CollectorCondition),
				FreshnessCondition: string(view.Monitoring.FreshnessCondition), CoverageCondition: string(view.Monitoring.CoverageCondition),
				SupportCondition:   string(view.Monitoring.SupportCondition),
				ExpectedCollectors: view.Monitoring.ExpectedCollectors, FreshCollectors: view.Monitoring.FreshCollectors,
				FreshSources: view.Monitoring.FreshSources, StaleSources: view.Monitoring.StaleSources,
				SourcesWithoutData: view.Monitoring.SourcesWithoutData, CompleteStreams: view.Monitoring.CompleteStreams,
				PartialStreams: view.Monitoring.PartialStreams, NoDataStreams: view.Monitoring.NoDataStreams,
				UnavailableStreams: view.Monitoring.UnavailableStreams, HistoricalStreams: view.Monitoring.HistoricalStreams,
				ExpectedOperations: view.Monitoring.ExpectedOperations, FreshOperations: view.Monitoring.FreshOperations,
				LateOperations: view.Monitoring.LateOperations, FailedOperations: view.Monitoring.FailedOperations},
			Workload: string(view.Workload), Progress: string(view.Progress), Attention: append([]string{}, view.Attention...)}
	}
	return result
}

func mapSignal(signal domain.HealthSignal) contract.HealthSignal {
	evidence := make([]string, len(signal.Evidence))
	for index, id := range signal.Evidence {
		evidence[index] = string(id)
	}
	counter := make([]string, len(signal.CounterEvidence))
	for index, id := range signal.CounterEvidence {
		counter[index] = string(id)
	}
	return contract.HealthSignal{SchemaVersion: signal.SchemaVersion, Type: contract.HealthState(signal.Type), Category: contract.HealthState(signal.Category), Severity: contract.HealthSeverity(signal.Severity), SourceID: string(signal.SourceID), EntityKey: signal.EntityKey, Metric: signal.Metric, ObservedAt: signal.ObservedAt, ProjectedAt: signal.ProjectedAt, Freshness: contract.Freshness(signal.Freshness), Coverage: mapCoverage(signal.Coverage, 0), Evidence: evidence, CounterEvidence: counter, Reason: signal.Reason}
}

func mapGPU(item application.GPUSummaryProjection) contract.GPUSummary {
	parts := strings.Split(item.EntityKey, "/")
	nodeID, gpuID := item.EntityKey, item.EntityKey
	if len(parts) >= 4 {
		nodeID, gpuID = parts[1], parts[3]
	}
	result := contract.GPUSummary{GPUID: gpuID, NodeID: nodeID, Health: contract.HealthState(domain.HealthSignalNoData), Severity: contract.HealthSeverity(domain.HealthSeverityUnknown), Signals: []contract.HealthSignal{}, Metrics: map[string]contract.GPUMetric{}}
	var observed, collected time.Time
	for _, observation := range item.Observations {
		result.Metrics[observation.Metric] = contract.GPUMetric{Value: observation.Value, Unit: observation.Unit, ObservedAt: observation.ObservedAt}
		if observation.ObservedAt.After(observed) {
			observed = observation.ObservedAt
		}
		if observation.CollectedAt.After(collected) {
			collected = observation.CollectedAt
		}
	}
	for _, signal := range item.Signals {
		result.Signals = append(result.Signals, mapSignal(signal))
		if severityRank(signal.Severity) >= severityRank(domain.HealthSeverity(result.Severity)) {
			result.Health = contract.HealthState(signal.Type)
			result.Severity = contract.HealthSeverity(signal.Severity)
		}
	}
	result.StateMetadata = stateMetadata(observed, collected, item.Freshness, statusForCount(len(item.Observations)), domain.Coverage{SeriesReturned: len(item.Observations), Complete: true}, 0)
	return result
}

func mapRun(clusterID domain.ClusterID, item application.CollectionRunProjection, now time.Time, freshFor time.Duration) contract.CollectionRun {
	failures := make([]contract.CollectionError, 0, len(item.Failures))
	for _, failure := range item.Failures {
		failures = append(failures, contract.CollectionError{Code: string(failure.Code), SourceID: string(item.SourceID), TargetID: failure.Target, Retryable: failure.Retryable, Message: failure.Message})
	}
	freshness := domain.FreshnessAt(&item.CompletedAt, now, freshFor)
	return contract.CollectionRun{RunID: string(item.RunID), ClusterID: string(clusterID), SourceID: string(item.SourceID), Query: string(item.Query), Status: contract.CollectionStatus(item.Status), ScheduledFor: item.ScheduledFor, StartedAt: item.StartedAt, CompletedAt: item.CompletedAt, Failures: failures, StateMetadata: stateMetadata(item.CompletedAt, item.CompletedAt, freshness, item.Status, item.Coverage, len(item.Failures))}
}

func mapEvidence(item application.EvidenceProjection) contract.Evidence {
	envelope := item.Envelope
	source := envelope.Source()
	timeRange := envelope.TimeRange()
	coverage := envelope.Coverage()
	expected := make([]contract.EvidenceTarget, len(coverage.Expected))
	for index, target := range coverage.Expected {
		expected[index] = contract.EvidenceTarget{Kind: string(target.Kind), ID: string(target.ID)}
	}
	covered := make([]contract.EvidenceTarget, len(coverage.Covered))
	for index, target := range coverage.Covered {
		covered[index] = contract.EvidenceTarget{Kind: string(target.Kind), ID: string(target.ID)}
	}
	result := contract.Evidence{EvidenceID: string(envelope.ID()), SchemaVersion: envelope.SchemaVersion(), ClusterID: string(envelope.ClusterID()), Status: contract.EvidenceStatus(envelope.Status()), Source: contract.EvidenceSourceReference{SourceID: string(source.SourceID), RunID: string(source.RunID), Operation: string(source.Operation), DefinitionVersion: source.DefinitionVersion, Reference: string(source.Reference)}, CollectedAt: envelope.CollectedAt(), Coverage: contract.EvidenceCoverage{Expected: expected, Covered: covered, Complete: coverage.Complete()}}
	result.TimeRange.Start, result.TimeRange.End = timeRange.Start, timeRange.End
	if artifact, ok := envelope.Artifact(); ok {
		mapped := contract.ArtifactReference{ArtifactID: string(artifact.ArtifactID), SHA256: artifact.SHA256.String(), Bytes: artifact.Bytes, MediaType: artifact.MediaType, Compression: string(artifact.Compression), ParserVersion: artifact.ParserVersion, RetentionClass: string(artifact.RetentionClass), Availability: string(item.ArtifactAvailability)}
		mapped.Redactions.PolicyVersion, mapped.Redactions.MatchCount = artifact.Redactions.PolicyVersion, artifact.Redactions.MatchCount
		result.Artifact = &mapped
	}
	if supersedes, ok := envelope.Supersedes(); ok {
		value := string(supersedes)
		result.Supersedes = &value
	}
	return result
}

func mapEvent(event events.Event) (contract.EventType, any) {
	switch payload := event.Payload.(type) {
	case events.CollectionUpdatedV1:
		return contract.EventTypeCollectionRunUpdated, map[string]any{"schema_version": 1, "cluster_id": event.ClusterID, "occurred_at": event.CreatedAt, "run_id": payload.RunID, "status": payload.Status}
	case *events.CollectionUpdatedV1:
		return contract.EventTypeCollectionRunUpdated, map[string]any{"schema_version": 1, "cluster_id": event.ClusterID, "occurred_at": event.CreatedAt, "run_id": payload.RunID, "status": payload.Status}
	case events.SourceUpdatedV1:
		return contract.EventTypeSourceUpdated, map[string]any{"schema_version": 1, "cluster_id": event.ClusterID, "occurred_at": event.CreatedAt, "source_id": payload.SourceID, "status": payload.Availability, "freshness": domain.FreshnessUnknown}
	case *events.SourceUpdatedV1:
		return contract.EventTypeSourceUpdated, map[string]any{"schema_version": 1, "cluster_id": event.ClusterID, "occurred_at": event.CreatedAt, "source_id": payload.SourceID, "status": payload.Availability, "freshness": domain.FreshnessUnknown}
	default:
		return contract.EventType(event.Type), map[string]any{"schema_version": event.SchemaVersion, "cluster_id": event.ClusterID, "occurred_at": event.CreatedAt}
	}
}

func statusForCount(count int) domain.ResultStatus {
	if count == 0 {
		return domain.ResultNoData
	}
	return domain.ResultSucceeded
}
func aggregateSourceStatus(items []application.SourceProjection) domain.ResultStatus {
	status := statusForCount(len(items))
	for _, item := range items {
		if item.Availability == "UNAVAILABLE" {
			return domain.ResultFailed
		}
		if item.LastFailureCode != nil {
			status = domain.ResultPartial
		}
	}
	return status
}
func aggregateSourceFreshness(items []application.SourceProjection) domain.Freshness {
	result := domain.FreshnessUnknown
	for _, item := range items {
		if item.Freshness == domain.FreshnessStale {
			return domain.FreshnessStale
		}
		if item.Freshness == domain.FreshnessFresh {
			result = domain.FreshnessFresh
		}
	}
	return result
}
func freshnessForObservations(items []application.ObservationProjection, now time.Time, freshFor time.Duration) domain.Freshness {
	result := domain.FreshnessUnknown
	for _, item := range items {
		value := domain.FreshnessAt(&item.Observation.CollectedAt, now, freshFor)
		if value == domain.FreshnessStale {
			return value
		}
		result = value
	}
	return result
}
func aggregateGPUFreshness(items []application.GPUSummaryProjection) domain.Freshness {
	result := domain.FreshnessUnknown
	for _, item := range items {
		if item.Freshness == domain.FreshnessStale {
			return domain.FreshnessStale
		}
		result = item.Freshness
	}
	return result
}
func aggregateRunStatus(items []application.CollectionRunProjection) domain.ResultStatus {
	result := statusForCount(len(items))
	for _, item := range items {
		if item.Status == domain.ResultFailed {
			return item.Status
		}
		if item.Status == domain.ResultPartial {
			result = item.Status
		}
	}
	return result
}
func freshnessForRuns(items []application.CollectionRunProjection, now time.Time, freshFor time.Duration) domain.Freshness {
	result := domain.FreshnessUnknown
	for _, item := range items {
		value := domain.FreshnessAt(&item.CompletedAt, now, freshFor)
		if value == domain.FreshnessStale {
			return value
		}
		result = value
	}
	return result
}
func evidenceListStatus(items []application.EvidenceProjection) domain.ResultStatus {
	result := statusForCount(len(items))
	for _, item := range items {
		switch item.Envelope.Status() {
		case domain.EvidenceUnavailable:
			return domain.ResultFailed
		case domain.EvidencePartial:
			result = domain.ResultPartial
		case domain.EvidenceNoData:
			if result == domain.ResultSucceeded {
				result = domain.ResultNoData
			}
		}
	}
	return result
}
func severityRank(value domain.HealthSeverity) int {
	switch value {
	case domain.HealthSeverityCritical:
		return 3
	case domain.HealthSeverityWarning:
		return 2
	case domain.HealthSeverityInfo:
		return 1
	default:
		return 0
	}
}

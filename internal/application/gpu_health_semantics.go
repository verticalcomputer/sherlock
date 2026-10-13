package application

import (
	"sort"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func healthFieldSupport(fields []domain.DCGMFieldEvidence, identity domain.GPUObservationIdentity, metric string) (string, bool) {
	for _, field := range fields {
		if identity.Canonical && field.NodeID == identity.NodeID && field.GPU == identity.PhysicalGPUUUID && field.Metric == metric {
			return field.State, true
		}
	}
	return "", false
}

func gpuSupportSignals(result domain.CollectionResult, base domain.HealthSignal) []domain.HealthSignal {
	present := map[string]bool{}
	for _, observation := range result.Observations {
		identity, ok := domain.ResolveGPUObservationIdentity(result.Task.ClusterID, result.Task.SourceID, observation)
		if ok {
			present[identity.EntityKey+"\x00"+observation.Metric] = true
		}
	}
	signals := []domain.HealthSignal{}
	for _, field := range result.Coverage.MetricFields {
		category := metricCategory(field.Metric)
		if category == "" || result.Task.Node != "" && string(field.NodeID) != result.Task.Node {
			continue
		}
		entity, err := domain.CreateEntityIdentity(domain.EntityIdentity{ClusterID: result.Task.ClusterID, Kind: domain.EntityGPU, NodeID: field.NodeID, PhysicalGPUUUID: field.GPU})
		if err != nil {
			continue
		}
		if field.State == "SUPPORTED" && present[entity.Key()+"\x00"+field.Metric] {
			continue
		}
		signal := base
		signal.Type, signal.Category, signal.Severity, signal.EntityKey, signal.Metric = domain.HealthSignalPartial, category, domain.HealthSeverityUnknown, entity.Key(), field.Metric
		signal.Reason = "expected field is UNKNOWN or missing; absence is not healthy"
		if field.State == "NOT_SUPPORTED" {
			signal.Reason = "expected field is NOT_SUPPORTED; other fields retain independent support"
		}
		if field.State == "UNKNOWN" && (field.Reason == "collection_failed" || field.Reason == "source_unavailable") {
			signal.Type = domain.HealthSignalUnavailable
			signal.Reason = "latest scoped sensor collection failed; current field health is unavailable"
		}
		signals = append(signals, signal)
	}
	sort.Slice(signals, func(i, j int) bool {
		if signals[i].EntityKey != signals[j].EntityKey {
			return signals[i].EntityKey < signals[j].EntityKey
		}
		return signals[i].Metric < signals[j].Metric
	})
	return signals
}

func invalidCurrentHealthEvidence(group healthGroup, current []domain.Observation, now, completed time.Time) string {
	if !completed.IsZero() && completed.After(now) {
		return "collection completion is in the future; current health is unknown"
	}
	for _, observation := range current {
		if observation.ObservedAt.IsZero() || observation.ObservedAt.After(now) || !observation.CollectedAt.IsZero() && observation.CollectedAt.After(now) {
			return "observation time is missing or in the future; current health is unknown"
		}
		if !domain.ValidGPUHealthObservation(observation) {
			return "sensor value, unit or semantics is invalid; current health is unknown"
		}
		explicit := observation.Semantics
		for _, other := range group.observations {
			if other.Metric != observation.Metric || !other.ObservedAt.Equal(observation.ObservedAt) {
				continue
			}
			if other.Value != observation.Value || !domain.ValidGPUHealthObservation(other) || !compatibleHealthSemantics(explicit, other.Semantics) {
				return "conflicting sensor evidence at the same timestamp; current health is unknown"
			}
			if other.Semantics != nil {
				explicit = other.Semantics
			}
		}
	}
	return ""
}

func compatibleHealthSemantics(a, b *domain.MetricSemantics) bool {
	// Older observations lack metadata. Its absence is not a contradiction of
	// the reviewed sensor contract, but two explicit contracts must agree.
	return a == nil || b == nil || *a == *b
}

func counterResetObserved(current domain.Observation, history []domain.Observation) bool {
	if current.Semantics != nil && current.Semantics.ResetObserved {
		return true
	}
	var prior *domain.Observation
	for i := range history {
		candidate := &history[i]
		if candidate.Metric == current.Metric && candidate.ObservedAt.Equal(current.ObservedAt) && candidate.Semantics != nil && candidate.Semantics.ResetObserved {
			return true
		}
		if candidate.Metric == current.Metric && candidate.ObservedAt.Before(current.ObservedAt) && domain.ValidGPUHealthObservation(*candidate) && (prior == nil || candidate.ObservedAt.After(prior.ObservedAt)) {
			prior = candidate
		}
	}
	return prior != nil && current.Value < prior.Value
}

func currentECCHealthEvidence(base domain.HealthSignal, group healthGroup, current []domain.Observation, now, completed time.Time, thresholds GPUHealthThresholds) ([]domain.Observation, []domain.HealthSignal) {
	usableMetrics := map[string]bool{}
	uncertain := []domain.HealthSignal{}
	for _, observation := range current {
		field := group
		field.observations = nil
		for _, candidate := range group.observations {
			if candidate.Metric == observation.Metric {
				field.observations = append(field.observations, candidate)
			}
		}
		reason := invalidCurrentHealthEvidence(field, []domain.Observation{observation}, now, completed)
		state := signalForGroup(base, field, observation.ObservedAt)
		if reason != "" {
			state.Type, state.Severity, state.Freshness, state.Reason = domain.HealthSignalPartial, domain.HealthSeverityUnknown, domain.FreshnessUnknown, reason
		} else if domain.FreshnessAt(&observation.ObservedAt, now, thresholds.FreshFor) == domain.FreshnessStale {
			state.Type, state.Severity, state.Freshness, state.Reason = domain.HealthSignalStale, domain.HealthSeverityUnknown, domain.FreshnessStale, "sensor observation is outside the freshness window"
		} else {
			usableMetrics[observation.Metric] = true
			continue
		}
		state.Evidence = []domain.ObservationID{observation.ID}
		uncertain = append(uncertain, state)
	}
	usable := []domain.Observation{}
	for _, observation := range group.observations {
		if usableMetrics[observation.Metric] {
			usable = append(usable, observation)
		}
	}
	return usable, uncertain
}

func evaluateECCGroup(signal domain.HealthSignal, group healthGroup, values []domain.Observation) (domain.HealthSignal, bool) {
	severity := domain.HealthSeverityInfo
	reset, historical, boolean := false, false, false
	for _, observation := range values {
		definition, _ := domain.GPUHealthSensor(observation.Metric)
		if definition.Kind == "counter" {
			historical = historical || observation.Value > 0
			reset = reset || counterResetObserved(observation, group.observations)
		}
		if observation.Value > 0 {
			if definition.Unit == "boolean" {
				boolean = true
			}
			if definition.PositiveSeverity == domain.HealthSeverityCritical {
				severity = domain.HealthSeverityCritical
			} else if severity == domain.HealthSeverityInfo {
				severity = domain.HealthSeverityWarning
			}
		}
	}
	if severity == domain.HealthSeverityInfo && reset {
		signal.Type, signal.Severity, signal.Reason = domain.HealthSignalPartial, domain.HealthSeverityUnknown, "counter reset observed; the prior fault and counter epoch are unknown, with no proven delta or rate"
		signal.Evidence = observationIDs(values)
		return signal, true
	}
	signal.Severity = severity
	signal.Threshold = &domain.HealthThreshold{Operator: ">=", Value: 1, Unit: "count"}
	if boolean && !historical {
		signal.Threshold.Unit = "boolean"
	}
	if severity == domain.HealthSeverityInfo {
		signal.Type = domain.HealthSignalNormal
		signal.Reason = "available ECC/remap fields are zero; missing fields and unknown counter epochs are not cleared"
	} else if historical {
		signal.Reason = "historical ECC/remapped-row count is positive; epoch is unknown and no new delta, rate or active error is proven"
		if boolean {
			signal.Reason += "; row-remap failure state is asserted"
		}
	} else {
		signal.Reason = "row-remap failure state is asserted"
	}
	if reset {
		signal.Reason += "; counter reset observed"
	}
	for _, observation := range values {
		definition, _ := domain.GPUHealthSensor(observation.Metric)
		matches := observation.Value > 0 && (severity != domain.HealthSeverityCritical || definition.PositiveSeverity == domain.HealthSeverityCritical)
		if severity == domain.HealthSeverityInfo {
			matches = observation.Value == 0
		}
		if matches {
			signal.Evidence = append(signal.Evidence, observation.ID)
		} else {
			signal.CounterEvidence = append(signal.CounterEvidence, observation.ID)
		}
	}
	// Category/API severities remain unchanged; the reason carries the exact
	// distinction between an asserted boolean and historical count evidence.
	signal.Reason = strings.TrimSpace(signal.Reason)
	return signal, true
}

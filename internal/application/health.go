package application

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const healthSignalSchemaVersion = 1

type GPUHealthThresholds struct {
	FreshFor               time.Duration
	ThermalWarningCelsius  float64
	ThermalCriticalCelsius float64
	MemoryWarningPercent   float64
	MemoryCriticalPercent  float64
	PowerWarningPercent    float64
	PowerCriticalPercent   float64
	UtilizationHighPercent float64
}

func DefaultGPUHealthThresholds() GPUHealthThresholds {
	return GPUHealthThresholds{
		FreshFor:              2 * time.Minute,
		ThermalWarningCelsius: 80, ThermalCriticalCelsius: 85,
		MemoryWarningPercent: 90, MemoryCriticalPercent: 95,
		PowerWarningPercent: 90, PowerCriticalPercent: 100,
		UtilizationHighPercent: 95,
	}
}

func (t GPUHealthThresholds) Validate() error {
	if t.FreshFor <= 0 {
		return fmt.Errorf("health freshness window must be positive")
	}
	for name, pair := range map[string][2]float64{
		"thermal": {t.ThermalWarningCelsius, t.ThermalCriticalCelsius},
		"memory":  {t.MemoryWarningPercent, t.MemoryCriticalPercent},
		"power":   {t.PowerWarningPercent, t.PowerCriticalPercent},
	} {
		if math.IsNaN(pair[0]) || math.IsNaN(pair[1]) || math.IsInf(pair[0], 0) || math.IsInf(pair[1], 0) || pair[0] <= 0 || pair[1] <= pair[0] {
			return fmt.Errorf("%s health thresholds require a positive warning below critical", name)
		}
	}
	if math.IsNaN(t.UtilizationHighPercent) || math.IsInf(t.UtilizationHighPercent, 0) || t.UtilizationHighPercent <= 0 || t.UtilizationHighPercent > 100 {
		return fmt.Errorf("utilization threshold must be in (0, 100]")
	}
	return nil
}

// ProjectGPUHealth converts a collection result into stable, sorted signals.
// It does not invent health for absent metrics, and it does not treat a stale
// incident reading as proof of a current incident.
func ProjectGPUHealth(result domain.CollectionResult, now time.Time, thresholds GPUHealthThresholds) ([]domain.HealthSignal, error) {
	if err := thresholds.Validate(); err != nil {
		return nil, err
	}
	now = now.UTC()
	base := signalBase(result, now)
	if result.Status == domain.ResultFailed {
		base.Type, base.Severity, base.Reason = domain.HealthSignalUnavailable, domain.HealthSeverityUnknown, "collection failed"
		if len(result.Failures) > 0 {
			base.Reason = string(result.Failures[0].Code)
		}
		return []domain.HealthSignal{base}, nil
	}
	supportSignals := gpuSupportSignals(result, base)
	if result.Status == domain.ResultNoData || len(result.Observations) == 0 {
		if len(supportSignals) > 0 {
			return supportSignals, nil
		}
		base.Type, base.Severity, base.Reason = domain.HealthSignalNoData, domain.HealthSeverityUnknown, "collection returned no observations"
		return []domain.HealthSignal{base}, nil
	}

	groups, rejected := groupHealthObservations(result)
	if len(groups) == 0 {
		if len(supportSignals) > 0 {
			return supportSignals, nil
		}
		base.Type, base.Severity, base.Reason = domain.HealthSignalNoData, domain.HealthSeverityUnknown, "collection contained no supported GPU health observations"
		return []domain.HealthSignal{base}, nil
	}

	partial := result.Status == domain.ResultPartial || !result.Coverage.Complete || coverageShort(result.Coverage) || rejected || len(supportSignals) > 0
	signals := append([]domain.HealthSignal{}, supportSignals...)
	if partial {
		state := base
		state.Type, state.Severity, state.Reason = domain.HealthSignalPartial, domain.HealthSeverityUnknown, "collection coverage is incomplete"
		signals = append(signals, state)
	}
	for _, group := range groups {
		latest := latestObservationTime(group.observations)
		current := currentObservations(group.observations)
		groupPartial := partial
		if group.category == domain.HealthSignalECC {
			usable, uncertain := currentECCHealthEvidence(base, group, current, now, result.CompletedAt, thresholds)
			signals = append(signals, uncertain...)
			groupPartial = groupPartial || len(uncertain) > 0
			if len(usable) == 0 {
				continue
			}
			group.observations = usable
			current = currentObservations(usable)
			latest = latestObservationTime(current)
		}
		if reason := invalidCurrentHealthEvidence(group, current, now, result.CompletedAt); reason != "" {
			state := signalForGroup(base, group, latest)
			state.Type, state.Severity, state.Freshness = domain.HealthSignalPartial, domain.HealthSeverityUnknown, domain.FreshnessUnknown
			state.Evidence, state.Reason = observationIDs(current), reason
			signals = append(signals, state)
			continue
		}
		freshnessBasis := oldestObservationTime(current)
		if domain.FreshnessAt(&freshnessBasis, now, thresholds.FreshFor) == domain.FreshnessStale {
			state := signalForGroup(base, group, latest)
			state.Type, state.Severity, state.Freshness = domain.HealthSignalStale, domain.HealthSeverityUnknown, domain.FreshnessStale
			state.Evidence = observationIDs(current)
			state.Reason = "latest observation is outside the freshness window"
			signals = append(signals, state)
			continue
		}
		signal, evaluable := evaluateGroup(base, group, latest, thresholds)
		if !evaluable {
			signal.Type, signal.Severity = domain.HealthSignalPartial, domain.HealthSeverityUnknown
			signal.Evidence = observationIDs(group.observations)
			signal.Reason = "metric requires missing companion evidence"
			signals = append(signals, signal)
			continue
		}
		if groupPartial && signal.Type == domain.HealthSignalNormal {
			continue
		}
		signals = append(signals, signal)
	}
	if len(signals) == 0 {
		base.Type, base.Severity, base.Reason = domain.HealthSignalNoData, domain.HealthSeverityUnknown, "no current health conclusion"
		signals = append(signals, base)
	}
	sort.SliceStable(signals, func(i, j int) bool {
		if signals[i].EntityKey != signals[j].EntityKey {
			return signals[i].EntityKey < signals[j].EntityKey
		}
		if signals[i].Type != signals[j].Type {
			return signals[i].Type < signals[j].Type
		}
		return signals[i].Metric < signals[j].Metric
	})
	return signals, nil
}

type healthGroup struct {
	entity       string
	category     domain.HealthSignalType
	sensor       string
	observations []domain.Observation
}

func groupHealthObservations(result domain.CollectionResult) ([]healthGroup, bool) {
	byKey := make(map[string]*healthGroup)
	rejected := false
	for _, observation := range result.Observations {
		category := metricCategory(observation.Metric)
		if category == "" {
			continue
		}
		identity, valid := domain.ResolveGPUObservationIdentity(result.Task.ClusterID, result.Task.SourceID, observation)
		if !valid || result.Task.Node != "" && string(identity.NodeID) != result.Task.Node {
			rejected = true
			continue
		}
		observation.EntityKey = identity.EntityKey
		if state, present := healthFieldSupport(result.Coverage.MetricFields, identity, observation.Metric); present && state != "SUPPORTED" {
			rejected = true
			continue
		}
		sensor := ""
		if category == domain.HealthSignalThermal {
			definition, _ := domain.GPUHealthSensor(observation.Metric)
			sensor = definition.Sensor
		}
		key := observation.EntityKey + "\x00" + string(category) + "\x00" + sensor
		group := byKey[key]
		if group == nil {
			group = &healthGroup{entity: observation.EntityKey, category: category, sensor: sensor}
			byKey[key] = group
		}
		group.observations = append(group.observations, observation)
	}
	groups := make([]healthGroup, 0, len(byKey))
	for _, group := range byKey {
		sort.SliceStable(group.observations, func(i, j int) bool {
			if !group.observations[i].ObservedAt.Equal(group.observations[j].ObservedAt) {
				return group.observations[i].ObservedAt.Before(group.observations[j].ObservedAt)
			}
			return group.observations[i].ID < group.observations[j].ID
		})
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].entity != groups[j].entity {
			return groups[i].entity < groups[j].entity
		}
		if groups[i].category != groups[j].category {
			return groups[i].category < groups[j].category
		}
		return groups[i].sensor < groups[j].sensor
	})
	return groups, rejected
}

func metricCategory(metric string) domain.HealthSignalType {
	definition, _ := domain.GPUHealthSensor(metric)
	return definition.Category
}

func evaluateGroup(base domain.HealthSignal, group healthGroup, latest time.Time, thresholds GPUHealthThresholds) (domain.HealthSignal, bool) {
	signal := signalForGroup(base, group, latest)
	current := latestByMetric(group.observations)
	values := make([]domain.Observation, 0, len(current))
	for _, observation := range current {
		values = append(values, observation)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })

	var value float64
	var warning, critical float64
	unit := ""
	switch group.category {
	case domain.HealthSignalXID:
		warning, critical, unit = 1, 1, "count"
		value = maximum(values)
	case domain.HealthSignalECC:
		return evaluateECCGroup(signal, group, values)
	case domain.HealthSignalThermal:
		value, warning, critical, unit = maximum(values), thresholds.ThermalWarningCelsius, thresholds.ThermalCriticalCelsius, "celsius"
	case domain.HealthSignalMemory:
		var ok bool
		value, ok = percentage(values, "DCGM_FI_DEV_FB_USED", "DCGM_FI_DEV_FB_FREE", "DCGM_FI_DEV_FB_TOTAL")
		if !ok {
			return signal, false
		}
		warning, critical, unit = thresholds.MemoryWarningPercent, thresholds.MemoryCriticalPercent, "percent"
	case domain.HealthSignalPower:
		var ok bool
		value, ok = percentage(values, "DCGM_FI_DEV_POWER_USAGE", "", "DCGM_FI_DEV_POWER_MGMT_LIMIT")
		if !ok {
			return signal, false
		}
		warning, critical, unit = thresholds.PowerWarningPercent, thresholds.PowerCriticalPercent, "percent"
	case domain.HealthSignalUtilization:
		value, warning, critical, unit = maximum(values), thresholds.UtilizationHighPercent, thresholds.UtilizationHighPercent, "percent"
	}

	threshold := warning
	severity := domain.HealthSeverityInfo
	if value >= critical && group.category != domain.HealthSignalUtilization {
		threshold, severity = critical, domain.HealthSeverityCritical
	} else if value >= warning {
		severity = domain.HealthSeverityWarning
	}
	if value < warning {
		signal.Type = domain.HealthSignalNormal
		signal.Severity = domain.HealthSeverityInfo
		signal.Reason = fmt.Sprintf("%s metric is below the warning threshold", strings.ToLower(string(group.category)))
	} else {
		signal.Severity = severity
		signal.Reason = fmt.Sprintf("%s metric meets the %s threshold", strings.ToLower(string(group.category)), strings.ToLower(string(severity)))
	}
	if group.category == domain.HealthSignalThermal {
		signal.Reason = strings.ReplaceAll(group.sensor, "_", " ") + ": " + signal.Reason
	}
	if group.category == domain.HealthSignalXID && value >= warning {
		signal.Reason = "latest XID code is nonzero; this gauge does not establish new event identity, count or frequency"
	}
	signal.Threshold = &domain.HealthThreshold{Operator: ">=", Value: threshold, Unit: unit}
	for _, observation := range values {
		if observationSupports(group.category, observation, warning, critical, severity, values) {
			signal.Evidence = append(signal.Evidence, observation.ID)
		} else {
			signal.CounterEvidence = append(signal.CounterEvidence, observation.ID)
		}
	}
	return signal, true
}

func observationSupports(category domain.HealthSignalType, observation domain.Observation, warning, critical float64, severity domain.HealthSeverity, all []domain.Observation) bool {
	value := observation.Value
	if category == domain.HealthSignalMemory {
		percentage, ok := percentage(all, "DCGM_FI_DEV_FB_USED", "DCGM_FI_DEV_FB_FREE", "DCGM_FI_DEV_FB_TOTAL")
		if !ok {
			return false
		}
		value = percentage
	}
	if category == domain.HealthSignalPower {
		percentage, ok := percentage(all, "DCGM_FI_DEV_POWER_USAGE", "", "DCGM_FI_DEV_POWER_MGMT_LIMIT")
		if !ok {
			return false
		}
		value = percentage
	}
	if severity == domain.HealthSeverityCritical {
		return value >= critical
	}
	if severity == domain.HealthSeverityWarning {
		return value >= warning
	}
	return value < warning
}

func percentage(observations []domain.Observation, usedToken, freeToken, totalToken string) (float64, bool) {
	var used, free, total *float64
	for i := range observations {
		observation := &observations[i]
		metric := observation.Metric
		switch {
		case usedToken != "" && metric == usedToken:
			used = &observation.Value
		case freeToken != "" && metric == freeToken:
			free = &observation.Value
		case totalToken != "" && metric == totalToken:
			total = &observation.Value
		}
	}
	if used == nil {
		return 0, false
	}
	if total != nil && free != nil && *used+*free > *total {
		return 0, false
	}
	if total != nil && *total > 0 {
		if usedToken == "DCGM_FI_DEV_FB_USED" && *used > *total {
			return 0, false
		}
		return *used / *total * 100, true
	}
	if free != nil && *used+*free > 0 {
		return *used / (*used + *free) * 100, true
	}
	return 0, false
}

func latestByMetric(observations []domain.Observation) map[string]domain.Observation {
	latest := make(map[string]domain.Observation)
	for _, observation := range observations {
		previous, exists := latest[observation.Metric]
		if !exists || observation.ObservedAt.After(previous.ObservedAt) || (observation.ObservedAt.Equal(previous.ObservedAt) && observation.ID > previous.ID) {
			latest[observation.Metric] = observation
		}
	}
	return latest
}

func currentObservations(observations []domain.Observation) []domain.Observation {
	latest := latestByMetric(observations)
	current := make([]domain.Observation, 0, len(latest))
	for _, observation := range latest {
		current = append(current, observation)
	}
	sort.Slice(current, func(i, j int) bool { return current[i].ID < current[j].ID })
	return current
}

func maximum(observations []domain.Observation) float64 {
	maximum := observations[0].Value
	for _, observation := range observations[1:] {
		if observation.Value > maximum {
			maximum = observation.Value
		}
	}
	return maximum
}

func signalBase(result domain.CollectionResult, now time.Time) domain.HealthSignal {
	entity := "cluster/" + string(result.Task.ClusterID)
	if result.Task.Node != "" {
		entity = "node/" + result.Task.Node
	}
	return domain.HealthSignal{SchemaVersion: healthSignalSchemaVersion, ClusterID: result.Task.ClusterID, SourceID: result.Task.SourceID, EntityKey: entity, ProjectedAt: now, Freshness: domain.FreshnessUnknown, Coverage: result.Coverage}
}

func signalForGroup(base domain.HealthSignal, group healthGroup, observedAt time.Time) domain.HealthSignal {
	base.Type, base.Category, base.EntityKey, base.ObservedAt, base.Freshness = group.category, group.category, group.entity, observedAt.UTC(), domain.FreshnessFresh
	base.Metric = group.observations[0].Metric
	for _, observation := range group.observations[1:] {
		if observation.Metric != base.Metric {
			base.Metric = ""
			break
		}
	}
	return base
}

func latestObservationTime(observations []domain.Observation) time.Time {
	latest := observations[0].ObservedAt.UTC()
	for _, observation := range observations[1:] {
		if observation.ObservedAt.After(latest) {
			latest = observation.ObservedAt.UTC()
		}
	}
	return latest
}

func oldestObservationTime(observations []domain.Observation) time.Time {
	oldest := observations[0].ObservedAt.UTC()
	for _, observation := range observations[1:] {
		if observation.ObservedAt.Before(oldest) {
			oldest = observation.ObservedAt.UTC()
		}
	}
	return oldest
}

func observationIDs(observations []domain.Observation) []domain.ObservationID {
	ids := make([]domain.ObservationID, 0, len(observations))
	for _, observation := range observations {
		ids = append(ids, observation.ID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func coverageShort(coverage domain.Coverage) bool {
	return coverage.SeriesExpected != nil && coverage.SeriesReturned < *coverage.SeriesExpected
}

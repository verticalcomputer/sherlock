package testbed

import (
	"encoding/json"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
)

type DetectionResult struct {
	Scope          string `json:"scope"`
	Measured       bool   `json:"measured"`
	Opened         bool   `json:"opened"`
	LatencySeconds int64  `json:"latency_seconds,omitempty"`
	Note           string `json:"note,omitempty"`
}

func detect(s Scenario) (DetectionResult, error) {
	if s.Detection.Kind == "not_exercised" {
		return DetectionResult{Scope: "NOT_EXERCISED", Note: "Investigation evidence is simulated; this scenario does not qualify its production detector or incident bridge."}, nil
	}
	end := s.World.End
	policy := monitoring.Policy{ID: "testbed-policy", Revision: 1, ClusterID: "cluster", SourceID: "source", EntityKey: "cluster/GPU/node-1/GPU-a/", Rule: monitoring.RuleGPUThermal, RuleVersion: 1, Metric: "DCGM_FI_DEV_GPU_TEMP", Unit: "celsius", Binding: monitoring.Binding{Operation: domain.OperationPrometheusGPUTemperature, Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{"node-1"}}, ScheduleRevision: 1, InventoryRevisionID: "inventory-1"}, EnrolledAt: end.Add(-10 * time.Minute), FreshForSeconds: 300, ConfirmCount: 2, ConfirmWindowSeconds: 180, ConfirmMinDurationSeconds: 30, RecoverCount: 2, RecoverWindowSeconds: 180, RecoverMinDurationSeconds: 30, MaxSampleGapSeconds: 30, OpenThreshold: 80, RecoverBelow: 70, Severity: domain.HealthSeverityCritical}
	if s.Detection.Kind == "telemetry_loss" {
		policy.Rule = monitoring.RuleTelemetryLoss
		policy.EntityKey = "source/source"
		policy.Metric = ""
		policy.Unit = ""
		policy.ConfirmCount = 1
		policy.ConfirmMinDurationSeconds = 0
		policy.OpenThreshold = 0
		policy.RecoverBelow = 0
		policy.FreshForSeconds = 60
		policy.EnrolledAt = end.Add(-time.Minute)
		decision, err := monitoring.Evaluate(policy, monitoring.State{}, monitoring.Input{At: end, AuthorityValid: true})
		result := DetectionResult{Scope: "PRODUCTION_EVALUATOR_ONLY", Measured: true, Opened: decision.Transition != nil, Note: "Evaluated with no new samples; durable enrollment, episode/outbox and notification delivery are not exercised."}
		if decision.Transition != nil {
			result.LatencySeconds = int64(decision.Transition.At.Sub(policy.EnrolledAt).Seconds())
		}
		return result, err
	}
	var state monitoring.State
	result := DetectionResult{Scope: "PRODUCTION_EVALUATOR_ONLY", Measured: true, Note: "Absolute thermal threshold only; power-matched cooling and the incident bridge are not qualified."}
	for i, at := range []time.Time{end.Add(-30 * time.Second), end} {
		observation := domain.Observation{ID: domain.ObservationID([]string{"sample-a", "sample-b"}[i]), ClusterID: policy.ClusterID, SourceID: policy.SourceID, EntityKey: policy.EntityKey, Metric: policy.Metric, Value: *s.Detection.Temperature, Unit: policy.Unit, ObservedAt: at, CollectedAt: at}
		run := monitoring.RunEvidence{RunID: domain.RunID(observation.ID), ClusterID: policy.ClusterID, SourceID: policy.SourceID, Binding: policy.Binding, CompletedAt: at, Status: domain.ResultSucceeded, CoverageComplete: true, Count: 1, FieldState: "SUPPORTED"}
		sample := monitoring.Sample{Observation: observation, RunID: run.RunID, CollectionCompletedAt: at, Status: run.Status, Supported: true, CoverageComplete: true}
		decision, err := monitoring.Evaluate(policy, state, monitoring.Input{At: at, AuthorityValid: true, Samples: []monitoring.Sample{sample}, Runs: []monitoring.RunEvidence{run}})
		if err != nil {
			return result, err
		}
		// Round-trip state to exercise the durable JSON contract between samples.
		raw, _ := json.Marshal(decision.State)
		if err = json.Unmarshal(raw, &state); err != nil {
			return result, err
		}
		if decision.Transition != nil {
			result.Opened = true
			result.LatencySeconds = int64(decision.Transition.At.Sub(end.Add(-30 * time.Second)).Seconds())
		}
	}
	return result, nil
}

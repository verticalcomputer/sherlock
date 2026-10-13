package domain

import (
	"fmt"
	"slices"
	"strings"
)

const XIDEvidenceDefinitionVersion = "prometheus-dcgm-xid-v1"

// XIDEvidenceForCollection projects one fixed, allow-listed DCGM XID
// collection into immutable evidence metadata. The normalized observations
// remain in PostgreSQL under the referenced run; no Prometheus credential,
// endpoint, or arbitrary query text enters the envelope.
func XIDEvidenceForCollection(result CollectionResult) (EvidenceEnvelope, bool, error) {
	if result.Task.Query != QueryGPUXID {
		return EvidenceEnvelope{}, false, nil
	}
	if result.Task.RunID == "" || result.Task.ClusterID == "" || result.Task.SourceID == "" || result.CompletedAt.IsZero() {
		return EvidenceEnvelope{}, false, fmt.Errorf("XID collection evidence identity is incomplete")
	}
	status, err := xidEvidenceStatus(result)
	if err != nil {
		return EvidenceEnvelope{}, false, err
	}
	coveredTargets := make([]EvidenceTarget, 0, len(result.Observations)*2)
	seen := make(map[EvidenceTarget]struct{}, len(result.Observations)*2)
	for _, observation := range result.Observations {
		if observation.ClusterID != result.Task.ClusterID || observation.SourceID != result.Task.SourceID || observation.Metric != "DCGM_FI_DEV_XID_ERRORS" {
			return EvidenceEnvelope{}, false, fmt.Errorf("XID evidence contains an unrelated observation")
		}
		for _, target := range xidObservationTargets(observation) {
			if _, exists := seen[target]; exists {
				continue
			}
			seen[target] = struct{}{}
			coveredTargets = append(coveredTargets, target)
		}
	}
	targets := slices.Clone(result.Coverage.ExpectedTargets)
	if len(targets) == 0 {
		targets = slices.Clone(coveredTargets)
	}
	expected := make(map[EvidenceTarget]struct{}, len(targets))
	for _, target := range targets {
		expected[target] = struct{}{}
	}
	covered := slices.DeleteFunc(coveredTargets, func(target EvidenceTarget) bool {
		_, ok := expected[target]
		return !ok
	})
	slices.SortFunc(targets, func(left, right EvidenceTarget) int {
		if left.Kind != right.Kind {
			return strings.Compare(string(left.Kind), string(right.Kind))
		}
		return strings.Compare(string(left.ID), string(right.ID))
	})
	slices.SortFunc(covered, func(left, right EvidenceTarget) int {
		if left.Kind != right.Kind {
			return strings.Compare(string(left.Kind), string(right.Kind))
		}
		return strings.Compare(string(left.ID), string(right.ID))
	})
	if status == EvidenceUnavailable {
		covered = nil
	}
	observed := xidEvidenceTimeRange(result)
	digest := ChecksumSHA256([]byte("xid-evidence-v1\x00" + string(result.Task.ClusterID) + "\x00" + string(result.Task.SourceID) + "\x00" + string(result.Task.RunID)))
	envelope, err := CreateEvidenceEnvelope(NewEvidenceEnvelope{
		ID: EvidenceID("xid-" + digest.String()), SchemaVersion: EvidenceSchemaVersion,
		ClusterID: result.Task.ClusterID, Status: status,
		Source: EvidenceSourceReference{
			SourceID: result.Task.SourceID, RunID: result.Task.RunID,
			Operation: EvidenceOperationID(QueryGPUXID), DefinitionVersion: XIDEvidenceDefinitionVersion,
			Reference: "prometheus:allowlist:DCGM_FI_DEV_XID_ERRORS",
		},
		TimeRange: observed, CollectedAt: result.CompletedAt,
		Coverage: EvidenceCoverage{Expected: targets, Covered: covered},
	})
	if err != nil {
		return EvidenceEnvelope{}, false, fmt.Errorf("build XID collection evidence: %w", err)
	}
	return envelope, true, nil
}

func xidEvidenceStatus(result CollectionResult) (EvidenceStatus, error) {
	// A complete Prometheus response does not prove complete fleet coverage.
	// Some DCGM deployments expose XID series only for a subset of GPUs. Only
	// claim COMPLETE/NO_DATA when the collector was given an explicit expected
	// series cardinality and returned all of it; otherwise preserve the useful
	// observations as PARTIAL evidence.
	seriesComplete := result.Coverage.Complete && result.Coverage.SeriesExpected != nil &&
		*result.Coverage.SeriesExpected == result.Coverage.SeriesReturned
	switch result.Status {
	case ResultSucceeded:
		if seriesComplete {
			return EvidenceComplete, nil
		}
		return EvidencePartial, nil
	case ResultNoData:
		if seriesComplete && result.Coverage.SeriesReturned == 0 {
			return EvidenceNoData, nil
		}
		return EvidencePartial, nil
	case ResultPartial:
		return EvidencePartial, nil
	case ResultFailed:
		return EvidenceUnavailable, nil
	default:
		return "", fmt.Errorf("unknown XID collection result status %q", result.Status)
	}
}

func xidEvidenceTimeRange(result CollectionResult) EvidenceTimeRange {
	if result.Task.Range != nil {
		return EvidenceTimeRange{Start: result.Task.Range.Start, End: result.Task.Range.End}
	}
	start, end := result.Task.ScheduledFor, result.Task.ScheduledFor
	for index, observation := range result.Observations {
		if index == 0 || observation.ObservedAt.Before(start) {
			start = observation.ObservedAt
		}
		if index == 0 || observation.ObservedAt.After(end) {
			end = observation.ObservedAt
		}
	}
	return EvidenceTimeRange{Start: start, End: end}
}

func xidObservationTargets(observation Observation) []EvidenceTarget {
	labels := make(map[string]string, len(observation.Labels))
	for _, label := range observation.Labels {
		labels[label.Name] = label.Value
	}
	host := labels["Hostname"]
	if host == "" {
		host = labels["hostname"]
	}
	gpu := labels["UUID"]
	if gpu == "" {
		gpu = labels["uuid"]
	}
	result := make([]EvidenceTarget, 0, 2)
	if validInvestigationToken(host) {
		result = append(result, EvidenceTarget{Kind: EvidenceTargetNode, ID: EvidenceTargetID(host)})
	}
	if validInvestigationToken(gpu) {
		result = append(result, EvidenceTarget{Kind: EvidenceTargetGPU, ID: EvidenceTargetID(gpu)})
	}
	return result
}

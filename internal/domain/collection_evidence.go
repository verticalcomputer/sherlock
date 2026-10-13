package domain

import (
	"fmt"
	"slices"
	"strings"
)

const CollectionEvidenceDefinitionVersion = "prometheus-collection-evidence-v1"

// CollectionEvidenceForCollection projects every fixed, allow-listed
// collection class into immutable evidence. XID retains its specialized
// projection and sticky-gauge semantics.
func CollectionEvidenceForCollection(result CollectionResult) (EvidenceEnvelope, bool, error) {
	if result.Task.Query == QueryGPUXID {
		return XIDEvidenceForCollection(result)
	}
	if err := result.Task.Query.Validate(); err != nil {
		return EvidenceEnvelope{}, false, nil
	}
	if result.Task.RunID == "" || result.Task.ClusterID == "" || result.Task.SourceID == "" || result.CompletedAt.IsZero() {
		return EvidenceEnvelope{}, false, fmt.Errorf("collection evidence identity is incomplete")
	}
	status, err := collectionEvidenceStatus(result)
	if err != nil {
		return EvidenceEnvelope{}, false, err
	}
	coveredTargets := make([]EvidenceTarget, 0, len(result.Observations)*2)
	coveredSeen := make(map[EvidenceTarget]struct{}, len(result.Observations)*2)
	for _, observation := range result.Observations {
		if observation.ClusterID != result.Task.ClusterID || observation.SourceID != result.Task.SourceID {
			return EvidenceEnvelope{}, false, fmt.Errorf("collection evidence contains an unrelated observation")
		}
		for _, target := range CollectionObservationTargets(result.Task.Query, observation) {
			if _, exists := coveredSeen[target]; exists {
				continue
			}
			coveredSeen[target], coveredTargets = struct{}{}, append(coveredTargets, target)
		}
	}
	targets := slices.Clone(result.Coverage.ExpectedTargets)
	// Preserve useful observed scope when no authoritative inventory exists,
	// while keeping the envelope PARTIAL because SeriesExpected is absent.
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
	digest := ChecksumSHA256([]byte("collection-evidence-v1\x00" + string(result.Task.ClusterID) + "\x00" + string(result.Task.SourceID) + "\x00" + string(result.Task.RunID) + "\x00" + string(result.Task.Query)))
	envelope, err := CreateEvidenceEnvelope(NewEvidenceEnvelope{
		ID: EvidenceID("collection-" + digest.String()), SchemaVersion: EvidenceSchemaVersion,
		ClusterID: result.Task.ClusterID, Status: status,
		Source: EvidenceSourceReference{
			SourceID: result.Task.SourceID, RunID: result.Task.RunID,
			Operation: EvidenceOperationID(result.Task.Query), DefinitionVersion: CollectionEvidenceDefinitionVersion,
			Reference: EvidenceSourceLocator("prometheus:allowlist:" + string(result.Task.Query)),
		},
		TimeRange: xidEvidenceTimeRange(result), CollectedAt: result.CompletedAt,
		Coverage: EvidenceCoverage{Expected: targets, Covered: covered},
	})
	if err != nil {
		return EvidenceEnvelope{}, false, fmt.Errorf("build collection evidence: %w", err)
	}
	return envelope, true, nil
}

// CollectionObservationTargets returns the independently observable targets
// named by one fixed Prometheus observation. Cluster identity is deliberately
// absent: a query response does not independently observe a cluster target.
func CollectionObservationTargets(query QueryKind, observation Observation) []EvidenceTarget {
	if query == QuerySourceHealth {
		for _, label := range observation.Labels {
			if label.Name == "instance" && validInvestigationToken(label.Value) {
				return []EvidenceTarget{{Kind: EvidenceTargetSource, ID: EvidenceTargetID(label.Value)}}
			}
		}
		return []EvidenceTarget{{Kind: EvidenceTargetSource, ID: EvidenceTargetID(observation.SourceID)}}
	}
	if query.IsGPU() {
		return xidObservationTargets(observation)
	}
	return nil
}

func collectionEvidenceStatus(result CollectionResult) (EvidenceStatus, error) {
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
		return "", fmt.Errorf("unknown collection result status %q", result.Status)
	}
}

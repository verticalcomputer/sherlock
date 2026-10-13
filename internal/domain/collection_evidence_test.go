package domain

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCollectionEvidenceProjectsGPUHealthWithConservativeCoverage(t *testing.T) {
	now := time.Date(2026, 8, 21, 2, 44, 0, 0, time.UTC)
	result := CollectionResult{
		Task:   CollectionTask{RunID: "run-gpu", ClusterID: "cluster-a", SourceID: "prometheus-a", Query: QueryGPUUtilization, ScheduledFor: now},
		Status: ResultSucceeded, CompletedAt: now.Add(time.Second), Coverage: Coverage{Complete: true, SeriesReturned: 1},
		Observations: []Observation{{ClusterID: "cluster-a", SourceID: "prometheus-a", Labels: []Label{{Name: "Hostname", Value: "node-1"}, {Name: "UUID", Value: "GPU-1"}}, ObservedAt: now}},
	}
	evidence, present, err := CollectionEvidenceForCollection(result)
	if err != nil || !present {
		t.Fatalf("evidence present=%v err=%v", present, err)
	}
	if evidence.Status() != EvidencePartial || evidence.Source().Operation != EvidenceOperationID(QueryGPUUtilization) {
		t.Fatalf("evidence status/source=%s/%s", evidence.Status(), evidence.Source().Operation)
	}
	coverage := evidence.Coverage()
	if len(coverage.Expected) != 2 || len(coverage.Covered) != 2 {
		t.Fatalf("coverage=%+v", coverage)
	}
	for _, target := range coverage.Expected {
		if target.Kind == EvidenceTargetCluster {
			t.Fatalf("cluster coverage was fabricated: %+v", coverage)
		}
	}
}

func TestCollectionEvidenceCompleteCoverageBecomesComplete(t *testing.T) {
	now := time.Date(2026, 8, 21, 2, 44, 0, 0, time.UTC)
	expectedSeries := 1
	expectedTargets := []EvidenceTarget{{Kind: EvidenceTargetNode, ID: "node-1"}, {Kind: EvidenceTargetGPU, ID: "GPU-1"}}
	result := CollectionResult{
		Task:   CollectionTask{RunID: "run-complete", ClusterID: "cluster-a", SourceID: "prometheus-a", Query: QueryGPUUtilization, ScheduledFor: now},
		Status: ResultSucceeded, CompletedAt: now.Add(time.Second),
		Coverage:     Coverage{Complete: true, SeriesExpected: &expectedSeries, SeriesReturned: 1, ExpectedTargets: expectedTargets},
		Observations: []Observation{{ClusterID: "cluster-a", SourceID: "prometheus-a", Labels: []Label{{Name: "Hostname", Value: "node-1"}, {Name: "UUID", Value: "GPU-1"}}, ObservedAt: now}},
	}
	evidence, present, err := CollectionEvidenceForCollection(result)
	if err != nil || !present || evidence.Status() != EvidenceComplete || !evidence.Coverage().Complete() {
		t.Fatalf("evidence=%+v present=%t err=%v", evidence, present, err)
	}
}

func TestCollectionEvidenceMissingGPUStaysPartialAndNamesTarget(t *testing.T) {
	now := time.Date(2026, 8, 21, 2, 44, 0, 0, time.UTC)
	expectedSeries := 2
	missing := EvidenceTarget{Kind: EvidenceTargetGPU, ID: "GPU-2"}
	result := CollectionResult{
		Task:   CollectionTask{RunID: "run-partial", ClusterID: "cluster-a", SourceID: "prometheus-a", Query: QueryGPUUtilization, ScheduledFor: now},
		Status: ResultSucceeded, CompletedAt: now.Add(time.Second),
		Coverage:     Coverage{Complete: true, SeriesExpected: &expectedSeries, SeriesReturned: 1, ExpectedTargets: []EvidenceTarget{{Kind: EvidenceTargetNode, ID: "node-1"}, {Kind: EvidenceTargetGPU, ID: "GPU-1"}, missing}},
		Observations: []Observation{{ClusterID: "cluster-a", SourceID: "prometheus-a", Labels: []Label{{Name: "Hostname", Value: "node-1"}, {Name: "UUID", Value: "GPU-1"}}, ObservedAt: now}},
	}
	evidence, _, err := CollectionEvidenceForCollection(result)
	if err != nil || evidence.Status() != EvidencePartial || slices.Contains(evidence.Coverage().Covered, missing) || !slices.Contains(evidence.Coverage().Expected, missing) {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
}

func TestCollectionEvidencePreservesSpecializedXIDProjection(t *testing.T) {
	now := time.Date(2026, 8, 21, 2, 44, 0, 0, time.UTC)
	result := CollectionResult{Task: CollectionTask{RunID: "run-xid", ClusterID: "cluster-a", SourceID: "prometheus-a", Query: QueryGPUXID, ScheduledFor: now}, Status: ResultNoData, CompletedAt: now.Add(time.Second)}
	evidence, present, err := CollectionEvidenceForCollection(result)
	if err != nil || !present || !strings.HasPrefix(string(evidence.ID()), "xid-") {
		t.Fatalf("specialized XID evidence=%s present=%v err=%v", evidence.ID(), present, err)
	}
}

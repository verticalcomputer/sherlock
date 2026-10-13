package domain

import (
	"testing"
	"time"
)

func TestXIDEvidenceForCollectionBuildsDeterministicBoundedCoverage(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	result := CollectionResult{
		Task:   CollectionTask{RunID: "run-1", ClusterID: "cluster-a", SourceID: "prometheus-a", Query: QueryGPUXID, ScheduledFor: now},
		Status: ResultSucceeded, CompletedAt: now.Add(time.Second), Coverage: Coverage{Complete: true, SeriesReturned: 2},
		Observations: []Observation{
			xidEvidenceObservation(now, "obs-1", "node-b", "GPU-b", 94),
			xidEvidenceObservation(now, "obs-2", "node-a", "GPU-a", 0),
		},
	}
	first, ok, err := XIDEvidenceForCollection(result)
	if err != nil || !ok {
		t.Fatalf("evidence ok=%t err=%v", ok, err)
	}
	second, _, _ := XIDEvidenceForCollection(result)
	if !first.Equal(second) || first.Status() != EvidencePartial || first.Source().Operation != EvidenceOperationID(QueryGPUXID) {
		t.Fatalf("unexpected evidence: %#v", first)
	}
	coverage := first.Coverage()
	if len(coverage.Expected) != 4 || len(coverage.Covered) != 4 || coverage.Expected[0].Kind == EvidenceTargetCluster {
		t.Fatalf("coverage=%+v", coverage)
	}
}

func TestXIDEvidenceForCollectionRequiresExplicitExpectedSeriesForComplete(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	expected := 1
	result := CollectionResult{
		Task:   CollectionTask{RunID: "run-1", ClusterID: "cluster-a", SourceID: "prometheus-a", Query: QueryGPUXID, ScheduledFor: now},
		Status: ResultSucceeded, CompletedAt: now.Add(time.Second),
		Coverage:     Coverage{Complete: true, SeriesExpected: &expected, SeriesReturned: 1},
		Observations: []Observation{xidEvidenceObservation(now, "obs-1", "node-a", "GPU-a", 94)},
	}
	evidence, ok, err := XIDEvidenceForCollection(result)
	if err != nil || !ok || evidence.Status() != EvidenceComplete {
		t.Fatalf("status=%s ok=%t err=%v", evidence.Status(), ok, err)
	}
}

func TestXIDEvidenceForCollectionPreservesNoDataAndUnavailable(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name   string
		result ResultStatus
		want   EvidenceStatus
	}{
		{name: "no data without expected fleet", result: ResultNoData, want: EvidencePartial},
		{name: "unavailable", result: ResultFailed, want: EvidenceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := CollectionResult{Task: CollectionTask{RunID: "run-1", ClusterID: "cluster-a", SourceID: "prometheus-a", Query: QueryGPUXID, ScheduledFor: now}, Status: test.result, CompletedAt: now.Add(time.Second)}
			evidence, ok, err := XIDEvidenceForCollection(result)
			if err != nil || !ok || evidence.Status() != test.want {
				t.Fatalf("status=%s ok=%t err=%v", evidence.Status(), ok, err)
			}
		})
	}
}

func xidEvidenceObservation(now time.Time, id ObservationID, host, uuid string, value float64) Observation {
	return Observation{ID: id, SchemaVersion: 1, ClusterID: "cluster-a", SourceID: "prometheus-a", Kind: "gpu_xid", EntityKey: "node/" + host + "/gpu/0", Metric: "DCGM_FI_DEV_XID_ERRORS", Labels: []Label{{Name: "UUID", Value: uuid}, {Name: "hostname", Value: host}}, Value: value, Unit: "xid_code", ObservedAt: now, CollectedAt: now.Add(time.Second), SourceReference: "prometheus:dcgm_gpu_xid"}
}

package domain

import (
	"math"
	"strings"
	"testing"
	"time"
)

func goodputTime() time.Time {
	return time.Date(2026, 9, 14, 14, 30, 0, 123456789, time.FixedZone("IST", 5*60*60+30*60))
}

func goodputNode() EntityIdentity {
	return EntityIdentity{ClusterID: "cluster-a", Kind: EntityNode, NodeID: "node-stable-01"}
}

func goodputGPU() EntityIdentity {
	return EntityIdentity{ClusterID: "cluster-a", Kind: EntityGPU, NodeID: "node-stable-01", PhysicalGPUUUID: "GPU-001"}
}

func goodputJob() JobIdentity {
	return JobIdentity{SchedulerNamespace: "slurm-prod", JobID: "12345", SubmitAt: goodputTime(), Attempt: 0}
}

func TestCreateEntityIdentity(t *testing.T) {
	tests := []struct {
		name     string
		identity EntityIdentity
		wantErr  string
	}{
		{name: "node", identity: goodputNode()},
		{name: "physical GPU", identity: goodputGPU()},
		{name: "MIG", identity: EntityIdentity{ClusterID: "cluster-a", Kind: EntityMIG, NodeID: "node-stable-01", PhysicalGPUUUID: "GPU-001", MIGIdentity: "MIG-001"}},
		{name: "GPU missing physical identity", identity: EntityIdentity{ClusterID: "cluster-a", Kind: EntityGPU, NodeID: "node-stable-01"}, wantErr: "physical GPU UUID"},
		{name: "node with GPU identity", identity: EntityIdentity{ClusterID: "cluster-a", Kind: EntityNode, NodeID: "node-stable-01", PhysicalGPUUUID: "GPU-001"}, wantErr: "cannot include"},
		{name: "unknown kind", identity: EntityIdentity{ClusterID: "cluster-a", Kind: "ASIC", NodeID: "node-stable-01"}, wantErr: "unknown entity kind"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity, err := CreateEntityIdentity(test.identity)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("CreateEntityIdentity() error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateEntityIdentity() error = %v", err)
			}
			if identity.Key() != test.identity.Key() {
				t.Fatalf("identity key = %q, want %q", identity.Key(), test.identity.Key())
			}
		})
	}
}

func TestCreateInventoryRevisionRejectsDuplicatesAndNormalizesUTC(t *testing.T) {
	now := goodputTime()
	revision, err := CreateInventoryRevision(InventoryRevision{
		SchemaVersion: InventoryContractSchemaVersion, ID: "inventory-r1", ClusterID: "cluster-a", SourceID: "slurm", SourceAt: now,
		EffectiveAt: now, ObservedAt: now, Entities: []EntityIdentity{goodputNode(), goodputGPU()},
	})
	if err != nil {
		t.Fatalf("CreateInventoryRevision() error = %v", err)
	}
	if revision.SourceAt.Location() != time.UTC || revision.EffectiveAt.Location() != time.UTC || revision.ObservedAt.Location() != time.UTC {
		t.Fatal("revision timestamps were not normalized to UTC")
	}
	_, err = CreateInventoryRevision(InventoryRevision{
		SchemaVersion: InventoryContractSchemaVersion, ID: "inventory-r2", ClusterID: "cluster-a", SourceID: "slurm", SourceAt: now,
		EffectiveAt: now, ObservedAt: now, Entities: []EntityIdentity{goodputNode(), goodputNode()},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate entity") {
		t.Fatalf("duplicate inventory error = %v", err)
	}
}

func TestCreateAllocationSnapshotUsesStableEntitiesAndExplicitUnknown(t *testing.T) {
	now := goodputTime()
	snapshot, err := CreateAllocationSnapshot(AllocationSnapshot{
		SchemaVersion: InventoryContractSchemaVersion, ClusterID: "cluster-a", SourceID: "slurm", Job: goodputJob(),
		State: AllocationSuspended, SourceAt: now, EffectiveAt: now.Add(-time.Minute), ObservedAt: now,
		Entities: []EntityIdentity{goodputGPU()},
	})
	if err != nil {
		t.Fatalf("CreateAllocationSnapshot() error = %v", err)
	}
	if snapshot.Job.SubmitAt.Location() != time.UTC || snapshot.EffectiveAt.Location() != time.UTC {
		t.Fatal("allocation timestamps were not normalized to UTC")
	}
	_, err = CreateAllocationSnapshot(AllocationSnapshot{
		SchemaVersion: InventoryContractSchemaVersion, ClusterID: "cluster-a", SourceID: "slurm", Job: goodputJob(),
		State: AllocationUnknown, SourceAt: now, EffectiveAt: now, ObservedAt: now, Entities: []EntityIdentity{goodputGPU()},
	})
	if err == nil || !strings.Contains(err.Error(), "cannot claim entities") {
		t.Fatalf("unknown allocation error = %v", err)
	}
}

func TestCreateSourceCoveragePreservesUnknownAndUnsupported(t *testing.T) {
	now := goodputTime()
	for _, coverage := range []SourceCoverage{
		{SchemaVersion: InventoryContractSchemaVersion, ClusterID: "cluster-a", SourceID: "loki", Scope: CoverageEvents, State: SourceCoverageUnknown, SourceAt: now, EffectiveAt: now, ObservedAt: now},
		{SchemaVersion: InventoryContractSchemaVersion, ClusterID: "cluster-a", SourceID: "redfish", Scope: CoverageInventory, State: SourceCoverageUnsupported, SourceAt: now, EffectiveAt: now, ObservedAt: now},
		{SchemaVersion: InventoryContractSchemaVersion, ClusterID: "cluster-a", SourceID: "prometheus", Scope: CoverageMetrics, State: SourceCoveragePartial, Expected: 8, Observed: 7, SourceAt: now, EffectiveAt: now, ObservedAt: now},
	} {
		accepted, err := CreateSourceCoverage(coverage)
		if err != nil {
			t.Fatalf("CreateSourceCoverage(%s) error = %v", coverage.State, err)
		}
		if accepted.State != coverage.State {
			t.Fatalf("coverage state = %s, want %s", accepted.State, coverage.State)
		}
	}
	_, err := CreateSourceCoverage(SourceCoverage{SchemaVersion: InventoryContractSchemaVersion, ClusterID: "cluster-a", SourceID: "prometheus", Scope: CoverageMetrics, State: SourceCoverageComplete, Expected: 8, Observed: 7, SourceAt: now, EffectiveAt: now, ObservedAt: now})
	if err == nil || !strings.Contains(err.Error(), "complete source coverage") {
		t.Fatalf("incomplete complete-coverage error = %v", err)
	}
}

func TestCreateProgressObservation(t *testing.T) {
	now := goodputTime()
	committed := 42.5
	measured, err := CreateProgressObservation(ProgressObservation{
		SchemaVersion: InventoryContractSchemaVersion, ClusterID: "cluster-a", SourceID: "workload-exporter", Job: goodputJob(), Cohort: "training-images",
		State: ProgressMeasured, Unit: "images", Committed: &committed, ResetEpoch: "checkpoint-9", SourceAt: now, EffectiveAt: now, ObservedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateProgressObservation() error = %v", err)
	}
	committed = 0
	if *measured.Committed != 42.5 || measured.ObservedAt.Location() != time.UTC {
		t.Fatalf("progress observation did not copy measurement or normalize UTC: %+v", measured)
	}
	for _, state := range []ProgressState{ProgressUnknown, ProgressUnmeasured, ProgressUnsupported} {
		accepted, err := CreateProgressObservation(ProgressObservation{
			SchemaVersion: InventoryContractSchemaVersion, ClusterID: "cluster-a", SourceID: "workload-exporter", Job: goodputJob(), Cohort: "training-images",
			State: state, SourceAt: now, EffectiveAt: now, ObservedAt: now,
		})
		if err != nil || accepted.Committed != nil {
			t.Fatalf("CreateProgressObservation(%s) = %+v, %v", state, accepted, err)
		}
	}
	_, err = CreateProgressObservation(ProgressObservation{
		SchemaVersion: InventoryContractSchemaVersion, ClusterID: "cluster-a", SourceID: "workload-exporter", Job: goodputJob(), Cohort: "training-images",
		State: ProgressMeasured, Unit: "images", SourceAt: now, EffectiveAt: now, ObservedAt: now,
	})
	if err == nil || !strings.Contains(err.Error(), "measured progress") {
		t.Fatalf("missing progress counter error = %v", err)
	}
	for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -1} {
		_, err := CreateProgressObservation(ProgressObservation{
			SchemaVersion: InventoryContractSchemaVersion, ClusterID: "cluster-a", SourceID: "workload-exporter", Job: goodputJob(), Cohort: "training-images",
			State: ProgressMeasured, Unit: "images", Committed: &value, ResetEpoch: "checkpoint-9", SourceAt: now, EffectiveAt: now, ObservedAt: now,
		})
		if err == nil {
			t.Fatalf("invalid committed output %v was accepted", value)
		}
	}
}

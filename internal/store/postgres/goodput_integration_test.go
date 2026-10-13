//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestGoodputStorePersistsImmutableScopedInventoryAndAllocations(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	clusterID := domain.ClusterID("goodput-cluster-" + suffix)
	otherClusterID := domain.ClusterID("goodput-other-cluster-" + suffix)
	expectedSource := domain.SourceID("goodput-expected-" + suffix)
	observedSource := domain.SourceID("goodput-observed-" + suffix)
	collections, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []domain.SourceID{expectedSource, observedSource} {
		if err := collections.EnsureSource(ctx, clusterID, "Goodput cluster", source, string(source)); err != nil {
			t.Fatal(err)
		}
	}
	if err := collections.EnsureSource(ctx, otherClusterID, "Other goodput cluster", domain.SourceID("goodput-other-source-"+suffix), "other"); err != nil {
		t.Fatal(err)
	}
	store, err := storepg.NewGoodputStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	entities := []domain.EntityIdentity{
		{ClusterID: clusterID, Kind: domain.EntityNode, NodeID: "node-a"},
		{ClusterID: clusterID, Kind: domain.EntityGPU, NodeID: "node-a", PhysicalGPUUUID: "GPU-a"},
	}
	firstExpected := goodputInventoryRevision("expected-1-"+suffix, clusterID, expectedSource, now.Add(-2*time.Minute), entities)
	observed := goodputInventoryRevision("observed-1-"+suffix, clusterID, observedSource, now.Add(-time.Minute), entities)
	secondExpected := goodputInventoryRevision("expected-2-"+suffix, clusterID, expectedSource, now, []domain.EntityIdentity{entities[0]})
	if inserted, err := store.RecordExpectedInventoryRevision(ctx, firstExpected); err != nil || !inserted {
		t.Fatalf("record first expected inventory inserted=%t err=%v", inserted, err)
	}
	if inserted, err := store.RecordObservedInventoryRevision(ctx, observed); err != nil || !inserted {
		t.Fatalf("record observed inventory inserted=%t err=%v", inserted, err)
	}
	if inserted, err := store.RecordExpectedInventoryRevision(ctx, secondExpected); err != nil || !inserted {
		t.Fatalf("record second expected inventory inserted=%t err=%v", inserted, err)
	}
	if inserted, err := store.RecordExpectedInventoryRevision(ctx, secondExpected); err != nil || inserted {
		t.Fatalf("duplicate inventory inserted=%t err=%v", inserted, err)
	}
	currentExpected, found, err := store.GetCurrentInventoryRevision(ctx, clusterID, expectedSource, application.InventoryExpected)
	if err != nil || !found || currentExpected.Revision.ID != secondExpected.ID || len(currentExpected.Revision.Entities) != 1 {
		t.Fatalf("current expected=%+v found=%t err=%v", currentExpected, found, err)
	}
	currentObserved, found, err := store.GetCurrentInventoryRevision(ctx, clusterID, observedSource, application.InventoryObserved)
	if err != nil || !found || currentObserved.Revision.ID != observed.ID || len(currentObserved.Revision.Entities) != 2 {
		t.Fatalf("current observed=%+v found=%t err=%v", currentObserved, found, err)
	}
	if _, found, err := store.GetInventoryRevision(ctx, otherClusterID, secondExpected.ID); err != nil || found {
		t.Fatalf("foreign cluster inventory found=%t err=%v", found, err)
	}
	var firstValidTo time.Time
	if err := pool.QueryRow(ctx, `SELECT valid_to FROM goodput_inventory_revision_validity WHERE cluster_id=$1 AND revision_id=$2`, clusterID, firstExpected.ID).Scan(&firstValidTo); err != nil || !firstValidTo.Equal(secondExpected.EffectiveAt) {
		t.Fatalf("expected inventory validity end=%s want=%s err=%v", firstValidTo, secondExpected.EffectiveAt, err)
	}

	job := domain.JobIdentity{SchedulerNamespace: "slurm", JobID: "42", SubmitAt: now.Add(-time.Hour), Attempt: 1}
	running := goodputAllocationSnapshot(clusterID, observedSource, job, domain.AllocationRunning, now.Add(-30*time.Second), []domain.EntityIdentity{entities[1]})
	completing := goodputAllocationSnapshot(clusterID, observedSource, job, domain.AllocationCompleting, now, []domain.EntityIdentity{entities[1]})
	if inserted, err := store.RecordAllocationSnapshot(ctx, running); err != nil || !inserted {
		t.Fatalf("record running allocation inserted=%t err=%v", inserted, err)
	}
	if inserted, err := store.RecordAllocationSnapshot(ctx, completing); err != nil || !inserted {
		t.Fatalf("record completing allocation inserted=%t err=%v", inserted, err)
	}
	if inserted, err := store.RecordAllocationSnapshot(ctx, completing); err != nil || inserted {
		t.Fatalf("duplicate allocation inserted=%t err=%v", inserted, err)
	}
	allocations, more, err := store.ListCurrentAllocationSnapshots(ctx, clusterID, 1)
	if err != nil || more || len(allocations) != 1 || allocations[0].State != domain.AllocationCompleting || len(allocations[0].Entities) != 1 || allocations[0].Entities[0].Key() != entities[1].Key() {
		t.Fatalf("current allocations=%+v more=%t err=%v", allocations, more, err)
	}
	otherAllocations, more, err := store.ListCurrentAllocationSnapshots(ctx, otherClusterID, 1)
	if err != nil || more || len(otherAllocations) != 0 {
		t.Fatalf("foreign cluster allocations=%+v more=%t err=%v", otherAllocations, more, err)
	}
}

func goodputInventoryRevision(id string, clusterID domain.ClusterID, sourceID domain.SourceID, effectiveAt time.Time, entities []domain.EntityIdentity) domain.InventoryRevision {
	return domain.InventoryRevision{
		SchemaVersion: domain.InventoryContractSchemaVersion, ID: domain.InventoryRevisionID(id), ClusterID: clusterID, SourceID: sourceID,
		SourceAt: effectiveAt, EffectiveAt: effectiveAt, ObservedAt: effectiveAt.Add(time.Second), Entities: entities,
	}
}

func goodputAllocationSnapshot(clusterID domain.ClusterID, sourceID domain.SourceID, job domain.JobIdentity, state domain.AllocationState, effectiveAt time.Time, entities []domain.EntityIdentity) domain.AllocationSnapshot {
	return domain.AllocationSnapshot{
		SchemaVersion: domain.InventoryContractSchemaVersion, ClusterID: clusterID, SourceID: sourceID, Job: job, State: state,
		SourceAt: effectiveAt, EffectiveAt: effectiveAt, ObservedAt: effectiveAt.Add(time.Second), Entities: entities,
	}
}

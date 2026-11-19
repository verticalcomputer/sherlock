//go:build integration

package postgres_test

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestContinuousCoolingUploadRevisionAndReceiptAuthority(t *testing.T) {
	pool := durableTestDatabase(t)
	ctx := t.Context()
	admin, _ := storepg.NewCollectionStore(pool)
	const cluster, source, collector = "continuous-cluster", "continuous-source", "continuous-collector"
	if err := admin.EnsureSource(ctx, cluster, cluster, source, source); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO collectors(collector_id,cluster_id,display_name,status,version,build_commit,protocol_min,protocol_max,operating_system,architecture)
 VALUES($1,$2,$1,'ACTIVE','fixture','fixture',1,2,'test','test')`, collector, cluster); err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	inventory, _ := storepg.NewGoodputStore(pool)
	before := now.Add(-time.Hour)
	revision := domain.InventoryRevision{SchemaVersion: 1, ID: "continuous-inventory", ClusterID: cluster, SourceID: source,
		SourceAt: before, EffectiveAt: before, ObservedAt: before, Entities: []domain.EntityIdentity{
			{ClusterID: cluster, Kind: domain.EntityNode, NodeID: "node-a"},
			{ClusterID: cluster, Kind: domain.EntityGPU, NodeID: "node-a", PhysicalGPUUUID: "GPU-a"},
		}}
	if _, err := inventory.RecordExpectedInventoryRevision(ctx, revision); err != nil {
		t.Fatal(err)
	}
	store := coolingUploadRestrictedStore(t, pool)
	slot := now.UTC().Add(2 * time.Second).Truncate(domain.CoolingUploadInterval).Add(domain.CoolingUploadInterval)
	p := domain.CoolingUploadProfile{Version: 3, ProfileID: "continuous", Revision: 10, CollectorID: collector, ClusterID: cluster, SourceID: source,
		InventoryRevision: string(revision.ID), StartsAt: slot.Add(-time.Minute), State: "ENABLED", Assets: []domain.CoolingUploadAsset{{NodeID: "node-a", GPUUUID: "GPU-a"}}}
	// Start as a V2-only family: its ordinary idempotent restart must still work.
	legacy := p
	legacy.Version, legacy.Revision, legacy.State = domain.CoolingUploadVersion, 1, ""
	legacy.EndsAt = slot.Add(time.Hour)
	legacyHash := domain.ChecksumSHA256([]byte("legacy")).String()
	for range 2 {
		if err := store.RegisterCoolingUploadProfile(ctx, legacy, legacyHash); err != nil {
			t.Fatal("V2-only startup", err)
		}
	}
	hash := domain.ChecksumSHA256([]byte("enabled")).String()
	if err := store.RegisterCoolingUploadProfile(ctx, p, hash); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterCoolingUploadProfile(ctx, p, hash); err != nil {
		t.Fatal("idempotent registration", err)
	}
	conflict := p
	conflict.Revision = 0
	if err := store.RegisterCoolingUploadProfile(ctx, conflict, hash); err == nil {
		t.Fatal("invalid revision accepted")
	}
	other := p
	other.ProfileID = "other"
	if err := store.RegisterCoolingUploadProfile(ctx, other, hash); err == nil {
		t.Fatal("overlapping collection accepted")
	}
	waitForCoolingUploadSlot(t, pool, slot)
	report := coolingUploadTestReport(p, hash, domain.QueryGPUPower, slot)
	report.Version = 3
	if accepted, err := store.RecordCoolingUpload(ctx, collector, cluster, report); err != nil || !accepted {
		t.Fatalf("V3 receipt accepted=%v err=%v", accepted, err)
	}
	if accepted, err := store.RecordCoolingUpload(ctx, collector, cluster, report); err != nil || !accepted {
		t.Fatalf("retry accepted=%v err=%v", accepted, err)
	}
	disabled := p
	disabled.Revision = 11
	disabled.State = "DISABLED"
	disabledHash := domain.ChecksumSHA256([]byte("disabled")).String()
	if err := store.RegisterCoolingUploadProfile(ctx, disabled, disabledHash); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterCoolingUploadProfile(ctx, disabled, disabledHash); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterCoolingUploadProfile(ctx, p, hash); err == nil {
		t.Fatal("stale revision reinstalled")
	}
	// Neither a previously admitted V2 startup nor a delayed/new V2 revision
	// may undo V3's durable disable, even if its numeric revision is higher.
	for _, v2Revision := range []int64{1, 9, 20} {
		stale := legacy
		stale.Revision = v2Revision
		if err := store.RegisterCoolingUploadProfile(ctx, stale, legacyHash); err == nil {
			t.Errorf("V2 revision %d reinstalled after V3 disable", v2Revision)
		}
	}
	var legacyRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM prometheus_cooling_upload_profiles WHERE profile_id=$1 AND protocol_version=2`, p.ProfileID).Scan(&legacyRows); err != nil || legacyRows != 1 {
		t.Fatalf("rejected V2 registration mutated authority: rows=%d err=%v", legacyRows, err)
	}
	legacyReport := coolingUploadTestReport(legacy, legacyHash, domain.QueryGPUPower, slot)
	if _, err := store.RecordCoolingUpload(ctx, collector, cluster, legacyReport); !errors.Is(err, collectorcontrol.ErrCoolingUploadRejected) {
		t.Fatalf("previous V2 authority admitted a report after V3 disable: %v", err)
	}

	if _, err := store.RecordCoolingUpload(ctx, collector, cluster, report); !errors.Is(err, collectorcontrol.ErrCoolingUploadRejected) {
		t.Fatalf("revoked receipt accepted: %v", err)
	}
	var retained bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM prometheus_cooling_upload_receipts WHERE run_id=$1)`, report.Result.Task.RunID).Scan(&retained); err != nil || !retained {
		t.Fatalf("retained original provenance lost %v %v", retained, err)
	}
	reenrolled := p
	reenrolled.Revision = 12
	if err := store.RegisterCoolingUploadProfile(ctx, reenrolled, hash); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterCoolingUploadProfile(ctx, disabled, disabledHash); err == nil {
		t.Fatal("reordered disabled revision accepted")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM prometheus_cooling_upload_profiles WHERE profile_id=$1 AND revoked_at IS NULL AND collection_state='ENABLED'`, p.ProfileID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("active authorities=%d err=%v", count, err)
	}
	// A downgrade must refuse retained V3 authority without losing its receipts.
	down, err := os.ReadFile("../../../migrations/000084_continuous_cooling_upload.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, string(down)); err == nil {
		tx.Rollback(ctx)
		t.Fatal("downgrade accepted retained V3 authority")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM prometheus_cooling_upload_receipts WHERE run_id=$1)`, report.Result.Task.RunID).Scan(&retained); err != nil || !retained {
		t.Fatalf("downgrade damaged retained receipt %v %v", retained, err)
	}

}

func TestContinuousCoolingUploadDowngradeEmpty(t *testing.T) {
	pool := durableTestDatabase(t)
	down, err := os.ReadFile("../../../migrations/000084_continuous_cooling_upload.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), string(down)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='prometheus_cooling_upload_profiles' AND column_name='protocol_version')`).Scan(&exists); err != nil || exists {
		t.Fatalf("V3 metadata survived empty rollback: %v %v", exists, err)
	}
}

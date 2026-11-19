//go:build integration

package postgres_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFleetCoolingProfileStorageReceiptAndRollback(t *testing.T) {
	pool := durableTestDatabase(t)
	ctx := t.Context()
	down, e := os.ReadFile("../../../migrations/000087_fleet_cooling_profiles.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	up, e := os.ReadFile("../../../migrations/000087_fleet_cooling_profiles.up.sql")
	if e != nil {
		t.Fatal(e)
	}
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, string(down)); e != nil {
		t.Fatal("empty rollback", e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, string(up)); e != nil {
		t.Fatal("reapply", e)
	}
	admin, _ := storepg.NewCollectionStore(pool)
	const cluster, source, collector = "fleet-cluster", "fleet-source", "fleet-collector"
	if e = admin.EnsureSource(ctx, cluster, cluster, source, source); e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, `INSERT INTO collectors(collector_id,cluster_id,display_name,status,version,build_commit,protocol_min,protocol_max,operating_system,architecture) VALUES($1,$2,$1,'ACTIVE','fixture','fixture',1,2,'test','test')`, collector, cluster); e != nil {
		t.Fatal(e)
	}
	var now time.Time
	if e = pool.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); e != nil {
		t.Fatal(e)
	}
	inventory, _ := storepg.NewGoodputStore(pool)
	before := now.Add(-time.Hour)
	revision := domain.InventoryRevision{SchemaVersion: 1, ID: "fleet-inventory", ClusterID: cluster, SourceID: source, SourceAt: before, EffectiveAt: before, ObservedAt: before}
	slot := now.UTC().Add(2 * time.Second).Truncate(15 * time.Second).Add(15 * time.Second)
	p := domain.CoolingUploadProfile{Version: 3, ProfileID: "fleet", Revision: 1, CollectorID: collector, ClusterID: cluster, SourceID: source, InventoryRevision: string(revision.ID), StartsAt: slot.Add(-time.Minute), State: "ENABLED"}
	for i := range 128 {
		node := domain.StableNodeID(fmt.Sprintf("node-%02d-", i/8) + strings.Repeat("n", 90))
		gpu := domain.PhysicalGPUUUID(fmt.Sprintf("GPU-%03d-", i) + strings.Repeat("g", 90))
		if i%8 == 0 {
			revision.Entities = append(revision.Entities, domain.EntityIdentity{ClusterID: cluster, Kind: domain.EntityNode, NodeID: node})
		}
		revision.Entities = append(revision.Entities, domain.EntityIdentity{ClusterID: cluster, Kind: domain.EntityGPU, NodeID: node, PhysicalGPUUUID: gpu})
		p.Assets = append(p.Assets, domain.CoolingUploadAsset{NodeID: node, GPUUUID: gpu})
	}
	if _, e = inventory.RecordExpectedInventoryRevision(ctx, revision); e != nil {
		t.Fatal(e)
	}
	store := coolingUploadRestrictedStore(t, pool)
	body, _ := json.Marshal(p)
	if len(body) <= 16<<10 {
		t.Fatal("fixture does not exercise old decode limit")
	}
	hash := domain.ChecksumSHA256(body).String()
	if e = store.RegisterCoolingUploadProfile(ctx, p, hash); e != nil {
		t.Fatal("128-GPU registration", e)
	}
	if e = store.RegisterCoolingUploadProfile(ctx, p, hash); e != nil {
		t.Fatal("idempotent registration", e)
	}
	var size int
	if e = pool.QueryRow(ctx, `SELECT octet_length(profile::text) FROM prometheus_cooling_upload_profiles WHERE profile_id=$1`, p.ProfileID).Scan(&size); e != nil || size > 65536 || size <= 8192 {
		t.Fatalf("stored bytes%d err%v", size, e)
	}
	waitForCoolingUploadSlot(t, pool, slot)
	r := coolingUploadTestReport(p, hash, domain.QueryGPUPower, slot)
	r.Version = 3
	if ok, e := store.RecordCoolingUpload(ctx, collector, cluster, r); e != nil || !ok {
		t.Fatalf("128-GPU receipt accepted%v: %v", ok, e)
	}
	var observations int
	if e = pool.QueryRow(ctx, `SELECT count(*) FROM observations WHERE run_id=$1`, r.Result.Task.RunID).Scan(&observations); e != nil || observations != 128 {
		t.Fatalf("observations%d error%v", observations, e)
	}
	if ok, e := store.RecordCoolingUpload(ctx, "other-collector", cluster, r); e == nil || ok {
		t.Fatal("foreign caller receipt accepted")
	}
	tx, e = pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = tx.Exec(ctx, string(down))
	var pg *pgconn.PgError
	if !errors.As(e, &pg) || pg.Code != "55000" {
		t.Fatalf("fleet downgrade not safely rejected: %v", e)
	}
	_ = tx.Rollback(ctx)
	// Database V2 JSON bound remains 8KiB even after the V3 expansion.
	legacy := p
	legacy.Version = 2
	legacy.State = ""
	legacy.EndsAt = slot.Add(time.Hour)
	legacy.ProfileID = "legacy-size"
	legacyBody, _ := json.Marshal(legacy)
	_, e = pool.Exec(ctx, `INSERT INTO prometheus_cooling_upload_profiles(profile_id,revision,profile_hash,cluster_id,source_id,collector_id,inventory_revision,profile,starts_at,ends_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9)`, legacy.ProfileID, hash, cluster, source, collector, revision.ID, legacyBody, legacy.StartsAt, legacy.EndsAt)
	if !errors.As(e, &pg) || pg.Code != "23514" || pg.ConstraintName != "prometheus_cooling_upload_profiles_profile_check" {
		t.Fatalf("V2 byte bound not enforced: %v", e)
	}
	t.Logf("fleet JSONB %d bytes; 128 observations durable; V2 bound and retained-authority downgrade refusal verified", size)
}

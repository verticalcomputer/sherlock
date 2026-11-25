//go:build integration

package postgres

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestProductionWarmingPeerReceiptScope(t *testing.T) {
	f, s, c, profile, hash, now := productionFleetFixture(t, 16)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	f.exec(t, `UPDATE prometheus_cooling_upload_profiles SET registered_at=starts_at-interval '1 second' WHERE profile_id=$1 AND revision=$2`, profile.ProfileID, profile.Revision)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	w, err := NewCollectionStore(f.admin)
	if err != nil {
		t.Fatal(err)
	}
	slot := now.Truncate(15 * time.Second)
	var first, second time.Time
	for _, query := range []domain.QueryKind{domain.QueryGPUTemperature, domain.QueryGPUPower} {
		report := assessmentUploadReport(profile, hash, query, slot)
		report.Version = 3
		for i := range report.Result.Observations {
			if query == domain.QueryGPUTemperature {
				report.Result.Observations[i].Value = float64(50 + i)
			}
		}
		if accepted, err := w.RecordCoolingUpload(t.Context(), profile.CollectorID, profile.ClusterID, report); err != nil || !accepted {
			t.Fatal("upload", err)
		}
		var at time.Time
		if err := f.admin.QueryRow(t.Context(), "SELECT received_at FROM prometheus_cooling_upload_receipts WHERE run_id=$1", report.Result.Task.RunID).Scan(&at); err != nil {
			t.Fatal(err)
		}
		if query == domain.QueryGPUTemperature {
			first = at
		} else {
			second = at
		}
	}
	target := c.Assessment.Assets[0].EntityKey
	review := func(at time.Time) *cooling.PeerContext {
		return s.suspectedPeers(t.Context(), target, at, cooling.WarmingContext{Rows: [][4]*float64{peerTarget(slot.Sub(at).Seconds(), 75, 200)}})
	}
	if got := review(first); got.Status != "sparse" || len(got.Rows) != 0 {
		t.Fatalf("future power receipt entered context: %+v", got)
	}
	got := review(second)
	if got.Status != "available" || got.DistinctPeers != 7 || len(got.Rows) != 1 || got.Rows[0].MedianC != 54 || got.Rows[0].MaxC != 57 {
		t.Fatalf("scope did not exclude target or other node: %+v", got)
	}
	// An observation altered after durable admission has lost the original
	// writer proof even if the UUID, scope and historical timestamps still match.
	f.exec(t, `UPDATE observations SET value=value+1 WHERE entity_key=$1 AND metric=$2`, c.Assessment.Assets[1].EntityKey, cooling.Temperature)
	got = review(second)
	if got.DistinctPeers != 6 {
		t.Fatalf("non-original row included: %+v", got)
	}
	addInventory := func(id, digest string, observed time.Time) {
		f.exec(t, `INSERT INTO goodput_inventory_revisions(revision_id,cluster_id,source_id,inventory_class,schema_version,content_digest,source_at,effective_at,observed_at)
            VALUES($1,$2,$3,'EXPECTED',1,decode(repeat($4,32),'hex'),$5,$5,$6)`, id, profile.ClusterID, profile.SourceID, digest, slot.Add(-30*time.Second), observed)
	}
	addInventory("later-observation", "cd", second.Add(time.Hour))
	if got := review(second); got.DistinctPeers != 6 {
		t.Fatalf("future inventory changed historical decision: %+v", got)
	}
	addInventory("already-visible", "de", slot.Add(-time.Second))
	if got := review(second); got.Status != "sparse" {
		t.Fatalf("superseded inventory admitted: %+v", got)
	}
	s.config.Assessment.InventoryRevision = "wrong-inventory"
	if got := review(second); got.Status != "sparse" {
		t.Fatal(got)
	}
}

func TestProductionWarmingPeerSuccessorScope(t *testing.T) {
	f, s, c, p, _, now := productionFleetFixture(t, 16)
	w, err := NewCollectionStore(f.admin)
	if err != nil {
		t.Fatal(err)
	}
	p.Revision++
	p.Assets = p.Assets[:8]
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	hash := domain.ChecksumSHA256(raw).String()
	if err = w.RegisterCoolingUploadProfile(t.Context(), p, hash); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	f.exec(t, `UPDATE prometheus_cooling_upload_profiles SET registered_at=starts_at-interval '1 second' WHERE profile_id=$1 AND revision=$2`, p.ProfileID, p.Revision)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	slot := now.Truncate(15 * time.Second)
	for _, q := range []domain.QueryKind{domain.QueryGPUTemperature, domain.QueryGPUPower} {
		report := assessmentUploadReport(p, hash, q, slot)
		report.Version = 3
		if accepted, err := w.RecordCoolingUpload(t.Context(), p.CollectorID, p.ClusterID, report); err != nil || !accepted {
			t.Fatalf("successor receipt accepted=%v: %v", accepted, err)
		}
	}
	var at time.Time
	if err := f.admin.QueryRow(t.Context(), "SELECT clock_timestamp()").Scan(&at); err != nil {
		t.Fatal(err)
	}
	target := c.Assessment.Assets[0]
	review := func() *cooling.PeerContext {
		return s.suspectedPeers(t.Context(), target.EntityKey, at, cooling.WarmingContext{Rows: [][4]*float64{peerTarget(slot.Sub(at).Seconds(), 75, 200)}})
	}
	if got := review(); got.Status != "sparse" {
		t.Fatalf("successor with changed node scope admitted: %+v", got)
	}
	for i := range s.config.Assessment.Bindings {
		s.config.Assessment.Bindings[i].ScopeNodes = []string{target.NodeID}
	}
	if got := review(); got.DistinctPeers != 7 {
		t.Fatalf("compatible successor omitted: %+v", got)
	}
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	f.exec(t, `UPDATE prometheus_cooling_upload_profiles SET registered_at=$3 WHERE profile_id=$1 AND revision=$2`, p.ProfileID, p.Revision, slot)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	if got := review(); got.Status != "sparse" {
		t.Fatalf("successor registered too late admitted: %+v", got)
	}
}

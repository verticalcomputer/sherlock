//go:build integration && !race

package postgres

import (
	"encoding/json"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// Latency qualification uses the release-like build: race instrumentation changes
// CPU cost, not the deployed deadline. The full backlog and exact runtime limits
// stay mandatory here; the incremental aged lifecycle also runs under -race.
func TestProductionAssessmentAgedBacklogBudget(t *testing.T) {
	f, s, c, now := productionStoreFixture(t)
	var profileBody []byte
	var hash string
	b := c.Assessment.Bindings[0]
	if err := f.admin.QueryRow(t.Context(), `SELECT profile,profile_hash FROM prometheus_cooling_upload_profiles WHERE profile_id=$1 AND revision=$2`, b.UploadProfileID, b.ScheduleRevision).Scan(&profileBody, &hash); err != nil {
		t.Fatal(err)
	}
	var profile domain.CoolingUploadProfile
	if err := json.Unmarshal(profileBody, &profile); err != nil {
		t.Fatal(err)
	}
	// Historic, authenticated receipts are synthesized only in this disposable DB.
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	f.exec(t, `UPDATE prometheus_cooling_upload_profiles SET registered_at=starts_at-interval '1 second' WHERE profile_id=$1 AND revision=$2`, profile.ProfileID, profile.Revision)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	writer, _ := NewCollectionStore(f.admin)
	if err := f.admin.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	last := now.Truncate(domain.CoolingUploadInterval)
	for slot := last.Add(-15*time.Minute + 15*time.Second); !slot.After(last); slot = slot.Add(15 * time.Second) {
		for _, query := range domain.CoolingUploadQueries() {
			report := assessmentUploadReport(profile, hash, query, slot)
			report.Version = 3
			if _, err := writer.RecordCoolingUpload(t.Context(), profile.CollectorID, profile.ClusterID, report); err != nil {
				t.Fatal(err)
			}
		}
	}
	entry := now.Add(-30 * time.Minute)
	e, err := a.NewProductionEngine(t.Context(), c, entry, s.registry)
	if err != nil {
		t.Fatal(err)
	}
	asset := c.Assessment.Assets[0].EntityKey
	for sec := 0; sec <= 150; sec += 15 {
		at := entry.Add(time.Duration(sec) * time.Second)
		if err = e.Advance(t.Context(), at, at, at, productionStoreSamples(t, c, at), nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.Candidates) != 1 || e.Candidates[0].Phase != "FINAL" || !e.Enrollments[asset].Active {
		t.Fatalf("agedproofsetup %+v", e.Candidates)
	}
	snapshot, err := e.SnapshotProduction(asset, entry.Add(150*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE production_assessment_enrollments SET created_at=$2,notifications_enabled=false WHERE enrollment_id=$1`, c.Assessment.RunID, entry)
	f.exec(t, `UPDATE production_assessment_states SET snapshot=$3 WHERE enrollment_id=$1 AND asset=$2`, c.Assessment.RunID, asset, snapshot)
	var elapsed []time.Duration
	for n := 0; n < 10; n++ {
		before := time.Now()
		if err = s.Refresh(t.Context()); err != nil {
			t.Fatalf("aged refresh %d: %v", n, err)
		}
		elapsed = append(elapsed, time.Since(before))
		var code string
		var size int
		if err = f.admin.QueryRow(t.Context(), `SELECT last_failure_code,octet_length(snapshot) FROM production_assessment_states WHERE enrollment_id=$1 AND asset=$2`, c.Assessment.RunID, asset).Scan(&code, &size); err != nil {
			t.Fatal(err)
		}
		if code != "" {
			t.Fatalf("aged refresh failure %s", code)
		}
		if size > a.ProductionSnapshotLimit {
			t.Fatal("unbounded working snapshot")
		}
	}
	assessmentProfileDistribution(t, "production_aged_refresh", elapsed)
	t.Log("10 fresh production refreshes with 30-minute-old retained entry proof and 60-slot/15-minute admitted receipt window; no per-fact DB reads; unchanged 250ms GPU/2s refresh limits")
}

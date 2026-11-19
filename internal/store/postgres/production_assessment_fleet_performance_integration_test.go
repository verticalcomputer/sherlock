//go:build integration && !race

package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// Full fleet qualification uses actual admitted 15-minute receipt history and
// 30-minute retained entry proof. Setup is excluded from pass/GPU measurements.
func TestProductionAssessmentFleetAgedBacklogBudget(t *testing.T) {
	for _, fixture := range []struct {
		n    int
		aged bool
	}{{112, true}, {128, true}, {128, false}} {
		n := fixture.n
		for _, individual := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d_GPUs_aged_%t_individual_%t", n, fixture.aged, individual), func(t *testing.T) {
				f, s, c, profile, hash, _ := productionFleetFixture(t, n)
				f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`)
				f.exec(t, `UPDATE prometheus_cooling_upload_profiles SET registered_at=starts_at-interval '1 second' WHERE profile_id=$1 AND revision=$2`, profile.ProfileID, profile.Revision)
				f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`)
				var now time.Time
				if err := f.admin.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
					t.Fatal(err)
				}
				writer, _ := NewCollectionStore(f.admin)
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
				if fixture.aged {
					seedFleetSnapshots(t, f, s, c, now.Add(-30*time.Minute), true)
				}
				// Use an independent DB fixture for the individual measurement. The
				// first complete Refresh sweep must consume untouched aged proof
				// and the full receipt backlog, not already-processed snapshots.
				if individual {
					// Measure the complete per-GPU path including durable scheduling claim.
					_, queue, err := s.refreshQueues(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					gpuTimes := []time.Duration{}
					for _, entry := range queue {
						began := time.Now()
						gpu, stop := context.WithTimeout(t.Context(), a.ShadowGPUBudget)
						claimed, err := s.claimRefreshAttempt(gpu, entry, false)
						if err == nil && claimed {
							err = s.refreshAsset(gpu, entry.asset, false)
						}
						stop()
						elapsed := time.Since(began)
						gpuTimes = append(gpuTimes, elapsed)
						if err != nil || !claimed || elapsed > a.ShadowGPUBudget {
							t.Fatalf("%d-GPU aged individual pass %s,claimed%v: %v diagnostics=%v", n, elapsed, claimed, err, AssessmentDiagnosticFields(err))
						}
					}
					assessmentProfileDistribution(t, fmt.Sprintf("fleet_gpu_aged_%t", fixture.aged), gpuTimes)
					var failures int
					if err := f.admin.QueryRow(t.Context(), `SELECT sum(failure_count) FROM production_assessment_states`).Scan(&failures); err != nil || failures != 0 {
						t.Fatalf("individual fleet failures%d: %v", failures, err)
					}
					return
				}
				var cycleStart time.Time
				if err := f.admin.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&cycleStart); err != nil {
					t.Fatal(err)
				}
				cycle := time.Now()
				passes := []time.Duration{}
				remaining := n
				for pass := 0; pass < 16 && remaining > 0; pass++ {
					began := time.Now()
					err := s.Refresh(t.Context())
					elapsed := time.Since(began)
					passes = append(passes, elapsed)
					if err != nil || elapsed > a.ShadowRefreshBudget {
						t.Fatalf("fleet refresh %s: %v diagnostics=%v", elapsed, err, AssessmentDiagnosticFields(err))
					}
					if err = f.admin.QueryRow(t.Context(), `SELECT count(*) FROM production_assessment_states WHERE last_acquire_attempt_at IS NULL OR last_acquire_attempt_at<$1`, cycleStart).Scan(&remaining); err != nil {
						t.Fatal(err)
					}
				}
				// The data source's existing 15s cadence remains the healthy fleet sweep gate.
				if remaining != 0 || time.Since(cycle) > 15*time.Second {
					assessmentProfileDistribution(t, fmt.Sprintf("fleet_refresh_aged_%t", fixture.aged), passes)
					t.Fatalf("fleet cycle remaining%d elapsed%s", remaining, time.Since(cycle))
				}
				var failures int
				if err := f.admin.QueryRow(t.Context(), `SELECT sum(failure_count) FROM production_assessment_states`).Scan(&failures); err != nil || failures != 0 {
					t.Fatalf("fleet failures%d: %v", failures, err)
				}
				assessmentProfileDistribution(t, fmt.Sprintf("fleet_refresh_aged_%t", fixture.aged), passes)
				t.Logf("%d GPUs with 120 admitted receipts, aged proof=%t: all acquired in %s across %d bounded passes", n, fixture.aged, time.Since(cycle), len(passes))
			})
		}
	}
}

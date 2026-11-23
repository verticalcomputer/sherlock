//go:build integration

package postgres

import (
	"encoding/json"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestProductionOrderedFailedCoveragePrecedesPositiveSamples(t *testing.T) {
	f, store, config, profile, hash, now := productionFleetFixture(t, 1)
	asset := config.Assessment.Assets[0]
	start := now.Truncate(domain.CoolingUploadInterval).Add(-2 * time.Minute)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	f.exec(t, `UPDATE prometheus_cooling_upload_profiles SET registered_at=starts_at-interval '1 second' WHERE profile_id=$1 AND revision=$2`, profile.ProfileID, profile.Revision)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	f.exec(t, `CREATE FUNCTION fixture_coverage_clock() RETURNS trigger LANGUAGE plpgsql AS $$
	BEGIN SELECT completed_at + interval '1 second' INTO NEW.received_at FROM collection_runs WHERE run_id=NEW.run_id; RETURN NEW; END $$;
	CREATE TRIGGER zz_fixture_coverage_clock BEFORE INSERT ON prometheus_cooling_upload_receipts FOR EACH ROW EXECUTE FUNCTION fixture_coverage_clock()`)
	writer, err := NewCollectionStore(f.admin)
	if err != nil {
		t.Fatal(err)
	}
	var failedID string
	for sec := 0; sec <= 60; sec += 15 {
		slot := start.Add(time.Duration(sec) * time.Second)
		for _, query := range domain.CoolingUploadQueries() {
			report := assessmentUploadReport(profile, hash, query, slot)
			report.Version = profile.Version
			if query == domain.QueryGPUTemperature {
				if sec == 45 {
					report.Result.Status = domain.ResultFailed
					report.Result.Observations = nil
					report.Result.Coverage = domain.Coverage{}
					report.Result.Failures = []domain.CollectionFailure{{Code: domain.FailureSourceUnavailable, Message: "fixture source unavailable"}}
					failedID = string(profile.Task(query, slot).RunID)
				} else {
					report.Result.Observations[0].Value = 82
				}
			}
			if ok, err := writer.RecordCoolingUpload(t.Context(), profile.CollectorID, profile.ClusterID, report); err != nil || !ok {
				t.Fatalf("fixture report %s at %d: %v %v", query, sec, ok, err)
			}
		}
	}
	at := start.Add(65 * time.Second)
	read := func() []a.Fact {
		tx, err := f.admin.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		facts, err := loadAssessmentInputAfter(t.Context(), tx, config.Assessment, asset, at, start)
		if err != nil {
			t.Fatal(err)
		}
		return facts
	}
	decisions := func(facts []a.Fact) []a.Decision {
		t.Helper()
		e, err := a.NewProductionAssetEngine(t.Context(), config, start, store.registry, asset.EntityKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.AdvanceProductionBatch(t.Context(), asset.EntityKey, at, facts); err != nil {
			t.Fatal(err)
		}
		return e.Decisions
	}
	verify := func(facts []a.Fact, expectedNegative time.Time) {
		t.Helper()
		negatives, samples := 0, 0
		for _, fact := range facts {
			switch fact.Kind {
			case "COVERAGE":
				var cov a.Coverage
				if err := json.Unmarshal(fact.Body, &cov); err != nil {
					t.Fatal(err)
				}
				if cov.Code != "UNSUPPORTED" || cov.SourceRecord != failedID || !fact.AvailableAt.Equal(expectedNegative) {
					t.Fatalf("coverage %+v visible %s want %s", cov, fact.AvailableAt, expectedNegative)
				}
				negatives++
			case "SAMPLE":
				samples++
				if expectedNegative.Equal(at) && !fact.AvailableAt.Equal(at) {
					t.Fatalf("positive precedes uncertain coverage: %s", fact.AvailableAt)
				}
			}
		}
		if negatives != 1 || samples == 0 {
			t.Fatalf("%d negative reports, %d samples", negatives, samples)
		}
		for _, d := range decisions(facts) {
			if d.Action == "INVESTIGATE" {
				t.Fatalf("incorrect sustained heat despite failed sample: %+v", d)
			}
		}
	}
	facts := read()
	verify(facts, start.Add(46*time.Second))
	for i := range facts {
		if facts[i].Kind == "COVERAGE" {
			facts[i].AvailableAt = at
		}
	}
	early := false
	for _, d := range decisions(facts) {
		early = early || d.Action == "INVESTIGATE" && d.LogicalAt.Before(at)
	}
	if !early {
		t.Fatal("negative control did not reproduce premature investigation")
	}
	t.Run("incomplete observation page", func(t *testing.T) {
		tx, err := f.admin.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		powerID := string(profile.Task(domain.QueryGPUPower, start).RunID)
		if _, err = tx.Exec(t.Context(), `UPDATE observations SET labels=jsonb_build_array(jsonb_build_object('name','test','value',repeat('a',18000))) WHERE run_id=$1`, powerID); err != nil {
			t.Fatal(err)
		}
		batch, err := loadAssessmentInputAfter(t.Context(), tx, config.Assessment, asset, at, start)
		if err != nil {
			t.Fatal(err)
		}
		truncated := false
		samples := 0
		for _, fact := range batch {
			if fact.Kind == "COVERAGE" {
				var coverage a.Coverage
				if err = json.Unmarshal(fact.Body, &coverage); err != nil {
					t.Fatal(err)
				}
				if coverage.Code == "TRUNCATED" {
					truncated = true
					if !fact.AvailableAt.Equal(at) {
						t.Fatal("truncation backdated")
					}
				}
			}
			if fact.Kind == "SAMPLE" {
				samples++
				if !fact.AvailableAt.Equal(at) {
					t.Fatal("sample predates incomplete acquisition")
				}
			}
		}
		if !truncated || samples == 0 {
			t.Fatalf("truncated %v, samples %d", truncated, samples)
		}
	})
	// A later transaction touched the run. Its status can no longer supply
	// the ordering of the original negative report.
	f.exec(t, `UPDATE collection_runs SET coverage_complete=coverage_complete WHERE run_id=$1`, failedID)
	verify(read(), at)
}

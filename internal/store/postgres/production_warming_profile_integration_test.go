//go:build integration

package postgres

import (
	"os"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
)

// Exercise the actual evaluator permissions and query against publisher tables.
func TestDatabaseWarmingProfileAsOf(t *testing.T) {
	f, s, c, at := productionStoreFixture(t)
	run := c.Assessment.RunID
	asset := c.Assessment.Assets[0].EntityKey
	for _, path := range []string{"deploy/cooling-baseline/schema.sql", "scripts/production-assessment-grants.sql"} {
		b, err := os.ReadFile("../../../" + path)
		if err != nil {
			t.Fatal(err)
		}
		f.exec(t, string(b))
	}
	s.pool = f.restrictedPool(t)
	f.exec(t, "GRANT sherlock_assessment_production TO "+f.role)
	s.UseDatabaseWarmingProfiles()
	warming := cooling.WarmingContext{ComparableLoad: &cooling.WarmingReference{PowerW: 207}}
	if got := s.warmingProfileLookup(t.Context(), asset, at, warming); got.Status != "lookup_error" {
		t.Fatalf("expected missing grant to degrade: %+v", got)
	}
	grants, err := os.ReadFile("../../../scripts/cooling-profile-reader-grants.sql")
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, string(grants))
	if _, err := s.pool.Exec(t.Context(), "SELECT histogram FROM cooling_history.temperature_band"); err == nil {
		t.Fatal("histogram exposed")
	}
	ctx := cooling.WarmingContext{ComparableLoad: &cooling.WarmingReference{PowerW: 207}}
	check := func(when time.Time, want string) {
		t.Helper()
		got := s.warmingProfileLookup(t.Context(), asset, when, ctx)
		if got.Status != want || got.CenterW != 200 || (got.MedianC != nil) != (want == "qualified") || (got.P95C != nil) != (want == "qualified") {
			t.Fatalf("want %s, got %+v", want, got)
		}
		if want == "qualified" && (*got.MedianC != 62 || *got.P95C != 65 || got.Days != 30) {
			t.Fatalf("wrong cumulative profile %+v", got)
		}
	}
	seed := func(cut, pub time.Time, source, key string, days int, last time.Time) {
		f.exec(t, `INSERT INTO cooling_history.refresh (enrollment_id,cutoff,start_at,cluster_id,source_id,input,published_at,asset_count) VALUES ($1,$2,$3,$4,$5,'seed',$6,1)`, run, cut, at.Add(-40*24*time.Hour), c.Assessment.ClusterID, source, pub)
		f.exec(t, `INSERT INTO cooling_history.gpu VALUES ($1,$2,$3,300,20)`, run, cut, key)
		f.exec(t, `INSERT INTO cooling_history.temperature_band VALUES ($1,$2,$3,200,62,65,300,$4,40,$5,'{}')`, run, cut, key, days, last)
	}
	age := func(n int) time.Time { return at.Add(time.Duration(n) * time.Hour) }
	seed(age(-12), age(-2), c.Assessment.SourceID, asset, 30, age(-13))
	check(age(-1), "unavailable") // Data committed, availability fence still absent.
	mark := func(cut, visible time.Time) {
		f.exec(t, `INSERT INTO cooling_history.available_refresh VALUES($1,$2,$3)`, run, cut, visible)
	}
	mark(age(-12), age(-1))
	check(age(-2).Add(30*time.Minute), "unavailable")
	check(age(-3), "unavailable")
	seed(age(-8), age(-1), c.Assessment.SourceID+"other", asset, 2, age(-9))
	mark(age(-8), age(-1))
	check(at, "qualified")
	seed(age(-4), age(1), c.Assessment.SourceID, asset+"other", 30, age(-5))
	mark(age(-4), age(1))
	check(at, "qualified")
	check(age(1), "no_matching_band")
	seed(age(2), age(3), c.Assessment.SourceID, asset, 2, age(1))
	mark(age(2), age(3))
	check(age(3), "sparse")
	seed(age(4), age(5), c.Assessment.SourceID, asset, 30, age(-200))
	mark(age(4), age(5))
	check(age(5), "stale")
	// An unreadable store is distinct from an absent historical snapshot.
	f.exec(t, "REVOKE USAGE ON SCHEMA cooling_history FROM sherlock_assessment_production")
	check(age(5), "lookup_error")
}

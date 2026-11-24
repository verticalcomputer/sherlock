package coolingprofile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
)

func example(cutoff time.Time) snapshot {
	median, upper := 60., 65.
	return snapshot{Schema: 1, Cluster: "test", Source: "source", Enrollment: "cohort", Cutoff: cutoff, Published: cutoff.Add(time.Minute), Assets: map[string][]band{"asset": {{CenterW: 650, MedianC: &median, P95C: &upper, Samples: 80, Periods: 5, Days: 4, Last: cutoff.Add(-time.Minute)}}}}
}
func publish(t testing.TB, dir string, s snapshot) {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, s.Cutoff.Format("2006-01-02")+".json"), b, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestHistoricalProfileLookup(t *testing.T) {
	cutoff := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	context := cooling.WarmingContext{ComparableLoad: &cooling.WarmingReference{PowerW: 641}}
	for _, tc := range []struct {
		name, want string
		edit       func(*snapshot)
	}{
		{"qualified", "qualified", func(*snapshot) {}},
		{"future publication", "unavailable", func(s *snapshot) { s.Published = cutoff.Add(2 * time.Hour) }},
		{"wrong source", "unavailable", func(s *snapshot) { s.Source = "different" }},
		{"wrong enrollment", "unavailable", func(s *snapshot) { s.Enrollment = "different" }},
		{"unknown GPU", "no_matching_band", func(s *snapshot) { delete(s.Assets, "asset") }},
		{"sparse periods", "sparse", func(s *snapshot) { s.Assets["asset"][0].Periods = 2 }},
		{"sparse days", "sparse", func(s *snapshot) { s.Assets["asset"][0].Days = 2 }},
		{"stale", "stale", func(s *snapshot) { s.Assets["asset"][0].Last = cutoff.Add(-8 * day) }},
		{"ambiguous band", "invalid", func(s *snapshot) { s.Assets["asset"] = append(s.Assets["asset"], s.Assets["asset"][0]) }},
		{"invalid interval", "invalid", func(s *snapshot) { s.Assets["asset"][0].Last = cutoff }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := example(cutoff)
			tc.edit(&s)
			dir := t.TempDir()
			publish(t, dir, s)
			out := NewReader(dir, "test", "source", "cohort").Lookup("asset", cutoff.Add(time.Hour), context)
			if out.Status != tc.want || out.CenterW != 650 {
				t.Fatalf("%+v", out)
			}
			if tc.want == "qualified" {
				if *out.MedianC != 60 || *out.P95C != 65 || out.Periods != 5 || out.Days != 4 {
					t.Fatalf("%+v", out)
				}
			} else if out.MedianC != nil || out.P95C != nil {
				t.Fatalf("unexpected estimated temperatures: %+v", out)
			}
		})
	}
}
func TestPrePublicationUsesPreviousSnapshot(t *testing.T) {
	dir := t.TempDir()
	today := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	prior := example(today.Add(-day))
	newer := example(today)
	later := 70.
	newer.Assets["asset"][0].P95C = &later
	publish(t, dir, prior)
	publish(t, dir, newer)
	r := NewReader(dir, "test", "source", "cohort")
	c := cooling.WarmingContext{ComparableLoad: &cooling.WarmingReference{PowerW: 650}}
	for _, tc := range []struct {
		at   time.Time
		want float64
	}{{today, 65}, {today.Add(time.Hour), 70}, {today, 65}} {
		out := r.Lookup("asset", tc.at, c)
		if out.P95C == nil || *out.P95C != tc.want {
			t.Fatalf("%+v", out)
		}
	}
	if out := r.Lookup("asset", today.Add(3*day), c); out.Status != "unavailable" {
		t.Fatalf("expired profile: %+v", out)
	}
}
func BenchmarkHistoricalProfileLookup(b *testing.B) {
	dir := b.TempDir()
	cutoff := time.Now().UTC().Truncate(day)
	publish(b, dir, example(cutoff))
	r := NewReader(dir, "test", "source", "cohort")
	c := cooling.WarmingContext{ComparableLoad: &cooling.WarmingReference{PowerW: 650}}
	for b.Loop() {
		if r.Lookup("asset", cutoff.Add(time.Hour), c).Status != "qualified" {
			b.Fatal("profile unavailable")
		}
	}
}

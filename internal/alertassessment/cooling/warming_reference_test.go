package cooling

import (
	"slices"
	"testing"
	"time"
)

func comparableSamples() []WarmingSample {
	var rows []WarmingSample
	for seconds := -300; seconds <= 90; seconds += 15 {
		temp := 59.
		if seconds >= -15 {
			temp = 67
		}
		rows = append(rows, warmingSamples(Temperature, seconds, temp)...)
		rows = append(rows, warmingSamples(Power, seconds, 550)...)
	}
	return rows
}

func TestComparableWarmingReportsActualBaselineAndConfirmsSustainedRise(t *testing.T) {
	rows := comparableSamples()
	check := func(seconds int) (WarmingContext, bool) {
		return ConfirmedComparableWarming(rows, warmingAnchor, warmingAnchor.Add(time.Duration(seconds)*time.Second), time.Time{})
	}
	early, ok := check(15)
	if ok || early.ComparableLoad == nil || early.EndpointC != 67 {
		t.Fatalf("expected held crossing with measured endpoint")
	}
	result, ok := check(30)
	if !ok || result.ComparableLoad == nil {
		t.Fatal("sustained rise missing")
	}
	ref := *result.ComparableLoad
	if ref != (WarmingReference{Start: -300, Through: -15, MedianC: 59, PowerW: 550, Samples: 20}) || result.ReferenceTime != (ref.Start+ref.Through)/2 || result.ReferenceC != ref.MedianC {
		t.Fatalf("unexpected reference: %+v", ref)
	}
	// A physical power drop and return to the same operating temperature.
	// The low temperature must never become the new reference.
	for i, r := range rows {
		if !r.SourceAt.Before(warmingAnchor.Add(-3*time.Minute)) && r.SourceAt.Before(warmingAnchor.Add(-45*time.Second)) {
			if r.Metric == Power {
				rows[i].Value = 120
			} else {
				rows[i].Value = 36
			}
		} else if r.Metric == Temperature {
			rows[i].Value = 66
		}
	}
	rebound, ok := check(90)
	if ok || rebound.ComparableLoad == nil || rebound.ReferenceC != 66 || rebound.ComparableLoad.Through >= -180 || rebound.EndpointC != 66 {
		t.Fatalf("rebound incorrectly classified %+v", rebound.ComparableLoad)
	}
}

func TestComparableWarmingRejectsAbsentOrInvalidatedBaseline(t *testing.T) {
	at := func(sec int) time.Time { return warmingAnchor.Add(time.Duration(sec) * time.Second) }
	for _, mode := range []string{"absent power", "late baseline", "sparse matches", "stale matches", "late conflict", "late duplicate"} {
		t.Run(mode, func(t *testing.T) {
			rows := comparableSamples()
			var gaps []WarmingNegative
			switch mode {
			case "absent power":
				rows = slices.DeleteFunc(rows, func(r WarmingSample) bool { return r.Metric == Power })
			case "late baseline":
				for i, r := range rows {
					if r.SourceAt.Before(warmingAnchor) {
						rows[i].AvailableAt = at(1)
					}
				}
			case "sparse matches":
				rows = slices.DeleteFunc(rows, func(r WarmingSample) bool { return r.SourceAt.Before(at(-45)) })
			case "stale matches":
				rows = slices.DeleteFunc(rows, func(r WarmingSample) bool { return r.SourceAt.Before(warmingAnchor) && r.SourceAt.After(at(-75)) })
			case "late conflict":
				gaps = []WarmingNegative{{Power, at(-121), at(-120), at(30)}}
			case "late duplicate":
				rows = append(rows, WarmingSample{Power, 250, at(-120), at(30)})
			}
			if c, ok := ConfirmedComparableWarming(rows, warmingAnchor, at(30), time.Time{}, gaps...); ok || c.ComparableLoad != nil {
				t.Fatal("unusable reference accepted")
			}
		})
	}
}

func TestComparableWarmingRequiresComparablePowerDuringEntireCrossing(t *testing.T) {
	at := func(sec int) time.Time { return warmingAnchor.Add(time.Duration(sec) * time.Second) }
	for _, mode := range []string{"different load", "missing pair", "gap", "between temperature scrapes", "after last temperature"} {
		t.Run(mode, func(t *testing.T) {
			rows := comparableSamples()
			var gaps []WarmingNegative
			switch mode {
			case "different load":
				for i, r := range rows {
					if r.SourceAt.Equal(at(15)) && r.Metric == Power {
						rows[i].Value = 576
					}
				}
			case "missing pair":
				rows = slices.DeleteFunc(rows, func(r WarmingSample) bool { return r.SourceAt.Equal(at(15)) && r.Metric == Power })
			case "gap":
				gaps = []WarmingNegative{{Power, at(9), at(10), at(44)}}
			case "between temperature scrapes":
				rows = append(rows, WarmingSample{Power, 500, at(20), at(20)})
			case "after last temperature":
				rows = append(rows, WarmingSample{Power, 500, at(33), at(33)})
			}
			if c, ok := ConfirmedComparableWarming(rows, warmingAnchor, at(44), time.Time{}, gaps...); ok || c.ComparableLoad == nil {
				t.Fatal("invalid crossing admitted or reference lost")
			}
			if _, ok := ConfirmedComparableWarming(rows, warmingAnchor, at(90), time.Time{}, gaps...); !ok {
				t.Fatal("fresh independent crossing not admitted")
			}
		})
	}
}

func TestComparableReferenceIsFrozenInEntryEvidence(t *testing.T) {
	at := func(n int) time.Time { return warmingAnchor.Add(time.Duration(n) * time.Second) }
	entry := comparableSamples()
	working := slices.Clone(entry)
	// Backfilled pairs carry pre-entry observation/receipt times but were
	// absent from the entry record. They cannot retrain its median.
	for i := -299; i < -30; i += 4 {
		t := at(i).Add(500 * time.Millisecond)
		working = append(working, WarmingSample{Temperature, 68, t, t}, WarmingSample{Power, 550, t, t})
	}
	c, ok := ConfirmedComparableWarmingFromEvidence(entry, nil, working, warmingAnchor, warmingAnchor, at(30), time.Time{})
	if !ok || c.ReferenceC != 59 || c.ComparableLoad.Samples != 20 {
		t.Fatalf("entry reference changed or invalidated: %+v", c.ComparableLoad)
	}
	negative := WarmingNegative{Power, at(-120), at(-120), at(30)}
	if _, ok := ConfirmedComparableWarmingFromEvidence(entry, nil, working, warmingAnchor, warmingAnchor, at(30), time.Time{}, negative); ok {
		t.Fatal("late conflict failed to veto frozen entry")
	}
}

func TestRecentLoadedIntervalSupersedesEarlierDip(t *testing.T) {
	for _, tc := range []struct {
		name          string
		first, second int
		wantEnd       int
	}{
		{"settled interval after remote dip", -660, 0, -15},
		{"second distinct dip", -225, -75, -90},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rows []WarmingSample
			for sec := -900; sec <= 30; sec += 15 {
				power, temp := 550., 67.
				if sec < tc.first {
					temp = 59
				}
				if sec == tc.first || (tc.second != 0 && sec == tc.second) {
					power, temp = 120, 36
				}
				rows = append(rows, warmingSamples(Temperature, sec, temp)...)
				rows = append(rows, warmingSamples(Power, sec, power)...)
			}
			c, ok := ConfirmedComparableWarming(rows, warmingAnchor, warmingAnchor.Add(30*time.Second), time.Time{})
			if ok || c.ComparableLoad == nil || c.ComparableLoad.Through != float64(tc.wantEnd) {
				t.Fatalf("selected stale dip: %+v eligible=%v", c.ComparableLoad, ok)
			}
		})
	}
}

func TestComparableBaselineUsesEntryKnowledgeCutoff(t *testing.T) {
	rows := comparableSamples()
	receipt := warmingAnchor.Add(10 * time.Second)
	for i := range rows {
		if !rows[i].SourceAt.After(warmingAnchor) {
			rows[i].AvailableAt = receipt
		}
	}
	check := func(known time.Time) bool {
		_, ok := ConfirmedComparableWarmingFromEvidence(rows, nil, rows, warmingAnchor, known, warmingAnchor.Add(30*time.Second), time.Time{})
		return ok
	}
	if !check(receipt) || check(receipt.Add(-time.Nanosecond)) {
		t.Fatal("batch visibility at actual entry not respected")
	}
}

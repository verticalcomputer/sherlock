package cooling

import (
	"context"
	"slices"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

func TestCoolingCoverageEdgesGapsAndCounts(t *testing.T) {
	h := &history{negatives: make(map[string][]negative)}
	e := evidence{h: h, policy: DefaultPolicy(), cutoff: clock(63)}
	for _, tc := range []struct {
		name    string
		seconds []int
		want    bool
	}{
		{"inclusive edges and max gap", []int{15, 45, 50, 60}, true},
		{"late first", []int{16, 40, 60}, false},
		{"late last", []int{0, 20, 44, 44}, false},
		{"gap above bound", []int{0, 31, 45, 60}, false},
		{"too few observations", []int{15, 45}, false},
		{"repeated values count as observations", []int{0, 15, 30, 45}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ps []point
			for _, sec := range tc.seconds {
				ps = append(ps, point{at: clock(sec), value: 70})
			}
			if got := e.covered(Temperature, ps, clock(0), clock(60), 2, false); got != tc.want {
				t.Fatalf("coverage=%v, want %v", got, tc.want)
			}
		})
	}
	left := []point{{at: clock(0), value: 200}, {at: clock(15), value: 200}}
	e.h.negatives[Power] = []negative{{clock(30), clock(30), clock(15)}}
	if !e.covered(Power, left, clock(0), clock(30), 2, true) || e.covered(Power, left, clock(0), clock(30), 2, false) {
		t.Fatal("transition split is not half-open on the left")
	}
}

func TestCoolingConflictAndDuplicateUseAvailability(t *testing.T) {
	r := request(t, constant(75), nil)
	r.DiscoveryFloor = clock(900)
	orig := r.Facts[len(r.Facts)-2]
	bad := sample(t, Temperature, clock(885), clock(900), 73)
	conflict := fact(t, clock(900), "CONFLICT", a.Conflict{Metric: Temperature, SourceAt: clock(885), Values: a.SortedUnique([]string{orig.ID, bad.ID}), Code: "CONFLICT"})
	negative := rebase(t, r, clock(900), bad, conflict)
	x, _ := invoke(t, negative)
	requireOutcome(t, x, "NO_CANDIDATE")
	old, _ := invoke(t, r)
	requireOutcome(t, old, "OBSERVING")
	// One identical observation and a later PROVENANCE row must not satisfy a
	// three-distinct-timestamp persistent predicate.
	r.Facts = r.Facts[len(r.Facts)-2:]
	arrival := fact(t, clock(900), "PROVENANCE", a.ProvenanceFact{SampleID: orig.ID, SourceRecord: "repeat", Provenance: a.Provenance{
		Mode: "fixture", CollectionRunID: "repeat", Operation: "fixture", ScheduleRevision: 1, InventoryRevision: "fixture", SourceRecord: "repeat",
	}})
	x, _ = invoke(t, rebase(t, r, clock(900), arrival))
	requireOutcome(t, x, "NO_CANDIDATE")
}

func TestCoolingFreshnessAndCurrentCoverageAtLogicalTime(t *testing.T) {
	for _, tc := range []struct {
		name       string
		at         int
		latestTemp float64
		unknown    bool
		endpoint   bool
	}{
		{"fresh despite late execution", 910, 70, false, true},
		{"fresh boundary", 945, 70, false, true},
		{"stale by one second", 946, 70, false, false},
		{"current interval unknown with older endpoint available", 910, 70, true, false},
		{"DCGM sentinel is skipped", 910, 140737488355330, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request(t, func(sec int) float64 {
				if sec == 900 {
					return tc.latestTemp
				}
				return 70
			}, nil)
			at := clock(tc.at)
			r.DiscoveryFloor = at
			base := thermal(t, "thermal", 1, "OPEN", "gpu_thermal", 1, at, at)
			var more = []a.Fact{base, sample(t, Temperature, at.Add(15*time.Second), at, 10)}
			if tc.unknown {
				more = append(more, fact(t, at, "COVERAGE", a.Coverage{Metric: Temperature, From: clock(885), Through: at.Add(15 * time.Second), Code: "COVERAGE", SourceRecord: "fixture"}))
			}
			r = rebase(t, r, at, more...)
			r.ExecutedAt = at.Add(10 * time.Minute)
			x, _ := invoke(t, r)
			requireOutcome(t, x, "URGENT_BYPASS")
			if (x.TerminalEndpointID != "") != tc.endpoint {
				t.Fatalf("endpoint=%s, want available=%v", x.TerminalEndpointID, tc.endpoint)
			}
		})
	}
}

func TestCoolingPersistentOnlySettlesAtRecoveryThreshold(t *testing.T) {
	r := request(t, constant(75), nil)
	r.DiscoveryFloor = r.LogicalAt
	x, m := invoke(t, r)
	arm := armRequest(t, m, x, 60_000)
	for _, tc := range []struct {
		v    float64
		want string
	}{{70, "TRANSIENT_SUPPORTED"}, {70.1, "UNRESOLVED_WARMING"}} {
		var cooling []a.Fact
		for s := 915; s <= 960; s += 15 {
			cooling = append(cooling, sample(t, Temperature, clock(s), clock(s), tc.v))
		}
		y, _ := invoke(t, rebase(t, arm, clock(960), cooling...))
		requireOutcome(t, y, tc.want)
	}
}

func TestCoolingUrgentOccurrenceIsEligibleAtItsLatestSnapshot(t *testing.T) {
	r := request(t, nil, nil)
	r.DiscoveryFloor = clock(900)
	open := fact(t, clock(900), "QUALIFIED", a.Qualified{PolicyID: "thermal", Occurrence: 1, Transition: "OPEN", Rule: "gpu_thermal", RuleVersion: 1, EnrollmentRevision: 1,
		Severity: "CRITICAL", QualifiedAt: clock(900), Snapshot: []a.SnapshotEntry{{Metric: Temperature, Unit: "celsius", Support: "UNKNOWN", SourceAt: clock(915)}}})
	x, _ := invoke(t, rebase(t, r, clock(900), open))
	requireOutcome(t, x, "NO_CANDIDATE")
	x, _ = invoke(t, rebase(t, r, clock(925), open))
	requireOutcome(t, x, "URGENT_BYPASS")
	if x.EntryQualifiedAt == nil || !x.EntryQualifiedAt.Equal(clock(915)) || !slices.Contains(x.Support, open.ID) {
		t.Fatalf("urgency qualified at wrong event: %+v", x)
	}
	alreadyClosed := thermal(t, "thermal", 1, "RECOVER", "gpu_thermal", 1, clock(910), clock(910))
	x, _ = invoke(t, rebase(t, r, clock(925), open, alreadyClosed))
	requireOutcome(t, x, "NO_CANDIDATE")
}

func BenchmarkCoolingComparisonArms(b *testing.B) {
	r := request(b, warmRamp, constant(200))
	r.DiscoveryFloor = r.LogicalAt
	reg := registry(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entry, input, err := reg.Invoke(context.Background(), r)
		if err != nil {
			b.Fatal(err)
		}
		for _, budget := range a.Budgets {
			arm := armRequest(b, input, entry, budget)
			x, m, err := reg.Invoke(context.Background(), arm)
			if err != nil {
				b.Fatal(err)
			}
			requireOutcome(b, x, "COOLING_SUSPECTED")
			input.Facts, input.Bundle = m.Facts, m.Bundle
		}
	}
}

func TestCoolingOptionalUtilizationCannotChangeAssessment(t *testing.T) {
	d := (Category{}).Describe()
	if !slices.ContainsFunc(d.Metrics, func(m a.Metric) bool { return m.Metric == Utilization && m.Unit == "percent" && !m.Required }) {
		t.Fatal("optional utilization missing from descriptor")
	}
	r := request(t, warmRamp, constant(200))
	r.DiscoveryFloor = r.LogicalAt
	baseline, _ := invoke(t, r)
	var utilization []a.Fact
	for sec := 0; sec <= 900; sec += 15 {
		at := clock(sec)
		utilization = append(utilization, fact(t, at, "SAMPLE", a.Sample{Metric: Utilization, Unit: "percent", SourceAt: at, CollectedAt: at, CompletedAt: at,
			Value: float64(sec % 100), SourceRecord: "fixture", Provenance: a.Provenance{Mode: "fixture", CollectionRunID: "fixture", Operation: "fixture", ScheduleRevision: 1, InventoryRevision: "fixture", SourceRecord: "fixture"}}))
	}
	x, _ := invoke(t, rebase(t, r, r.LogicalAt, utilization...))
	if x.Outcome != baseline.Outcome || x.State.Hash != baseline.State.Hash || x.InitialCandidateState.Hash != baseline.InitialCandidateState.Hash ||
		!slices.Equal(x.Support, baseline.Support) || !x.EntryQualifiedAt.Equal(*baseline.EntryQualifiedAt) {
		t.Fatalf("optional utilization influenced the determination: %+v", x)
	}
}

func TestCoolingPersistentOnlySettlesAtDeadlineWithoutEarlierEndpoint(t *testing.T) {
	r := request(t, constant(75), nil)
	r.DiscoveryFloor = r.LogicalAt
	entry, m := invoke(t, r)
	arm := armRequest(t, m, entry, 120_000)
	var cooled []a.Fact
	for sec := 975; sec <= 1020; sec += 15 {
		cooled = append(cooled, sample(t, Temperature, clock(sec), clock(sec), 69))
	}
	// The latest 45 seconds are covered, but the first cool point's own
	// 30-second endpoint has no preceding samples after entry.
	result, _ := invoke(t, rebase(t, arm, clock(1020), cooled...))
	requireOutcome(t, result, "TRANSIENT_SUPPORTED")
	if result.Action != "NONE" || result.TerminalEndpointID == "" {
		t.Fatalf("persistent-only transient lacks its expected action or current endpoint: %+v", result)
	}
}

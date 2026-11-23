package alertassessment_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// countingProduction delegates to the production cooling category and counts
// invocations. The descriptor is unchanged, so hashes and snapshots are too.
type countingProduction struct {
	cooling.ProductionCategory
	calls *atomic.Int64
}

func (c countingProduction) Evaluate(ctx context.Context, r a.Request) (a.Result, error) {
	c.calls.Add(1)
	return c.ProductionCategory.Evaluate(ctx, r)
}

// plainProduction delegates to the production cooling category without
// embedding it, so it does not opt into VisibleInputReplay.
type plainProduction struct {
	inner cooling.ProductionCategory
	calls *atomic.Int64
}

func (c plainProduction) Describe() a.Descriptor { return c.inner.Describe() }
func (c plainProduction) ValidatePolicy(ctx context.Context, p a.Payload) error {
	return c.inner.ValidatePolicy(ctx, p)
}
func (c plainProduction) Evaluate(ctx context.Context, r a.Request) (a.Result, error) {
	c.calls.Add(1)
	return c.inner.Evaluate(ctx, r)
}
func (c plainProduction) ValidateResult(ctx context.Context, r a.Request, x a.Result) error {
	return c.inner.ValidateResult(ctx, r, x)
}

type replayCase struct {
	t      *testing.T
	c      a.ProductionConfig
	r      *a.Registry
	calls  *atomic.Int64
	start  time.Time
	asset  string
	legacy bool
}

func newReplayCase(t *testing.T, legacy bool) *replayCase {
	return newReplayCaseFor(t, legacy, true)
}

func newReplayCaseFor(t *testing.T, legacy, optIn bool) *replayCase {
	t.Helper()
	c, _, start := productionFixture(t)
	calls := new(atomic.Int64)
	var production a.Category = countingProduction{calls: calls}
	if !optIn {
		production = plainProduction{calls: calls}
	}
	r, err := a.NewRegistry(cooling.Category{}, production)
	if err != nil {
		t.Fatal(err)
	}
	return &replayCase{t: t, c: c, r: r, calls: calls, start: start, asset: c.Assessment.Assets[0].EntityKey, legacy: legacy}
}

// pass mirrors one production refresh: restore, admit, advance, snapshot.
func (rc *replayCase) pass(raw []byte, at time.Time, facts []a.Fact) ([]byte, string, []time.Time) {
	rc.t.Helper()
	e, err := a.NewProductionAssetEngine(rc.t.Context(), rc.c, rc.start, rc.r, rc.asset)
	if err != nil {
		rc.t.Fatal(err)
	}
	if err = e.RestoreProduction(rc.asset, raw); err != nil {
		rc.t.Fatal(err)
	}
	a.SetReplayHiddenBoundaries(e, rc.legacy)
	if err = e.AdvanceAssets(rc.t.Context(), at, at, at, facts, nil, []string{rc.asset}); err != nil {
		rc.t.Fatal(err)
	}
	out, logical := "", []time.Time{}
	for _, d := range e.Decisions {
		logical = append(logical, d.LogicalAt)
		evidence, err := e.ProductionEvidence(d)
		if err != nil {
			rc.t.Fatal(err)
		}
		b, _ := json.Marshal(d)
		out += string(b) + "\n" + string(evidence) + "\n"
	}
	snap, err := e.SnapshotProduction(rc.asset, at)
	if err != nil {
		rc.t.Fatal(err)
	}
	return snap, out, logical
}

func (rc *replayCase) sample(metric string, source, available time.Time, temperature float64) a.Fact {
	rc.t.Helper()
	var b a.Binding
	for _, x := range rc.c.Assessment.Bindings {
		if x.Metric == metric {
			b = x
		}
	}
	v, u := temperature, "celsius"
	if metric == cooling.Power {
		v, u = 200, "watts"
	}
	id := fmt.Sprintf("sample-%s-%d", metric, source.Unix())
	digest := domain.ChecksumSHA256([]byte(id)).String()
	s := a.Sample{Metric: metric, Unit: u, SourceAt: source, CollectedAt: source, CompletedAt: source, Value: v, SourceRecord: id, Provenance: a.Provenance{Mode: "upload", CollectionRunID: domain.CoolingUploadRunPrefix + digest, Operation: b.Operation, ScheduleRevision: b.ScheduleRevision, InventoryRevision: rc.c.Assessment.InventoryRevision, SourceRecord: id, CollectorID: b.UploadCollectorID, UploadProfileID: b.UploadProfileID, UploadProfileHash: b.UploadProfileHash}}
	f, err := a.NewFact(rc.c.Assessment.Category, rc.c.Assessment.RunID, rc.asset, "SAMPLE", available, s)
	if err != nil {
		rc.t.Fatal(err)
	}
	return f
}

func (rc *replayCase) fact(kind string, available time.Time, body any) a.Fact {
	rc.t.Helper()
	f, err := a.NewFact(rc.c.Assessment.Category, rc.c.Assessment.RunID, rc.asset, kind, available, body)
	if err != nil {
		rc.t.Fatal(err)
	}
	return f
}

// visibleScenario describes passes after a steady warm phase. Each source slot
// in (prev, at] is admitted at the pass that first sees it; lag(source) gives
// its availability, clamped to that pass (lag 0 = available at the pass).
type visibleScenario struct {
	name     string
	warm     func(time.Duration) float64
	cold     func(time.Duration) float64
	downtime time.Duration
	passes   int
	cadence  time.Duration
	lag      func(time.Duration) time.Duration
	extra    func(rc *replayCase, restart time.Time) []a.Fact
	// expect lists decision substrings the scenario must produce; inGap
	// requires a decision whose logical time precedes the restart; fewer
	// requires that hidden boundaries were actually skipped.
	expect []string
	inGap  bool
	fewer  bool
	// same requires identical invocations: nothing in the scenario is hidden.
	same bool
}

type visibleRun struct {
	snaps     [][]byte
	decisions []string
	calls     int64
	inGap     int
}

func (sc visibleScenario) run(t *testing.T, legacy bool) visibleRun {
	return sc.runFor(t, legacy, true)
}

func (sc visibleScenario) runFor(t *testing.T, legacy, optIn bool) visibleRun {
	rc := newReplayCaseFor(t, legacy, optIn)
	at, raw := rc.start, []byte(nil)
	slot := 15 * time.Second
	admit := func(prev, at time.Time, temp func(time.Duration) float64, lag func(time.Duration) time.Duration) []a.Fact {
		out := []a.Fact{}
		for s := prev.Add(slot); !s.After(at); s = s.Add(slot) {
			if s.Before(at.Add(-900 * time.Second)) {
				continue
			}
			available := at
			if lag != nil {
				if late := s.Add(lag(s.Sub(rc.start))); late.Before(at) {
					available = late
				}
			}
			for _, m := range []string{cooling.Temperature, cooling.Power} {
				out = append(out, rc.sample(m, s, available, temp(s.Sub(rc.start))))
			}
		}
		return out
	}
	for range 11 {
		raw, _, _ = rc.pass(raw, at, admit(at.Add(-slot), at, sc.warm, nil))
		at = at.Add(slot)
	}
	prev := at.Add(-slot)
	restart := prev.Add(sc.downtime)
	rc.calls.Store(0)
	out := visibleRun{}
	cadence := sc.cadence
	if cadence == 0 {
		cadence = slot
	}
	for i := range sc.passes {
		at := restart.Add(time.Duration(i) * cadence)
		facts := admit(prev, at, sc.cold, sc.lag)
		if i == 0 && sc.extra != nil {
			facts = append(facts, sc.extra(rc, restart)...)
		}
		var d string
		var logical []time.Time
		raw, d, logical = rc.pass(raw, at, facts)
		out.snaps, out.decisions = append(out.snaps, raw), append(out.decisions, d)
		for _, l := range logical {
			if l.Before(restart) {
				out.inGap++
			}
		}
		prev = at
	}
	out.calls = rc.calls.Load()
	return out
}

func visibleScenarios() []visibleScenario {
	hot := func(time.Duration) float64 { return 82 }
	cool := func(time.Duration) float64 { return 55 }
	// Warms past entry thresholds in the last minute of the steady phase, so an
	// arm opens just before the outage and its deadline falls inside the gap.
	lateRamp := func(d time.Duration) float64 {
		if d >= 90*time.Second {
			return 55 + float64(d-90*time.Second)/float64(time.Second)
		}
		return 55
	}
	ramp := func(d time.Duration) float64 { return 55 + float64(d%(600*time.Second))/float64(20*time.Second) }
	return []visibleScenario{
		{name: "overdue restart, recovers", warm: hot, cold: cool, downtime: 1050 * time.Second, passes: 13, expect: []string{`"kind":"RECOVER"`}, fewer: true},
		{name: "overdue restart, enters hot", warm: cool, cold: hot, downtime: 1050 * time.Second, passes: 13, expect: []string{`"kind":"TERMINAL"`, `"action":"INVESTIGATE"`}},
		{name: "short restart, stays hot", warm: hot, cold: hot, downtime: 60 * time.Second, passes: 13, fewer: true},
		{name: "overdue restart, healthy", warm: cool, cold: cool, downtime: 1050 * time.Second, passes: 13},
		{name: "restart, warms mid window", warm: cool, cold: ramp, downtime: 960 * time.Second, passes: 13, expect: []string{`"kind":"TERMINAL"`}},
		{name: "arm deadline inside gap", warm: lateRamp, cold: hot, downtime: 300 * time.Second, passes: 13, expect: []string{`"kind":"TERMINAL"`}, inGap: true, fewer: true},
		{name: "arm deadline inside gap, cools", warm: lateRamp, cold: cool, downtime: 300 * time.Second, passes: 13, expect: []string{`"kind":"TERMINAL"`, `"kind":"RECOVER"`}, inGap: true, fewer: true},
		// Receipts arrive late but inside the gap: their availability instants are
		// real input changes and must still be reconstructed.
		{name: "late receipts visible inside gap", warm: cool, cold: hot, downtime: 600 * time.Second, passes: 8, lag: func(time.Duration) time.Duration { return 20 * time.Second }, expect: []string{`"kind":"TERMINAL"`}, fewer: true},
		{name: "slow passes, mixed lateness", warm: hot, cold: ramp, downtime: 120 * time.Second, passes: 8, cadence: 75 * time.Second,
			lag: func(d time.Duration) time.Duration { return time.Duration(int64(d/time.Second)%4) * 10 * time.Second }, fewer: true},
		{name: "coverage loss during gap", warm: hot, cold: hot, downtime: 600 * time.Second, passes: 8,
			extra: func(rc *replayCase, restart time.Time) []a.Fact {
				from := restart.Add(-400 * time.Second)
				return []a.Fact{rc.fact("COVERAGE", restart, a.Coverage{Metric: cooling.Temperature, Code: "sparse", From: from, Through: from.Add(120 * time.Second), SourceRecord: "gap"})}
			}, fewer: true},
		// A boundary after its fact's availability, inside the gap, stays an event.
		{name: "coverage boundary after availability", warm: hot, cold: hot, downtime: 600 * time.Second, passes: 8,
			lag: func(time.Duration) time.Duration { return 0 },
			extra: func(rc *replayCase, restart time.Time) []a.Fact {
				available := restart.Add(-300 * time.Second)
				return []a.Fact{rc.fact("COVERAGE", available, a.Coverage{Metric: cooling.Temperature, Code: "sparse", From: available.Add(-20 * time.Second), Through: available.Add(100 * time.Second), SourceRecord: "ahead"})}
			}, same: true},
		// Urgent paths: an independently qualified critical event whose snapshot
		// falls inside the gap, with and without its recovery, and one already
		// visible inside the gap.
		{name: "urgent open inside gap", warm: hot, cold: hot, downtime: 600 * time.Second, passes: 8,
			extra: func(rc *replayCase, restart time.Time) []a.Fact {
				return []a.Fact{rc.qualified("OPEN", 1, restart, restart.Add(-300*time.Second))}
			}, expect: []string{`"action":"URGENT"`}, fewer: true},
		{name: "urgent open and recover inside gap", warm: hot, cold: cool, downtime: 600 * time.Second, passes: 8,
			extra: func(rc *replayCase, restart time.Time) []a.Fact {
				return []a.Fact{rc.qualified("OPEN", 1, restart, restart.Add(-400*time.Second)), rc.qualified("RECOVER", 1, restart, restart.Add(-200*time.Second))}
			}, expect: []string{`"kind":"RECOVER"`}, fewer: true},
		{name: "urgent open visible mid gap", warm: hot, cold: hot, downtime: 600 * time.Second, passes: 8,
			extra: func(rc *replayCase, restart time.Time) []a.Fact {
				return []a.Fact{rc.qualified("OPEN", 1, restart.Add(-250*time.Second), restart.Add(-300*time.Second))}
			}, expect: []string{`"action":"URGENT"`}, inGap: true, fewer: true},
	}
}

func (rc *replayCase) qualified(transition string, occ int64, available, qualifiedAt time.Time) a.Fact {
	rc.t.Helper()
	return rc.fact("QUALIFIED", available, a.Qualified{PolicyID: "visible-replay", Occurrence: occ, Transition: transition, Rule: "gpu_thermal", RuleVersion: 1,
		EnrollmentRevision: 1, Severity: "CRITICAL", QualifiedAt: qualifiedAt, Snapshot: []a.SnapshotEntry{}})
}

// TestVisibleReplayMatchesFullReplay requires reconstruction to produce the
// same snapshots, ordered decisions and evidence as the previous reconstruction
// that also invoked at hidden source boundaries, while invoking less.
func TestVisibleReplayMatchesFullReplay(t *testing.T) {
	for _, sc := range visibleScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			full, visible := sc.run(t, true), sc.run(t, false)
			for i := range full.snaps {
				if string(visible.snaps[i]) != string(full.snaps[i]) {
					t.Fatalf("pass %d snapshot differs from full replay", i)
				}
				if visible.decisions[i] != full.decisions[i] {
					t.Fatalf("pass %d decisions differ from full replay:\n got %s\nwant %s", i, visible.decisions[i], full.decisions[i])
				}
			}
			all := strings.Join(visible.decisions, "")
			for _, want := range sc.expect {
				if !strings.Contains(all, want) {
					t.Fatalf("scenario produced no %s decision", want)
				}
			}
			if sc.inGap && visible.inGap == 0 {
				t.Fatal("scenario produced no decision inside the gap")
			}
			if visible.calls > full.calls || sc.fewer && visible.calls == full.calls || sc.same && visible.calls != full.calls {
				t.Fatalf("invocations full=%d visible=%d (fewer=%v)", full.calls, visible.calls, sc.fewer)
			}
			t.Logf("invocations full=%d visible=%d decisions in gap=%d", full.calls, visible.calls, visible.inGap)
		})
	}
}

// The saving is real where it matters: an overdue restart replays far fewer
// invocations, and boundaries visible at or after availability are kept.
func TestVisibleReplaySkipsOnlyHiddenBoundaries(t *testing.T) {
	sc := visibleScenarios()[0]
	if full, visible := sc.run(t, true).calls, sc.run(t, false).calls; visible*4 > full {
		t.Fatalf("overdue restart invocations full=%d visible=%d, want at least 4x fewer", full, visible)
	}
}

// A category that does not implement VisibleInputReplay keeps the full
// reconstruction, including hidden boundaries.
func TestVisibleReplayIsOptIn(t *testing.T) {
	sc := visibleScenarios()[0]
	full := sc.run(t, true)
	plain := sc.runFor(t, false, false)
	if plain.calls != full.calls {
		t.Fatalf("category without opt-in invoked %d times, full reconstruction %d", plain.calls, full.calls)
	}
	for i := range full.snaps {
		if string(plain.snaps[i]) != string(full.snaps[i]) || plain.decisions[i] != full.decisions[i] {
			t.Fatalf("pass %d differs for a category without opt-in", i)
		}
	}
	if opted := sc.run(t, false); opted.calls >= full.calls {
		t.Fatalf("opted-in category did not skip hidden boundaries: %d >= %d", opted.calls, full.calls)
	}
}

// A hidden source time can coincide with a change to previously visible
// evidence: the oldest sample drops out, while the last endpoint is fresh.
// Record exactly what the real cooling tracker sees between the two passes.
type windowProbe struct {
	cooling.ProductionCategory
	edge, after               time.Time
	expired, latest, incoming string
	reached                   atomic.Bool
}

func (p *windowProbe) Evaluate(ctx context.Context, r a.Request) (a.Result, error) {
	if r.Scope == "TRACKER" && r.Purpose == "FOLLOW_UP" && r.LogicalAt.Equal(p.after) {
		contains := func(id string) bool {
			return slices.ContainsFunc(r.Facts, func(f a.Fact) bool { return f.ID == id })
		}
		p.reached.Store(!contains(p.expired) && contains(p.latest) && !contains(p.incoming))
	}
	return p.ProductionCategory.Evaluate(ctx, r)
}

func TestVisibleReplayRevisitsTrackerWhenWindowShrinks(t *testing.T) {
	rc := newReplayCase(t, false)
	at := func(s int) time.Time { return rc.start.Add(time.Duration(s) * time.Second) }
	probe := &windowProbe{edge: at(1050), after: at(1057)}
	reg, err := a.NewRegistry(cooling.Category{}, probe)
	if err != nil {
		t.Fatal(err)
	}
	rc.r = reg
	var raw []byte
	for s := 0; s <= 1035; s += 15 {
		temp := rc.sample(cooling.Temperature, at(s), at(s), 82)
		if s == 150 {
			probe.expired = temp.ID
		}
		if s == 1035 {
			probe.latest = temp.ID
		}
		raw, _, _ = rc.pass(raw, at(s), []a.Fact{temp, rc.sample(cooling.Power, at(s), at(s), 200)})
	}
	raw, _, _ = rc.pass(raw, at(1045), nil)
	end := at(1069)
	first := rc.sample(cooling.Temperature, probe.edge, end, 83)
	second := rc.sample(cooling.Temperature, probe.after, end, 84)
	probe.incoming = second.ID
	rc.pass(raw, end, []a.Fact{first, second})
	if !probe.reached.Load() {
		t.Fatal("tracker never saw the shortened history before the delayed samples became available")
	}
}

func TestVisibleReplayPreservesInactiveDiscoveryRevision(t *testing.T) {
	sc := visibleScenarios()[0]
	sc.downtime = 540 * time.Second
	sc.passes = 13
	sc.cold = func(d time.Duration) float64 {
		if d > 690*time.Second {
			return 82
		}
		return 55
	}
	sc.lag = func(d time.Duration) time.Duration {
		if d < 570*time.Second {
			return 0
		}
		return time.Hour
	}
	full, opt := sc.run(t, true), sc.run(t, false)
	for i := range full.snaps {
		if string(full.snaps[i]) != string(opt.snaps[i]) || full.decisions[i] != opt.decisions[i] {
			t.Fatalf("pass %d diverged after re-arm", i)
		}
	}
}

func TestVisibleReplayRetriesRearmAfterDisposition(t *testing.T) {
	run := func(legacy bool) time.Duration {
		rc := newReplayCase(t, legacy)
		p := cooling.DefaultPolicy()
		p.RearmSeconds, p.SettlingSeconds, p.PersistentConfirmSeconds = 15, 45, 120
		rc.c.Assessment.Policy, _ = json.Marshal(p)
		at := func(s int) time.Time { return rc.start.Add(time.Duration(s) * time.Second) }
		var raw []byte
		for s := 0; s <= 105; s += 15 {
			temp := 55.
			if s <= 60 {
				temp = 82
			}
			raw, _, _ = rc.pass(raw, at(s), []a.Fact{rc.sample(cooling.Temperature, at(s), at(s), temp), rc.sample(cooling.Power, at(s), at(s), 200)})
		}
		var facts []a.Fact
		for s := 120; s <= 195; s += 15 {
			available := at(s)
			if s%30 != 0 {
				available = at(195)
			}
			facts = append(facts, rc.sample(cooling.Temperature, at(s), available, 55), rc.sample(cooling.Power, at(s), available, 200))
		}
		_, out, _ := rc.pass(raw, at(195), facts)
		for _, line := range strings.Split(out, "\n") {
			var d a.Decision
			if json.Unmarshal([]byte(line), &d) == nil && d.Kind == "RECOVER" {
				return d.LogicalAt.Sub(rc.start)
			}
		}
		t.Fatal("missing recovery")
		return 0
	}
	for _, legacy := range []bool{true, false} {
		if when := run(legacy); when != 135*time.Second {
			t.Fatalf("legacy=%t recovered at %s", legacy, when)
		}
	}
}

func TestVisibleReplayAfterEmptyPassFinalizesArm(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		rc := newReplayCase(t, legacy)
		p := cooling.DefaultPolicy()
		p.RearmSeconds, p.SettlingSeconds, p.PersistentConfirmSeconds = 15, 240, 120
		rc.c.Assessment.Policy, _ = json.Marshal(p)
		at := func(s int) time.Time { return rc.start.Add(time.Duration(s) * time.Second) }
		var raw []byte
		for s := 0; s <= 120; s += 15 {
			temp := 55.
			if s <= 60 {
				temp = 82
			}
			raw, _, _ = rc.pass(raw, at(s), []a.Fact{rc.sample(cooling.Temperature, at(s), at(s), temp), rc.sample(cooling.Power, at(s), at(s), 200)})
		}
		raw, _, _ = rc.pass(raw, at(151), nil)
		_, out, _ := rc.pass(raw, at(181), []a.Fact{rc.sample(cooling.Power, at(152), at(181), 200)})
		var recovered time.Time
		for _, line := range strings.Split(out, "\n") {
			var d a.Decision
			if json.Unmarshal([]byte(line), &d) == nil && d.Kind == "RECOVER" {
				recovered = d.LogicalAt
			}
		}
		if !recovered.Equal(at(152)) {
			t.Fatalf("legacy=%t recovered at %s, want %s", legacy, recovered, at(152))
		}
	}
}

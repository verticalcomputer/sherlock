package alertassessment_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
)

// The reference for catch-up is continuous evaluation: the same production
// per-pass cycle run every 15 s through the gap, each fact admitted at the
// first pass at or after its availability. Catch-up instead stops passes
// during the gap and resumes at restart. After every post-restart pass, the
// state that decides alerts must be the same: decisions and their evidence
// (apart from when they were executed and committed), candidates with their
// notification deadlines, the tracker and re-arm sequence, and telemetry-loss
// records. Only execution/commit times and the lateness derived from them may
// differ, because catch-up commits later by construction.

type timelineFact struct {
	f      a.Fact
	source time.Time
}

type continuousScenario struct {
	name string
	// temp gives the temperature of the source slot at offset d from start;
	// ok=false means no sample exists for that slot (collector outage).
	temp func(d time.Duration) (float64, bool)
	// gapLag, when set, makes gap slots available at source+lag (a multiple of
	// 15 s) instead of being held until the restart.
	gapLag   time.Duration
	warm     time.Duration // steady passes before the outage
	downtime time.Duration
	after    time.Duration // passes after restart
	extra    func(rc *replayCase, start, restart time.Time) []a.Fact
	faults   func(rc *replayCase, start, restart time.Time) []a.Fault
	// expect lists decision substrings the reference must produce.
	expect []string
	// check inspects the reference outcome for scenario-specific behaviour.
	check func(t *testing.T, ref outcome)
	// legacyDiffers marks scenarios where the previous reconstruction is
	// expected to deviate from continuous evaluation (documented below).
	legacyDiffers bool
	// evidenceRestamped marks scenarios where catch-up materializes derived
	// facts at the restart commit time while continuous evaluation does so
	// at each pass. Their content-derived IDs, and so bundle membership,
	// differ in both the previous and the new reconstruction. Everything
	// else must still match continuous evaluation, and the new
	// reconstruction must match the previous one exactly.
	evidenceRestamped bool
	// catchUpDiffers marks a documented property of catch-up itself: both
	// reconstructions deviate identically from continuous evaluation, and the
	// new one must equal the previous one exactly.
	catchUpDiffers bool
	// legacyEither skips the expectation on the previous reconstruction.
	legacyEither bool
}

type outcome struct {
	views    []string // per post-restart pass
	core     []string // views without evidence bundles (see evidenceRestamped)
	kinds    map[string]string
	calls    int64
	sequence int64
	rearms   int
	inGap    int
}

const (
	modeContinuous = iota
	modeCatchUp
	modeLegacy
)

func (sc continuousScenario) timeline(rc *replayCase, start, restart, end time.Time) []timelineFact {
	out := []timelineFact{}
	gapStart := start.Add(sc.warm)
	for s := start; !s.After(end); s = s.Add(15 * time.Second) {
		v, ok := sc.temp(s.Sub(start))
		if !ok {
			continue
		}
		available := s
		if s.After(gapStart) && s.Before(restart) {
			available = restart
			if sc.gapLag > 0 && s.Add(sc.gapLag).Before(restart) {
				available = s.Add(sc.gapLag)
			}
		}
		for _, m := range []string{cooling.Temperature, cooling.Power} {
			out = append(out, timelineFact{rc.sample(m, s, available, v), s})
		}
	}
	if sc.extra != nil {
		for _, f := range sc.extra(rc, start, restart) {
			out = append(out, timelineFact{f, f.AvailableAt})
		}
	}
	return out
}

func (sc continuousScenario) run(t *testing.T, mode int) outcome {
	rc := newReplayCase(t, mode == modeLegacy)
	start := rc.start
	restart := start.Add(sc.warm + sc.downtime)
	end := restart.Add(sc.after)
	facts := sc.timeline(rc, start, restart, end)
	var faults []a.Fault
	if sc.faults != nil {
		faults = sc.faults(rc, start, restart)
	}
	passes := []time.Time{}
	for p := start; !p.After(end); p = p.Add(15 * time.Second) {
		if mode != modeContinuous && p.After(start.Add(sc.warm)) && p.Before(restart) {
			continue
		}
		passes = append(passes, p)
	}
	admitted := map[string]bool{}
	raw := []byte(nil)
	decisions, cores := []string{}, []string{}
	out := outcome{kinds: map[string]string{}}
	// Telemetry and failure records are collected as each pass produces them:
	// production snapshots do not carry telemetry records between passes.
	records := map[string]string{}
	for _, p := range passes {
		batch := []a.Fact{}
		for _, tf := range facts {
			// The store loads only the history window for a new admission.
			if admitted[tf.f.ID] || tf.f.AvailableAt.After(p) || tf.source.Before(p.Add(-900*time.Second)) {
				continue
			}
			admitted[tf.f.ID] = true
			batch = append(batch, tf.f)
		}
		if p.Equal(restart) {
			rc.calls.Store(0)
		}
		e, err := a.NewProductionAssetEngine(rc.t.Context(), rc.c, rc.start, rc.r, rc.asset)
		if err != nil {
			t.Fatal(err)
		}
		if err = e.RestoreProduction(rc.asset, raw); err != nil {
			t.Fatal(err)
		}
		a.SetReplayHiddenBoundaries(e, mode == modeLegacy)
		before := int64(0)
		if en := e.Enrollments[rc.asset]; en != nil {
			before = en.Sequence
		}
		if err = e.AdvanceAssets(rc.t.Context(), p, p, p, batch, faults, []string{rc.asset}); err != nil {
			t.Fatal(err)
		}
		for _, d := range e.Decisions {
			evidence, err := e.ProductionEvidence(d)
			if err != nil {
				t.Fatal(err)
			}
			d.ExecutedAt, d.CommittedAt, d.LatenessUS = time.Time{}, time.Time{}, 0
			b, _ := json.Marshal(d)
			decisions = append(decisions, string(b)+"\n"+stripCommitTiming(t, evidence))
			d.BundleID = ""
			b, _ = json.Marshal(d)
			cores = append(cores, string(b))
			if d.LogicalAt.After(start.Add(sc.warm)) && d.LogicalAt.Before(restart) {
				out.inGap++
			}
		}
		for id, r := range e.Telemetry {
			if r.Asset == rc.asset {
				b, _ := json.Marshal(r)
				records["telemetry "+id] = string(b)
			}
		}
		for _, f := range e.Failures {
			if f.Asset == rc.asset {
				b, _ := json.Marshal(struct {
					ID, Kind, Code, Scope, Candidate string
					First                            time.Time
					From, Through                    *time.Time
					Facts                            []string
				}{f.ID, f.Kind, f.Code, f.ScopeKey, f.CandidateID, f.FirstAt, f.LogicalFrom, f.LogicalThrough, f.FactIDs})
				records["failure "+f.ID] = string(b)
			}
		}
		en := e.Enrollments[rc.asset]
		if en != nil && en.Sequence > before && before > 0 {
			out.rearms += int(en.Sequence - before)
		}
		if raw, err = e.SnapshotProduction(rc.asset, p); err != nil {
			t.Fatal(err)
		}
		if p.Before(restart) {
			continue
		}
		out.views = append(out.views, semanticView(t, e, rc.asset, decisions, records))
		out.core = append(out.core, coreView(e, rc.asset, cores, records))
		for _, f := range e.Facts {
			out.kinds[f.ID] = f.Kind
		}
		if en != nil {
			out.sequence = en.Sequence
		}
	}
	out.calls = rc.calls.Load()
	return out
}

// semanticView is everything that decides or delivers an alert, in a stable
// order. Decisions are cumulative and sorted by logical time, because
// continuous evaluation emits gap decisions in earlier passes.
func semanticView(t *testing.T, e *a.Engine, asset string, decisions []string, records map[string]string) string {
	t.Helper()
	ds := slices.Clone(decisions)
	slices.Sort(ds)
	candidates := []string{}
	for _, c := range e.Candidates {
		if c.Asset != asset {
			continue
		}
		b, _ := json.Marshal(struct {
			ID, Phase              string
			Sequence, Budget       int64
			Entered, Due, Fallback time.Time
			Basis, State           string
			Terminal               *a.Terminal
			Next                   *time.Time
		}{c.ID, c.Phase, c.Sequence, c.BudgetMS, c.EnteredAt, c.DueAt, c.Entry.Fallback.DueAt, c.Entry.Basis, c.State.Hash, c.Terminal, c.NextLogicalAt})
		candidates = append(candidates, string(b))
	}
	slices.Sort(candidates)
	en := e.Enrollments[asset]
	tracker := ""
	if en.Tracker != nil {
		tracker = en.Tracker.Hash
	}
	enrollment, _ := json.Marshal(struct {
		Sequence int64
		Active   bool
		Tracker  string
		Floor    time.Time
		Next     *time.Time
	}{en.Sequence, en.Active, tracker, en.DiscoveryFloor, en.NextLogicalAt})
	recs := []string{}
	for k, v := range records {
		recs = append(recs, k+" "+v)
	}
	slices.Sort(recs)
	return fmt.Sprintf("decisions:\n%s\ncandidates:\n%s\nenrollment: %s\nrecords:\n%s", strings.Join(ds, "\n"), strings.Join(candidates, "\n"), enrollment, strings.Join(recs, "\n"))
}

// coreView is the alert-relevant state without evidence bundles: decisions,
// the enrollment (re-arm sequence), records, and candidates keyed by ID so
// that retention of finished candidates can be compared on the intersection.
func coreView(e *a.Engine, asset string, decisions []string, records map[string]string) string {
	ds := slices.Clone(decisions)
	slices.Sort(ds)
	en := e.Enrollments[asset]
	tracker := ""
	if en.Tracker != nil {
		tracker = en.Tracker.Hash
	}
	parts := map[string]any{"decisions": ds, "records": records,
		"enrollment": []any{en.Sequence, en.Active, tracker, en.DiscoveryFloor, en.NextLogicalAt}}
	candidates := map[string]any{}
	for _, c := range e.Candidates {
		if c.Asset == asset {
			candidates[c.ID] = []any{c.Phase, c.Sequence, c.EnteredAt, c.DueAt, c.Entry.Fallback.DueAt, c.State.Hash, c.Terminal}
		}
	}
	parts["candidates"] = candidates
	b, _ := json.Marshal(parts)
	return string(b)
}

// sameCore compares core views, requiring equal candidates on the intersection.
func sameCore(t *testing.T, got, ref string) string {
	t.Helper()
	var g, r map[string]json.RawMessage
	if json.Unmarshal([]byte(got), &g) != nil || json.Unmarshal([]byte(ref), &r) != nil {
		t.Fatal("bad core view")
	}
	for _, k := range []string{"decisions", "records", "enrollment"} {
		if string(g[k]) != string(r[k]) {
			return k + ": " + firstDiff(string(g[k]), string(r[k]))
		}
	}
	var gc, rc map[string]json.RawMessage
	_ = json.Unmarshal(g["candidates"], &gc)
	_ = json.Unmarshal(r["candidates"], &rc)
	shared := 0
	for id, v := range rc {
		if w, ok := gc[id]; ok {
			shared++
			if string(w) != string(v) {
				return "candidate " + id + ": " + firstDiff(string(w), string(v))
			}
		}
	}
	if len(rc) > 0 && shared == 0 {
		return "no candidate in common"
	}
	// Only finished candidates may differ in retention.
	for _, side := range []struct {
		name     string
		mine, of map[string]json.RawMessage
	}{{"continuous", rc, gc}, {"catch-up", gc, rc}} {
		for id, v := range side.mine {
			if _, ok := side.of[id]; !ok && strings.Contains(string(v), `"OBSERVING"`) {
				return "in-flight candidate " + id + " only in " + side.name
			}
		}
	}
	return ""
}

func stripCommitTiming(t *testing.T, raw []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var strip func(any)
	strip = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for _, k := range []string{"executed_at", "committed_at", "lateness_us"} {
				delete(x, k)
			}
			for _, y := range x {
				strip(y)
			}
		case []any:
			for _, y := range x {
				strip(y)
			}
		}
	}
	strip(v)
	b, _ := json.Marshal(v)
	return string(b)
}

func firstDiff(x, y string) string {
	xs, ys := strings.Split(x, "\n"), strings.Split(y, "\n")
	for i := range min(len(xs), len(ys)) {
		if xs[i] != ys[i] {
			j := 0
			for j < min(len(xs[i]), len(ys[i])) && xs[i][j] == ys[i][j] {
				j++
			}
			from := max(0, j-160)
			return fmt.Sprintf("line %d at %d:\n catch-up:   …%.360s\n continuous: …%.360s", i, j, xs[i][from:], ys[i][from:])
		}
	}
	return fmt.Sprintf("length %d vs %d", len(xs), len(ys))
}

func continuousScenarios() []continuousScenario {
	always := func(v float64) func(time.Duration) (float64, bool) {
		return func(time.Duration) (float64, bool) { return v, true }
	}
	phases := func(steps ...any) func(time.Duration) (float64, bool) {
		// steps: until(time.Duration), temperature(float64) pairs; final temperature after.
		return func(d time.Duration) (float64, bool) {
			for i := 0; i+1 < len(steps); i += 2 {
				if d < steps[i].(time.Duration) {
					v := steps[i+1].(float64)
					return v, v > 0
				}
			}
			v := steps[len(steps)-1].(float64)
			return v, v > 0
		}
	}
	s := time.Second
	T, R, U, I := `"kind":"TERMINAL"`, `"kind":"RECOVER"`, `"action":"URGENT"`, `"action":"INVESTIGATE"`
	return []continuousScenario{
		{name: "overdue restart, recovers", temp: phases(165*s, 82.0, 55.0), warm: 165 * s, downtime: 1050 * s, after: 180 * s, expect: []string{R}},
		{name: "arm deadline inside gap", temp: phases(120*s, 55.0, 82.0), warm: 165 * s, downtime: 300 * s, after: 180 * s, expect: []string{T, I},
			check: func(t *testing.T, ref outcome) {
				if ref.inGap == 0 {
					t.Fatal("no decision inside the gap")
				}
			}},
		{name: "urgent open inside gap", temp: always(82), warm: 165 * s, downtime: 600 * s, after: 120 * s, expect: []string{U},
			extra: func(rc *replayCase, start, restart time.Time) []a.Fact {
				return []a.Fact{rc.qualified("OPEN", 1, restart, restart.Add(-300*s))}
			}},
		// Re-arm and rediscovery inside the gap, from samples that became
		// visible during it: hot entry, 450 s of covered recovery, hot again.
		// The restart still loads every sample visible in the gap (the store
		// admits only the last 900 s, a limitation of catch-up itself).
		{name: "rearm then rediscovery inside gap", temp: phases(165*s, 82.0, 615*s, 55.0, 82.0), gapLag: 15 * s, warm: 165 * s, downtime: 735 * s, after: 180 * s, expect: []string{T}, evidenceRestamped: true,
			check: func(t *testing.T, ref outcome) {
				if ref.rearms == 0 || ref.sequence < 2 {
					t.Fatalf("no re-arm and rediscovery: rearms=%d sequence=%d", ref.rearms, ref.sequence)
				}
			}},
		// Already-visible hot samples age out of the 900-s window during the
		// gap while the gap's own samples stay hidden until restart.
		{name: "visible samples age out, gap samples hidden", temp: phases(165*s, 82.0, 55.0), warm: 165 * s, downtime: 950 * s, after: 240 * s, expect: []string{R}},
		// Window edge: after a warm phase longer than the window, the oldest
		// visible samples leave it while the latest is still fresh (cooling
		// selects history plus freshness). Continuous evaluation does not act
		// at those instants; the previous reconstruction did.
		{name: "oldest visible samples leave window while current is fresh", temp: phases(1005*s, 82.0, 55.0), warm: 1005 * s, downtime: 300 * s, after: 180 * s, legacyEither: true},
		// The same ageing with no samples at all during an outage.
		{name: "visible samples age out during silent outage", temp: phases(165*s, 82.0, 165*s+1050*s, 0.0, 55.0), warm: 165 * s, downtime: 1050 * s, after: 240 * s},
		// Telemetry-loss qualified events: an open qualified inside the gap and
		// admitted at restart, one visible during the gap, and one first seen
		// already recovered, which by design yields no record.
		{name: "telemetry loss qualified inside gap", temp: always(82), warm: 165 * s, downtime: 600 * s, after: 120 * s,
			extra: func(rc *replayCase, start, restart time.Time) []a.Fact {
				return []a.Fact{rc.telemetryLoss("OPEN", 1, restart, restart.Add(-400*s))}
			},
			check: func(t *testing.T, ref outcome) {
				if !strings.Contains(ref.views[len(ref.views)-1], `"open_fact"`) {
					t.Fatal("no telemetry-loss record")
				}
			}},
		{name: "telemetry loss first seen recovered", temp: always(82), warm: 165 * s, downtime: 600 * s, after: 120 * s,
			extra: func(rc *replayCase, start, restart time.Time) []a.Fact {
				return []a.Fact{rc.telemetryLoss("OPEN", 3, restart, restart.Add(-400*s)), rc.telemetryLoss("RECOVER", 3, restart, restart.Add(-250*s))}
			},
			check: func(t *testing.T, ref outcome) {
				if strings.Contains(ref.views[len(ref.views)-1], `"open_fact"`) {
					t.Fatal("unexpected record for an occurrence first seen recovered")
				}
			}},
		{name: "telemetry loss visible mid gap", temp: always(82), warm: 165 * s, downtime: 600 * s, after: 120 * s,
			extra: func(rc *replayCase, start, restart time.Time) []a.Fact {
				return []a.Fact{rc.telemetryLoss("OPEN", 2, restart.Add(-300*s), restart.Add(-310*s))}
			},
			check: func(t *testing.T, ref outcome) {
				if !strings.Contains(ref.views[len(ref.views)-1], `"open_fact"`) {
					t.Fatal("no telemetry-loss record")
				}
			}},
		// Injected faults. A fault at a real event (the restart follow-up)
		// fires in every mode. Budget exhaustion there stops the rest of that
		// pass in every mode; the next pass recovers.
		{name: "fault at restart follow-up", temp: phases(165*s, 82.0, 55.0), warm: 165 * s, downtime: 600 * s, after: 120 * s, check: func(t *testing.T, ref outcome) {
			if !strings.Contains(ref.views[len(ref.views)-1], `"Code":"MALFORMED_RESULT"`) {
				t.Fatal("injected fault did not fire")
			}
		},
			faults: func(rc *replayCase, start, restart time.Time) []a.Fault {
				return []a.Fault{{At: restart, Asset: rc.asset, Purpose: "FOLLOW_UP", Code: "MALFORMED_RESULT"}}
			}},
		{name: "budget exhausted at restart follow-up", temp: phases(165*s, 82.0, 55.0), warm: 165 * s, downtime: 600 * s, after: 120 * s, check: func(t *testing.T, ref outcome) {
			if !strings.Contains(ref.views[len(ref.views)-1], `"Code":"TIME_BUDGET"`) {
				t.Fatal("injected fault did not fire")
			}
		},
			faults: func(rc *replayCase, start, restart time.Time) []a.Fault {
				return []a.Fault{{At: restart, Asset: rc.asset, Purpose: "FOLLOW_UP", Code: "TIME_BUDGET"}}
			}},
		// A fault at an instant where no fact becomes visible: continuous
		// evaluation never invokes there, so it never fires. The previous
		// reconstruction invoked there and did fire it.
		// Budget exhaustion at a real event inside the gap: continuous evaluation
		// loses only that pass's remaining work, while catch-up compresses the
		// gap into one pass and loses the rest of the reconstruction, with the
		// previous and the new code alike.
		{name: "budget exhausted at a visible event inside gap", temp: phases(165*s, 82.0, 55.0), gapLag: 15 * s, warm: 165 * s, downtime: 600 * s, after: 120 * s, catchUpDiffers: true,
			faults: func(rc *replayCase, start, restart time.Time) []a.Fault {
				return []a.Fault{{At: restart.Add(-300 * s), Asset: rc.asset, Purpose: "FOLLOW_UP", Code: "TIME_BUDGET"}}
			}, check: func(t *testing.T, ref outcome) {
				if !strings.Contains(ref.views[len(ref.views)-1], `"Code":"TIME_BUDGET"`) {
					t.Fatal("injected fault did not fire")
				}
			}},
		{name: "fault at hidden instant", temp: phases(165*s, 82.0, 55.0), warm: 165 * s, downtime: 600 * s, after: 120 * s, legacyDiffers: true,
			faults: func(rc *replayCase, start, restart time.Time) []a.Fault {
				return []a.Fault{{At: restart.Add(-300 * s), Asset: rc.asset, Purpose: "FOLLOW_UP", Code: "MALFORMED_RESULT"}}
			}},
		{name: "budget exhausted at hidden instant", temp: phases(165*s, 82.0, 55.0), warm: 165 * s, downtime: 600 * s, after: 120 * s, legacyDiffers: true,
			faults: func(rc *replayCase, start, restart time.Time) []a.Fault {
				return []a.Fault{{At: restart.Add(-300 * s), Asset: rc.asset, Purpose: "FOLLOW_UP", Code: "TIME_BUDGET"}}
			}},
	}
}

func (rc *replayCase) telemetryLoss(transition string, occ int64, available, qualifiedAt time.Time) a.Fact {
	rc.t.Helper()
	return rc.fact("QUALIFIED", available, a.Qualified{PolicyID: "visible-telemetry", Occurrence: occ, Transition: transition, Rule: "telemetry_loss", RuleVersion: 1,
		EnrollmentRevision: 1, Severity: "CRITICAL", QualifiedAt: qualifiedAt, Snapshot: []a.SnapshotEntry{}})
}

// TestCatchUpMatchesContinuousEvaluation is the timing reference for
// catch-up reconstruction.
func TestCatchUpMatchesContinuousEvaluation(t *testing.T) {
	var legacyDiffs atomic.Int64
	for _, sc := range continuousScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			ref := sc.run(t, modeContinuous)
			got := sc.run(t, modeCatchUp)
			legacy := sc.run(t, modeLegacy)
			last := ref.views[len(ref.views)-1]
			for _, want := range sc.expect {
				if !strings.Contains(last, want) {
					t.Fatalf("reference produced no %s decision", want)
				}
			}
			if sc.check != nil {
				sc.check(t, ref)
			}
			for i := range ref.views {
				if sc.catchUpDiffers {
					if got.views[i] != legacy.views[i] {
						t.Fatalf("post-restart pass %d differs from the previous reconstruction: %s", i, firstDiff(got.views[i], legacy.views[i]))
					}
					continue
				}
				if sc.evidenceRestamped {
					if got.views[i] != legacy.views[i] {
						t.Fatalf("post-restart pass %d differs from the previous reconstruction: %s", i, firstDiff(got.views[i], legacy.views[i]))
					}
					if d := sameCore(t, got.core[i], ref.core[i]); d != "" {
						t.Fatalf("post-restart pass %d differs from continuous evaluation: %s", i, d)
					}
					continue
				}
				if got.views[i] != ref.views[i] {
					t.Fatalf("post-restart pass %d differs from continuous evaluation: %s", i, firstDiff(got.views[i], ref.views[i]))
				}
			}
			if sc.catchUpDiffers {
				if slices.Equal(got.views, ref.views) {
					t.Fatal("expected catch-up to deviate from continuous evaluation")
				}
				t.Logf("catch-up deviates from continuous evaluation, identically in both reconstructions: %s", firstDiff(got.views[len(got.views)-1], ref.views[len(ref.views)-1]))
				return
			}
			same := slices.Equal(legacy.views, ref.views)
			if sc.evidenceRestamped || sc.legacyEither {
				same = !sc.legacyDiffers
			}
			if sc.legacyDiffers == same {
				t.Fatalf("previous reconstruction matches continuous evaluation=%v, expected %v", same, !sc.legacyDiffers)
			}
			if !same {
				legacyDiffs.Add(1)
			}
			t.Logf("calls after restart: catch-up=%d previous=%d; continuous total=%d; decisions in gap=%d rearms=%d", got.calls, legacy.calls, ref.calls, ref.inGap, ref.rearms)
		})
	}
}

// The opt-in applies wherever the engine evaluates a category: production
// asset engines and suite/archive engines alike, and only for categories that
// report it.
func TestVisibleReplayOptInByEngineKind(t *testing.T) {
	c, r, start := productionFixture(t)
	e, err := a.NewProductionAssetEngine(t.Context(), c, start, r, c.Assessment.Assets[0].EntityKey)
	if err != nil {
		t.Fatal(err)
	}
	if !a.VisibleInputReplayEnabled(e) {
		t.Fatal("production cooling engine did not opt in")
	}
	a.SetReplayHiddenBoundaries(e, true)
	if a.VisibleInputReplayEnabled(e) {
		t.Fatal("oracle did not restore the previous reconstruction")
	}
	plain := newReplayCaseFor(t, false, false)
	e, err = a.NewProductionAssetEngine(t.Context(), plain.c, plain.start, plain.r, plain.asset)
	if err != nil {
		t.Fatal(err)
	}
	if a.VisibleInputReplayEnabled(e) {
		t.Fatal("category without the marker opted in")
	}
	suite, reg := fixture(t)
	e, err = a.NewEngine(t.Context(), suite.Config, suite.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	if !a.VisibleInputReplayEnabled(e) {
		t.Fatal("suite cooling engine did not opt in")
	}
	reg, err = a.NewRegistry(reassessmentContextFixture{})
	if err != nil {
		t.Fatal(err)
	}
	e, err = a.NewEngine(t.Context(), suite.Config, suite.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	if a.VisibleInputReplayEnabled(e) {
		t.Fatal("time-dependent fixture opted in")
	}
}

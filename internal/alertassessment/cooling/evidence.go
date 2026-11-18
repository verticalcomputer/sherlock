package cooling

import (
	"context"
	"encoding/json"
	"math"
	"slices"
	"sort"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

type point struct {
	id        string
	at        time.Time
	available time.Time
	value     float64
}

type negative struct {
	from, through, available time.Time
}

type qualified struct {
	id       string
	eligible time.Time
	body     a.Qualified
}

func (q qualified) occurrence() a.Occurrence {
	return a.Occurrence{PolicyID: q.body.PolicyID, Occurrence: q.body.Occurrence}
}

func (q qualified) matches(open qualified) bool {
	return q.occurrence() == open.occurrence() && q.body.Rule == open.body.Rule &&
		q.body.RuleVersion == open.body.RuleVersion && q.body.EnrollmentRevision == open.body.EnrollmentRevision &&
		!q.body.QualifiedAt.Before(open.body.QualifiedAt)
}

type history struct {
	temps, powers []point
	negatives     map[string][]negative
	conflicts     map[string]map[time.Time]time.Time
	opens         []qualified
	recoveries    map[a.Occurrence]qualified
	index         map[string]a.Fact
	samples       map[string]a.Sample
	events        []time.Time
}

// Decode once per invocation. Historical views select from these typed values
// without rehashing manifests or reparsing the same fact on each event.
func loadHistory(ctx context.Context, r a.Request, p Policy) (*history, error) {
	h := &history{
		negatives:  make(map[string][]negative),
		conflicts:  map[string]map[time.Time]time.Time{Temperature: {}, Power: {}},
		recoveries: make(map[a.Occurrence]qualified),
		index:      make(map[string]a.Fact, len(r.Facts)),
		samples:    make(map[string]a.Sample),
	}
	floor := r.DiscoveryFloor
	if r.Purpose == "FOLLOW_UP" {
		floor = r.LogicalAt.Add(-seconds(p.RearmSeconds + p.FreshSeconds))
	}
	addEvent := func(t time.Time) {
		if r.Scope == "TRACKER" && !t.Before(floor) && !t.After(r.LogicalAt) {
			h.events = append(h.events, t)
		}
	}
	addEvent(floor)
	addEvent(r.LogicalAt)
	for _, f := range r.Facts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if f.AvailableAt.After(r.AvailabilityCutoff) {
			continue
		}
		h.index[f.ID] = f
		switch f.Kind {
		case "SAMPLE":
			s, err := a.DecodeSample(ctx, r.Category, f)
			if err != nil {
				return nil, err
			}
			addEvent(f.AvailableAt)
			addEvent(later(f.AvailableAt, s.SourceAt))
			// Normalized fixture and live inputs use the existing DCGM value
			// domain. A sentinel is unknown at its source time.
			if !validSampleValue(s.Metric, s.Value) {
				h.negatives[s.Metric] = append(h.negatives[s.Metric], negative{s.SourceAt, s.SourceAt, f.AvailableAt})
				continue
			}
			if r.Purpose != "DISCOVER" {
				h.samples[f.ID] = s
			}
			pt := point{f.ID, s.SourceAt, f.AvailableAt, s.Value}
			switch {
			case s.Metric == Temperature && s.Unit == "celsius":
				h.temps = append(h.temps, pt)
			case s.Metric == Power && s.Unit == "watts":
				h.powers = append(h.powers, pt)
			}
		case "COVERAGE":
			var c a.Coverage
			if err := json.Unmarshal(f.Body, &c); err != nil {
				return nil, err
			}
			h.negatives[c.Metric] = append(h.negatives[c.Metric], negative{c.From, c.Through, f.AvailableAt})
			addEvent(f.AvailableAt)
			addEvent(later(f.AvailableAt, c.Through))
		case "CONFLICT":
			var c a.Conflict
			if err := json.Unmarshal(f.Body, &c); err != nil {
				return nil, err
			}
			h.negatives[c.Metric] = append(h.negatives[c.Metric], negative{c.SourceAt, c.SourceAt, f.AvailableAt})
			if byTime := h.conflicts[c.Metric]; byTime != nil {
				byTime[c.SourceAt] = f.AvailableAt
			}
			addEvent(f.AvailableAt)
			addEvent(later(f.AvailableAt, c.SourceAt))
		case "PROVENANCE":
			// Its sample supplies the source eligibility boundary.
			addEvent(f.AvailableAt)
		case "QUALIFIED":
			var q a.Qualified
			if err := json.Unmarshal(f.Body, &q); err != nil {
				return nil, err
			}
			at := later(f.AvailableAt, q.QualifiedAt)
			for _, s := range q.Snapshot {
				at = later(at, s.SourceAt)
			}
			addEvent(f.AvailableAt)
			addEvent(at)
			if q.Rule != "gpu_thermal" && q.Rule != "hbm_thermal" {
				continue
			}
			event := qualified{f.ID, at, q}
			if q.Transition == "RECOVER" {
				h.recoveries[event.occurrence()] = event
			} else if q.Transition == "OPEN" && q.Severity == "CRITICAL" {
				h.opens = append(h.opens, event)
			}
		}
	}
	for _, ps := range [][]point{h.temps, h.powers} {
		slices.SortFunc(ps, func(a, b point) int { return a.at.Compare(b.at) })
	}
	slices.SortFunc(h.events, time.Time.Compare)
	h.events = slices.CompactFunc(h.events, time.Time.Equal)
	return h, nil
}

func validSampleValue(metric string, v float64) bool {
	// Match the existing DCGM blank-value boundary (domain.NormalizeDCGMCollection).
	return validNumber(v) && v < 140737488355328 && (metric != Power || v >= 0)
}

func later(a, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}

func seconds(v int64) time.Duration { return time.Duration(v) * time.Second }

type evidence struct {
	h               *history
	req             a.Request
	policy          Policy
	logical, cutoff time.Time
	temps, powers   []point
}

func (e *evidence) at(logical, cutoff time.Time) {
	e.logical, e.cutoff = logical, cutoff
	from := logical.Add(-seconds(e.policy.HistorySeconds + e.policy.FreshSeconds))
	e.temps = e.selectPoints(e.temps[:0], e.h.temps, Temperature, from)
	if e.req.Purpose != "DISCOVER" {
		e.powers = e.selectPoints(e.powers[:0], e.h.powers, Power, from)
	}
}

func (e *evidence) observePower() {
	from := e.logical.Add(-seconds(e.policy.HistorySeconds + e.policy.FreshSeconds))
	e.powers = e.selectPoints(e.powers[:0], e.h.powers, Power, from)
}

func (e *evidence) selectPoints(dst, src []point, metric string, from time.Time) []point {
	// Multiple distinct admitted values at the same source timestamp are all
	// unusable, even if a malformed caller omitted the conflict fact.
	ps := window(src, from, e.logical, false)
	conflicts := e.h.conflicts[metric]
	for start := 0; start < len(ps); {
		end, count := start, 0
		var one point
		for end < len(ps) && ps[end].at.Equal(ps[start].at) {
			if !ps[end].available.After(e.cutoff) {
				one = ps[end]
				count++
			}
			end++
		}
		if count == 1 {
			conflict, ok := conflicts[one.at]
			if !ok || conflict.After(e.cutoff) {
				dst = append(dst, one)
			}
		}
		start = end
	}
	return dst
}

func (e evidence) urgent() []qualified {
	var current []qualified
	for _, open := range e.h.opens {
		if open.eligible.After(e.logical) || e.h.index[open.id].AvailableAt.After(e.cutoff) {
			continue
		}
		if _, ok := e.recovery(open); !ok {
			current = append(current, open)
		}
	}
	return current
}

func (e evidence) recovery(open qualified) (qualified, bool) {
	r, ok := e.h.recoveries[open.occurrence()]
	return r, ok && !r.eligible.After(e.logical) && !e.h.index[r.id].AvailableAt.After(e.cutoff) && r.matches(open)
}

func window(ps []point, from, through time.Time, exclusiveEnd bool) []point {
	lo := sort.Search(len(ps), func(i int) bool { return !ps[i].at.Before(from) })
	hi := lo + sort.Search(len(ps)-lo, func(i int) bool {
		at := ps[lo+i].at
		return at.After(through) || exclusiveEnd && at.Equal(through)
	})
	return ps[lo:hi]
}

func (e evidence) unknown(metric string, from, through time.Time, exclusiveEnd bool) bool {
	for _, n := range e.h.negatives[metric] {
		if !n.available.After(e.cutoff) && !n.through.Before(from) && !n.from.After(through) &&
			(!exclusiveEnd || n.from.Before(through)) {
			return true
		}
	}
	return false
}

func (e evidence) covered(metric string, ps []point, from, through time.Time, minimum int64, exclusiveEnd bool) bool {
	p := e.policy
	required := max(int64(2), int64(math.Ceil(p.CoverageRatio*through.Sub(from).Seconds()/float64(p.CadenceSeconds))), minimum)
	if int64(len(ps)) < required || ps[0].at.Sub(from) > seconds(p.EdgeToleranceSeconds) ||
		through.Sub(ps[len(ps)-1].at) > seconds(p.EdgeToleranceSeconds) || e.unknown(metric, from, through, exclusiveEnd) {
		return false
	}
	for i := 1; i < len(ps); i++ {
		if ps[i].at.Sub(ps[i-1].at) > seconds(p.GapSeconds) {
			return false
		}
	}
	return true
}

func median(ps []point) float64 {
	var stack [32]float64
	values := stack[:0]
	for _, p := range ps {
		values = append(values, p.value)
	}
	slices.Sort(values)
	n := len(values)
	if n%2 == 1 {
		return values[n/2]
	}
	lo, hi := values[n/2-1], values[n/2]
	if math.Abs(lo) <= math.MaxFloat64/2 && math.Abs(hi) <= math.MaxFloat64/2 {
		return (lo + hi) / 2
	}
	return lo/2 + hi/2
}

func pointIDs(groups ...[]point) []string {
	var ids []string
	for _, ps := range groups {
		for _, p := range ps {
			ids = append(ids, p.id)
		}
	}
	return a.SortedUnique(ids)
}

type endpoint struct {
	at     time.Time
	value  float64
	points []point
}

func (e evidence) endpoint(at time.Time) (endpoint, bool) {
	from := at.Add(-seconds(e.policy.EndpointSeconds))
	ps := window(e.temps, from, at, false)
	if !e.covered(Temperature, ps, from, at, e.policy.EndpointMinSamples, false) {
		return endpoint{}, false
	}
	return endpoint{at: at, value: median(ps), points: ps}, true
}

func (e evidence) current() (endpoint, bool) {
	if len(e.temps) == 0 {
		return endpoint{}, false
	}
	at := e.temps[len(e.temps)-1].at
	if e.logical.Sub(at) > seconds(e.policy.FreshSeconds) {
		return endpoint{}, false
	}
	return e.endpoint(at)
}

func (ep endpoint) feature() a.Feature {
	return a.Feature{FeatureKind: "temperature_endpoint", SourceAt: ep.at, Value: ep.value, Unit: "celsius", Support: pointIDs(ep.points)}
}

func (ep endpoint) ref(id string) a.FeatureRef {
	var at time.Time
	for _, p := range ep.points {
		at = later(at, p.available)
	}
	return a.FeatureRef{ID: id, Value: ep.value, SourceAt: ep.at, AvailableAt: at}
}

func (e evidence) aligned(ps []point, at time.Time) bool {
	offset := seconds(e.policy.AlignmentSeconds)
	return len(window(ps, at.Add(-offset), at.Add(offset), false)) > 0
}

type powerStats struct {
	points       []point
	median, span float64
}

func (e evidence) stable(from, at time.Time) (powerStats, bool) {
	start := from.Add(-seconds(e.policy.PowerPrefixSeconds))
	ps := window(e.powers, start, at, false)
	if !e.covered(Power, ps, start, at, 2, false) || !e.aligned(ps, at) || !e.aligned(ps, from) {
		return powerStats{}, false
	}
	lo, hi := ps[0].value, ps[0].value
	for _, p := range ps[1:] {
		lo, hi = min(lo, p.value), max(hi, p.value)
	}
	m := median(ps)
	return powerStats{points: ps, median: m, span: hi - lo}, hi-lo <= e.powerTolerance(m)
}

func (e evidence) powerTolerance(w float64) float64 {
	return math.Max(e.policy.StableWatts, e.policy.StableRatio*w)
}

type warmingBranch struct {
	name   string
	old    endpoint
	points []point
}

type entryEvidence struct {
	current    endpoint
	warming    []warmingBranch
	persistent []point
}

func (ev entryEvidence) exists() bool { return len(ev.warming) != 0 || len(ev.persistent) != 0 }

func (e evidence) entry(cur endpoint) entryEvidence {
	out := entryEvidence{current: cur}
	p := e.policy
	for _, branch := range []struct {
		name     string
		duration int64
		delta    float64
	}{{"RAPID", p.RapidSeconds, p.RapidDeltaC}, {"SLOW", p.SlowSeconds, p.SlowDeltaC}} {
		from := cur.at.Add(-seconds(branch.duration))
		old, ok := e.endpoint(from)
		if !ok || cur.value-old.value < branch.delta {
			continue
		}
		ps := window(e.temps, from, cur.at, false)
		if e.covered(Temperature, ps, from, cur.at, 2, false) {
			out.warming = append(out.warming, warmingBranch{branch.name, old, ps})
		}
	}
	out.persistent = e.warmInterval(cur, p.PersistentEntrySeconds, p.PersistentEntrySamples, p.PersistentC)
	return out
}

func (e evidence) warmInterval(cur endpoint, duration, minimum int64, threshold float64) []point {
	from := cur.at.Add(-seconds(duration))
	ps := window(e.temps, from, cur.at, false)
	if !e.covered(Temperature, ps, from, cur.at, minimum, false) {
		return nil
	}
	for _, pt := range ps {
		if pt.value < threshold {
			return nil
		}
	}
	return ps
}

func (e evidence) referenceValid(ref *a.FeatureRef) bool {
	if ref == nil || ref.SourceAt.After(e.logical) || ref.AvailableAt.After(e.cutoff) {
		return false
	}
	f, ok := e.h.index[ref.ID]
	if !ok || f.Kind != "FEATURE" || !f.AvailableAt.Equal(ref.AvailableAt) {
		return false
	}
	var b a.Feature
	if json.Unmarshal(f.Body, &b) != nil || b.FeatureKind != "temperature_endpoint" || b.Unit != "celsius" ||
		!b.SourceAt.Equal(ref.SourceAt) || b.Value != ref.Value {
		return false
	}
	from := ref.SourceAt.Add(-seconds(e.policy.EndpointSeconds))
	ps := make([]point, 0, len(b.Support))
	for _, id := range b.Support {
		s, ok := e.h.samples[id]
		if !ok || s.Metric != Temperature || s.Unit != "celsius" || s.SourceAt.Before(from) || s.SourceAt.After(ref.SourceAt) {
			return false
		}
		ps = append(ps, point{at: s.SourceAt, value: s.Value})
	}
	slices.SortFunc(ps, func(a, b point) int { return a.at.Compare(b.at) })
	for i := 1; i < len(ps); i++ {
		if ps[i].at.Equal(ps[i-1].at) {
			return false
		}
	}
	return e.covered(Temperature, ps, from, ref.SourceAt, e.policy.EndpointMinSamples, false) && median(ps) == ref.Value
}

func (e evidence) reboundValid(r *Rebound) bool {
	if !e.referenceValid(&r.Reference) {
		return false
	}
	width := seconds(e.policy.TransitionSeconds)
	for _, split := range []time.Time{r.DropAt, r.RiseAt} {
		if e.unknown(Power, split.Add(-width), split.Add(width), false) {
			return false
		}
	}
	for _, id := range r.Support {
		f, ok := e.h.index[id]
		if !ok {
			return false
		}
		var b a.Feature
		if f.Kind != "FEATURE" || json.Unmarshal(f.Body, &b) != nil || b.FeatureKind != "rebound" || b.Unit != "watts" ||
			b.Value != r.PrePowerW || b.SourceAt.After(e.logical) || e.unknown(Power, b.SourceAt.Add(-seconds(e.policy.EndpointSeconds)), b.SourceAt, false) {
			return false
		}
		for _, raw := range b.Support {
			s, ok := e.h.samples[raw]
			if !ok || s.SourceAt.After(e.logical) || e.unknown(s.Metric, s.SourceAt, s.SourceAt, false) {
				return false
			}
		}
	}
	return true
}

func (e evidence) settled(s State, cur endpoint, duration, minimum int64, newRebound bool) []point {
	from := cur.at.Add(-seconds(duration))
	ps := window(e.temps, from, cur.at, false)
	if !e.covered(Temperature, ps, from, cur.at, minimum, false) {
		return nil
	}
	ref := s.Reference
	if s.Rebound != nil {
		if !newRebound && !e.reboundValid(s.Rebound) {
			return nil
		}
		ref = &s.Rebound.Reference
	} else if ref != nil && !e.referenceValid(ref) {
		return nil
	}
	for _, p := range ps {
		if !e.settledValue(s, ref, p.value) {
			return nil
		}
		if ref != nil {
			observed, covered := e.endpoint(p.at)
			if !covered || !e.settledValue(s, ref, observed.value) {
				return nil
			}
		}
	}
	return ps
}

func (e evidence) settlingSupport(ps []point) []point {
	// Early endpoint medians may need the cadence immediately before the
	// nominal settling interval. Cite their complete raw support as well.
	return window(e.temps, ps[0].at.Add(-seconds(e.policy.EndpointSeconds)), ps[len(ps)-1].at, false)
}

func (e evidence) settledValue(s State, ref *a.FeatureRef, value float64) bool {
	if value >= e.policy.PersistentC {
		return false
	}
	if ref != nil {
		return math.Abs(value-ref.Value) <= e.policy.ReferenceToleranceC
	}
	return len(s.Branches) == 0 || value <= e.policy.PersistentRecoveryC
}

type transition struct {
	at          time.Time
	left, right []point
	pre         float64
}

type reboundEvidence struct {
	drop, rise transition
	reference  endpoint
	current    []point
}

func (e evidence) rebound(ctx context.Context, cur endpoint) (*reboundEvidence, error) {
	p := e.policy
	t := cur.at
	from := t.Add(-seconds(p.EndpointSeconds))
	current := window(e.powers, from, t, false)
	if !e.covered(Power, current, from, t, 2, false) || !e.aligned(current, t) {
		return nil, nil
	}
	currentMedian := median(current)
	width := seconds(p.TransitionSeconds)
	oldest := t.Add(-seconds(p.HistorySeconds))
	e.powers = window(e.powers, oldest, t, false)
	e.temps = window(e.temps, oldest, t, false)
	var rises []transition
	var drops []reboundEvidence
	for _, pt := range e.powers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s := pt.at
		lo, hi := s.Add(-width), s.Add(width)
		if hi.After(t) {
			continue
		}
		left, right := window(e.powers, lo, s, true), window(e.powers, s, hi, false)
		if !e.covered(Power, left, lo, s, 2, true) || !e.covered(Power, right, s, hi, 2, false) {
			continue
		}
		l, r := median(left), median(right)
		threshold := math.Max(p.TransitionWatts, p.TransitionRatio*math.Max(l, r))
		tr := transition{s, left, right, l}
		if r-l >= threshold {
			rises = append(rises, tr)
		}
		if l-r < threshold || math.Abs(currentMedian-l) > e.powerTolerance(l) {
			continue
		}
		ref, ok := e.endpoint(lo)
		if !ok || slices.ContainsFunc(ref.points, func(pt point) bool { return pt.value >= p.PersistentC }) {
			continue
		}
		drops = append(drops, reboundEvidence{drop: tr, reference: ref, current: current})
	}
	if len(rises) == 0 {
		return nil, nil
	}
	// Each split has exactly one pair of deterministic windows, so identical
	// (rise,drop) timestamps cannot yield alternative support lists.
	rise := rises[len(rises)-1]
	for i := len(drops) - 1; i >= 0; i-- {
		if !drops[i].drop.at.Add(width).After(rise.at) {
			drops[i].rise = rise
			return &drops[i], nil
		}
	}
	return nil, nil
}

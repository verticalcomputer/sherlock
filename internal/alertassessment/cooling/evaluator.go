package cooling

import (
	"context"
	"slices"
	"strings"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

type result struct {
	a.Result
	req a.Request
	err error
}

func newResult(r a.Request) *result {
	return &result{req: r, Result: a.Result{Kind: "UNCHANGED", UpdateCodes: []string{}, Reasons: []string{}, Support: []string{}, ProposedFeatures: []a.Feature{}}}
}

func (x *result) assessment(outcome, phase, action, summary string, reasons ...string) {
	x.Kind, x.Outcome, x.Phase, x.Action, x.Summary = "ASSESSMENT", CategoryID+"/"+outcome, phase, action, summary
	x.Reasons = append(x.Reasons, reasons...)
}

func (x *result) addFeature(f a.Feature) string {
	if x.err != nil {
		return ""
	}
	id, err := a.FeatureID(x.req, f)
	if err != nil {
		x.err = err
		return ""
	}
	if !slices.Contains(x.Support, id) {
		x.Support = append(x.Support, id)
		if _, exists := slices.BinarySearch(x.req.Bundle.Features, id); !exists {
			x.ProposedFeatures = append(x.ProposedFeatures, f)
		}
	}
	return id
}

func (x *result) endpoint(ep endpoint) a.FeatureRef {
	return ep.ref(x.addFeature(ep.feature()))
}

func (x *result) materializedBundleID(bundle a.Bundle) (string, error) {
	if x.err != nil {
		return "", x.err
	}
	features := slices.Clone(bundle.Features)
	for _, f := range x.ProposedFeatures {
		id, err := a.FeatureID(x.req, f)
		if err != nil {
			return "", err
		}
		features = append(features, id)
	}
	bundle.Features = a.SortedUnique(features)
	return a.BundleID(CategoryID, bundle)
}

func (x *result) freezeRebound(cur endpoint, rebound reboundEvidence) *Rebound {
	id := x.addFeature(a.Feature{FeatureKind: "rebound", SourceAt: cur.at, Value: rebound.drop.pre, Unit: "watts", Support: pointIDs(
		rebound.drop.left, rebound.drop.right, rebound.rise.left, rebound.rise.right, rebound.current, rebound.reference.points,
	)})
	return &Rebound{DropAt: rebound.drop.at, RiseAt: rebound.rise.at, Reference: x.endpoint(rebound.reference), PrePowerW: rebound.drop.pre, Support: []string{id}}
}

func (x *result) state(kind string, v any) *a.Payload {
	if x.err != nil {
		return nil
	}
	p, err := payload(kind, v)
	x.err = err
	return p
}

func (x *result) finished() (a.Result, error) {
	if x.err != nil {
		return a.Result{}, x.err
	}
	x.Support = a.SortedUnique(x.Support)
	x.Reasons = a.SortedUnique(x.Reasons)
	x.UpdateCodes = a.SortedUnique(x.UpdateCodes)
	return x.Result, nil
}

func (x *result) addProof(kind, unit string, at time.Time, value float64, ps ...[]point) {
	x.addFeature(a.Feature{FeatureKind: kind, SourceAt: at, Value: value, Unit: unit, Support: pointIDs(ps...)})
}

func (x *result) details(branches []string, temp *a.FeatureRef, delta *float64, stats *powerStats, rebound *Rebound, coverage string) {
	d := Details{Schema: 1, Branches: branches, Temperature: temp, SignedChangeC: delta, Rebound: rebound, Coverage: coverage, Support: a.SortedUnique(slices.Clone(x.Support))}
	if stats != nil {
		d.PowerMedianW, d.PowerRangeW = &stats.median, &stats.span
	}
	x.Details = x.state("details", d)
}

func (x *result) terminalEndpoint(cur endpoint, ok bool) *a.FeatureRef {
	if !ok {
		return nil
	}
	ref := x.endpoint(cur)
	x.TerminalEndpointID = ref.ID
	return &ref
}

func (Category) Evaluate(ctx context.Context, r a.Request) (a.Result, error) {
	if err := ctx.Err(); err != nil {
		return a.Result{}, err
	}
	p, tracker, arm, err := decode(ctx, r)
	if err != nil {
		return a.Result{}, err
	}
	h, err := loadHistory(ctx, r, p)
	if err != nil {
		return a.Result{}, err
	}
	e := evidence{ctx: ctx, h: h, req: r, policy: p}
	if r.Purpose == "DISCOVER" {
		return e.discover(ctx)
	}
	e.at(r.LogicalAt, r.AvailabilityCutoff)
	if r.Scope == "TRACKER" {
		return e.track(ctx, tracker)
	}
	if r.Purpose == "FOLLOW_UP" {
		return e.followArm()
	}
	return e.assess(arm)
}

func (e *evidence) discover(ctx context.Context) (a.Result, error) {
	for _, at := range e.h.events {
		if err := ctx.Err(); err != nil {
			return a.Result{}, err
		}
		cutoff := at
		if e.req.AvailabilityCutoff.Before(cutoff) {
			cutoff = e.req.AvailabilityCutoff
		}
		e.at(at, cutoff)
		cur, haveCurrent := e.current()
		urgent := e.urgent()
		var entry entryEvidence
		if len(urgent) == 0 && haveCurrent {
			entry = e.entry(cur)
		}
		if len(urgent) == 0 && !entry.exists() {
			continue
		}
		x := newResult(e.req)
		tracker := initial()
		tracker.Active = true
		if len(urgent) > 0 {
			if len(urgent) > 8 {
				return a.Result{}, a.ErrInvalid
			}
			x.assessment("URGENT_BYPASS", "FINAL", "URGENT", "Independently qualified critical thermal evidence.", "urgent")
			tracker.UrgentOccurrences = occurrences(urgent)
			for _, f := range urgent {
				x.Support = append(x.Support, f.id)
			}
			ref := x.terminalEndpoint(cur, haveCurrent)
			if ref != nil {
				x.details(tracker.Branches, ref, nil, nil, nil, "SUPPORTED")
			}
		} else {
			x.assessment("OBSERVING", "OBSERVING", "NONE", "Temperature concern requires assessment. The cause is uncertain.")
			ref := x.endpoint(cur)
			tracker.EntryEndpoint = &ref
			tracker.LastEndpointAt = &cur.at
			var proof [][]point
			proofValue := cur.value
			for _, branch := range entry.warming {
				old := x.endpoint(branch.old)
				tracker.Reference = &old // RAPID precedes SLOW, the longer reference.
				tracker.Branches = append(tracker.Branches, branch.name)
				x.Reasons = append(x.Reasons, strings.ToLower(branch.name))
				proofValue = cur.value - branch.old.value
				proof = append(proof, branch.points)
			}
			if len(entry.persistent) > 0 {
				tracker.Branches = append(tracker.Branches, "PERSISTENT")
				x.Reasons = append(x.Reasons, "persistent")
				proof = append(proof, entry.persistent)
			}
			x.addProof("entry", "celsius", cur.at, proofValue, proof...)
			tracker.Branches = a.SortedUnique(tracker.Branches)
			if len(entry.warming) > 0 {
				// Temperature determines the first entry event. Only that
				// event's power evidence can select the initial rebound.
				e.observePower()
				rebound, err := e.rebound(ctx, cur)
				if err != nil {
					return a.Result{}, err
				}
				if rebound != nil {
					tracker.Rebound = x.freezeRebound(cur, *rebound)
					entryView, err := a.EntryView(e.req, at)
					if err != nil {
						return a.Result{}, err
					}
					tracker.Rebound.BundleID, err = x.materializedBundleID(entryView.Bundle)
					if err != nil {
						return a.Result{}, err
					}
				}
			}
		}
		x.EntryQualifiedAt = &at
		x.State = x.state("tracker", tracker)
		x.InitialCandidateState = x.state("candidate", candidate(tracker))
		return x.finished()
	}
	x := newResult(e.req)
	x.assessment("NO_CANDIDATE", "NO_CANDIDATE", "NONE", "No supported entry in the available evidence.")
	x.State = x.state("tracker", initial())
	return x.finished()
}

func (e evidence) assess(s State) (a.Result, error) {
	x := newResult(e.req)
	cur, haveCurrent := e.current()
	if urgent := e.urgent(); len(urgent) > 0 {
		if len(urgent) > 8 {
			return a.Result{}, a.ErrInvalid
		}
		for _, f := range urgent {
			x.Support = append(x.Support, f.id)
		}
		x.assessment("URGENT_BYPASS", "FINAL", "URGENT", "Independently qualified critical thermal evidence.", "urgent")
		if ref := x.terminalEndpoint(cur, haveCurrent); ref != nil {
			x.details(s.Branches, ref, nil, nil, nil, "SUPPORTED")
		}
		return x.finished()
	}
	if haveCurrent {
		p := e.policy
		if ps := e.warmInterval(cur, p.PersistentConfirmSeconds, 2, p.PersistentC); ps != nil {
			x.addProof("entry", "celsius", cur.at, cur.value, ps)
			x.assessment("COOLING_SUSPECTED", "FINAL", "INVESTIGATE", "Sustained high temperature warrants investigation. The cause is uncertain.", "persistent")
			x.details(s.Branches, x.terminalEndpoint(cur, true), nil, nil, nil, "SUPPORTED")
			return x.finished()
		}
		if hasWarming(s.Branches) && e.referenceValid(s.EntryEndpoint) {
			if ps := e.warmInterval(cur, p.PersistenceSeconds, p.PersistenceSamples, s.EntryEndpoint.Value-p.PersistenceDropC); ps != nil {
				for _, branch := range e.entry(cur).warming {
					if !slices.Contains(s.Branches, branch.name) {
						continue
					}
					power, stable := e.stable(branch.old.at, cur.at)
					if !stable {
						continue
					}
					x.endpoint(branch.old)
					x.Support = append(x.Support, s.EntryEndpoint.ID)
					change := cur.value - branch.old.value
					x.addProof("entry", "celsius", cur.at, change, branch.points, power.points, ps)
					x.assessment("COOLING_SUSPECTED", "FINAL", "INVESTIGATE", "Persistent warming at stable power warrants investigation.", strings.ToLower(branch.name), "stable_power")
					x.details(s.Branches, x.terminalEndpoint(cur, true), &change, &power, nil, "SUPPORTED")
					return x.finished()
				}
			}
		}
		if s.Rebound == nil || e.req.SharedContext != nil {
			if ps := e.settled(s, cur, p.SettlingSeconds, p.SettlingSamples, false); ps != nil {
				x.assessment("TRANSIENT_SUPPORTED", "FINAL", "NONE", "Covered temperatures returned to the required settling range.", "settled")
				if s.Reference != nil {
					ps = e.settlingSupport(ps)
				}
				x.addProof("coverage", "seconds", cur.at, float64(p.SettlingSeconds), ps)
				x.citeReference(s)
				x.details(s.Branches, x.terminalEndpoint(cur, true), nil, nil, s.Rebound, "SUPPORTED")
				return x.finished()
			}
		}
	}
	if !e.logical.Before(e.req.Entry.Fallback.DueAt) {
		x.assessment("UNRESOLVED_WARMING", "FINAL", "INVESTIGATE", "Credible temperature concern remains unresolved at the observation deadline.", "deadline", "insufficient_evidence")
		x.Support = append(x.Support, e.req.Entry.Support...)
		if ref := x.terminalEndpoint(cur, haveCurrent); ref != nil {
			x.details(s.Branches, ref, nil, nil, nil, "UNKNOWN")
		}
		return x.finished()
	}
	x.assessment("OBSERVING", "OBSERVING", "NONE", "Concern remains under observation.")
	if haveCurrent && (s.LastEndpointAt == nil || s.LastEndpointAt.Before(cur.at)) {
		s.LastEndpointAt = &cur.at
	}
	x.State = x.state("candidate", s)
	return x.finished()
}

func (x *result) citeReference(s State) {
	if s.Rebound != nil {
		x.Reasons = append(x.Reasons, "rebound")
		x.Support = append(x.Support, s.Rebound.Reference.ID)
		x.Support = append(x.Support, s.Rebound.Support...)
	} else if s.Reference != nil {
		x.Support = append(x.Support, s.Reference.ID)
	}
}

func (e evidence) followArm() (a.Result, error) {
	x := newResult(e.req)
	terminal := e.req.Terminal
	for _, f := range e.urgent() {
		if !slices.Contains(terminal.UrgentOccurrences, f.occurrence()) {
			x.Support = append(x.Support, f.id)
		}
	}
	if len(x.Support) > 0 {
		x.UpdateCodes = append(x.UpdateCodes, "urgent")
		x.Reasons = append(x.Reasons, "urgent")
	}
	base := terminal.Endpoint
	if base != nil && !base.SourceAt.After(terminal.LogicalAt) && !base.AvailableAt.After(terminal.LogicalAt) &&
		terminal.LogicalAt.Sub(base.SourceAt) <= seconds(e.policy.FreshSeconds) && e.referenceValid(base) {
		if cur, ok := e.current(); ok && cur.value-base.Value >= e.policy.UpdateDeltaC {
			x.UpdateCodes = append(x.UpdateCodes, "higher_temperature")
			x.endpoint(cur)
			x.Support = append(x.Support, base.ID)
		}
	}
	if len(x.UpdateCodes) > 0 {
		x.Kind = "UPDATE"
		x.Action = "INVESTIGATE"
		if slices.Contains(x.UpdateCodes, "urgent") {
			x.Action = "URGENT"
		}
		x.Summary = "New qualified evidence warrants investigation."
	}
	return x.finished()
}

func (e evidence) track(ctx context.Context, t TrackerState) (a.Result, error) {
	x := newResult(e.req)
	if !t.Active {
		return x.finished()
	}
	urgent := e.urgent()
	urgentChanged, err := e.trackUrgent(x, &t, urgent)
	if err != nil {
		return a.Result{}, err
	}
	cur, haveCurrent := e.current()
	if !haveCurrent {
		if urgentChanged {
			x.State = x.state("tracker", t)
		}
		return x.finished()
	}
	selected := false
	if t.Rebound == nil && hasWarming(t.Branches) {
		rebound, err := e.rebound(ctx, cur)
		if err != nil {
			return a.Result{}, err
		}
		if rebound != nil {
			t.Rebound = x.freezeRebound(cur, *rebound)
			selected = true
		}
	}
	s := candidate(t)
	ps := e.settled(s, cur, e.policy.RearmSeconds, 2, selected)
	var recoveries []string
	from := cur.at.Add(-seconds(e.policy.RearmSeconds))
	wantRearm := ps != nil && len(urgent) == 0
	if wantRearm {
		wantRearm = s.EntryEndpoint == nil || !from.Before(s.EntryEndpoint.SourceAt)
		for _, occurrence := range t.UrgentOccurrences {
			var recovered bool
			for _, open := range e.h.opens {
				if open.occurrence() == occurrence && !from.Before(open.body.QualifiedAt) {
					if recovery, ok := e.recovery(open); ok {
						recoveries = append(recoveries, open.id, recovery.id)
						recovered = true
						break
					}
				}
			}
			wantRearm = wantRearm && recovered
		}
	}
	if wantRearm {
		var err error
		wantRearm, err = e.rearmContinuity(ctx, ps, from, cur.at)
		if err != nil {
			return a.Result{}, err
		}
	}
	if wantRearm {
		x.Kind = "REARM"
		x.Summary = "Covered recovery interval permits another physical assessment."
		x.Reasons = append(x.Reasons, "settled")
		x.addProof("coverage", "seconds", cur.at, float64(e.policy.RearmSeconds), e.settlingSupport(ps))
		x.citeReference(s)
		x.Support = append(x.Support, recoveries...)
	}
	if selected {
		t.Rebound.BundleID, err = x.materializedBundleID(e.req.Bundle)
		if err != nil {
			return a.Result{}, err
		}
	}
	if wantRearm {
		if s.Rebound != nil {
			x.details(s.Branches, nil, nil, nil, s.Rebound, "SUPPORTED")
		}
		x.State = x.state("tracker", initial())
	} else if selected || urgentChanged {
		x.State = x.state("tracker", t)
	}
	return x.finished()
}

// Keep the identity of unresolved critical occurrences independently of sample
// freshness. The originating OPEN and exact RECOVER remain the rearm proof.
func (e evidence) trackUrgent(x *result, t *TrackerState, urgent []qualified) (bool, error) {
	tracked := slices.Clone(t.UrgentOccurrences)
	for _, open := range urgent {
		occurrence := open.occurrence()
		if !slices.Contains(tracked, occurrence) {
			tracked = append(tracked, occurrence)
			x.Support = append(x.Support, open.id)
		}
	}
	if len(tracked) > 8 {
		// Recovered events may be released to free a slot, but only with
		// the qualified pair attached to the resulting tracker context.
		for _, open := range e.h.opens {
			if i := slices.Index(tracked, open.occurrence()); i >= 0 {
				if recover, ok := e.recovery(open); ok {
					tracked = slices.Delete(tracked, i, i+1)
					x.Support = append(x.Support, open.id, recover.id)
				}
			}
		}
		if len(tracked) > 8 {
			return false, a.ErrInvalid
		}
	}
	slices.SortFunc(tracked, compareOccurrence)
	changed := !slices.Equal(t.UrgentOccurrences, tracked)
	t.UrgentOccurrences = tracked
	return changed, nil
}

// Check every source endpoint in the clean interval against retained evidence,
// then check the historical admission events as seen at their original cutoff.
// A later arrival can add evidence to the current view without hiding a warming
// predicate that was already supported during the recovery interval.
func (e evidence) rearmContinuity(ctx context.Context, ps []point, from, through time.Time) (bool, error) {
	for _, pt := range ps {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		ep, covered := e.endpoint(pt.at)
		if !covered || e.entry(ep).exists() {
			return false, nil
		}
	}
	view := e
	view.temps, view.powers = nil, nil
	events := []time.Time{from}
	for _, at := range e.h.events {
		if at.After(from) && !at.After(through) {
			events = append(events, at)
		}
	}
	for _, at := range events {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		view.logical, view.cutoff = at, at
		if view.cutoff.After(e.cutoff) {
			view.cutoff = e.cutoff
		}
		start := at.Add(-seconds(e.policy.HistorySeconds + e.policy.FreshSeconds))
		view.temps = view.selectPoints(view.temps[:0], e.h.temps, Temperature, start)
		if ep, covered := view.current(); covered && view.entry(ep).exists() {
			return false, nil
		}
	}
	return true, nil
}

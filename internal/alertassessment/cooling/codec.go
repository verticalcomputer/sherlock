package cooling

import (
	"bytes"
	"context"
	"math"
	"reflect"
	"slices"
	"sync/atomic"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

const stateLimit = 16 << 10
const detailsLimit = 4 << 10

func initial() TrackerState {
	return TrackerState{Schema: 1, Branches: []string{}, UrgentOccurrences: []a.Occurrence{}}
}

func candidate(t TrackerState) State {
	return State{Schema: t.Schema, Branches: t.Branches, EntryEndpoint: t.EntryEndpoint, Reference: t.Reference, Rebound: t.Rebound, LastEndpointAt: t.LastEndpointAt}
}

func payload(kind string, v any) (*a.Payload, error) {
	p, err := a.NewPayload(CategoryID, kind, 1, v)
	return &p, err
}

func decodePayload[T any](p a.Payload, kind string, limit int) (T, error) {
	var v T
	if p.Category != CategoryID || p.Kind != kind || p.Schema != 1 || len(p.Body) > limit ||
		p.Hash != a.Hash(kind, CategoryID, 1, p.Body) {
		return v, a.ErrInvalid
	}
	if err := a.DecodeStrict(p.Body, &v, limit); err != nil {
		return v, err
	}
	b, err := a.Canonical(v)
	if err != nil || !bytes.Equal(b, p.Body) {
		return v, a.ErrInvalid
	}
	return v, nil
}

// Policy contains only scalar values. Cache exactly one immutable, fully
// validated decode; return it by value. This avoids repeating strict parsing at
// each retained history boundary without caching authority, state or decisions.
// Identity includes the complete envelope and copied bytes, not just a digest.
type decodedPolicy struct {
	payload a.Payload
	policy  Policy
}

var lastDecodedPolicy atomic.Pointer[decodedPolicy]

func decodePolicy(ctx context.Context, payload a.Payload) (Policy, error) {
	if err := ctx.Err(); err != nil {
		return Policy{}, err
	}
	if cached := lastDecodedPolicy.Load(); cached != nil && payload.Category == cached.payload.Category && payload.Kind == cached.payload.Kind && payload.Schema == cached.payload.Schema && payload.Hash == cached.payload.Hash && bytes.Equal(payload.Body, cached.payload.Body) {
		return cached.policy, nil
	}
	p, err := decodePayload[Policy](payload, "policy", stateLimit)
	if err != nil {
		return p, err
	}
	if err = p.Validate(); err != nil {
		return p, err
	}
	if err = ctx.Err(); err != nil {
		return Policy{}, err
	}
	payload.Body = bytes.Clone(payload.Body)
	lastDecodedPolicy.Store(&decodedPolicy{payload: payload, policy: p})
	return p, nil
}

func validTime(at time.Time) bool {
	return !at.IsZero() && at.Location() == time.UTC && at.Year() >= 1 && at.Year() <= 9999 && at.Nanosecond()%1000 == 0
}

func validOptionalTime(at *time.Time) bool {
	return at == nil || validTime(*at)
}

func validNumber(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

func validFeatureRef(r a.FeatureRef) bool {
	return a.ValidHash(r.ID) && validNumber(r.Value) && validTime(r.SourceAt) && validTime(r.AvailableAt)
}

func validRebound(r Rebound) bool {
	return validTime(r.DropAt) && validTime(r.RiseAt) && r.DropAt.Before(r.RiseAt) && r.Reference.SourceAt.Before(r.DropAt) &&
		validFeatureRef(r.Reference) && validNumber(r.PrePowerW) && r.PrePowerW >= 0 && a.ValidHash(r.BundleID) && validHashes(r.Support) && len(r.Support) > 0
}

func validHashes(ids []string) bool {
	return a.Set(ids, 32) == nil && !slices.ContainsFunc(ids, func(id string) bool { return !a.ValidHash(id) })
}

func validBranches(branches []string) bool {
	return a.Set(branches, 3) == nil && !slices.ContainsFunc(branches, func(b string) bool {
		return b != "RAPID" && b != "SLOW" && b != "PERSISTENT"
	})
}

func hasWarming(branches []string) bool {
	return slices.Contains(branches, "RAPID") || slices.Contains(branches, "SLOW")
}

func validateState(s State) error {
	if s.Schema != 1 || !validBranches(s.Branches) || !validOptionalTime(s.LastEndpointAt) ||
		(len(s.Branches) > 0) != (s.EntryEndpoint != nil) || hasWarming(s.Branches) != (s.Reference != nil) {
		return a.ErrInvalid
	}
	if s.EntryEndpoint != nil && (!validFeatureRef(*s.EntryEndpoint) || s.LastEndpointAt != nil && s.LastEndpointAt.Before(s.EntryEndpoint.SourceAt)) ||
		s.Reference != nil && (!validFeatureRef(*s.Reference) || !s.Reference.SourceAt.Before(s.EntryEndpoint.SourceAt)) ||
		s.Rebound != nil && (s.Reference == nil || !validRebound(*s.Rebound)) {
		return a.ErrInvalid
	}
	return nil
}

func validateStateAt(s State, p Policy, logical, cutoff time.Time) error {
	if err := validateState(s); err != nil {
		return err
	}
	if s.LastEndpointAt != nil && s.LastEndpointAt.After(logical) {
		return a.ErrInvalid
	}
	for _, ref := range []*a.FeatureRef{s.EntryEndpoint, s.Reference} {
		if ref != nil && (ref.SourceAt.After(logical) || ref.AvailableAt.After(cutoff)) {
			return a.ErrInvalid
		}
	}
	if s.Reference != nil {
		width := p.RapidSeconds
		if slices.Contains(s.Branches, "SLOW") {
			width = p.SlowSeconds
		}
		if !s.Reference.SourceAt.Equal(s.EntryEndpoint.SourceAt.Add(-seconds(width))) {
			return a.ErrInvalid
		}
	}
	if rb := s.Rebound; rb != nil {
		width := seconds(p.TransitionSeconds)
		if !rb.Reference.SourceAt.Equal(rb.DropAt.Add(-width)) || rb.DropAt.Add(width).After(rb.RiseAt) || rb.RiseAt.Add(width).After(logical) ||
			rb.Reference.AvailableAt.After(cutoff) || rb.Reference.Value >= p.PersistentC {
			return a.ErrInvalid
		}
	}
	return nil
}

func compareOccurrence(x, y a.Occurrence) int {
	if x.PolicyID < y.PolicyID {
		return -1
	}
	if x.PolicyID > y.PolicyID {
		return 1
	}
	if x.Occurrence < y.Occurrence {
		return -1
	}
	if x.Occurrence > y.Occurrence {
		return 1
	}
	return 0
}

func validateTracker(t TrackerState) error {
	if err := validateState(candidate(t)); err != nil {
		return err
	}
	if t.UrgentOccurrences == nil || len(t.UrgentOccurrences) > 8 || !validOptionalTime(t.RearmSince) ||
		t.Active != (len(t.Branches) > 0 || len(t.UrgentOccurrences) > 0) ||
		!t.Active && (t.LastEndpointAt != nil || t.RearmSince != nil) ||
		t.RearmSince != nil && (t.LastEndpointAt == nil || t.RearmSince.After(*t.LastEndpointAt)) {
		return a.ErrInvalid
	}
	for i, occ := range t.UrgentOccurrences {
		if !a.ValidID(occ.PolicyID, 128) || occ.Occurrence < 1 || i > 0 && compareOccurrence(t.UrgentOccurrences[i-1], occ) >= 0 {
			return a.ErrInvalid
		}
	}
	return nil
}

func validateDetails(d Details) error {
	if d.Schema != 1 || !validBranches(d.Branches) || !validHashes(d.Support) ||
		d.Coverage != "SUPPORTED" && d.Coverage != "UNKNOWN" ||
		d.Temperature != nil && !validFeatureRef(*d.Temperature) || d.Rebound != nil && !validRebound(*d.Rebound) ||
		d.SignedChangeC != nil && !validNumber(*d.SignedChangeC) ||
		d.PowerMedianW != nil && (!validNumber(*d.PowerMedianW) || *d.PowerMedianW < 0) ||
		d.PowerRangeW != nil && (!validNumber(*d.PowerRangeW) || *d.PowerRangeW < 0) {
		return a.ErrInvalid
	}
	return nil
}

func decode(ctx context.Context, r a.Request) (Policy, TrackerState, State, error) {
	t := initial()
	var s State
	p, err := decodePolicy(ctx, r.Policy)
	if err != nil {
		return p, t, s, err
	}
	if err = p.Validate(); err != nil {
		return p, t, s, err
	}
	if r.Contract != 1 || r.Implementation != 1 || r.Category != CategoryID ||
		!validTime(r.LogicalAt) || !validTime(r.AvailabilityCutoff) || r.AvailabilityCutoff.After(r.LogicalAt) ||
		!validTime(r.DiscoveryFloor) || r.DiscoveryFloor.After(r.LogicalAt) {
		return p, t, s, a.ErrInvalid
	}
	switch r.Scope {
	case "TRACKER":
		if r.Purpose != "DISCOVER" && r.Purpose != "FOLLOW_UP" || r.Purpose == "FOLLOW_UP" && r.State == nil || r.SharedContext != nil {
			return p, t, s, a.ErrInvalid
		}
		if r.State != nil {
			t, err = decodePayload[TrackerState](*r.State, "tracker", stateLimit)
			if err == nil {
				err = validateTracker(t)
			}
			if err == nil {
				err = validateStateAt(candidate(t), p, r.LogicalAt, r.AvailabilityCutoff)
			}
		}
		if err == nil && r.Purpose == "DISCOVER" && t.Active {
			err = a.ErrInvalid
		}
	case "ARM":
		if r.State == nil || r.Entry == nil || (r.Purpose == "ASSESS" && r.Terminal != nil) ||
			(r.Purpose == "FOLLOW_UP" && r.Terminal == nil) || r.Purpose != "ASSESS" && r.Purpose != "FOLLOW_UP" {
			return p, t, s, a.ErrInvalid
		}
		s, err = decodePayload[State](*r.State, "candidate", stateLimit)
		if err == nil {
			err = validateStateAt(s, p, r.LogicalAt, r.AvailabilityCutoff)
		}
		if err != nil || r.SharedContext == nil {
			break
		}
		c := r.SharedContext
		if c.Revision < 1 || !a.ValidHash(c.BundleID) || !validTime(c.AvailableAt) || c.AvailableAt.After(r.AvailabilityCutoff) {
			return p, t, s, a.ErrInvalid
		}
		shared, decodeErr := decodePayload[TrackerState](c.Payload, "tracker", stateLimit)
		if decodeErr != nil {
			return p, t, s, decodeErr
		}
		if err = validateTracker(shared); err != nil {
			return p, t, s, err
		}
		if err = validateStateAt(candidate(shared), p, c.AvailableAt, c.AvailableAt); err != nil {
			return p, t, s, err
		}
		if r.Purpose == "ASSESS" {
			if !shared.Active || !slices.Equal(s.Branches, shared.Branches) ||
				!reflect.DeepEqual(s.EntryEndpoint, shared.EntryEndpoint) || !reflect.DeepEqual(s.Reference, shared.Reference) ||
				s.Rebound != nil && !reflect.DeepEqual(s.Rebound, shared.Rebound) {
				return p, t, s, a.ErrInvalid
			}
			s.Rebound = shared.Rebound
		}
	default:
		err = a.ErrInvalid
	}
	return p, t, s, err
}

func (c Category) ValidateResult(ctx context.Context, r a.Request, actual a.Result) error {
	// Recompute the semantic result from raw evidence. Materialization only adds
	// references, so it cannot move discovery or change the selected medians.
	expected, err := c.Evaluate(ctx, r)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(actual.ProposedFeatures))
	for _, f := range actual.ProposedFeatures {
		id, err := a.FeatureID(r, f)
		if err != nil || seen[id] || !slices.Contains(expected.Support, id) || !slices.Contains(r.Bundle.Features, id) {
			return a.ErrInvalid
		}
		seen[id] = true
	}
	if len(expected.ProposedFeatures) != 0 {
		// Every needed feature must already exist in the materialized bundle.
		return a.ErrInvalid
	}
	actual.ProposedFeatures = expected.ProposedFeatures
	if actual.Details != nil {
		d, err := decodePayload[Details](*actual.Details, "details", detailsLimit)
		if err != nil || validateDetails(d) != nil || expected.Details == nil {
			return a.ErrInvalid
		}
		want, err := decodePayload[Details](*expected.Details, "details", detailsLimit)
		if err != nil {
			return err
		}
		// These measurements are optional. When supplied, they describe the
		// same evidence as the result and, on a terminal, the same projection.
		if !matchesOptional(d.Temperature, want.Temperature) || !matchesOptional(d.SignedChangeC, want.SignedChangeC) ||
			!matchesOptional(d.PowerMedianW, want.PowerMedianW) || !matchesOptional(d.PowerRangeW, want.PowerRangeW) ||
			!matchesOptional(d.Rebound, want.Rebound) || d.Schema != want.Schema || d.Coverage != want.Coverage ||
			!slices.Equal(d.Branches, want.Branches) || !slices.Equal(d.Support, want.Support) {
			return a.ErrInvalid
		}
	}
	actual.Details, expected.Details = nil, nil
	if !reflect.DeepEqual(actual, expected) {
		return a.ErrInvalid
	}
	return ctx.Err()
}

func matchesOptional[T any](actual, expected *T) bool {
	return actual == nil || reflect.DeepEqual(actual, expected)
}

func occurrences(qs []qualified) []a.Occurrence {
	out := make([]a.Occurrence, 0, len(qs))
	for _, q := range qs {
		out = append(out, q.occurrence())
	}
	slices.SortFunc(out, compareOccurrence)
	return slices.Compact(out)
}

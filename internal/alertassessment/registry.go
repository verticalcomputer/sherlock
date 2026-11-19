package alertassessment

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
)

type Registration struct {
	category   Category
	descriptor Descriptor
	hash       string
}
type Registry struct {
	entries map[string]map[int64]Registration
	latest  map[string]int64
}

func NewRegistry(categories ...Category) (*Registry, error) {
	r := &Registry{entries: map[string]map[int64]Registration{}, latest: map[string]int64{}}
	for _, c := range categories {
		if c == nil || nilAdapter(reflect.ValueOf(c)) {
			return nil, ErrInvalid
		}
		d, e := registeredDescriptor(c)
		if e != nil {
			return nil, e
		}
		if _, ok := r.entries[d.Category][d.Implementation]; ok {
			return nil, fmt.Errorf("%w: duplicate category implementation", ErrInvalid)
		}
		h, e := Identity("descriptor", d.Category, d)
		if e != nil {
			return nil, e
		}
		if r.entries[d.Category] == nil {
			r.entries[d.Category] = make(map[int64]Registration)
		}
		r.entries[d.Category][d.Implementation] = Registration{c, d, h}
		r.latest[d.Category] = max(r.latest[d.Category], d.Implementation)
	}
	return r, nil
}

func nilAdapter(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func copyDescriptor(d Descriptor) Descriptor {
	d.Modes, d.Metrics = slices.Clone(d.Modes), slices.Clone(d.Metrics)
	d.Outcomes, d.Reasons, d.Updates = slices.Clone(d.Outcomes), slices.Clone(d.Reasons), slices.Clone(d.Updates)
	return d
}

func registeredDescriptor(c Category) (d Descriptor, err error) {
	defer func() {
		if recover() != nil {
			d, err = Descriptor{}, ErrInvalid
		}
	}()
	d = c.Describe()
	if err = validateDescriptor(d); err != nil {
		return Descriptor{}, err
	}
	return copyDescriptor(d), nil
}

func (r *Registry) Lookup(category string) (Category, Descriptor, string, error) {
	if r == nil {
		return nil, Descriptor{}, "", ErrInvalid
	}
	return r.LookupVersion(category, r.latest[category])
}

func (r *Registry) LookupVersion(category string, implementation int64) (Category, Descriptor, string, error) {
	if r == nil {
		return nil, Descriptor{}, "", ErrInvalid
	}
	v, ok := r.entries[category][implementation]
	if !ok {
		return nil, Descriptor{}, "", fmt.Errorf("%w: unknown category implementation", ErrInvalid)
	}
	return v.category, copyDescriptor(v.descriptor), v.hash, nil
}
func validateDescriptor(d Descriptor) error {
	if !ValidID(d.Category, 128) || d.Contract != 1 || d.Implementation < 1 || d.PolicySchema < 1 || d.TrackerSchema < 1 || d.CandidateSchema < 1 || d.DetailsSchema < 1 {
		return ErrInvalid
	}
	if Set(d.Modes, 3) != nil || len(d.Modes) == 0 || Set(d.Reasons, 32) != nil {
		return ErrInvalid
	}
	for _, m := range d.Modes {
		if m != "replay" && m != "shadow" && m != "production" {
			return ErrInvalid
		}
	}
	l := d.PayloadLimits
	if l.Policy < 1 || l.Policy > MaxPayloadBytes || l.Tracker < 1 || l.Tracker > MaxPayloadBytes || l.Candidate < 1 || l.Candidate > MaxPayloadBytes || l.Details < 1 || l.Details > MaxDetailsBytes {
		return ErrInvalid
	}
	if d.Metrics == nil || len(d.Metrics) > 3 || d.Outcomes == nil || len(d.Outcomes) > 32 || d.Updates == nil || len(d.Updates) > 8 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, m := range d.Metrics {
		if seen[m.Metric] || !ValidID(m.Metric, 128) || !ValidID(m.Unit, 128) || m.HistorySeconds < 1 || m.HistorySeconds > 900 {
			return ErrInvalid
		}
		seen[m.Metric] = true
	}
	seen = map[string]bool{}
	terminalOutcomes := map[string]Outcome{}
	for _, o := range d.Outcomes {
		k := o.Purpose + "/" + o.Code
		if seen[k] || !strings.HasPrefix(o.Code, d.Category+"/") || len(o.Code) <= len(d.Category)+1 || !ValidID(o.Code, 128) {
			return ErrInvalid
		}
		seen[k] = true
		if o.Purpose != "DISCOVER" && o.Purpose != "ASSESS" {
			return ErrInvalid
		}
		if o.Phase != "NO_CANDIDATE" && o.Phase != "OBSERVING" && o.Phase != "FINAL" {
			return ErrInvalid
		}
		if o.Purpose == "ASSESS" && o.Phase == "NO_CANDIDATE" || o.Purpose == "DISCOVER" && o.Phase == "FINAL" && o.Action != "URGENT" {
			return ErrInvalid
		}
		if o.Phase != "FINAL" {
			if o.EvidenceClass != "NONTERMINAL" || o.Action != "NONE" {
				return ErrInvalid
			}
		} else {
			switch o.EvidenceClass {
			case "SUPPORTED_CONCERN":
				if o.Action != "INVESTIGATE" && o.Action != "URGENT" {
					return ErrInvalid
				}
			case "UNRESOLVED":
				if o.Action != "INVESTIGATE" {
					return ErrInvalid
				}
			case "BENIGN":
				if o.Action != "NONE" {
					return ErrInvalid
				}
			default:
				return ErrInvalid
			}
			if prior, exists := terminalOutcomes[o.Code]; exists && (prior.Action != o.Action || prior.EvidenceClass != o.EvidenceClass) {
				return ErrInvalid
			}
			terminalOutcomes[o.Code] = o
		}
	}
	seen = map[string]bool{}
	for _, u := range d.Updates {
		if seen[u.Code] || !ValidID(u.Code, 128) || (u.Action != "INVESTIGATE" && u.Action != "URGENT") || (u.EvidenceClass != "SUPPORTED_CONCERN" && u.EvidenceClass != "UNRESOLVED") {
			return ErrInvalid
		}
		seen[u.Code] = true
	}
	b, e := Canonical(d)
	if e != nil || len(b) > 16<<10 {
		return ErrInvalid
	}
	return nil
}

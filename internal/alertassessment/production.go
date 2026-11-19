package alertassessment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

const ProductionSnapshotLimit = 16 << 20

// ProductionConfig explicitly selects a separate continuous lifecycle. A
// shadow Config cannot enable it and its serialized contract stays unchanged.
type ProductionConfig struct {
	Schema               int64  `json:"schema"`
	Revision             int64  `json:"revision"`
	NotificationsEnabled bool   `json:"notifications_enabled"`
	EvidenceBaseURL      string `json:"evidence_base_url,omitempty"`
	Assessment           Config `json:"assessment"`
}

func ParseProductionConfig(ctx context.Context, raw []byte, registry *Registry) (ProductionConfig, error) {
	var c ProductionConfig
	if err := DecodeStrict(raw, &c, 64<<10); err != nil {
		return c, err
	}
	return NormalizeProductionConfig(ctx, c, registry)
}
func NormalizeProductionConfig(ctx context.Context, c ProductionConfig, r *Registry) (ProductionConfig, error) {
	if c.Schema != 1 || c.Revision < 1 || !productionPathID(c.Assessment.RunID) || !productionPathID(c.Assessment.ClusterID) {
		return c, ErrInvalid
	}
	// Slack notifications can carry their own investigation context without a
	// public evidence origin. A configured origin still has the same restrictions.
	if c.EvidenceBaseURL != "" {
		u, err := url.Parse(c.EvidenceBaseURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.EscapedPath() != "" && u.EscapedPath() != "/") || len(c.EvidenceBaseURL) > 512 || strings.ContainsAny(c.EvidenceBaseURL, "<>?#\r\n") {
			return c, fmt.Errorf("invalid production evidence URL")
		}
	}
	c.Assessment.production = true
	var err error
	c.Assessment, err = NormalizeConfig(ctx, c.Assessment, r)
	if err != nil {
		return c, err
	}
	_, d, _, err := r.LookupVersion(c.Assessment.Category, c.Assessment.Implementation)
	if err != nil || !slices.Contains(d.Modes, "production") {
		return c, ErrInvalid
	}
	return c, nil
}

// NewProductionEngine uses the same execution, temporal evidence and deadline
// machinery as replay/shadow, with explicit single-arm continuous admission.
func NewProductionEngine(ctx context.Context, c ProductionConfig, start time.Time, r *Registry) (*Engine, error) {
	c, err := NormalizeProductionConfig(ctx, c, r)
	if err != nil {
		return nil, err
	}
	e, err := NewEngine(ctx, c.Assessment, start, r)
	if err != nil {
		return nil, err
	}
	e.AdmissionEndAt = time.Time{}
	e.Shadow = true // Apply the same cooperative GPU execution bound.
	return e, nil
}

type ProductionSnapshot struct {
	Schema      int64        `json:"schema"`
	Enrollment  *Enrollment  `json:"enrollment"`
	ProcessedAt time.Time    `json:"processed_at"`
	LastPass    time.Time    `json:"last_pass"`
	State       string       `json:"state"`
	StopReason  string       `json:"stop_reason"`
	Candidates  []*Candidate `json:"candidates"`
	Facts       []Fact       `json:"facts"`
	Bundles     []Bundle     `json:"bundles"`
}

// RestoreProduction confines each stored snapshot to exactly one admitted GPU.
func (e *Engine) RestoreProduction(asset string, raw []byte) error {
	if !e.Config.production || !slices.ContainsFunc(e.Config.Assets, func(a Asset) bool { return a.EntityKey == asset }) {
		return ErrInvalid
	}
	e.Config.Assets = slices.DeleteFunc(slices.Clone(e.Config.Assets), func(a Asset) bool { return a.EntityKey != asset })
	for key := range e.Enrollments {
		if key != asset {
			delete(e.Enrollments, key)
		}
	}
	if len(raw) == 0 {
		return nil
	}
	var s ProductionSnapshot
	if err := DecodeStrict(raw, &s, ProductionSnapshotLimit); err != nil {
		return err
	}
	if s.Schema != 1 || s.Enrollment == nil || s.Enrollment.Asset != asset || s.Enrollment.Revision < 1 || s.Enrollment.Sequence < 0 || s.Facts == nil || s.Bundles == nil || len(s.Candidates) > 1 || (s.State != "ACTIVE" && s.State != "DRAINING" && s.State != "CLOSED") {
		return ErrInvalid
	}
	for _, c := range s.Candidates {
		if c.Asset != asset || c.Sequence != s.Enrollment.Sequence || c.BudgetMS != 120000 {
			return ErrInvalid
		}
	}
	facts := map[string]Fact{}
	for _, f := range s.Facts {
		if _, duplicate := facts[f.ID]; duplicate {
			return ErrInvalid
		}
		if f.Asset != asset || f.Run != e.Config.RunID {
			return ErrInvalid
		}
		facts[f.ID] = f
	}
	bundles := map[string]Bundle{}
	for _, b := range s.Bundles {
		if _, duplicate := bundles[b.ID]; duplicate {
			return ErrInvalid
		}
		if b.Asset != asset || b.Run != e.Config.RunID {
			return ErrInvalid
		}
		bundles[b.ID] = b
	}
	e.Enrollments[asset] = s.Enrollment
	s.Enrollment.ProcessedAt = s.ProcessedAt
	e.Candidates, e.Facts, e.Bundles = s.Candidates, facts, bundles
	e.State, e.StopReason, e.lastPass = s.State, s.StopReason, s.LastPass
	return nil
}

// ProductionEvidence retains the decision's exact immutable proof closure.
func (e *Engine) ProductionEvidence(d Decision) (json.RawMessage, error) {
	return e.ProductionEvidenceContext(context.Background(), d)
}

// ProductionEvidenceContext observes the same cooperative persistence deadline.
func (e *Engine) ProductionEvidenceContext(ctx context.Context, d Decision) (json.RawMessage, error) {
	facts, bundles, err := e.productionClosure(ctx, []string{d.BundleID}, nil)
	if err != nil {
		return nil, err
	}
	b, err := Canonical(struct {
		Decision Decision `json:"decision"`
		Facts    []Fact   `json:"facts"`
		Bundles  []Bundle `json:"bundles"`
	}{d, productionFactSlice(facts), productionBundleSlice(bundles)})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || len(b) > 4<<20 {
		return nil, ErrInvalid
	}
	return b, nil
}

// SnapshotProduction bounds current working state; closed evidence is retained
// separately by persistence, never reloaded into every evaluation.
func (e *Engine) SnapshotProduction(asset string, at time.Time) ([]byte, error) {
	return e.SnapshotProductionContext(context.Background(), asset, at)
}

// SnapshotProductionContext stops bounded proof traversal when the GPU pass expires.
func (e *Engine) SnapshotProductionContext(ctx context.Context, asset string, at time.Time) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.Config.production || e.Enrollments[asset] == nil {
		return nil, ErrInvalid
	}
	en := e.Enrollments[asset]
	candidates := []*Candidate{}
	roots := []string{}
	ids := []string{}
	if en.Active {
		for _, c := range e.Candidates {
			if c.Asset == asset && c.Sequence == en.Sequence {
				candidates = append(candidates, c)
				roots = append(roots, c.Entry.BundleID)
				if c.Terminal != nil && c.Terminal.Endpoint != nil {
					ids = append(ids, c.Terminal.Endpoint.ID)
				}
			}
		}
		if en.SharedContext != nil {
			roots = append(roots, en.SharedContext.BundleID)
			for id, f := range e.Facts {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if f.Kind == "TRACKER_CONTEXT" {
					var tc TrackerContext
					if json.Unmarshal(f.Body, &tc) == nil && tc.Revision == en.SharedContext.Revision && tc.BundleID == en.SharedContext.BundleID {
						ids = append(ids, id)
					}
				}
			}
		}
	}
	for id, f := range e.Facts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if f.Asset == asset && recentFact(f, at.Add(-900*time.Second)) {
			ids = append(ids, id)
		}
	}
	facts, bundles, err := e.productionClosure(ctx, roots, ids)
	if err != nil {
		return nil, err
	}
	s := ProductionSnapshot{Schema: 1, Enrollment: en, ProcessedAt: en.ProcessedAt, LastPass: e.lastPass, State: e.State, StopReason: e.StopReason, Candidates: candidates, Facts: productionFactSlice(facts), Bundles: productionBundleSlice(bundles)}
	// The snapshot itself is not content-addressed. Encode the typed envelope
	// directly while preserving canonical opaque bodies and sorted fact IDs.
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	err = encoder.Encode(s)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	b := bytes.TrimSuffix(out.Bytes(), []byte("\n"))
	if err != nil || len(b) > ProductionSnapshotLimit {
		return nil, fmt.Errorf("CAPACITY: production snapshot")
	}
	return b, nil
}
func (e *Engine) productionClosure(ctx context.Context, roots, ids []string) (map[string]Fact, map[string]Bundle, error) {
	facts := map[string]Fact{}
	bundles := map[string]Bundle{}
	var addFact func(string) error
	addBundle := func(id string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, ok := bundles[id]; ok {
			return nil
		}
		b, ok := e.Bundles[id]
		if !ok {
			return fmt.Errorf("missing proof bundle %s", id)
		}
		bundles[id] = b
		for _, x := range append(slices.Clone(b.Facts), b.Features...) {
			if err := addFact(x); err != nil {
				return err
			}
		}
		return nil
	}
	addFact = func(id string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, ok := facts[id]; ok {
			return nil
		}
		f, ok := e.Facts[id]
		if !ok {
			return fmt.Errorf("missing proof fact %s", id)
		}
		facts[id] = f
		if len(facts) > 4096 {
			return ErrInvalid
		}
		for _, x := range factRefs(f) {
			if err := addFact(x); err != nil {
				return err
			}
		}
		if f.Kind == "TRACKER_CONTEXT" {
			var t TrackerContext
			if json.Unmarshal(f.Body, &t) != nil {
				return ErrInvalid
			}
			if err := addBundle(t.BundleID); err != nil {
				return err
			}
		}
		return nil
	}
	for _, id := range roots {
		if err := addBundle(id); err != nil {
			return nil, nil, err
		}
	}
	for _, id := range ids {
		if err := addFact(id); err != nil {
			return nil, nil, err
		}
	}
	return facts, bundles, nil
}

func productionFactSlice(m map[string]Fact) []Fact {
	out := make([]Fact, 0, len(m))
	for _, f := range m {
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b Fact) int { return strings.Compare(a.ID, b.ID) })
	return out
}
func productionBundleSlice(m map[string]Bundle) []Bundle {
	out := make([]Bundle, 0, len(m))
	for _, b := range m {
		out = append(out, b)
	}
	slices.SortFunc(out, func(a, b Bundle) int { return strings.Compare(a.ID, b.ID) })
	return out
}

var productionPathPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func productionPathID(s string) bool {
	return s != "." && s != ".." && productionPathPattern.MatchString(s)
}

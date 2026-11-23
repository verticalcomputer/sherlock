package alertassessment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	maxFactBytes           = 16 << 10
	maxTrackerContextBytes = 24 << 10
	maxFeatureBytes        = 64 << 10
	maxBundleBytes         = 256 << 10
	maxPointsPerMetric     = 256
	maxPoints              = 768
	maxResultMetadata      = 8 << 10
)

func validAsset(key string) bool {
	if !ValidID(key, 256) {
		return false
	}
	parts := strings.Split(key, "/")
	if len(parts) != 5 || !ValidID(parts[0], 128) || !ValidID(parts[2], 128) || !ValidID(parts[3], 128) {
		return false
	}
	cluster := domain.ClusterID(parts[0])
	const source domain.SourceID = "assessment"
	id, ok := domain.ResolveGPUObservationIdentity(cluster, source, domain.Observation{ClusterID: cluster, SourceID: source, EntityKey: key})
	return ok && id.Canonical && id.EntityKey == key
}

func boundedSummary(s string) bool { return len(s) <= 2048 && utf8.ValidString(s) }
func finite(v float64) bool        { return !math.IsNaN(v) && !math.IsInf(v, 0) }

func validProvenance(p Provenance) bool {
	for _, id := range []string{p.CollectionRunID, p.Operation, p.InventoryRevision, p.SourceRecord} {
		if !ValidID(id, 128) {
			return false
		}
	}
	if p.ScheduleRevision <= 0 {
		return false
	}
	digest, reserved := strings.CutPrefix(p.CollectionRunID, domain.CoolingUploadRunPrefix)
	if reserved != (p.Mode == "upload") || reserved && !ValidHash(digest) {
		return false
	}
	legacy := p.JobID != "" || p.ConfigurationRevision != nil
	durable := p.WorkID != "" || p.CollectorID != ""
	upload := p.UploadProfileID != "" || p.UploadProfileHash != ""
	switch p.Mode {
	case "legacy":
		return !upload && !durable && ValidID(p.JobID, 128) && p.ConfigurationRevision != nil && *p.ConfigurationRevision >= 0
	case "durable":
		return !upload && !legacy && ValidID(p.WorkID, 128) && ValidID(p.CollectorID, 128)
	case "fixture":
		return !upload && !legacy && !durable
	case "upload":
		return !legacy && p.WorkID == "" && ValidID(p.CollectorID, 128) && ValidID(p.UploadProfileID, 128) && ValidHash(p.UploadProfileHash)
	default:
		return false
	}
}

func validFeature(p Feature) bool {
	if !durableTime(p.SourceAt) || !finite(p.Value) || !ValidID(p.Unit, 128) || len(p.Support) == 0 || hashSet(p.Support, maxPoints) != nil {
		return false
	}
	switch p.FeatureKind {
	case "temperature_endpoint", "power_endpoint", "entry", "rebound", "coverage":
		return true
	default:
		return false
	}
}

func validQualified(q Qualified) bool {
	if !ValidID(q.PolicyID, 128) || q.Occurrence <= 0 || q.RuleVersion <= 0 || q.EnrollmentRevision <= 0 || !durableTime(q.QualifiedAt) ||
		(q.Transition != "OPEN" && q.Transition != "RECOVER") || (q.Severity != "WARNING" && q.Severity != "CRITICAL") || len(q.Snapshot) > 32 || q.Snapshot == nil {
		return false
	}
	if q.Rule != "gpu_thermal" && q.Rule != "hbm_thermal" && q.Rule != "telemetry_loss" {
		return false
	}
	for _, s := range q.Snapshot {
		if !ValidID(s.Metric, 128) || !ValidID(s.Unit, 128) || !durableTime(s.SourceAt) ||
			(s.Support != "SUPPORTED" && s.Support != "UNKNOWN") || (s.Value != nil && !finite(*s.Value)) {
			return false
		}
	}
	return true
}

func validFactScope(category string, f Fact) bool {
	return ValidID(category, 128) && ValidID(f.Run, 128) && validAsset(f.Asset) && durableTime(f.AvailableAt)
}

func validSample(f Fact, s Sample) bool {
	return ValidID(s.Metric, 128) && ValidID(s.Unit, 128) && ValidID(s.SourceRecord, 128) &&
		durableTime(s.SourceAt) && durableTime(s.CollectedAt) && durableTime(s.CompletedAt) &&
		!s.CollectedAt.After(s.CompletedAt) && !s.CompletedAt.After(f.AvailableAt) && finite(s.Value) &&
		s.SourceRecord == s.Provenance.SourceRecord && validProvenance(s.Provenance)
}

// These wire projections use Canonical's lexical key order. Their inputs
// have already passed typed validation, including UTF-8 and durable times.
func encodeSampleBody(s Sample) ([]byte, error) {
	type provenance struct {
		CollectionRunID       string `json:"collection_run_id"`
		CollectorID           string `json:"collector_id,omitempty"`
		ConfigurationRevision *int64 `json:"configuration_revision,omitempty"`
		InventoryRevision     string `json:"inventory_revision"`
		JobID                 string `json:"job_id,omitempty"`
		Mode                  string `json:"mode"`
		Operation             string `json:"operation"`
		ScheduleRevision      int64  `json:"schedule_revision"`
		SourceRecord          string `json:"source_record"`
		UploadProfileHash     string `json:"upload_profile_hash,omitempty"`
		UploadProfileID       string `json:"upload_profile_id,omitempty"`
		WorkID                string `json:"work_id,omitempty"`
	}
	if s.Value == 0 {
		s.Value = 0 // Canonical encodes negative zero as zero.
	}
	p := s.Provenance
	return json.Marshal(struct {
		CollectedAt  time.Time  `json:"collected_at"`
		CompletedAt  time.Time  `json:"completed_at"`
		Metric       string     `json:"metric"`
		Provenance   provenance `json:"provenance"`
		SourceAt     time.Time  `json:"source_at"`
		SourceRecord string     `json:"source_record"`
		Unit         string     `json:"unit"`
		Value        float64    `json:"value"`
	}{
		CollectedAt: s.CollectedAt, CompletedAt: s.CompletedAt, Metric: s.Metric,
		Provenance: provenance{
			CollectionRunID: p.CollectionRunID, CollectorID: p.CollectorID, ConfigurationRevision: p.ConfigurationRevision,
			InventoryRevision: p.InventoryRevision, JobID: p.JobID, Mode: p.Mode, Operation: p.Operation,
			ScheduleRevision: p.ScheduleRevision, SourceRecord: p.SourceRecord, WorkID: p.WorkID,
			UploadProfileID: p.UploadProfileID, UploadProfileHash: p.UploadProfileHash,
		},
		SourceAt: s.SourceAt, SourceRecord: s.SourceRecord, Unit: s.Unit, Value: s.Value,
	})
}

func sampleIdentity(category string, f Fact, s Sample) (string, error) {
	if s.Value == 0 {
		s.Value = 0
	}
	b, err := json.Marshal(struct {
		Asset    string    `json:"asset"`
		Metric   string    `json:"metric"`
		Run      string    `json:"run"`
		SourceAt time.Time `json:"source_at"`
		Unit     string    `json:"unit"`
		Value    float64   `json:"value"`
	}{Asset: f.Asset, Metric: s.Metric, Run: f.Run, SourceAt: s.SourceAt, Unit: s.Unit, Value: s.Value})
	if err != nil {
		return "", err
	}
	return Hash("sample", category, 1, b), nil
}

func factFitsEnvelope(f Fact, limit int) bool {
	// Canonical body is embedded verbatim. Count the envelope without
	// asking json.Marshal to scan the full fact body again.
	envelope := f
	envelope.Body = json.RawMessage(`{}`)
	if envelope.ID == "" {
		envelope.ID = strings.Repeat("0", 64)
	}
	encoded, err := json.Marshal(envelope)
	return err == nil && len(encoded)-2+len(f.Body) <= limit
}

// factBody validates the typed, canonical body. Reference relationships are
// checked separately because admission can insert the entire closure at once.
func factBody(category string, f Fact, sample *Sample) (any, error) {
	if !validFactScope(category, f) {
		return nil, ErrInvalid
	}
	if f.Kind == "SAMPLE" {
		if len(f.Body) == 0 || len(f.Body) > maxFactBytes {
			return nil, ErrInvalid
		}
		if sample == nil {
			sample = new(Sample)
			if err := json.Unmarshal(f.Body, sample); err != nil {
				return nil, err
			}
		}
		if !validSample(f, *sample) {
			return nil, ErrInvalid
		}
		canonical, err := encodeSampleBody(*sample)
		if err != nil || !bytes.Equal(canonical, f.Body) || !factFitsEnvelope(f, maxFactBytes) {
			return nil, ErrInvalid
		}
		return sample, nil
	}
	var b any
	limit := maxFactBytes
	switch f.Kind {
	case "COVERAGE":
		b = new(Coverage)
	case "QUALIFIED":
		b = new(Qualified)
	case "FEATURE":
		b, limit = new(Feature), maxFeatureBytes
	case "CONFLICT":
		b = new(Conflict)
	case "PROVENANCE":
		b = new(ProvenanceFact)
	case "TRACKER_CONTEXT":
		b, limit = new(TrackerContext), maxTrackerContextBytes
	default:
		return nil, ErrInvalid
	}
	if len(f.Body) == 0 || len(f.Body) > limit {
		return nil, ErrInvalid
	}
	if f.Kind == "TRACKER_CONTEXT" {
		// The opaque payload body must pass structural validation too.
		if err := DecodeStrict(f.Body, b, limit); err != nil {
			return nil, err
		}
	} else if err := json.Unmarshal(f.Body, b); err != nil {
		return nil, err
	}
	// These concrete fact types serialize every required field. Exact bytes
	// reject unknown, duplicate, case-aliased, missing and null fields after
	// decoding, in addition to rejecting noncanonical primitive encodings.
	canonical, err := Canonical(b)
	if err != nil || !bytes.Equal(canonical, f.Body) || !factFitsEnvelope(f, limit) {
		return nil, ErrInvalid
	}
	switch s := b.(type) {
	case *Coverage:
		if !ValidID(s.Metric, 128) || !ValidID(s.Code, 128) || !ValidID(s.SourceRecord, 128) ||
			!durableTime(s.From) || !durableTime(s.Through) || s.From.After(s.Through) {
			return nil, ErrInvalid
		}
	case *Qualified:
		if !validQualified(*s) {
			return nil, ErrInvalid
		}
	case *Feature:
		if !validFeature(*s) {
			return nil, ErrInvalid
		}
	case *Conflict:
		if !ValidID(s.Metric, 128) || !durableTime(s.SourceAt) || s.Code != "CONFLICT" || len(s.Values) != 2 || hashSet(s.Values, 2) != nil {
			return nil, ErrInvalid
		}
	case *ProvenanceFact:
		if !ValidHash(s.SampleID) || !ValidID(s.SourceRecord, 128) || s.SourceRecord != s.Provenance.SourceRecord || !validProvenance(s.Provenance) {
			return nil, ErrInvalid
		}
	case *TrackerContext:
		if s.Category != category || s.Revision <= 0 || !ValidHash(s.BundleID) || ValidatePayload(s.Payload, category, "tracker", s.Payload.Schema) != nil {
			return nil, ErrInvalid
		}
	}
	return b, nil
}

func factIdentity(category string, f Fact, body any) (string, error) {
	if s, ok := body.(*Sample); ok {
		return sampleIdentity(category, f, *s)
	}
	m := map[string]any{"run": f.Run, "asset": f.Asset}
	var kind string
	switch s := body.(type) {
	case *Coverage:
		kind = "coverage"
		m["metric"], m["from"], m["through"], m["code"], m["source_record"] = s.Metric, s.From, s.Through, s.Code, s.SourceRecord
	case *Qualified:
		kind = "qualified"
		m["policy_id"], m["occurrence"], m["transition"] = s.PolicyID, s.Occurrence, s.Transition
	case *Feature:
		kind = "feature"
		m["feature_kind"], m["source_at"], m["value"], m["unit"], m["support"] = s.FeatureKind, s.SourceAt, s.Value, s.Unit, s.Support
	case *Conflict:
		kind = "conflict"
		m["metric"], m["source_at"] = s.Metric, s.SourceAt
	case *ProvenanceFact:
		kind = "provenance"
		delete(m, "asset")
		m["sample_id"], m["source_record"] = s.SampleID, s.SourceRecord
	case *TrackerContext:
		kind = "tracker_context"
		m["category"], m["revision"], m["payload_hash"], m["bundle_id"] = s.Category, s.Revision, s.Payload.Hash, s.BundleID
	default:
		return "", ErrInvalid
	}
	return Identity(kind, category, m)
}

func FactIdentity(category string, f Fact) (string, error) {
	b, err := factBody(category, f, nil)
	if err != nil {
		return "", err
	}
	return factIdentity(category, f, b)
}

func NewFact(category, run, asset, kind string, at time.Time, body any) (Fact, error) {
	f := Fact{Run: run, Asset: asset, Kind: kind, AvailableAt: normalizeTime(at)}
	if s, ok := body.(Sample); kind == "SAMPLE" && ok {
		s.SourceAt = normalizeTime(s.SourceAt)
		s.CollectedAt = normalizeTime(s.CollectedAt)
		s.CompletedAt = normalizeTime(s.CompletedAt)
		if !validFactScope(category, f) || !validSample(f, s) {
			return Fact{}, ErrInvalid
		}
		b, err := encodeSampleBody(s)
		if err != nil {
			return Fact{}, err
		}
		f.Body = b
		if !factFitsEnvelope(f, maxFactBytes) {
			return Fact{}, ErrInvalid
		}
		f.ID, err = sampleIdentity(category, f, s)
		return f, err
	}
	b, err := Canonical(body)
	if err != nil {
		return Fact{}, err
	}
	f.Body = b
	f.ID, err = FactIdentity(category, f)
	return f, err
}

func FeatureID(r Request, f Feature) (string, error) {
	f.SourceAt = normalizeTime(f.SourceAt)
	if !validFeature(f) {
		return "", ErrInvalid
	}
	return factIdentity(r.Category, Fact{Run: r.Run, Asset: r.Asset}, &f)
}

func BundleID(category string, b Bundle) (string, error) {
	encoded, err := encodeBundleIdentity(b)
	if err != nil {
		return "", err
	}
	return Hash("bundle", category, 1, encoded), nil
}

func encodeBundleIdentity(b Bundle) ([]byte, error) {
	logicalAt, cutoff := normalizeTime(b.LogicalAt), normalizeTime(b.AvailabilityCutoff)
	if !utf8.ValidString(b.Asset) || !utf8.ValidString(b.Run) || logicalAt.Year() < 1 || logicalAt.Year() > 9999 || cutoff.Year() < 1 || cutoff.Year() > 9999 {
		return nil, ErrInvalid
	}
	for _, ids := range [][]string{b.Facts, b.Features} {
		for _, id := range ids {
			if !utf8.ValidString(id) {
				return nil, ErrInvalid
			}
		}
	}
	if b.Facts == nil {
		b.Facts = []string{}
	}
	if b.Features == nil {
		b.Features = []string{}
	}
	// Match Canonical's lexical key order without allocating a reflected
	// value for each element of the manifest.
	wire := struct {
		Asset              string    `json:"asset"`
		AvailabilityCutoff time.Time `json:"availability_cutoff"`
		Facts              []string  `json:"facts"`
		Features           []string  `json:"features"`
		LogicalAt          time.Time `json:"logical_at"`
		LookbackSeconds    int64     `json:"lookback_seconds"`
		Run                string    `json:"run"`
	}{
		Asset: b.Asset, AvailabilityCutoff: cutoff, Facts: b.Facts, Features: b.Features,
		LogicalAt: logicalAt, LookbackSeconds: b.LookbackSeconds, Run: b.Run,
	}
	return json.Marshal(wire)
}

func NewBundle(category, run, asset string, at time.Time, facts []Fact) (Bundle, error) {
	at = normalizeTime(at)
	b := Bundle{Run: run, Asset: asset, LogicalAt: at, AvailabilityCutoff: at, LookbackSeconds: 900, Facts: []string{}, Features: []string{}}
	for _, f := range facts {
		if f.AvailableAt.After(at) {
			continue
		}
		if f.Kind == "FEATURE" {
			b.Features = append(b.Features, f.ID)
		} else {
			b.Facts = append(b.Facts, f.ID)
		}
	}
	b.Facts = SortedUnique(b.Facts)
	b.Features = SortedUnique(b.Features)
	var err error
	b.ID, err = BundleID(category, b)
	return b, err
}

func isRawSupport(f Fact) bool {
	return f.Kind == "SAMPLE" || f.Kind == "COVERAGE" || f.Kind == "QUALIFIED"
}

func references(b any) []string {
	switch s := b.(type) {
	case *Feature:
		return s.Support
	case *ProvenanceFact:
		return []string{s.SampleID}
	case *Conflict:
		return s.Values
	default:
		return nil
	}
}

type factBodyCacheKey struct{}

type cachedFactBody struct {
	category string
	fact     Fact
	body     any
	verified bool
}

func (s cachedFactBody) matches(category string, f Fact) bool {
	return s.category == category && s.fact.Run == f.Run && s.fact.Asset == f.Asset && s.fact.Kind == f.Kind &&
		s.fact.AvailableAt == f.AvailableAt && bytes.Equal(s.fact.Body, f.Body)
}

// factBodyCache is bounded and lasts for one GPU call group. Host selectors
// share sample parses; verified entries also share typed body/identity checks.
// Every hit requires the exact category, envelope and bytes. Graph edges and
// temporal eligibility are always revalidated against the current request.
// Cached bodies are private, read-only host values, never category arguments.
type factBodyCache struct {
	mu       sync.Mutex
	items    map[string]cachedFactBody
	payloads map[string]Payload // last host-validated envelope per payload kind
	bytes    int
}

func withFactValidationCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, factBodyCacheKey{}, &factBodyCache{items: make(map[string]cachedFactBody)})
}

func checkedSamples(ctx context.Context) *factBodyCache {
	cache, _ := ctx.Value(factBodyCacheKey{}).(*factBodyCache)
	return cache
}

func (c *factBodyCache) lookup(category string, f Fact) *Sample {
	s, verified := c.find(category, f)
	if !verified {
		return nil
	}
	return s
}

func (c *factBodyCache) find(category string, f Fact) (*Sample, bool) {
	if f.Kind != "SAMPLE" {
		return nil, false
	}
	body, verified := c.findBody(category, f)
	sample, _ := body.(*Sample)
	return sample, verified
}

func (c *factBodyCache) findBody(category string, f Fact) (any, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.items[f.ID]
	if !ok || !item.matches(category, f) {
		return nil, false
	}
	return item.body, item.verified
}

// decodeForSelection supplies a read-only parse to host callers that select
// facts before graph validation. Category callbacks use DecodeSample instead.
func (c *factBodyCache) decodeForSelection(category string, f Fact) (*Sample, error) {
	if s, _ := c.find(category, f); s != nil {
		return s, nil
	}
	s := new(Sample)
	if err := json.Unmarshal(f.Body, s); err != nil {
		return nil, err
	}
	c.remember(category, f, s, false)
	return s, nil
}

func (c *factBodyCache) remember(category string, f Fact, b any, verified bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if item, ok := c.items[f.ID]; ok {
		if verified && !item.verified && item.matches(category, f) {
			item.body, item.verified = b, true
			c.items[f.ID] = item
		}
		return
	}
	limit := maxFactBytes
	switch f.Kind {
	case "FEATURE":
		limit = maxFeatureBytes
	case "TRACKER_CONTEXT":
		limit = maxTrackerContextBytes
	}
	if len(c.items) == maxPoints || len(f.Body) > limit || len(f.Body) > MaxInputBytes-c.bytes {
		return
	}
	f.Body = slices.Clone(f.Body)
	c.items[f.ID] = cachedFactBody{category: category, fact: f, body: b, verified: verified}
	c.bytes += len(f.Body)
}

// DecodeSample reuses a checked decode when the sample is byte-for-byte
// identical to the host-validated input. Other callers decode their own data.
func DecodeSample(ctx context.Context, category string, f Fact) (Sample, error) {
	if checked := checkedSamples(ctx).lookup(category, f); checked != nil {
		b := *checked
		b.Provenance.ConfigurationRevision = copyPointer(b.Provenance.ConfigurationRevision)
		return b, nil
	}
	var b Sample
	err := json.Unmarshal(f.Body, &b)
	return b, err
}

// factGraph caches checked bodies and eligibility while walking the finite typed
// fact edges. Tracker contexts point to bundles and are validated separately.
type factGraph struct {
	category string
	index    map[string]Fact
	bodies   map[string]any
	times    map[string]time.Time
	samples  *factBodyCache
}

func newFactGraph(category string, index map[string]Fact) *factGraph {
	return &factGraph{category: category, index: index, bodies: make(map[string]any), times: make(map[string]time.Time)}
}

func (g *factGraph) body(id string) (any, error) {
	if b, ok := g.bodies[id]; ok {
		return b, nil
	}
	f, ok := g.index[id]
	if !ok || f.ID != id {
		return nil, ErrInvalid
	}
	cached, verified := g.samples.findBody(g.category, f)
	if verified {
		g.bodies[id] = cached
		return cached, nil
	}
	parsed, _ := cached.(*Sample)
	b, err := factBody(g.category, f, parsed)
	if err != nil {
		return nil, err
	}
	hash, err := factIdentity(g.category, f, b)
	if err != nil || hash != id {
		return nil, ErrInvalid
	}
	g.bodies[id] = b
	g.samples.remember(g.category, f, b, true)
	return b, nil
}

func (g *factGraph) eligibility(id string) (time.Time, error) {
	if t, ok := g.times[id]; ok {
		return t, nil
	}
	b, err := g.body(id)
	if err != nil {
		return time.Time{}, err
	}
	f := g.index[id]
	at := f.AvailableAt
	latestAdmission := time.Time{}
	for _, ref := range references(b) {
		raw, ok := g.index[ref]
		if !ok || raw.Run != f.Run || raw.Asset != f.Asset || raw.AvailableAt.After(f.AvailableAt) {
			return time.Time{}, ErrInvalid
		}
		if f.Kind == "FEATURE" && !isRawSupport(raw) || f.Kind != "FEATURE" && raw.Kind != "SAMPLE" {
			return time.Time{}, ErrInvalid
		}
		latestAdmission = laterTime(latestAdmission, raw.AvailableAt)
		t, err := g.eligibility(ref)
		if err != nil {
			return time.Time{}, err
		}
		at = laterTime(at, t)
	}
	switch s := b.(type) {
	case *Sample:
		at = laterTime(at, s.SourceAt)
	case *Coverage:
		at = laterTime(at, s.Through)
	case *Qualified:
		at = laterTime(at, s.QualifiedAt)
		for _, v := range s.Snapshot {
			at = laterTime(at, v.SourceAt)
		}
	case *Feature:
		if !f.AvailableAt.Equal(latestAdmission) {
			return time.Time{}, ErrInvalid
		}
		at = laterTime(at, s.SourceAt)
	case *Conflict:
		a := g.bodies[s.Values[0]].(*Sample)
		b := g.bodies[s.Values[1]].(*Sample)
		if a.Metric != s.Metric || b.Metric != s.Metric || a.Unit != b.Unit || !a.SourceAt.Equal(s.SourceAt) || !b.SourceAt.Equal(s.SourceAt) || a.Value == b.Value || !f.AvailableAt.Equal(latestAdmission) {
			return time.Time{}, ErrInvalid
		}
	}
	g.times[id] = at
	return at, nil
}

func laterTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// ValidateFact verifies canonical content and the legal same-scope raw support
// closure. Use ValidateTrackerContext as well for a tracker-to-bundle edge.
func ValidateFact(category string, f Fact, facts map[string]Fact) error {
	_, err := validateFact(context.Background(), category, f, facts)
	return err
}

func validateFact(ctx context.Context, category string, f Fact, facts map[string]Fact) (time.Time, error) {
	g := newFactGraph(category, facts)
	g.samples = checkedSamples(ctx)
	return g.checkFact(f)
}

func (g *factGraph) checkFact(f Fact) (time.Time, error) {
	stored, ok := g.index[f.ID]
	if !ok || stored.Run != f.Run || stored.Asset != f.Asset || stored.Kind != f.Kind || !stored.AvailableAt.Equal(f.AvailableAt) || !bytes.Equal(stored.Body, f.Body) {
		return time.Time{}, ErrInvalid
	}
	return g.eligibility(f.ID)
}

func validBundleEnvelope(b Bundle) bool {
	return ValidHash(b.ID) && ValidID(b.Run, 128) && validAsset(b.Asset) && durableTime(b.LogicalAt) && durableTime(b.AvailabilityCutoff) && !b.AvailabilityCutoff.After(b.LogicalAt) &&
		b.LookbackSeconds >= 0 && b.LookbackSeconds <= 900 && len(b.Facts) <= MaxFacts && len(b.Features) <= MaxFacts && len(b.Facts)+len(b.Features) <= MaxFacts &&
		hashSet(b.Facts, MaxFacts) == nil && hashSet(b.Features, MaxFacts) == nil
}

func (g *factGraph) checkBundle(b Bundle) error {
	if !validBundleEnvelope(b) {
		return ErrInvalid
	}
	encoded, err := encodeBundleIdentity(b)
	// The manifest adds only the validated hexadecimal ID and its JSON key.
	if err != nil || len(encoded)+len(`,"id":""`)+len(b.ID) > maxBundleBytes || Hash("bundle", g.category, 1, encoded) != b.ID {
		return ErrInvalid
	}
	for _, refs := range []struct {
		ids      []string
		features bool
	}{{b.Facts, false}, {b.Features, true}} {
		for _, id := range refs.ids {
			f, ok := g.index[id]
			if !ok || f.Run != b.Run || f.Asset != b.Asset || f.AvailableAt.After(b.AvailabilityCutoff) || (f.Kind == "FEATURE") != refs.features {
				return ErrInvalid
			}
			if _, err := g.eligibility(id); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateBundle verifies the manifest and the complete raw fact closure.
func ValidateBundle(category string, b Bundle, facts map[string]Fact) error {
	return newFactGraph(category, facts).checkBundle(b)
}

// ValidateTrackerContext verifies the edge to a validated tracker evaluation
// bundle. Each context must have been created from eligible positive evidence.
// References to older, already validated contexts decrease in revision, so each
// prior context's availability also bounds its own closure's eligibility.
func ValidateTrackerContext(category string, f Fact, b Bundle, facts map[string]Fact) error {
	return validateTrackerContext(context.Background(), category, f, b, facts)
}

func validateTrackerContext(ctx context.Context, category string, f Fact, b Bundle, facts map[string]Fact) error {
	g := newFactGraph(category, facts)
	g.samples = checkedSamples(ctx)
	if err := g.checkBundle(b); err != nil {
		return err
	}
	if _, err := g.checkFact(f); err != nil {
		return err
	}
	tracker, ok := g.bodies[f.ID].(*TrackerContext)
	if !ok || tracker.BundleID != b.ID || f.Run != b.Run || f.Asset != b.Asset || !f.AvailableAt.Equal(b.LogicalAt) {
		return ErrInvalid
	}
	for _, id := range b.Facts {
		if older, ok := g.bodies[id].(*TrackerContext); ok && older.Revision >= tracker.Revision {
			return ErrInvalid
		}
		if !negativeFact(g.index[id]) && g.times[id].After(f.AvailableAt) {
			return ErrInvalid
		}
	}
	for _, id := range b.Features {
		if g.times[id].After(f.AvailableAt) {
			return ErrInvalid
		}
	}
	return nil
}

// A known negative fact applies at admission even when its source interval or
// conflicting sample keys extend into the future.
func negativeFact(f Fact) bool { return f.Kind == "CONFLICT" || f.Kind == "COVERAGE" }

// Eligibility uses already admitted facts. In particular, it does not postpone
// the application of conflicts/coverage failures before their source times.
// Tracker bundle edges are validated by the host/store before category use.
func Eligibility(f Fact, index map[string]Fact) (time.Time, error) {
	return eligibility(f, index, "", nil)
}

func eligibility(f Fact, index map[string]Fact, category string, samples *factBodyCache) (time.Time, error) {
	at := f.AvailableAt
	var refs []string
	switch f.Kind {
	case "SAMPLE":
		b, err := samples.decodeForSelection(category, f)
		if err != nil {
			return at, err
		}
		at = laterTime(at, b.SourceAt)
	case "COVERAGE":
		var b Coverage
		if err := json.Unmarshal(f.Body, &b); err != nil {
			return at, err
		}
		at = laterTime(at, b.Through)
	case "QUALIFIED":
		var b Qualified
		if err := json.Unmarshal(f.Body, &b); err != nil {
			return at, err
		}
		at = laterTime(at, b.QualifiedAt)
		for _, s := range b.Snapshot {
			at = laterTime(at, s.SourceAt)
		}
	case "FEATURE":
		var b Feature
		if err := json.Unmarshal(f.Body, &b); err != nil {
			return at, err
		}
		at = laterTime(at, b.SourceAt)
		refs = b.Support
	case "PROVENANCE":
		var b ProvenanceFact
		if err := json.Unmarshal(f.Body, &b); err != nil {
			return at, err
		}
		refs = []string{b.SampleID}
	case "CONFLICT":
		var b Conflict
		if err := json.Unmarshal(f.Body, &b); err != nil {
			return at, err
		}
		refs = b.Values
	case "TRACKER_CONTEXT":
	default:
		return at, ErrInvalid
	}
	for _, id := range refs {
		raw, ok := index[id]
		if !ok || raw.Run != f.Run || raw.Asset != f.Asset || f.Kind == "FEATURE" && !isRawSupport(raw) || f.Kind != "FEATURE" && raw.Kind != "SAMPLE" {
			return at, ErrInvalid
		}
		t, err := eligibility(raw, index, category, samples)
		if err != nil {
			return at, err
		}
		at = laterTime(at, t)
	}
	return at, nil
}

func indexFacts(facts []Fact) map[string]Fact {
	ids := make(map[string]Fact, len(facts))
	for _, f := range facts {
		ids[f.ID] = f
	}
	return ids
}

func EventTimes(r Request) ([]time.Time, error) {
	return eventTimes(r, nil)
}

func eventTimes(r Request, timesByID map[string]time.Time) ([]time.Time, error) {
	var ids map[string]Fact
	times := []time.Time{r.DiscoveryFloor, r.LogicalAt}
	for _, f := range r.Facts {
		if f.Kind == "FEATURE" || f.Kind == "TRACKER_CONTEXT" {
			continue
		}
		e, checked := timesByID[f.ID]
		if !checked {
			if ids == nil {
				ids = indexFacts(r.Facts)
			}
			var err error
			e, err = Eligibility(f, ids)
			if err != nil {
				return nil, err
			}
		}
		for _, t := range []time.Time{f.AvailableAt, e} {
			if !t.Before(r.DiscoveryFloor) && !t.After(r.LogicalAt) {
				times = append(times, t)
			}
		}
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	return slices.CompactFunc(times, time.Time.Equal), nil
}

// At reconstructs the admitted view at a historical logical event. Future
// source values remain visible as retained, unusable values.
func At(r Request, at time.Time) Request {
	return cutoffView(r, at, func(Fact) bool { return true })
}

func cutoffView(r Request, at time.Time, keep func(Fact) bool) Request {
	r.LogicalAt = normalizeTime(at)
	r.AvailabilityCutoff = normalizeTime(at)
	facts := make([]Fact, 0, len(r.Facts))
	for _, f := range r.Facts {
		if !f.AvailableAt.After(at) && keep(f) {
			facts = append(facts, f)
		}
	}
	r.Facts = facts
	r.Bundle, _ = NewBundle(r.Category, r.Run, r.Asset, at, facts)
	return r
}

// EntryView freezes the complete entry/zero-arm view. Known conflicts and
// coverage gaps are retained at admission, including their raw dependencies.
func EntryView(r Request, at time.Time) (Request, error) {
	return entryView(context.Background(), r, at)
}

func entryView(ctx context.Context, r Request, at time.Time) (Request, error) {
	at = normalizeTime(at)
	if at.After(r.AvailabilityCutoff) {
		return Request{}, ErrInvalid
	}
	ids := indexFacts(r.Facts)
	samples := checkedSamples(ctx)
	eligible := make(map[string]bool, len(ids))
	closure := make(map[string]bool)
	for _, f := range r.Facts {
		if f.AvailableAt.After(at) {
			continue
		}
		if f.Kind == "CONFLICT" {
			var c Conflict
			if err := json.Unmarshal(f.Body, &c); err != nil {
				return Request{}, err
			}
			for _, id := range c.Values {
				closure[id] = true
			}
		}
		e, err := eligibility(f, ids, r.Category, samples)
		if err != nil {
			return Request{}, err
		}
		if !e.After(at) || negativeFact(f) {
			eligible[f.ID] = true
		}
	}
	view := r
	view.LogicalAt, view.AvailabilityCutoff = at, at
	view.Facts = make([]Fact, 0, len(r.Facts))
	for _, f := range r.Facts {
		if eligible[f.ID] || closure[f.ID] && !f.AvailableAt.After(at) {
			view.Facts = append(view.Facts, f)
		}
	}
	// Preserve the distinction between the manifest and its frozen closure.
	// A future sample retained for a conflict stays only in the closure.
	view.Bundle.LogicalAt, view.Bundle.AvailabilityCutoff = at, at
	view.Bundle.Facts = slices.DeleteFunc(slices.Clone(r.Bundle.Facts), func(id string) bool { return !eligible[id] })
	view.Bundle.Features = slices.DeleteFunc(slices.Clone(r.Bundle.Features), func(id string) bool { return !eligible[id] })
	var err error
	view.Bundle.ID, err = BundleID(r.Category, view.Bundle)
	return view, err
}

// validatePayload reuses only the host's structural, canonical-body and hash
// checks. Descriptor bounds and exact metadata are checked on every call, and
// the category still performs its own policy and result validation.
func (c *factBodyCache) validatePayload(p Payload, category, kind string, schema, limit int64) error {
	if int64(len(p.Body)) > limit || p.Category != category || p.Kind != kind || p.Schema != schema {
		return ErrInvalid
	}
	if c == nil {
		return ValidatePayload(p, category, kind, schema)
	}
	c.mu.Lock()
	prev, ok := c.payloads[kind]
	c.mu.Unlock()
	if ok && prev.Category == category && prev.Schema == schema && prev.Hash == p.Hash && bytes.Equal(prev.Body, p.Body) {
		return nil
	}
	if err := ValidatePayload(p, category, kind, schema); err != nil {
		return err
	}
	c.mu.Lock()
	if c.payloads == nil {
		c.payloads = make(map[string]Payload)
	}
	c.payloads[kind] = copyPayload(p)
	c.mu.Unlock()
	return nil
}

func stateDeclaration(r Request, d Descriptor) (kind string, version, limit int64) {
	if r.Scope == "TRACKER" {
		return "tracker", d.TrackerSchema, d.PayloadLimits.Tracker
	}
	return "candidate", d.CandidateSchema, d.PayloadLimits.Candidate
}

func validateArm(r Request, g *factGraph) error {
	if r.Entry == nil || r.BudgetMS == nil || !slices.Contains(v1Budgets[:], *r.BudgetMS) || r.Sequence < 1 || r.State == nil {
		return ErrInvalid
	}
	id, err := Identity("candidate", r.Category, map[string]any{"run": r.Run, "category": r.Category, "asset": r.Asset, "sequence": r.Sequence, "budget_ms": *r.BudgetMS})
	if err != nil || id != r.CandidateID {
		return ErrInvalid
	}
	terminalID, err := Identity("terminal", r.Category, map[string]any{"candidate": id})
	if err != nil {
		return err
	}
	e := r.Entry
	f := e.Fallback
	if (e.Basis != "CATEGORY_CONCERN" && e.Basis != "INDEPENDENT_URGENT") || !durableTime(e.AvailableAt) || e.AvailableAt.After(r.AvailabilityCutoff) ||
		!ValidHash(e.BundleID) || len(e.Support) == 0 || hashSet(e.Support, 32) != nil || f.Schema != 1 ||
		!durableTime(f.DueAt) || !f.DueAt.Equal(e.AvailableAt.Add(time.Duration(*r.BudgetMS)*time.Millisecond)) || f.Action != "INVESTIGATE" ||
		f.Route != "hardware_investigation" || !boundedSummary(f.Summary) || f.TerminalID != terminalID {
		return ErrInvalid
	}
	for _, id := range e.Support {
		t, err := g.eligibility(id)
		if err != nil || t.After(e.AvailableAt) {
			return ErrInvalid
		}
	}
	if e.Basis == "INDEPENDENT_URGENT" && !hasUrgentEvidence(e.Support, g) {
		return ErrInvalid
	}
	switch r.Purpose {
	case "ASSESS":
		if r.Terminal != nil || r.LogicalAt.After(f.DueAt) {
			return ErrInvalid
		}
	case "FOLLOW_UP":
		t := r.Terminal
		if t == nil || t.DecisionID != terminalID || !durableTime(t.LogicalAt) || t.LogicalAt.Before(e.AvailableAt) || t.LogicalAt.After(f.DueAt) || !t.LogicalAt.Before(r.LogicalAt) ||
			(t.Action != "NONE" && t.Action != "INVESTIGATE" && t.Action != "URGENT") || !validOccurrences(t.UrgentOccurrences) || t.Action != "URGENT" && len(t.UrgentOccurrences) > 0 {
			return ErrInvalid
		}
		if t.Endpoint != nil && !validEndpoint(t.Endpoint, t.LogicalAt, g) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func validOccurrences(xs []Occurrence) bool {
	if xs == nil || len(xs) > 8 {
		return false
	}
	for i, x := range xs {
		if !ValidID(x.PolicyID, 128) || x.Occurrence <= 0 {
			return false
		}
		if i > 0 && (xs[i-1].PolicyID > x.PolicyID || xs[i-1].PolicyID == x.PolicyID && xs[i-1].Occurrence >= x.Occurrence) {
			return false
		}
	}
	return true
}

func validEndpoint(ref *FeatureRef, at time.Time, g *factGraph) bool {
	t, err := g.eligibility(ref.ID)
	if err != nil || t.After(at) {
		return false
	}
	f, ok := g.bodies[ref.ID].(*Feature)
	return ok && f.FeatureKind == "temperature_endpoint" && f.Unit == "celsius" && ref.Value == f.Value && durableTime(ref.SourceAt) && durableTime(ref.AvailableAt) &&
		ref.SourceAt.Equal(f.SourceAt) && ref.AvailableAt.Equal(g.index[ref.ID].AvailableAt)
}

func hasUrgentEvidence(ids []string, g *factGraph) bool {
	for _, id := range ids {
		switch b := g.bodies[id].(type) {
		case *Qualified:
			if b.Transition == "OPEN" && b.Severity == "CRITICAL" && (b.Rule == "gpu_thermal" || b.Rule == "hbm_thermal") {
				return true
			}
		case *Feature:
			if hasUrgentEvidence(b.Support, g) {
				return true
			}
		}
	}
	return false
}

func matchSharedContext(r Request, d Descriptor, g *factGraph) bool {
	s := r.SharedContext
	if s == nil {
		return true
	}
	if r.Scope != "ARM" || !durableTime(s.AvailableAt) || s.AvailableAt.After(r.AvailabilityCutoff) || s.Revision <= 0 {
		return false
	}
	for id, body := range g.bodies {
		if v, ok := body.(*TrackerContext); ok && v.Category == d.Category && v.Revision == s.Revision && v.BundleID == s.BundleID &&
			g.index[id].AvailableAt.Equal(s.AvailableAt) && v.Payload.Hash == s.Payload.Hash && bytes.Equal(v.Payload.Body, s.Payload.Body) {
			return true
		}
	}
	return false
}

func boundedRequestMetadata(r Request, d Descriptor, samples *factBodyCache) bool {
	if !validBundleEnvelope(r.Bundle) || r.Bundle.Run != r.Run || r.Bundle.Asset != r.Asset || !r.Bundle.LogicalAt.Equal(r.LogicalAt) || !r.Bundle.AvailabilityCutoff.Equal(r.AvailabilityCutoff) {
		return false
	}
	if r.Scope == "ARM" && (!ValidHash(r.CandidateID) || r.Purpose != "ASSESS" && r.Purpose != "FOLLOW_UP") {
		return false
	}
	if e := r.Entry; e != nil {
		f := e.Fallback
		if !ValidID(e.Basis, 128) || !ValidHash(e.BundleID) || hashSet(e.Support, 32) != nil || !ValidID(f.Action, 128) ||
			!ValidID(f.Route, 128) || !boundedSummary(f.Summary) || !ValidHash(f.TerminalID) {
			return false
		}
	}
	if t := r.Terminal; t != nil {
		if !ValidHash(t.DecisionID) || !ValidID(t.Action, 128) || !validOccurrences(t.UrgentOccurrences) || t.Endpoint != nil && !ValidHash(t.Endpoint.ID) {
			return false
		}
	}
	if s := r.SharedContext; s != nil {
		if !ValidHash(s.BundleID) || samples.validatePayload(s.Payload, d.Category, "tracker", d.TrackerSchema, d.PayloadLimits.Tracker) != nil {
			return false
		}
	}
	return true
}

// boundedRequestBytes measures a bounded envelope and each fact separately.
// Large aggregate inputs cannot force allocation of their serialized form.
// A valid fact body is compact canonical JSON, embedded verbatim by Marshal.
func boundedRequestBytes(r Request) bool {
	facts := r.Facts
	r.Facts = []Fact{}
	base, err := json.Marshal(r)
	if err != nil || len(base) > MaxInputBytes {
		return false
	}
	if len(facts) == 0 {
		return true
	}
	envelope, err := json.Marshal(Fact{Run: r.Run, Asset: r.Asset, Body: json.RawMessage(`{}`)})
	if err != nil {
		return false
	}
	// The shared run and asset are already escaped. Subtract the template's
	// timestamp and raw body, then count each fact's variable fields below.
	fixedBytes := len(envelope) - len(`0001-01-01T00:00:00Z`) - len(`{}`)
	size := len(base) + len(facts) - 1 // commas between facts
	var stamp [32]byte
	for _, f := range facts {
		limit := maxFactBytes
		switch f.Kind {
		case "SAMPLE", "COVERAGE", "QUALIFIED", "CONFLICT", "PROVENANCE":
		case "TRACKER_CONTEXT":
			limit = maxTrackerContextBytes
		case "FEATURE":
			limit = maxFeatureBytes
		default:
			return false
		}
		bodyBytes := len(f.Body)
		if bodyBytes > limit || !ValidHash(f.ID) || f.Run != r.Run || f.Asset != r.Asset || !durableTime(f.AvailableAt) || f.AvailableAt.After(r.AvailabilityCutoff) {
			return false
		}
		// The validated ID and kind contain only unescaped ASCII, and the
		// timestamp is durable UTC. Canonical raw bodies embed verbatim.
		factBytes := fixedBytes + len(f.ID) + len(f.Kind) + len(f.AvailableAt.AppendFormat(stamp[:0], time.RFC3339Nano)) + bodyBytes
		if factBytes > limit || factBytes > MaxInputBytes-size {
			return false
		}
		size += factBytes
	}
	return true
}

func validateRequest(r Request, d Descriptor, hash string, samples *factBodyCache) (*factGraph, error) {
	if r.Contract != d.Contract || r.Implementation != d.Implementation || r.Category != d.Category || r.DescriptorHash != hash || !ValidHash(hash) || !ValidHash(r.ConfigHash) ||
		!ValidID(r.Run, 128) || !validAsset(r.Asset) || !durableTime(r.LogicalAt) || !durableTime(r.AvailabilityCutoff) || !durableTime(r.ExecutedAt) ||
		!durableTime(r.DiscoveryFloor) || r.AvailabilityCutoff.After(r.LogicalAt) || r.ExecutedAt.Before(r.LogicalAt) || r.ExpectedRevision < 1 || r.Sequence < 0 ||
		r.Facts == nil || len(r.Facts) > MaxFacts {
		return nil, ErrInvalid
	}
	if r.Scope != "TRACKER" && r.Scope != "ARM" {
		return nil, ErrInvalid
	}
	if r.Scope == "TRACKER" {
		if r.CandidateID != "" || r.BudgetMS != nil || r.Entry != nil || r.Terminal != nil || r.SharedContext != nil ||
			(r.Purpose != "DISCOVER" && r.Purpose != "FOLLOW_UP") || (r.Purpose == "FOLLOW_UP" && r.Sequence == 0) ||
			(r.Purpose == "DISCOVER" && r.DiscoveryFloor.After(r.LogicalAt)) || (r.State == nil && (r.Purpose != "DISCOVER" || r.Sequence != 0)) {
			return nil, ErrInvalid
		}
	}
	if samples.validatePayload(r.Policy, d.Category, "policy", d.PolicySchema, d.PayloadLimits.Policy) != nil {
		return nil, ErrInvalid
	}
	if r.State != nil {
		kind, version, limit := stateDeclaration(r, d)
		if samples.validatePayload(*r.State, d.Category, kind, version, limit) != nil {
			return nil, ErrInvalid
		}
	}
	if !boundedRequestMetadata(r, d, samples) || !boundedRequestBytes(r) {
		return nil, ErrInvalid
	}
	idx := make(map[string]Fact, len(r.Facts))
	for _, f := range r.Facts {
		if _, ok := idx[f.ID]; ok {
			return nil, ErrInvalid
		}
		idx[f.ID] = f
	}
	g := newFactGraph(r.Category, idx)
	g.samples = samples
	if err := g.checkBundle(r.Bundle); err != nil {
		return nil, err
	}
	points := 0
	metrics := make(map[string]int, len(d.Metrics))
	for _, f := range r.Facts {
		if _, err := g.eligibility(f.ID); err != nil {
			return nil, err
		}
		if sample, ok := g.bodies[f.ID].(*Sample); ok {
			points++
			metrics[sample.Metric]++
			if points > maxPoints || metrics[sample.Metric] > maxPointsPerMetric {
				return nil, ErrInvalid
			}
			if !slices.ContainsFunc(d.Metrics, func(m Metric) bool { return m.Metric == sample.Metric && m.Unit == sample.Unit }) {
				return nil, ErrInvalid
			}
		}
	}
	if r.Scope == "ARM" {
		if err := validateArm(r, g); err != nil {
			return nil, err
		}
	}
	if !matchSharedContext(r, d, g) {
		return nil, ErrInvalid
	}
	return g, nil
}

func ValidateRequest(r Request, d Descriptor, hash string) error {
	_, err := validateRequest(r, d, hash, nil)
	return err
}

func copyPayload(p Payload) Payload { p.Body = slices.Clone(p.Body); return p }
func copyPointer[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func copyRequest(r Request) Request {
	r.Policy = copyPayload(r.Policy)
	r.Facts = slices.Clone(r.Facts)
	for i := range r.Facts {
		r.Facts[i].Body = slices.Clone(r.Facts[i].Body)
	}
	r.Bundle.Facts, r.Bundle.Features = slices.Clone(r.Bundle.Facts), slices.Clone(r.Bundle.Features)
	r.BudgetMS = copyPointer(r.BudgetMS)
	if r.State != nil {
		state := copyPayload(*r.State)
		r.State = &state
	}
	if r.SharedContext != nil {
		r.SharedContext = copyPointer(r.SharedContext)
		r.SharedContext.Payload = copyPayload(r.SharedContext.Payload)
	}
	if r.Entry != nil {
		r.Entry = copyPointer(r.Entry)
		r.Entry.Support = slices.Clone(r.Entry.Support)
	}
	if r.Terminal != nil {
		r.Terminal = copyPointer(r.Terminal)
		r.Terminal.Endpoint = copyPointer(r.Terminal.Endpoint)
		r.Terminal.UrgentOccurrences = slices.Clone(r.Terminal.UrgentOccurrences)
	}
	return r
}

func copyResult(x Result) Result {
	if x.State != nil {
		p := copyPayload(*x.State)
		x.State = &p
	}
	if x.InitialCandidateState != nil {
		p := copyPayload(*x.InitialCandidateState)
		x.InitialCandidateState = &p
	}
	if x.Details != nil {
		p := copyPayload(*x.Details)
		x.Details = &p
	}
	x.UpdateCodes, x.Reasons, x.Support = slices.Clone(x.UpdateCodes), slices.Clone(x.Reasons), slices.Clone(x.Support)
	x.NextLogicalAt, x.EntryQualifiedAt = copyPointer(x.NextLogicalAt), copyPointer(x.EntryQualifiedAt)
	x.ProposedFeatures = slices.Clone(x.ProposedFeatures)
	for i := range x.ProposedFeatures {
		x.ProposedFeatures[i].Support = slices.Clone(x.ProposedFeatures[i].Support)
	}
	return x
}

func unsupportedPayloads(req Request, d Descriptor) bool {
	_, version, _ := stateDeclaration(req, d)
	return req.Policy.Schema != d.PolicySchema || req.State != nil && req.State.Schema != version ||
		req.SharedContext != nil && req.SharedContext.Payload.Schema != d.TrackerSchema
}

// Invoke shares the caller's cooperative GPU-pass budget. No returned state or
// feature survives an invalid invocation or a call finishing after the budget.
func (r *Registry) Invoke(ctx context.Context, req Request) (result Result, materialized Request, err error) {
	defer func() {
		if recover() != nil {
			result, materialized, err = Result{}, Request{}, fmt.Errorf("PANIC")
		}
		if ctx.Err() != nil {
			result, materialized, err = Result{}, Request{}, fmt.Errorf("TIME_BUDGET")
		}
	}()
	if ctx.Err() != nil {
		return Result{}, Request{}, fmt.Errorf("TIME_BUDGET")
	}
	if !ValidID(req.Category, 128) {
		return Result{}, Request{}, fmt.Errorf("INVALID_INPUT: %w", ErrInvalid)
	}
	c, d, h, err := r.LookupVersion(req.Category, req.Implementation)
	if err != nil || req.Contract != d.Contract || req.Implementation != d.Implementation || req.DescriptorHash != h || unsupportedPayloads(req, d) {
		return Result{}, Request{}, fmt.Errorf("UNSUPPORTED_VERSION")
	}
	samples := checkedSamples(ctx)
	if samples == nil {
		ctx = withFactValidationCache(ctx)
		samples = checkedSamples(ctx)
	}
	g, err := validateRequest(req, d, h, samples)
	if err != nil {
		return Result{}, Request{}, fmt.Errorf("INVALID_INPUT: %w", ErrInvalid)
	}
	if ctx.Err() != nil {
		return Result{}, Request{}, fmt.Errorf("TIME_BUDGET")
	}
	if err := c.ValidatePolicy(ctx, copyPayload(req.Policy)); err != nil {
		return Result{}, Request{}, fmt.Errorf("INVALID_INPUT: %w", ErrInvalid)
	}
	if ctx.Err() != nil {
		return Result{}, Request{}, fmt.Errorf("TIME_BUDGET")
	}
	x, err := c.Evaluate(ctx, copyRequest(req))
	if err != nil {
		return Result{}, Request{}, fmt.Errorf("MALFORMED_RESULT: %w", ErrInvalid)
	}
	if ctx.Err() != nil {
		return Result{}, Request{}, fmt.Errorf("TIME_BUDGET")
	}
	if err := validateResultSize(req, x, d, samples); err != nil {
		return Result{}, Request{}, fmt.Errorf("MALFORMED_RESULT: %w", ErrInvalid)
	}
	x = copyResult(x)
	m, err := materialize(copyRequest(req), x, g)
	if err != nil {
		return Result{}, Request{}, fmt.Errorf("MALFORMED_RESULT: %w", ErrInvalid)
	}
	if err := validateResult(m, x, d, g); err != nil {
		return Result{}, Request{}, fmt.Errorf("MALFORMED_RESULT: %w", ErrInvalid)
	}
	if ctx.Err() != nil {
		return Result{}, Request{}, fmt.Errorf("TIME_BUDGET")
	}
	if err := c.ValidateResult(ctx, copyRequest(m), copyResult(x)); err != nil {
		return Result{}, Request{}, fmt.Errorf("MALFORMED_RESULT: %w", ErrInvalid)
	}
	return x, m, nil
}

func materialize(r Request, result Result, g *factGraph) (Request, error) {
	cutoff := r.LogicalAt
	if result.EntryQualifiedAt != nil {
		cutoff = *result.EntryQualifiedAt
	}
	seen := make(map[string]bool, len(result.ProposedFeatures))
	for _, p := range result.ProposedFeatures {
		if !validFeature(p) || p.SourceAt.After(cutoff) {
			return Request{}, ErrInvalid
		}
		at := time.Time{}
		for _, id := range p.Support {
			f, ok := g.index[id]
			if !ok || !isRawSupport(f) {
				return Request{}, ErrInvalid
			}
			e, err := g.eligibility(id)
			if err != nil || e.After(cutoff) {
				return Request{}, ErrInvalid
			}
			at = laterTime(at, f.AvailableAt)
		}
		f, err := NewFact(r.Category, r.Run, r.Asset, "FEATURE", at, p)
		if err != nil || seen[f.ID] {
			return Request{}, ErrInvalid
		}
		seen[f.ID] = true
		if _, ok := g.index[f.ID]; !ok {
			r.Facts = append(r.Facts, f)
			g.index[f.ID] = f
			body := p
			g.bodies[f.ID] = &body
		}
		r.Bundle.Features = append(r.Bundle.Features, f.ID)
	}
	if len(r.Facts) > MaxFacts {
		return Request{}, ErrInvalid
	}
	if len(result.ProposedFeatures) == 0 {
		return r, nil
	}
	r.Bundle.Features = SortedUnique(r.Bundle.Features)
	var err error
	r.Bundle.ID, err = BundleID(r.Category, r.Bundle)
	if err != nil || g.checkBundle(r.Bundle) != nil {
		return Request{}, ErrInvalid
	}
	if !boundedRequestBytes(r) {
		return Request{}, ErrInvalid
	}
	return r, nil
}

func validateResultSize(r Request, x Result, d Descriptor, samples *factBodyCache) error {
	if Set(x.UpdateCodes, 8) != nil || Set(x.Reasons, 8) != nil || hashSet(x.Support, 32) != nil || !boundedSummary(x.Summary) ||
		x.ProposedFeatures == nil || len(x.ProposedFeatures) > 8 ||
		(x.Kind != "ASSESSMENT" && x.Kind != "UPDATE" && x.Kind != "REARM" && x.Kind != "UNCHANGED") ||
		len(x.Phase) > 128 || len(x.Action) > 128 || len(x.Outcome) > 128 || x.TerminalEndpointID != "" && !ValidHash(x.TerminalEndpointID) {
		return ErrInvalid
	}
	for _, feature := range x.ProposedFeatures {
		if !validFeature(feature) {
			return ErrInvalid
		}
	}
	if x.State != nil {
		kind, version, limit := stateDeclaration(r, d)
		if samples.validatePayload(*x.State, d.Category, kind, version, limit) != nil {
			return ErrInvalid
		}
	}
	if x.InitialCandidateState != nil && samples.validatePayload(*x.InitialCandidateState, d.Category, "candidate", d.CandidateSchema, d.PayloadLimits.Candidate) != nil {
		return ErrInvalid
	}
	if x.Details != nil && samples.validatePayload(*x.Details, d.Category, "details", d.DetailsSchema, d.PayloadLimits.Details) != nil {
		return ErrInvalid
	}
	b, err := Canonical(x.ProposedFeatures)
	if err != nil || len(b) > MaxProposalBytes {
		return ErrInvalid
	}
	meta := x
	meta.State, meta.InitialCandidateState = nil, nil
	meta.ProposedFeatures = []Feature{}
	b, err = Canonical(meta)
	if err != nil || len(b) > maxResultMetadata {
		return ErrInvalid
	}
	return nil
}

func ValidateResult(r Request, x Result, d Descriptor) error {
	if err := validateResultSize(r, x, d, nil); err != nil {
		return err
	}
	return validateResult(r, x, d, newFactGraph(r.Category, indexFacts(r.Facts)))
}

func validateResult(r Request, x Result, d Descriptor, g *factGraph) error {
	for _, v := range x.Reasons {
		if !slices.Contains(d.Reasons, v) {
			return ErrInvalid
		}
	}
	entry := r.Purpose == "DISCOVER" && x.Kind == "ASSESSMENT" && x.Phase != "NO_CANDIDATE"
	if entry {
		if x.State == nil || x.InitialCandidateState == nil || x.EntryQualifiedAt == nil || len(x.Support) == 0 ||
			!durableTime(*x.EntryQualifiedAt) || x.EntryQualifiedAt.After(r.AvailabilityCutoff) {
			return ErrInvalid
		}
		events, err := eventTimes(r, g.times)
		if err != nil || !slices.ContainsFunc(events, x.EntryQualifiedAt.Equal) {
			return ErrInvalid
		}
	} else if x.InitialCandidateState != nil || x.EntryQualifiedAt != nil {
		return ErrInvalid
	}

	switch x.Kind {
	case "ASSESSMENT":
		if len(x.UpdateCodes) > 0 || (r.Purpose != "DISCOVER" && r.Purpose != "ASSESS") ||
			!slices.ContainsFunc(d.Outcomes, func(o Outcome) bool {
				return o.Code == x.Outcome && o.Purpose == r.Purpose && o.Phase == x.Phase && o.Action == x.Action
			}) {
			return ErrInvalid
		}
		if r.Purpose == "ASSESS" && x.Phase == "NO_CANDIDATE" || r.Purpose == "DISCOVER" && x.Phase == "FINAL" && x.Action != "URGENT" {
			return ErrInvalid
		}
	case "UPDATE":
		if r.Scope != "ARM" || r.Purpose != "FOLLOW_UP" || r.Terminal == nil || x.Outcome != "" || x.Phase != "" || len(x.UpdateCodes) == 0 {
			return ErrInvalid
		}
		action := "INVESTIGATE"
		for _, code := range x.UpdateCodes {
			i := slices.IndexFunc(d.Updates, func(u Update) bool { return u.Code == code })
			if i < 0 {
				return ErrInvalid
			}
			if d.Updates[i].Action == "URGENT" {
				action = "URGENT"
			}
		}
		if action != x.Action {
			return ErrInvalid
		}
	case "REARM":
		if r.Scope != "TRACKER" || r.Purpose != "FOLLOW_UP" || len(x.Support) == 0 {
			return ErrInvalid
		}
		fallthrough
	case "UNCHANGED":
		if x.Outcome != "" || x.Phase != "" || x.Action != "" || len(x.UpdateCodes) > 0 || r.Purpose == "DISCOVER" {
			return ErrInvalid
		}
	}
	if r.Scope == "ARM" && r.Terminal != nil && x.State != nil {
		return ErrInvalid
	}
	if r.Scope == "ARM" && r.Purpose == "ASSESS" && r.Entry != nil && !r.LogicalAt.Before(r.Entry.Fallback.DueAt) && x.Phase != "FINAL" {
		return ErrInvalid
	}
	if x.NextLogicalAt != nil && (!durableTime(*x.NextLogicalAt) || !x.NextLogicalAt.After(r.LogicalAt) ||
		r.Purpose == "ASSESS" && r.Entry != nil && x.NextLogicalAt.After(r.Entry.Fallback.DueAt)) {
		return ErrInvalid
	}
	if x.TerminalEndpointID != "" && (x.Kind != "ASSESSMENT" || x.Phase != "FINAL" || !slices.Contains(x.Support, x.TerminalEndpointID)) {
		return ErrInvalid
	}
	cutoff := r.LogicalAt
	if entry {
		cutoff = *x.EntryQualifiedAt
	}
	for _, id := range x.Support {
		if !slices.Contains(r.Bundle.Facts, id) && !slices.Contains(r.Bundle.Features, id) {
			return ErrInvalid
		}
		at, err := g.eligibility(id)
		if err != nil || at.After(cutoff) {
			return ErrInvalid
		}
		if id == x.TerminalEndpointID {
			p, ok := g.bodies[id].(*Feature)
			if !ok || p.FeatureKind != "temperature_endpoint" || p.Unit != "celsius" || !slices.Contains(r.Bundle.Features, id) {
				return ErrInvalid
			}
		}
	}
	if entry && x.Phase == "FINAL" && !hasUrgentEvidence(x.Support, g) {
		return ErrInvalid
	}
	return nil
}

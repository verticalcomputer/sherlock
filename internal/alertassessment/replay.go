package alertassessment

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Candidate struct {
	ID            string     `json:"id"`
	Asset         string     `json:"asset"`
	Sequence      int64      `json:"sequence"`
	BudgetMS      int64      `json:"budget_ms"`
	Revision      int64      `json:"revision"`
	Phase         string     `json:"phase"`
	EnteredAt     time.Time  `json:"entered_at"`
	DueAt         time.Time  `json:"due_at"`
	Entry         Entry      `json:"entry"`
	InitialState  Payload    `json:"initial_state"`
	State         Payload    `json:"state"`
	Terminal      *Terminal  `json:"terminal,omitempty"`
	NextLogicalAt *time.Time `json:"next_logical_at,omitempty"`
	ReservedCodes []string   `json:"reserved_codes"`
}
type Decision struct {
	ID                string       `json:"id"`
	CandidateID       string       `json:"candidate_id"`
	Asset             string       `json:"asset"`
	Sequence          int64        `json:"sequence"`
	BudgetMS          int64        `json:"budget_ms"`
	Kind              string       `json:"kind"`
	LogicalAt         time.Time    `json:"logical_at"`
	ExecutedAt        time.Time    `json:"executed_at"`
	CommittedAt       time.Time    `json:"committed_at"`
	LatenessUS        int64        `json:"lateness_us"`
	Action            string       `json:"action"`
	DecisionSource    string       `json:"decision_source"`
	Outcome           string       `json:"outcome,omitempty"`
	HostCause         string       `json:"host_cause,omitempty"`
	FailureCode       string       `json:"failure_code,omitempty"`
	BundleID          string       `json:"bundle_id"`
	Codes             []string     `json:"codes"`
	Reasons           []string     `json:"reasons"`
	Support           []string     `json:"support"`
	Summary           string       `json:"summary"`
	Details           *Payload     `json:"details,omitempty"`
	TerminalEndpoint  *FeatureRef  `json:"terminal_endpoint,omitempty"`
	UrgentOccurrences []Occurrence `json:"urgent_occurrences"`
}
type CoverageInterval struct {
	From    time.Time `json:"from"`
	Through time.Time `json:"through"`
	Code    string    `json:"code"`
	Count   int64     `json:"count"`
}

type Failure struct {
	ID             string     `json:"id"`
	Kind           string     `json:"kind"`
	ScopeKey       string     `json:"scope_key"`
	FirstAt        time.Time  `json:"first_at"`
	Count          int64      `json:"count"`
	BundleID       string     `json:"bundle_id,omitempty"`
	FactIDs        []string   `json:"fact_ids"`
	Code           string     `json:"code"`
	Asset          string     `json:"asset"`
	At             time.Time  `json:"at"`
	CandidateID    string     `json:"candidate_id,omitempty"`
	LogicalFrom    *time.Time `json:"logical_from,omitempty"`
	LogicalThrough *time.Time `json:"logical_through,omitempty"`
}
type TelemetryRecord struct {
	ID               string    `json:"id"`
	Asset            string    `json:"asset"`
	PolicyID         string    `json:"policy_id"`
	Occurrence       int64     `json:"occurrence"`
	Disposition      string    `json:"disposition"`
	PhysicalSequence int64     `json:"physical_sequence,omitempty"`
	OpenFact         string    `json:"open_fact"`
	RecoverFact      string    `json:"recover_fact,omitempty"`
	BundleID         string    `json:"bundle_id"`
	Summary          string    `json:"summary"`
	PreviewID        string    `json:"preview_id,omitempty"`
	FirstAt          time.Time `json:"first_at"`
	LastAt           time.Time `json:"last_at"`
	Count            int64     `json:"count"`
}

type Enrollment struct {
	ProcessedAt    time.Time      `json:"-"`
	Asset          string         `json:"asset"`
	Sequence       int64          `json:"sequence"`
	Revision       int64          `json:"revision"`
	DiscoveryFloor time.Time      `json:"discovery_floor"`
	Tracker        *Payload       `json:"tracker,omitempty"`
	SharedContext  *SharedContext `json:"shared_context,omitempty"`
	NextLogicalAt  *time.Time     `json:"next_logical_at,omitempty"`
	Active         bool           `json:"active"`
}
type Fault struct {
	At       time.Time  `json:"at"`
	Asset    string     `json:"asset"`
	Purpose  string     `json:"purpose"`
	BudgetMS *int64     `json:"budget_ms,omitempty"`
	Code     string     `json:"code"`
	Until    *time.Time `json:"until,omitempty"`
}
type Legacy struct {
	Asset     string    `json:"asset"`
	At        time.Time `json:"at"`
	Triggered bool      `json:"triggered"`
}
type Label struct {
	Asset          string     `json:"asset"`
	From           time.Time  `json:"from"`
	Through        time.Time  `json:"through"`
	Classification string     `json:"classification"`
	ActionDue      *time.Time `json:"action_due,omitempty"`
}
type Expected struct {
	Asset          string    `json:"asset"`
	Sequence       int64     `json:"sequence"`
	BudgetMS       int64     `json:"budget_ms"`
	LogicalAt      time.Time `json:"logical_at"`
	Action         string    `json:"action"`
	Outcome        string    `json:"outcome,omitempty"`
	DecisionSource string    `json:"decision_source"`
}
type Suite struct {
	Schema     int64      `json:"schema"`
	Config     Config     `json:"config"`
	StartAt    time.Time  `json:"start_at"`
	Provenance string     `json:"provenance"`
	Facts      []Fact     `json:"facts"`
	Legacy     []Legacy   `json:"legacy"`
	Labels     []Label    `json:"labels"`
	Faults     []Fault    `json:"faults"`
	Expected   []Expected `json:"expected"`
}

type Engine struct {
	Config                            Config
	Registry                          *Registry
	StartAt, AdmissionEndAt, ClosedAt time.Time
	State                             string
	Enrollments                       map[string]*Enrollment
	Facts                             map[string]Fact
	Bundles                           map[string]Bundle
	Candidates                        []*Candidate
	Decisions                         []Decision
	Failures                          []Failure
	FollowupTruncated                 bool
	StopReason                        string
	RecordedBuildHash                 string
	FailureOverflow                   int64
	Telemetry                         map[string]*TelemetryRecord
	// Shadow enables the real aggregate execution limit. Fixture replay injects
	// failures by purpose and budget so its semantic results are machine independent.
	Shadow bool
	// CommitClock samples actual statement time after evaluation when supplied by
	// the live caller. Replay always uses the provided deterministic commit time.
	CommitClock   func() time.Time
	LookupFact    func(context.Context, string) (Fact, bool)
	LookupBundle  func(context.Context, string) (Bundle, bool)
	LookupContext func(ctx context.Context, asset string, cutoff, floor time.Time) (Fact, bool)
	// PrefetchFacts resolves a bounded set into the backing resolver's positive
	// cache and returns confirmed absences. Absences live for one GPU pass only;
	// newly admitted/derived in-memory facts always take precedence.
	PrefetchFacts func(context.Context, []string) ([]string, error)
	passMissing   map[string]bool
	// LookupAdmittedFact only returns already-admitted facts. The archive reader
	// exposes its full index through LookupFact for validation, not admission.
	archiveInput               bool
	proposalBytes              int
	passFeatures               map[string]time.Time
	boundaries                 map[string][]time.Time
	exhausted                  bool
	lastPass                   time.Time
	previewComparisons         map[string]previewChange
	endpointAvailability       map[string]string
	descriptor                 Descriptor
	descriptorHash, configHash string
	policy                     Payload
	UnknownFrom                *time.Time
	UnknownThrough             *time.Time
	archiveEvidence            *json.Encoder
	archiveEvidenceErr         error
	archiveSticky              [8][]archiveQualificationRef
	archiveInputBound          map[string]time.Time
	payloadReady               bool
	factBytes                  int64
	bundleBytes                int64
	CoverageIntervals          []CoverageInterval
	endpointConflictIDs        map[string][][32]byte
	// ObserveGPU records one duration per asset advance that attempts evaluation,
	// historical reconstruction or due fallback, including work before invocation.
	ObserveGPU         func(asset string, elapsed time.Duration)
	attemptedGPUWork   bool
	inlineTxn          *inlineCheckpoint
	trustedEntryProofs map[string]bool
	// ExpiryFailure suppresses source/category work for the specified asset.
	// The empty key applies to the entire existing run.
	ExpiryFailure map[string]string
	recoveryOnly  bool
}

func NewEngine(ctx context.Context, c Config, start time.Time, r *Registry) (*Engine, error) {
	start = clock(start)
	if start.IsZero() {
		return nil, ErrInvalid
	}
	normalized, err := NormalizeConfig(ctx, c, r)
	if err != nil {
		return nil, err
	}
	c = normalized
	_, d, h, _ := r.LookupVersion(c.Category, c.Implementation)
	p, err := c.PolicyPayload(ctx, r)
	if err != nil {
		return nil, err
	}
	ch, err := c.Hash()
	if err != nil {
		return nil, err
	}
	return newEngine(c, start, r, d, h, ch, p), nil
}

// NewRecoveryEngine restores host-only expiry for an already matched durably
// pinned run. It cannot validate the unavailable category policy or run the
// category. Callers must never use it to admit a new run.
func NewRecoveryEngine(ctx context.Context, c Config, start time.Time, d Descriptor, configHash, descriptorHash string) (*Engine, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	start = clock(start)
	if start.IsZero() {
		return nil, ErrInvalid
	}
	c, err := NormalizeRecoveryConfig(c, d)
	if err != nil {
		return nil, err
	}
	ch, err := c.Hash()
	if err != nil || ch != configHash {
		return nil, ErrInvalid
	}
	dh, err := Identity("descriptor", d.Category, d)
	if err != nil || dh != descriptorHash {
		return nil, ErrInvalid
	}
	d, err = Clone(d)
	if err != nil {
		return nil, err
	}
	p, err := NewPayload(c.Category, "policy", d.PolicySchema, c.Policy)
	if err != nil {
		return nil, err
	}
	e := newEngine(c, start, nil, d, dh, ch, p)
	e.recoveryOnly = true
	e.ForceDeadlineFallback("UNSUPPORTED_VERSION")
	return e, nil
}

func newEngine(c Config, start time.Time, r *Registry, d Descriptor, descriptorHash, configHash string, p Payload) *Engine {

	e := &Engine{Config: c, Registry: r, StartAt: start, AdmissionEndAt: start.Add(time.Duration(c.RunDurationSeconds) * time.Second), State: "ACTIVE", Enrollments: map[string]*Enrollment{}, Facts: map[string]Fact{}, Bundles: map[string]Bundle{}, Candidates: []*Candidate{}, Decisions: []Decision{}, Failures: []Failure{}, Telemetry: map[string]*TelemetryRecord{}, descriptor: d, descriptorHash: descriptorHash, configHash: configHash, policy: p, ExpiryFailure: map[string]string{}}
	for _, a := range c.Assets {
		e.Enrollments[a.EntityKey] = &Enrollment{Asset: a.EntityKey, Revision: 1, DiscoveryFloor: start}
	}
	return e
}
func (e *Engine) ForceDeadlineFallback(code string) { e.SuppressAsset("", code) }

func (e *Engine) SuppressAsset(asset, code string) {
	if asset != "" && e.Enrollments[asset] == nil {
		return
	}
	if e.ExpiryFailure == nil {
		e.ExpiryFailure = map[string]string{}
	}
	e.ExpiryFailure[asset] = hostExpiryCause(code)
}

func hostExpiryCause(code string) string {
	switch code {
	case "CAPACITY", "UNSUPPORTED_VERSION", "INVALID_INPUT", "COVERAGE", "STORE_UNAVAILABLE", "AUTHORITY_LOST", "TIME_BUDGET":
		return code
	default:
		return "INVALID_INPUT"
	}
}

func (e *Engine) expiryCause(asset string) string {
	if code := e.ExpiryFailure[""]; code != "" {
		return hostExpiryCause(code)
	}
	if code := e.ExpiryFailure[asset]; code != "" {
		return hostExpiryCause(code)
	}
	if e.recoveryOnly {
		return "UNSUPPORTED_VERSION"
	}
	return ""
}

func clock(at time.Time) time.Time { return at.UTC().Truncate(time.Microsecond) }

func (e *Engine) fact(ctx context.Context, id string) (Fact, bool) {
	if f, ok := e.Facts[id]; ok {
		return f, true
	}
	if e.LookupFact != nil {
		if e.passMissing[id] {
			return Fact{}, false
		}
		return e.LookupFact(ctx, id)
	}
	return Fact{}, false
}

func (e *Engine) bundle(ctx context.Context, id string) (Bundle, bool) {
	if b, ok := e.Bundles[id]; ok {
		return b, true
	}
	if e.LookupBundle != nil {
		return e.LookupBundle(ctx, id)
	}
	return Bundle{}, false
}

func (e *Engine) RequestContext(ctx context.Context, en *Enrollment, at time.Time) (*SharedContext, string) {
	var best *SharedContext
	var id string
	consider := func(f Fact) {
		if f.Asset != en.Asset || f.Run != e.Config.RunID || f.Kind != "TRACKER_CONTEXT" || f.AvailableAt.After(at) || f.AvailableAt.Before(en.DiscoveryFloor) {
			return
		}
		var c TrackerContext
		if json.Unmarshal(f.Body, &c) != nil || c.Revision > en.Revision || c.Category != e.Config.Category {
			return
		}
		if best == nil || f.AvailableAt.After(best.AvailableAt) || f.AvailableAt.Equal(best.AvailableAt) && (c.Revision > best.Revision || c.Revision == best.Revision && f.ID > id) {
			best = &SharedContext{Payload: c.Payload, AvailableAt: f.AvailableAt, BundleID: c.BundleID, Revision: c.Revision}
			id = f.ID
		}
	}
	for _, f := range e.Facts {
		consider(f)
	}
	if best == nil && e.LookupContext != nil {
		if f, ok := e.LookupContext(ctx, en.Asset, at, en.DiscoveryFloor); ok {
			consider(f)
		}
	}
	return best, id
}

type archiveQualificationRef struct {
	id   [32]byte
	atUS int64
}

func stickyQualification(f Fact) bool {
	var q Qualified
	return f.Kind == "QUALIFIED" && json.Unmarshal(f.Body, &q) == nil && q.Rule != "telemetry_loss" && q.Severity == "CRITICAL" && q.Transition == "OPEN"
}

func (e *Engine) matchingRecovery(ctx context.Context, f Fact, at time.Time) (Fact, bool) {
	var open Qualified
	if json.Unmarshal(f.Body, &open) != nil {
		return Fact{}, false
	}
	id, _ := Identity("qualified", e.Config.Category, map[string]any{"run": f.Run, "asset": f.Asset, "policy_id": open.PolicyID, "occurrence": open.Occurrence, "transition": "RECOVER"})
	recovery, ok := e.fact(ctx, id)
	var q Qualified
	if !ok || recovery.AvailableAt.After(at) || json.Unmarshal(recovery.Body, &q) != nil ||
		q.Rule != open.Rule || q.RuleVersion != open.RuleVersion || q.EnrollmentRevision != open.EnrollmentRevision || q.QualifiedAt.Before(open.QualifiedAt) {
		return Fact{}, false
	}
	return recovery, true
}

// prefetchFacts keeps network round trips out of per-reference traversal. The
// resolver owns bounded positive storage; only confirmed misses are pass-local.
func (e *Engine) prefetchFacts(ctx context.Context, ids []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.PrefetchFacts == nil {
		return nil
	}
	if len(ids) > MaxFacts {
		return ErrInvalid
	}
	pending := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := e.Facts[id]; !ok && !e.passMissing[id] {
			pending = append(pending, id)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	missing, err := e.PrefetchFacts(ctx, pending)
	if err != nil {
		return err
	}
	if e.passMissing != nil {
		if len(e.passMissing)+len(missing) > 6144 {
			return fmt.Errorf("CAPACITY")
		}
		for _, id := range missing {
			e.passMissing[id] = true
		}
	}
	return ctx.Err()
}

func (e *Engine) request(ctx context.Context, en *Enrollment, at, executed time.Time, purpose string, c *Candidate) (Request, error) {
	index := map[string]Fact{}
	samples := checkedSamples(ctx)
	inputBytes := 0
	lower := at.Add(-900 * time.Second)
	var add func(string) error
	add = func(id string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, ok := index[id]; ok {
			return nil
		}
		if err := e.prefetchFacts(ctx, []string{id}); err != nil {
			return err
		}
		f, ok := e.fact(ctx, id)
		if err := ctx.Err(); err != nil {
			return err
		}
		if !ok || f.Asset != en.Asset || f.Run != e.Config.RunID || f.AvailableAt.After(at) || len(index) >= MaxFacts {
			return ErrInvalid
		}
		inputBytes += len(f.Body) + len(f.Asset) + len(f.Run) + len(f.ID) + 160
		if inputBytes > MaxInputBytes {
			return ErrInvalid
		}
		index[id] = f
		for _, ref := range factRefs(f) {
			if err := add(ref); err != nil {
				return err
			}
		}
		return nil
	}
	addBundle := func(id string) error {
		b, ok := e.bundle(ctx, id)
		if err := ctx.Err(); err != nil {
			return err
		}
		if !ok || b.Asset != en.Asset || b.Run != e.Config.RunID || b.AvailabilityCutoff.After(at) {
			return ErrInvalid
		}
		if err := e.prefetchFacts(ctx, append(slices.Clone(b.Facts), b.Features...)); err != nil {
			return err
		}
		for _, ids := range [][]string{b.Facts, b.Features} {
			for _, id := range ids {
				if err := add(id); err != nil {
					return err
				}
			}
		}
		return nil
	}
	r := Request{Contract: 1, Implementation: e.Config.Implementation, Category: e.Config.Category, Run: e.Config.RunID, Asset: en.Asset, DescriptorHash: e.descriptorHash, ConfigHash: e.configHash, Purpose: purpose, Scope: "TRACKER", Sequence: en.Sequence, ExpectedRevision: en.Revision, LogicalAt: at, AvailabilityCutoff: at, ExecutedAt: executed, DiscoveryFloor: en.DiscoveryFloor, Policy: e.policy, State: en.Tracker}
	var shared *SharedContext
	var contextID string
	if c != nil || en.Active {
		shared, contextID = e.RequestContext(ctx, en, at)
	}
	if c != nil {
		r.Scope, r.CandidateID, r.BudgetMS, r.Sequence, r.ExpectedRevision = "ARM", c.ID, &c.BudgetMS, c.Sequence, c.Revision
		r.State, r.Entry, r.Terminal = &c.State, &c.Entry, c.Terminal
		if en.DiscoveryFloor.After(c.EnteredAt) {
			r.DiscoveryFloor = c.EnteredAt
		}
		if err := addBundle(c.Entry.BundleID); err != nil {
			return r, err
		}
		if c.Terminal != nil && c.Terminal.Endpoint != nil {
			if err := add(c.Terminal.Endpoint.ID); err != nil {
				return r, err
			}
		}
		r.SharedContext = shared
	} else if en.Active {
		for _, arm := range e.Candidates {
			if arm.Asset == en.Asset && arm.Sequence == en.Sequence {
				if err := addBundle(arm.Entry.BundleID); err != nil {
					return r, err
				}
				break
			}
		}
	}
	if shared != nil {
		if err := add(contextID); err != nil {
			return r, err
		}
		if err := addBundle(shared.BundleID); err != nil {
			return r, err
		}
	}
	for _, f := range e.Facts {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		if f.Asset != en.Asset || f.AvailableAt.After(at) {
			continue
		}
		keep := false
		if f.Kind == "SAMPLE" {
			sample, err := samples.decodeForSelection(e.Config.Category, f)
			keep = err == nil && !sample.SourceAt.Before(lower)
		} else {
			keep = recentFact(f, lower)
		}
		if !keep && en.Active && !f.AvailableAt.Before(en.DiscoveryFloor) && stickyQualification(f) {
			recovered, matched := e.matchingRecovery(ctx, f, at)
			keep = !matched || maxTime(recovered.AvailableAt, rawBoundary(recovered)).After(at)
		}
		if t, ok := e.passFeatures[f.ID]; ok && !t.After(at) {
			keep = true
		}
		if f.Kind == "CONFLICT" && !keep {
			for _, id := range factRefs(f) {
				if _, ok := index[id]; ok {
					keep = true
					break
				}
			}
		}
		if !keep {
			continue
		}
		if err := add(f.ID); err != nil {
			return r, err
		}
	}
	if lostUntil, ok := e.archiveInputBound[en.Asset]; ok && !at.After(lostUntil) {
		return r, ErrInvalid
	}
	if e.archiveInput && en.Active {
		assetIndex := slices.IndexFunc(e.Config.Assets, func(asset Asset) bool { return asset.EntityKey == en.Asset })
		for _, ref := range e.archiveSticky[assetIndex] {
			if ref.atUS < en.DiscoveryFloor.UnixMicro() || ref.atUS > at.UnixMicro() {
				continue
			}
			id := hex.EncodeToString(ref.id[:])
			if _, ok := index[id]; ok {
				continue
			}
			f, ok := e.fact(ctx, id)
			if !ok {
				return r, ErrInvalid
			}
			recovery, matched := e.matchingRecovery(ctx, f, at)
			if !recentFact(f, lower) && matched && !maxTime(recovery.AvailableAt, rawBoundary(recovery)).After(at) {
				continue
			}
			if err := add(id); err != nil {
				return r, err
			}
		}
	}
	if en.Active {
		for _, f := range index {
			if !stickyQualification(f) {
				continue
			}
			if recovery, ok := e.matchingRecovery(ctx, f, at); ok {
				if err := add(recovery.ID); err != nil {
					return r, err
				}
			}
		}
	}
	if e.LookupFact != nil && (en.Active || c != nil) {
		ids := make([]string, 0, len(index))
		for _, f := range index {
			if err := ctx.Err(); err != nil {
				return r, err
			}
			if f.Kind != "SAMPLE" {
				continue
			}
			sample, err := samples.decodeForSelection(e.Config.Category, f)
			if err != nil || !sample.SourceAt.Before(lower) {
				continue
			}
			id, _ := Identity("conflict", e.Config.Category, map[string]any{"run": e.Config.RunID, "asset": f.Asset, "metric": sample.Metric, "source_at": sample.SourceAt})
			ids = append(ids, id)
		}
		if err := e.prefetchFacts(ctx, ids); err != nil {
			return r, err
		}
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return r, err
			}
			if conflict, ok := e.fact(ctx, id); ok && !conflict.AvailableAt.After(at) {
				if err := add(id); err != nil {
					return r, err
				}
			}
		}
	}

	r.Facts = make([]Fact, 0, len(index))
	points := 0
	for _, f := range index {
		r.Facts = append(r.Facts, f)
		if f.Kind == "SAMPLE" {
			points++
		}
	}
	if points > 768 {
		return r, ErrInvalid
	}
	slices.SortFunc(r.Facts, func(a, b Fact) int { return strings.Compare(a.ID, b.ID) })
	var err error
	r.Bundle, err = NewBundle(e.Config.Category, e.Config.RunID, en.Asset, at, r.Facts)
	return r, err
}

func factRefs(f Fact) []string {
	switch f.Kind {
	case "FEATURE":
		var v Feature
		if json.Unmarshal(f.Body, &v) == nil {
			return v.Support
		}
	case "CONFLICT":
		var v Conflict
		if json.Unmarshal(f.Body, &v) == nil {
			return v.Values
		}
	case "PROVENANCE":
		var v ProvenanceFact
		if json.Unmarshal(f.Body, &v) == nil {
			return []string{v.SampleID}
		}
	}
	return nil
}

func recentFact(f Fact, lower time.Time) bool {
	switch f.Kind {
	case "SAMPLE":
		var v Sample
		return json.Unmarshal(f.Body, &v) == nil && !v.SourceAt.Before(lower)
	case "COVERAGE":
		var v Coverage
		return json.Unmarshal(f.Body, &v) == nil && !v.Through.Before(lower)
	case "QUALIFIED":
		return !maxTime(f.AvailableAt, rawBoundary(f)).Before(lower)
	case "CONFLICT":
		var v Conflict
		return json.Unmarshal(f.Body, &v) == nil && !v.SourceAt.Before(lower)
	}
	return false
}

func (e *Engine) retain(r Request) {
	for _, f := range r.Facts {
		if _, ok := e.Facts[f.ID]; !ok {
			if f.Kind == "FEATURE" || f.Kind == "TRACKER_CONTEXT" {
				e.keepDerived(f)
			} else {
				e.putFact(f)
			}
			if f.Kind == "FEATURE" && e.passFeatures != nil {
				e.passFeatures[f.ID] = r.LogicalAt
			}
		}
	}
	e.keepBundle(r.Bundle)
}

func (e *Engine) spoolEvidence(v any) {
	if e.archiveEvidence != nil && e.archiveEvidenceErr == nil {
		e.archiveEvidenceErr = e.archiveEvidence.Encode(v)
	}
}

func (e *Engine) putFact(f Fact) {
	e.Facts[f.ID] = f
	if e.inlineTxn != nil {
		e.inlineTxn.facts = append(e.inlineTxn.facts, f.ID)
	}
}

func (e *Engine) keepDerived(f Fact) {
	if _, ok := e.Facts[f.ID]; !ok {
		e.putFact(f)
		if e.payloadReady {
			e.factBytes += factPayloadBytes(f)
		}
		e.spoolEvidence(f)
	}
}

func (e *Engine) keepBundle(b Bundle) {
	if _, ok := e.Bundles[b.ID]; !ok {
		e.Bundles[b.ID] = b
		if e.inlineTxn != nil {
			e.inlineTxn.bundles = append(e.inlineTxn.bundles, b.ID)
		}
		if e.payloadReady {
			e.bundleBytes += bundlePayloadBytes(b)
		}
		e.spoolEvidence(b)
	}
}

func (e *Engine) fail(code string, r Request) {
	scope := r.CandidateID
	from, through := r.LogicalAt, r.LogicalAt
	if scope == "" {
		scope = r.Purpose + "/" + strconv.FormatInt(r.Sequence, 10)
		if r.Purpose == "DISCOVER" && !r.DiscoveryFloor.IsZero() {
			from = r.DiscoveryFloor
		}
	}
	e.recordFailureWindow(code, r.Asset, scope, r.CandidateID, r.ExecutedAt, "", nil, from, through)
}

func (e *Engine) recordFailure(code, asset, scope, candidate string, at time.Time, bundle string, refs []string) {
	e.recordFailureWindow(code, asset, scope, candidate, at, bundle, refs, at, at)
}

// RecordCoverageGap records a missed source interval without inferring an outage.
func (e *Engine) RecordCoverageGap(from, through time.Time) {
	from, through = clock(from), clock(through)
	if from.IsZero() || through.Before(from) {
		return
	}
	e.retainCoverageGap("COVERAGE", from, through)
	e.recordFailureWindow("COVERAGE", "", "acquisition_gap", "", through, "", nil, from, through)
}

func extendCoverageInterval(dst *CoverageInterval, src CoverageInterval) {
	if src.From.Before(dst.From) {
		dst.From = src.From
	}
	dst.Through = maxTime(dst.Through, src.Through)
	dst.Count += src.Count
}

func (e *Engine) retainCoverageGap(code string, from, through time.Time) {
	if e.UnknownFrom == nil || from.Before(*e.UnknownFrom) {
		e.UnknownFrom = &from
	}
	if e.UnknownThrough == nil || through.After(*e.UnknownThrough) {
		e.UnknownThrough = &through
	}
	gap := CoverageInterval{From: from, Through: through, Code: code, Count: 1}
	sameCode := -1
	for i, prior := range e.CoverageIntervals {
		if prior.Code != code {
			continue
		}
		if !through.Before(prior.From) && !from.After(prior.Through) {
			extendCoverageInterval(&e.CoverageIntervals[i], gap)
			return
		}
		sameCode = i
	}
	if len(e.CoverageIntervals) < 1024 {
		e.CoverageIntervals = append(e.CoverageIntervals, gap)
		return
	}
	if sameCode >= 0 {
		extendCoverageInterval(&e.CoverageIntervals[sameCode], gap)
		return
	}
	// Compact two ordinary intervals to make room for this gap while retaining
	// the separate deadline-capacity witness.
	ordinary := -1
	for i, prior := range e.CoverageIntervals {
		if prior.Code == "DEADLINE_CAPACITY" {
			continue
		}
		if ordinary >= 0 {
			extendCoverageInterval(&e.CoverageIntervals[ordinary], prior)
			e.CoverageIntervals[ordinary].Code = "COVERAGE"
			e.CoverageIntervals[i] = gap
			return
		}
		ordinary = i
	}
	// A ledger dominated by deadline-capacity witnesses can still cover the
	// omitted window without removing any of those witnesses.
	if ordinary < 0 {
		ordinary = len(e.CoverageIntervals) - 1
	}
	extendCoverageInterval(&e.CoverageIntervals[ordinary], gap)
}

func (e *Engine) recordFailureWindow(code, asset, scope, candidate string, at time.Time, bundle string, refs []string, from, through time.Time) {

	key := map[string]any{"run": e.Config.RunID, "code": code, "scope_key": scope}
	if asset != "" {
		key["asset"] = asset
	}
	id, _ := Identity("failure", e.Config.Category, key)
	for i := range e.Failures {
		f := &e.Failures[i]
		if f.ID == id {
			f.At, f.Count = maxTime(at, f.At), f.Count+1
			if f.LogicalFrom == nil || from.Before(*f.LogicalFrom) {
				f.LogicalFrom = &from
			}
			if f.LogicalThrough == nil || through.After(*f.LogicalThrough) {
				f.LogicalThrough = &through
			}
			return
		}
	}
	if len(e.Failures)+len(e.Telemetry) >= 1024 {
		e.FailureOverflow++
		return
	}
	kind := "COMPONENT"
	if code == "COVERAGE" || code == "CONFLICT" || code == "CAPACITY" {
		kind = "COVERAGE"
	}
	e.Failures = append(e.Failures, Failure{ID: id, Kind: kind, ScopeKey: scope, Asset: asset, CandidateID: candidate, Code: code, FirstAt: at, At: at, Count: 1, BundleID: bundle, FactIDs: append([]string{}, refs...), LogicalFrom: &from, LogicalThrough: &through})
}

func failureCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "TIME_BUDGET"
	}
	for _, c := range []string{"PANIC", "TIME_BUDGET", "UNSUPPORTED_VERSION", "INVALID_INPUT", "MALFORMED_RESULT", "STORE_UNAVAILABLE", "AUTHORITY_LOST", "CAPACITY", "COVERAGE", "HOST_STATE", "CONFLICT"} {
		if strings.Contains(err.Error(), c) {
			return c
		}
	}
	return "MALFORMED_RESULT"
}

func preparationFailure(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "TIME_BUDGET"
	}
	if strings.Contains(err.Error(), "CAPACITY") {
		return "CAPACITY"
	}
	return "INVALID_INPUT"
}

func (e *Engine) budgetSpent(ctx context.Context) bool { return e.exhausted || ctx.Err() != nil }

func faultMatches(f Fault, r Request) bool {
	return f.Asset == r.Asset && f.Purpose == r.Purpose && f.At.Equal(r.LogicalAt) &&
		(f.BudgetMS == nil && r.BudgetMS == nil || f.BudgetMS != nil && r.BudgetMS != nil && *f.BudgetMS == *r.BudgetMS)
}

func (e *Engine) invoke(ctx context.Context, r Request, faults []Fault) (Result, Request, error) {
	if e.exhausted || ctx.Err() != nil {
		return Result{}, Request{}, fmt.Errorf("TIME_BUDGET")
	}
	for _, f := range faults {
		if faultMatches(f, r) && f.Code != "STORE_UNAVAILABLE" {
			if f.Code == "TIME_BUDGET" {
				e.exhausted = true
			}
			return Result{}, Request{}, fmt.Errorf("%s", f.Code)
		}
	}
	x, m, err := e.Registry.Invoke(ctx, r)
	if err != nil {
		return x, m, err
	}
	if len(x.ProposedFeatures) > 0 {
		b, err := Canonical(x.ProposedFeatures)
		if err != nil || e.proposalBytes+len(b) > MaxProposalBytes {
			return Result{}, Request{}, fmt.Errorf("MALFORMED_RESULT")
		}
		e.proposalBytes += len(b)
	}
	if x.Kind == "ASSESSMENT" && x.Phase == "FINAL" && x.Action == "URGENT" && len(urgentOccurrences(m, x.Support)) > 8 {
		return Result{}, Request{}, fmt.Errorf("MALFORMED_RESULT")
	}
	n := len(e.Facts)
	for _, f := range m.Facts {
		if _, ok := e.Facts[f.ID]; !ok {
			n++
		}
	}
	if int64(n) > e.Config.Limits.FactCount {
		return Result{}, Request{}, fmt.Errorf("CAPACITY")
	}
	return x, m, nil
}
func (e *Engine) terminal(ctx context.Context, c *Candidate, r Request, x Result, cause string, committed time.Time) {
	if c.Terminal != nil {
		return
	}
	id := c.Entry.Fallback.TerminalID
	d := Decision{ID: id, CandidateID: c.ID, Asset: c.Asset, Sequence: c.Sequence, BudgetMS: c.BudgetMS, Kind: "TERMINAL", LogicalAt: r.LogicalAt, ExecutedAt: r.ExecutedAt, CommittedAt: committed, LatenessUS: max(int64(0), committed.Sub(c.DueAt).Microseconds()), Action: x.Action, DecisionSource: "CATEGORY", Outcome: x.Outcome, BundleID: r.Bundle.ID, Codes: []string{}, Reasons: x.Reasons, Support: x.Support, Summary: x.Summary, Details: x.Details, UrgentOccurrences: []Occurrence{}}
	if cause != "" {
		d.DecisionSource = "HOST_FALLBACK"
		d.Action = "INVESTIGATE"
		d.Outcome = ""
		d.HostCause = "DEADLINE_FALLBACK"
		d.FailureCode = cause
		d.Support = append([]string{}, c.Entry.Support...)
		d.BundleID = c.Entry.BundleID
		d.Summary = c.Entry.Fallback.Summary
		d.Reasons = []string{}
		d.Details = nil
	} else {
		for _, f := range r.Facts {
			if f.ID == x.TerminalEndpointID {
				var feature Feature
				_ = json.Unmarshal(f.Body, &feature)
				d.TerminalEndpoint = &FeatureRef{ID: f.ID, Value: feature.Value, SourceAt: feature.SourceAt, AvailableAt: f.AvailableAt}
			}
		}
		if d.Action == "URGENT" {
			d.UrgentOccurrences = urgentOccurrences(r, x.Support)
		}
	}
	c.Terminal = &Terminal{DecisionID: id, LogicalAt: d.LogicalAt, Action: d.Action, Endpoint: d.TerminalEndpoint, UrgentOccurrences: d.UrgentOccurrences}
	c.Phase = "FINAL"
	c.Revision++
	if x.State != nil && cause == "" {
		c.State = *x.State
	}
	if e.archiveInput {
		if e.previewComparisons == nil {
			e.previewComparisons = map[string]previewChange{}
		}
		if d.TerminalEndpoint != nil {
			if e.endpointConflictIDs == nil {
				e.endpointConflictIDs = map[string][][32]byte{}
			}
			if refs, ok := e.endpointConflicts(ctx, c.Asset, d.TerminalEndpoint.ID); ok {
				e.endpointConflictIDs[c.ID] = refs
			}
		}
		if change, ok := e.previewChange(ctx, d); ok {
			e.previewComparisons[d.ID] = change
		}
	}
	e.Decisions = append(e.Decisions, d)
}
func urgentOccurrences(r Request, support []string) []Occurrence {
	out := []Occurrence{}
	for _, f := range r.Facts {
		if f.Kind != "QUALIFIED" || !slices.Contains(support, f.ID) {
			continue
		}
		var q Qualified
		if json.Unmarshal(f.Body, &q) == nil && q.Transition == "OPEN" && q.Severity == "CRITICAL" &&
			(q.Rule == "gpu_thermal" || q.Rule == "hbm_thermal") {
			out = append(out, Occurrence{PolicyID: q.PolicyID, Occurrence: q.Occurrence})
		}
	}
	slices.SortFunc(out, func(a, b Occurrence) int {
		if a.PolicyID != b.PolicyID {
			return strings.Compare(a.PolicyID, b.PolicyID)
		}
		if a.Occurrence < b.Occurrence {
			return -1
		}
		if a.Occurrence > b.Occurrence {
			return 1
		}
		return 0
	})
	return slices.Compact(out)
}

func (e *Engine) update(c *Candidate, r Request, x Result, committed time.Time) {
	codes := []string{}
	for _, code := range x.UpdateCodes {
		if !slices.Contains(c.ReservedCodes, code) {
			codes = append(codes, code)
		}
	}
	if len(codes) == 0 {
		return
	}
	action := "INVESTIGATE"
	for _, u := range e.descriptor.Updates {
		if slices.Contains(codes, u.Code) && u.Action == "URGENT" {
			action = "URGENT"
		}
	}
	id, _ := Identity("update", e.Config.Category, map[string]any{"candidate": c.ID, "codes": codes})
	e.Decisions = append(e.Decisions, Decision{ID: id, CandidateID: c.ID, Asset: c.Asset, Sequence: c.Sequence, BudgetMS: c.BudgetMS, Kind: "UPDATE", LogicalAt: r.LogicalAt, ExecutedAt: r.ExecutedAt, CommittedAt: committed, Action: action, DecisionSource: "CATEGORY", BundleID: r.Bundle.ID, Codes: codes, Reasons: x.Reasons, Support: x.Support, Summary: x.Summary, Details: x.Details, UrgentOccurrences: []Occurrence{}})
	c.ReservedCodes = SortedUnique(append(c.ReservedCodes, codes...))
	c.Revision++
}

// BeginDrain closes admission without resetting the originally pinned cutoff.
func (e *Engine) BeginDrain(reason string) {
	if e.State == "ACTIVE" {
		e.State, e.StopReason = "DRAINING", reason
	}
}

func (e *Engine) commitTime(fallback time.Time) time.Time {
	if e.CommitClock != nil {
		if now := clock(e.CommitClock()); now.After(fallback) {
			return now
		}
	}
	return fallback
}

func (e *Engine) admit(ctx context.Context, at time.Time, facts []Fact) ([]Fact, error) {
	if len(facts) == 0 {
		return nil, nil
	}
	ordered := append([]Fact{}, facts...)
	slices.SortStableFunc(ordered, func(a, b Fact) int {
		if c := a.AvailableAt.Compare(b.AvailableAt); c != 0 {
			return c
		}
		if n := strings.Compare(a.ID, b.ID); n != 0 {
			return n
		}
		return bytes.Compare(a.Body, b.Body)
	})
	added := make(map[string]Fact, len(ordered))
	lookup := func(id string) (Fact, bool) {
		if f, ok := added[id]; ok {
			return f, true
		}
		if e.archiveInput {
			f, ok := e.Facts[id]
			return f, ok
		}
		return e.fact(ctx, id)
	}
	type sampleKey struct {
		asset, metric string
		source        time.Time
	}
	first := map[sampleKey]Fact{}
	conflicted := map[sampleKey]bool{}
	for _, f := range e.Facts {
		switch f.Kind {
		case "SAMPLE":
			var v Sample
			if json.Unmarshal(f.Body, &v) != nil {
				return nil, ErrInvalid
			}
			k := sampleKey{f.Asset, v.Metric, clock(v.SourceAt)}
			old, ok := first[k]
			if !ok || f.AvailableAt.Before(old.AvailableAt) || f.AvailableAt.Equal(old.AvailableAt) && f.ID < old.ID {
				first[k] = f
			}
		case "CONFLICT":
			var v Conflict
			if json.Unmarshal(f.Body, &v) != nil {
				return nil, ErrInvalid
			}
			conflicted[sampleKey{f.Asset, v.Metric, clock(v.SourceAt)}] = true
		}
	}
	for _, f := range ordered {
		if f.Run != e.Config.RunID || e.Enrollments[f.Asset] == nil || f.AvailableAt.After(at) || f.AvailableAt.Before(e.StartAt) || !e.Config.production && !f.AvailableAt.Before(e.AdmissionEndAt) {
			return nil, ErrInvalid
		}
		h, err := FactIdentity(e.Config.Category, f)
		if err != nil || h != f.ID {
			return nil, ErrInvalid
		}
		old, duplicate := lookup(f.ID)
		if duplicate && f.AvailableAt.Before(old.AvailableAt) {
			return nil, ErrInvalid
		}
		if e.archiveInput {
			if duplicate {
				return nil, ErrInvalid
			}
			added[f.ID] = f
			continue
		}
		if f.Kind == "SAMPLE" {
			var sample Sample
			if json.Unmarshal(f.Body, &sample) != nil || !e.sampleAuthorized(sample) {
				return nil, ErrInvalid
			}
			key := sampleKey{f.Asset, sample.Metric, clock(sample.SourceAt)}
			if duplicate {
				var previous Sample
				if json.Unmarshal(old.Body, &previous) != nil {
					return nil, ErrInvalid
				}
				if sample.SourceRecord != previous.SourceRecord {
					prov, err := NewFact(e.Config.Category, f.Run, f.Asset, "PROVENANCE", f.AvailableAt, ProvenanceFact{SampleID: f.ID, SourceRecord: sample.SourceRecord, Provenance: sample.Provenance})
					if err != nil {
						return nil, err
					}
					if _, ok := lookup(prov.ID); !ok {
						added[prov.ID] = prov
					}
				}
				continue
			}
			if previous, ok := first[key]; ok && !conflicted[key] {
				conflict, err := NewFact(e.Config.Category, f.Run, f.Asset, "CONFLICT", f.AvailableAt, Conflict{Metric: sample.Metric, SourceAt: key.source, Values: SortedUnique([]string{previous.ID, f.ID}), Code: "CONFLICT"})
				if err != nil {
					return nil, err
				}
				added[conflict.ID], conflicted[key] = conflict, true
			} else if !ok {
				first[key] = f
			}
		} else if duplicate {
			// Qualified occurrence identity is immutable. A changed repeated value
			// cannot replace the snapshot first admitted.
			continue
		}
		added[f.ID] = f
	}
	if int64(len(e.Facts)+len(added)) > e.Config.Limits.FactCount {
		e.BeginDrain("CAPACITY")
		e.recordFailure("CAPACITY", "", "fact_count", "", at, "", nil)
		return nil, nil
	}
	for _, f := range added {
		if !e.archiveInput && f.Kind == "TRACKER_CONTEXT" {
			return nil, ErrInvalid
		}
		closure := map[string]Fact{f.ID: f}
		for _, id := range factRefs(f) {
			ref, ok := lookup(id)
			if !ok && e.archiveInput {
				ref, ok = e.fact(ctx, id)
			}
			if !ok {
				return nil, ErrInvalid
			}
			closure[id] = ref
		}
		if err := ValidateFact(e.Config.Category, f, closure); err != nil {
			return nil, err
		}
		if f.Kind == "PROVENANCE" && !e.provenanceFactAuthorized(f, closure) {
			return nil, ErrInvalid
		}
	}
	var addedBytes int64
	if !e.Shadow && !e.archiveInput {
		for _, f := range added {
			addedBytes += factPayloadBytes(f)
		}
		if e.inlinePayloadBytes()+addedBytes > e.Config.Limits.PayloadBytes-(4<<20) {
			e.BeginDrain("CAPACITY")
			e.recordFailure("CAPACITY", "", "payload_reserve", "", at, "", nil)
			return nil, nil
		}
		e.factBytes += addedBytes
	}

	out := make([]Fact, 0, len(added))
	for _, f := range added {
		e.putFact(f)
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b Fact) int {
		if c := a.AvailableAt.Compare(b.AvailableAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out, nil
}

func wireBytes(v any) int64 { b, _ := Canonical(v); return int64(len(b)) }
func textBytes(parts ...string) int64 {
	var n int64
	for _, p := range parts {
		n += int64(len(p))
	}
	return n
}
func factPayloadBytes(f Fact) int64 {
	return textBytes(f.ID, f.Run, f.Asset, f.Kind) + 8 + wireBytes(f)
}
func bundlePayloadBytes(b Bundle) int64 { return textBytes(b.ID, b.Run, b.Asset) + 16 + wireBytes(b) }
func payloadBodyBytes(p *Payload) int64 {
	if p == nil {
		return 0
	}
	return int64(len(p.Body) + len(p.Hash))
}

func (e *Engine) inlinePayloadBytes() int64 {
	if !e.payloadReady {
		for _, f := range e.Facts {
			e.factBytes += factPayloadBytes(f)
		}
		for _, b := range e.Bundles {
			e.bundleBytes += bundlePayloadBytes(b)
		}
		e.payloadReady = true
	}
	// Each counted term is a physical V1 column. JSON bytea uses canonical
	// bytes; duplicate candidate and enrollment states count separately.
	coverage := e.CoverageIntervals
	if coverage == nil {
		coverage = []CoverageInterval{}
	}
	n := e.factBytes + e.bundleBytes + wireBytes(e.Config) + wireBytes(e.descriptor) + wireBytes(coverage) +
		textBytes(e.Config.RunID, "replay", e.State, e.StopReason) + 3*64 + 6*8 + 1 + 2*8
	if !e.lastPass.IsZero() {
		n += 8
	}
	if e.State != "ACTIVE" {
		n += 8
	}
	if !e.ClosedAt.IsZero() {
		n += 8
	}
	if e.UnknownFrom != nil {
		n += 16
	}
	bindings := wireBytes(e.Config.Bindings)
	for _, asset := range e.Config.Assets {
		en := e.Enrollments[asset.EntityKey]
		n += textBytes(e.Config.RunID, e.Config.Category, asset.EntityKey, asset.NodeID, asset.GPUUUID, e.Config.InventoryRevision) + bindings + 8*4 + 1 + payloadBodyBytes(en.Tracker)
		if !en.ProcessedAt.IsZero() {
			n += 8
		}
	}
	for _, c := range e.Candidates {
		n += textBytes(e.Config.RunID, c.ID, e.Config.Category, c.Asset, c.Phase, c.Entry.BundleID) + 5*8 + wireBytes(c.Entry) + payloadBodyBytes(&c.InitialState) + payloadBodyBytes(&c.State) + wireBytes(c.ReservedCodes)
		if c.Terminal != nil {
			n += textBytes(c.Terminal.DecisionID) + wireBytes(*c.Terminal)
		}
	}
	for _, d := range e.Decisions {
		route := "hardware_investigation"
		if d.Action == "NONE" {
			route = "none"
		}
		meta := archiveDecisionMetadata{Schema: 1, Route: route, TerminalEndpoint: d.TerminalEndpoint, UrgentOccurrences: d.UrgentOccurrences}
		n += textBytes(e.Config.RunID, d.ID, d.CandidateID, d.Kind, d.Action, d.DecisionSource, d.Outcome, d.HostCause, d.FailureCode, d.BundleID, d.Summary) + 4*8 +
			wireBytes(d.Codes) + wireBytes(d.Reasons) + wireBytes(d.Support) + wireBytes(meta) + payloadBodyBytes(d.Details)
	}
	for _, f := range e.Failures {
		from, through := f.FirstAt, f.At
		if f.LogicalFrom != nil {
			from = *f.LogicalFrom
		}
		if f.LogicalThrough != nil {
			through = *f.LogicalThrough
		}
		body := archiveDiagnostic{Schema: 1, BundleID: f.BundleID, FactIDs: f.FactIDs, Message: f.Code, From: from, Through: through}
		n += textBytes(e.Config.RunID, f.ID, e.Config.Category, f.Asset, f.Kind, f.Code, f.ScopeKey) + 3*8 + wireBytes(body)
	}
	for _, t := range e.Telemetry {
		body := archiveTelemetryBody{Schema: 1, PolicyID: t.PolicyID, Occurrence: t.Occurrence, Disposition: t.Disposition, PhysicalSequence: t.PhysicalSequence, OpenFact: t.OpenFact, RecoverFact: t.RecoverFact, BundleID: t.BundleID, Summary: t.Summary, PreviewID: t.PreviewID}
		n += textBytes(e.Config.RunID, t.ID, e.Config.Category, t.Asset, "QUALIFIED_TELEMETRY", "QUALIFIED_TELEMETRY", t.ID) + 3*8 + wireBytes(body)
	}
	return n
}

func (e *Engine) sampleAuthorized(s Sample) bool {
	if s.SourceRecord != s.Provenance.SourceRecord || !e.provenanceAuthorized(s.Metric, s.Provenance) {
		return false
	}
	return slices.ContainsFunc(e.descriptor.Metrics, func(m Metric) bool {
		return m.Metric == s.Metric && m.Unit == s.Unit
	})
}

func (e *Engine) provenanceAuthorized(metric string, p Provenance) bool {
	if e.Config.InventoryRevision != p.InventoryRevision {
		return false
	}
	for _, b := range e.Config.Bindings {
		if b.Metric != metric || b.Operation != p.Operation || (!e.Config.production && b.ScheduleRevision != p.ScheduleRevision) || (e.Config.production && p.ScheduleRevision < b.ScheduleRevision) {
			continue
		}
		if b.UploadProfileID == "" {
			return p.Mode != "upload"
		}
		return p.Mode == "upload" && b.UploadProfileID == p.UploadProfileID && (b.UploadProfileHash == p.UploadProfileHash || e.Config.production && ValidHash(p.UploadProfileHash)) && b.UploadCollectorID == p.CollectorID
	}
	return false
}

func (e *Engine) provenanceFactAuthorized(f Fact, index map[string]Fact) bool {
	var p ProvenanceFact
	if json.Unmarshal(f.Body, &p) != nil {
		return false
	}
	if p.Provenance.Mode != "upload" && !e.Config.usesUpload() {
		return true
	}
	var s Sample
	return json.Unmarshal(index[p.SampleID].Body, &s) == nil && s.Provenance.CollectorID == p.Provenance.CollectorID && e.provenanceAuthorized(s.Metric, p.Provenance)
}

func (e *Engine) qualifiedTelemetry(ctx context.Context, en *Enrollment, cutoff time.Time, priorSequence int64) {
	if lostUntil, ok := e.archiveInputBound[en.Asset]; ok && !cutoff.After(lostUntil) {
		return
	}
	type event struct {
		f  Fact
		q  Qualified
		at time.Time
	}
	type pair struct{ open, recover *event }
	occurrences := map[string]pair{}
	for _, f := range e.Facts {
		if f.Asset != en.Asset || f.Kind != "QUALIFIED" || f.AvailableAt.After(cutoff) {
			continue
		}
		var q Qualified
		if json.Unmarshal(f.Body, &q) != nil || q.Rule != "telemetry_loss" {
			continue
		}
		effective := f.AvailableAt
		if boundary := rawBoundary(f); boundary.After(effective) {
			effective = boundary
		}
		if effective.After(cutoff) {
			continue
		}
		id, _ := Identity("telemetry_record", e.Config.Category, map[string]any{"run": e.Config.RunID, "category": e.Config.Category, "asset": f.Asset, "policy_id": q.PolicyID, "occurrence": q.Occurrence})
		p := occurrences[id]
		if q.Transition == "OPEN" {
			p.open = &event{f, q, effective}
		} else if q.Transition == "RECOVER" {
			p.recover = &event{f, q, effective}
		}
		occurrences[id] = p
	}
	ids := make([]string, 0, len(occurrences))
	for id := range occurrences {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	matches := func(open Qualified, recover *event) bool {
		return recover != nil && open.RuleVersion == recover.q.RuleVersion && open.EnrollmentRevision == recover.q.EnrollmentRevision && !recover.q.QualifiedAt.Before(open.QualifiedAt)
	}
	for _, id := range ids {
		p := occurrences[id]
		if rec := e.Telemetry[id]; rec != nil {
			if rec.RecoverFact != "" || p.recover == nil {
				continue
			}
			f, ok := e.fact(ctx, rec.OpenFact)
			var q Qualified
			if ok && json.Unmarshal(f.Body, &q) == nil && matches(q, p.recover) && !p.recover.at.Before(rec.FirstAt) {
				e.stageSourceMutation()
				rec.RecoverFact, rec.LastAt, rec.Count = p.recover.f.ID, p.recover.at, rec.Count+1
			}
			continue
		}
		// An occurrence first seen closed supplies no retrospective preview.
		if p.open == nil || !p.open.at.After(en.ProcessedAt) || matches(p.open.q, p.recover) {
			continue
		}
		if len(e.Failures)+len(e.Telemetry) >= 1024 {
			e.FailureOverflow++
			continue
		}
		f, q, eligible := p.open.f, p.open.q, p.open.at
		b, _ := NewBundle(e.Config.Category, e.Config.RunID, en.Asset, eligible, []Fact{f})
		e.keepBundle(b)
		rec := &TelemetryRecord{ID: id, Asset: f.Asset, PolicyID: q.PolicyID, Occurrence: q.Occurrence, Disposition: "PREVIEW", OpenFact: f.ID, BundleID: b.ID, Summary: "Qualified loss of GPU telemetry warrants monitoring investigation.", PreviewID: id, FirstAt: eligible, LastAt: eligible, Count: 1}
		seq := priorSequence
		if seq == 0 && en.Active {
			for _, c := range e.Candidates {
				if c.Asset == en.Asset && c.Sequence == en.Sequence && !c.EnteredAt.After(eligible) {
					seq = en.Sequence
					break
				}
			}
		}
		if seq > 0 {
			rec.Disposition, rec.PhysicalSequence, rec.PreviewID, rec.Summary = "ANNOTATION", seq, "", "Qualified loss of GPU telemetry limits evidence for the active concern."
		}
		e.stageSourceMutation()
		e.Telemetry[id] = rec
	}
}

func (e *Engine) quarantine(c *Candidate, at time.Time) {
	c.Phase = "QUARANTINED"
	c.Revision++
	e.recordFailure("HOST_STATE", c.Asset, c.ID, c.ID, at, "", nil)
}

type fallbackContextKey struct{}

func (e *Engine) trusted(ctx context.Context, c *Candidate) bool {
	// An expired category budget cannot erase a previously admitted deadline.
	// Host-only entry verification may finish under the enclosing refresh budget.
	if parent, ok := ctx.Value(fallbackContextKey{}).(context.Context); ok {
		ctx = parent
	}
	id, _ := Identity("candidate", e.Config.Category, map[string]any{"run": e.Config.RunID, "category": e.Config.Category, "asset": c.Asset, "sequence": c.Sequence, "budget_ms": c.BudgetMS})
	terminalID, _ := Identity("terminal", e.Config.Category, map[string]any{"candidate": id})
	entry := c.Entry
	fallback := entry.Fallback
	if c.ID != id || e.Enrollments[c.Asset] == nil || c.Sequence <= 0 || !slices.Contains(Budgets[:], c.BudgetMS) ||
		c.EnteredAt.Before(e.StartAt) || !e.Config.production && !c.EnteredAt.Before(e.AdmissionEndAt) || c.EnteredAt != clock(c.EnteredAt) || !c.EnteredAt.Equal(entry.AvailableAt) || !c.DueAt.Equal(c.EnteredAt.Add(time.Duration(c.BudgetMS)*time.Millisecond)) ||
		!fallback.DueAt.Equal(c.DueAt) || fallback.TerminalID != terminalID || fallback.Schema != 1 || fallback.Action != "INVESTIGATE" || fallback.Route != e.Config.Fallback.Route ||
		fallback.Summary == "" || len(fallback.Summary) > 2048 || !utf8.ValidString(fallback.Summary) ||
		entry.Basis != "CATEGORY_CONCERN" && entry.Basis != "INDEPENDENT_URGENT" || len(entry.Support) == 0 || Set(entry.Support, 32) != nil {
		return false
	}
	proofKey := ""
	if e.trustedEntryProofs != nil {
		proofKey, _ = Identity("entry_proof", e.Config.Category, map[string]any{"bundle": entry.BundleID, "basis": entry.Basis, "support": entry.Support, "at": entry.AvailableAt})
		if ok := e.trustedEntryProofs[proofKey]; ok {
			return true
		}
	}
	b, ok := e.bundle(ctx, entry.BundleID)
	hash, err := BundleID(e.Config.Category, b)
	if !ok || err != nil || hash != b.ID || b.ID != entry.BundleID || b.Run != e.Config.RunID || b.Asset != c.Asset ||
		!b.AvailabilityCutoff.Equal(c.EnteredAt) || !b.LogicalAt.Equal(c.EnteredAt) || b.LookbackSeconds != 900 || len(b.Facts)+len(b.Features) > MaxFacts || Set(b.Facts, MaxFacts) != nil || Set(b.Features, MaxFacts) != nil {
		return false
	}
	if err := e.prefetchFacts(ctx, entry.Support); err != nil {
		return false
	}
	index := map[string]Fact{}
	urgent := false
	for _, id := range entry.Support {
		if !ValidHash(id) || !slices.Contains(b.Facts, id) && !slices.Contains(b.Features, id) {
			return false
		}
		f, ok := e.fact(ctx, id)
		if !ok || f.Run != b.Run || f.Asset != b.Asset || (f.Kind == "FEATURE") != slices.Contains(b.Features, id) {
			return false
		}
		index[id] = f
		if err := e.prefetchFacts(ctx, factRefs(f)); err != nil {
			return false
		}
		for _, ref := range factRefs(f) {
			raw, ok := e.fact(ctx, ref)
			if !ok || raw.Run != b.Run || raw.Asset != b.Asset {
				return false
			}
			index[ref] = raw
		}
		effective, err := validateFact(ctx, e.Config.Category, f, index)
		if err != nil || effective.After(c.EnteredAt) {
			return false
		}
		if f.Kind == "QUALIFIED" {
			var q Qualified
			if json.Unmarshal(f.Body, &q) == nil && q.Transition == "OPEN" && q.Severity == "CRITICAL" && (q.Rule == "gpu_thermal" || q.Rule == "hbm_thermal") {
				urgent = true
			}
		}
	}
	valid := entry.Basis != "INDEPENDENT_URGENT" || urgent
	if valid && proofKey != "" {
		e.trustedEntryProofs[proofKey] = true
	}
	return valid
}

func (e *Engine) assess(ctx context.Context, en *Enrollment, c *Candidate, at, executed, commit time.Time, faults []Fault, catchingUp ...bool) {
	if c.Phase != "OBSERVING" {
		return
	}
	code := e.expiryCause(c.Asset)
	if code != "" && at.Before(c.DueAt) {
		return
	}
	e.attemptedGPUWork = true
	if code != "" {
		if !e.trusted(ctx, c) {
			e.quarantine(c, executed)
			return
		}
		r := Request{CandidateID: c.ID, Asset: c.Asset, LogicalAt: c.DueAt, ExecutedAt: maxTime(executed, c.DueAt), Purpose: "ASSESS"}
		e.fail(code, r)
		e.terminal(ctx, c, r, Result{}, code, e.commitTime(commit))
		return
	}
	if e.budgetSpent(ctx) {
		r := Request{CandidateID: c.ID, Asset: c.Asset, LogicalAt: at, ExecutedAt: executed, Purpose: "ASSESS"}
		committed := e.commitTime(commit)
		e.fail("TIME_BUDGET", r)
		historical := len(catchingUp) > 0 && catchingUp[0] && at.Before(c.DueAt)
		if historical || committed.Before(c.DueAt) {
			return
		}
		if !e.trusted(ctx, c) {
			e.quarantine(c, executed)
			return
		}
		r.LogicalAt = c.DueAt
		r.ExecutedAt = maxTime(executed, c.DueAt)
		e.terminal(ctx, c, r, Result{}, "TIME_BUDGET", committed)
		return
	}
	if !e.trusted(ctx, c) {
		e.quarantine(c, executed)
		return
	}
	if at.After(c.DueAt) {
		at = c.DueAt
	}
	for {
		r, err := e.request(ctx, en, at, executed, "ASSESS", c)
		if err == nil && at.Equal(c.EnteredAt) {
			r, err = entryView(ctx, r, at)
		}
		x, m := Result{}, Request{}
		if err == nil {
			x, m, err = e.invoke(ctx, r, faults)
		} else {
			err = fmt.Errorf("%s", preparationFailure(err))
		}
		committed := e.commitTime(commit)
		code := ""
		if err != nil {
			code = failureCode(err)
			e.fail(code, r)
		}
		if err == nil && x.Kind == "ASSESSMENT" && x.Phase == "FINAL" {
			if at.Before(c.DueAt) && e.State == "ACTIVE" {
				e.stageSourceMutation()
			}
			e.retain(m)
			e.terminal(ctx, c, m, x, "", committed)
			return
		}
		if !committed.Before(c.DueAt) && !(len(catchingUp) > 0 && catchingUp[0] && at.Before(c.DueAt)) {
			if at.Before(c.DueAt) && ctx.Err() == nil && !e.exhausted {
				at = c.DueAt
				executed = committed
				continue
			}
			if code == "" {
				code = "MALFORMED_RESULT"
				if ctx.Err() != nil || e.exhausted {
					code = "TIME_BUDGET"
				}
				e.fail(code, r)
			}
			r.LogicalAt = c.DueAt
			if r.ExecutedAt.Before(r.LogicalAt) {
				r.ExecutedAt = committed
			}
			e.terminal(ctx, c, r, Result{}, code, committed)
			return
		}
		if err == nil {
			if x.State != nil && x.State.Hash != c.State.Hash {
				if at.Before(c.DueAt) && e.State == "ACTIVE" {
					e.stageSourceMutation()
				}
				e.retain(m)
				c.State = *x.State
				c.Revision++
			}
			c.NextLogicalAt = x.NextLogicalAt
		}
		return
	}
}

func (e *Engine) discover(ctx context.Context, en *Enrollment, at, executed, commit time.Time, faults []Fault, catchingUp bool) time.Time {
	e.attemptedGPUWork = true
	if e.budgetSpent(ctx) {
		e.fail("TIME_BUDGET", Request{Asset: en.Asset, Sequence: en.Sequence, Purpose: "DISCOVER", LogicalAt: at, ExecutedAt: executed, DiscoveryFloor: en.DiscoveryFloor})
		next := at.Add(time.Second)
		en.NextLogicalAt = &next
		return time.Time{}
	}
	r, err := e.request(ctx, en, at, executed, "DISCOVER", nil)
	if err != nil {
		e.fail(preparationFailure(err), r)
		next := at.Add(time.Second)
		en.NextLogicalAt = &next
		return time.Time{}
	}
	x, m, err := e.invoke(ctx, r, faults)
	if err != nil {
		e.fail(failureCode(err), r)
		next := at.Add(time.Second)
		en.NextLogicalAt = &next
		return time.Time{}
	}
	if x.Kind != "ASSESSMENT" {
		e.fail("MALFORMED_RESULT", r)
		return time.Time{}
	}
	if x.Phase == "NO_CANDIDATE" {
		changed := x.State != nil && (en.Tracker == nil || en.Tracker.Hash != x.State.Hash)
		if changed || len(x.ProposedFeatures) > 0 || len(x.Support) > 0 || x.Details != nil {
			e.stageSourceMutation()
			e.retain(m)
		}
		if changed {
			en.Tracker = x.State
		}
		en.DiscoveryFloor, en.NextLogicalAt = at, x.NextLogicalAt
		en.Revision++
		return time.Time{}
	}
	if int64(len(e.Candidates)/len(e.Config.BudgetsMS)) >= e.Config.Limits.PhysicalCandidates {
		e.recordFailure("CAPACITY", en.Asset, "physical_candidates", "", at, "", nil)
		e.BeginDrain("CAPACITY")
		return time.Time{}
	}
	qualified := *x.EntryQualifiedAt
	view, err := entryView(ctx, m, qualified)
	if err != nil {
		e.fail("INVALID_INPUT", r)
		return time.Time{}
	}
	if ctx.Err() != nil {
		e.fail("TIME_BUDGET", r)
		return time.Time{}
	}
	contextFact, err := e.trackerFact(ctx, en, qualified, view, *x.State)
	if err != nil {
		code := failureCode(err)
		e.fail(code, r)
		if code == "CAPACITY" {
			e.BeginDrain(code)
		}
		return time.Time{}
	}
	if ctx.Err() != nil {
		e.fail("TIME_BUDGET", r)
		return time.Time{}
	}
	e.retain(view)
	en.Sequence++
	en.Revision++
	en.Active, en.Tracker = true, x.State
	e.keepDerived(contextFact)
	en.SharedContext = &SharedContext{Payload: *x.State, AvailableAt: qualified, BundleID: view.Bundle.ID, Revision: en.Revision}
	en.NextLogicalAt = x.NextLogicalAt
	if qualified.Before(at) {
		wake := at.Add(time.Microsecond)
		en.NextLogicalAt = &wake
	}
	basis := "CATEGORY_CONCERN"
	if x.Phase == "FINAL" && x.Action == "URGENT" {
		basis = "INDEPENDENT_URGENT"
	}
	for _, budget := range e.Config.BudgetsMS {
		id, _ := Identity("candidate", e.Config.Category, map[string]any{"run": e.Config.RunID, "category": e.Config.Category, "asset": en.Asset, "sequence": en.Sequence, "budget_ms": budget})
		terminalID, _ := Identity("terminal", e.Config.Category, map[string]any{"candidate": id})
		due := qualified.Add(time.Duration(budget) * time.Millisecond)
		entry := Entry{Basis: basis, AvailableAt: qualified, BundleID: view.Bundle.ID, Support: x.Support, Fallback: Fallback{Schema: 1, DueAt: due, Action: "INVESTIGATE", Route: e.Config.Fallback.Route, Summary: "Credible temperature concern remains uncertain and warrants hardware investigation.", TerminalID: terminalID}}
		initial := *x.InitialCandidateState
		c := &Candidate{ID: id, Asset: en.Asset, Sequence: en.Sequence, BudgetMS: budget, Revision: 1, Phase: "OBSERVING", EnteredAt: qualified, DueAt: due, Entry: entry, InitialState: initial, State: initial, ReservedCodes: []string{}}
		e.Candidates = append(e.Candidates, c)
		if basis == "INDEPENDENT_URGENT" {
			final := x
			final.State = nil // DISCOVER returns the tracker state, never the arm state.
			e.terminal(ctx, c, view, final, "", e.commitTime(commit))
		} else {
			armAt := qualified
			if budget > 0 && !catchingUp && !qualified.Before(at) && !e.commitTime(commit).Before(due) {
				armAt = due
			}
			e.assess(ctx, en, c, armAt, executed, commit, faults, catchingUp || qualified.Before(at))
		}
	}

	return qualified
}

func (e *Engine) followTracker(ctx context.Context, en *Enrollment, at, executed time.Time, faults []Fault) bool {
	e.attemptedGPUWork = true
	if e.budgetSpent(ctx) {
		e.fail("TIME_BUDGET", Request{Asset: en.Asset, Sequence: en.Sequence, Purpose: "FOLLOW_UP", LogicalAt: at, ExecutedAt: executed})
		return false
	}
	r, err := e.request(ctx, en, at, executed, "FOLLOW_UP", nil)
	if err != nil {
		e.fail(preparationFailure(err), r)
		return false
	}
	r, err = entryView(ctx, r, at)
	if err != nil {
		e.fail(preparationFailure(err), r)
		return false
	}
	x, m, err := e.invoke(ctx, r, faults)
	if err != nil {
		e.fail(failureCode(err), r)
		return false
	}
	en.NextLogicalAt = x.NextLogicalAt
	if x.Kind == "REARM" {
		// The state update is authorized only after every arm has a disposition.
		for _, c := range e.Candidates {
			if c.Asset == en.Asset && c.Sequence == en.Sequence && c.Phase == "OBSERVING" {
				return false
			}
		}
		e.stageSourceMutation()
		e.retain(m)
		if e.Config.production {
			for _, c := range e.Candidates {
				if c.Asset == en.Asset && c.Sequence == en.Sequence {
					id, _ := Identity("recovery", e.Config.Category, map[string]any{"candidate": c.ID})
					e.Decisions = append(e.Decisions, Decision{ID: id, CandidateID: c.ID, Asset: c.Asset, Sequence: c.Sequence, BudgetMS: c.BudgetMS, Kind: "RECOVER", LogicalAt: at, ExecutedAt: executed, CommittedAt: e.commitTime(executed), Action: "NONE", DecisionSource: "CATEGORY", BundleID: m.Bundle.ID, Codes: []string{}, Reasons: x.Reasons, Support: x.Support, Summary: x.Summary, Details: x.Details, UrgentOccurrences: []Occurrence{}})
				}
			}
		}
		en.Active, en.DiscoveryFloor, en.SharedContext = false, at, nil
		if x.State != nil {
			en.Tracker = x.State
		}
		en.Revision++
		return true
	}
	if x.State == nil || en.Tracker != nil && en.Tracker.Hash == x.State.Hash {
		return false
	}
	fact, err := e.trackerFact(ctx, en, at, m, *x.State)
	if err != nil {
		e.fail(failureCode(err), r)
		return false
	}
	if ctx.Err() != nil {
		e.fail("TIME_BUDGET", r)
		return false
	}
	e.stageSourceMutation()
	e.retain(m)
	e.keepDerived(fact)
	en.Tracker, en.Revision = x.State, en.Revision+1
	en.SharedContext = &SharedContext{Payload: *x.State, AvailableAt: at, BundleID: m.Bundle.ID, Revision: en.Revision}
	return false
}

// trackerFact pins the entire validated materialized bundle before the new
// context exists, so references always point to immutable older revisions.
func (e *Engine) trackerFact(ctx context.Context, en *Enrollment, at time.Time, r Request, p Payload) (Fact, error) {
	f, err := NewFact(e.Config.Category, e.Config.RunID, en.Asset, "TRACKER_CONTEXT", at, TrackerContext{Category: e.Config.Category, Revision: en.Revision + 1, Payload: p, BundleID: r.Bundle.ID})
	if err != nil {
		return Fact{}, fmt.Errorf("INVALID_INPUT")
	}
	index := make(map[string]Fact, len(r.Facts)+1)
	count := len(e.Facts) + 1
	for _, raw := range r.Facts {
		index[raw.ID] = raw
		if _, ok := e.Facts[raw.ID]; !ok {
			count++
		}
	}
	if int64(count) > e.Config.Limits.FactCount {
		return Fact{}, fmt.Errorf("CAPACITY")
	}
	index[f.ID] = f
	if validateTrackerContext(ctx, e.Config.Category, f, r.Bundle, index) != nil {
		return Fact{}, fmt.Errorf("INVALID_INPUT")
	}
	return f, nil
}

type inlineCheckpoint struct {
	facts, bundles                   []string
	enrollments                      map[string]Enrollment
	candidatePtrs                    []*Candidate
	candidates                       []Candidate
	decisions                        []Decision
	failures                         []Failure
	telemetry                        map[string]*TelemetryRecord
	boundaries                       map[string][]time.Time
	coverage                         []CoverageInterval
	unknownFrom, unknownThrough      *time.Time
	factBytes, bundleBytes, overflow int64
	state, stopReason                string
	closedAt, lastPass               time.Time
	followupTruncated                bool
	sourceEffects                    bool
}

func (e *Engine) stageSourceMutation() {
	if e.inlineTxn != nil {
		e.inlineTxn.sourceEffects = true
	}
}

func (e *Engine) checkpointInline(at time.Time, facts []Fact) *inlineCheckpoint {
	if e.Shadow || e.archiveInput || e.State != "ACTIVE" || !at.Before(e.AdmissionEndAt) {
		return nil
	}
	work := len(facts) > 0 || e.lastPass.IsZero()
	for _, en := range e.Enrollments {
		pending := e.boundaries[en.Asset]
		work = work || len(pending) > 0 && !pending[0].After(at) || en.NextLogicalAt != nil && !en.NextLogicalAt.After(at)
	}
	if !work {
		return nil
	}
	e.inlinePayloadBytes()
	tx := &inlineCheckpoint{
		enrollments: map[string]Enrollment{}, candidatePtrs: slices.Clone(e.Candidates), candidates: make([]Candidate, len(e.Candidates)),
		decisions: slices.Clone(e.Decisions), failures: slices.Clone(e.Failures), telemetry: map[string]*TelemetryRecord{},
		coverage: slices.Clone(e.CoverageIntervals), unknownFrom: e.UnknownFrom, unknownThrough: e.UnknownThrough,
		factBytes: e.factBytes, bundleBytes: e.bundleBytes, overflow: e.FailureOverflow, state: e.State, stopReason: e.StopReason,
		closedAt: e.ClosedAt, lastPass: e.lastPass, followupTruncated: e.FollowupTruncated,
	}
	for asset, en := range e.Enrollments {
		tx.enrollments[asset] = *en
	}
	for i, c := range e.Candidates {
		tx.candidates[i] = *c
	}
	for id, t := range e.Telemetry {
		copy := *t
		tx.telemetry[id] = &copy
	}
	if e.boundaries != nil {
		tx.boundaries = map[string][]time.Time{}
		for asset, times := range e.boundaries {
			tx.boundaries[asset] = slices.Clone(times)
		}
	}
	e.inlineTxn = tx
	return tx
}

func (e *Engine) rollbackInline(tx *inlineCheckpoint) {
	for _, id := range tx.facts {
		delete(e.Facts, id)
	}
	for _, id := range tx.bundles {
		delete(e.Bundles, id)
	}
	for asset, en := range tx.enrollments {
		*e.Enrollments[asset] = en
	}
	for i, c := range tx.candidatePtrs {
		*c = tx.candidates[i]
	}
	e.Candidates, e.Decisions, e.Failures, e.Telemetry = tx.candidatePtrs, tx.decisions, tx.failures, tx.telemetry
	e.CoverageIntervals, e.UnknownFrom, e.UnknownThrough = tx.coverage, tx.unknownFrom, tx.unknownThrough
	e.boundaries, e.factBytes, e.bundleBytes, e.FailureOverflow = tx.boundaries, tx.factBytes, tx.bundleBytes, tx.overflow
	e.State, e.StopReason, e.ClosedAt, e.lastPass, e.FollowupTruncated = tx.state, tx.stopReason, tx.closedAt, tx.lastPass, tx.followupTruncated
}

// Advance evaluates a serialized snapshot at a normalized logical wake time.
func (e *Engine) Advance(ctx context.Context, at, executed, committed time.Time, facts []Fact, faults []Fault) error {
	return e.AdvanceAssets(ctx, at, executed, committed, facts, faults, nil)
}

// AdvanceAssets restricts non-expiry work to selected assets. Every loaded
// observing arm still receives its exact due tick, even during drain.
func (e *Engine) AdvanceAssets(ctx context.Context, at, executed, committed time.Time, facts []Fact, faults []Fault, selected []string) error {
	if e.State == "CLOSED" {
		return nil
	}
	at, executed, committed = clock(at), clock(executed), clock(committed)
	if at.Before(e.StartAt) || executed.Before(at) || committed.Before(executed) || !e.lastPass.IsZero() && at.Before(e.lastPass) {
		return ErrInvalid
	}
	if !e.Config.production && !at.Before(e.AdmissionEndAt) {
		e.BeginDrain("DURATION")
	}
	if len(e.ExpiryFailure) > 0 {
		facts = slices.DeleteFunc(slices.Clone(facts), func(f Fact) bool { return e.expiryCause(f.Asset) != "" })
	}
	tx := e.checkpointInline(at, facts)
	defer func() { e.inlineTxn = nil }()
	admitted := []Fact{}
	if e.State == "ACTIVE" {
		var err error
		admitted, err = e.admit(ctx, at, facts)
		if err != nil {
			return err
		}
	}
	if e.archiveInput && len(admitted) > 0 {
		e.trimArchiveRing(ctx, at)
	}
	if e.boundaries == nil {
		e.boundaries = map[string][]time.Time{}
		for _, f := range e.Facts {
			e.trackBoundary(f, at)
		}
	} else {
		for _, f := range admitted {
			e.trackBoundary(f, at)
		}
	}
	for _, asset := range e.Config.Assets {
		if err := ctx.Err(); err != nil {
			return err
		}
		en := e.Enrollments[asset.EntityKey]
		var started time.Time
		if e.ObserveGPU != nil {
			started = time.Now()
		}
		e.attemptedGPUWork = false
		pass := context.WithValue(ctx, fallbackContextKey{}, ctx)
		cancel := func() {}
		if e.Shadow {
			pass, cancel = context.WithTimeout(pass, ShadowGPUBudget)
		}
		pass = withFactValidationCache(pass)
		e.proposalBytes, e.exhausted = 0, false
		e.passFeatures = map[string]time.Time{}
		e.passMissing = map[string]bool{}
		e.trustedEntryProofs = map[string]bool{}
		e.advanceAsset(pass, en, at, executed, committed, admitted, faults, selected == nil || slices.Contains(selected, en.Asset))
		if e.ObserveGPU != nil && e.attemptedGPUWork {
			e.ObserveGPU(en.Asset, time.Since(started))
		}
		cancel()
		e.trustedEntryProofs = nil
		e.passMissing = nil
	}
	e.lastPass = at
	if tx != nil && (len(admitted) > 0 || len(e.Candidates) > len(tx.candidates) || tx.sourceEffects) &&
		e.inlinePayloadBytes() > e.Config.Limits.PayloadBytes-(4<<20) {
		e.rollbackInline(tx)
		e.inlineTxn = nil
		e.BeginDrain("CAPACITY")
		e.recordFailure("CAPACITY", "", "payload_reserve", "", at, "", nil)
		return e.AdvanceAssets(ctx, at, executed, committed, nil, faults, selected)
	}

	if e.State == "DRAINING" {
		for _, c := range e.Candidates {
			if c.Phase == "OBSERVING" {
				return nil
			}
		}
		e.State, e.ClosedAt = "CLOSED", e.commitTime(committed)
		for _, en := range e.Enrollments {
			e.FollowupTruncated = e.FollowupTruncated || en.Active
		}
		for _, rec := range e.Telemetry {
			e.FollowupTruncated = e.FollowupTruncated || rec.RecoverFact == ""
		}
	}
	return nil
}

func (e *Engine) advanceAsset(ctx context.Context, en *Enrollment, at, executed, committed time.Time, admitted []Fact, faults []Fault, requested bool) {
	suppression := e.expiryCause(en.Asset)
	selected := requested && suppression == ""
	if selected && e.State == "ACTIVE" && en.Active && !en.ProcessedAt.IsZero() && at.Sub(en.ProcessedAt) > time.Second {
		e.reconstructAfterEntry(ctx, en, en.ProcessedAt, at, executed, committed, faults, false)
	}

	priorSequence := int64(0)
	if en.Active {
		priorSequence = en.Sequence
	}
	// Expired earlier cutoffs cannot use a tracker result selected by this wake.
	for _, c := range e.Candidates {
		if c.Asset == en.Asset && c.Phase == "OBSERVING" && (c.DueAt.Before(at) || !selected && c.DueAt.Equal(at)) {
			e.assess(ctx, en, c, c.DueAt, executed, committed, faults)
		}
	}
	if !selected {
		if requested && e.State == "ACTIVE" && suppression == "CAPACITY" {
			purpose, from := "DISCOVER", en.DiscoveryFloor
			if en.Active {
				purpose, from = "FOLLOW_UP", maxTime(from, en.ProcessedAt)
			}
			scope := purpose + "/" + strconv.FormatInt(en.Sequence, 10)
			overflow := e.FailureOverflow
			e.recordFailureWindow(suppression, en.Asset, scope, "", executed, "", nil, from, at)
			if e.FailureOverflow > overflow {
				e.retainCoverageGap(suppression, from, at)
			}
		}
		return
	}
	changed := e.lastPass.IsZero()
	for _, f := range admitted {
		if f.Asset != en.Asset {
			continue
		}
		changed = true
		if f.Kind == "COVERAGE" {
			var coverage Coverage
			if json.Unmarshal(f.Body, &coverage) == nil {
				scope, _ := Identity("coverage_scope", e.Config.Category, map[string]any{"metric": coverage.Metric, "code": coverage.Code})
				b, _ := NewBundle(e.Config.Category, e.Config.RunID, en.Asset, f.AvailableAt, []Fact{f})
				e.keepBundle(b)
				e.recordFailure("COVERAGE", en.Asset, scope, "", f.AvailableAt, b.ID, []string{f.ID})
			}
		}

		if f.Kind == "CONFLICT" {
			for _, c := range e.Candidates {
				if c.Asset == en.Asset && c.Terminal != nil && c.Terminal.LogicalAt.Before(f.AvailableAt) {
					b, _ := NewBundle(e.Config.Category, e.Config.RunID, en.Asset, f.AvailableAt, []Fact{f})
					e.keepBundle(b)
					e.recordFailure("CONFLICT", en.Asset, f.ID, "", f.AvailableAt, b.ID, []string{f.ID})
					break
				}
			}
		}
	}
	pending := e.boundaries[en.Asset]
	consumed := 0
	for consumed < len(pending) && !pending[consumed].After(at) {
		changed = true
		consumed++
	}
	e.boundaries[en.Asset] = pending[consumed:]
	if e.State == "ACTIVE" && !en.Active {
		entered := time.Time{}
		if changed || en.Tracker == nil || en.NextLogicalAt != nil && !en.NextLogicalAt.After(at) {
			entered = e.discover(ctx, en, at, executed, committed, faults, false)
		}
		if !entered.IsZero() && entered.Before(at) {
			e.qualifiedTelemetry(ctx, en, entered, 0)
			en.ProcessedAt = entered
			e.reconstructAfterEntry(ctx, en, entered, at, executed, committed, faults, true)
		}
		if changed {
			e.qualifiedTelemetry(ctx, en, at, priorSequence)
		}
		en.ProcessedAt = at
		return
	}
	if e.State == "ACTIVE" {
		if en.NextLogicalAt != nil && !en.NextLogicalAt.After(at) {
			changed = true
			en.NextLogicalAt = nil
		}
		if changed {
			e.followTracker(ctx, en, at, executed, faults)
		}
	}
	e.applyArmEvent(ctx, en, at, executed, committed, faults, changed, false)
	if e.State == "ACTIVE" {
		if changed {
			e.qualifiedTelemetry(ctx, en, at, priorSequence)
		}
		en.ProcessedAt = at
	}
}

func (e *Engine) applyArmEvent(ctx context.Context, en *Enrollment, at, executed, committed time.Time, faults []Fault, changed, catchingUp bool) {

	for _, c := range e.Candidates {
		if c.Asset != en.Asset || c.Sequence != en.Sequence {
			continue
		}
		switch c.Phase {
		case "OBSERVING":
			if !c.DueAt.After(at) || changed || c.NextLogicalAt != nil && !c.NextLogicalAt.After(at) {
				e.assess(ctx, en, c, at, executed, committed, faults, catchingUp)
			}
		case "FINAL":
			if e.State != "ACTIVE" || !changed || !c.Terminal.LogicalAt.Before(at) || len(c.ReservedCodes) == len(e.descriptor.Updates) {
				continue
			}
			e.attemptedGPUWork = true
			if e.budgetSpent(ctx) {
				e.fail("TIME_BUDGET", Request{Asset: en.Asset, CandidateID: c.ID, Sequence: c.Sequence, Purpose: "FOLLOW_UP", LogicalAt: at, ExecutedAt: executed})
				continue
			}
			r, err := e.request(ctx, en, at, executed, "FOLLOW_UP", c)
			if err != nil {
				e.fail(preparationFailure(err), r)
				continue
			}
			x, m, err := e.invoke(ctx, r, faults)
			if err != nil {
				e.fail(failureCode(err), r)
				continue
			}
			if x.Kind == "UPDATE" && slices.ContainsFunc(x.UpdateCodes, func(code string) bool { return !slices.Contains(c.ReservedCodes, code) }) {
				e.stageSourceMutation()
				e.retain(m)
				e.update(c, m, x, e.commitTime(committed))
			}
		}
	}
}

// Reconstruct each retained event after effective entry. Intermediate
// nonterminal state is staged in this same pass; overdue arms receive their
// final disposition before the pass commits.
func (e *Engine) reconstructAfterEntry(ctx context.Context, en *Enrollment, entered, at, executed, committed time.Time, faults []Fault, includeWake bool) {
	e.attemptedGPUWork = true
	times := []time.Time{}
	samples := checkedSamples(ctx)
	if includeWake {
		times = append(times, at)
	}
	for _, f := range e.Facts {
		if f.Asset != en.Asset || f.AvailableAt.After(at) {
			continue
		}
		for _, t := range []time.Time{f.AvailableAt, rawBoundaryWithSamples(f, e.Config.Category, samples)} {
			if t.After(entered) && t.Before(at) {
				times = append(times, t)
			}
		}
	}
	slices.SortFunc(times, time.Time.Compare)
	times = slices.CompactFunc(times, time.Time.Equal)
	for _, event := range times {
		for {
			var next time.Time
			for _, c := range e.Candidates {
				if c.Asset != en.Asset || c.Sequence != en.Sequence || c.Phase != "OBSERVING" {
					continue
				}
				if c.DueAt.Before(event) && (next.IsZero() || c.DueAt.Before(next)) {
					next = c.DueAt
				}
			}
			if next.IsZero() {
				break
			}
			e.applyArmEvent(ctx, en, next, executed, committed, faults, false, true)
		}
		priorSequence := int64(0)
		if en.Active {
			priorSequence = en.Sequence
			e.followTracker(ctx, en, event, executed, faults)
			e.applyArmEvent(ctx, en, event, executed, committed, faults, true, event.Before(at))
		} else {
			e.discover(ctx, en, event, executed, committed, faults, event.Before(at))
		}
		e.qualifiedTelemetry(ctx, en, event, priorSequence)
		en.ProcessedAt = event
	}
}

type ReplayError struct{ Code string }

func (e *ReplayError) Error() string { return e.Code }

func ParseSuite(data []byte, registry *Registry) (Suite, error) {
	var s Suite
	if err := DecodeStrict(data, &s, 16<<20); err != nil {
		return s, fmt.Errorf("%w: inline fixture", ErrInvalid)
	}
	normalized, err := NormalizeConfig(context.Background(), s.Config, registry)
	if err != nil {
		return s, err
	}
	s.Config = normalized
	return s, validateSuite(s, registry)
}

func validateSuite(s Suite, registry *Registry) error {
	if s.Schema != 1 || s.StartAt.IsZero() || !validReplayProvenance(s.Provenance) {
		return ErrInvalid
	}
	if err := s.Config.Validate(context.Background(), registry); err != nil {
		return err
	}
	if s.Config.usesUpload() && s.Provenance != "OBSERVED_AVAILABILITY" {
		return ErrInvalid
	}
	if len(s.Facts) > 200000 || len(s.Labels) > 200000 || len(s.Legacy) > 200000 || len(s.Faults) > 200000 || len(s.Expected) > 200000 {
		return ErrInvalid
	}
	if err := ValidateLabels(s); err != nil {
		return err
	}
	start := clock(s.StartAt)
	end := start.Add(time.Duration(s.Config.RunDurationSeconds) * time.Second)
	assets := map[string]bool{}
	for _, a := range s.Config.Assets {
		assets[a.EntityKey] = true
	}
	expectedKeys := map[string]bool{}
	for _, x := range s.Expected {
		if !assets[x.Asset] || x.Sequence <= 0 || !slices.Contains(Budgets[:], x.BudgetMS) || x.LogicalAt.Before(start) || x.LogicalAt.After(end.Add(120*time.Second)) || !slices.Contains([]string{"NONE", "INVESTIGATE", "URGENT"}, x.Action) {
			return ErrInvalid
		}
		if x.DecisionSource != "CATEGORY" && x.DecisionSource != "HOST_FALLBACK" || x.DecisionSource == "CATEGORY" && !ValidID(x.Outcome, 128) || x.DecisionSource == "HOST_FALLBACK" && (x.Outcome != "" || x.Action != "INVESTIGATE") {
			return ErrInvalid
		}
		k := fmt.Sprintf("%s:%d:%d", x.Asset, x.Sequence, x.BudgetMS)
		if expectedKeys[k] {
			return ErrInvalid
		}
		expectedKeys[k] = true
	}
	faultKeys := map[string]bool{}
	for _, f := range s.Faults {
		if !assets[f.Asset] || f.At.Before(start) || f.At.After(end.Add(120*time.Second)) || !slices.Contains([]string{"DISCOVER", "ASSESS", "FOLLOW_UP"}, f.Purpose) || !slices.Contains([]string{"PANIC", "MALFORMED_RESULT", "TIME_BUDGET", "UNSUPPORTED_VERSION", "STORE_UNAVAILABLE"}, f.Code) {
			return ErrInvalid
		}
		if f.BudgetMS != nil && (!slices.Contains(Budgets[:], *f.BudgetMS) || f.Purpose == "DISCOVER") || f.BudgetMS == nil && f.Purpose == "ASSESS" {
			return ErrInvalid
		}
		if f.Code == "STORE_UNAVAILABLE" && (f.Until == nil || !f.Until.After(f.At)) || f.Code != "STORE_UNAVAILABLE" && f.Until != nil {
			return ErrInvalid
		}
		budget := ""
		if f.BudgetMS != nil {
			budget = fmt.Sprint(*f.BudgetMS)
		}
		k := fmt.Sprintf("%s:%s:%s:%s", f.Asset, clock(f.At).Format(time.RFC3339Nano), f.Purpose, budget)
		if faultKeys[k] {
			return ErrInvalid
		}
		faultKeys[k] = true
	}
	for _, f := range s.Facts {
		if !assets[f.Asset] || f.Run != s.Config.RunID || f.AvailableAt.Before(start) || !f.AvailableAt.Before(end) || f.Kind == "TRACKER_CONTEXT" || f.Kind == "FEATURE" {
			return ErrInvalid
		}
		h, err := FactIdentity(s.Config.Category, f)
		if err != nil || h != f.ID {
			return ErrInvalid
		}
	}
	return nil
}

func validReplayProvenance(p string) bool {
	return slices.Contains([]string{"SYNTHETIC", "SOURCE_TIME_SIMULATION", "OBSERVED_AVAILABILITY"}, p)
}

func Replay(ctx context.Context, s Suite, registry *Registry) (*Engine, error) {
	if err := validateSuite(s, registry); err != nil {
		return nil, err
	}
	e, err := NewEngine(ctx, s.Config, s.StartAt, registry)
	if err != nil {
		return nil, err
	}
	facts := append([]Fact{}, s.Facts...)
	for i := range facts {
		facts[i].AvailableAt = clock(facts[i].AvailableAt)
	}
	slices.SortStableFunc(facts, func(a, b Fact) int {
		if c := a.AvailableAt.Compare(b.AvailableAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	faults := append([]Fault{}, s.Faults...)
	events := []time.Time{}
	for i := range faults {
		f := &faults[i]
		f.At = clock(f.At)
		events = append(events, f.At)
		if f.Until != nil {
			until := clock(*f.Until)
			f.Until = &until
			events = append(events, until)
		}
	}
	for _, f := range facts {
		events = append(events, f.AvailableAt)
		if t := rawBoundary(f); t.After(f.AvailableAt) {
			events = append(events, t)
		}
	}
	slices.SortFunc(events, time.Time.Compare)
	events = slices.CompactFunc(events, time.Time.Equal)
	cursor, eventCursor := 0, 0
	for at := e.StartAt; e.State != "CLOSED"; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var unavailable *Fault
		for i := range faults {
			f := &faults[i]
			if f.Code == "STORE_UNAVAILABLE" && !at.Before(f.At) && at.Before(*f.Until) && (unavailable == nil || f.Until.After(*unavailable.Until)) {
				unavailable = f
			}
		}
		if unavailable != nil {
			e.recordFailureWindow("STORE_UNAVAILABLE", unavailable.Asset, unavailable.Purpose, "", *unavailable.Until, "", nil, unavailable.At, *unavailable.Until)
			at = *unavailable.Until
			continue
		}
		batch := []Fact{}
		for cursor < len(facts) && !facts[cursor].AvailableAt.After(at) {
			f := facts[cursor]
			cursor++
			// A selected snapshot rolled back during a synthetic store outage. The
			// retry receives its new admission clock and never backdates evidence.
			for _, fault := range faults {
				if fault.Code == "STORE_UNAVAILABLE" && !f.AvailableAt.Before(fault.At) && f.AvailableAt.Before(*fault.Until) {
					f.AvailableAt = at
					break
				}
			}
			if f.AvailableAt.Before(e.AdmissionEndAt) {
				batch = append(batch, f)
			}
		}
		if err = e.Advance(ctx, at, at, at, batch, faults); err != nil {
			return nil, err
		}
		for eventCursor < len(events) && !events[eventCursor].After(at) {
			eventCursor++
		}
		next := e.StartAt.Add((at.Sub(e.StartAt)/time.Second + 1) * time.Second)
		if eventCursor < len(events) && events[eventCursor].Before(next) {
			next = events[eventCursor]
		}
		at = e.nextWake(at, next)
	}
	return e, nil
}

func (e *Engine) nextWake(at, next time.Time) time.Time {
	consider := func(t time.Time) {
		if t.After(at) && t.Before(next) {
			next = t
		}
	}
	consider(e.AdmissionEndAt)
	for _, pending := range e.boundaries {
		if len(pending) > 0 {
			consider(pending[0])
		}
	}
	for _, c := range e.Candidates {
		if c.Phase == "OBSERVING" {
			consider(c.DueAt)
			if c.NextLogicalAt != nil {
				consider(*c.NextLogicalAt)
			}
		}
	}
	for _, en := range e.Enrollments {
		if en.NextLogicalAt != nil {
			consider(*en.NextLogicalAt)
		}
	}
	return next
}

func (e *Engine) trackBoundary(f Fact, at time.Time) {
	t := rawBoundary(f)
	if !t.After(at) {
		return
	}
	pending := e.boundaries[f.Asset]
	i, _ := slices.BinarySearchFunc(pending, t, time.Time.Compare)
	if i < len(pending) && pending[i].Equal(t) {
		return
	}
	e.boundaries[f.Asset] = slices.Insert(pending, i, t)
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func rawBoundary(f Fact) time.Time {
	return rawBoundaryWithSamples(f, "", nil)
}

func rawBoundaryWithSamples(f Fact, category string, samples *factBodyCache) time.Time {
	var t time.Time
	switch f.Kind {
	case "SAMPLE":
		if s, err := samples.decodeForSelection(category, f); err == nil {
			t = s.SourceAt
		}
	case "COVERAGE":
		var c Coverage
		if json.Unmarshal(f.Body, &c) == nil {
			t = c.Through
		}
	case "QUALIFIED":
		var q Qualified
		if json.Unmarshal(f.Body, &q) == nil {
			t = q.QualifiedAt
			for _, s := range q.Snapshot {
				if s.SourceAt.After(t) {
					t = s.SourceAt
				}
			}
		}
	}
	return clock(t)
}

type archiveRunRow struct {
	RunID             string       `json:"run_id"`
	Config            archiveBytes `json:"config"`
	ConfigHash        string       `json:"config_hash"`
	InputConfigHash   string       `json:"input_config_hash,omitempty"`
	Descriptor        archiveBytes `json:"descriptor"`
	DescriptorHash    string       `json:"descriptor_hash"`
	BuildHash         string       `json:"build_hash"`
	Mode              string       `json:"mode"`
	State             string       `json:"state"`
	StartAt           time.Time    `json:"start_at"`
	AdmissionEndAt    time.Time    `json:"admission_end_at"`
	StoppedAt         *time.Time   `json:"stopped_at,omitempty"`
	StopReason        string       `json:"stop_reason,omitempty"`
	ClosedAt          *time.Time   `json:"closed_at,omitempty"`
	LastSuccessAt     *time.Time   `json:"last_success_at,omitempty"`
	PayloadBytes      int64        `json:"payload_bytes"`
	FactCount         int64        `json:"fact_count"`
	PhysicalCount     int64        `json:"physical_count"`
	RecordCount       int64        `json:"record_count"`
	OverflowCount     int64        `json:"overflow_count"`
	UnknownFrom       *time.Time   `json:"unknown_from,omitempty"`
	UnknownThrough    *time.Time   `json:"unknown_through,omitempty"`
	Coverage          archiveBytes `json:"coverage"`
	IncompleteCount   int64        `json:"incomplete_count"`
	FollowupTruncated bool         `json:"followup_truncated"`
}
type archiveEnrollmentsRow struct {
	RunID             string       `json:"run_id"`
	Category          string       `json:"category"`
	Asset             string       `json:"asset"`
	NodeID            string       `json:"node_id"`
	GPUUUID           string       `json:"gpu_uuid"`
	InventoryRevision string       `json:"inventory_revision"`
	Bindings          archiveBytes `json:"bindings"`
	DiscoveryFloor    time.Time    `json:"discovery_floor"`
	NextDueAt         time.Time    `json:"next_due_at"`
	LastAttemptAt     *time.Time   `json:"last_attempt_at,omitempty"`
	Sequence          int64        `json:"sequence"`
	Revision          int64        `json:"revision"`
	RearmEligible     bool         `json:"rearm_eligible"`
	Tracker           archiveBytes `json:"tracker,omitempty"`
	TrackerHash       string       `json:"tracker_hash,omitempty"`
}
type archiveFactsRow struct {
	RunID       string       `json:"run_id"`
	ID          string       `json:"id"`
	Asset       string       `json:"asset"`
	Kind        string       `json:"kind"`
	AvailableAt time.Time    `json:"available_at"`
	Body        archiveBytes `json:"body"`
}
type archiveBundlesRow struct {
	RunID              string       `json:"run_id"`
	ID                 string       `json:"id"`
	Asset              string       `json:"asset"`
	LogicalAt          time.Time    `json:"logical_at"`
	AvailabilityCutoff time.Time    `json:"availability_cutoff"`
	Body               archiveBytes `json:"body"`
}
type archiveCandidatesRow struct {
	RunID         string       `json:"run_id"`
	ID            string       `json:"id"`
	Category      string       `json:"category"`
	Asset         string       `json:"asset"`
	Sequence      int64        `json:"sequence"`
	BudgetMS      int64        `json:"budget_ms"`
	Revision      int64        `json:"revision"`
	Phase         string       `json:"phase"`
	EnteredAt     time.Time    `json:"entered_at"`
	DueAt         time.Time    `json:"due_at"`
	EntryBundle   string       `json:"entry_bundle"`
	Entry         archiveBytes `json:"entry"`
	InitialState  archiveBytes `json:"initial_state"`
	InitialHash   string       `json:"initial_hash"`
	State         archiveBytes `json:"state"`
	StateHash     string       `json:"state_hash"`
	TerminalID    string       `json:"terminal_id,omitempty"`
	Terminal      archiveBytes `json:"terminal,omitempty"`
	ReservedCodes []string     `json:"reserved_codes"`
}
type archiveDecisionsRow struct {
	RunID          string       `json:"run_id"`
	ID             string       `json:"id"`
	CandidateID    string       `json:"candidate_id"`
	Kind           string       `json:"kind"`
	LogicalAt      time.Time    `json:"logical_at"`
	ExecutedAt     time.Time    `json:"executed_at"`
	CommittedAt    time.Time    `json:"committed_at"`
	LatenessUS     int64        `json:"lateness_us"`
	Action         string       `json:"action"`
	DecisionSource string       `json:"decision_source"`
	Outcome        string       `json:"outcome,omitempty"`
	HostCause      string       `json:"host_cause,omitempty"`
	FailureCode    string       `json:"failure_code,omitempty"`
	BundleID       string       `json:"bundle_id"`
	Codes          []string     `json:"codes"`
	Reasons        []string     `json:"reasons"`
	Support        []string     `json:"support"`
	Summary        string       `json:"summary"`
	Details        archiveBytes `json:"details,omitempty"`
	DetailsHash    string       `json:"details_hash,omitempty"`
	Metadata       archiveBytes `json:"metadata"`
}
type archiveFailuresRow struct {
	RunID    string       `json:"run_id"`
	ID       string       `json:"id"`
	Category string       `json:"category,omitempty"`
	Asset    string       `json:"asset,omitempty"`
	Kind     string       `json:"kind"`
	Code     string       `json:"code"`
	ScopeKey string       `json:"scope_key"`
	FirstAt  time.Time    `json:"first_at"`
	LastAt   time.Time    `json:"last_at"`
	Count    int64        `json:"count"`
	Body     archiveBytes `json:"body"`
}

const (
	archiveChunkLimit    = 8 << 20
	archiveRecordLimit   = 384 << 10
	archiveManifestLimit = 256 << 10
	archiveByteLimit     = 2 << 30
)

var archiveSections = [...]string{"run", "enrollments", "facts", "bundles", "candidates", "decisions", "failures"}

type ArchiveMetadata struct {
	RunID              string
	ConfigHash         string
	Provenance         string
	SourcePayloadBytes int64
	RecordCount        int64
}

type ArchiveSource interface {
	Metadata() ArchiveMetadata
	Next(context.Context) (ArchiveRow, error)
	Close(context.Context) error
}

type ArchiveRow struct {
	Table string          `json:"table"`
	Key   string          `json:"key"`
	Body  json.RawMessage `json:"body"`
}

type ArchiveChunk struct {
	File    string `json:"file"`
	Bytes   int64  `json:"bytes"`
	SHA256  string `json:"sha256"`
	Records int64  `json:"records"`
	Section string `json:"section"`
}

type ArchiveManifest struct {
	Schema             int64          `json:"schema"`
	RunID              string         `json:"run_id"`
	ConfigHash         string         `json:"config_hash"`
	Provenance         string         `json:"provenance"`
	SourcePayloadBytes int64          `json:"source_payload_bytes"`
	RecordCount        int64          `json:"record_count"`
	Chunks             []ArchiveChunk `json:"chunks"`
	Complete           bool           `json:"complete"`
}

type archiveBytes string

func decodeArchiveBytes(v archiveBytes, max int) ([]byte, error) {
	if len(v) == 0 || len(v) > base64.StdEncoding.EncodedLen(max) {
		return nil, ErrInvalid
	}
	b, err := base64.StdEncoding.Strict().DecodeString(string(v))
	if err != nil || len(b) == 0 || len(b) > max || base64.StdEncoding.EncodeToString(b) != string(v) {
		return nil, ErrInvalid
	}
	return b, nil
}

func decodeArchivePayload(v archiveBytes, max int, dst any) error {
	b, err := decodeArchiveBytes(v, max)
	if err != nil {
		return err
	}
	if err = DecodeStrict(b, dst, max); err != nil {
		return ErrInvalid
	}
	canon, err := Canonical(reflect.ValueOf(dst).Elem().Interface())
	if err != nil || !bytes.Equal(b, canon) {
		return ErrInvalid
	}
	return nil
}

func decodeArchiveRow(row ArchiveRow) (any, int64, error) {
	var dst any
	switch row.Table {
	case "run":
		dst = &archiveRunRow{}
	case "enrollments":
		dst = &archiveEnrollmentsRow{}
	case "facts":
		dst = &archiveFactsRow{}
	case "bundles":
		dst = &archiveBundlesRow{}
	case "candidates":
		dst = &archiveCandidatesRow{}
	case "decisions":
		dst = &archiveDecisionsRow{}
	case "failures":
		dst = &archiveFailuresRow{}
	default:
		return nil, 0, ErrInvalid
	}
	if err := DecodeStrict(row.Body, dst, archiveRecordLimit); err != nil {
		return nil, 0, ErrInvalid
	}
	v := reflect.ValueOf(dst).Elem()
	keyField := "ID"
	if row.Table == "run" {
		keyField = "RunID"
	}
	if row.Table == "enrollments" {
		keyField = "Asset"
	}
	if row.Key != v.FieldByName(keyField).String() || !ValidID(row.Key, 256) {
		return nil, 0, ErrInvalid
	}
	if row.Table != "run" && row.Table != "enrollments" && !ValidHash(row.Key) {
		return nil, 0, ErrInvalid
	}
	if !ValidID(v.FieldByName("RunID").String(), 128) {
		return nil, 0, ErrInvalid
	}
	var present map[string]json.RawMessage
	if err := json.Unmarshal(row.Body, &present); err != nil {
		return nil, 0, ErrInvalid
	}
	if run, ok := dst.(*archiveRunRow); ok {
		if _, exists := present["input_config_hash"]; exists && !ValidHash(run.InputConfigHash) {
			return nil, 0, ErrInvalid
		}
	}
	var n int64
	for i := range v.NumField() {
		col := v.Field(i)
		key, _, _ := strings.Cut(v.Type().Field(i).Tag.Get("json"), ",")
		if _, ok := present[key]; !ok {
			continue
		}
		switch typed := col.Interface().(type) {
		case archiveBytes:
			b, err := decodeArchiveBytes(typed, archiveRecordLimit)
			if err != nil {
				return nil, 0, err
			}
			n += int64(len(b))
		case string:
			n += int64(len(typed))
		case time.Time:
			if typed.IsZero() || typed != clock(typed) {
				return nil, 0, ErrInvalid
			}
			n += 8
		case *time.Time:
			if typed == nil || typed.IsZero() || *typed != clock(*typed) {
				return nil, 0, ErrInvalid
			}
			n += 8
		case int64:
			n += 8
		case bool:
			n++
		case []string:
			b, err := Canonical(typed)
			if err != nil {
				return nil, 0, err
			}
			n += int64(len(b))
		default:
			return nil, 0, ErrInvalid
		}
	}
	return dst, n, nil
}

// ArchiveRowPayloadBytes returns the exact accounting for one physical row.
func ArchiveRowPayloadBytes(row ArchiveRow) (int64, error) {
	_, n, err := decodeArchiveRow(row)
	return n, err
}

// PrivateDirectory creates a new report directory and marks it incomplete
// until the caller has written its final manifest.
func PrivateDirectory(path string) error {
	if err := os.Mkdir(path, 0700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return &ReplayError{Code: "OUTPUT_EXISTS"}
		}
		return err
	}
	return os.WriteFile(filepath.Join(path, "INCOMPLETE"), []byte("INCOMPLETE\n"), 0600)
}

func OpenPrivateFile(dir, name string) (*os.File, error) {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return nil, ErrInvalid
	}
	return os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
}

func CompletePrivateDirectory(dir string, manifest any) error {
	b, err := Canonical(manifest)
	if err != nil {
		return err
	}
	f, err := OpenPrivateFile(dir, "manifest.tmp")
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(b, '\n'))
	syncErr := f.Sync()
	closeErr := f.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	marker := filepath.Join(dir, "INCOMPLETE")
	if err = os.Remove(marker); err != nil {
		return err
	}
	if err = os.Rename(filepath.Join(dir, "manifest.tmp"), filepath.Join(dir, "manifest.json")); err != nil {
		_ = os.WriteFile(marker, []byte("INCOMPLETE\n"), 0600)
		return err
	}
	return nil
}

// WriteArchive consumes only the selected read-only run snapshot. Complete
// manifests become visible after every validated chunk is safely written.
func WriteArchive(ctx context.Context, dir string, source ArchiveSource) (ArchiveManifest, error) {
	meta := source.Metadata()
	m := ArchiveManifest{Schema: 1, RunID: meta.RunID, ConfigHash: meta.ConfigHash, Provenance: meta.Provenance, Chunks: []ArchiveChunk{}}
	if !ValidID(meta.RunID, 128) || !ValidHash(meta.ConfigHash) || !validReplayProvenance(meta.Provenance) || meta.RecordCount < 1 || meta.RecordCount > 1000000 || meta.SourcePayloadBytes < 1 || meta.SourcePayloadBytes > 512<<20 {
		return m, ErrInvalid
	}
	if err := PrivateDirectory(dir); err != nil {
		return m, err
	}
	var chunk bytes.Buffer
	var current ArchiveChunk
	var totalBytes int64
	flush := func() error {
		if chunk.Len() == 0 {
			return nil
		}
		if len(m.Chunks) >= 248 || totalBytes+int64(chunk.Len()) > archiveByteLimit {
			return ErrInvalid
		}
		current.File = fmt.Sprintf("data-%04d.ndjson", len(m.Chunks))
		current.Bytes = int64(chunk.Len())
		current.SHA256 = fmt.Sprintf("%x", sha256.Sum256(chunk.Bytes()))
		f, err := OpenPrivateFile(dir, current.File)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(chunk.Bytes())
		if err = errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
			return err
		}
		totalBytes += current.Bytes
		m.Chunks = append(m.Chunks, current)
		current = ArchiveChunk{}
		chunk.Reset()
		return nil
	}
	order := archiveOrder{section: -1}
	for {
		if err := ctx.Err(); err != nil {
			return m, err
		}
		row, err := source.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, err
		}
		data, err := Canonical(row)
		if err != nil || len(data)+1 > archiveRecordLimit {
			return m, ErrInvalid
		}
		cols, n, err := decodeArchiveRow(row)
		if err != nil || order.accept(row, cols, meta.RunID) != nil {
			return m, ErrInvalid
		}
		if chunk.Len() > 0 && (current.Section != row.Table || chunk.Len()+len(data)+1 > archiveChunkLimit) {
			if err := flush(); err != nil {
				return m, err
			}
		}
		current.Section = row.Table
		current.Records++
		chunk.Write(data)
		chunk.WriteByte('\n')
		m.SourcePayloadBytes += n
		m.RecordCount++
		if m.SourcePayloadBytes > meta.SourcePayloadBytes || m.RecordCount > meta.RecordCount {
			return m, ErrInvalid
		}
	}
	if m.SourcePayloadBytes != meta.SourcePayloadBytes || m.RecordCount != meta.RecordCount {
		return m, ErrInvalid
	}
	if err := flush(); err != nil {
		return m, err
	}
	m.Complete = true
	if err := CompletePrivateDirectory(dir, m); err != nil {
		m.Complete = false
		return m, err
	}
	return m, nil
}

type archiveOrder struct {
	section int
	key     string
	at      time.Time
	runSeen bool
}

func (o *archiveOrder) accept(r ArchiveRow, row any, run string) error {
	section := slices.Index(archiveSections[:], r.Table)
	if !o.runSeen && section != 0 || section < o.section || section == 0 && o.runSeen ||
		reflect.ValueOf(row).Elem().FieldByName("RunID").String() != run {
		return ErrInvalid
	}
	var at time.Time
	if v, ok := row.(*archiveFactsRow); ok {
		at = v.AvailableAt
	}
	if section == o.section && (at.Before(o.at) || at.Equal(o.at) && r.Key <= o.key) {
		return ErrInvalid
	}
	o.section, o.at, o.key, o.runSeen = section, at, r.Key, true
	return nil
}

// ReadLocalFile rejects symlinks and non-regular files and keeps the physical
// size check coupled to the opened file descriptor.
func ReadLocalFile(path string, max int64) ([]byte, error) {
	file, err := openLocalFile(path, max)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrInvalid
	}
	return b, nil
}

func openLocalFile(path string, max int64) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > max {
		return nil, ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	actual, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !actual.Mode().IsRegular() || !os.SameFile(info, actual) || actual.Size() > max {
		file.Close()
		return nil, ErrInvalid
	}
	return file, nil
}

type archiveIndexEntry struct {
	hash                  [32]byte
	chunk, offset, length uint32
	_                     uint32
}
type archiveBundleChunk struct {
	chunk       int
	first, last string
}

type archiveReader struct {
	manifest ArchiveManifest
	files    []*os.File
	facts    []archiveIndexEntry
	bundles  []archiveBundleChunk
	run      archiveRunRow
}

func (r *archiveReader) close() {
	for _, f := range r.files {
		_ = f.Close()
	}
}

func readArchive(ctx context.Context, dir string) (*archiveReader, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalid
	}
	b, err := ReadLocalFile(filepath.Join(dir, "manifest.json"), archiveManifestLimit)
	if err != nil {
		return nil, err
	}
	r := &archiveReader{}
	if err = DecodeStrict(b, &r.manifest, archiveManifestLimit); err != nil {
		return nil, fmt.Errorf("%w: archive manifest", ErrInvalid)
	}
	m := r.manifest
	if m.Schema != 1 || !m.Complete || !ValidID(m.RunID, 128) || !ValidHash(m.ConfigHash) || !validReplayProvenance(m.Provenance) || m.SourcePayloadBytes < 1 || m.SourcePayloadBytes > 512<<20 || m.RecordCount < 1 || m.RecordCount > 1000000 || len(m.Chunks) < 1 || len(m.Chunks) > 248 {
		return nil, ErrInvalid
	}
	listed, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(listed) != len(m.Chunks)+1 {
		return nil, ErrInvalid
	}
	ok := false
	defer func() {
		if !ok {
			r.close()
		}
	}()
	var bytesRead, records, payload int64
	for i, c := range m.Chunks {
		if c.File != fmt.Sprintf("data-%04d.ndjson", i) || !ValidHash(c.SHA256) || c.Bytes < 1 || c.Bytes > archiveChunkLimit || c.Records < 1 || !slices.Contains(archiveSections[:], c.Section) {
			return nil, ErrInvalid
		}
		bytesRead += c.Bytes
		if bytesRead > archiveByteLimit {
			return nil, ErrInvalid
		}
		f, err := openLocalFile(filepath.Join(dir, c.File), archiveChunkLimit)
		if err != nil {
			return nil, err
		}
		r.files = append(r.files, f)
		h := sha256.New()
		n, err := io.Copy(h, io.NewSectionReader(f, 0, c.Bytes+1))
		if err != nil {
			return nil, err
		}
		if n != c.Bytes || fmt.Sprintf("%x", h.Sum(nil)) != c.SHA256 {
			return nil, ErrInvalid
		}
	}
	order := archiveOrder{section: -1}
	if err := r.each(ctx, "", func(chunk, offset, length int, row ArchiveRow, cols any, n int64) error {
		if err := order.accept(row, cols, m.RunID); err != nil {
			return err
		}
		records++
		payload += n
		if records > m.RecordCount || payload > m.SourcePayloadBytes {
			return ErrInvalid
		}
		switch v := cols.(type) {
		case *archiveRunRow:
			r.run = *v
			if v.State != "CLOSED" || v.ClosedAt == nil || v.ConfigHash != m.ConfigHash || v.RecordCount != m.RecordCount || v.PayloadBytes != m.SourcePayloadBytes || v.FactCount > 200000 || !ValidHash(v.BuildHash) || v.InputConfigHash != "" && !ValidHash(v.InputConfigHash) || !v.StartAt.Before(v.AdmissionEndAt) {
				return ErrInvalid
			}
		case *archiveFactsRow:
			if len(r.facts) >= 200000 {
				return ErrInvalid
			}
			raw, _ := hex.DecodeString(v.ID)
			ref := archiveIndexEntry{chunk: uint32(chunk), offset: uint32(offset), length: uint32(length)}
			copy(ref.hash[:], raw)
			r.facts = append(r.facts, ref)
		case *archiveBundlesRow:
			last := len(r.bundles) - 1
			if last < 0 || r.bundles[last].chunk != chunk {
				r.bundles = append(r.bundles, archiveBundleChunk{chunk, row.Key, row.Key})
			} else {
				r.bundles[last].last = row.Key
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if records != m.RecordCount || payload != m.SourcePayloadBytes || int64(len(r.facts)) != r.run.FactCount {
		return nil, ErrInvalid
	}
	slices.SortFunc(r.facts, func(a, b archiveIndexEntry) int { return bytes.Compare(a.hash[:], b.hash[:]) })
	for i := 1; i < len(r.facts); i++ {
		if r.facts[i].hash == r.facts[i-1].hash {
			return nil, ErrInvalid
		}
	}
	ok = true
	return r, nil
}

func (r *archiveReader) each(ctx context.Context, section string, visit func(chunk, offset, length int, row ArchiveRow, cols any, n int64) error) error {
	for i, c := range r.manifest.Chunks {
		if section != "" && c.Section != section {
			continue
		}
		if err := r.scan(ctx, i, visit); err != nil {
			return err
		}
	}
	return nil
}

func (r *archiveReader) scan(ctx context.Context, i int, visit func(chunk, offset, length int, row ArchiveRow, cols any, n int64) error) error {
	c := r.manifest.Chunks[i]
	reader := bufio.NewReaderSize(io.NewSectionReader(r.files[i], 0, c.Bytes), archiveRecordLimit)
	offset, count := 0, int64(0)
	for int64(offset) < c.Bytes {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := reader.ReadSlice('\n')
		if err != nil || len(line) > archiveRecordLimit {
			return ErrInvalid
		}
		row, cols, n, err := parseArchiveLine(line)
		if err != nil || row.Table != c.Section {
			return ErrInvalid
		}
		if err = visit(i, offset, len(line), row, cols, n); err != nil {
			if errors.Is(err, errArchiveFound) {
				return err
			}
			return fmt.Errorf("validate archive %s row %d: %w", c.Section, count+1, err)
		}
		offset += len(line)
		count++
	}
	if count != c.Records || int64(offset) != c.Bytes {
		return ErrInvalid
	}
	return nil
}

func parseArchiveLine(line []byte) (ArchiveRow, any, int64, error) {
	var row ArchiveRow
	if err := DecodeStrict(line, &row, archiveRecordLimit); err != nil {
		return row, nil, 0, err
	}
	cols, n, err := decodeArchiveRow(row)
	return row, cols, n, err
}

func (r *archiveReader) fact(ctx context.Context, id string) (Fact, bool) {
	var f Fact
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) != 32 {
		return f, false
	}
	i := sort.Search(len(r.facts), func(i int) bool { return bytes.Compare(r.facts[i].hash[:], raw) >= 0 })
	if i == len(r.facts) || !bytes.Equal(r.facts[i].hash[:], raw) {
		return f, false
	}
	ref := r.facts[i]
	line := make([]byte, ref.length)
	if _, err = r.files[ref.chunk].ReadAt(line, int64(ref.offset)); err != nil {
		return f, false
	}
	_, cols, _, err := parseArchiveLine(line)
	if err != nil {
		return f, false
	}
	f, err = r.decodeFact(cols.(*archiveFactsRow))
	return f, err == nil && f.ID == id
}

func (r *archiveReader) decodeFact(v *archiveFactsRow) (Fact, error) {
	var f Fact
	limit := 16 << 10
	if v.Kind == "FEATURE" {
		limit = 64 << 10
	}
	if v.Kind == "TRACKER_CONTEXT" {
		limit = 24 << 10
	}
	if err := decodeArchivePayload(v.Body, limit, &f); err != nil {
		return f, err
	}
	if f.Run != v.RunID || f.Asset != v.Asset || f.Kind != v.Kind || f.ID != v.ID || !f.AvailableAt.Equal(v.AvailableAt) {
		return f, ErrInvalid
	}
	return f, nil
}

var errArchiveFound = errors.New("archive lookup found")

func (r *archiveReader) bundle(ctx context.Context, id string) (Bundle, bool) {
	var b Bundle
	i := sort.Search(len(r.bundles), func(i int) bool { return r.bundles[i].last >= id })
	if i == len(r.bundles) || r.bundles[i].first > id {
		return b, false
	}
	chunk := r.bundles[i].chunk
	err := r.scan(ctx, chunk, func(_, _, _ int, row ArchiveRow, cols any, _ int64) error {
		if row.Key != id {
			return nil
		}
		var err error
		b, err = r.decodeBundle(cols.(*archiveBundlesRow))
		if err != nil {
			return err
		}
		return errArchiveFound
	})
	return b, errors.Is(err, errArchiveFound)
}

func (r *archiveReader) decodeBundle(v *archiveBundlesRow) (Bundle, error) {
	var b Bundle
	if err := decodeArchivePayload(v.Body, 256<<10, &b); err != nil {
		return b, err
	}
	if b.Run != v.RunID || b.Asset != v.Asset || b.ID != v.ID || !b.LogicalAt.Equal(v.LogicalAt) || !b.AvailabilityCutoff.Equal(v.AvailabilityCutoff) {
		return b, ErrInvalid
	}
	return b, nil
}

type ArchiveReplay struct {
	Ideal                  *Engine
	Observed               *Engine
	Manifest               ArchiveManifest
	ExecutionNotReproduced []string
	Mismatched             []string
}

type archiveDecisionMetadata struct {
	Schema            int64        `json:"schema"`
	Route             string       `json:"route"`
	TerminalEndpoint  *FeatureRef  `json:"terminal_endpoint,omitempty"`
	UrgentOccurrences []Occurrence `json:"urgent_occurrences"`
}

type archiveDiagnostic struct {
	Schema   int64     `json:"schema"`
	BundleID string    `json:"bundle_id,omitempty"`
	FactIDs  []string  `json:"fact_ids"`
	Message  string    `json:"message"`
	From     time.Time `json:"from"`
	Through  time.Time `json:"through"`
}

type archiveTelemetryBody struct {
	Schema           int64  `json:"schema"`
	PolicyID         string `json:"policy_id"`
	Occurrence       int64  `json:"occurrence"`
	Disposition      string `json:"disposition"`
	PhysicalSequence int64  `json:"physical_sequence,omitempty"`
	OpenFact         string `json:"open_fact"`
	RecoverFact      string `json:"recover_fact,omitempty"`
	BundleID         string `json:"bundle_id"`
	Summary          string `json:"summary"`
	PreviewID        string `json:"preview_id,omitempty"`
}

func (r *archiveReader) refs(ctx context.Context, ids []string) (map[string]Fact, error) {
	out := make(map[string]Fact, len(ids))
	queue := slices.Clone(ids)
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if _, ok := out[id]; ok {
			continue
		}
		if len(out) >= MaxFacts {
			return nil, ErrInvalid
		}
		f, ok := r.fact(ctx, id)
		if !ok {
			return nil, ErrInvalid
		}
		out[id] = f
		queue = append(queue, factRefs(f)...)
	}
	return out, nil
}

func archivePayload(category, kind string, schema int64, raw archiveBytes, hash string, max int) (Payload, error) {
	b, err := decodeArchiveBytes(raw, max)
	if err != nil {
		return Payload{}, err
	}
	p, err := NewPayload(category, kind, schema, json.RawMessage(b))
	if err != nil || p.Hash != hash || !bytes.Equal(p.Body, b) {
		return Payload{}, ErrInvalid
	}
	return p, nil
}

func ReplayArchive(ctx context.Context, dir string, registry *Registry) (ArchiveReplay, error) {
	return ReplayArchiveWithEvidence(ctx, dir, registry, nil)
}

// ReplayArchiveWithEvidence streams newly generated ideal evidence into the
// optional writer. Archived raw evidence remains in the input archive.
func ReplayArchiveWithEvidence(ctx context.Context, dir string, registry *Registry, evidence io.Writer) (ArchiveReplay, error) {
	result := ArchiveReplay{ExecutionNotReproduced: []string{}, Mismatched: []string{}}
	reader, err := readArchive(ctx, dir)
	if err != nil {
		return result, err
	}
	defer reader.close()
	result.Manifest = reader.manifest
	var c Config
	if err = decodeArchivePayload(reader.run.Config, 64<<10, &c); err != nil {
		return result, err
	}
	if _, _, _, err := registry.LookupVersion(c.Category, c.Implementation); err != nil {
		return result, &ReplayError{Code: "REPLAY_UNAVAILABLE"}
	}
	normalized, normalizeErr := NormalizeConfig(ctx, c, registry)
	if normalizeErr != nil {
		return result, normalizeErr
	}
	oldConfig, _ := Canonical(c)
	normalizedConfig, _ := Canonical(normalized)
	if !bytes.Equal(oldConfig, normalizedConfig) {
		return result, ErrInvalid
	}
	c = normalized
	if c.usesUpload() && reader.manifest.Provenance != "OBSERVED_AVAILABILITY" {
		return result, ErrInvalid
	}
	configHash, err := c.Hash()
	if err != nil || reader.run.PayloadBytes > c.Limits.PayloadBytes || reader.run.FactCount > c.Limits.FactCount || reader.run.PhysicalCount > c.Limits.PhysicalCandidates || configHash != reader.run.ConfigHash || c.RunID != reader.run.RunID || !reader.run.AdmissionEndAt.Equal(reader.run.StartAt.Add(time.Duration(c.RunDurationSeconds)*time.Second)) {
		return result, ErrInvalid
	}
	var d Descriptor
	if err = decodeArchivePayload(reader.run.Descriptor, 16<<10, &d); err != nil {
		return result, err
	}
	dh, err := Identity("descriptor", d.Category, d)
	if err != nil || dh != reader.run.DescriptorHash {
		return result, ErrInvalid
	}
	ideal, err := NewEngine(ctx, c, reader.run.StartAt, registry)
	if err != nil || ideal.descriptorHash != reader.run.DescriptorHash {
		return result, &ReplayError{Code: "REPLAY_UNAVAILABLE"}
	}
	observed, err := NewEngine(ctx, c, reader.run.StartAt, registry)
	if err != nil {
		return result, err
	}
	observed.Shadow = true
	observed.State, observed.ClosedAt, observed.StopReason = reader.run.State, *reader.run.ClosedAt, reader.run.StopReason
	ideal.RecordedBuildHash = reader.run.BuildHash
	observed.RecordedBuildHash = reader.run.BuildHash
	observed.FailureOverflow, observed.FollowupTruncated = reader.run.OverflowCount, reader.run.FollowupTruncated
	observed.LookupFact, observed.LookupBundle = reader.fact, reader.bundle
	if err = reader.validateObserved(ctx, observed); err != nil {
		return result, fmt.Errorf("validate observed assessment: %w", err)
	}
	ideal.LookupFact, ideal.LookupBundle = reader.fact, reader.bundle
	ideal.archiveInput = true
	if evidence != nil {
		ideal.archiveEvidence = json.NewEncoder(evidence)
	}
	if err := decodeArchivePayload(reader.run.Coverage, 256<<10, &observed.CoverageIntervals); err != nil || len(observed.CoverageIntervals) > 1024 {
		return result, ErrInvalid
	}
	for _, gap := range observed.CoverageIntervals {
		if gap.Count < 1 || gap.From.After(gap.Through) || !ValidID(gap.Code, 128) {
			return result, ErrInvalid
		}
	}
	ideal.CoverageIntervals = observed.CoverageIntervals
	ideal.archiveSticky = observed.archiveSticky
	ideal.archiveInputBound = map[string]time.Time{}
	ideal.UnknownFrom, ideal.UnknownThrough = reader.run.UnknownFrom, reader.run.UnknownThrough
	observed.UnknownFrom, observed.UnknownThrough = reader.run.UnknownFrom, reader.run.UnknownThrough
	if err = reader.runIdeal(ctx, ideal); err != nil {
		return result, fmt.Errorf("reconstruct ideal assessment: %w", err)
	}
	affected := map[string]bool{}
	gaps := archiveUncertainIntervals(observed)
	stop := observed.AdmissionEndAt
	if reader.run.StoppedAt != nil && reader.run.StoppedAt.Before(stop) {
		stop = *reader.run.StoppedAt
	}
	for _, ledger := range []*Engine{observed, ideal} {
		for _, c := range ledger.Candidates {
			if c.Phase == "QUARANTINED" {
				affected[c.ID] = true
				continue
			}
			through := archiveFollowupThrough(c, ledger, stop)
			if slices.ContainsFunc(gaps, func(gap CoverageInterval) bool {
				return !through.Before(gap.From) && !c.EnteredAt.After(gap.Through)
			}) || observed.FailureOverflow > 0 && observed.UnknownFrom == nil {
				affected[c.ID] = true
			}
			for _, f := range observed.Failures {
				if archiveFailureAffects(f, c, through) {
					affected[c.ID] = true
					break
				}
			}
		}
	}
	for id := range affected {
		result.ExecutionNotReproduced = append(result.ExecutionNotReproduced, id)
	}
	seen := map[string]Decision{}
	for _, d := range ideal.Decisions {
		seen[d.ID] = d
	}
	for _, want := range observed.Decisions {
		got, ok := seen[want.ID]
		delete(seen, want.ID)
		if affected[want.CandidateID] {
			continue
		}
		if !ok || !equalSemanticDecision(got, want) {
			result.Mismatched = append(result.Mismatched, want.ID)
		}
	}
	for id, d := range seen {
		if !affected[d.CandidateID] {
			result.Mismatched = append(result.Mismatched, id)
		}
	}
	result.ExecutionNotReproduced = SortedUnique(result.ExecutionNotReproduced)
	result.Mismatched = SortedUnique(result.Mismatched)
	// Read-only disk resolvers are valid only while processing the archive.
	// Retain bounded evidence referenced by observed reports before closing.
	if err := reader.copyPresentationEvidence(ctx, observed); err != nil {
		return result, err
	}
	if err := reader.copyPresentationEvidence(ctx, ideal); err != nil {
		return result, err
	}
	ideal.LookupFact, ideal.LookupBundle = nil, nil
	ideal.archiveEvidence = nil
	ideal.archiveSticky = [8][]archiveQualificationRef{}
	observed.archiveSticky = [8][]archiveQualificationRef{}
	observed.LookupFact, observed.LookupBundle = nil, nil
	result.Ideal, result.Observed = ideal, observed
	return result, nil
}

func archiveUncertainIntervals(e *Engine) []CoverageInterval {
	var gaps []CoverageInterval
	for _, gap := range e.CoverageIntervals {
		if gap.Code == "COVERAGE" || gap.Code == "CAPACITY" || gap.Code == "DEADLINE_CAPACITY" || gap.Code == "AUTHORITY_LOST" {
			gaps = append(gaps, gap)
		}
	}
	if e.UnknownFrom == nil || e.UnknownThrough == nil {
		return gaps
	}
	envelope := CoverageInterval{From: *e.UnknownFrom, Through: *e.UnknownThrough, Code: "COVERAGE", Count: 1}
	if len(gaps) == 0 {
		return []CoverageInterval{envelope}
	}
	if e.FailureOverflow == 0 {
		return gaps
	}
	earliest, latest := gaps[0].From, gaps[0].Through
	for _, gap := range gaps[1:] {
		if gap.From.Before(earliest) {
			earliest = gap.From
		}
		if gap.Through.After(latest) {
			latest = gap.Through
		}
	}
	// Once the bounded interval ledger is full its omitted intervals can
	// extend the known envelope. Keep the previous exact gaps, and mark the
	// unrepresented enclosing extents unknown.
	if envelope.From.Before(earliest) {
		prefix := envelope
		prefix.Through = earliest.Add(-time.Microsecond)
		gaps = append(gaps, prefix)
	}
	if envelope.Through.After(latest) {
		suffix := envelope
		suffix.From = latest.Add(time.Microsecond)
		gaps = append(gaps, suffix)
	}
	return gaps
}

func archiveFollowupThrough(c *Candidate, e *Engine, stop time.Time) time.Time {
	through := maxTime(stop, c.DueAt)
	for _, next := range e.Candidates {
		if next.Asset == c.Asset && next.Sequence > c.Sequence && next.EnteredAt.Before(through) {
			through = next.EnteredAt.Add(-time.Microsecond)
		}
	}
	if en := e.Enrollments[c.Asset]; en != nil && !en.Active && en.Sequence == c.Sequence && !en.DiscoveryFloor.Before(c.EnteredAt) && en.DiscoveryFloor.Before(through) {
		// An inactive enrollment's discovery floor is at or after its committed
		// rearm. It supplies an upper bound on this last sequence's follow-up.
		through = en.DiscoveryFloor
	}
	return through
}

func archiveFailureAffects(f Failure, c *Candidate, followupThrough time.Time) bool {
	if f.Code == "COVERAGE" || f.Code == "CONFLICT" || f.Asset != "" && f.Asset != c.Asset {
		return false
	}
	if f.CandidateID != "" {
		return f.CandidateID == c.ID
	}
	from, through := f.FirstAt, f.At
	if f.LogicalFrom != nil {
		from = *f.LogicalFrom
	}
	if f.LogicalThrough != nil {
		through = *f.LogicalThrough
	}
	purpose, seqText, scoped := strings.Cut(f.ScopeKey, "/")
	seq, err := strconv.ParseInt(seqText, 10, 64)
	if f.Code == "CAPACITY" && f.Count > 1 && scoped && (purpose == "DISCOVER" || purpose == "FOLLOW_UP") {
		// The durable body retains first evidence. The latest execution is a
		// conservative upper bound for subsequent omitted logical cutoffs.
		through = maxTime(through, f.At)
	}
	if purpose == "DISCOVER" {
		if scoped && (err != nil || seq+1 != c.Sequence) {
			return false
		}
		return !c.EnteredAt.Before(from) && !c.EnteredAt.After(through)
	}
	if purpose == "FOLLOW_UP" && scoped {
		return err == nil && seq == c.Sequence && !through.Before(c.EnteredAt)
	}
	return !through.Before(c.EnteredAt) && !followupThrough.Before(from)
}

func equalSemanticDecision(a, b Decision) bool {
	for _, d := range []*Decision{&a, &b} {
		d.ExecutedAt, d.CommittedAt, d.LatenessUS = time.Time{}, time.Time{}, 0
	}
	aa, err := Canonical(a)
	if err != nil {
		return false
	}
	bb, err := Canonical(b)
	return err == nil && bytes.Equal(aa, bb)
}

func (r *archiveReader) validateObserved(ctx context.Context, e *Engine) error {
	var enrollmentCount, quarantined int64
	candidates := map[string]*Candidate{}
	terminals := map[string]bool{}
	reservations := map[string][]string{}
	returnErr := r.each(ctx, "", func(_, _, _ int, row ArchiveRow, cols any, _ int64) error {
		switch v := cols.(type) {
		case *archiveEnrollmentsRow:
			en := e.Enrollments[v.Asset]
			if en == nil || v.Category != e.Config.Category || v.InventoryRevision != e.Config.InventoryRevision || v.Revision < 1 || v.DiscoveryFloor.Before(e.StartAt) || v.DiscoveryFloor.After(e.AdmissionEndAt) {
				return ErrInvalid
			}
			i := slices.IndexFunc(e.Config.Assets, func(a Asset) bool { return a.EntityKey == v.Asset })
			if i < 0 || e.Config.Assets[i].GPUUUID != v.GPUUUID || e.Config.Assets[i].NodeID != v.NodeID {
				return ErrInvalid
			}
			var bindings []Binding
			if err := decodeArchivePayload(v.Bindings, 8192, &bindings); err != nil {
				return err
			}
			got, _ := Canonical(bindings)
			want, _ := Canonical(e.Config.Bindings)
			if !bytes.Equal(got, want) {
				return ErrInvalid
			}
			if v.Tracker != "" || v.TrackerHash != "" {
				p, err := archivePayload(e.Config.Category, "tracker", e.descriptor.TrackerSchema, v.Tracker, v.TrackerHash, 16<<10)
				if err != nil {
					return err
				}
				en.Tracker = &p
			}
			en.Sequence, en.Revision, en.Active, en.DiscoveryFloor = v.Sequence, v.Revision, !v.RearmEligible, v.DiscoveryFloor
			enrollmentCount++
		case *archiveFactsRow:
			f, err := r.decodeFact(v)
			if err != nil || e.Enrollments[f.Asset] == nil {
				return ErrInvalid
			}
			index, err := r.refs(ctx, factRefs(f))
			if err != nil {
				return err
			}
			index[f.ID] = f
			if err := ValidateFact(e.Config.Category, f, index); err != nil {
				return err
			}
			if f.Kind == "SAMPLE" {
				var s Sample
				if json.Unmarshal(f.Body, &s) != nil || !e.sampleAuthorized(s) {
					return ErrInvalid
				}
			}
			if f.Kind == "PROVENANCE" && !e.provenanceFactAuthorized(f, index) {
				return ErrInvalid
			}
			if stickyQualification(f) {
				assetIndex := slices.IndexFunc(e.Config.Assets, func(asset Asset) bool { return asset.EntityKey == f.Asset })
				ref := archiveQualificationRef{atUS: f.AvailableAt.UnixMicro()}
				hash, _ := hex.DecodeString(f.ID)
				copy(ref.id[:], hash)
				e.archiveSticky[assetIndex] = append(e.archiveSticky[assetIndex], ref)
			}
			if f.Kind != "TRACKER_CONTEXT" {
				return nil
			}
			var t TrackerContext
			if json.Unmarshal(f.Body, &t) != nil {
				return ErrInvalid
			}
			b, ok := r.bundle(ctx, t.BundleID)
			if !ok {
				return ErrInvalid
			}
			index, err = r.refs(ctx, joinBundle(b))
			if err != nil {
				return err
			}
			index[f.ID] = f
			return ValidateTrackerContext(e.Config.Category, f, b, index)
		case *archiveBundlesRow:
			b, err := r.decodeBundle(v)
			if err != nil || e.Enrollments[b.Asset] == nil {
				return ErrInvalid
			}
			index, err := r.refs(ctx, joinBundle(b))
			if err != nil {
				return err
			}
			return ValidateBundle(e.Config.Category, b, index)
		case *archiveCandidatesRow:
			if len(candidates) >= 1280 || v.Category != e.Config.Category || e.Enrollments[v.Asset] == nil || v.Revision < 1 || v.Sequence < 1 || !slices.Contains(Budgets[:], v.BudgetMS) || Set(v.ReservedCodes, 8) != nil {
				return ErrInvalid
			}
			c := &Candidate{ID: v.ID, Asset: v.Asset, Sequence: v.Sequence, BudgetMS: v.BudgetMS, Revision: v.Revision, Phase: v.Phase, EnteredAt: v.EnteredAt, DueAt: v.DueAt, ReservedCodes: v.ReservedCodes}
			if c.Phase == "QUARANTINED" {
				id, _ := Identity("candidate", e.Config.Category, map[string]any{"run": e.Config.RunID, "category": e.Config.Category, "asset": c.Asset, "sequence": c.Sequence, "budget_ms": c.BudgetMS})
				if v.Terminal != "" || v.TerminalID != "" || c.ID != id || !c.DueAt.Equal(c.EnteredAt.Add(time.Duration(c.BudgetMS)*time.Millisecond)) {
					return ErrInvalid
				}
				quarantined++
			} else {
				if c.Phase != "FINAL" {
					return ErrInvalid
				}
				if err := decodeArchivePayload(v.Entry, 8192, &c.Entry); err != nil {
					return err
				}
				if c.Entry.BundleID != v.EntryBundle || !e.trusted(ctx, c) {
					return ErrInvalid
				}
				var err error
				c.InitialState, err = archivePayload(e.Config.Category, "candidate", e.descriptor.CandidateSchema, v.InitialState, v.InitialHash, 16<<10)
				if err != nil {
					return err
				}
				c.State, err = archivePayload(e.Config.Category, "candidate", e.descriptor.CandidateSchema, v.State, v.StateHash, 16<<10)
				if err != nil {
					return err
				}
				c.Terminal = &Terminal{}
				if err = decodeArchivePayload(v.Terminal, 8192, c.Terminal); err != nil {
					return err
				}
				if v.TerminalID != c.Terminal.DecisionID || v.TerminalID != c.Entry.Fallback.TerminalID {
					return ErrInvalid
				}
			}
			candidates[c.ID] = c
			e.Candidates = append(e.Candidates, c)
		case *archiveDecisionsRow:
			c := candidates[v.CandidateID]
			if c == nil || c.Terminal == nil {
				return ErrInvalid
			}
			d, err := r.validateDecision(ctx, e, v, c, terminals, reservations)
			if err != nil {
				return err
			}
			e.Decisions = append(e.Decisions, d)
		case *archiveFailuresRow:
			if len(e.Failures)+len(e.Telemetry) >= 1024 || v.Count < 1 || v.LastAt.Before(v.FirstAt) || (v.Asset != "" && e.Enrollments[v.Asset] == nil) || v.Category != "" && v.Category != e.Config.Category {
				return ErrInvalid
			}
			if v.Kind == "QUALIFIED_TELEMETRY" {
				return r.validateTelemetry(ctx, e, v)
			}
			if v.Kind != "COMPONENT" && v.Kind != "COVERAGE" {
				return ErrInvalid
			}
			var d archiveDiagnostic
			if err := decodeArchivePayload(v.Body, 16<<10, &d); err != nil {
				return err
			}
			if d.Schema != 1 || Set(d.FactIDs, 32) != nil || d.Through.Before(d.From) || len(d.Message) > 2048 {
				return ErrInvalid
			}
			if d.BundleID != "" {
				b, ok := r.bundle(ctx, d.BundleID)
				if !ok || b.Asset != v.Asset || b.AvailabilityCutoff.After(v.FirstAt) {
					return ErrInvalid
				}
			}
			for _, id := range d.FactIDs {
				f, ok := r.fact(ctx, id)
				if !ok || f.Asset != v.Asset || f.AvailableAt.After(v.FirstAt) {
					return ErrInvalid
				}
			}
			f := Failure{ID: v.ID, Code: v.Code, Asset: v.Asset, Kind: v.Kind, ScopeKey: v.ScopeKey, FirstAt: v.FirstAt, At: v.LastAt, Count: v.Count, FactIDs: d.FactIDs, BundleID: d.BundleID, LogicalFrom: &d.From, LogicalThrough: &d.Through}
			if candidates[v.ScopeKey] != nil {
				f.CandidateID = v.ScopeKey
			}
			e.Failures = append(e.Failures, f)
		}
		return nil
	})
	if returnErr != nil {
		return returnErr
	}
	if enrollmentCount != int64(len(e.Config.Assets)) || quarantined != r.run.IncompleteCount || len(e.Candidates)%len(Budgets) != 0 || int64(len(e.Candidates)/len(e.Config.BudgetsMS)) != r.run.PhysicalCount {
		return ErrInvalid
	}
	type physicalKey struct {
		Asset    string
		Sequence int64
	}
	arms := map[physicalKey]map[int64]*Candidate{}
	hostState := map[string]bool{}
	for _, f := range e.Failures {
		if f.Code == "HOST_STATE" && f.Kind == "COMPONENT" && candidates[f.CandidateID] != nil && candidates[f.CandidateID].Asset == f.Asset {
			wanted, _ := Identity("failure", e.Config.Category, map[string]any{"run": e.Config.RunID, "asset": f.Asset, "code": f.Code, "scope_key": f.CandidateID})
			if f.ID == wanted {
				hostState[f.CandidateID] = true
			}
		}
	}
	for _, c := range e.Candidates {
		if c.Phase == "QUARANTINED" && !hostState[c.ID] || c.Phase == "FINAL" && !terminals[c.ID] || !slices.Equal(c.ReservedCodes, SortedUnique(reservations[c.ID])) {
			return ErrInvalid
		}
		key := physicalKey{c.Asset, c.Sequence}
		if arms[key] == nil {
			arms[key] = map[int64]*Candidate{}
		}
		arm := arms[key]
		if arm[c.BudgetMS] != nil {
			return ErrInvalid
		}
		arm[c.BudgetMS] = c
	}
	for _, arm := range arms {
		if len(arm) != len(Budgets) {
			return ErrInvalid
		}
		base := arm[0]
		var valid *Candidate
		for _, c := range arm {
			if !c.EnteredAt.Equal(base.EnteredAt) {
				return ErrInvalid
			}
			if c.Phase == "QUARANTINED" {
				continue
			}
			if valid == nil {
				valid = c
				continue
			}
			if c.Entry.BundleID != valid.Entry.BundleID || c.Entry.Basis != valid.Entry.Basis || c.InitialState.Hash != valid.InitialState.Hash || !slices.Equal(c.Entry.Support, valid.Entry.Support) {
				return ErrInvalid
			}
		}
	}
	return nil
}

func joinBundle(b Bundle) []string {
	ids := make([]string, 0, len(b.Facts)+len(b.Features))
	return append(append(ids, b.Facts...), b.Features...)
}

func (r *archiveReader) validateDecision(ctx context.Context, e *Engine, v *archiveDecisionsRow, c *Candidate, terminals map[string]bool, reserved map[string][]string) (Decision, error) {
	d := Decision{ID: v.ID, CandidateID: c.ID, Asset: c.Asset, Sequence: c.Sequence, BudgetMS: c.BudgetMS, Kind: v.Kind, LogicalAt: v.LogicalAt, ExecutedAt: v.ExecutedAt, CommittedAt: v.CommittedAt, LatenessUS: v.LatenessUS, Action: v.Action, DecisionSource: v.DecisionSource, Outcome: v.Outcome, HostCause: v.HostCause, FailureCode: v.FailureCode, BundleID: v.BundleID, Codes: v.Codes, Reasons: v.Reasons, Support: v.Support, Summary: v.Summary}
	if Set(v.Codes, 8) != nil || Set(v.Reasons, 8) != nil || Set(v.Support, 32) != nil || len(v.Summary) > 2048 || v.LogicalAt.Before(c.EnteredAt) || v.ExecutedAt.Before(v.LogicalAt) || v.CommittedAt.Before(v.ExecutedAt) {
		return d, ErrInvalid
	}
	b, ok := r.bundle(ctx, v.BundleID)
	if !ok || b.Asset != c.Asset || b.AvailabilityCutoff.After(v.LogicalAt) {
		return d, ErrInvalid
	}
	ids := joinBundle(b)
	for _, id := range v.Support {
		if !slices.Contains(ids, id) {
			return d, ErrInvalid
		}
	}
	var metadata archiveDecisionMetadata
	if err := decodeArchivePayload(v.Metadata, 8192, &metadata); err != nil {
		return d, err
	}
	if metadata.Schema != 1 || !slices.Contains([]string{"hardware_investigation", "none"}, metadata.Route) || len(metadata.UrgentOccurrences) > 8 {
		return d, ErrInvalid
	}
	d.TerminalEndpoint, d.UrgentOccurrences = metadata.TerminalEndpoint, metadata.UrgentOccurrences
	if v.Details != "" || v.DetailsHash != "" {
		p, err := archivePayload(e.Config.Category, "details", e.descriptor.DetailsSchema, v.Details, v.DetailsHash, MaxDetailsBytes)
		if err != nil {
			return d, err
		}
		d.Details = &p
	}
	switch v.Kind {
	case "TERMINAL":
		if terminals[c.ID] || c.Terminal.DecisionID != d.ID || !c.Terminal.LogicalAt.Equal(d.LogicalAt) || c.Terminal.Action != d.Action || c.DueAt.Before(d.LogicalAt) || len(d.Codes) > 0 || d.LatenessUS != max(int64(0), d.CommittedAt.Sub(c.DueAt).Microseconds()) || !slices.Equal(c.Terminal.UrgentOccurrences, d.UrgentOccurrences) {
			return d, ErrInvalid
		}
		if c.Terminal.Endpoint == nil != (d.TerminalEndpoint == nil) || c.Terminal.Endpoint != nil && *c.Terminal.Endpoint != *d.TerminalEndpoint {
			return d, ErrInvalid
		}
		if d.DecisionSource == "HOST_FALLBACK" {
			if d.Outcome != "" || d.Action != "INVESTIGATE" || d.HostCause != "DEADLINE_FALLBACK" || d.FailureCode == "" || d.TerminalEndpoint != nil || d.BundleID != c.Entry.BundleID || !slices.Equal(d.Support, c.Entry.Support) {
				return d, ErrInvalid
			}
		} else if d.DecisionSource != "CATEGORY" || d.HostCause != "" || d.FailureCode != "" || !slices.ContainsFunc(e.descriptor.Outcomes, func(o Outcome) bool { return o.Phase == "FINAL" && o.Code == d.Outcome && o.Action == d.Action }) {
			return d, ErrInvalid
		}
		if d.TerminalEndpoint != nil {
			f, ok := r.fact(ctx, d.TerminalEndpoint.ID)
			var feature Feature
			if !ok || !slices.Contains(d.Support, f.ID) || f.Kind != "FEATURE" || json.Unmarshal(f.Body, &feature) != nil || feature.FeatureKind != "temperature_endpoint" || feature.Unit != "celsius" || f.AvailableAt != d.TerminalEndpoint.AvailableAt || feature.SourceAt != d.TerminalEndpoint.SourceAt || feature.Value != d.TerminalEndpoint.Value {
				return d, ErrInvalid
			}
		}
		terminals[c.ID] = true
	case "UPDATE":
		if d.DecisionSource != "CATEGORY" || d.Outcome != "" || d.HostCause != "" || d.FailureCode != "" || d.TerminalEndpoint != nil || len(d.Codes) == 0 || !d.LogicalAt.After(c.Terminal.LogicalAt) || d.LatenessUS != 0 {
			return d, ErrInvalid
		}
		action := "INVESTIGATE"
		for _, code := range d.Codes {
			if slices.Contains(reserved[c.ID], code) {
				return d, ErrInvalid
			}
			i := slices.IndexFunc(e.descriptor.Updates, func(u Update) bool { return u.Code == code })
			if i < 0 {
				return d, ErrInvalid
			}
			if e.descriptor.Updates[i].Action == "URGENT" {
				action = "URGENT"
			}
			reserved[c.ID] = append(reserved[c.ID], code)
		}
		id, _ := Identity("update", e.Config.Category, map[string]any{"candidate": c.ID, "codes": d.Codes})
		if d.ID != id || d.Action != action {
			return d, ErrInvalid
		}
	default:
		return d, ErrInvalid
	}
	return d, nil
}

func (r *archiveReader) validateTelemetry(ctx context.Context, e *Engine, v *archiveFailuresRow) error {
	var d archiveTelemetryBody
	if err := decodeArchivePayload(v.Body, 16<<10, &d); err != nil {
		return err
	}
	id, _ := Identity("telemetry_record", e.Config.Category, map[string]any{"run": e.Config.RunID, "category": e.Config.Category, "asset": v.Asset, "policy_id": d.PolicyID, "occurrence": d.Occurrence})
	if v.ID != id || d.Schema != 1 ||
		d.Disposition == "PREVIEW" && (d.PreviewID != id || d.PhysicalSequence != 0) ||
		d.Disposition == "ANNOTATION" && (d.PreviewID != "" || d.PhysicalSequence <= 0) ||
		!slices.Contains([]string{"PREVIEW", "ANNOTATION"}, d.Disposition) {
		return ErrInvalid
	}
	b, ok := r.bundle(ctx, d.BundleID)
	if !ok || b.Asset != v.Asset || b.AvailabilityCutoff.After(v.FirstAt) || !slices.Contains(b.Facts, d.OpenFact) {
		return ErrInvalid
	}
	for i, ref := range []string{d.OpenFact, d.RecoverFact} {
		if i == 1 && ref == "" {
			continue
		}
		f, ok := r.fact(ctx, ref)
		var q Qualified
		if !ok || f.Asset != v.Asset || f.Kind != "QUALIFIED" || json.Unmarshal(f.Body, &q) != nil || q.Rule != "telemetry_loss" || q.PolicyID != d.PolicyID || q.Occurrence != d.Occurrence {
			return ErrInvalid
		}
		if i == 0 && (q.Transition != "OPEN" || maxTime(f.AvailableAt, rawBoundary(f)) != v.FirstAt) || i == 1 && (q.Transition != "RECOVER" || maxTime(f.AvailableAt, rawBoundary(f)).After(v.LastAt)) {
			return ErrInvalid
		}
	}
	e.Telemetry[id] = &TelemetryRecord{ID: id, Asset: v.Asset, PolicyID: d.PolicyID, Occurrence: d.Occurrence, Disposition: d.Disposition, PhysicalSequence: d.PhysicalSequence, OpenFact: d.OpenFact, RecoverFact: d.RecoverFact, BundleID: d.BundleID, Summary: d.Summary, PreviewID: d.PreviewID, FirstAt: v.FirstAt, LastAt: v.LastAt, Count: v.Count}
	return nil
}

func (r *archiveReader) runIdeal(ctx context.Context, e *Engine) error {
	at := e.StartAt
	stop := e.AdmissionEndAt
	if r.run.StoppedAt != nil && r.run.StoppedAt.Before(stop) {
		stop = *r.run.StoppedAt
	}
	batch := []Fact{}
	var bytesInBatch int
	flush := func(wake time.Time, admit []Fact) error {
		if !wake.Before(stop) {
			e.BeginDrain(r.run.StopReason)
		}
		before := len(e.Bundles)
		if len(admit) > 0 {
			e.trimArchiveRing(ctx, wake)
		}
		if err := e.Advance(ctx, wake, wake, wake, admit, nil); err != nil {
			return err
		}
		if len(admit) > 0 || len(e.Bundles) != before {
			e.trimArchiveRing(ctx, wake)
		}
		return e.archiveEvidenceErr
	}
	nextTick := func(target time.Time) error {
		for e.State != "CLOSED" {
			next := e.StartAt.Add((at.Sub(e.StartAt)/time.Second + 1) * time.Second)
			if stop.After(at) && stop.Before(next) {
				next = stop
			}
			next = e.nextWake(at, next)
			if !next.Before(target) {
				return nil
			}
			at = next
			if err := flush(at, nil); err != nil {
				return err
			}
		}
		return nil
	}
	last := time.Time{}
	err := r.each(ctx, "facts", func(_, _, _ int, row ArchiveRow, cols any, _ int64) error {
		v := cols.(*archiveFactsRow)
		if v.Kind == "FEATURE" || v.Kind == "TRACKER_CONTEXT" {
			return nil
		}
		f, err := r.decodeFact(v)
		if err != nil {
			return err
		}
		if !f.AvailableAt.Before(stop) || f.AvailableAt.Before(e.StartAt) {
			return ErrInvalid
		}
		if !last.IsZero() && !f.AvailableAt.Equal(last) {
			if err = nextTick(last); err != nil {
				return err
			}
			at = last
			if err = flush(at, batch); err != nil {
				return err
			}
			batch = batch[:0]
			bytesInBatch = 0
		}
		last = f.AvailableAt
		bytesInBatch += len(f.Body)
		if len(batch) >= MaxFacts*len(e.Enrollments) || bytesInBatch > MaxInputBytes {
			return ErrInvalid
		}
		batch = append(batch, f)
		return nil
	})
	if err != nil {
		return err
	}
	if len(batch) > 0 {
		if err = nextTick(last); err != nil {
			return err
		}
		at = last
		if err = flush(at, batch); err != nil {
			return err
		}
	}
	return nextTick(e.AdmissionEndAt.Add(121 * time.Second))
}

func (e *Engine) trimArchiveRing(ctx context.Context, at time.Time) {
	bundles := map[string]bool{}
	frozen := map[string]bool{}
	for _, en := range e.Enrollments {
		if !en.Active {
			continue
		}
		if c, id := e.RequestContext(ctx, en, at); c != nil {
			bundles[c.BundleID] = true
			frozen[id] = true
		}
		for _, arm := range e.Candidates {
			if arm.Asset != en.Asset || arm.Sequence != en.Sequence || arm.Phase == "QUARANTINED" {
				continue
			}
			bundles[arm.Entry.BundleID] = true
			if arm.Terminal != nil && arm.Terminal.Endpoint != nil {
				frozen[arm.Terminal.Endpoint.ID] = true
			}
		}
	}
	for id, b := range e.Bundles {
		if bundles[id] {
			for _, ref := range joinBundle(b) {
				frozen[ref] = true
			}
			continue
		}
		delete(e.Bundles, id)
	}
	raw := []Fact{}
	lower := at.Add(-900 * time.Second)
	for id, f := range e.Facts {
		if f.Kind == "FEATURE" || f.Kind == "TRACKER_CONTEXT" {
			if !frozen[id] {
				delete(e.Facts, id)
			}
			continue
		}
		if recentFact(f, lower) {
			raw = append(raw, f)
			continue
		}
		delete(e.Facts, id)
	}
	size := 0
	count, samples := map[string]int{}, map[string]int{}
	for _, f := range raw {
		size += len(f.Body) + len(f.Asset) + len(f.Run) + len(f.ID) + 160
		count[f.Asset]++
		if f.Kind == "SAMPLE" {
			samples[f.Asset]++
		}
	}
	overflow := size > MaxInputBytes
	for asset, n := range count {
		overflow = overflow || n > MaxFacts || samples[asset] > 768
	}
	if !overflow {
		return
	}
	// Overflow makes the affected inputs unknown until every evicted fact has
	// aged out. Never quietly evaluate a partial ring.
	slices.SortFunc(raw, func(a, b Fact) int {
		if d := a.AvailableAt.Compare(b.AvailableAt); d != 0 {
			return d
		}
		return strings.Compare(a.ID, b.ID)
	})
	for _, f := range raw {
		if size <= MaxInputBytes && count[f.Asset] <= MaxFacts && (f.Kind != "SAMPLE" || samples[f.Asset] <= 768) {
			continue
		}
		count[f.Asset]--
		if f.Kind == "SAMPLE" {
			samples[f.Asset]--
		}
		delete(e.Facts, f.ID)
		size -= len(f.Body) + len(f.Asset) + len(f.Run) + len(f.ID) + 160
		until := maxTime(f.AvailableAt, rawBoundary(f)).Add(900 * time.Second)
		if until.After(e.archiveInputBound[f.Asset]) {
			e.archiveInputBound[f.Asset] = until
		}
	}
}

func (r *archiveReader) copyPresentationEvidence(ctx context.Context, e *Engine) error {
	if e.previewComparisons == nil {
		e.previewComparisons = make(map[string]previewChange)
	}
	e.endpointAvailability = make(map[string]string)
	for _, c := range e.Candidates {
		if c.Terminal == nil {
			continue
		}
		e.endpointAvailability[c.ID] = e.temperatureCoverage(ctx, c)
	}
	for _, d := range e.Decisions {
		if change, ok := e.previewChange(ctx, d); ok {
			e.previewComparisons[d.ID] = change
		}
	}
	return nil
}

// WriteEvidence emits retained, hash-addressed input records in stable order.
func (e *Engine) WriteEvidence(w io.Writer) error {
	enc := json.NewEncoder(w)
	facts := make([]string, 0, len(e.Facts))
	for id := range e.Facts {
		facts = append(facts, id)
	}
	slices.Sort(facts)
	for _, id := range facts {
		if err := enc.Encode(e.Facts[id]); err != nil {
			return err
		}
	}
	bundles := make([]string, 0, len(e.Bundles))
	for id := range e.Bundles {
		bundles = append(bundles, id)
	}
	slices.Sort(bundles)
	for _, id := range bundles {
		if err := enc.Encode(e.Bundles[id]); err != nil {
			return err
		}
	}
	return nil
}

// WriteArchiveEvidence copies only retained facts/manifests into the
// presentation directory, without loading complete chunks into memory.
func WriteArchiveEvidence(ctx context.Context, dir string, w io.Writer) error {
	r, err := readArchive(ctx, dir)
	if err != nil {
		return err
	}
	defer r.close()
	enc := json.NewEncoder(w)
	for _, section := range []string{"facts", "bundles"} {
		if err = r.each(ctx, section, func(_, _, _ int, _ ArchiveRow, cols any, _ int64) error {
			if section == "facts" {
				f, err := r.decodeFact(cols.(*archiveFactsRow))
				if err != nil {
					return err
				}
				return enc.Encode(f)
			}
			b, err := r.decodeBundle(cols.(*archiveBundlesRow))
			if err != nil {
				return err
			}
			return enc.Encode(b)
		}); err != nil {
			return err
		}
	}
	return nil
}

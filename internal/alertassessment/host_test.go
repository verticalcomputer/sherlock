package alertassessment

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"slices"
	"strings"
	"testing"
	"time"
)

const testAsset = "cluster/GPU/node/GPU-a/"

var testTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func testPayload(t *testing.T, category, kind string, body any) Payload {
	t.Helper()
	p, err := NewPayload(category, kind, 1, body)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func testProvenance(id string) Provenance {
	return Provenance{Mode: "fixture", CollectionRunID: "fixture", Operation: "fixture", ScheduleRevision: 1, InventoryRevision: "fixture", SourceRecord: id}
}

func testSample(t *testing.T, source, available time.Time, value float64) Fact {
	t.Helper()
	f, err := NewFact("test", "run", testAsset, "SAMPLE", available, Sample{Metric: "temperature", Unit: "celsius", Value: value, SourceAt: source, CollectedAt: available, CompletedAt: available, SourceRecord: "fixture", Provenance: testProvenance("fixture")})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func testRequest(t *testing.T, d Descriptor, facts ...Fact) Request {
	t.Helper()
	at := testTime.Add(time.Minute)
	hash, err := Identity("descriptor", d.Category, d)
	if err != nil {
		t.Fatal(err)
	}
	r := Request{Contract: 1, Implementation: d.Implementation, Category: d.Category, Run: "run", Asset: testAsset, DescriptorHash: hash, ConfigHash: strings.Repeat("a", 64), Purpose: "DISCOVER", Scope: "TRACKER", ExpectedRevision: 1,
		LogicalAt: at, AvailabilityCutoff: at, ExecutedAt: at, DiscoveryFloor: testTime, Facts: append([]Fact{}, facts...), Policy: testPayload(t, d.Category, "policy", map[string]any{})}
	r.Bundle, err = NewBundle(r.Category, r.Run, r.Asset, at, r.Facts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func testResult(kind string) Result {
	return Result{Kind: kind, UpdateCodes: []string{}, Reasons: []string{}, Support: []string{}, ProposedFeatures: []Feature{}}
}

func testAssessment(phase, code, action string) Result {
	x := testResult("ASSESSMENT")
	x.Phase, x.Outcome, x.Action = phase, code, action
	return x
}

func testArm(t *testing.T, budget int64, facts ...Fact) Request {
	t.Helper()
	r := testRequest(t, testDescriptor(), facts...)
	r.Purpose, r.Scope, r.Sequence, r.BudgetMS = "ASSESS", "ARM", 1, &budget
	r.CandidateID, _ = Identity("candidate", r.Category, map[string]any{"run": r.Run, "category": r.Category, "asset": r.Asset, "sequence": r.Sequence, "budget_ms": budget})
	terminal, _ := Identity("terminal", r.Category, map[string]any{"candidate": r.CandidateID})
	state := testPayload(t, r.Category, "candidate", map[string]any{})
	r.State = &state
	r.Entry = &Entry{Basis: "CATEGORY_CONCERN", AvailableAt: r.LogicalAt, BundleID: r.Bundle.ID, Support: []string{facts[0].ID}, Fallback: Fallback{Schema: 1, DueAt: r.LogicalAt.Add(time.Duration(budget) * time.Millisecond), Action: "INVESTIGATE", Route: "hardware_investigation", TerminalID: terminal}}
	return r
}

func TestAssessmentInvokeIsolatesBothModuleBoundaries(t *testing.T) {
	d := testDescriptor()
	f := testSample(t, testTime, testTime, 41)
	r := testRequest(t, d, f)
	p := testPayload(t, d.Category, "tracker", map[string]any{"n": int64(1)})
	x := testAssessment("NO_CANDIDATE", "test/none", "NONE")
	x.State = &p
	x.Support = []string{f.ID}
	a := &testAdapter{descriptor: d,
		policy: func(_ context.Context, p Payload) error { p.Body[0] = '['; return nil },
		evaluate: func(_ context.Context, r Request) (Result, error) {
			if string(r.Policy.Body) != "{}" {
				t.Fatal("policy callback mutated evaluation input")
			}
			r.Facts[0].Body[0] = '['
			r.Bundle.Facts[0] = "replaced"
			return x, nil
		},
		validate: func(_ context.Context, r Request, x Result) error {
			if !bytes.Equal(f.Body, r.Facts[0].Body) || r.Bundle.Facts[0] != f.ID {
				t.Fatal("evaluation mutated retained input")
			}
			r.Facts[0].Body[0] = '['
			x.State.Body[0] = '['
			x.Support[0] = "replaced"
			return nil
		},
	}
	registry, err := NewRegistry(a)
	if err != nil {
		t.Fatal(err)
	}
	got, m, err := registry.Invoke(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.State.Body, p.Body) || got.Support[0] != f.ID || !bytes.Equal(m.Facts[0].Body, f.Body) {
		t.Fatal("validator mutated returned values")
	}
	p.Body[0], x.Support[0] = '[', "replaced"
	if got.State.Body[0] != '{' || got.Support[0] != f.ID || r.Facts[0].Body[0] != '{' {
		t.Fatal("invocation retained aliased memory")
	}
}

func TestAssessmentInvokeIsAtomicOnFault(t *testing.T) {
	for _, phase := range []string{"before", "evaluate", "validate", "panic", "oversized", "wrong kind"} {
		t.Run(phase, func(t *testing.T) {
			d := testDescriptor()
			x := testAssessment("NO_CANDIDATE", "test/none", "NONE")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			a := &testAdapter{descriptor: d, evaluate: func(_ context.Context, _ Request) (Result, error) {
				calls++
				switch phase {
				case "evaluate":
					cancel()
				case "panic":
					panic("untrusted detail")
				case "oversized":
					x.State = &Payload{Category: d.Category, Kind: "tracker", Schema: 1, Body: []byte(strings.Repeat("x", MaxPayloadBytes+1))}
				case "wrong kind":
					x.Action = "URGENT"
				}
				return x, nil
			}, validate: func(_ context.Context, _ Request, _ Result) error {
				if phase == "validate" {
					cancel()
				}
				return nil
			}}
			if phase == "before" {
				cancel()
			}
			registry, err := NewRegistry(a)
			if err != nil {
				t.Fatal(err)
			}
			got, m, err := registry.Invoke(ctx, testRequest(t, d))
			want := "TIME_BUDGET"
			if phase == "panic" {
				want = "PANIC"
			}
			if phase == "oversized" || phase == "wrong kind" {
				want = "MALFORMED_RESULT"
			}
			if err == nil || !strings.HasPrefix(err.Error(), want) || got.Kind != "" || m.Category != "" || phase == "before" && calls != 0 {
				t.Fatalf("fault leaked result or called canceled adapter: %s, %s, %v", got.Kind, m.Category, err)
			}
		})
	}
}

func TestAssessmentHostFreezesEntryByEligibilityAndKeepsNegativeFacts(t *testing.T) {
	d := testDescriptor()
	early := testSample(t, testTime, testTime, 50)
	futureAt := testTime.Add(30 * time.Second)
	later := testSample(t, futureAt, testTime, 51)
	other := testSample(t, futureAt, testTime, 52)
	conflict, err := NewFact(d.Category, "run", testAsset, "CONFLICT", testTime, Conflict{Metric: "temperature", SourceAt: futureAt, Code: "CONFLICT", Values: SortedUnique([]string{later.ID, other.ID})})
	if err != nil {
		t.Fatal(err)
	}
	r := testRequest(t, d, early, later, other, conflict)
	tracker := testPayload(t, d.Category, "tracker", map[string]any{})
	state := testPayload(t, d.Category, "candidate", map[string]any{})
	x := testAssessment("OBSERVING", "test/observe", "NONE")
	x.State, x.InitialCandidateState, x.EntryQualifiedAt = &tracker, &state, &testTime
	p := Feature{FeatureKind: "entry", SourceAt: testTime, Value: 50, Unit: "celsius", Support: []string{early.ID}}
	id, err := FeatureID(r, p)
	if err != nil {
		t.Fatal(err)
	}
	x.Support, x.ProposedFeatures = []string{id}, []Feature{p}
	a := &testAdapter{descriptor: d, evaluate: func(context.Context, Request) (Result, error) { return x, nil }}
	registry, err := NewRegistry(a)
	if err != nil {
		t.Fatal(err)
	}
	got, m, err := registry.Invoke(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	view, err := EntryView(m, *got.EntryQualifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	if !view.Bundle.LogicalAt.Equal(testTime) || !view.Bundle.AvailabilityCutoff.Equal(testTime) || !slices.Contains(view.Bundle.Features, id) || !slices.Contains(view.Bundle.Facts, conflict.ID) || slices.Contains(view.Bundle.Facts, later.ID) {
		t.Fatalf("entry cutoff was not frozen: %+v", view.Bundle)
	}
	if err := ValidateBundle(d.Category, view.Bundle, indexFacts(view.Facts)); err != nil {
		t.Fatal("negative fact lost closure", err)
	}
	// A future sample may be retained for a known conflict, but cannot support entry.
	x.ProposedFeatures[0].Support[0] = later.ID
	if _, _, err := registry.Invoke(context.Background(), r); err == nil {
		t.Fatal("later evidence supplied entry support")
	}
	// Reuse a normalized feature supplied as closure but absent from the manifest.
	x.ProposedFeatures[0].Support[0] = early.ID
	r.Facts = m.Facts
	_, m, err = registry.Invoke(context.Background(), r)
	if err != nil || !slices.Contains(m.Bundle.Features, id) || len(m.Facts) != 5 {
		t.Fatalf("feature reuse failed: %v", err)
	}
}

func TestAssessmentFactAndBundleRejectInvalidClosure(t *testing.T) {
	early := testSample(t, testTime, testTime, 50)
	feature := Feature{FeatureKind: "entry", SourceAt: testTime, Value: 50, Unit: "celsius", Support: []string{early.ID}}
	f, err := NewFact("test", "run", testAsset, "FEATURE", testTime, feature)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBundle("test", "run", testAsset, testTime, []Fact{f})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBundle("test", b, indexFacts([]Fact{f, early})); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBundle("test", b, indexFacts([]Fact{f})); err == nil {
		t.Fatal("dangling feature accepted")
	}
	f.AvailableAt = f.AvailableAt.Add(time.Second)
	if err := ValidateFact("test", f, indexFacts([]Fact{f, early})); err == nil {
		t.Fatal("invalid feature availability accepted")
	}
	feature.Support = []string{f.ID}
	second, err := NewFact("test", "run", testAsset, "FEATURE", f.AvailableAt, feature)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFact("test", second, indexFacts([]Fact{second, f, early})); err == nil {
		t.Fatal("derived-to-derived edge accepted")
	}
	var s Sample
	if err := json.Unmarshal(early.Body, &s); err != nil {
		t.Fatal(err)
	}
	s.Provenance.Mode = "durable"
	if _, err := NewFact("test", "run", testAsset, "SAMPLE", testTime, s); err == nil {
		t.Fatal("missing mode-specific provenance accepted")
	}
}

func TestAssessmentBundleIdentityMatchesCanonicalProjection(t *testing.T) {
	for _, b := range []Bundle{
		{},
		{ID: strings.Repeat("a", 64), Run: "run<&>", Asset: "GPU/温/\u2028/", AvailabilityCutoff: testTime,
			LogicalAt: testTime.In(time.FixedZone("other", -19800)).Add(123456789), LookbackSeconds: 1<<63 - 1,
			Facts: []string{"b", "a"}, Features: []string{}},
		{Run: "invalid\xff"},
		{Facts: []string{"invalid\xff"}},
		{Features: []string{"invalid\xff"}},
		{LogicalAt: time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)},
		{AvailabilityCutoff: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		want, wantErr := Identity("bundle", "test", map[string]any{
			"run": b.Run, "asset": b.Asset, "logical_at": b.LogicalAt, "availability_cutoff": b.AvailabilityCutoff,
			"lookback_seconds": b.LookbackSeconds, "facts": b.Facts, "features": b.Features,
		})
		got, gotErr := BundleID("test", b)
		if got != want || (gotErr == nil) != (wantErr == nil) {
			t.Fatalf("bundle identity = %s (%v), want %s (%v) for %+v", got, gotErr, want, wantErr, b)
		}
	}
}

func TestAssessmentHashSetIsStrictAndBounded(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for _, tc := range []struct {
		hashes []string
		limit  int
		valid  bool
	}{
		{nil, 2, false},
		{[]string{}, 0, true},
		{[]string{a, b}, 2, true},
		{[]string{a, b}, 1, false},
		{[]string{b, a}, 2, false},
		{[]string{a, a}, 2, false},
		{[]string{strings.ToUpper(a)}, 1, false},
		{[]string{a[:63] + "\xff"}, 1, false},
		{[]string{a[:63] + "\n"}, 1, false},
	} {
		if err := hashSet(tc.hashes, tc.limit); (err == nil) != tc.valid {
			t.Fatalf("hash set %q at limit %d: expected valid %t, got %v", tc.hashes, tc.limit, tc.valid, err)
		}
	}
}

func TestAssessmentRequestFactByteBoundAccountsForEscapingAndFraction(t *testing.T) {
	for _, fraction := range []time.Duration{0, 120 * time.Microsecond, 123456 * time.Microsecond} {
		f := testSample(t, testTime, testTime, 50)
		r := testRequest(t, testDescriptor(), f)
		r.Run, r.Asset = "run<\"&>\\", "cluster/GPU/温/GPU-a/"
		f.Run, f.Asset = r.Run, r.Asset
		f.AvailableAt = f.AvailableAt.Add(fraction)
		f.Body = json.RawMessage(`{"value":""}`)
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		pad := strings.Repeat("x", maxFactBytes-len(b))
		f.Body = json.RawMessage(`{"value":"` + pad + `"}`)
		r.Facts[0] = f
		if !boundedRequestBytes(r) {
			t.Fatalf("fact with timestamp fraction %s did not fit exact byte bound", fraction)
		}
		r.Facts[0].Body = json.RawMessage(`{"value":"` + pad + `x"}`)
		if boundedRequestBytes(r) {
			t.Fatalf("fact with timestamp fraction %s exceeded byte bound", fraction)
		}
	}
}

func TestAssessmentCanonicalFactRejectsAmbiguousEncoding(t *testing.T) {
	f := testSample(t, testTime, testTime, 0)
	for _, tc := range []struct{ name, old, replacement string }{
		{"missing required default", `,"value":0`, ""},
		{"null required default", `"value":0`, `"value":null`},
		{"null optional", `"mode":"fixture"`, `"configuration_revision":null,"mode":"fixture"`},
		{"case alias", `"mode":"fixture"`, `"Mode":"fixture"`},
		{"unknown field", `"mode":"fixture"`, `"extra":0,"mode":"fixture"`},
		{"duplicate nested key", `"mode":"fixture"`, `"mode":"legacy","mode":"fixture"`},
		{"invalid unicode", `"collection_run_id":"fixture"`, `"collection_run_id":"\ud800"`},
		{"noncanonical float", `"value":0`, `"value":-0`},
		{"noncanonical time", `"source_at":"2026-01-01T00:00:00Z"`, `"source_at":"2026-01-01T00:00:00.000000Z"`},
		{"identity mismatch", `"value":0`, `"value":1`},
		{"negative int64", `"schedule_revision":1`, `"schedule_revision":-1`},
		{"overflow int64", `"schedule_revision":1`, `"schedule_revision":9223372036854775808`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := f
			changed.Body = bytes.Replace(f.Body, []byte(tc.old), []byte(tc.replacement), 1)
			if bytes.Equal(f.Body, changed.Body) {
				t.Fatal("body fixture did not change")
			}
			index := map[string]Fact{changed.ID: changed}
			if err := ValidateFact("test", changed, index); err == nil {
				t.Fatal("accepted malformed fact")
			}
			ctx := withFactValidationCache(t.Context())
			cache := checkedSamples(ctx)
			_, _ = cache.decodeForSelection("test", changed)
			if _, err := validateFact(ctx, "test", changed, index); err == nil || cache.lookup("test", changed) != nil {
				t.Fatal("promoted an invalid parsed sample")
			}
		})
	}
}

func TestAssessmentSampleIdentityMatchesCanonicalProjection(t *testing.T) {
	const run = "run<>&\"\\温"
	at := testTime.In(time.FixedZone("other", -19800)).Add(123456789 * time.Nanosecond)
	revision := int64(0)
	for _, mode := range []string{"fixture", "legacy", "durable"} {
		for _, value := range []float64{math.Copysign(0, -1), math.SmallestNonzeroFloat64, math.MaxFloat64, 62.5} {
			p := testProvenance("source<>&\u2028")
			p.Mode, p.ScheduleRevision = mode, math.MaxInt64
			switch mode {
			case "legacy":
				p.JobID, p.ConfigurationRevision = `job"\`, &revision
			case "durable":
				p.WorkID, p.CollectorID = "work<>&", "collector\u2029"
			}
			s := Sample{Metric: "temperature", Unit: "celsius", SourceAt: at.Add(-time.Second), CollectedAt: at, CompletedAt: at,
				Value: value, SourceRecord: p.SourceRecord, Provenance: p}
			wantBody, err := Canonical(s)
			if err != nil {
				t.Fatal(err)
			}
			wantID, err := Identity("sample", "test", map[string]any{
				"asset": testAsset, "metric": s.Metric, "run": run, "source_at": s.SourceAt, "unit": s.Unit, "value": s.Value,
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, body := range []any{s, &s} {
				f, err := NewFact("test", run, testAsset, "SAMPLE", at, body)
				if err != nil || !bytes.Equal(f.Body, wantBody) || f.ID != wantID || f.AvailableAt != normalizeTime(at) {
					t.Fatalf("%s sample with value %g: body = %s, id = %s, error = %v, want %s and %s", mode, value, f.Body, f.ID, err, wantBody, wantID)
				}
				if err := ValidateFact("test", f, map[string]Fact{f.ID: f}); err != nil {
					t.Fatalf("%s sample with value %g rejected: %v", mode, value, err)
				}
			}
		}
	}
}

func TestAssessmentSampleCacheRequiresExactImmutableFact(t *testing.T) {
	const largestRevision = int64(1<<63 - 1)
	revision := largestRevision
	f, err := NewFact("test", "run", testAsset, "SAMPLE", testTime, Sample{
		Metric: "temperature", Unit: "celsius", SourceAt: testTime, CollectedAt: testTime, CompletedAt: testTime,
		Value: 41, SourceRecord: "source", Provenance: Provenance{
			Mode: "legacy", CollectionRunID: "collection", Operation: "operation", ScheduleRevision: largestRevision,
			InventoryRevision: "inventory", SourceRecord: "source", JobID: "job", ConfigurationRevision: &revision,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := withFactValidationCache(context.Background())
	cache, _ := ctx.Value(sampleCacheKey{}).(*sampleCache)
	validate := func(category string, f Fact) error {
		g := newFactGraph(category, map[string]Fact{f.ID: f})
		g.samples = cache
		_, err := g.eligibility(f.ID)
		return err
	}
	frozen := f
	frozen.Body = slices.Clone(f.Body)
	if _, err := cache.decodeForSelection("test", f); err != nil || cache.lookup("test", f) != nil {
		t.Fatalf("selection parse appeared verified: %v", err)
	}
	if err := validate("test", f); err != nil || cache.lookup("test", f) == nil {
		t.Fatalf("valid sample did not populate cache: %v", err)
	}
	sample, err := DecodeSample(ctx, "test", f)
	if err != nil || sample.Provenance.ScheduleRevision != largestRevision ||
		sample.Provenance.ConfigurationRevision == nil || *sample.Provenance.ConfigurationRevision != largestRevision {
		t.Fatalf("decoded sample: %+v, %v", sample, err)
	}
	*sample.Provenance.ConfigurationRevision = 0
	f.Body[0] = '['
	if err := validate("test", f); err == nil {
		t.Fatal("accepted mutated fact bytes")
	}
	sample, err = DecodeSample(ctx, "test", frozen)
	if err != nil || cache.lookup("test", frozen) == nil ||
		sample.Provenance.ConfigurationRevision == nil || *sample.Provenance.ConfigurationRevision != largestRevision {
		t.Fatalf("caller mutation altered the cached sample: %+v, %v", sample, err)
	}
	differentSource := frozen
	differentSource.Body = bytes.ReplaceAll(frozen.Body, []byte(`"source_record":"source"`), []byte(`"source_record":"other"`))
	if err := validate("test", differentSource); err != nil {
		t.Fatalf("same sample identity with different valid provenance: %v", err)
	}
	sample, err = DecodeSample(ctx, "test", differentSource)
	if err != nil || sample.SourceRecord != "other" {
		t.Fatalf("cache returned a sample from a different source record: %+v, %v", sample, err)
	}
	if err := validate("wrong-category", frozen); err == nil {
		t.Fatal("reused verification across categories")
	}
	frozen.AvailableAt = testTime.Add(-time.Second)
	if err := validate("test", frozen); err == nil {
		t.Fatal("reused verification at a different availability")
	}
}

func TestAssessmentRequestFindsExternalConflictForPinnedOldSample(t *testing.T) {
	at := testTime.Add(901 * time.Second)
	old := testSample(t, testTime, testTime, 41)
	other := testSample(t, testTime, testTime, 42)
	recent := testSample(t, at, at, 43)
	conflict, err := NewFact("test", "run", testAsset, "CONFLICT", testTime, Conflict{
		Metric: "temperature", SourceAt: testTime, Code: "CONFLICT", Values: SortedUnique([]string{old.ID, other.ID}),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBundle("test", "run", testAsset, testTime, []Fact{old})
	if err != nil {
		t.Fatal(err)
	}
	e := Engine{Config: Config{RunID: "run", Category: "test"}, Facts: indexFacts([]Fact{old, recent}), Bundles: map[string]Bundle{b.ID: b}}
	restored := indexFacts([]Fact{other, conflict})
	en := &Enrollment{Asset: testAsset, DiscoveryFloor: testTime}
	c := &Candidate{Entry: Entry{BundleID: b.ID}, EnteredAt: testTime}
	for _, warm := range []bool{false, true} {
		ctx := withFactValidationCache(t.Context())
		if warm {
			for _, f := range []Fact{old, recent} {
				if _, err := validateFact(ctx, e.Config.Category, f, e.Facts); err != nil {
					t.Fatal(err)
				}
			}
		}
		var lookedUp []string
		e.LookupFact = func(id string) (Fact, bool) {
			lookedUp = append(lookedUp, id)
			f, ok := restored[id]
			return f, ok
		}
		r, err := e.request(ctx, en, at, at, "ASSESS", c)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(SortedUnique(lookedUp), SortedUnique([]string{conflict.ID, other.ID})) || !slices.Contains(r.Bundle.Facts, conflict.ID) || len(r.Facts) != 4 {
			t.Fatalf("warm=%t: retained conflict and closure missing or unexpected lookups: facts=%v lookups=%v", warm, r.Bundle.Facts, lookedUp)
		}
		if err := ValidateBundle("test", r.Bundle, indexFacts(r.Facts)); err != nil {
			t.Fatalf("warm=%t: invalid conflict closure: %v", warm, err)
		}
	}
}

func TestAssessmentArmDeadlineAndTerminalAreImmutable(t *testing.T) {
	f := testSample(t, testTime, testTime, 51)
	r := testArm(t, 0, f)
	d := testDescriptor()
	x := testAssessment("OBSERVING", "test/observe", "NONE")
	a := &testAdapter{descriptor: d, evaluate: func(context.Context, Request) (Result, error) { return x, nil }}
	registry, err := NewRegistry(a)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := registry.Invoke(context.Background(), r); err == nil {
		t.Fatal("zero arm observed beyond deadline")
	}
	x = testAssessment("FINAL", "test/final", "INVESTIGATE")
	if _, _, err := registry.Invoke(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	r.Purpose = "FOLLOW_UP"
	r.Terminal = &Terminal{DecisionID: r.Entry.Fallback.TerminalID, LogicalAt: r.LogicalAt, Action: "INVESTIGATE", UrgentOccurrences: []Occurrence{}}
	r = At(r, r.LogicalAt.Add(time.Second))
	r.ExecutedAt = r.LogicalAt
	x = testResult("UPDATE")
	x.Action, x.UpdateCodes = "URGENT", []string{"higher", "urgent"}
	if _, _, err := registry.Invoke(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	x.State = r.State
	if _, _, err := registry.Invoke(context.Background(), r); err == nil {
		t.Fatal("terminal state mutation accepted")
	}
	r.Entry.Fallback.Route = "untrusted"
	x.State = nil
	if _, _, err := registry.Invoke(context.Background(), r); err == nil || !strings.HasPrefix(err.Error(), "INVALID_INPUT") {
		t.Fatalf("foreign fallback route accepted: %v", err)
	}
}

func TestAssessmentTrackerContextRequiresEligiblePositiveClosure(t *testing.T) {
	const category = "test"
	futureAt := testTime.Add(time.Second)
	future := testSample(t, futureAt, testTime, 50)
	other := testSample(t, futureAt, testTime, 51)
	earlier := testSample(t, testTime, testTime, 49)
	conflict, err := NewFact(category, "run", testAsset, "CONFLICT", testTime, Conflict{Metric: "temperature", SourceAt: futureAt, Code: "CONFLICT", Values: SortedUnique([]string{future.ID, other.ID})})
	if err != nil {
		t.Fatal(err)
	}
	coverage, err := NewFact(category, "run", testAsset, "COVERAGE", testTime, Coverage{Metric: "temperature", From: testTime, Through: futureAt, Code: "MISS", SourceRecord: "gap"})
	if err != nil {
		t.Fatal(err)
	}
	proposed, err := NewFact(category, "run", testAsset, "FEATURE", testTime, Feature{FeatureKind: "entry", SourceAt: futureAt, Value: 49, Unit: "celsius", Support: []string{earlier.ID}})
	if err != nil {
		t.Fatal(err)
	}
	tracker := testPayload(t, category, "tracker", map[string]any{})
	d := testDescriptor()
	r := testRequest(t, d, earlier, future, other, conflict, coverage, proposed)
	ctx := withFactValidationCache(t.Context())
	if _, err := validateRequest(r, d, r.DescriptorHash, checkedSamples(ctx)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		manifest  []Fact
		available time.Time
		missing   string
		valid     bool
	}{
		{"future sample", []Fact{future}, testTime, "", false},
		{"future feature", []Fact{proposed}, testTime, "", false},
		{"now eligible", []Fact{future, proposed}, futureAt, "", true},
		{"negative dependency", []Fact{conflict, coverage}, testTime, "", true},
		{"missing cached dependency", []Fact{conflict, coverage}, testTime, other.ID, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := NewBundle(category, "run", testAsset, tc.available, tc.manifest)
			if err != nil {
				t.Fatal(err)
			}
			f, err := NewFact(category, "run", testAsset, "TRACKER_CONTEXT", tc.available, TrackerContext{Category: category, Revision: 2, Payload: tracker, BundleID: b.ID})
			if err != nil {
				t.Fatal(err)
			}
			facts := indexFacts([]Fact{earlier, future, other, conflict, coverage, proposed, f})
			delete(facts, tc.missing)
			if err := ValidateTrackerContext(category, f, b, facts); (err == nil) != tc.valid {
				t.Fatalf("context valid = %v, want %v (%v)", err == nil, tc.valid, err)
			}
			if err := validateTrackerContext(ctx, category, f, b, facts); (err == nil) != tc.valid {
				t.Fatalf("context with cached samples valid = %v, want %v (%v)", err == nil, tc.valid, err)
			}
		})
	}

	// A source timestamp usable in frozen support still does not join an
	// evaluation manifest unless the original request selected the fact.
	r.Facts = slices.DeleteFunc(r.Facts, func(f Fact) bool { return f.ID == proposed.ID })
	r.Bundle, err = NewBundle(category, r.Run, r.Asset, r.LogicalAt, []Fact{future, conflict, coverage})
	if err != nil {
		t.Fatal(err)
	}
	view, err := entryView(ctx, r, testTime)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(view.Bundle.Facts, SortedUnique([]string{conflict.ID, coverage.ID})) || len(view.Facts) != 5 {
		t.Fatalf("historical view lost manifest/closure distinction: %+v", view.Bundle)
	}
	r.Facts[1].Body = json.RawMessage(`[`)
	if _, err := entryView(ctx, r, testTime); err == nil {
		t.Fatal("historical view used cached sample after its body changed")
	}
}

func TestAssessmentRequestBoundsBeforeModuleEvaluation(t *testing.T) {
	d := testDescriptor()
	f := testSample(t, testTime, testTime, 50)
	large := strings.Repeat("x", MaxPayloadBytes+1)
	registry, err := NewRegistry(&testAdapter{descriptor: d, evaluate: func(context.Context, Request) (Result, error) {
		t.Fatal("oversize request reached category")
		return Result{}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Request){
		"bundle count":   func(r *Request) { r.Bundle.Facts = make([]string, MaxFacts+1) },
		"bundle id":      func(r *Request) { r.Bundle.ID = large },
		"bundle element": func(r *Request) { r.Bundle.Features = []string{large} },
		"fact id":        func(r *Request) { r.Facts[0].ID = large },
		"fact asset":     func(r *Request) { r.Facts[0].Asset = large },
		"request asset":  func(r *Request) { r.Asset = strings.Repeat("/", MaxPayloadBytes+1) },
		"fact body":      func(r *Request) { r.Facts[0].Body = json.RawMessage(large) },
		"entry support":  func(r *Request) { r.Entry.Support = make([]string, 33) },
		"entry summary":  func(r *Request) { r.Entry.Fallback.Summary = large },
		"shared context": func(r *Request) {
			r.SharedContext = &SharedContext{BundleID: r.Bundle.ID, Payload: Payload{Category: d.Category, Kind: "tracker", Schema: 1, Body: json.RawMessage(large)}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := testArm(t, 15000, f)
			mutate(&r)
			if _, _, err := registry.Invoke(context.Background(), r); err == nil || !strings.HasPrefix(err.Error(), "INVALID_INPUT") {
				t.Fatalf("invalid envelope rejected with %v", err)
			}
		})
	}

	// Each envelope remains below its own cap while their aggregate exceeds
	// the request cap. The helper must reject before marshaling all the bodies.
	r := testRequest(t, d, f)
	f.Kind = "FEATURE"
	f.Body = json.RawMessage(`{"value":"` + strings.Repeat("x", 60<<10) + `"}`)
	r.Facts = make([]Fact, 300)
	for i := range r.Facts {
		r.Facts[i] = f
	}
	if boundedRequestBytes(r) {
		t.Fatal("oversized aggregate request accepted")
	}
}

package cooling

import (
	"bytes"
	"context"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

func TestCoolingStrictPolicy(t *testing.T) {
	r := request(t, nil, nil)
	for _, tc := range []struct {
		name, old, new string
	}{
		{"unknown key", `"cadence_seconds":15`, `"extra":0,"cadence_seconds":15`},
		{"case alias", `"cadence_seconds":15`, `"Cadence_seconds":15`},
		{"duplicate key", `"cadence_seconds":15`, `"cadence_seconds":15,"cadence_seconds":15`},
		{"missing key", `"cadence_seconds":15,`, ``},
		{"null", `"cadence_seconds":15`, `"cadence_seconds":null`},
		{"trailing", `"update_delta_c":5}`, `"update_delta_c":5} {}`},
		{"overflow int", `"cadence_seconds":15`, `"cadence_seconds":9223372036854775808`},
		{"overflow float", `"update_delta_c":5`, `"update_delta_c":1e400`},
		{"noncanonical float", `"update_delta_c":5`, `"update_delta_c":5.0`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := r.Policy
			p.Body = bytes.Replace(p.Body, []byte(tc.old), []byte(tc.new), 1)
			if bytes.Equal(p.Body, r.Policy.Body) {
				t.Fatalf("test pattern %s missing", tc.old)
			}
			p.Hash = a.Hash(p.Kind, p.Category, p.Schema, p.Body)
			if err := (Category{}).ValidatePolicy(context.Background(), p); err == nil {
				t.Fatal("invalid typed policy accepted")
			}
		})
	}
	alternate := bytes.Replace(r.Policy.Body, []byte(`"update_delta_c":5`), []byte(`"update_delta_c":5.0`), 1)
	normal, err := (Category{}).NormalizePolicy(context.Background(), alternate)
	if err != nil || !bytes.Equal(normal, r.Policy.Body) {
		t.Fatalf("typed policy normalization failed: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*Policy)
	}{
		{"window exceeds history", func(p *Policy) { p.HistorySeconds = 719 }},
		{"recovery threshold exceeds persistent", func(p *Policy) { p.PersistentRecoveryC = 75 }},
		{"ratio above one", func(p *Policy) { p.StableRatio = 1.1 }},
		{"too few samples", func(p *Policy) { p.EndpointMinSamples = 1 }},
		{"nonfinite", func(p *Policy) { p.PersistentC = math.Inf(1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := DefaultPolicy()
			tc.edit(&p)
			if err := p.Validate(); err == nil {
				t.Fatal("invalid relation accepted")
			}
		})
	}
}

func TestCoolingTypedTrackerVariant(t *testing.T) {
	r := request(t, warmRamp, nil)
	r.DiscoveryFloor = r.LogicalAt
	x, m := invoke(t, r)
	valid, err := decodePayload[TrackerState](*x.State, "tracker", stateLimit)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*TrackerState)
	}{
		{"inactive with history", func(s *TrackerState) { s.Active = false }},
		{"warming without reference", func(s *TrackerState) { s.Reference = nil }},
		{"persistent-only with ordinary reference", func(s *TrackerState) { s.Branches = []string{"PERSISTENT"} }},
		{"unknown branch", func(s *TrackerState) { s.Branches = []string{"invalid"} }},
		{"duplicate branch", func(s *TrackerState) { s.Branches = []string{"RAPID", "RAPID"} }},
		{"negative occurrence", func(s *TrackerState) { s.UrgentOccurrences = []a.Occurrence{{PolicyID: "thermal", Occurrence: -1}} }},
		{"unsorted occurrence", func(s *TrackerState) {
			s.UrgentOccurrences = []a.Occurrence{{PolicyID: "thermal", Occurrence: 2}, {PolicyID: "thermal", Occurrence: 1}}
		}},
		{"wrong endpoint hash", func(s *TrackerState) { ref := *s.EntryEndpoint; ref.ID = "INVALID"; s.EntryEndpoint = &ref }},
		{"wrong reference time", func(s *TrackerState) {
			ref := *s.Reference
			ref.SourceAt = ref.SourceAt.Add(time.Second)
			s.Reference = &ref
		}},
		{"future progress", func(s *TrackerState) { at := m.LogicalAt.Add(time.Second); s.LastEndpointAt = &at }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := valid
			tc.edit(&s)
			p, err := payload("tracker", s)
			if err != nil {
				return // The common codec rejects out-of-domain integers first.
			}
			bad := trackerRequest(m, p)
			if _, err := (Category{}).Evaluate(context.Background(), bad); err == nil {
				t.Fatal("malformed tracker state accepted")
			}
		})
	}
	if _, _, err := registry(t).Invoke(context.Background(), trackerRequest(m, x.InitialCandidateState)); err == nil {
		t.Fatal("tracker accepted a candidate payload")
	}
	unknown := a.Payload{Category: CategoryID, Kind: "tracker", Schema: 2, Body: x.State.Body, Hash: a.Hash("tracker", CategoryID, 2, x.State.Body)}
	if _, _, err := registry(t).Invoke(context.Background(), trackerRequest(m, &unknown)); err == nil || !strings.Contains(err.Error(), "UNSUPPORTED_VERSION") {
		t.Fatalf("incorrect unsupported state version error: %v", err)
	}
}

func TestCoolingRejectsInvalidOutcomeTransition(t *testing.T) {
	r := request(t, warmRamp, nil)
	x, m := invoke(t, r)
	bad := x
	bad.Outcome = CategoryID + "/TRANSIENT_SUPPORTED"
	bad.Phase = "FINAL"
	if err := (Category{}).ValidateResult(context.Background(), m, bad); err == nil {
		t.Fatal("accepted transient discovery")
	}
	bad = x
	bad.Reasons = slices.Replace(slices.Clone(bad.Reasons), 0, 1, "unsupported")
	if err := (Category{}).ValidateResult(context.Background(), m, bad); err == nil {
		t.Fatal("accepted undeclared reason")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := registry(t).Invoke(ctx, r); err == nil || !strings.Contains(err.Error(), "TIME_BUDGET") {
		t.Fatalf("canceled invocation was not discarded: %v", err)
	}
}

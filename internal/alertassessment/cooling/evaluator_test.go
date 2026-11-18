package cooling

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

var origin = time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)

const asset = "fixture/GPU/node/GPU-00000000-0000-0000-0000-000000000001/"

func clock(s int) time.Time { return origin.Add(time.Duration(s) * time.Second) }

func fact(t testing.TB, at time.Time, kind string, body any) a.Fact {
	t.Helper()
	f, err := a.NewFact(CategoryID, "run", asset, kind, at, body)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func sample(t testing.TB, metric string, source, available time.Time, value float64) a.Fact {
	t.Helper()
	unit := "celsius"
	if metric == Power {
		unit = "watts"
	}
	return fact(t, available, "SAMPLE", a.Sample{
		Metric: metric, Unit: unit, SourceAt: source, CollectedAt: available, CompletedAt: available, Value: value, SourceRecord: "fixture",
		Provenance: a.Provenance{Mode: "fixture", CollectionRunID: "fixture", Operation: "fixture", ScheduleRevision: 1, InventoryRevision: "fixture", SourceRecord: "fixture"},
	})
}

func thermal(t testing.TB, policy string, n int64, transition, rule string, revision int64, source, available time.Time) a.Fact {
	t.Helper()
	return fact(t, available, "QUALIFIED", a.Qualified{
		PolicyID: policy, Occurrence: n, Transition: transition, Rule: rule, RuleVersion: 1, EnrollmentRevision: revision,
		Severity: "CRITICAL", QualifiedAt: source, Snapshot: []a.SnapshotEntry{},
	})
}

func registry(t testing.TB) *a.Registry {
	t.Helper()
	reg, err := a.NewRegistry(Category{})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func rebase(t testing.TB, r a.Request, at time.Time, extra ...a.Fact) a.Request {
	t.Helper()
	r.LogicalAt, r.AvailabilityCutoff, r.ExecutedAt = at, at, at
	r.Facts = slices.Clone(r.Facts)
	r.Facts = append(r.Facts, extra...)
	r.Facts = slices.DeleteFunc(r.Facts, func(f a.Fact) bool { return f.AvailableAt.After(at) })
	b, err := a.NewBundle(r.Category, r.Run, r.Asset, at, r.Facts)
	if err != nil {
		t.Fatal(err)
	}
	r.Bundle = b
	return r
}

func request(t testing.TB, temp, power func(int) float64) a.Request {
	t.Helper()
	r := a.Request{Contract: 1, Implementation: 1, Category: CategoryID, Run: "run", Asset: asset, Purpose: "DISCOVER", Scope: "TRACKER", DiscoveryFloor: origin, ExpectedRevision: 1, Facts: []a.Fact{}}
	_, _, r.DescriptorHash, _ = registry(t).Lookup(CategoryID)
	r.ConfigHash = r.DescriptorHash
	p, err := a.NewPayload(CategoryID, "policy", 1, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	r.Policy = p
	for sec := 0; sec <= 900; sec += 15 {
		if temp != nil {
			r.Facts = append(r.Facts, sample(t, Temperature, clock(sec), clock(sec), temp(sec)))
		}
		if power != nil {
			r.Facts = append(r.Facts, sample(t, Power, clock(sec), clock(sec), power(sec)))
		}
	}
	return rebase(t, r, clock(900))
}

func invoke(t testing.TB, r a.Request) (a.Result, a.Request) {
	t.Helper()
	x, m, err := registry(t).Invoke(context.Background(), r)
	if err != nil {
		_, directErr := (Category{}).Evaluate(context.Background(), r)
		t.Fatalf("invoke %s %s at %s: %v (evaluate: %v)", r.Scope, r.Purpose, r.LogicalAt, err, directErr)
	}
	return x, m
}

func armRequest(t testing.TB, r a.Request, discovery a.Result, budget int64) a.Request {
	t.Helper()
	kind := "CATEGORY_CONCERN"
	if discovery.Action == "URGENT" {
		kind = "INDEPENDENT_URGENT"
	}
	r.Scope, r.Purpose, r.Sequence = "ARM", "ASSESS", 1
	r.State, r.BudgetMS = discovery.InitialCandidateState, &budget
	r.CandidateID, _ = a.Identity("candidate", CategoryID, map[string]any{"run": r.Run, "category": r.Category, "asset": r.Asset, "sequence": r.Sequence, "budget_ms": budget})
	terminal, _ := a.Identity("terminal", CategoryID, map[string]any{"candidate": r.CandidateID})
	entered := *discovery.EntryQualifiedAt
	r.Entry = &a.Entry{Basis: kind, AvailableAt: entered, BundleID: r.Bundle.ID, Support: discovery.Support, Fallback: a.Fallback{
		Schema: 1, DueAt: entered.Add(time.Duration(budget) * time.Millisecond), TerminalID: terminal,
		Action: "INVESTIGATE", Route: "hardware_investigation", Summary: discovery.Summary,
	}}
	return r
}

func trackerRequest(r a.Request, state *a.Payload) a.Request {
	r.Purpose, r.Sequence, r.State = "FOLLOW_UP", 1, state
	return r
}

func requireOutcome(t testing.TB, x a.Result, outcome string) {
	t.Helper()
	if x.Outcome != CategoryID+"/"+outcome {
		t.Fatalf("got %s (%v), want %s", x.Outcome, x.Reasons, outcome)
	}
}

func constant(v float64) func(int) float64 { return func(int) float64 { return v } }

func warmRamp(s int) float64 {
	if s >= 650 {
		return 64
	}
	return 50
}

func TestCoolingTemperatureQualifiesBeforePowerCorroboration(t *testing.T) {
	cases := []struct {
		name        string
		temp, power func(int) float64
		branch, end string
	}{
		{"falling", func(s int) float64 { return 70 - float64(s)/30 }, constant(200), "", ""},
		{"rapid", func(s int) float64 { return 30 + float64(s)/25 }, constant(200), "RAPID", "COOLING_SUSPECTED"},
		{"slow", func(s int) float64 { return 55 + float64(s)/100 }, constant(200), "SLOW", "COOLING_SUSPECTED"},
		{"changing power", warmRamp, func(s int) float64 { return 100 + float64(s) }, "RAPID", "UNRESOLVED_WARMING"},
		{"unknown power", warmRamp, nil, "RAPID", "UNRESOLVED_WARMING"},
		{"persistent without power", constant(75), nil, "PERSISTENT", "COOLING_SUSPECTED"},
		{"cooling while still hot", func(s int) float64 { return 86 - float64(s)/100 }, nil, "PERSISTENT", "COOLING_SUSPECTED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := request(t, tc.temp, tc.power)
			r.DiscoveryFloor = r.LogicalAt
			x, m := invoke(t, r)
			if tc.branch == "" {
				requireOutcome(t, x, "NO_CANDIDATE")
				return
			}
			requireOutcome(t, x, "OBSERVING")
			var tracker TrackerState
			if err := json.Unmarshal(x.State.Body, &tracker); err != nil || !slices.Contains(tracker.Branches, tc.branch) {
				t.Fatalf("branch %s missing from %+v: %v", tc.branch, tracker, err)
			}
			y, _ := invoke(t, armRequest(t, m, x, 0))
			requireOutcome(t, y, tc.end)
		})
	}
}

func TestCoolingHostMaterializesLongSupport(t *testing.T) {
	r := request(t, func(s int) float64 { return 40 + float64(s)/100 }, constant(200))
	x, m := invoke(t, r)
	if x.EntryQualifiedAt == nil || !x.EntryQualifiedAt.Equal(clock(615)) || len(m.Bundle.Features) == 0 || len(x.Support) > 32 {
		t.Fatalf("entry at %v, features %d, citations %d", x.EntryQualifiedAt, len(m.Bundle.Features), len(x.Support))
	}
	if !slices.ContainsFunc(x.ProposedFeatures, func(f a.Feature) bool { return len(f.Support) > 32 }) {
		t.Fatal("long raw support closure missing")
	}
}

func TestCoolingFirstEligibilityAndLateAdmission(t *testing.T) {
	for _, tc := range []struct {
		name         string
		availability int
		want         int
	}{{"future source", 885, 900}, {"late admission", 905, 905}} {
		t.Run(tc.name, func(t *testing.T) {
			r := request(t, func(s int) float64 {
				if s >= 870 {
					return 75
				}
				return 74.9
			}, nil)
			r.DiscoveryFloor = clock(885)
			r.Facts = r.Facts[:len(r.Facts)-1]
			last := sample(t, Temperature, clock(900), clock(tc.availability), 75)
			early := rebase(t, r, clock(tc.want-1), last)
			x, _ := invoke(t, early)
			requireOutcome(t, x, "NO_CANDIDATE")
			late := rebase(t, r, clock(925), last)
			late.DiscoveryFloor = early.LogicalAt
			x, m := invoke(t, late)
			if x.EntryQualifiedAt == nil || !x.EntryQualifiedAt.Equal(clock(tc.want)) {
				t.Fatalf("qualification %v, want %s", x.EntryQualifiedAt, clock(tc.want))
			}
			if m.Facts[len(r.Facts)].ID != last.ID || !m.Facts[len(r.Facts)].AvailableAt.Equal(last.AvailableAt) {
				t.Fatal("raw sample was rewritten")
			}
			for _, changed := range []time.Time{clock(tc.want - 1), clock(tc.want + 1), late.LogicalAt} {
				y := x
				y.EntryQualifiedAt = &changed
				if err := (Category{}).ValidateResult(context.Background(), m, y); err == nil {
					t.Fatalf("accepted incorrect entry time %s", changed)
				}
			}
		})
	}
}

func TestCoolingEveryPersistenceSampleMustPass(t *testing.T) {
	for _, tc := range []struct {
		name   string
		dip    float64
		latest float64
		want   string
	}{
		{"1.1 degree dip", 62.9, 64, "UNRESOLVED_WARMING"},
		{"0.9 degree dip", 63.1, 64, "COOLING_SUSPECTED"},
		{"falling after qualifying plateau", 64, 55, "UNRESOLVED_WARMING"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request(t, warmRamp, constant(200))
			r.DiscoveryFloor = r.LogicalAt
			x, m := invoke(t, r)
			arm := armRequest(t, m, x, 30_000)
			arm = rebase(t, arm, clock(930), sample(t, Temperature, clock(915), clock(915), 64), sample(t, Temperature, clock(920), clock(920), tc.dip),
				sample(t, Temperature, clock(930), clock(930), tc.latest), sample(t, Power, clock(915), clock(915), 200), sample(t, Power, clock(930), clock(930), 200))
			y, _ := invoke(t, arm)
			requireOutcome(t, y, tc.want)
		})
	}
}

func TestCoolingDoesNotBorrowStablePowerPrefix(t *testing.T) {
	for _, tc := range []struct {
		name string
		keep func(a.Sample) bool
		want string
	}{
		{"complete", func(a.Sample) bool { return true }, "COOLING_SUSPECTED"},
		{"power missing before both branch windows", func(s a.Sample) bool { return s.Metric != Power || !s.SourceAt.Before(clock(600)) }, "UNRESOLVED_WARMING"},
		{"end alignment missing", func(s a.Sample) bool { return s.Metric != Power || s.SourceAt.Before(clock(885)) }, "UNRESOLVED_WARMING"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request(t, warmRamp, constant(200))
			r.DiscoveryFloor = r.LogicalAt
			r.Facts = slices.DeleteFunc(r.Facts, func(f a.Fact) bool { var s a.Sample; _ = json.Unmarshal(f.Body, &s); return !tc.keep(s) })
			r = rebase(t, r, r.LogicalAt)
			x, m := invoke(t, r)
			requireOutcome(t, x, "OBSERVING")
			y, _ := invoke(t, armRequest(t, m, x, 0))
			requireOutcome(t, y, tc.want)
		})
	}
}

func TestCoolingTerminalCurrentProjectionAndUpdateThreshold(t *testing.T) {
	r := request(t, warmRamp, nil)
	r = rebase(t, r, clock(945), sample(t, Temperature, clock(915), clock(915), 64), sample(t, Temperature, clock(930), clock(930), 70),
		sample(t, Temperature, clock(945), clock(945), 72))
	r.DiscoveryFloor = r.LogicalAt
	x, m := invoke(t, r)
	arm := armRequest(t, m, x, 15_000)
	arm = rebase(t, arm, clock(960), sample(t, Temperature, clock(960), clock(960), 72))
	arm.ExecutedAt = clock(1560)
	y, m := invoke(t, arm)
	requireOutcome(t, y, "UNRESOLVED_WARMING")
	var detail Details
	if err := json.Unmarshal(y.Details.Body, &detail); err != nil || detail.Temperature == nil || detail.Temperature.Value != 72 ||
		!detail.Temperature.SourceAt.Equal(clock(960)) || y.TerminalEndpointID != detail.Temperature.ID {
		t.Fatalf("terminal temperature: %+v, %v", detail.Temperature, err)
	}
	invalid := y
	invalid.TerminalEndpointID = ""
	if err := (Category{}).ValidateResult(context.Background(), m, invalid); err == nil {
		t.Fatal("accepted omitted terminal projection")
	}
	var old State
	if err := json.Unmarshal(x.InitialCandidateState.Body, &old); err != nil || old.EntryEndpoint == nil ||
		old.EntryEndpoint.Value != 70 || !old.EntryEndpoint.SourceAt.Equal(clock(945)) || !slices.Contains(y.Support, old.EntryEndpoint.ID) {
		t.Fatalf("older entry endpoint was not retained as a citation: %+v, %v", old.EntryEndpoint, err)
	}
	invalid = y
	invalid.TerminalEndpointID = old.EntryEndpoint.ID
	if err := (Category{}).ValidateResult(context.Background(), m, invalid); err == nil {
		t.Fatal("accepted alternative terminal projection")
	}
	invalid = y
	badDetails := detail
	badRef := *detail.Temperature
	badRef.Value--
	badDetails.Temperature = &badRef
	invalid.Details, _ = payload("details", badDetails)
	if err := (Category{}).ValidateResult(context.Background(), m, invalid); err == nil {
		t.Fatal("accepted details/projection disagreement")
	}
	withoutDetails := y
	withoutDetails.Details = nil
	if err := (Category{}).ValidateResult(context.Background(), m, withoutDetails); err != nil {
		t.Fatalf("optional detail omission rejected: %v", err)
	}
	arm = m
	arm.Purpose = "FOLLOW_UP"
	arm.Terminal = &a.Terminal{DecisionID: arm.Entry.Fallback.TerminalID, LogicalAt: arm.LogicalAt, Action: "INVESTIGATE", Endpoint: detail.Temperature, UrgentOccurrences: []a.Occurrence{}}
	for _, tc := range []struct {
		value float64
		want  bool
	}{{76.999, false}, {77, true}} {
		follow := rebase(t, arm, clock(1005), sample(t, Temperature, clock(975), clock(975), tc.value), sample(t, Temperature, clock(990), clock(990), tc.value), sample(t, Temperature, clock(1005), clock(1005), tc.value))
		z, _ := invoke(t, follow)
		if slices.Contains(z.UpdateCodes, "higher_temperature") != tc.want || z.State != nil || z.Outcome != "" {
			t.Fatalf("update at %v: %+v", tc.value, z)
		}
	}
}

func TestCoolingUrgentOnlyRecoveryUsesExactOccurrence(t *testing.T) {
	r := request(t, constant(65), nil)
	r.DiscoveryFloor = r.LogicalAt
	open := thermal(t, "thermal-policy", 2, "OPEN", "gpu_thermal", 1, clock(900), clock(900))
	x, m := invoke(t, rebase(t, r, clock(900), open))
	requireOutcome(t, x, "URGENT_BYPASS")
	if x.TerminalEndpointID == "" {
		t.Fatal("urgent terminal omitted available temperature")
	}
	tracker := trackerRequest(m, x.State)
	var cooled []a.Fact
	for s := 915; s <= 1200; s += 15 {
		cooled = append(cooled, sample(t, Temperature, clock(s), clock(s), 65))
	}
	for _, tc := range []struct {
		name     string
		recovery a.Fact
		want     string
	}{
		{"another occurrence", thermal(t, "thermal-policy", 3, "RECOVER", "gpu_thermal", 1, clock(915), clock(915)), "UNCHANGED"},
		{"another revision", thermal(t, "thermal-policy", 2, "RECOVER", "gpu_thermal", 2, clock(915), clock(915)), "UNCHANGED"},
		{"exact recovery", thermal(t, "thermal-policy", 2, "RECOVER", "gpu_thermal", 1, clock(915), clock(915)), "REARM"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			y, _ := invoke(t, rebase(t, tracker, clock(1200), append(slices.Clone(cooled), tc.recovery)...))
			if y.Kind != tc.want {
				t.Fatalf("got %s, want %s", y.Kind, tc.want)
			}
			if tc.want == "REARM" && !slices.Contains(y.Support, tc.recovery.ID) {
				t.Fatal("rearm omitted exact recovery evidence")
			}
		})
	}
}

func TestCoolingRearmChecksIntermediateWarming(t *testing.T) {
	r := request(t, func(s int) float64 {
		switch {
		case s >= 850:
			return 76
		case s >= 375 && s <= 540:
			return 61
		default:
			return 68
		}
	}, nil)
	r.DiscoveryFloor = r.LogicalAt
	x, m := invoke(t, r)
	tracker := trackerRequest(m, x.State)
	var cooled []a.Fact
	for s := 915; s <= 1575; s += 15 {
		cooled = append(cooled, sample(t, Temperature, clock(s), clock(s), 68))
	}
	middle, _ := invoke(t, rebase(t, tracker, clock(1260), cooled...))
	if middle.Kind != "UNCHANGED" {
		t.Fatalf("rearmed with intermediate slow warming: %+v", middle)
	}
	last := rebase(t, tracker, clock(1575), cooled...)
	ready, _ := invoke(t, last)
	if ready.Kind != "REARM" {
		t.Fatalf("did not rearm after a complete clean interval: %+v", ready)
	}
	unknown := fact(t, clock(1575), "COVERAGE", a.Coverage{Metric: Temperature, From: clock(1425), Through: clock(1425), Code: "COVERAGE", SourceRecord: "fixture"})
	incomplete, _ := invoke(t, rebase(t, last, clock(1575), unknown))
	if incomplete.Kind != "UNCHANGED" {
		t.Fatalf("rearmed through a recorded coverage failure: %+v", incomplete)
	}
}

func reboundRequest(t *testing.T) a.Request {
	r := request(t, func(s int) float64 {
		if s >= 630 {
			return 64
		}
		return 50
	}, func(s int) float64 {
		if s >= 510 && s < 570 || s >= 690 && s < 765 {
			return 100
		}
		return 200
	})
	r.DiscoveryFloor = r.LogicalAt
	return r
}

func TestCoolingLatestReboundIsFrozenInMaterializedEntryBundle(t *testing.T) {
	r := rebase(t, reboundRequest(t), clock(925), sample(t, Power, clock(915), clock(915), 250), sample(t, Temperature, clock(915), clock(915), 69))
	entry, m := invoke(t, r)
	if entry.EntryQualifiedAt == nil || !entry.EntryQualifiedAt.Equal(clock(900)) {
		t.Fatalf("qualification %v, want %s", entry.EntryQualifiedAt, clock(900))
	}
	withRebound, err := a.EntryView(m, *entry.EntryQualifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	var tstate TrackerState
	if err := json.Unmarshal(entry.State.Body, &tstate); err != nil || tstate.Rebound == nil {
		t.Fatalf("rebound missing: %v %+v", err, tstate)
	}
	ref := tstate.Rebound
	if !ref.DropAt.Equal(clock(690)) || !ref.RiseAt.Equal(clock(780)) || !ref.Reference.SourceAt.Equal(clock(660)) ||
		ref.Reference.Value != 64 || ref.PrePowerW != 200 || ref.BundleID != withRebound.Bundle.ID {
		t.Fatalf("wrong rebound or supporting bundle: %+v, bundle %s", ref, withRebound.Bundle.ID)
	}
	var want []string
	for _, f := range withRebound.Facts {
		if f.Kind != "SAMPLE" {
			continue
		}
		var s a.Sample
		if err := json.Unmarshal(f.Body, &s); err != nil {
			t.Fatal(err)
		}
		sec := int(s.SourceAt.Sub(origin).Seconds())
		if s.Metric == Temperature && slices.Contains([]int{630, 645, 660}, sec) ||
			s.Metric == Power && slices.Contains([]int{660, 675, 690, 705, 720, 750, 765, 780, 795, 810, 870, 885, 900}, sec) {
			want = append(want, f.ID)
		}
	}
	for _, proposal := range entry.ProposedFeatures {
		if proposal.FeatureKind == "rebound" && !slices.Equal(proposal.Support, a.SortedUnique(want)) {
			t.Fatalf("selected rebound support %v, want %v", proposal.Support, a.SortedUnique(want))
		}
	}
	ctxFact := fact(t, clock(900), "TRACKER_CONTEXT", a.TrackerContext{Category: CategoryID, Revision: 2, Payload: *entry.State, BundleID: withRebound.Bundle.ID})
	shared := &a.SharedContext{Payload: *entry.State, AvailableAt: ctxFact.AvailableAt, BundleID: withRebound.Bundle.ID, Revision: 2}
	zero := rebase(t, armRequest(t, withRebound, entry, 0), clock(900), ctxFact)
	without, _ := invoke(t, zero)
	requireOutcome(t, without, "UNRESOLVED_WARMING")
	zero.SharedContext = shared
	with, _ := invoke(t, zero)
	requireOutcome(t, with, "TRANSIENT_SUPPORTED")
	if !slices.Contains(with.Reasons, "rebound") || !slices.Contains(with.Support, ref.Reference.ID) {
		t.Fatal("transient omitted the frozen rebound evidence")
	}
	// A conflict in the frozen original power proof disables that reference,
	// even though the earlier transition pair could yield another reference.
	fromConflict := sample(t, Power, clock(765), clock(945), 201)
	var original string
	for _, f := range withRebound.Facts {
		if f.Kind == "SAMPLE" {
			var s a.Sample
			if err := json.Unmarshal(f.Body, &s); err == nil && s.Metric == Power && s.SourceAt.Equal(clock(765)) {
				original = f.ID
			}
		}
	}
	conflict := fact(t, clock(945), "CONFLICT", a.Conflict{Metric: Power, SourceAt: clock(765), Values: a.SortedUnique([]string{original, fromConflict.ID}), Code: "CONFLICT"})
	arm := rebase(t, armRequest(t, withRebound, entry, 120_000), clock(945), ctxFact)
	arm.SharedContext = shared
	contested := rebase(t, arm, clock(945), fromConflict, conflict)
	blocked, _ := invoke(t, contested)
	requireOutcome(t, blocked, "OBSERVING")
	changed, _ := invoke(t, rebase(t, trackerRequest(withRebound, entry.State), clock(945), fromConflict, conflict))
	if changed.State != nil || len(changed.ProposedFeatures) > 0 {
		t.Fatalf("tracker replaced the contested rebound: %+v", changed)
	}
	arm.SharedContext = nil
	observing, _ := invoke(t, arm)
	var state State
	if err := json.Unmarshal(observing.State.Body, &state); err != nil || state.Rebound == nil || state.Rebound.BundleID != ref.BundleID {
		t.Fatalf("missing context altered the persisted rebound: %+v, %v", state.Rebound, err)
	}
	var hot []a.Fact
	for s := 915; s <= 975; s += 15 {
		hot = append(hot, sample(t, Temperature, clock(s), clock(s), 75))
	}
	strong, _ := invoke(t, rebase(t, arm, clock(975), hot...))
	requireOutcome(t, strong, "COOLING_SUSPECTED")
}

func TestCoolingAbsentStaleAndConflictedTerminalNeverSeedBaseline(t *testing.T) {
	r := request(t, warmRamp, nil)
	r.DiscoveryFloor = r.LogicalAt
	entry, m := invoke(t, r)
	arm := armRequest(t, m, entry, 60_000)
	var state State
	if err := json.Unmarshal(arm.State.Body, &state); err != nil {
		t.Fatal(err)
	}
	arm.Purpose = "FOLLOW_UP"
	newOpen := thermal(t, "hbm", 1, "OPEN", "hbm_thermal", 1, clock(990), clock(990))
	oldOpen := thermal(t, "gpu", 1, "OPEN", "gpu_thermal", 1, clock(915), clock(915))
	last := []a.Fact{sample(t, Temperature, clock(960), clock(960), 70), sample(t, Temperature, clock(975), clock(975), 70), sample(t, Temperature, clock(990), clock(990), 70), oldOpen}
	contested := sample(t, Temperature, clock(900), clock(990), 65)
	original := sample(t, Temperature, clock(900), clock(900), 64)
	conflict := fact(t, clock(990), "CONFLICT", a.Conflict{Metric: Temperature, SourceAt: clock(900), Values: a.SortedUnique([]string{original.ID, contested.ID}), Code: "CONFLICT"})
	for _, tc := range []struct {
		name string
		base *a.FeatureRef
		at   int
		new  bool
		bad  bool
		want []string
	}{
		{"no endpoint and same urgent occurrence", nil, 915, false, false, []string{}},
		{"no endpoint and new urgent occurrence", nil, 915, true, false, []string{"urgent"}},
		{"stale endpoint", state.EntryEndpoint, 950, true, false, []string{"urgent"}},
		{"contested endpoint", state.EntryEndpoint, 915, true, true, []string{"urgent"}},
		{"combined update", state.EntryEndpoint, 915, true, false, []string{"higher_temperature", "urgent"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := arm
			r.Terminal = &a.Terminal{DecisionID: r.Entry.Fallback.TerminalID, LogicalAt: clock(tc.at), Action: "URGENT", Endpoint: tc.base, UrgentOccurrences: []a.Occurrence{{PolicyID: "gpu", Occurrence: 1}}}
			facts := slices.Clone(last)
			if tc.new {
				facts = append(facts, newOpen)
			}
			if tc.bad {
				facts = append(facts, contested, conflict)
			}
			y, _ := invoke(t, rebase(t, r, clock(990), facts...))
			if !slices.Equal(y.UpdateCodes, tc.want) || slices.Contains(y.Support, oldOpen.ID) || len(tc.want) > 0 && y.Action != "URGENT" {
				t.Fatalf("got %+v, want codes %v", y, tc.want)
			}
		})
	}
}

func TestCoolingFirstReboundWaitsForItsOwnEvidenceWithoutDelayingEntry(t *testing.T) {
	r := reboundRequest(t)
	for i, f := range r.Facts {
		var v a.Sample
		if err := json.Unmarshal(f.Body, &v); err != nil {
			t.Fatal(err)
		}
		if v.Metric == Power {
			r.Facts[i].AvailableAt = clock(915)
		}
	}
	late := rebase(t, r, clock(925))
	entry, m := invoke(t, late)
	if entry.EntryQualifiedAt == nil || !entry.EntryQualifiedAt.Equal(clock(900)) {
		t.Fatalf("late power changed earliest temperature entry: %v", entry.EntryQualifiedAt)
	}
	tracker, err := decodePayload[TrackerState](*entry.State, "tracker", stateLimit)
	if err != nil || tracker.Rebound != nil {
		t.Fatalf("entry borrowed late power: %+v (%v)", tracker.Rebound, err)
	}
	follow, view := invoke(t, trackerRequest(m, entry.State))
	tracker, err = decodePayload[TrackerState](*follow.State, "tracker", stateLimit)
	if err != nil || tracker.Rebound == nil || tracker.Rebound.BundleID != view.Bundle.ID {
		t.Fatalf("newly eligible rebound failed to freeze at follow-up: %+v (%v)", tracker.Rebound, err)
	}
}

func TestCoolingSettlingRequiresAllIntermediateMedians(t *testing.T) {
	r := request(t, func(s int) float64 {
		if s >= 650 {
			return 72
		}
		return 60
	}, nil)
	r.DiscoveryFloor = r.LogicalAt
	entry, m := invoke(t, r)
	arm := armRequest(t, m, entry, 120_000)
	samples := []a.Fact{sample(t, Temperature, clock(915), clock(915), 72)}
	for s := 930; s <= 990; s += 15 {
		samples = append(samples, sample(t, Temperature, clock(s), clock(s), 60))
	}
	blocked, _ := invoke(t, rebase(t, arm, clock(975), samples...))
	requireOutcome(t, blocked, "OBSERVING")
	clear, _ := invoke(t, rebase(t, arm, clock(990), samples...))
	requireOutcome(t, clear, "TRANSIENT_SUPPORTED")
}

func TestCoolingRearmRequiresEveryIntermediateEndpointCovered(t *testing.T) {
	r := request(t, warmRamp, nil)
	r.DiscoveryFloor = r.LogicalAt
	entry, m := invoke(t, r)
	tracker := trackerRequest(m, entry.State)
	var cool []a.Fact
	for s := 915; s <= 1260; s += 15 {
		if s != 1035 {
			cool = append(cool, sample(t, Temperature, clock(s), clock(s), 50))
		}
	}
	// A 30-second gap at [1020,1050] passes 5-minute interval coverage,
	// but the sample at 1055 has no covered [1025,1055] endpoint.
	cool = append(cool, sample(t, Temperature, clock(1055), clock(1055), 50))
	gapped, _ := invoke(t, rebase(t, tracker, clock(1260), cool...))
	if gapped.Kind != "UNCHANGED" {
		t.Fatalf("rearmed despite uncovered intermediate endpoint: %+v", gapped)
	}
	complete, _ := invoke(t, rebase(t, tracker, clock(1260), append(cool, sample(t, Temperature, clock(1035), clock(1260), 50))...))
	if complete.Kind != "REARM" {
		t.Fatalf("rearm failed with complete intermediate endpoints: %+v", complete)
	}
}

func TestCoolingWarmingTrackerPersistsPostEntryUrgentThroughHistoryLoss(t *testing.T) {
	r := request(t, warmRamp, nil)
	r.DiscoveryFloor = r.LogicalAt
	entry, m := invoke(t, r)
	tr := trackerRequest(m, entry.State)
	open := thermal(t, "thermal", 2, "OPEN", "gpu_thermal", 1, clock(960), clock(960))
	tracked, _ := invoke(t, rebase(t, tr, clock(960), open))
	if tracked.State == nil {
		t.Fatal("tracker ignored post-entry OPEN while temperature was stale")
	}
	s, err := decodePayload[TrackerState](*tracked.State, "tracker", stateLimit)
	if err != nil || !slices.Equal(s.UrgentOccurrences, []a.Occurrence{{PolicyID: "thermal", Occurrence: 2}}) || !slices.Contains(tracked.Support, open.ID) {
		t.Fatalf("qualified occurrence was not recorded with proof: %+v (%v)", s.UrgentOccurrences, err)
	}
	tr.State = tracked.State
	var cooled []a.Fact
	for sec := 1590; sec <= 2205; sec += 15 {
		cooled = append(cooled, sample(t, Temperature, clock(sec), clock(sec), 50))
	}
	missingOpen, _ := invoke(t, rebase(t, tr, clock(2205), cooled...))
	if missingOpen.Kind != "UNCHANGED" {
		t.Fatalf("urgent occurrence disappearing was treated as recovery: %+v", missingOpen)
	}
	recovery := thermal(t, "thermal", 2, "RECOVER", "gpu_thermal", 1, clock(2175), clock(2175))
	recovered, _ := invoke(t, rebase(t, tr, clock(2205), append(cooled, open, recovery)...))
	if recovered.Kind != "REARM" || !slices.Contains(recovered.Support, open.ID) || !slices.Contains(recovered.Support, recovery.ID) {
		t.Fatalf("rearm did not prove exact recovery: %+v", recovered)
	}
}

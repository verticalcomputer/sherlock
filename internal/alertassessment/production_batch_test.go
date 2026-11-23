package alertassessment_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
)

type recordingCooling struct {
	cooling.ProductionCategory
	calls *[]time.Time
}

func (c recordingCooling) Evaluate(ctx context.Context, r a.Request) (a.Result, error) {
	*c.calls = append(*c.calls, r.LogicalAt)
	return c.ProductionCategory.Evaluate(ctx, r)
}

func TestProductionBatchExpiryDuringSilence(t *testing.T) {
	rc := newReplayCase(t, false)
	var calls []time.Time
	r, err := a.NewRegistry(cooling.Category{}, recordingCooling{calls: &calls})
	if err != nil {
		t.Fatal(err)
	}
	e, err := a.NewProductionAssetEngine(t.Context(), rc.c, rc.start, r, rc.asset)
	if err != nil {
		t.Fatal(err)
	}
	facts := productionSamples(t, rc.c, rc.start, 55)
	if err := e.AdvanceProductionBatch(t.Context(), rc.asset, rc.start, facts); err != nil {
		t.Fatal(err)
	}
	policy, err := rc.c.Assessment.PolicyPayload(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	_, freshness := (cooling.ProductionCategory{}).ReplaySampleWindows(t.Context(), policy)
	edge := rc.start.Add(freshness)
	calls = nil
	if err := e.AdvanceProductionBatch(t.Context(), rc.asset, edge, nil); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(calls, edge) {
		t.Fatal("sample expired on inclusive boundary")
	}
	if err := e.AdvanceProductionBatch(t.Context(), rc.asset, edge.Add(time.Second), nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(calls, edge.Add(time.Microsecond)) {
		t.Fatalf("missing expiry wake: %v", calls)
	}
}

func TestProductionBatchDeadlineUsesIntermediateEvidence(t *testing.T) {
	rc := newReplayCase(t, false)
	engine := func() *a.Engine {
		e, err := a.NewProductionAssetEngine(t.Context(), rc.c, rc.start, rc.r, rc.asset)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	direct, batch := engine(), engine()
	var pending []a.Fact
	for sec := 0; sec <= 180; sec += 15 {
		at := rc.start.Add(time.Duration(sec) * time.Second)
		temp := 80.0
		if sec > 30 {
			temp = 72
		}
		facts := productionSamples(t, rc.c, at, temp)
		pending = append(pending, facts...)
		if err := direct.AdvanceAssets(t.Context(), at, at, at, facts, nil, []string{rc.asset}); err != nil {
			t.Fatal(err)
		}
	}
	now := rc.start.Add(180 * time.Second)
	slices.Reverse(pending)
	if err := batch.AdvanceProductionBatch(t.Context(), rc.asset, now, pending); err != nil {
		t.Fatal(err)
	}
	if len(batch.Decisions) == 0 || len(direct.Decisions) != len(batch.Decisions) {
		t.Fatalf("decisions differ: direct %+v batch %+v", direct.Decisions, batch.Decisions)
	}
	for i, got := range batch.Decisions {
		want := direct.Decisions[i]
		if got.Kind != "TERMINAL" || !got.LogicalAt.Equal(batch.Candidates[0].DueAt) {
			t.Fatalf("expected deadline decision, got %+v", got)
		}
		if got.ID != want.ID || got.BundleID != want.BundleID || got.Action != want.Action || !got.LogicalAt.Equal(want.LogicalAt) || !slices.Equal(got.Support, want.Support) {
			t.Fatalf("decision or evidence differs: got %+v want %+v", got, want)
		}
		if !got.ExecutedAt.Equal(now) || !got.CommittedAt.Equal(now) {
			t.Fatalf("backdated audit clock: %+v", got)
		}
		raw, err := batch.ProductionEvidence(got)
		if err != nil {
			t.Fatal(err)
		}
		var proof struct{ Facts []a.Fact }
		if err := json.Unmarshal(raw, &proof); err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(proof.Facts, func(f a.Fact) bool {
			return f.Kind == "SAMPLE" && f.AvailableAt.After(rc.start.Add(120*time.Second)) && !f.AvailableAt.After(got.LogicalAt)
		}) {
			t.Fatalf("missing intermediate predeadline sample in %s proof at %s", got.Kind, got.LogicalAt)
		}
	}
}

func TestProductionBatchLateAdmissionAndCancellation(t *testing.T) {
	rc := newReplayCase(t, false)
	e, err := a.NewProductionAssetEngine(t.Context(), rc.c, rc.start, rc.r, rc.asset)
	if err != nil {
		t.Fatal(err)
	}
	frontier := rc.start.Add(time.Minute)
	if err := e.AdvanceProductionBatch(t.Context(), rc.asset, frontier, nil); err != nil {
		t.Fatal(err)
	}
	now := frontier.Add(time.Minute)
	f := rc.sample(cooling.Temperature, rc.start, frontier, 55)
	if err := e.AdvanceProductionBatch(t.Context(), rc.asset, now, []a.Fact{f}); err != nil {
		t.Fatal(err)
	}
	if !e.Facts[f.ID].AvailableAt.Equal(now) {
		t.Fatalf("backdated newly admitted sample: %v", e.Facts[f.ID])
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := e.AdvanceProductionBatch(ctx, rc.asset, now, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

// A statement clock can cross a deadline while processing a query whose
// evidence snapshot precedes it. Only the next qualified snapshot may finalize.
func TestProductionBatchCommitClockCannotCrossEvidenceFrontier(t *testing.T) {
	rc := newReplayCase(t, false)
	e, err := a.NewProductionAssetEngine(t.Context(), rc.c, rc.start, rc.r, rc.asset)
	if err != nil {
		t.Fatal(err)
	}
	for sec := 0; sec <= 135; sec += 15 {
		at := rc.start.Add(time.Duration(sec) * time.Second)
		temp := 80.0
		if sec > 30 {
			temp = 72
		}
		if err := e.AdvanceProductionBatch(t.Context(), rc.asset, at, productionSamples(t, rc.c, at, temp)); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.Candidates) != 1 || e.Candidates[0].Phase != "OBSERVING" {
		t.Fatal("missing observation")
	}
	due := e.Candidates[0].DueAt
	e.CommitClock = func() time.Time { return due.Add(time.Second) }
	at := due.Add(-time.Millisecond)
	if err := e.AdvanceProductionBatch(t.Context(), rc.asset, at, productionSamples(t, rc.c, at, 73)); err != nil {
		t.Fatal(err)
	}
	if len(e.Decisions) != 0 {
		t.Fatalf("decision crossed acquisition frontier: %+v", e.Decisions)
	}
	if err := e.AdvanceProductionBatch(t.Context(), rc.asset, due, productionSamples(t, rc.c, due, 74)); err != nil {
		t.Fatal(err)
	}
	if len(e.Decisions) != 1 || !e.Decisions[0].LogicalAt.Equal(due) || !e.Decisions[0].CommittedAt.Equal(e.CommitClock()) {
		t.Fatalf("incorrect deadline: %+v", e.Decisions)
	}
}

type uncoalescedCooling struct{ recordingCooling }

func (uncoalescedCooling) CoalescesStaleFinalSamples() bool { return false }

func TestProductionBatchStaleFinalPrefixMatchesEveryReceipt(t *testing.T) {
	rc := newReplayCase(t, false)
	warm, err := a.NewProductionAssetEngine(t.Context(), rc.c, rc.start, rc.r, rc.asset)
	if err != nil {
		t.Fatal(err)
	}
	for sec := 0; sec <= 150; sec += 15 {
		at := rc.start.Add(time.Duration(sec) * time.Second)
		if err := warm.AdvanceProductionBatch(t.Context(), rc.asset, at, productionSamples(t, rc.c, at, 80)); err != nil {
			t.Fatal(err)
		}
	}
	if len(warm.Candidates) != 1 || warm.Candidates[0].Phase != "FINAL" {
		t.Fatal("expected finalized tracker")
	}
	snapshot, err := warm.SnapshotProduction(rc.asset, rc.start.Add(150*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	now := rc.start.Add(30 * time.Minute)
	var facts []a.Fact
	for i := 0; i < 8; i++ {
		received := now.Add(time.Duration(i) * time.Second)
		src := received.Add(-12*time.Minute + time.Duration(i)*15*time.Second)
		facts = append(facts, rc.sample(cooling.Power, src, received, 0), rc.sample(cooling.Temperature, src, received, 68))
	}
	// A fresh power sample is a conservative barrier even if temperature is
	// still stale. A later temperature sample must observe the admitted power.
	facts = append(facts, rc.sample(cooling.Power, now.Add(8*time.Second), now.Add(8*time.Second), 0), rc.sample(cooling.Temperature, now.Add(9*time.Second), now.Add(9*time.Second), 90))
	compare := func(t *testing.T, raw []byte, wantSavings bool) {
		run := func(coalesce bool) ([]byte, []string, int) {
			var calls []time.Time
			rec := recordingCooling{calls: &calls}
			var category a.Category = rec
			if !coalesce {
				category = uncoalescedCooling{rec}
			}
			reg, err := a.NewRegistry(cooling.Category{}, category)
			if err != nil {
				t.Fatal(err)
			}
			e, err := a.NewProductionAssetEngine(t.Context(), rc.c, rc.start, reg, rc.asset)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.RestoreProduction(rc.asset, raw); err != nil {
				t.Fatal(err)
			}
			at := now.Add(10 * time.Second)
			if err := e.AdvanceProductionBatch(t.Context(), rc.asset, at, facts); err != nil {
				t.Fatal(err)
			}
			var decisions []string
			for _, d := range e.Decisions {
				proof, err := e.ProductionEvidence(d)
				if err != nil {
					t.Fatal(err)
				}
				decisions = append(decisions, string(proof))
			}
			output, err := e.SnapshotProduction(rc.asset, at)
			if err != nil {
				t.Fatal(err)
			}
			return output, decisions, len(calls)
		}
		want, proofs, oldCalls := run(false)
		got, actual, newCalls := run(true)
		if string(got) != string(want) || !slices.Equal(actual, proofs) {
			t.Fatal("coalescing changed proof or durable state")
		}
		if wantSavings && newCalls >= oldCalls || !wantSavings && newCalls != oldCalls {
			t.Fatalf("expected savings %t: calls %d vs %d", wantSavings, newCalls, oldCalls)
		}
	}
	t.Run("stale prefix and fresh barrier", func(t *testing.T) { compare(t, snapshot, true) })
	t.Run("tracker wake inside stale prefix", func(t *testing.T) {
		var s a.ProductionSnapshot
		if err := json.Unmarshal(snapshot, &s); err != nil {
			t.Fatal(err)
		}
		wake := now.Add(4 * time.Second)
		s.Enrollment.NextLogicalAt = &wake
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		compare(t, raw, false)
	})
}

// This models one delayed upload with paired sensors, a deadline, and a cool
// sample during the gap. Every completed timestamp can be the last committed
// one before a crash.
func TestProductionSliceRestartMatchesUninterrupted(t *testing.T) {
	rc := newReplayCase(t, false)
	engine := func(raw []byte) *a.Engine {
		t.Helper()
		e, err := a.NewProductionAssetEngine(t.Context(), rc.c, rc.start, rc.r, rc.asset)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.RestoreProduction(rc.asset, raw); err != nil {
			t.Fatal(err)
		}
		return e
	}
	snapshot := func(e *a.Engine, at time.Time) []byte {
		t.Helper()
		raw, err := e.SnapshotProduction(rc.asset, at)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	proofs := func(e *a.Engine) []string {
		t.Helper()
		var out []string
		for _, d := range e.Decisions {
			raw, err := e.ProductionEvidence(d)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, string(raw))
		}
		return out
	}
	var inputs []a.Fact
	for sec := 0; sec <= 510; sec += 15 {
		temp := 80.0
		if sec > 150 {
			temp = 55
		}
		inputs = append(inputs, productionSamples(t, rc.c, rc.start.Add(time.Duration(sec)*time.Second), temp)...)
	}
	slices.Reverse(inputs)
	through := rc.start.Add(520 * time.Second)
	// Receipt/decision publication times stay fixed in this differential so the
	// full immutable proofs, including their hashes and clocks, are comparable.
	full := engine(nil)
	if err := full.AdvanceProductionBatch(t.Context(), rc.asset, through, inputs); err != nil {
		t.Fatal(err)
	}
	if len(full.Decisions) < 2 {
		t.Fatalf("fixture lacks transitions: %+v", full.Decisions)
	}
	want := proofs(full)
	e := engine(nil)
	if err := e.AdvanceProductionSlice(t.Context(), rc.asset, through, inputs, time.Now().Add(-time.Second), 1); err != nil {
		t.Fatal(err)
	}
	if !e.ProductionBatchPending() || len(e.Facts) != 0 {
		t.Fatal("acquisition must checkpoint before evaluation")
	}
	var got []string
	for i := 0; e.ProductionBatchPending(); i++ {
		if i > 200 {
			t.Fatal("cursor failed to advance")
		}
		// Pruning at a much later wall clock must not erase logical evidence.
		raw := snapshot(e, through.Add(2*time.Hour))
		e = engine(raw)
		if err := e.AdvanceProductionSlice(t.Context(), rc.asset, through, inputs[:1], time.Time{}, 1); !errors.Is(err, a.ErrInvalid) {
			t.Fatalf("accepted new facts while replaying: %v", err)
		}
		if err := e.AdvanceProductionSlice(t.Context(), rc.asset, through, nil, time.Time{}, 1); err != nil {
			t.Fatal(err)
		}
		got = append(got, proofs(e)...)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("interrupted proofs differ: got %d want %d", len(got), len(want))
	}
	if string(snapshot(e, through)) != string(snapshot(full, through)) {
		t.Fatal("interrupted snapshot differs")
	}

	// In service each slice has its own physical execution clock. No later
	// publication can advance the frozen logical cutoff or change its decisions.
	e = engine(nil)
	if err := e.AdvanceProductionSlice(t.Context(), rc.asset, through, inputs, time.Time{}, 1); err != nil {
		t.Fatal(err)
	}
	var delayed []a.Decision
	delayed = append(delayed, e.Decisions...)
	for i := 1; e.ProductionBatchPending(); i++ {
		if i > 200 {
			t.Fatal("delayed replay stuck")
		}
		physical := through.Add(time.Duration(i) * time.Minute)
		e = engine(snapshot(e, physical))
		if err := e.AdvanceProductionSlice(t.Context(), rc.asset, physical, nil, time.Time{}, 3); err != nil {
			t.Fatal(err)
		}
		for _, d := range e.Decisions {
			if !d.ExecutedAt.Equal(physical) || !d.CommittedAt.Equal(physical) {
				t.Fatal("backdated a delayed decision")
			}
		}
		delayed = append(delayed, e.Decisions...)
	}
	if len(delayed) != len(full.Decisions) {
		t.Fatalf("delayed replay lost transitions: %+v", delayed)
	}
	for i, d := range delayed {
		ref := full.Decisions[i]
		if d.ID != ref.ID || d.Kind != ref.Kind || d.Action != ref.Action || d.BundleID != ref.BundleID || !d.LogicalAt.Equal(ref.LogicalAt) || !slices.Equal(d.Support, ref.Support) {
			t.Fatalf("delayed replay changed %s transition", ref.Kind)
		}
	}
}

func TestProductionSliceResumeAfterWallClockAdvances(t *testing.T) {
	rc := newReplayCase(t, false)
	fresh := func() *a.Engine {
		t.Helper()
		e, err := a.NewProductionAssetEngine(t.Context(), rc.c, rc.start, rc.r, rc.asset)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := fresh()
	receipt := rc.start.Add(time.Minute)
	through := receipt.Add(time.Minute)
	resume := through.Add(time.Hour)
	inputs := productionSamples(t, rc.c, receipt, 55)
	inputs = append(inputs, rc.telemetryLoss("OPEN", 1, receipt, receipt), rc.telemetryLoss("RECOVER", 1, through, through))
	inputs = append(inputs, rc.fact("COVERAGE", receipt, a.Coverage{Metric: cooling.Temperature, Code: "sparse", From: receipt, Through: receipt, SourceRecord: "gap"}))
	if err := e.AdvanceProductionSlice(t.Context(), rc.asset, through, inputs, time.Time{}, 1); err != nil {
		t.Fatal(err)
	}
	if !e.ProductionBatchPending() || len(e.Telemetry) != 1 || e.ProductionSliceFailure() == nil {
		t.Fatal("fixture did not produce both ledgers in its first timestamp")
	}
	for _, f := range inputs[:2] {
		if _, ok := e.Facts[f.ID]; !ok {
			t.Fatal("split a same-time receipt group")
		}
	}
	snapshot, err := e.SnapshotProduction(rc.asset, resume)
	if err != nil {
		t.Fatal(err)
	}
	e = fresh()
	if err = e.RestoreProduction(rc.asset, snapshot); err != nil {
		t.Fatal(err)
	}
	if e.ProductionSliceFailure() != nil {
		t.Fatal("restored old failure as a fresh event")
	}
	if err = e.AdvanceProductionSlice(t.Context(), rc.asset, resume, nil, time.Now().Add(-time.Second), 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("silent no-progress retry: %v", err)
	}
	timedOut, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if err = e.AdvanceProductionSlice(timedOut, rc.asset, resume, nil, time.Time{}, 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hard timeout: %v", err)
	}
	for i := 0; e.ProductionBatchPending(); i++ {
		if i > 20 {
			t.Fatal("replay stuck")
		}
		if err = e.AdvanceProductionSlice(t.Context(), rc.asset, resume, nil, time.Time{}, 1); err != nil {
			t.Fatal(err)
		}
	}
	if !e.Enrollments[rc.asset].ProcessedAt.Equal(through) {
		t.Fatal("physical restart clock replaced frozen frontier")
	}
	for _, record := range e.Telemetry {
		if record.RecoverFact != inputs[3].ID || !record.LastAt.Equal(through) || record.Count != 2 {
			t.Fatalf("telemetry recovery lost: %+v", record)
		}
	}
	if len(e.Telemetry) != 1 || e.ProductionSliceFailure() != nil {
		t.Fatal("incorrect replay ledger")
	}
	late := rc.sample(cooling.Temperature, receipt.Add(time.Second), receipt.Add(time.Second), 56)
	if err = e.AdvanceProductionBatch(t.Context(), rc.asset, resume, []a.Fact{late}); err != nil {
		t.Fatal(err)
	}
	if f := e.Facts[late.ID]; !f.AvailableAt.Equal(resume) {
		t.Fatalf("retroactive receipt %v", f.AvailableAt)
	}
}

func TestProductionRejectsCorruptPendingReplay(t *testing.T) {
	rc := newReplayCase(t, false)
	engine := func() *a.Engine {
		e, err := a.NewProductionAssetEngine(t.Context(), rc.c, rc.start, rc.r, rc.asset)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := engine()
	now := rc.start.Add(time.Minute)
	if err := e.AdvanceProductionSlice(t.Context(), rc.asset, now, productionSamples(t, rc.c, rc.start, 55), time.Now().Add(-time.Second), 1); err != nil {
		t.Fatal(err)
	}
	raw, err := e.SnapshotProduction(rc.asset, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*a.ProductionSnapshot)
	}{
		{"missing horizon", func(s *a.ProductionSnapshot) { s.PendingReplay.Through = now.Add(time.Second) }},
		{"unordered", func(s *a.ProductionSnapshot) { s.PendingReplay.Steps[0].At = now.Add(time.Second) }},
		{"other asset", func(s *a.ProductionSnapshot) { s.PendingReplay.Steps[0].Facts[0].Asset = "other" }},
		{"future fact", func(s *a.ProductionSnapshot) { s.PendingReplay.Steps[0].Facts[0].AvailableAt = now.Add(time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s a.ProductionSnapshot
			if err := json.Unmarshal(raw, &s); err != nil {
				t.Fatal(err)
			}
			tc.change(&s)
			b, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			if err = engine().RestoreProduction(rc.asset, b); !errors.Is(err, a.ErrInvalid) {
				t.Fatalf("accepted corrupt replay: %v", err)
			}
		})
	}
}

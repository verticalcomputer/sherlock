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

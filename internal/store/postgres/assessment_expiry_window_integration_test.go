//go:build integration

package postgres

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
)

type assessmentExpiryFixtureEntry struct {
	at   time.Time
	wide bool
}

func stageAssessmentExpiryFixture(t *testing.T, f *assessmentFixture, store *AssessmentStore, entries []assessmentExpiryFixtureEntry, settledThrough time.Time) {
	t.Helper()
	ctx := context.Background()
	start := entries[0].at
	f.config = store.config
	// The replay fixture can stage already-overdue observing arms.
	f.seedRun(t, start)
	bindings, err := a.Canonical(f.config.Bindings)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := a.NewEngine(ctx, f.config, start, f.registry)
	if err != nil {
		t.Fatal(err)
	}
	snap := newAssessmentSnapshot()
	assets := []string{}
	for i, entry := range entries {
		asset := f.config.Assets[i]
		assets = append(assets, asset.EntityKey)
		f.exec(t, `INSERT INTO assessment_enrollments(run_id,category,asset,node_id,gpu_uuid,inventory_revision,bindings,discovery_floor,next_due_at,sequence,revision,rearm_eligible) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,0,1,true)`,
			f.config.RunID, f.config.Category, asset.EntityKey, asset.NodeID, asset.GPUUUID, f.config.InventoryRevision, bindings, start)
		snap.enrollmentRevision[asset.EntityKey] = 1
		var facts []a.Fact
		if entry.wide {
			facts = assessmentWideExpiryEntry(t, f.config, asset.EntityKey, entry.at)
		} else {
			for _, offset := range []time.Duration{-30 * time.Second, -15 * time.Second, 0} {
				facts = append(facts, assessmentWarmSample(t, f.config, asset.EntityKey, entry.at.Add(offset), entry.at))
			}
		}
		if err := engine.AdvanceAssets(ctx, entry.at, entry.at, entry.at, facts, nil, []string{asset.EntityKey}); err != nil {
			t.Fatal(err)
		}
	}
	if err := engine.AdvanceAssets(ctx, settledThrough, settledThrough, settledThrough, nil, nil, []string{}); err != nil {
		t.Fatal(err)
	}
	if len(engine.Candidates) != len(assets)*len(a.Budgets) {
		t.Fatalf("expected complete comparison cohorts, got %d candidates with failures %+v", len(engine.Candidates), engine.Failures)
	}
	for _, candidate := range engine.Candidates {
		if got, want := candidate.Phase == "OBSERVING", candidate.DueAt.After(settledThrough); got != want {
			t.Fatalf("unexpected staged phase for candidate due at %s: %s", candidate.DueAt, candidate.Phase)
		}
	}
	tx, err := beginAssessmentTx(ctx, f.admin)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	if err := store.saveEngine(ctx, tx, engine, snap, settledThrough, assets); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func assessmentWideExpiryEntry(t *testing.T, config a.Config, asset string, entry time.Time) []a.Fact {
	t.Helper()
	var facts []a.Fact
	for _, metric := range assessmentProfileMetrics {
		count := 129
		if metric.metric == cooling.Temperature {
			count = 253 // Leave space within the 256-point limit for three pre-deadline samples.
		}
		for offset := 1 - count; offset <= 0; offset++ {
			value := metric.value
			if metric.metric == cooling.Temperature {
				value = 74
				if offset >= -32 {
					value = 75
				}
			}
			source := entry.Add(time.Duration(offset) * time.Second)
			ref := fmt.Sprintf("wide-expiry-%s-%d", metric.metric, source.UnixMicro())
			fact, err := a.NewFact(config.Category, config.RunID, asset, "SAMPLE", entry, a.Sample{
				Metric: metric.metric, Unit: metric.unit, SourceAt: source, CollectedAt: entry,
				CompletedAt: entry, Value: value, SourceRecord: ref,
				Provenance: a.Provenance{Mode: "fixture", CollectionRunID: ref, Operation: metric.operation, ScheduleRevision: 1, InventoryRevision: config.InventoryRevision, SourceRecord: ref},
			})
			if err != nil {
				t.Fatal(err)
			}
			facts = append(facts, fact)
		}
	}
	return facts
}

func storeAssessmentExpiryFixtureFacts(t *testing.T, f *assessmentFixture, facts []a.Fact) {
	t.Helper()
	_, err := f.admin.CopyFrom(context.Background(), pgx.Identifier{"public", "assessment_facts"},
		[]string{"run_id", "id", "asset", "kind", "available_at", "body"},
		pgx.CopyFromSlice(len(facts), func(i int) ([]any, error) {
			fact := facts[i]
			body, err := encodeAssessmentFact(fact)
			return []any{fact.Run, fact.ID, fact.Asset, fact.Kind, fact.AvailableAt, body}, err
		}))
	if err != nil {
		t.Fatal(err)
	}
}

func requireAssessmentExpiryDecision(t *testing.T, e *a.Engine, asset string, due time.Time, eligible []a.Fact, tooLate a.Fact) (a.Decision, a.Bundle) {
	t.Helper()
	for _, d := range e.Decisions {
		if d.Asset != asset || d.BudgetMS != 30000 {
			continue
		}
		bundle, ok := e.Bundles[d.BundleID]
		if !ok {
			t.Fatalf("missing decision bundle %s", d.BundleID)
		}
		checkAssessmentExpiryDecision(t, d, bundle, due, eligible, tooLate)
		return d, bundle
	}
	t.Fatalf("missing 30-second decision for %s with failures %+v", asset, e.Failures)
	return a.Decision{}, a.Bundle{}
}

func checkAssessmentExpiryDecision(t *testing.T, d a.Decision, bundle a.Bundle, due time.Time, eligible []a.Fact, tooLate a.Fact) {
	t.Helper()
	if d.DecisionSource != "CATEGORY" || d.Outcome != cooling.CategoryID+"/COOLING_SUSPECTED" ||
		!d.LogicalAt.Equal(due) || !bundle.AvailabilityCutoff.Equal(due) || d.BundleID != bundle.ID {
		t.Fatalf("unexpected decision at %s: %+v", due, d)
	}
	for _, fact := range eligible {
		if !slices.Contains(bundle.Facts, fact.ID) {
			t.Fatalf("missing eligible post-entry fact %s", fact.ID)
		}
	}
	if slices.Contains(bundle.Facts, tooLate.ID) {
		t.Fatalf("post-cutoff fact %s entered the decision bundle", tooLate.ID)
	}
}

type assessmentExpiryClockTx struct {
	pgx.Tx
	t                *testing.T
	transactionAt    time.Time
	clockSamples     []time.Time
	clockReads       int
	initial, catchUp []string
}

func (tx *assessmentExpiryClockTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	switch sql {
	case "SELECT transaction_timestamp()":
		return tx.Tx.QueryRow(ctx, "SELECT $1::timestamptz", tx.transactionAt)
	case "SELECT clock_timestamp()":
		if tx.clockReads >= len(tx.clockSamples) {
			tx.t.Fatalf("unexpected clock read after %d samples", tx.clockReads)
		}
		sample := tx.clockSamples[tx.clockReads]
		tx.clockReads++
		return tx.Tx.QueryRow(ctx, "SELECT $1::timestamptz", sample)
	default:
		return tx.Tx.QueryRow(ctx, sql, args...)
	}
}

func (tx *assessmentExpiryClockTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if sql == assessmentRetainedLookbackSQL {
		asset := args[1].(string)
		if tx.clockReads == 0 {
			tx.initial = append(tx.initial, asset)
		} else {
			tx.catchUp = append(tx.catchUp, asset)
		}
	}
	return tx.Tx.Query(ctx, sql, args...)
}

func TestAssessmentRefreshReloadsNewlyDueRetainedWindows(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	prepareAssessmentProfile(t, f, time.Now().UTC())
	f.config.Assets = f.config.Assets[:4]
	first, peer, blocked, later := f.config.Assets[0].EntityKey, f.config.Assets[1].EntityKey, f.config.Assets[2].EntityKey, f.config.Assets[3].EntityKey
	store, err := NewAssessmentStore(ctx, f.restrictedPool(t), f.registry, f.config, "expiry-window-fixture")
	if err != nil {
		t.Fatal(err)
	}
	var start time.Time
	if err := f.admin.QueryRow(ctx, "SELECT clock_timestamp()-interval '1 minute'").Scan(&start); err != nil {
		t.Fatal(err)
	}
	start = start.UTC()
	peerEntry := start.Add(100 * time.Millisecond)
	firstDue, peerDue := start.Add(30*time.Second), peerEntry.Add(30*time.Second)
	entries := []assessmentExpiryFixtureEntry{{at: start}, {at: peerEntry}, {at: peerEntry}, {at: start.Add(2 * time.Second)}}
	stageAssessmentExpiryFixture(t, f, store, entries, start.Add(17*time.Second))
	eligible := []a.Fact{
		assessmentWarmSample(t, f.config, peer, peerEntry.Add(15*time.Second), peerEntry.Add(16*time.Second)),
		assessmentWarmSample(t, f.config, peer, peerEntry.Add(29*time.Second), peerEntry.Add(29*time.Second)),
	}
	tooLate := assessmentWarmSample(t, f.config, peer, peerDue, peerDue.Add(time.Millisecond))
	facts := append(slices.Clone(eligible), tooLate)
	for i := range a.MaxFacts + 1 {
		fact, err := a.NewFact(f.config.Category, f.config.RunID, blocked, "COVERAGE", peerEntry.Add(time.Second),
			a.Coverage{Metric: cooling.Temperature, From: peerEntry, Through: peerEntry, Code: "OVERFLOW_FIXTURE", SourceRecord: fmt.Sprintf("expiry-overflow-%d", i)})
		if err != nil {
			t.Fatal(err)
		}
		facts = append(facts, fact)
	}
	storeAssessmentExpiryFixtureFacts(t, f, facts)

	// Derive the reference from a transaction whose first load is already
	// at the peer cutoff. Both paths see the same immutable starting rows.
	reference := func() a.Bundle {
		tx, err := beginAssessmentTx(ctx, store.pool)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackMonitoringTx(tx)
		e, _, err := store.loadEngine(ctx, tx, peerDue, true)
		if err != nil {
			t.Fatal(err)
		}
		e.Shadow = false
		if err := e.AdvanceAssets(ctx, peerDue, peerDue, peerDue, nil, nil, []string{}); err != nil {
			t.Fatal(err)
		}
		_, bundle := requireAssessmentExpiryDecision(t, e, peer, peerDue, eligible, tooLate)
		return bundle
	}()

	pass, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()
	tx, err := beginAssessmentTx(pass, store.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	// Script the two logical wakes plus their execution/commit samples. The
	// loader, evaluators and persistence still use the normal refresh path.
	catchUpAt := peerDue.Add(2 * time.Millisecond)
	clockTx := &assessmentExpiryClockTx{
		Tx: tx, t: t, transactionAt: firstDue,
		clockSamples: []time.Time{firstDue, catchUpAt, catchUpAt.Add(time.Millisecond), catchUpAt.Add(2 * time.Millisecond)},
	}
	if err := store.refreshAssessmentTx(pass, clockTx, true); err != nil {
		t.Fatalf("refresh=%v after %d clock reads, retained windows loaded at start %v and catch-up %v",
			err, clockTx.clockReads, clockTx.initial, clockTx.catchUp)
	}
	if clockTx.clockReads != len(clockTx.clockSamples) || !slices.Equal(clockTx.initial, []string{first}) || !slices.Equal(clockTx.catchUp, []string{peer, blocked}) {
		t.Fatalf("read %d clocks, retained windows loaded at start %v and catch-up %v", clockTx.clockReads, clockTx.initial, clockTx.catchUp)
	}
	var d a.Decision
	var encoded []byte
	if err := f.admin.QueryRow(ctx, `SELECT d.logical_at,d.executed_at,d.committed_at,d.lateness_us,d.decision_source,d.outcome,d.bundle_id,b.body
FROM assessment_decisions d JOIN assessment_candidates c ON (c.run_id,c.id)=(d.run_id,d.candidate_id)
JOIN assessment_bundles b ON (b.run_id,b.id)=(d.run_id,d.bundle_id)
WHERE d.run_id=$1 AND c.asset=$2 AND c.budget_ms=30000 AND d.kind='TERMINAL'`, f.config.RunID, peer).
		Scan(&d.LogicalAt, &d.ExecutedAt, &d.CommittedAt, &d.LatenessUS, &d.DecisionSource, &d.Outcome, &d.BundleID, &encoded); err != nil {
		t.Fatal(err)
	}
	var persisted a.Bundle
	if err := a.DecodeStrict(encoded, &persisted, 256<<10); err != nil {
		t.Fatal(err)
	}
	checkAssessmentExpiryDecision(t, d, persisted, peerDue, eligible, tooLate)
	if persisted.ID != reference.ID || !d.ExecutedAt.Equal(clockTx.clockSamples[2]) ||
		d.CommittedAt.Before(clockTx.clockSamples[3]) || d.LatenessUS != d.CommittedAt.Sub(peerDue).Microseconds() {
		t.Fatalf("persisted decision has different evidence or invalid timing: reference=%s decision=%+v", reference.ID, d)
	}
	for _, want := range []struct{ asset, phase, source, failure string }{
		{first, "FINAL", "CATEGORY", ""},
		{blocked, "FINAL", "HOST_FALLBACK", "CAPACITY"},
		{later, "OBSERVING", "", ""},
	} {
		var phase, source, failure string
		if err := f.admin.QueryRow(ctx, `SELECT c.phase,coalesce(d.decision_source,''),coalesce(d.failure_code,'')
FROM assessment_candidates c LEFT JOIN assessment_decisions d ON (d.run_id,d.candidate_id,d.kind)=(c.run_id,c.id,'TERMINAL')
WHERE c.run_id=$1 AND c.asset=$2 AND c.budget_ms=30000`, f.config.RunID, want.asset).Scan(&phase, &source, &failure); err != nil {
			t.Fatal(err)
		}
		if phase != want.phase || source != want.source || failure != want.failure {
			t.Fatalf("asset %s: got %s/%s/%s, want %s/%s/%s", want.asset, phase, source, failure, want.phase, want.source, want.failure)
		}
	}
}

func TestAssessmentCatchUpExtendsEarlierArmRetainedWindow(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	prepareAssessmentProfile(t, f, time.Now().UTC())
	f.config.Assets = f.config.Assets[:1]
	asset := f.config.Assets[0].EntityKey
	store, err := NewAssessmentStore(ctx, f.restrictedPool(t), f.registry, f.config, "expiry-window-wide-fixture")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	firstDue, catchUpAt := start.Add(15*time.Second), start.Add(30*time.Second)
	stageAssessmentExpiryFixture(t, f, store, []assessmentExpiryFixtureEntry{{at: start, wide: true}}, start)
	earlyFact := assessmentWarmSample(t, f.config, asset, start.Add(14*time.Second), start.Add(14*time.Second))
	eligible := []a.Fact{
		assessmentWarmSample(t, f.config, asset, start.Add(15*time.Second), start.Add(16*time.Second)),
		assessmentWarmSample(t, f.config, asset, start.Add(29*time.Second), start.Add(29*time.Second)),
	}
	tooLate := assessmentWarmSample(t, f.config, asset, catchUpAt, catchUpAt.Add(time.Millisecond))
	storeAssessmentExpiryFixtureFacts(t, f, append(slices.Clone(eligible), earlyFact, tooLate))

	compute := func(loadAt time.Time, reload bool) a.Bundle {
		tx, err := beginAssessmentTx(ctx, store.pool)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackMonitoringTx(tx)
		e, snap, err := store.loadEngine(ctx, tx, loadAt, true)
		if err != nil {
			t.Fatal(err)
		}
		e.Shadow = false // Compare wide semantic views independently of race-test CPU timing.
		if _, ok := e.Facts[eligible[0].ID]; ok == reload {
			t.Fatalf("fixture did not create distinct initial history at %s", loadAt)
		}
		if err := e.AdvanceAssets(ctx, firstDue, firstDue, firstDue, nil, nil, []string{}); err != nil {
			t.Fatal(err)
		}
		if reload {
			var derived []string
			for id, fact := range e.Facts {
				if fact.Kind == "FEATURE" && !snap.facts[id] {
					derived = append(derived, id)
				}
			}
			if len(derived) == 0 {
				t.Fatal("first advance did not derive an in-transaction feature")
			}
			if err := reloadAssessmentExpiryWindows(ctx, tx, e, snap, catchUpAt); err != nil {
				t.Fatal(err)
			}
			for _, id := range derived {
				if _, ok := e.Facts[id]; !ok || snap.facts[id] {
					t.Fatalf("catch-up lost pending feature %s", id)
				}
			}
		}
		if err := e.AdvanceAssets(ctx, catchUpAt, catchUpAt, catchUpAt, nil, nil, []string{}); err != nil {
			t.Fatal(err)
		}
		_, bundle := requireAssessmentExpiryDecision(t, e, asset, catchUpAt, eligible, tooLate)
		if reload {
			if err := store.saveEngine(ctx, tx, e, snap, catchUpAt, nil); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		}
		return bundle
	}
	reference, extended := compute(catchUpAt, false), compute(firstDue, true)
	if extended.ID != reference.ID {
		t.Fatalf("extended window changed the cutoff evidence: initial=%s extended=%s", reference.ID, extended.ID)
	}
}

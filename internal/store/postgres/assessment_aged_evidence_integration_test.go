//go:build integration

package postgres

import (
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// Exercise the store's real resolver after frozen support has left the rolling
// window. Ordinary CI checks semantics/query counts under race instrumentation;
// the opt-in timing run keeps the real 50 ms GPU deadline on an uninstrumented build.
func TestAssessmentAgedEvidenceBatchesFollowup(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := t.Context()
	f.config.RunDurationSeconds = 3600
	entry := time.Now().UTC().Truncate(time.Microsecond).Add(-30 * time.Minute)
	f.seedRun(t, entry)
	f.seedEnrollment(t, entry)
	engine, err := a.NewEngine(ctx, f.config, entry, f.registry)
	if err != nil {
		t.Fatal(err)
	}
	asset := f.config.Assets[0].EntityKey
	var initial []a.Fact
	for i := 0; i < 60; i++ {
		source := entry.Add(time.Duration(i-59) * 15 * time.Second)
		temp := assessmentWarmSample(t, f.config, asset, source, entry)
		initial = append(initial, temp)
		power, err := a.NewFact(f.config.Category, f.config.RunID, asset, "SAMPLE", entry, a.Sample{Metric: cooling.Power, Unit: "watts", SourceAt: source, CollectedAt: entry, CompletedAt: entry, Value: 200, SourceRecord: temp.ID, Provenance: a.Provenance{Mode: "fixture", CollectionRunID: temp.ID, Operation: string(domain.OperationPrometheusGPUPower), ScheduleRevision: 1, InventoryRevision: f.config.InventoryRevision, SourceRecord: temp.ID}})
		if err != nil {
			t.Fatal(err)
		}
		initial = append(initial, power)
	}
	if err := engine.Advance(ctx, entry, entry, entry, initial, nil); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 8; i++ {
		at := entry.Add(time.Duration(i) * 15 * time.Second)
		if err := engine.Advance(ctx, at, at, at, []a.Fact{assessmentWarmSample(t, f.config, asset, at, at)}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(engine.Candidates) != 5 || !engine.Enrollments[asset].Active {
		t.Fatal("fixture must retain an active cohort")
	}
	for _, c := range engine.Candidates {
		if c.Phase != "FINAL" {
			t.Fatalf("arm %d is not final", c.BudgetMS)
		}
	}
	store := &AssessmentStore{pool: f.admin, registry: f.registry, config: f.config}
	snap := newAssessmentSnapshot()
	snap.enrollmentRevision[asset] = 1
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.saveEngine(ctx, tx, engine, snap, entry.Add(120*time.Second), []string{asset}); err != nil {
		rollbackMonitoringTx(tx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	trace := &assessmentQueryTrace{byStage: map[string][]time.Duration{}, failures: map[string]int{}}
	pc := f.restrictedPool(t).Config()
	pc.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store.pool = pool
	timing := os.Getenv("SHERLOCK_ASSESSMENT_AGED_TIMING") == "1"
	var durations []time.Duration
	for iteration := 0; iteration < 10; iteration++ {
		tx, err := beginAssessmentTx(ctx, pool)
		if err != nil {
			t.Fatal(err)
		}
		wake := entry.Add(30 * time.Minute)
		restored, snap, err := store.loadEngine(ctx, tx, wake, false)
		if err != nil {
			rollbackMonitoringTx(tx)
			t.Fatal(err)
		}
		if len(restored.Facts) != 0 {
			rollbackMonitoringTx(tx)
			t.Fatal("aged support must be absent from the resident window")
		}
		restored.Shadow = timing
		restored.ObserveGPU = func(_ string, d time.Duration) { durations = append(durations, d) }
		beforePoint, beforeBatch := len(trace.byStage["lookup_fact"]), len(trace.byStage["prefetch_admissions"])
		if err := restored.AdvanceAssets(ctx, wake, wake, wake, nil, nil, snap.selected); err != nil {
			rollbackMonitoringTx(tx)
			t.Fatal(err)
		}
		point, batch := len(trace.byStage["lookup_fact"])-beforePoint, len(trace.byStage["prefetch_admissions"])-beforeBatch
		if point != 0 || batch > 8 || batch == 0 {
			rollbackMonitoringTx(tx)
			t.Fatalf("aged evidence reads: point=%d batch=%d", point, batch)
		}
		if len(restored.Failures) != 0 {
			rollbackMonitoringTx(tx)
			t.Fatalf("aged follow-up failed: %+v", restored.Failures)
		}
		rollbackMonitoringTx(tx) // Each iteration is a fresh resolver, like restart/refresh.
	}
	p99 := assessmentProfileDistribution(t, "aged_gpu", durations)
	if timing && p99 > 50*time.Millisecond {
		t.Fatalf("aged GPU p99 %s exceeds unchanged 50 ms limit", p99)
	}
	t.Logf("aged evidence: 120 frozen samples, five final arms, 10 fresh transactions, zero per-fact SQL reads, <=8 batch reads/pass; timing=%t", timing)
}

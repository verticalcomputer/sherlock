//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestProductionOrderedRecoveryAtomicRestart(t *testing.T) {
	runOrderedRecoveryAtomicRestart(t, true, true)
}

func TestProductionOrderedFrozenInputsRespectAdmissionReserve(t *testing.T) {
	runOrderedRecoveryAtomicRestart(t, false, true)
}

func runOrderedRecoveryAtomicRestart(t *testing.T, priorOpen, atCapacity bool) {
	t.Helper()
	f, store, config, profile, hash, now := productionFleetFixture(t, 1)
	ctx := t.Context()
	asset := config.Assessment.Assets[0]
	run := config.Assessment.RunID
	start := now.Truncate(domain.CoolingUploadInterval).Add(-9 * time.Minute)

	// Set a prior authoritative checkpoint and use the database clock of each
	// synthetic upload. Keep all normal receipt, run and observation validation.
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	f.exec(t, `UPDATE prometheus_cooling_upload_profiles SET registered_at=starts_at-interval '1 second' WHERE profile_id=$1 AND revision=$2`, profile.ProfileID, profile.Revision)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	f.exec(t, `CREATE FUNCTION fixture_receipt_clock() RETURNS trigger LANGUAGE plpgsql AS $$
	BEGIN SELECT completed_at + interval '1 second' INTO NEW.received_at FROM collection_runs WHERE run_id=NEW.run_id; RETURN NEW; END $$;
	CREATE TRIGGER zz_fixture_receipt_clock BEFORE INSERT ON prometheus_cooling_upload_receipts FOR EACH ROW EXECUTE FUNCTION fixture_receipt_clock()`)

	config.Revision++
	config.NotificationsEnabled = true // Persist intents locally. No worker or webhook is configured.
	restart := func() *ProductionAssessmentStore {
		t.Helper()
		s, err := NewProductionAssessmentStore(ctx, f.admin, store.registry, config)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Start(ctx); err != nil {
			t.Fatal(err)
		}
		return s
	}
	store = restart()
	f.exec(t, `UPDATE production_assessment_enrollments SET created_at=$2, notifications_enabled_at=$2 WHERE enrollment_id=$1`, run, start)
	engine, err := a.NewProductionAssetEngine(ctx, config, start, store.registry, asset.EntityKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Advance(ctx, start, start, start, nil, nil); err != nil {
		t.Fatal(err)
	}
	processedSec := 0
	baselineRows := 0
	if priorOpen {
		// Stage the previous checkpoint with its real occurrence, incident and
		// outbox. Only the last few readings arrive in the acquisition under test.
		processedSec = 450
		for sec := 15; sec <= processedSec; sec += 15 {
			at := start.Add(time.Duration(sec) * time.Second)
			facts := productionStoreSamples(t, config, at)
			for i, fact := range facts {
				var sample a.Sample
				if err := json.Unmarshal(fact.Body, &sample); err != nil {
					t.Fatal(err)
				}
				if sample.Metric == "DCGM_FI_DEV_GPU_TEMP" && sec >= 165 {
					sample.Value = 60
					facts[i], err = a.NewFact(config.Assessment.Category, run, asset.EntityKey, "SAMPLE", at, sample)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			if err = engine.Advance(ctx, at, at, at, facts, nil); err != nil {
				t.Fatal(err)
			}
		}
		if len(engine.Decisions) != 1 {
			t.Fatalf("fixture should have one open occurrence: %d decisions", len(engine.Decisions))
		}
		d := engine.Decisions[0]
		evidence, err := engine.ProductionEvidenceContext(ctx, d)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := f.admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackMonitoringTx(tx)
		if _, err = tx.Exec(ctx, `INSERT INTO production_assessment_decisions(event_id,enrollment_id,occurrence_id,asset,kind,logical_at,evidence,evidence_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, d.ID, run, d.CandidateID, asset.EntityKey, d.Kind, d.LogicalAt, []byte(evidence), a.Hash("production_evidence", config.Assessment.Category, 1, evidence)); err != nil {
			t.Fatal(err)
		}
		if err = PublishProductionAssessment(ctx, tx, ProductionAssessmentEvent{EnrollmentID: run, ClusterID: config.Assessment.ClusterID, SourceID: config.Assessment.SourceID, Category: config.Assessment.Category, Asset: asset.EntityKey, OccurrenceID: d.CandidateID, EventID: d.ID, Kind: "OPEN", Summary: d.Summary, At: d.LogicalAt, Evidence: evidence}); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		baselineRows = 4 // One assessment decision, notification event, incident and outbox row.
	}
	before, err := engine.SnapshotProduction(asset.EntityKey, start.Add(time.Duration(processedSec)*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE production_assessment_states SET snapshot=$2 WHERE enrollment_id=$1`, run, before)

	writer, err := NewCollectionStore(f.admin)
	if err != nil {
		t.Fatal(err)
	}
	// A hot interval followed by a covered recovery and then a renewed rise.
	// Reading only the newest point would hide the intermediate recovery.
	for sec := processedSec + 15; sec <= 525; sec += 15 {
		slot := start.Add(time.Duration(sec) * time.Second)
		for _, query := range domain.CoolingUploadQueries() {
			report := assessmentUploadReport(profile, hash, query, slot)
			report.Version = profile.Version
			if query == domain.QueryGPUTemperature {
				v := 80.0
				if sec >= 165 && sec <= 495 {
					v = 60
				}
				report.Result.Observations[0].Value = v
			}
			if ok, err := writer.RecordCoolingUpload(ctx, profile.CollectorID, profile.ClusterID, report); err != nil || !ok {
				t.Fatalf("record fixture slot %d %s: admitted=%t err=%v", sec, query, ok, err)
			}
		}
	}
	f.exec(t, `CREATE FUNCTION fixture_reject_recovery() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
	IF NEW.transition='ASSESSMENT_RECOVER' THEN RAISE EXCEPTION 'fixture recovery rejected'; END IF; RETURN NEW; END $$;
	CREATE TRIGGER fixture_reject_recovery BEFORE INSERT ON gp09_alert_outbox FOR EACH ROW EXECUTE FUNCTION fixture_reject_recovery()`)
	// Model a source read that used the work allowance but left enough time
	// to commit its admitted facts. No logical instant has executed yet.
	gpu, stop := context.WithTimeout(ctx, a.ShadowGPUBudget)
	err = store.refreshAssetTx(gpu, asset, false, false, time.Now().Add(-time.Second))
	stop()
	if err != nil {
		t.Fatal(err)
	}
	state := func() ([]byte, bool, int) {
		t.Helper()
		var snapshot []byte
		var pending bool
		var rows int
		if err := f.admin.QueryRow(ctx, `SELECT snapshot,replay_pending, (SELECT count(*) FROM production_assessment_decisions)+(SELECT count(*) FROM production_notification_events)+(SELECT count(*) FROM incidents)+(SELECT count(*) FROM gp09_alert_outbox) FROM production_assessment_states WHERE enrollment_id=$1`, run).Scan(&snapshot, &pending, &rows); err != nil {
			t.Fatal(err)
		}
		return snapshot, pending, rows
	}
	checkpoint, pending, rows := state()
	if !pending || bytes.Equal(checkpoint, before) || rows != baselineRows {
		t.Fatalf("source acquisition failed to freeze input: pending=%t rows=%d", pending, rows)
	}
	if atCapacity {
		// Simulate another asset using the last admission slot after the source
		// read committed and before this asset resumes its accepted input.
		f.exec(t, `UPDATE production_assessment_enrollments SET retained_events=9968 WHERE enrollment_id=$1`, run)
		if !priorOpen {
			for slice := 0; slice < 12; slice++ {
				store = restart()
				if err := store.refreshAsset(ctx, asset, false); err != nil {
					t.Fatal(err)
				}
				checkpoint, pending, rows = state()
				if rows != 0 {
					t.Fatal("inactive asset opened a new occurrence using the active reserve")
				}
				if !pending {
					break
				}
			}
			var snap a.ProductionSnapshot
			if err := json.Unmarshal(checkpoint, &snap); err != nil {
				t.Fatal(err)
			}
			if pending || snap.Enrollment.Sequence != 0 || len(snap.Candidates) != 0 || len(snap.Facts) == 0 || snap.LastPass.Before(start.Add(525*time.Second)) {
				t.Fatalf("inactive capacity replay did not consume its evidence: pending=%t sequence=%d facts=%d last=%v", pending, snap.Enrollment.Sequence, len(snap.Facts), snap.LastPass)
			}
			return
		}
	}
	// Once input is frozen, exhausting a second slice before even one logical
	// step must be observable and may not count as a successful checkpoint.
	gpu, stop = context.WithTimeout(ctx, a.ShadowGPUBudget)
	err = store.refreshAssetTx(gpu, asset, false, false, time.Now().Add(-time.Second))
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("zero-progress continuation: %v", err)
	}
	if got, stillPending, gotRows := state(); !bytes.Equal(got, checkpoint) || !stillPending || gotRows != rows {
		t.Fatal("zero-progress retry changed the durable checkpoint")
	}
	down, err := os.ReadFile("../../../migrations/000091_production_assessment_replay.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	var refused *pgconn.PgError
	if _, err = f.admin.Exec(ctx, string(down)); !errors.As(err, &refused) || refused.Message != "unfinished production assessment replay batches" {
		t.Fatalf("downgrade with pending evidence: %v", err)
	}

	// Once admitted, even an unavailable source must not prevent finishing
	// the frozen sequence. All writes and locks here are fixture-local.
	// Simulate an upload correction arriving after the input view was frozen.
	// Its visibility belongs to the next acquisition, even across a restart.
	corrected := profile.Task(domain.QueryGPUTemperature, start.Add(510*time.Second))
	f.exec(t, `UPDATE observations SET value=value+1 WHERE run_id=$1`, string(corrected.RunID))
	store = restart()
	lockTx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(lockTx)
	if _, err := lockTx.Exec(ctx, `LOCK observations IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	var rejected *pgconn.PgError
	for attempt := 0; attempt < 12; attempt++ {
		err = store.refreshAsset(ctx, asset, false)
		if err != nil {
			break
		}
		checkpoint, pending, rows = state()
		if !pending {
			t.Fatal("drained without attempting recovery publication")
		}
	}
	if !errors.As(err, &rejected) || rejected.Message != "fixture recovery rejected" {
		t.Fatalf("expected recovery publication rejection, got %v", err)
	}
	got, pending, gotRows := state()
	if !bytes.Equal(checkpoint, got) || gotRows != rows || !pending {
		t.Fatalf("partial commit after failed slice: checkpoint changed=%t rows=%d/%d", !bytes.Equal(checkpoint, got), gotRows, rows)
	}
	f.exec(t, `DROP TRIGGER fixture_reject_recovery ON gp09_alert_outbox`)
	for attempt := 0; attempt < 2; attempt++ {
		store = restart()
		for slice := 0; ; slice++ {
			if err = store.refreshAsset(ctx, asset, false); err != nil {
				t.Fatal(err)
			}
			if _, pending, _ = state(); !pending {
				break
			}
			if slice >= 12 {
				t.Fatal("frozen evidence did not drain")
			}
		}
		if attempt == 0 {
			if atCapacity {
				// Active recovery already committed using the reserve; allow the
				// next acquisition to read the correction from the source.
				f.exec(t, `UPDATE production_assessment_enrollments SET retained_events=(SELECT count(*) FROM production_assessment_decisions WHERE enrollment_id=$1 AND closed_at IS NULL) WHERE enrollment_id=$1`, run)
			}
			if err = lockTx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		}
		var kinds, decisions, transitions []string
		var status string
		var recoverAt, processed time.Time
		err = f.admin.QueryRow(ctx, `SELECT array_agg(e.kind ORDER BY e.sequence),array_agg(d.kind ORDER BY e.sequence),array_agg(q.transition ORDER BY e.sequence),i.status,max(e.occurred_at) FILTER (WHERE e.kind='RECOVER'),
			(convert_from(s.snapshot,'UTF8')::jsonb->>'processed_at')::timestamptz
			FROM production_notification_events e JOIN production_notification_occurrences o USING (occurrence_id)
			JOIN gp09_alert_outbox q ON q.event_key=e.event_id JOIN incidents i USING (incident_id)
			JOIN production_assessment_decisions d ON d.event_id=e.event_id AND d.occurrence_id=o.occurrence_id AND d.closed_at=o.closed_at
			JOIN production_assessment_states s ON s.enrollment_id=o.enrollment_id AND s.asset=o.asset
			WHERE o.enrollment_id=$1 GROUP BY i.status,s.snapshot`, run).Scan(&kinds, &decisions, &transitions, &status, &recoverAt, &processed)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(kinds, []string{"OPEN", "RECOVER"}) || !slices.Equal(decisions, []string{"TERMINAL", "RECOVER"}) || !slices.Equal(transitions, []string{"ASSESSMENT_OPEN", "ASSESSMENT_RECOVER"}) || status != "RESOLVED" || !recoverAt.Before(start.Add(510*time.Second)) || processed.Before(start.Add(525*time.Second)) {
			t.Fatalf("retry %d: decisions %v, notifications %v / %v, incident %s, recovered %s, checkpoint %s", attempt, decisions, kinds, transitions, status, recoverAt, processed)
		}
	}
	raw, _, _ := state()
	var completed a.ProductionSnapshot
	if err = json.Unmarshal(raw, &completed); err != nil {
		t.Fatal(err)
	}
	var conflicts int
	for _, fact := range completed.Facts {
		if fact.Kind == "CONFLICT" {
			conflicts++
			if !fact.AvailableAt.Equal(completed.LastPass) {
				t.Fatalf("correction backdated into frozen evidence: %s vs %s", fact.AvailableAt, completed.LastPass)
			}
		}
	}
	if conflicts != 1 {
		t.Fatalf("expected one correction at first acquisition after draining, got %d", conflicts)
	}
	// Quiesced and drained checkpoints are readable by the previous schema.
	if _, err = f.admin.Exec(ctx, string(down)); err != nil {
		t.Fatal(err)
	}
	var legacyCompatible bool
	if err = f.admin.QueryRow(ctx, `SELECT NOT (convert_from(snapshot,'UTF8')::jsonb ? 'pending_replay') FROM production_assessment_states WHERE enrollment_id=$1`, run).Scan(&legacyCompatible); err != nil || !legacyCompatible {
		t.Fatalf("drained snapshot retained a new-format continuation: %v", err)
	}
}

// A server receipt can precede its commit. A subsequent edit can also make
// the original receipt older than the actual observation it now points at.
func TestProductionOrderedLateCommitAndCorrection(t *testing.T) {
	f, s, config, profile, hash, now := productionFleetFixture(t, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	asset := config.Assessment.Assets[0]
	slot := now.Truncate(domain.CoolingUploadInterval).Add(-domain.CoolingUploadInterval)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	f.exec(t, `UPDATE prometheus_cooling_upload_profiles SET registered_at=starts_at-interval '1 second' WHERE profile_id=$1 AND revision=$2`, profile.ProfileID, profile.Revision)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	ready, release := make(chan struct{}), make(chan struct{})
	poolConfig := f.admin.Config()
	poolConfig.ConnConfig.Tracer = orderedCommitBarrier{ready, release}
	writerPool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writerPool.Close)
	writer, err := NewCollectionStore(writerPool)
	if err != nil {
		t.Fatal(err)
	}
	upload := func(w *CollectionStore, query domain.QueryKind) error {
		report := assessmentUploadReport(profile, hash, query, slot)
		report.Version = profile.Version
		ok, err := w.RecordCoolingUpload(ctx, profile.CollectorID, profile.ClusterID, report)
		if err == nil && !ok {
			return fmt.Errorf("fixture upload %s declined", query)
		}
		return err
	}
	finished := make(chan error, 1)
	go func() { finished <- upload(writer, domain.QueryGPUTemperature) }()
	select {
	case <-ready:
	case err := <-finished:
		t.Fatalf("upload exited before commit: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	refresh := func() a.ProductionSnapshot {
		t.Helper()
		if err := s.refreshAsset(ctx, asset, false); err != nil {
			t.Fatal(err)
		}
		var raw []byte
		if err := f.admin.QueryRow(ctx, `SELECT snapshot FROM production_assessment_states WHERE enrollment_id=$1 AND asset=$2`, config.Assessment.RunID, asset.EntityKey).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var snap a.ProductionSnapshot
		if err := json.Unmarshal(raw, &snap); err != nil {
			t.Fatal(err)
		}
		return snap
	}
	first := refresh()
	for _, fact := range first.Facts {
		if fact.Kind == "SAMPLE" {
			t.Fatal("uncommitted observation entered checkpoint")
		}
	}
	close(release)
	if err = <-finished; err != nil {
		t.Fatal(err)
	}
	writer, err = NewCollectionStore(f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if err = upload(writer, domain.QueryGPUPower); err != nil {
		t.Fatal(err)
	}
	// Power arrived after the checkpoint, but a separate transaction changed
	// its value before the evaluator first saw it.
	f.exec(t, `UPDATE observations SET value=value+2 WHERE run_id=$1`, string(profile.Task(domain.QueryGPUPower, slot).RunID))
	second := refresh()
	got := map[string]float64{}
	for _, fact := range second.Facts {
		if fact.Kind != "SAMPLE" {
			continue
		}
		var sample a.Sample
		if err = json.Unmarshal(fact.Body, &sample); err != nil {
			t.Fatal(err)
		}
		if !fact.AvailableAt.Equal(second.LastPass) || !fact.AvailableAt.After(first.LastPass) {
			t.Fatalf("retroactive sample %s at %s; discovered %s", sample.Metric, fact.AvailableAt, second.LastPass)
		}
		got[sample.Metric] = sample.Value
	}
	if len(got) != 2 || got["DCGM_FI_DEV_GPU_TEMP"] != 75 || got["DCGM_FI_DEV_POWER_USAGE"] != 202 {
		t.Fatalf("missing corrected and late readings: %v", got)
	}
	f.exec(t, `UPDATE observations SET value=value+1 WHERE run_id=$1`, string(profile.Task(domain.QueryGPUTemperature, slot).RunID))
	third := refresh()
	conflicts := 0
	for _, fact := range third.Facts {
		if fact.Kind == "CONFLICT" {
			conflicts++
			if !fact.AvailableAt.Equal(third.LastPass) {
				t.Fatalf("retroactive correction conflict at %s; discovered %s", fact.AvailableAt, third.LastPass)
			}
		}
	}
	if conflicts != 1 {
		t.Fatalf("expected a single conflict after correcting retained evidence, got %d", conflicts)
	}
}

type orderedCommitBarrier struct{ ready, release chan struct{} }

func (b orderedCommitBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if q.SQL == "commit" {
		close(b.ready)
		select {
		case <-b.release:
		case <-ctx.Done():
		}
	}
	return ctx
}
func (orderedCommitBarrier) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// An unfinished asset re-enters the next ordinary lane even after its phase
// was claimed. Unattempted peers still lead; overdue candidates keep their
// independent deadline lane. A failed source read leaves the checkpoint intact.
func TestProductionOrderedReplayQueueFairness(t *testing.T) {
	f, s, c, _, _, _ := productionFleetFixture(t, 3)
	ctx := t.Context()
	first := c.Assessment.Assets[0]
	run := c.Assessment.RunID
	lock, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(lock)
	if _, err = lock.Exec(ctx, `LOCK observations IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	// Admission checks the receipt bindings before querying observations, so
	// lock the authority table as well when a fixture has no source receipts.
	if _, err = lock.Exec(ctx, `LOCK prometheus_cooling_upload_profiles IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 60*time.Millisecond)
	err = s.refreshAsset(short, first, false)
	cancel()
	if err == nil {
		t.Fatal("expected source acquisition deadline")
	}
	if err = lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var pristine bool
	if err = f.admin.QueryRow(ctx, `SELECT NOT replay_pending AND revision=1 AND octet_length(snapshot)=0 FROM production_assessment_states WHERE asset=$1`, first.EntityKey).Scan(&pristine); err != nil || !pristine {
		t.Fatalf("failed source acquisition changed checkpoint: %v", err)
	}
	// A previous successful source view aged out. Completing a new view
	// must explicitly expose the uncovered interval to operational status.
	var oldInput time.Time
	if err = f.admin.QueryRow(ctx, `UPDATE production_assessment_states SET last_input_at=clock_timestamp()-interval '16 minutes' WHERE asset=$1 RETURNING last_input_at`, first.EntityKey).Scan(&oldInput); err != nil {
		t.Fatal(err)
	}
	gpu, stop := context.WithTimeout(ctx, a.ShadowGPUBudget)
	err = s.refreshAssetTx(gpu, first, false, false, time.Now().Add(-time.Second))
	stop()
	if err != nil {
		t.Fatal(err)
	}
	status := func() ProductionAssessmentAssetStatus {
		t.Helper()
		result, err := ReadProductionAssessmentStatus(ctx, f.admin, c.Assessment.ClusterID, run)
		if err != nil {
			t.Fatal(err)
		}
		return result.Assets[0]
	}
	frozen := status()
	if !frozen.ReplayPending || frozen.LastInputAt == nil || frozen.InputGapFrom == nil || frozen.InputGapUntil == nil || !frozen.InputGapFrom.Equal(oldInput) || !frozen.InputGapUntil.Equal(frozen.LastInputAt.Add(-assessmentInputHistory)) {
		t.Fatalf("missing source coverage interval: %+v", frozen)
	}
	// Force the current phase to be already claimed independently of test
	// clock position, and set another asset's outstanding logical deadline.
	f.exec(t, `UPDATE production_assessment_states SET last_acquire_attempt_at=clock_timestamp()+interval '30 seconds' WHERE asset=$1`, first.EntityKey)
	f.exec(t, `UPDATE production_assessment_states SET next_due_at=clock_timestamp()-interval '1 second' WHERE asset=$1`, c.Assessment.Assets[1].EntityKey)
	due, acquire, err := s.refreshQueues(ctx)
	if err != nil || len(acquire) != 3 || acquire[2].asset != first || len(due) != 1 || due[0].asset != c.Assessment.Assets[1] {
		t.Fatalf("fair queue: due=%v acquire=%v err=%v", due, acquire, err)
	}
	if err := s.refreshAsset(ctx, first, false); err != nil {
		t.Fatal(err)
	}
	var pending bool
	if err = f.admin.QueryRow(ctx, `SELECT replay_pending FROM production_assessment_states WHERE enrollment_id=$1 AND asset=$2`, run, first.EntityKey).Scan(&pending); err != nil || pending {
		t.Fatalf("continuation failed to finish: pending=%t err=%v", pending, err)
	}
	completed := status()
	if completed.LastInputAt == nil || !completed.LastInputAt.Equal(*frozen.LastInputAt) {
		t.Fatal("replay advanced the source acquisition clock")
	}
	if err := s.refreshAsset(ctx, first, false); err != nil {
		t.Fatal(err)
	}
	later := status()
	if later.InputGapUntil == nil || !later.InputGapUntil.Equal(*frozen.InputGapUntil) || later.LastInputAt == nil || !later.LastInputAt.After(*completed.LastInputAt) {
		t.Fatal("healthy acquisition lost the historical coverage interval")
	}

}

func TestProductionOrderedReplayInitialCoverageAndMigrationLocks(t *testing.T) {
	f, s, c, _, _, now := productionFleetFixture(t, 2)
	ctx := t.Context()
	run := c.Assessment.RunID
	old, fresh := c.Assessment.Assets[0], c.Assessment.Assets[1]
	start := now.Add(-20 * time.Minute)
	f.exec(t, `UPDATE production_assessment_enrollments SET created_at=$2 WHERE enrollment_id=$1`, run, start)
	// An older evaluator left a recent snapshot; this proves an evaluation,
	// but cannot establish when the source history was last read.
	engine, err := a.NewProductionAssetEngine(ctx, c, start, s.registry, old.EntityKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Advance(ctx, now, now, now, nil, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := engine.SnapshotProduction(old.EntityKey, now)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE production_assessment_states SET snapshot=$2,last_attempt_at=clock_timestamp() WHERE asset=$1`, old.EntityKey, raw)
	// Both directions must back out promptly if a live reader holds the table.
	// Retrying the same bytes after the reader commits must succeed.
	for _, direction := range []string{"down", "up"} {
		body, err := os.ReadFile("../../../migrations/000091_production_assessment_replay." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		read, err := f.admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackMonitoringTx(read)
		if _, err = read.Exec(ctx, `LOCK TABLE production_assessment_states IN ACCESS SHARE MODE`); err != nil {
			t.Fatal(err)
		}
		limited, cancel := context.WithTimeout(ctx, 4*time.Second)
		_, err = f.admin.Exec(limited, string(body))
		cancel()
		var lockErr *pgconn.PgError
		if !errors.As(err, &lockErr) || lockErr.Code != "55P03" {
			t.Fatalf("%s migration lock: %v", direction, err)
		}
		if err = read.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		f.exec(t, string(body))
	}
	for _, asset := range []a.Asset{old, fresh} {
		var unknown bool
		if err := f.admin.QueryRow(ctx, `SELECT last_input_at IS NULL AND last_input_gap IS NULL FROM production_assessment_states WHERE asset=$1`, asset.EntityKey).Scan(&unknown); err != nil || !unknown {
			t.Fatalf("invented source history during migration: %v", err)
		}
		if err := s.refreshAsset(ctx, asset, false); err != nil {
			t.Fatal(err)
		}
		var gapIsExact bool
		err := f.admin.QueryRow(ctx, `SELECT last_input_gap=tstzrange($2,last_input_at-interval '900 seconds','[)') FROM production_assessment_states WHERE asset=$1`, asset.EntityKey, start).Scan(&gapIsExact)
		if err != nil || !gapIsExact {
			t.Fatalf("first acquisition failed to expose unknown coverage from enrollment: %v", err)
		}
	}
}

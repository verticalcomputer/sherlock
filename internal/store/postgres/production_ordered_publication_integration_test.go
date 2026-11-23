//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	runOrderedRecoveryAtomicRestart(t, true)
}

func runOrderedRecoveryAtomicRestart(t *testing.T, priorOpen bool) {
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
	var rejected *pgconn.PgError
	if err = store.refreshAsset(ctx, asset, false); !errors.As(err, &rejected) || rejected.Message != "fixture recovery rejected" {
		t.Fatalf("expected recovery publication rejection, got %v", err)
	}
	var checkpoint []byte
	var rows int
	if err = f.admin.QueryRow(ctx, `SELECT snapshot, (SELECT count(*) FROM production_assessment_decisions)+(SELECT count(*) FROM production_notification_events)+(SELECT count(*) FROM incidents)+(SELECT count(*) FROM gp09_alert_outbox) FROM production_assessment_states WHERE enrollment_id=$1`, run).Scan(&checkpoint, &rows); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, checkpoint) || rows != baselineRows {
		t.Fatalf("partial commit after publication failure: checkpoint changed=%t rows=%d", !bytes.Equal(before, checkpoint), rows)
	}
	f.exec(t, `DROP TRIGGER fixture_reject_recovery ON gp09_alert_outbox`)
	for attempt := 0; attempt < 2; attempt++ {
		store = restart()
		if err = store.refreshAsset(ctx, asset, false); err != nil {
			t.Fatal(err)
		}
		var kinds, transitions []string
		var status string
		var recoverAt, processed time.Time
		err = f.admin.QueryRow(ctx, `SELECT array_agg(e.kind ORDER BY e.sequence),array_agg(q.transition ORDER BY e.sequence),i.status,max(e.occurred_at) FILTER (WHERE e.kind='RECOVER'),
			(convert_from(s.snapshot,'UTF8')::jsonb->>'processed_at')::timestamptz
			FROM production_notification_events e JOIN production_notification_occurrences o USING (occurrence_id)
			JOIN gp09_alert_outbox q ON q.event_key=e.event_id JOIN incidents i USING (incident_id)
			JOIN production_assessment_states s ON s.enrollment_id=o.enrollment_id AND s.asset=o.asset
			WHERE o.enrollment_id=$1 GROUP BY i.status,s.snapshot`, run).Scan(&kinds, &transitions, &status, &recoverAt, &processed)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(kinds, []string{"OPEN", "RECOVER"}) || !slices.Equal(transitions, []string{"ASSESSMENT_OPEN", "ASSESSMENT_RECOVER"}) || status != "RESOLVED" || !recoverAt.Before(start.Add(510*time.Second)) || processed.Before(start.Add(525*time.Second)) {
			t.Fatalf("retry %d: %v / %v, incident %s, recovered %s, checkpoint %s", attempt, kinds, transitions, status, recoverAt, processed)
		}
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

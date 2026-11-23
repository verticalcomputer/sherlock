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
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestProductionOrderedRecoveryAtomicRestart(t *testing.T) {
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
	before, err := engine.SnapshotProduction(asset.EntityKey, start)
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
	for sec := 15; sec <= 525; sec += 15 {
		slot := start.Add(time.Duration(sec) * time.Second)
		for _, query := range domain.CoolingUploadQueries() {
			report := fleetHistoryReport(profile, hash, query, slot)
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
	if !bytes.Equal(before, checkpoint) || rows != 0 {
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
	writer, err := NewCollectionStore(fleetHistoryTracePool(t, f.admin, fleetHistoryTrace{before: func(ctx context.Context, query pgx.TraceQueryStartData) {
		if query.SQL == "commit" {
			close(ready)
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
	}}))
	if err != nil {
		t.Fatal(err)
	}
	upload := func(w *CollectionStore, query domain.QueryKind) error {
		ok, err := w.RecordCoolingUpload(ctx, profile.CollectorID, profile.ClusterID, fleetHistoryReport(profile, hash, query, slot))
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

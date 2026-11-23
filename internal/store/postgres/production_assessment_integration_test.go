//go:build integration

package postgres

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
)

func productionStoreFixture(t *testing.T, evidenceOrigin ...string) (*assessmentFixture, *ProductionAssessmentStore, a.ProductionConfig, time.Time) {
	t.Helper()
	f := newAssessmentFixture(t)
	var now time.Time
	if err := f.admin.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	writer, profile, _ := seedAssessmentUploadProfile(t, f, now.UTC())
	profile.Version = 3
	profile.State = "ENABLED"
	profile.EndsAt = time.Time{}
	profile.Revision++
	raw, _ := json.Marshal(profile)
	hash := domain.ChecksumSHA256(raw).String()
	if err := writer.RegisterCoolingUploadProfile(t.Context(), profile, hash); err != nil {
		t.Fatal(err)
	}
	for i := range f.config.Bindings {
		f.config.Bindings[i].ScheduleRevision = profile.Revision
		f.config.Bindings[i].UploadProfileHash = hash
	}
	f.config.Assets = f.config.Assets[:1]
	f.config.Implementation = 2
	f.config.RunDurationSeconds = 0
	f.config.BudgetsMS = []int64{120000}
	r, err := a.NewRegistry(cooling.Category{}, cooling.ProductionCategory{})
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://sherlock.example"
	if len(evidenceOrigin) > 0 {
		origin = evidenceOrigin[0]
	}
	c, err := a.NormalizeProductionConfig(t.Context(), a.ProductionConfig{Schema: 1, Revision: 1, NotificationsEnabled: true, EvidenceBaseURL: origin, Assessment: f.config}, r)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewProductionAssessmentStore(t.Context(), f.admin, r, c)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	return f, store, c, now.UTC().Truncate(time.Microsecond)
}

func TestProductionAssessmentWithoutEvidenceOrigin(t *testing.T) {
	f, s, c, now := productionStoreFixture(t, "")
	id, _ := seedProductionDue(t, f, s, c, now)
	if err := s.refreshAsset(t.Context(), c.Assessment.Assets[0], true); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(t.Context()); err != nil {
		t.Fatal("restart with empty origin", err)
	}
	var origin, link, message string
	if err := f.admin.QueryRow(t.Context(), `SELECT e.evidence_base_url,o.evidence_url,q.message FROM production_assessment_enrollments e JOIN production_notification_occurrences o ON o.enrollment_id=e.enrollment_id JOIN gp09_alert_outbox q ON q.assessment_occurrence=o.occurrence_id WHERE e.enrollment_id=$1`, c.Assessment.RunID).Scan(&origin, &link, &message); err != nil {
		t.Fatal(err)
	}
	if origin != "" || link != "" || strings.Contains(message, "History:") || strings.Contains(message, "/admin/") || !strings.Contains(message, id) || !strings.Contains(message, c.Assessment.Assets[0].EntityKey) {
		t.Fatalf("unexpected no-origin publication: origin=%q link=%q message=%q", origin, link, message)
	}
	changed := c
	changed.Revision++
	changed.EvidenceBaseURL = "https://sherlock.example"
	other, err := NewProductionAssessmentStore(t.Context(), f.admin, s.registry, changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Start(t.Context()); err == nil {
		t.Fatal("existing enrollment silently changed its evidence origin")
	}
}
func productionStoreSamples(t *testing.T, c a.ProductionConfig, at time.Time) []a.Fact {
	t.Helper()
	facts := []a.Fact{}
	for _, b := range c.Assessment.Bindings {
		v, unit := 80.0, "celsius"
		if b.Metric == cooling.Power {
			v, unit = 200, "watts"
		}
		id := fmt.Sprintf("production-sample-%s-%d", b.Metric, at.Unix())
		p := a.Provenance{Mode: "upload", CollectionRunID: domain.CoolingUploadRunPrefix + domain.ChecksumSHA256([]byte(id)).String(), Operation: b.Operation, ScheduleRevision: b.ScheduleRevision, InventoryRevision: c.Assessment.InventoryRevision, SourceRecord: id, CollectorID: b.UploadCollectorID, UploadProfileID: b.UploadProfileID, UploadProfileHash: b.UploadProfileHash}
		f, err := a.NewFact(c.Assessment.Category, c.Assessment.RunID, c.Assessment.Assets[0].EntityKey, "SAMPLE", at, a.Sample{Metric: b.Metric, Unit: unit, SourceAt: at, CollectedAt: at, CompletedAt: at, Value: v, SourceRecord: id, Provenance: p})
		if err != nil {
			t.Fatal(err)
		}
		facts = append(facts, f)
	}
	return facts
}
func seedProductionDue(t *testing.T, f *assessmentFixture, s *ProductionAssessmentStore, c a.ProductionConfig, now time.Time) (string, time.Time) {
	t.Helper()
	start := now.Add(-5 * time.Minute)
	e, err := a.NewProductionEngine(t.Context(), c, start, s.registry)
	if err != nil {
		t.Fatal(err)
	}
	asset := c.Assessment.Assets[0].EntityKey
	for sec := 0; sec <= 30; sec += 15 {
		at := start.Add(time.Duration(sec) * time.Second)
		if err = e.Advance(t.Context(), at, at, at, productionStoreSamples(t, c, at), nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.Candidates) != 1 || e.Candidates[0].Phase != "OBSERVING" {
		t.Fatalf("candidate setup %+v %+v", e.Candidates, e.Failures)
	}
	raw, err := e.SnapshotProduction(asset, start.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE production_assessment_enrollments SET created_at=$2,notifications_enabled_at=$2 WHERE enrollment_id=$1`, c.Assessment.RunID, start)
	f.exec(t, `UPDATE production_assessment_states SET snapshot=$3,next_due_at=$4 WHERE enrollment_id=$1 AND asset=$2`, c.Assessment.RunID, asset, raw, e.Candidates[0].DueAt)
	return e.Candidates[0].ID, e.Candidates[0].DueAt
}
func TestProductionDuePersistsRetainedDeadlineAfterInputFailure(t *testing.T) {
	for _, mode := range []string{"capacity", "aborted transaction"} {
		t.Run(mode, func(t *testing.T) {
			f, s, c, now := productionStoreFixture(t)
			occurrence, deadline := seedProductionDue(t, f, s, c, now)
			asset := c.Assessment.Assets[0]
			if mode == "capacity" {
				// The qualified-input reader must reject the entire batch
				// on its 33rd active transition, even when all rows are valid.
				tx, err := f.admin.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackMonitoringTx(tx)
				for n := 0; n < 33; n++ {
					id := fmt.Sprintf("fixture-qualified-%d", n)
					_, err = tx.Exec(t.Context(), `INSERT INTO gp09_monitor_enrollments(policy_id,cluster_id,source_id,entity_key,rule_id,rule_version,operation,scope_key,policy,evaluator_state)
 VALUES($1,$2,$3,$4,'gpu_thermal',1,'temperature',$5,'{}','{}')`, id, c.Assessment.ClusterID, c.Assessment.SourceID, asset.EntityKey, fmt.Sprintf("%064d", n))
					if err != nil {
						t.Fatal(err)
					}
					policy := monitoring.Policy{ID: id, ClusterID: domain.ClusterID(c.Assessment.ClusterID), SourceID: domain.SourceID(c.Assessment.SourceID), EntityKey: asset.EntityKey, Rule: monitoring.RuleGPUThermal, RuleVersion: 1, Revision: 1}
					err = publishMonitoringTransition(t.Context(), tx, policy, monitoring.Transition{Kind: monitoring.TransitionOpen, Occurrence: 1, At: now, Severity: domain.HealthSeverityWarning, Reason: monitoring.ReasonThermalThreshold}, nil)
					if err != nil {
						t.Fatal(err)
					}
				}
				if err = tx.Commit(t.Context()); err != nil {
					t.Fatal(err)
				}
			} else {
				tx, err := f.admin.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackMonitoringTx(tx)
				_, err = tx.Exec(t.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "prometheus-cooling-profile-family:"+c.Assessment.Bindings[0].UploadProfileID)
				if err != nil {
					t.Fatal(err)
				}
			}
			err := errors.Join(s.refreshLane(t.Context(), []productionRefreshEntry{{asset: asset}}, true, time.Now().Add(a.ShadowRefreshBudget))...)
			if mode == "capacity" && !errors.Is(err, ErrAssessmentCapacity) {
				t.Fatalf("capacity failure lost: %v", err)
			}
			var pg *pgconn.PgError
			if mode == "aborted transaction" && (!errors.As(err, &pg) || pg.Code != "55P03") {
				t.Fatalf("profile lock failure lost: %v", err)
			}
			if err = s.refreshAsset(t.Context(), asset, true); err != nil {
				t.Fatalf("duplicate due attempt: %v", err)
			}
			var count, failures int
			var settled bool
			err = f.admin.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM production_assessment_decisions WHERE occurrence_id=$2 AND kind='TERMINAL' AND logical_at=$3),
 failure_count, next_due_at IS NULL AND last_acquire_attempt_at IS NULL FROM production_assessment_states WHERE asset=$1`, asset.EntityKey, occurrence, deadline).Scan(&count, &failures, &settled)
			if err != nil || count != 1 || failures != 1 || !settled {
				t.Fatalf("terminals=%d failed reads=%d settled=%t err=%v", count, failures, settled, err)
			}
		})
	}
}

func TestProductionAssessmentAtomicDeadlineAndRestart(t *testing.T) {
	f, s, c, now := productionStoreFixture(t)
	id, due := seedProductionDue(t, f, s, c, now)
	f.exec(t, `CREATE FUNCTION production_test_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture publication rejected'; END $$;CREATE TRIGGER production_test_reject BEFORE INSERT ON gp09_alert_outbox FOR EACH ROW EXECUTE FUNCTION production_test_reject()`)
	if err := s.refreshAsset(t.Context(), c.Assessment.Assets[0], true); err == nil {
		t.Fatal("expected atomic publication failure")
	}
	var count int
	if err := f.admin.QueryRow(t.Context(), `SELECT count(*) FROM production_assessment_decisions`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial decision committed %d %v", count, err)
	}
	f.exec(t, `DROP TRIGGER production_test_reject ON gp09_alert_outbox;DROP FUNCTION production_test_reject()`)
	if err := s.refreshAsset(t.Context(), c.Assessment.Assets[0], true); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.refreshAsset(t.Context(), c.Assessment.Assets[0], true); err != nil {
		t.Fatal(err)
	}
	var eventAt time.Time
	var occurrence string
	if err := f.admin.QueryRow(t.Context(), `SELECT count(*),min(occurrence_id),min(logical_at) FROM production_assessment_decisions`).Scan(&count, &occurrence, &eventAt); err != nil {
		t.Fatal(err)
	}
	if count != 1 || occurrence != id || !eventAt.Equal(due) {
		t.Fatalf("deadline/id changed count%d occurrence%s at%s due%s", count, occurrence, eventAt, due)
	}
	if err := f.admin.QueryRow(t.Context(), `SELECT count(*) FROM gp09_alert_outbox WHERE assessment_enrollment=$1`, c.Assessment.RunID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("outbox count %d %v", count, err)
	}
	rev, err := SetProductionAssessmentNotifications(t.Context(), f.admin, c.Assessment.ClusterID, c.Assessment.RunID, 1, false, "operator")
	if err != nil || rev != 2 {
		t.Fatalf("disable %d %v", rev, err)
	}
	if err = s.Start(t.Context()); err == nil {
		t.Fatal("stale config re-enabled notification authority")
	}
	var status string
	if err = f.admin.QueryRow(t.Context(), `SELECT status FROM gp09_alert_outbox WHERE assessment_enrollment=$1`, c.Assessment.RunID).Scan(&status); err != nil || status != "DISABLED" {
		t.Fatalf("unclaimed notice notfenced %s %v", status, err)
	}
}
func TestProductionAssessmentMigrationGuard(t *testing.T) {
	f, _, _, _ := productionStoreFixture(t)
	down, err := os.ReadFile("../../../migrations/000085_production_assessment.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.admin.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err = tx.Exec(t.Context(), string(down)); err == nil {
		t.Fatal("downgrade deleted retained production state")
	}
}
func TestProductionAssessmentRestrictedRole(t *testing.T) {
	f, original, cfg, _ := productionStoreFixture(t)
	if err := CheckProductionAssessmentRole(t.Context(), f.admin); err == nil {
		t.Fatal("superuser accepted")
	}
	script, err := os.ReadFile("../../../scripts/production-assessment-grants.sql")
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, string(script))
	var db string
	if err = f.admin.QueryRow(t.Context(), `SELECT current_database()`).Scan(&db); err != nil {
		t.Fatal(err)
	}
	role := fmt.Sprintf("production_fixture_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{role}.Sanitize()
	f.exec(t, "CREATE ROLE "+quoted+" LOGIN PASSWORD 'fixture-local-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION")
	t.Cleanup(func() {
		_, _ = f.admin.Exec(t.Context(), "DROP OWNED BY "+quoted)
		_, _ = f.admin.Exec(t.Context(), "DROP ROLE "+quoted)
	})
	f.exec(t, "GRANT sherlock_assessment_production TO "+quoted)
	f.exec(t, "REVOKE CREATE,TEMPORARY ON DATABASE "+pgx.Identifier{db}.Sanitize()+" FROM PUBLIC")
	pc, err := pgxpool.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig.User = role
	pc.ConnConfig.Password = "fixture-local-only"
	pool, err := pgxpool.NewWithConfig(t.Context(), pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = CheckProductionAssessmentRole(t.Context(), pool); err != nil {
		t.Fatal("restricted role rejected", err)
	}
	f.exec(t, "REVOKE SELECT ON public.prometheus_cooling_receipt_observations FROM sherlock_assessment_production")
	if err = CheckProductionAssessmentRole(t.Context(), pool); err == nil {
		t.Fatal("production evaluator accepted without receipt lookup access")
	}
	f.exec(t, "GRANT SELECT ON public.prometheus_cooling_receipt_observations TO sherlock_assessment_production")
	var profileBody []byte
	var profileHash string
	binding := cfg.Assessment.Bindings[0]
	if err = f.admin.QueryRow(t.Context(), `SELECT profile,profile_hash FROM prometheus_cooling_upload_profiles WHERE profile_id=$1 AND revision=$2`, binding.UploadProfileID, binding.ScheduleRevision).Scan(&profileBody, &profileHash); err != nil {
		t.Fatal(err)
	}
	var profile domain.CoolingUploadProfile
	if err = json.Unmarshal(profileBody, &profile); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	f.exec(t, `UPDATE prometheus_cooling_upload_profiles SET registered_at=starts_at-interval '1 second' WHERE profile_id=$1 AND revision=$2`, profile.ProfileID, profile.Revision)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	var now time.Time
	if err = f.admin.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	writer, _ := NewCollectionStore(f.admin)
	for _, query := range domain.CoolingUploadQueries() {
		report := assessmentUploadReport(profile, profileHash, query, now.Truncate(domain.CoolingUploadInterval))
		report.Version = 3
		if _, err = writer.RecordCoolingUpload(t.Context(), profile.CollectorID, profile.ClusterID, report); err != nil {
			t.Fatal(err)
		}
	}
	runtime, err := NewProductionAssessmentStore(t.Context(), pool, original.registry, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.Start(t.Context()); err != nil {
		t.Fatal("restricted start", err)
	}
	if err = runtime.Refresh(t.Context()); err != nil {
		t.Fatal("restricted refresh", err)
	}
	var retained []byte
	if err = f.admin.QueryRow(t.Context(), `SELECT snapshot FROM production_assessment_states WHERE enrollment_id=$1 AND asset=$2`, cfg.Assessment.RunID, cfg.Assessment.Assets[0].EntityKey).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	var snap a.ProductionSnapshot
	if err = json.Unmarshal(retained, &snap); err != nil {
		t.Fatal(err)
	}
	samples := 0
	for _, fact := range snap.Facts {
		if fact.Kind == "SAMPLE" {
			samples++
		}
	}
	if samples != 2 {
		t.Fatalf("restricted source path retained %d samples", samples)
	}

	if _, err = runtime.Cleanup(t.Context()); err != nil {
		t.Fatal("restricted cleanup", err)
	}

	f.exec(t, "GRANT UPDATE(active) ON collection_jobs TO "+quoted)
	if err = CheckProductionAssessmentRole(t.Context(), pool); err == nil {
		t.Fatal("column workload write accepted")
	}
	f.exec(t, "REVOKE UPDATE(active) ON collection_jobs FROM "+quoted)
	// Role membership must not provide a SET ROLE route around the guard.
	f.exec(t, "GRANT pg_write_all_data TO "+quoted)
	if err = CheckProductionAssessmentRole(t.Context(), pool); err == nil {
		t.Fatal("reachable system role accepted")
	}
	f.exec(t, "REVOKE pg_write_all_data FROM "+quoted)
}

func TestProductionAssessmentEmptyMigrationRoundTrip(t *testing.T) {
	f := newAssessmentFixtureThrough(t, "000084_continuous_cooling_upload.up.sql")
	for _, name := range []string{"000085_production_assessment.up.sql", "000085_production_assessment.down.sql", "000085_production_assessment.up.sql"} {
		body, err := os.ReadFile("../../../migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		f.exec(t, string(body))
	}
}

func TestProductionAssessmentRejectsWrongBaselineHash(t *testing.T) {
	f, s, c, _ := productionStoreFixture(t)
	c.Assessment.RunID += "-wrong-hash"
	for i := range c.Assessment.Bindings {
		c.Assessment.Bindings[i].UploadProfileHash = fmt.Sprintf("%064d", 0)
	}
	store, err := NewProductionAssessmentStore(t.Context(), f.admin, s.registry, c)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Start(t.Context()); err == nil {
		t.Fatal("incorrect initial profile hash admitted")
	}
}

// Harden the existing shadow login before upgrading. Rehardening all functions
// after applying migrations would hide a newly exposed PUBLIC execution grant.
func TestProductionAssessmentUpgradePreservesShadowPreflight(t *testing.T) {
	f := newAssessmentFixtureThrough(t, "000084_continuous_cooling_upload.up.sql")
	restricted := f.restrictedPool(t)
	shadow := &AssessmentStore{pool: restricted}
	if err := shadow.Preflight(t.Context()); err != nil {
		t.Fatal("pre-upgrade qualified shadow role", err)
	}
	for _, name := range []string{"000085_production_assessment.up.sql", "000086_production_notifications.up.sql"} {
		body, err := os.ReadFile("../../../migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		f.exec(t, string(body))
		if err = shadow.Preflight(t.Context()); err != nil {
			t.Fatalf("shadow preflight after %s: %v", name, err)
		}
	}
}

// Incremental arrivals exercise the same complete 15-minute working window and
// 30-minute retained entry under the race detector. The separate performance
// gate presents all 120 authenticated receipts together in one refresh.
func TestProductionAssessmentAgedIncrementalLifecycle(t *testing.T) {
	f, s, c, now := productionStoreFixture(t)
	entry := now.Add(-30 * time.Minute)
	e, err := a.NewProductionEngine(t.Context(), c, entry, s.registry)
	if err != nil {
		t.Fatal(err)
	}
	asset := c.Assessment.Assets[0].EntityKey
	advance := func(at time.Time) {
		t.Helper()
		if err := e.Advance(t.Context(), at, at, at, productionStoreSamples(t, c, at), nil); err != nil {
			t.Fatal(err)
		}
		if len(e.Failures) > 0 {
			t.Fatalf("incremental failure: %+v", e.Failures)
		}
	}
	for sec := 0; sec <= 150; sec += 15 {
		advance(entry.Add(time.Duration(sec) * time.Second))
	}
	if len(e.Candidates) != 1 || e.Candidates[0].Phase != "FINAL" {
		t.Fatal("missing old active occurrence")
	}
	id, deadline := e.Candidates[0].ID, e.Candidates[0].DueAt
	for slot := now.Add(-15*time.Minute + 15*time.Second); !slot.After(now); slot = slot.Add(15 * time.Second) {
		advance(slot)
	}
	snapshot, err := e.SnapshotProductionContext(t.Context(), asset, now)
	if err != nil {
		t.Fatal(err)
	}
	var retained a.ProductionSnapshot
	if err = json.Unmarshal(snapshot, &retained); err != nil {
		t.Fatal(err)
	}
	recent := 0
	for _, fact := range retained.Facts {
		if fact.Kind == "SAMPLE" && !fact.AvailableAt.Before(now.Add(-15*time.Minute)) {
			recent++
		}
	}
	if recent != 120 || len(retained.Candidates) != 1 || retained.Candidates[0].ID != id || !retained.Candidates[0].DueAt.Equal(deadline) {
		t.Fatalf("lost aged proof or full window: %d samples", recent)
	}
	f.exec(t, `UPDATE production_assessment_enrollments SET created_at=$2,notifications_enabled=false WHERE enrollment_id=$1`, c.Assessment.RunID, entry)
	f.exec(t, `UPDATE production_assessment_states SET snapshot=$3 WHERE enrollment_id=$1 AND asset=$2`, c.Assessment.RunID, asset, snapshot)
	if err = s.Refresh(t.Context()); err != nil {
		t.Fatal("aged persisted refresh", err)
	}
	var code string
	if err = f.admin.QueryRow(t.Context(), `SELECT last_failure_code FROM production_assessment_states WHERE enrollment_id=$1 AND asset=$2`, c.Assessment.RunID, asset).Scan(&code); err != nil {
		t.Fatal(err)
	}
	if code == "TIME_BUDGET" {
		t.Fatal("aged incremental budget exhausted")
	}
}

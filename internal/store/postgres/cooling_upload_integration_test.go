//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adminview"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestCoolingUploadTransactionalAuthority(t *testing.T) {
	pool := durableTestDatabase(t)
	ctx := t.Context()
	admin, _ := storepg.NewCollectionStore(pool)
	const cluster, source, collector = "cooling-cluster", "cooling-source", "cooling-collector"
	if err := admin.EnsureSource(ctx, cluster, cluster, source, source); err != nil {
		t.Fatal(err)
	}
	if err := admin.EnsureSource(ctx, "other-cluster", "other", "other-source", "other"); err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO collectors (collector_id,cluster_id,display_name,status,version,build_commit,protocol_min,protocol_max,operating_system,architecture)
 VALUES ($1,$2,$1,'ACTIVE','fixture','fixture',1,2,'test','test'),
 ('second-collector',$2,'second','ACTIVE','fixture','fixture',1,2,'test','test'),
 ('other-collector','other-cluster','other','ACTIVE','fixture','fixture',1,2,'test','test')`, collector, cluster)
	store := coolingUploadRestrictedStore(t, pool)
	var now time.Time
	if err := pool.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		t.Fatal(err)
	}
	inventory, _ := storepg.NewGoodputStore(pool)
	old := now.Add(-time.Hour)
	revision := domain.InventoryRevision{SchemaVersion: 1, ID: "cooling-revision", ClusterID: cluster, SourceID: source,
		SourceAt: old, EffectiveAt: old, ObservedAt: old, Entities: []domain.EntityIdentity{
			{ClusterID: cluster, Kind: domain.EntityNode, NodeID: "node-a"},
			{ClusterID: cluster, Kind: domain.EntityNode, NodeID: "node-b"},
			{ClusterID: cluster, Kind: domain.EntityGPU, NodeID: "node-a", PhysicalGPUUUID: "GPU-a"},
			{ClusterID: cluster, Kind: domain.EntityGPU, NodeID: "node-a", PhysicalGPUUUID: "GPU-b"},
			{ClusterID: cluster, Kind: domain.EntityGPU, NodeID: "node-b", PhysicalGPUUUID: "GPU-c"},
		}}
	if _, err := inventory.RecordExpectedInventoryRevision(ctx, revision); err != nil {
		t.Fatal(err)
	}
	slot := now.UTC().Add(2 * time.Second).Truncate(domain.CoolingUploadInterval).Add(domain.CoolingUploadInterval)
	profile := domain.CoolingUploadProfile{Version: domain.CoolingUploadVersion, ProfileID: "cooling-profile", Revision: 1,
		CollectorID: collector, ClusterID: cluster, SourceID: source, InventoryRevision: string(revision.ID),
		StartsAt: slot.Add(-time.Minute), EndsAt: slot.Add(time.Minute),
		Assets: []domain.CoolingUploadAsset{{NodeID: "node-a", GPUUUID: "GPU-a"}, {NodeID: "node-a", GPUUUID: "GPU-b"}}}
	hash := domain.ChecksumSHA256([]byte("exact configured profile file")).String()
	register := func(p domain.CoolingUploadProfile, h string) {
		t.Helper()
		if err := store.RegisterCoolingUploadProfile(ctx, p, h); err != nil {
			t.Fatal(err)
		}
	}
	register(profile, hash)
	register(profile, hash)
	var registeredAt time.Time
	if err := pool.QueryRow(ctx, `SELECT registered_at FROM prometheus_cooling_upload_profiles WHERE profile_id=$1`, profile.ProfileID).
		Scan(&registeredAt); err != nil || registeredAt.Before(now) || !registeredAt.Before(slot) {
		t.Fatalf("registered_at=%v DB time=%v first accepted slot=%v err=%v", registeredAt, now, slot, err)
	}
	second := profile
	second.ProfileID, second.CollectorID = "second-profile", "second-collector"
	register(second, hash)
	assertRegistrationDenied := func(p domain.CoolingUploadProfile, h string) {
		t.Helper()
		if err := store.RegisterCoolingUploadProfile(ctx, p, h); err == nil {
			t.Fatal("ineligible registration succeeded")
		}
	}
	assertRegistrationDenied(profile, domain.ChecksumSHA256([]byte("changed bytes")).String())
	changed := profile
	changed.Assets = slices.Clone(profile.Assets[:1])
	assertRegistrationDenied(changed, hash)
	changed = profile
	changed.Revision++
	assertRegistrationDenied(changed, hash)
	changed.ProfileID, changed.SourceID = "foreign-source", "other-source"
	assertRegistrationDenied(changed, hash)
	changed.ProfileID, changed.SourceID, changed.CollectorID = "foreign-collector", source, "other-collector"
	assertRegistrationDenied(changed, hash)
	changed = second
	changed.ProfileID = "missing-asset"
	changed.Assets = []domain.CoolingUploadAsset{{NodeID: "node-a", GPUUUID: "GPU-c"}}
	assertRegistrationDenied(changed, hash)
	changed = profile
	changed.ProfileID, changed.EndsAt = "expired-profile", profile.StartsAt.Add(domain.CoolingUploadInterval)
	assertRegistrationDenied(changed, hash)
	if _, err := pool.Exec(ctx, `UPDATE prometheus_cooling_upload_profiles SET registered_at=starts_at WHERE profile_id=$1`, profile.ProfileID); err == nil {
		t.Fatal("profile registration time was mutable")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM prometheus_cooling_upload_profiles WHERE profile_id=$1`, profile.ProfileID); err == nil {
		t.Fatal("registered profile could be deleted and reused")
	}

	reportAt := func(p domain.CoolingUploadProfile, query domain.QueryKind, at time.Time) domain.CoolingUploadReport {
		return coolingUploadTestReport(p, hash, query, at)
	}
	assertReportDenied := func(id domain.CollectorID, cluster domain.ClusterID, r domain.CoolingUploadReport) {
		t.Helper()
		if ok, err := store.RecordCoolingUpload(ctx, id, cluster, r); ok || !errors.Is(err, collectorcontrol.ErrCoolingUploadRejected) {
			t.Fatalf("wanted authority rejection, accepted=%t err=%v", ok, err)
		}
	}
	assertReportDenied(collector, cluster, reportAt(profile, domain.QueryGPUTemperature, profile.StartsAt))
	assertReportDenied(collector, cluster, reportAt(profile, domain.QueryGPUTemperature, slot.Add(24*time.Hour)))
	stale := profile
	stale.ProfileID, stale.StartsAt = "old-slot-profile", slot.Add(-20*time.Minute)
	seedHistoricalCoolingUploadProfile(t, pool, stale, hash)
	assertReportDenied(collector, cluster, reportAt(stale, domain.QueryGPUTemperature, stale.StartsAt))
	expired := stale
	expired.ProfileID, expired.EndsAt = "historical-profile", slot.Add(-17*time.Minute)
	seedHistoricalCoolingUploadProfile(t, pool, expired, hash)
	register(expired, hash)
	assertReportDenied(collector, cluster, reportAt(expired, domain.QueryGPUTemperature, expired.StartsAt))
	waitForCoolingUploadSlot(t, pool, slot)
	report := reportAt(profile, domain.QueryGPUTemperature, slot)
	assertReportDenied("other-collector", cluster, report)
	assertReportDenied(collector, "other-cluster", report)
	wrong := report
	wrong.ProfileRevision++
	assertReportDenied(collector, cluster, wrong)
	wrong = report
	wrong.ProfileHash = domain.ChecksumSHA256([]byte("spoofed hash")).String()
	assertReportDenied(collector, cluster, wrong)
	wrong = report
	wrong.Result.Task.SourceID = "other-source"
	assertReportDenied(collector, cluster, wrong)
	wrong = reportAt(profile, domain.QueryGPUTemperature, slot)
	wrong.Result.Observations[1].Labels = wrong.Result.Observations[0].Labels
	wrong.Result.Observations[1].EntityKey = wrong.Result.Observations[0].EntityKey
	assertReportDenied(collector, cluster, wrong)
	wrong = reportAt(profile, domain.QueryGPUTemperature, slot)
	wrong.Result.Observations[0].ObservedAt = slot.Add(-domain.CoolingUploadInterval)
	assertReportDenied(collector, cluster, wrong)
	wrong = reportAt(profile, domain.QueryGPUTemperature, slot)
	wrong.Result.Observations[0].Labels[1].Value = "GPU-c"
	assertReportDenied(collector, cluster, wrong)

	// Force a failure at the final receipt insert. No run or sample can survive.
	exec(`ALTER TABLE prometheus_cooling_upload_receipts ADD CONSTRAINT fixture_reject_report CHECK (false)`)
	_, err := store.RecordCoolingUpload(ctx, collector, cluster, report)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.ConstraintName != "fixture_reject_report" {
		t.Fatalf("expected late receipt failure, got %v", err)
	}
	assertCoolingUploadRows(t, pool, 0, 0, 0)
	exec(`ALTER TABLE prometheus_cooling_upload_receipts DROP CONSTRAINT fixture_reject_report`)
	public, _ := storepg.NewPublicQueryStore(pool)
	dashboard, _ := adminview.NewPostgresStore(pool)
	healthAt := slot.Add(time.Second)
	healthBefore, found, err := public.GetHealth(ctx, cluster, healthAt, time.Minute)
	if err != nil || !found || healthBefore.CollectionStatus != domain.ResultNoData {
		t.Fatalf("baseline cluster health found=%t status=%s err=%v", found, healthBefore.CollectionStatus, err)
	}
	metricsBefore, err := dashboard.LoadGPUMetricsWithHealth(ctx, cluster, healthAt, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	assertHealthUnchanged := func() {
		t.Helper()
		health, found, err := public.GetHealth(ctx, cluster, healthAt, time.Minute)
		if err != nil || !found || !reflect.DeepEqual(health, healthBefore) {
			t.Fatalf("cluster health changed due to a cohort-only upload: found=%t health=%+v err=%v", found, health, err)
		}
		metrics, err := dashboard.LoadGPUMetricsWithHealth(ctx, cluster, healthAt, time.Minute)
		if err != nil || !reflect.DeepEqual(metrics, metricsBefore) {
			t.Fatalf("GPU metrics changed due to a cohort-only upload: err=%v", err)
		}
	}
	record := func(r domain.CoolingUploadReport, want bool) {
		t.Helper()
		if ok, err := store.RecordCoolingUpload(ctx, collector, cluster, r); ok != want || err != nil {
			t.Fatalf("accepted=%t want=%t err=%v", ok, want, err)
		}
	}
	// An evaluator may hold a shared family and revision lock until its
	// evidence snapshot commits. Receipt admission can overlap that read,
	// while an authority change must still wait for it.
	reader, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback(ctx)
	for _, key := range []string{"prometheus-cooling-profile-family:" + profile.ProfileID, fmt.Sprintf("prometheus-cooling-profile:%s:%d", profile.ProfileID, profile.Revision)} {
		if _, err := reader.Exec(ctx, "SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))", key); err != nil {
			t.Fatal(err)
		}
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	accepted, err := store.RecordCoolingUpload(bounded, collector, cluster, report)
	cancel()
	if err != nil || !accepted {
		t.Fatalf("receipt under evaluator lock: accepted=%t err=%v", accepted, err)
	}
	// Even an idempotent registration traverses the change-authority lock.
	changeCtx, cancelChange := context.WithTimeout(ctx, 100*time.Millisecond)
	changeErr := store.RegisterCoolingUploadProfile(changeCtx, profile, hash)
	cancelChange()
	if !errors.Is(changeErr, context.DeadlineExceeded) {
		t.Fatalf("registration did not wait for the evaluator: %v", changeErr)
	}
	if err = reader.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	assertHealthUnchanged()
	record(report, true)
	modified := reportAt(profile, domain.QueryGPUTemperature, slot)
	modified.Result.Observations[0].Value++
	record(modified, false)
	partial := reportAt(profile, domain.QueryGPUPower, slot)
	partial.Result.Status = domain.ResultPartial
	partial.Result.Observations = partial.Result.Observations[:1]
	partial.Result.Coverage = domain.Coverage{SeriesReturned: 1}
	partial.Result.Failures = []domain.CollectionFailure{{Code: domain.FailurePartialData, Message: "one cell missing"}}
	record(partial, true)
	failed := reportAt(second, domain.QueryGPUTemperature, slot)
	failed.Result.Status = domain.ResultFailed
	failed.Result.CompletedAt = slot.Add(time.Millisecond)
	failed.Result.Observations = nil
	failed.Result.Coverage = domain.Coverage{}
	failed.Result.Failures = []domain.CollectionFailure{{Code: domain.FailureSourceUnavailable, Message: "local source unavailable"}}
	if ok, err := store.RecordCoolingUpload(ctx, second.CollectorID, cluster, failed); err != nil || !ok {
		t.Fatalf("failed V2 attempt accepted=%t err=%v", ok, err)
	}
	assertHealthUnchanged()
	assertCoolingUploadRows(t, pool, 3, 3, 3)
	op, _ := domain.CollectionOperationForQuery(domain.QueryGPUTemperature)
	seed := domain.DesiredSchedule{ScheduleKey: domain.ScheduleKey{ClusterID: cluster, SourceID: source, Operation: op.ID},
		Enabled: true, Mode: domain.SchedulingLegacy, Interval: 30 * time.Second, Timeout: time.Second, MaxTargets: 10, MaxBytes: 10000}
	if yes, err := admin.EnrollDiscoveredDCGM(ctx, report.Result.Task.RunID, seed, healthAt); err != nil || yes {
		t.Fatalf("cohort-only metrics run enrolled a production schedule: enrolled=%t err=%v", yes, err)
	}

	wire, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var receivedAt, rawAt time.Time
	var payloadHash, reference string
	var coverageComplete bool
	var count int
	err = pool.QueryRow(ctx, `SELECT q.received_at,q.payload_hash,o.observed_at,o.source_reference,r.coverage_complete,r.series_expected
 FROM prometheus_cooling_upload_receipts q JOIN collection_runs r USING(run_id) JOIN observations o USING(run_id)
 WHERE q.run_id=$1 AND o.entity_key=$2 AND q.collector_id=$3 AND q.profile_hash=$4 AND r.job_id IS NULL`,
		report.Result.Task.RunID, report.Result.Observations[0].EntityKey, collector, hash).
		Scan(&receivedAt, &payloadHash, &rawAt, &reference, &coverageComplete, &count)
	if err != nil || !rawAt.Equal(report.Result.Observations[0].ObservedAt) ||
		reference != domain.DCGMSourceReference(domain.QueryGPUTemperature) || payloadHash != domain.ChecksumSHA256(wire).String() ||
		receivedAt.Before(slot) || !coverageComplete || count != len(profile.Assets) {
		t.Fatalf("receipt/sample mismatch at=%v source=%v ref=%q hash=%s complete=%t expected=%d err=%v", receivedAt, rawAt, reference, payloadHash, coverageComplete, count, err)
	}
	var states []string
	err = pool.QueryRow(ctx, `SELECT coverage_complete,series_expected,ARRAY(SELECT value->>'state' FROM jsonb_array_elements(metric_fields))
 FROM collection_runs WHERE run_id=$1`, partial.Result.Task.RunID).Scan(&coverageComplete, &count, &states)
	if err != nil || coverageComplete || count != len(profile.Assets) || !slices.Equal(states, []string{"SUPPORTED", "UNKNOWN"}) {
		t.Fatalf("partial coverage complete=%t expected=%d states=%v err=%v", coverageComplete, count, states, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE prometheus_cooling_upload_receipts SET received_at=received_at+interval '1 second'`); err == nil {
		t.Fatal("receipt time was mutable")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM prometheus_cooling_upload_receipts WHERE run_id=$1`, report.Result.Task.RunID); err == nil {
		t.Fatal("receipt could be deleted while its run remains")
	}

	exec(`UPDATE prometheus_cooling_upload_profiles SET revoked_at=clock_timestamp() WHERE profile_id=$1`, profile.ProfileID)
	if _, err := pool.Exec(ctx, `UPDATE prometheus_cooling_upload_profiles SET revoked_at=NULL WHERE profile_id=$1`, profile.ProfileID); err == nil {
		t.Fatal("profile revocation was reversed")
	}
	err = downCoolingUploadMigration(t, pool)
	pgErr = nil
	if !errors.As(err, &pgErr) || pgErr.Code != "55000" {
		t.Fatalf("down migration did not refuse retained provenance: %v", err)
	}
	var revokedProfile bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.prometheus_cooling_upload_profiles
 WHERE profile_id=$1 AND profile_hash=$2 AND revoked_at IS NOT NULL)`, profile.ProfileID, hash).Scan(&revokedProfile); err != nil || !revokedProfile {
		t.Fatalf("revoked profile did not survive down migration: found=%t err=%v", revokedProfile, err)
	}
	assertCoolingUploadRows(t, pool, 3, 3, 3)
	assertReportDenied(collector, cluster, report)
	secondReport := reportAt(second, domain.QueryGPUTemperature, slot)
	exec(`UPDATE collectors SET status='REVOKED',revoked_at=clock_timestamp() WHERE collector_id=$1`, second.CollectorID)
	assertReportDenied(second.CollectorID, cluster, secondReport)
	exec(`UPDATE collectors SET status='ACTIVE',revoked_at=NULL WHERE collector_id=$1`, second.CollectorID)
	revision.ID, revision.SourceAt, revision.EffectiveAt, revision.ObservedAt = "next-cooling-inventory", slot, slot, slot
	if _, err := inventory.RecordExpectedInventoryRevision(ctx, revision); err != nil {
		t.Fatal(err)
	}
	assertReportDenied(second.CollectorID, cluster, secondReport)
	assertCoolingUploadRows(t, pool, 3, 3, 3)
	aged := slot.Add(-40 * 24 * time.Hour)
	exec(`UPDATE observations SET observed_at=$2,collected_at=$2 WHERE run_id=$1`, report.Result.Task.RunID, aged)
	exec(`UPDATE collection_runs SET completed_at=$2 WHERE run_id=$1`, report.Result.Task.RunID, aged)
	retained, err := admin.ApplyRetention(ctx, healthAt, 7*24*time.Hour, 30*24*time.Hour)
	if err != nil || retained.ObservationsDeleted != 2 || retained.RunsDeleted != 1 || retained.EventsDeleted != 0 {
		t.Fatalf("cooling upload retention result=%+v err=%v", retained, err)
	}
	assertCoolingUploadRows(t, pool, 2, 1, 2)
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.prometheus_cooling_upload_profiles
 WHERE profile_id=$1 AND profile_hash=$2 AND revoked_at IS NOT NULL)`, profile.ProfileID, hash).Scan(&revokedProfile); err != nil || !revokedProfile {
		t.Fatalf("retention removed the expired run's profile: found=%t err=%v", revokedProfile, err)
	}

	// An enabled production schedule still has no attempt of its own. The
	// failed V2 temperature run is visible only in detailed run history.
	exec(`INSERT INTO collection_jobs (job_id,cluster_id,source_id,query_kind,interval_seconds,next_run_at)
 VALUES ('fleet-job',$1,$2,$3,30,$4)`, cluster, source, domain.QueryGPUTemperature, healthAt)
	exec(`INSERT INTO desired_schedules (cluster_id,source_id,operation,enabled,mode,interval_seconds,
 timeout_ms,jitter_ms,max_targets,max_bytes,priority,legacy_query_kind,legacy_job_id)
 VALUES ($1,$2,$3,true,'legacy',30,1000,0,10,10000,10,$4,'fleet-job')`, cluster, source, op.ID, domain.QueryGPUTemperature)
	health, found, err := public.GetHealth(ctx, cluster, healthAt, time.Minute)
	if err != nil || !found || health.Shared == nil || health.Shared.Monitoring.ExpectedOperations != 1 ||
		health.Shared.Monitoring.FreshOperations != 0 || health.Shared.Monitoring.LateOperations != 1 || health.Shared.Monitoring.FailedOperations != 0 {
		t.Fatalf("V2 attempt entered production schedule health: found=%t shared=%+v err=%v", found, health.Shared, err)
	}
}

func TestCoolingUploadDownMigrationEmpty(t *testing.T) {
	pool := durableTestDatabase(t)
	if err := downCoolingUploadMigration(t, pool); err != nil {
		t.Fatal(err)
	}
	var removed bool
	err := pool.QueryRow(t.Context(), `SELECT
 to_regclass('public.prometheus_cooling_upload_profiles') IS NULL AND
 to_regclass('public.prometheus_cooling_upload_receipts') IS NULL`).Scan(&removed)
	if err != nil || !removed {
		t.Fatalf("empty cooling upload tables survived down migration: removed=%t err=%v", removed, err)
	}
}

func downCoolingUploadMigration(t *testing.T, pool *pgxpool.Pool) error {
	t.Helper()
	body, err := os.ReadFile("../../../migrations/000083_cooling_upload.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, string(body)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func coolingUploadRestrictedStore(t *testing.T, pool *pgxpool.Pool) *storepg.CollectionStore {
	t.Helper()
	ctx := t.Context()
	role := pgx.Identifier{fmt.Sprintf("cooling_upload_fixture_%d", time.Now().UnixNano())}.Sanitize()
	if _, err := pool.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DROP OWNED BY "+role+"; DROP ROLE "+role); err != nil {
			t.Error(err)
		}
	})
	base := `GRANT USAGE ON SCHEMA public TO <role>;
 GRANT SELECT ON public.sources,public.collectors,public.goodput_inventory_revisions,public.goodput_inventory_revision_entities TO <role>;
 GRANT SELECT,INSERT ON public.collection_runs TO <role>;
 GRANT INSERT ON public.observations,public.collection_failures TO <role>;
 GRANT USAGE ON SEQUENCE public.collection_failures_failure_id_seq TO <role>;`
	grants, err := os.ReadFile("../../../scripts/cooling-upload-grants.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, strings.ReplaceAll(base, "<role>", role)+strings.ReplaceAll(string(grants), `:"upload_role"`, role)); err != nil {
		t.Fatal(err)
	}
	config := pool.Config().Copy()
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE "+role)
		return err
	}
	restricted, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restricted.Close)
	var canForgeProof bool
	err = restricted.QueryRow(ctx, `SELECT
		has_any_column_privilege('public.prometheus_cooling_receipt_observations', 'INSERT,UPDATE') OR
		has_table_privilege('public.prometheus_cooling_receipt_observations', 'DELETE,TRUNCATE,TRIGGER') OR
		has_column_privilege('public.prometheus_cooling_upload_receipts','observation_lookup_complete','INSERT,UPDATE') OR
		has_function_privilege('public.cooling_observation_locator()','EXECUTE') OR
		has_function_privilege('public.cooling_receipt_observation_proof()','EXECUTE')`).Scan(&canForgeProof)
	if err != nil || canForgeProof {
		t.Fatalf("restricted upload role can directly author lookup proof=%t: %v", canForgeProof, err)
	}
	store, err := storepg.NewCollectionStore(restricted)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func coolingUploadTestReport(profile domain.CoolingUploadProfile, hash string, query domain.QueryKind, slot time.Time) domain.CoolingUploadReport {
	field, _ := domain.CoolingUploadField(query)
	result := domain.CollectionResult{Task: profile.Task(query, slot), Status: domain.ResultSucceeded,
		StartedAt: slot, CompletedAt: slot, Coverage: domain.Coverage{Complete: true, SeriesReturned: len(profile.Assets)}}
	for i, asset := range profile.Assets {
		entity := domain.EntityIdentity{ClusterID: profile.ClusterID, Kind: domain.EntityGPU, NodeID: asset.NodeID, PhysicalGPUUUID: asset.GPUUUID}
		result.Observations = append(result.Observations, domain.Observation{ID: domain.ObservationID(fmt.Sprintf("sample-%d", i)),
			SchemaVersion: 1, ClusterID: profile.ClusterID, SourceID: profile.SourceID, Kind: strings.TrimPrefix(string(query), "dcgm_"),
			EntityKey: entity.Key(), Metric: field.Name, Unit: field.Unit, Value: 65 + float64(i),
			Labels:     []domain.Label{{Name: "Hostname", Value: string(asset.NodeID)}, {Name: "UUID", Value: string(asset.GPUUUID)}},
			ObservedAt: slot.Add(-5 * time.Second), CollectedAt: slot, SourceReference: domain.DCGMSourceReference(query)})
	}
	return domain.CoolingUploadReport{Version: domain.CoolingUploadVersion, ProfileID: profile.ProfileID,
		ProfileRevision: profile.Revision, ProfileHash: hash, Result: result}
}

func seedHistoricalCoolingUploadProfile(t *testing.T, pool *pgxpool.Pool, profile domain.CoolingUploadProfile, hash string) {
	t.Helper()
	ctx := t.Context()
	body, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Seed a profile that was registered long ago in the disposable database.
	// The trigger stays active for the application calls under test.
	if _, err := tx.Exec(ctx, `ALTER TABLE prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO prometheus_cooling_upload_profiles
 (profile_id,revision,profile_hash,cluster_id,source_id,collector_id,inventory_revision,profile,starts_at,ends_at,registered_at)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, profile.ProfileID, profile.Revision, hash, profile.ClusterID,
		profile.SourceID, profile.CollectorID, profile.InventoryRevision, body, profile.StartsAt, profile.EndsAt,
		profile.StartsAt.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func waitForCoolingUploadSlot(t *testing.T, pool *pgxpool.Pool, slot time.Time) {
	t.Helper()
	var seconds float64
	if err := pool.QueryRow(t.Context(), `SELECT greatest(extract(epoch FROM $1::timestamptz-clock_timestamp()),0)::float8`, slot).
		Scan(&seconds); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(time.Duration(seconds*float64(time.Second)) + 100*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
}

func assertCoolingUploadRows(t *testing.T, pool *pgxpool.Pool, wantRuns, wantSamples, wantReceipts int) {
	t.Helper()
	var runs, observations, receipts, projections, envelopes, events, completions, jobs, work, caches int
	var touched, proven, locators int
	err := pool.QueryRow(t.Context(), `SELECT
 (SELECT count(*) FROM collection_runs), (SELECT count(*) FROM observations),
 (SELECT count(*) FROM prometheus_cooling_upload_receipts), (SELECT count(*) FROM current_projections),
 (SELECT count(*) FROM evidence_envelopes), (SELECT count(*) FROM cluster_events),
 (SELECT count(*) FROM collection_events), (SELECT count(*) FROM collection_jobs), (SELECT count(*) FROM collector_work_items),
 (SELECT count(*) FROM collection_target_inventory), (SELECT count(*) FROM sources WHERE availability<>'UNKNOWN' OR last_attempt_at IS NOT NULL),
 (SELECT count(*) FROM prometheus_cooling_upload_receipts WHERE observation_lookup_complete),
 (SELECT count(*) FROM prometheus_cooling_receipt_observations)`).
		Scan(&runs, &observations, &receipts, &projections, &envelopes, &events, &completions, &jobs, &work, &caches, &touched, &proven, &locators)
	if err != nil || proven != wantReceipts || locators != wantSamples {
		t.Fatalf("proven receipts=%d want=%d locators=%d want=%d err=%v", proven, wantReceipts, locators, wantSamples, err)
	}
	if runs != wantRuns || observations != wantSamples || receipts != wantReceipts ||
		projections+envelopes+events+completions+jobs+work+caches+touched != 0 {
		t.Fatalf("runs=%d samples=%d receipts=%d projections=%d envelopes=%d events=%d completions=%d jobs=%d work=%d caches=%d touched=%d err=%v",
			runs, observations, receipts, projections, envelopes, events, completions, jobs, work, caches, touched, err)
	}
}

//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	investigationapi "github.com/verticalcomputer/sherlock/internal/adapters/investigationapi"
	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
	publicapi "github.com/verticalcomputer/sherlock/internal/api"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type monitoringFixture struct {
	pool       *pgxpool.Pool
	collection *storepg.CollectionStore
	monitor    *storepg.MonitoringStore
	now        time.Time
	sequence   int
}

func newMonitoringFixture(t *testing.T) *monitoringFixture {
	t.Helper()
	pool := durableTestDatabase(t)
	collection, _ := storepg.NewCollectionStore(pool)
	if err := collection.EnsureSource(context.Background(), "monitor-cluster", "Monitor", "monitor-source", "Monitor"); err != nil {
		t.Fatal(err)
	}
	f := &monitoringFixture{pool: pool, collection: collection, monitor: storepg.NewMonitoringStore(pool)}
	f.clock(t)
	goodput, _ := storepg.NewGoodputStore(pool)
	old := f.now.Add(-24 * time.Hour)
	if _, err := goodput.RecordExpectedInventoryRevision(context.Background(), domain.InventoryRevision{SchemaVersion: 1, ID: "monitor-expected", ClusterID: "monitor-cluster", SourceID: "monitor-source", SourceAt: old, EffectiveAt: old, ObservedAt: old, Entities: []domain.EntityIdentity{{ClusterID: "monitor-cluster", Kind: domain.EntityGPU, NodeID: "node-a", PhysicalGPUUUID: "GPU-a"}}}); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *monitoringFixture) clock(t *testing.T) time.Time {
	t.Helper()
	if err := f.pool.QueryRow(context.Background(), `SELECT clock_timestamp()`).Scan(&f.now); err != nil {
		t.Fatal(err)
	}
	return f.now
}
func (f *monitoringFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), query, args...); err != nil {
		t.Fatal(err)
	}
}
func (f *monitoringFixture) schedule(t *testing.T, q domain.QueryKind) monitoring.Binding {
	t.Helper()
	op, _ := domain.CollectionOperationForQuery(q)
	id := f.record(t, q, domain.ResultSucceeded, map[string]float64{domain.DCGMFields(q)[0].Name: 50}, f.clock(t).Add(-time.Second), false)
	seed := domain.DesiredSchedule{ScheduleKey: domain.ScheduleKey{ClusterID: "monitor-cluster", SourceID: "monitor-source", Operation: op.ID}, Enabled: true, Mode: domain.SchedulingLegacy, Interval: 30 * time.Second, Timeout: time.Second, MaxTargets: 1000, MaxBytes: 100000}
	if _, err := f.collection.EnrollDiscoveredDCGM(context.Background(), domain.RunID(id), seed, f.now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return monitoring.Binding{Operation: op.ID, ScheduleRevision: 1, Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{}}, InventoryRevisionID: "monitor-expected"}
}
func (f *monitoringFixture) policy(t *testing.T, id string, rule monitoring.RuleID, metric string, binding monitoring.Binding) monitoring.Policy {
	t.Helper()
	unit := "celsius"
	entity := "monitor-cluster/GPU/node-a/GPU-a/"
	threshold, recover := 80.0, 70.0
	severity := domain.HealthSeverityWarning
	if rule == monitoring.RuleTelemetryLoss {
		unit = ""
		entity = "source/monitor-source"
		threshold = 0
		recover = 0
	} else if rule == monitoring.RuleECCHistorical {
		unit = "count"
		threshold = 1
		recover = 0
		def, _ := domain.GPUHealthSensor(metric)
		severity = def.PositiveSeverity
	}
	return monitoring.Policy{ID: id, ClusterID: "monitor-cluster", SourceID: "monitor-source", EntityKey: entity, Rule: rule, RuleVersion: 1, Metric: metric, Unit: unit, Binding: binding, StartupGraceSeconds: 0, FreshForSeconds: 120, ConfirmCount: 1, ConfirmWindowSeconds: 120, RecoverCount: 2, RecoverWindowSeconds: 120, MaxSampleGapSeconds: 120, OpenThreshold: threshold, RecoverBelow: recover, Severity: severity}
}
func (f *monitoringFixture) record(t *testing.T, q domain.QueryKind, status domain.ResultStatus, values map[string]float64, at time.Time, bound bool) string {
	t.Helper()
	f.sequence++
	id := fmt.Sprintf("monitor-run-%06d", f.sequence)
	result := domain.CollectionResult{Task: domain.CollectionTask{RunID: domain.RunID(id), ClusterID: "monitor-cluster", SourceID: "monitor-source", Query: q, ScheduledFor: at, IdempotencyKey: id, MaxSeries: 1000, MaxBytes: 100000}, Status: status, StartedAt: at, CompletedAt: at, Coverage: domain.Coverage{Complete: status == domain.ResultSucceeded}}
	for metric, value := range values {
		field := domain.DCGMField{}
		for _, candidate := range domain.DCGMFields(q) {
			if candidate.Name == metric {
				field = candidate
			}
		}
		result.Observations = append(result.Observations, domain.Observation{ID: domain.ObservationID(id + "-" + metric), SchemaVersion: 1, ClusterID: "monitor-cluster", SourceID: "monitor-source", Kind: string(q), EntityKey: "monitor-cluster/GPU/node-a/GPU-a/", Metric: metric, Value: value, Unit: field.Unit, Labels: []domain.Label{{Name: "Hostname", Value: "node-a"}, {Name: "UUID", Value: "GPU-a"}}, ObservedAt: at, CollectedAt: at, SourceReference: domain.DCGMSourceReference(q)})
	}
	result.Coverage.SeriesReturned = len(result.Observations)
	if bound {
		var job string
		var config int64
		if err := f.pool.QueryRow(context.Background(), `SELECT job_id,configuration_revision FROM collection_jobs WHERE cluster_id='monitor-cluster' AND source_id='monitor-source' AND query_kind=$1`, q).Scan(&job, &config); err != nil {
			t.Fatal(err)
		}
		f.exec(t, `INSERT INTO collection_run_jobs(run_id,job_id,cluster_id,source_id,query_kind,node_filter,scheduled_for,configuration_revision,lease_generation) VALUES($1,$2,'monitor-cluster','monitor-source',$3,'',$4,$5,1)`, id, job, q, at, config)

	}
	if yes, err := f.collection.RecordResult(context.Background(), result); err != nil || !yes {
		t.Fatalf("record result %v %v", yes, err)
	}
	return id
}
func (f *monitoringFixture) refresh(t *testing.T) {
	t.Helper()
	f.exec(t, `UPDATE gp09_monitor_enrollments SET next_due_at=clock_timestamp() WHERE enabled`)
	if err := f.monitor.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func (f *monitoringFixture) status(t *testing.T, id string) storepg.MonitoringStatus {
	t.Helper()
	out, err := f.monitor.Status(context.Background(), "monitor-cluster", id)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMonitoringEnrollmentSilenceReplayOperatorsAndDelivery(t *testing.T) {
	f := newMonitoringFixture(t)
	binding := f.schedule(t, domain.QueryGPUTemperature)
	policy := f.policy(t, "silence", monitoring.RuleTelemetryLoss, "", binding)
	enrolled, err := f.monitor.Enroll(context.Background(), policy, 0, "local-operator")
	if err != nil || enrolled.State.PolicyID != policy.ID {
		t.Fatalf("enroll %+v %v", enrolled, err)
	}
	f.refresh(t)
	status := f.status(t, "silence")
	if !status.Enrollment.State.Open || len(status.Episodes) != 1 {
		t.Fatalf("silence without samples %+v", status)
	}
	episode := status.Episodes[0]
	f.refresh(t)
	if got := f.status(t, "silence"); len(got.Episodes) != 1 || got.Episodes[0].Version != 1 {
		t.Fatal("replay duplicated episode")
	}
	episode, err = f.monitor.Acknowledge(context.Background(), "monitor-cluster", "silence", 1, 1, "local-operator")
	if err != nil || episode.ClosedAt != nil {
		t.Fatalf("ack %+v %v", episode, err)
	}
	if _, err = f.monitor.AssignOwner(context.Background(), "monitor-cluster", "silence", 1, 1, "local-operator", "owner"); !errors.Is(err, storepg.ErrMonitoringRevision) {
		t.Fatalf("stale episode revision %v", err)
	}
	episode, err = f.monitor.AssignOwner(context.Background(), "monitor-cluster", "silence", 1, 2, "local-operator", "owner")
	if err != nil {
		t.Fatal(err)
	}
	episode, err = f.monitor.SetMaintenance(context.Background(), "monitor-cluster", "silence", 1, 3, "local-operator", 60)
	if err != nil {
		t.Fatal(err)
	}
	outbox, _ := storepg.NewAlertOutboxStore(f.pool)
	if _, found, err := outbox.Claim(context.Background()); err != nil || found {
		t.Fatalf("maintenance pending claim %v %v", found, err)
	}
	if _, err = f.monitor.SetMaintenance(context.Background(), "monitor-cluster", "silence", 1, 4, "local-operator", 0); err != nil {
		t.Fatal(err)
	}
	claim, found, err := outbox.Claim(context.Background())
	if err != nil || !found {
		t.Fatalf("claim monitor alert %v %v", found, err)
	}
	if _, err = outbox.Finish(context.Background(), claim, alertdelivery.Result{Outcome: alertdelivery.RetryableFailure, Code: "RECEIVER_RETRYABLE", HTTPStatus: 503}); err != nil {
		t.Fatal(err)
	}
	var pending, attempts int
	f.pool.QueryRow(context.Background(), `SELECT count(*) FROM gp09_alert_outbox WHERE status='PENDING' AND last_code='RECEIVER_RETRYABLE'`).Scan(&pending)
	f.pool.QueryRow(context.Background(), `SELECT count(*) FROM gp09_alert_delivery_attempts`).Scan(&attempts)
	if pending != 1 || attempts != 1 {
		t.Fatal("receiver failure invisible")
	}
	if _, err = f.monitor.Disable(context.Background(), "monitor-cluster", "silence", 1, "local-operator"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.monitor.Enroll(context.Background(), policy, 0, "local-operator"); !errors.Is(err, storepg.ErrMonitoringRevision) {
		t.Fatalf("disabled retry reenabled %v", err)
	}
	if !f.status(t, "silence").Enrollment.State.Open {
		t.Fatal("disable resolved fault")
	}
	if _, err = f.monitor.Enroll(context.Background(), policy, 2, "local-operator"); err != nil {
		t.Fatal(err)
	}
}

func TestMonitoringThermalAtomicRecoveryGenericAPIAndRetention(t *testing.T) {
	f := newMonitoringFixture(t)
	binding := f.schedule(t, domain.QueryGPUTemperature)
	policy := f.policy(t, "thermal", monitoring.RuleGPUThermal, "DCGM_FI_DEV_GPU_TEMP", binding)
	if _, err := f.monitor.Enroll(context.Background(), policy, 0, "local-operator"); err != nil {
		t.Fatal(err)
	}
	at := f.clock(t).Add(-time.Millisecond)
	run := f.record(t, domain.QueryGPUTemperature, domain.ResultSucceeded, map[string]float64{policy.Metric: 90}, at, true)
	f.refresh(t)
	status := f.status(t, "thermal")
	if !status.Enrollment.State.Open || len(status.Episodes) != 1 {
		t.Fatalf("thermal open %+v", status)
	}
	investigationStore, _ := storepg.NewInvestigationStore(f.pool)
	controller, _ := investigationapi.NewFailClosedController(investigationStore, platform.SystemClock{}, platform.RandomIDGenerator{})
	service, _ := investigationapi.NewService(f.pool, controller, platform.SystemClock{})
	incident, found, err := service.GetIncident(context.Background(), status.Episodes[0].IncidentID)
	if err != nil || !found || len(incident.EvidenceIDs) != 1 || len(incident.TargetIDs) != 1 || len(incident.InvestigationIDs) != 0 {
		t.Fatalf("generic incident %+v %v %v", incident, found, err)
	}
	items, _, err := service.ListIncidents(context.Background(), "monitor-cluster", publicapi.IncidentListOptions{PageSize: 10})
	if err != nil || len(items) != 1 {
		t.Fatalf("list incidents %d %v", len(items), err)
	}
	// A rolled-back write after incident creation may not leave a partial episode,
	// event or intent. Existing open state survives failed recovery publication.
	f.exec(t, `CREATE FUNCTION monitor_fail_recover() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.transition='MONITOR_RECOVER' THEN RAISE EXCEPTION 'synthetic publication failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER monitor_fail_recover BEFORE INSERT ON gp09_alert_outbox FOR EACH ROW EXECUTE FUNCTION monitor_fail_recover()`)
	f.record(t, domain.QueryGPUTemperature, domain.ResultSucceeded, map[string]float64{policy.Metric: 60}, f.clock(t).Add(-time.Millisecond), true)
	f.record(t, domain.QueryGPUTemperature, domain.ResultSucceeded, map[string]float64{policy.Metric: 60}, f.clock(t).Add(-time.Millisecond), true)
	f.exec(t, `UPDATE gp09_monitor_enrollments SET next_due_at=clock_timestamp()`)
	if err = f.monitor.Refresh(context.Background()); err == nil {
		t.Fatal("expected atomic publication failure")
	}
	status = f.status(t, "thermal")
	if !status.Enrollment.State.Open || status.Episodes[0].ClosedAt != nil || len(status.Episodes[0].Evidence) != 1 || status.Enrollment.LastFailureCode != "EVALUATION_FAILED" {
		t.Fatalf("partial recovery %+v", status)
	}
	f.exec(t, `DROP TRIGGER monitor_fail_recover ON gp09_alert_outbox; DROP FUNCTION monitor_fail_recover()`)
	f.refresh(t)
	status = f.status(t, "thermal")
	if status.Enrollment.State.Open || status.Episodes[0].ClosedAt == nil || len(status.Episodes[0].Evidence) != 2 {
		t.Fatalf("recovery %+v", status)
	}
	incident, _, err = service.GetIncident(context.Background(), status.Episodes[0].IncidentID)
	if err != nil || incident.Status != "RESOLVED" || len(incident.EvidenceIDs) != 2 {
		t.Fatalf("generic recovery %+v %v", incident, err)
	}
	// Snapshots have logical IDs, not destructive raw retention pins. Remove only
	// the superseded raw projection pin and run normal reference-safe retention.
	f.exec(t, `DELETE FROM current_projections WHERE observation_id IN(SELECT observation_id FROM observations WHERE run_id=$1)`, run)
	f.exec(t, `UPDATE observations SET collected_at=clock_timestamp()-interval '60 days' WHERE run_id=$1`, run)
	f.exec(t, `UPDATE collection_runs SET completed_at=clock_timestamp()-interval '60 days' WHERE run_id=$1`, run)
	if _, err = f.collection.ApplyRetention(context.Background(), f.clock(t), 7*24*time.Hour, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	status = f.status(t, "thermal")
	if len(status.Episodes[0].Evidence[0].Snapshot) != 1 || status.Episodes[0].Evidence[0].RawEvidenceAvailable {
		t.Fatalf("retention destroyed snapshot or lied about raw availability %+v", status)
	}
}

func TestMonitoringECCIndependentFieldsReviewedDispositionAndDisable(t *testing.T) {
	f := newMonitoringFixture(t)
	binding := f.schedule(t, domain.QueryGPUECC)
	a := f.policy(t, "ecc-sbe", monitoring.RuleECCHistorical, "DCGM_FI_DEV_ECC_SBE_VOL_TOTAL", binding)
	b := f.policy(t, "ecc-dbe", monitoring.RuleECCHistorical, "DCGM_FI_DEV_ECC_DBE_VOL_TOTAL", binding)
	for _, policy := range []monitoring.Policy{a, b} {
		if _, err := f.monitor.Enroll(context.Background(), policy, 0, "local-operator"); err != nil {
			t.Fatal(err)
		}
	}
	duplicate := a
	duplicate.ID = "ecc-duplicate"
	if _, err := f.monitor.Enroll(context.Background(), duplicate, 0, "local-operator"); err == nil {
		t.Fatal("duplicate active sensor accepted")
	}
	f.record(t, domain.QueryGPUECC, domain.ResultSucceeded, map[string]float64{a.Metric: 5, b.Metric: 2}, f.clock(t).Add(-time.Millisecond), true)
	f.refresh(t)
	status := f.status(t, a.ID)
	if !status.Enrollment.State.Open {
		t.Fatalf("ECC attention %+v", status)
	}
	if _, err := f.monitor.Disable(context.Background(), "monitor-cluster", a.ID, 1, "local-operator"); err != nil {
		t.Fatal(err)
	}
	episode, err := f.monitor.ReviewRecovery(context.Background(), "monitor-cluster", a.ID, 1, 1, "local-operator", status.Episodes[0].Evidence[0].EvidenceID)
	if err != nil || episode.ClosedReason != monitoring.ReasonReviewedDisposition {
		t.Fatalf("review %+v %v", episode, err)
	}
	if _, err = f.monitor.Enroll(context.Background(), a, 2, "local-operator"); err != nil {
		t.Fatal(err)
	}
	f.record(t, domain.QueryGPUECC, domain.ResultSucceeded, map[string]float64{a.Metric: 5}, f.clock(t).Add(-time.Millisecond), true)
	f.refresh(t)
	if got := f.status(t, a.ID); got.Enrollment.State.Open || len(got.Episodes) != 1 {
		t.Fatal("same reviewed historical baseline reopened")
	}
	f.record(t, domain.QueryGPUECC, domain.ResultSucceeded, map[string]float64{a.Metric: 6}, f.clock(t).Add(-time.Millisecond), true)
	f.refresh(t)
	if got := f.status(t, a.ID); !got.Enrollment.State.Open || len(got.Episodes) != 2 {
		t.Fatalf("changed historical attention %+v", got)
	}
}

func TestMonitoringConcurrentRefreshAndMigrationRollback(t *testing.T) {
	f := newMonitoringFixture(t)
	binding := f.schedule(t, domain.QueryGPUTemperature)
	policy := f.policy(t, "concurrent", monitoring.RuleTelemetryLoss, "", binding)
	if _, err := f.monitor.Enroll(context.Background(), policy, 0, "local-operator"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = storepg.NewMonitoringStore(f.pool).Refresh(context.Background()) }()
	}
	wg.Wait()
	status := f.status(t, policy.ID)
	if len(status.Episodes) != 1 {
		t.Fatalf("concurrent duplicates %+v", status)
	}
	down, err := os.ReadFile("../../../migrations/000076_existing_source_monitoring.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(context.Background(), string(down)); err == nil || !strings.Contains(err.Error(), "schema rollback refused") {
		t.Fatalf("populated rollback %v", err)
	}
	// Failed down migration is transactional in the migration runner; a direct
	// multi-statement PostgreSQL batch is also atomic and leaves evidence intact.
	if len(f.status(t, policy.ID).Episodes) != 1 {
		t.Fatal("rollback removed evidence")
	}
	empty := durableTestDatabase(t)
	if _, err = empty.Exec(context.Background(), string(down)); err != nil {
		t.Fatalf("empty rollback %v", err)
	}
	up, _ := os.ReadFile("../../../migrations/000076_existing_source_monitoring.up.sql")
	if _, err = empty.Exec(context.Background(), string(up)); err != nil {
		t.Fatalf("reexpand %v", err)
	}
}

func TestMonitoringSlowPolicyCannotStarveLaterPolicyAndCancellation(t *testing.T) {
	f := newMonitoringFixture(t)
	binding := f.schedule(t, domain.QueryGPUTemperature)
	slow := f.policy(t, "a-slow", monitoring.RuleGPUThermal, "DCGM_FI_DEV_GPU_TEMP", binding)
	fast := f.policy(t, "b-fast", monitoring.RuleHBMThermal, "DCGM_FI_DEV_MEMORY_TEMP", binding)
	for _, policy := range []monitoring.Policy{slow, fast} {
		if _, err := f.monitor.Enroll(context.Background(), policy, 0, "local-operator"); err != nil {
			t.Fatal(err)
		}
	}
	f.exec(t, `CREATE FUNCTION monitor_slow_policy() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.policy_id='a-slow' AND NEW.last_failure_code='' AND NEW.last_attempt_at IS DISTINCT FROM OLD.last_attempt_at THEN PERFORM pg_sleep(3); END IF; RETURN NEW; END $$; CREATE TRIGGER monitor_slow_policy BEFORE UPDATE ON gp09_monitor_enrollments FOR EACH ROW EXECUTE FUNCTION monitor_slow_policy()`)
	if err := f.monitor.Refresh(context.Background()); err == nil {
		t.Fatal("slow policy expected bounded failure")
	}
	a, b := f.status(t, slow.ID), f.status(t, fast.ID)
	if a.Enrollment.LastFailureCode != "EVALUATION_FAILED" || b.Enrollment.LastAttemptAt == nil || b.Enrollment.LastFailureCode != "" {
		t.Fatalf("slow row starved later policy: slow=%+v fast=%+v", a.Enrollment, b.Enrollment)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.monitor.Refresh(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation %v", err)
	}
}

func TestMonitoringIncrementalConflictingAliasUsesPreservedCursorEvidence(t *testing.T) {
	f := newMonitoringFixture(t)
	binding := f.schedule(t, domain.QueryGPUTemperature)
	policy := f.policy(t, "tie", monitoring.RuleGPUThermal, "DCGM_FI_DEV_GPU_TEMP", binding)
	policy.ConfirmCount = 2
	if _, err := f.monitor.Enroll(context.Background(), policy, 0, "local-operator"); err != nil {
		t.Fatal(err)
	}
	at := f.clock(t).Add(-time.Millisecond)
	first := f.record(t, domain.QueryGPUTemperature, domain.ResultSucceeded, map[string]float64{policy.Metric: 90}, at, true)
	f.refresh(t)
	if len(f.status(t, policy.ID).Enrollment.State.Pending) != 1 {
		t.Fatal("first genuine confirmation missing")
	}
	// Simulate ordinary raw retention after preserving a durable pending fact.
	// A later run carries a conflicting legacy alias with the same source time.
	f.exec(t, `DELETE FROM current_projections WHERE observation_id IN(SELECT observation_id FROM observations WHERE run_id=$1)`, first)
	f.exec(t, `DELETE FROM observations WHERE run_id=$1`, first)
	second := f.record(t, domain.QueryGPUTemperature, domain.ResultSucceeded, map[string]float64{policy.Metric: 40}, f.clock(t).Add(-time.Millisecond), true)
	f.exec(t, `UPDATE observations SET entity_key='node/node-a/gpu/GPU-a',observed_at=$2 WHERE run_id=$1`, second, at)
	f.refresh(t)
	got := f.status(t, policy.ID)
	if got.Enrollment.State.Open || len(got.Enrollment.State.Pending) != 0 || got.Enrollment.State.LastGap != monitoring.ReasonConflict {
		t.Fatalf("incremental alias manufactured confirmation %+v", got.Enrollment.State)
	}
}

func TestMonitoringCanonicalRemapAliasEvidenceAndNoAliasEnrollment(t *testing.T) {
	f := newMonitoringFixture(t)
	binding := f.schedule(t, domain.QueryGPUECC)
	policy := f.policy(t, "remap", monitoring.RuleECCHistorical, "DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", binding)
	policy.Rule = monitoring.RuleRemapFailure
	policy.Metric = "DCGM_FI_DEV_ROW_REMAP_FAILURE"
	policy.Unit = "boolean"
	policy.Severity = domain.HealthSeverityCritical
	if _, err := f.monitor.Enroll(context.Background(), policy, 0, "local-operator"); err != nil {
		t.Fatal(err)
	}
	alias := policy
	alias.ID = "remap-alias"
	alias.Metric = "DCGM_FI_DEV_ROW_REMAP_FAILED"
	if _, err := f.monitor.Enroll(context.Background(), alias, 0, "local-operator"); err == nil {
		t.Fatal("alias policy accepted")
	}
	run := f.record(t, domain.QueryGPUECC, domain.ResultSucceeded, map[string]float64{policy.Metric: 1}, f.clock(t).Add(-time.Millisecond), true)
	f.exec(t, `UPDATE observations SET metric='DCGM_FI_DEV_ROW_REMAP_FAILED' WHERE run_id=$1`, run)
	f.refresh(t)
	got := f.status(t, policy.ID)
	if !got.Enrollment.State.Open || got.Episodes[0].Evidence[0].Snapshot[0].Metric != "DCGM_FI_DEV_ROW_REMAP_FAILED" {
		t.Fatalf("alias source evidence rewritten/dropped %+v", got)
	}
}

func TestMonitoringDurableV1ExactOccurrenceReceiptAndRecovery(t *testing.T) {
	pool := durableTestDatabase(t)
	collection, _ := storepg.NewCollectionStore(pool)
	control, _ := storepg.NewCollectorControlStore(pool)
	fixture := durableFixture{pool, collection, control, domain.DurableAdmissionPolicy{GlobalLimit: 2, ClusterLimit: 2}}
	ctx := context.Background()
	schedules := fixture.seed(t, "monitor-durable", -time.Minute)
	var selected domain.DesiredSchedule
	for _, d := range schedules {
		if d.Operation == domain.OperationPrometheusGPUUtilization {
			selected = d
		} else {
			d.Enabled = false
			if _, err := collection.UpdateDesiredSchedule(ctx, d); err != nil {
				t.Fatal(err)
			}
		}
	}
	monitor := storepg.NewMonitoringStore(pool)
	policy := monitoring.Policy{ID: "durable-loss", ClusterID: selected.ClusterID, SourceID: selected.SourceID, EntityKey: "source/" + string(selected.SourceID), Rule: monitoring.RuleTelemetryLoss, RuleVersion: 1, Binding: monitoring.Binding{Operation: selected.Operation, ScheduleRevision: selected.Revision, Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{}}}, StartupGraceSeconds: 120, FreshForSeconds: 120, ConfirmCount: 1, ConfirmWindowSeconds: 120, RecoverCount: 2, RecoverWindowSeconds: 120, MaxSampleGapSeconds: 120, Severity: domain.HealthSeverityWarning}
	if _, err := monitor.Enroll(ctx, policy, 0, "local-operator"); err != nil {
		t.Fatal(err)
	}
	finalize := func(status domain.ResultStatus) {
		t.Helper()
		fixture.exec(t, `UPDATE durable_schedule_state SET next_due_at=clock_timestamp() WHERE cluster_id=$1 AND operation=$2`, selected.ClusterID, selected.Operation)
		admitted := fixture.admit(t)
		lease, found, err := control.ClaimWork(ctx, "monitor-durable-collector", strings.Repeat("a", 32), time.Minute)
		if err != nil || !found {
			t.Fatalf("claim %v %v", found, err)
		}
		var at time.Time
		if err = pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
			t.Fatal(err)
		}
		result := domain.CollectionResult{Task: lease.Work.Task, Status: status, StartedAt: at, CompletedAt: at, Coverage: domain.Coverage{Complete: status == domain.ResultSucceeded}}
		if status == domain.ResultSucceeded {
			result.Observations = []domain.Observation{{ID: domain.ObservationID("observation-" + lease.Work.Task.RunID), SchemaVersion: 1, ClusterID: selected.ClusterID, SourceID: selected.SourceID, Kind: "gpu_utilization", EntityKey: string(selected.ClusterID) + "/GPU/node-a/GPU-a/", Metric: "DCGM_FI_DEV_GPU_UTIL", Value: 95, Unit: "percent", ObservedAt: at, CollectedAt: at, SourceReference: "prometheus:" + string(domain.QueryGPUUtilization)}}
			result.Coverage.SeriesReturned = 1
		} else {
			result.Failures = []domain.CollectionFailure{{Code: domain.FailureSourceUnavailable, Message: "Synthetic unavailable source"}}
		}
		body, err := json.Marshal(domain.CollectorResultDocument{SchemaVersion: 1, WorkID: admitted.WorkID, Attempt: lease.Attempt, Result: result})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		checksum := hex.EncodeToString(digest[:])
		ref := collectorcontrol.LeaseRef{WorkID: admitted.WorkID, Attempt: lease.Attempt, LeaseToken: lease.LeaseToken}
		if _, err = control.UploadResultChunk(ctx, "monitor-durable-collector", collectorcontrol.ResultChunk{LeaseRef: ref, Index: 0, Payload: body, SHA256: checksum}); err != nil {
			t.Fatal(err)
		}
		if _, err = control.FinalizeResult(ctx, "monitor-durable-collector", collectorcontrol.ResultFinalization{LeaseRef: ref, RunID: result.Task.RunID, Status: status, ChunkCount: 1, Bytes: int64(len(body)), SHA256: checksum}); err != nil {
			t.Fatal(err)
		}
	}
	refresh := func() storepg.MonitoringStatus {
		t.Helper()
		fixture.exec(t, `UPDATE gp09_monitor_enrollments SET next_due_at=clock_timestamp()`)
		if err := monitor.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		got, err := monitor.Status(ctx, selected.ClusterID, policy.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	finalize(domain.ResultFailed)
	if got := refresh(); !got.Enrollment.State.Open || got.Episodes[0].Reason != monitoring.ReasonCollectionFailed {
		t.Fatalf("durable failure not detected %+v", got)
	}
	finalize(domain.ResultSucceeded)
	if got := refresh(); !got.Enrollment.State.Open {
		t.Fatal("single run prematurely recovered")
	}
	finalize(domain.ResultSucceeded)
	if got := refresh(); got.Enrollment.State.Open || got.Episodes[0].ClosedReason != monitoring.ReasonFreshRecovery {
		t.Fatalf("durable source recovery %+v", got)
	}
}

func TestMonitoringAuthorityRevisionForeignScopeAndFutureInventoryStayUnknown(t *testing.T) {
	f := newMonitoringFixture(t)
	binding := f.schedule(t, domain.QueryGPUTemperature)
	policy := f.policy(t, "authority", monitoring.RuleGPUThermal, "DCGM_FI_DEV_GPU_TEMP", binding)
	foreign := policy
	foreign.ID = "foreign"
	foreign.SourceID = "foreign-source"
	if _, err := f.monitor.Enroll(context.Background(), foreign, 0, "local-operator"); !errors.Is(err, storepg.ErrMonitoringAuthority) {
		t.Fatalf("foreign source accepted %v", err)
	}
	if _, err := f.monitor.Enroll(context.Background(), policy, 0, "local-operator"); err != nil {
		t.Fatal(err)
	}
	f.record(t, domain.QueryGPUTemperature, domain.ResultSucceeded, map[string]float64{policy.Metric: 90}, f.clock(t).Add(-time.Millisecond), true)
	f.refresh(t)
	now := f.clock(t)
	goodput, _ := storepg.NewGoodputStore(f.pool)
	if _, err := goodput.RecordExpectedInventoryRevision(context.Background(), domain.InventoryRevision{SchemaVersion: 1, ID: "monitor-future-inventory", ClusterID: "monitor-cluster", SourceID: "monitor-source", SourceAt: now.Add(time.Hour), EffectiveAt: now.Add(-time.Second), ObservedAt: now, Entities: []domain.EntityIdentity{{ClusterID: "monitor-cluster", Kind: domain.EntityGPU, NodeID: "node-a", PhysicalGPUUUID: "GPU-a"}}}); err != nil {
		t.Fatal(err)
	}
	f.refresh(t)
	got := f.status(t, policy.ID)
	if !got.Enrollment.State.Open || got.Enrollment.State.LastGap != monitoring.ReasonAuthority || got.Enrollment.LastFailureCode != "AUTHORITY_UNAVAILABLE" || got.Episodes[0].ClosedAt != nil {
		t.Fatalf("future inventory manufactured authority/recovery %+v", got)
	}
	future := policy
	future.ID = "future-enrollment"
	future.Binding.InventoryRevisionID = "monitor-future-inventory"
	if _, err := f.monitor.Enroll(context.Background(), future, 0, "local-operator"); !errors.Is(err, storepg.ErrMonitoringAuthority) {
		t.Fatalf("future-source inventory accepted %v", err)
	}
	d, err := f.collection.DesiredSchedule(context.Background(), domain.ScheduleKey{ClusterID: policy.ClusterID, SourceID: policy.SourceID, Operation: policy.Binding.Operation})
	if err != nil {
		t.Fatal(err)
	}
	d.Enabled = false
	if _, err = f.collection.UpdateDesiredSchedule(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	f.refresh(t)
	if got = f.status(t, policy.ID); !got.Enrollment.State.Open || got.Enrollment.State.LastGap != monitoring.ReasonAuthority {
		t.Fatal("disabled schedule falsely cleared")
	}
}

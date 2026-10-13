//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
)

type monitoringFleetFixture struct {
	pool                            *pgxpool.Pool
	cluster, source, job, inventory string
	base                            time.Time
	count                           int
	configuration                   int64
}

func newMonitoringFleetFixture(t *testing.T, count int) *monitoringFleetFixture {
	t.Helper()
	url := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal("fixture pool")
	}
	t.Cleanup(pool.Close)
	suffix := fmt.Sprint(time.Now().UnixNano())
	f := &monitoringFleetFixture{pool: pool, cluster: "monitor-fleet-c-" + suffix, source: "monitor-fleet-s-" + suffix, job: "monitor-fleet-j-" + suffix, inventory: "monitor-fleet-i-" + suffix, count: count}
	if err = pool.QueryRow(context.Background(), `SELECT clock_timestamp() - interval '1 hour'`).Scan(&f.base); err != nil {
		t.Fatal("fixture database clock")
	}
	f.exec(t, `INSERT INTO clusters(cluster_id,display_name) VALUES($1,'Synthetic monitoring fleet')`, f.cluster)
	f.exec(t, `INSERT INTO sources(source_id,cluster_id,kind,display_name,availability) VALUES($1,$2,'prometheus','Synthetic monitoring fleet','UNKNOWN')`, f.source, f.cluster)
	f.exec(t, `INSERT INTO collection_jobs(job_id,cluster_id,source_id,query_kind,interval_seconds,next_run_at) VALUES($1,$2,$3,'dcgm_gpu_temperature',30,clock_timestamp())`, f.job, f.cluster, f.source)
	f.exec(t, `INSERT INTO desired_schedules(cluster_id,source_id,operation,enabled,mode,interval_seconds,timeout_ms,jitter_ms,max_targets,max_bytes,priority,legacy_query_kind,legacy_job_id) VALUES($1,$2,'prometheus.gpu_temperature.v1',true,'legacy',30,5000,0,1000,1048576,50,'dcgm_gpu_temperature',$3)`, f.cluster, f.source, f.job)
	if err = pool.QueryRow(context.Background(), `SELECT configuration_revision FROM collection_jobs WHERE job_id=$1`, f.job).Scan(&f.configuration); err != nil {
		t.Fatal(err)
	}
	old := f.base.Add(-time.Hour)
	f.exec(t, `INSERT INTO goodput_inventory_revisions(revision_id,cluster_id,source_id,inventory_class,schema_version,content_digest,source_at,effective_at,observed_at) VALUES($1,$2,$3,'EXPECTED',1,decode(repeat('00',32),'hex'),$4,$4,$4)`, f.inventory, f.cluster, f.source, old)
	f.exec(t, `INSERT INTO goodput_inventory_revision_validity(cluster_id,revision_id,valid_from) VALUES($1,$2,$3)`, f.cluster, f.inventory, old)
	for i := 0; i < count; i++ {
		node, uuid := f.device(i)
		f.exec(t, `INSERT INTO goodput_inventory_revision_entities(cluster_id,revision_id,entity_kind,stable_node_id,physical_gpu_uuid) VALUES($1,$2,'GPU',$3,$4)`, f.cluster, f.inventory, node, uuid)
	}
	return f
}
func (f *monitoringFleetFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), query, args...); err != nil {
		t.Fatalf("synthetic monitoring fixture SQL: %v", err)
	}
}
func (f *monitoringFleetFixture) device(index int) (string, string) {
	return fmt.Sprintf("node-%03d", index/8+1), fmt.Sprintf("GPU-%03d", index)
}
func (f *monitoringFleetFixture) policy(id string) monitoring.Policy {
	node, uuid := f.device(f.count - 1)
	return monitoring.Policy{ID: id, ClusterID: domain.ClusterID(f.cluster), SourceID: domain.SourceID(f.source), EntityKey: f.cluster + "/GPU/" + node + "/" + uuid + "/", Rule: monitoring.RuleGPUThermal, RuleVersion: 1, Metric: "DCGM_FI_DEV_GPU_TEMP", Unit: "celsius", Binding: monitoring.Binding{Operation: domain.OperationPrometheusGPUTemperature, Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{}}, ScheduleRevision: 1, InventoryRevisionID: f.inventory}, StartupGraceSeconds: 0, FreshForSeconds: 86400, ConfirmCount: 3, ConfirmWindowSeconds: 120, ConfirmMinDurationSeconds: 60, RecoverCount: 3, RecoverWindowSeconds: 120, RecoverMinDurationSeconds: 60, MaxSampleGapSeconds: 60, OpenThreshold: 85, RecoverBelow: 75, Severity: domain.HealthSeverityCritical}
}
func (f *monitoringFleetFixture) attempt(t *testing.T, index int, targetValue float64) (string, string) {
	t.Helper()
	at := f.base.Add(time.Duration(index) * time.Second)
	run := fmt.Sprintf("%s-run-%04d", f.job, index)
	fields := []domain.DCGMFieldEvidence{}
	for i := 0; i < f.count; i++ {
		node, uuid := f.device(i)
		for _, metric := range []string{"DCGM_FI_DEV_GPU_TEMP", "DCGM_FI_DEV_MEMORY_TEMP"} {
			fields = append(fields, domain.DCGMFieldEvidence{NodeID: domain.StableNodeID(node), GPU: domain.PhysicalGPUUUID(uuid), Metric: metric, State: "SUPPORTED"})
		}
	}
	body, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	batch := &pgx.Batch{}
	batch.Queue(`INSERT INTO collection_runs(run_id,job_id,cluster_id,source_id,query_kind,idempotency_key,status,scheduled_for,started_at,completed_at,series_returned,bytes_read,coverage_complete,metric_fields) VALUES($1,$2,$3,$4,'dcgm_gpu_temperature',$1,'SUCCEEDED',$5,$5,$5,$6,100,true,$7)`, run, f.job, f.cluster, f.source, at, f.count*2, body)
	batch.Queue(`INSERT INTO collection_run_jobs(run_id,job_id,cluster_id,source_id,query_kind,node_filter,scheduled_for,configuration_revision,lease_generation) VALUES($1,$2,$3,$4,'dcgm_gpu_temperature','',$5,$6,1)`, run, f.job, f.cluster, f.source, at, f.configuration)
	lastObservation := ""
	for i := 0; i < f.count; i++ {
		node, uuid := f.device(i)
		for _, metric := range []string{"DCGM_FI_DEV_GPU_TEMP", "DCGM_FI_DEV_MEMORY_TEMP"} {
			value := float64(40)
			if i == f.count-1 && metric == "DCGM_FI_DEV_GPU_TEMP" {
				value = targetValue
			}
			id := fmt.Sprintf("%s-%03d-%s", run, i, metric)
			if i == f.count-1 && metric == "DCGM_FI_DEV_GPU_TEMP" {
				lastObservation = id
			}
			batch.Queue(`INSERT INTO observations(observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,observed_at,collected_at,source_reference,sample_fingerprint) VALUES($1,$2,$3,$4,1,'gpu_temperature',$5,$6,'[]'::jsonb,$7,'celsius',$8,$8,'synthetic-fleet',$9)`, id, run, f.cluster, f.source, f.cluster+"/GPU/"+node+"/"+uuid+"/", metric, value, at, []byte(id))
		}
	}
	results := f.pool.SendBatch(context.Background(), batch)
	defer results.Close()
	for i := 0; i < batch.Len(); i++ {
		if _, err = results.Exec(); err != nil {
			t.Fatalf("synthetic attempt batch: %v", err)
		}
	}
	return run, lastObservation
}
func (f *monitoringFleetFixture) refresh(t *testing.T, store *MonitoringStore, id string) MonitoringStatus {
	t.Helper()
	f.exec(t, `UPDATE gp09_monitor_enrollments SET next_due_at=clock_timestamp() WHERE cluster_id=$1 AND policy_id=$2`, f.cluster, id)
	if err := store.Refresh(context.Background()); err != nil {
		f.exec(t, `UPDATE gp09_monitor_enrollments SET next_due_at=clock_timestamp() WHERE cluster_id=$1 AND policy_id=$2`, f.cluster, id)
		_, _, cause := store.refreshOne(context.Background())
		t.Fatalf("actual synthetic monitoring refresh: %v; isolated underlying cause: %v", err, cause)
	}
	status, err := store.Status(context.Background(), domain.ClusterID(f.cluster), id)
	if err != nil {
		t.Fatal(err)
	}
	return status
}

func TestMonitoringFleetLateGPUIsNotHiddenByGlobalRawLimit(t *testing.T) {
	f := newMonitoringFleetFixture(t, 112)
	store := NewMonitoringStore(f.pool)
	policy := f.policy("fleet-late-" + f.cluster)
	if _, err := store.Enroll(context.Background(), policy, 0, "fixture-local-operator"); err != nil {
		t.Fatal(err)
	}
	for _, second := range []int{0, 30, 60} {
		f.attempt(t, second, 90)
	}
	status := f.refresh(t, store, policy.ID)
	if status.Enrollment.LastFailureCode != "" || !status.Enrollment.State.Open || len(status.Episodes) != 1 || status.Enrollment.State.FirstQualifying == nil || status.Enrollment.State.LastQualifying == nil {
		t.Fatalf("late GPU missing among672 raw observations: failure=%s state=%+v episodes=%d", status.Enrollment.LastFailureCode, status.Enrollment.State, len(status.Episodes))
	}
	if !status.Enrollment.State.FirstQualifying.ObservedAt.Equal(f.base) || !status.Enrollment.State.LastQualifying.ObservedAt.Equal(f.base.Add(60*time.Second)) {
		t.Fatal("three distinct late-GPU samples lost their exact hold interval")
	}
}

func TestMonitoringFleetLifetimeCursorSurvivesMoreThan256AttemptsAndRestart(t *testing.T) {
	f := newMonitoringFleetFixture(t, 1)
	store := NewMonitoringStore(f.pool)
	policy := f.policy("fleet-life-" + f.cluster)
	if _, err := store.Enroll(context.Background(), policy, 0, "fixture-local-operator"); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 270; index++ {
		_, last := f.attempt(t, index, 40)
		if index == 135 {
			store = NewMonitoringStore(f.pool)
		}
		status := f.refresh(t, store, policy.ID)
		if status.Enrollment.LastFailureCode != "" || status.Enrollment.HistoryCoverage != nil || status.Enrollment.State.SourceCursor == nil || string(status.Enrollment.State.SourceCursor.ObservationID) != last {
			t.Fatalf("lifetime cursor failed atattempt%d: failure=%s history=%+v state=%+v", index, status.Enrollment.LastFailureCode, status.Enrollment.HistoryCoverage, status.Enrollment.State)
		}
	}
}

func TestMonitoringFleetOverflowPreservesHistoryGapAfterRestartAndFreshSuffix(t *testing.T) {
	f := newMonitoringFleetFixture(t, 1)
	store := NewMonitoringStore(f.pool)
	policy := f.policy("fleet-gap-" + f.cluster)
	if _, err := store.Enroll(context.Background(), policy, 0, "fixture-local-operator"); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 300; index++ {
		f.attempt(t, index, 40)
	}
	status := f.refresh(t, store, policy.ID)
	if status.Enrollment.HistoryCoverage == nil || status.Enrollment.HistoryCoverage.OmittedAttemptsLowerBound < 1 || status.Enrollment.LastFailureCode != "HISTORY_TRUNCATED" || status.Enrollment.State.Open {
		t.Fatalf("overflow lost explicit coveragegap: %+v", status.Enrollment)
	}
	gap := *status.Enrollment.HistoryCoverage
	_, last := f.attempt(t, 300, 40)
	status = f.refresh(t, NewMonitoringStore(f.pool), policy.ID)
	if status.Enrollment.HistoryCoverage == nil || *status.Enrollment.HistoryCoverage != gap || status.Enrollment.LastFailureCode != "" || status.Enrollment.State.SourceCursor == nil || string(status.Enrollment.State.SourceCursor.ObservationID) != last {
		t.Fatal("fresh suffix/restart erased historygap or failed to advance")
	}
}

func TestMonitoringFleetTelemetryWitnessUsesFreshSupportedOperationEvidence(t *testing.T) {
	for _, fixture := range []struct {
		name      string
		edit      string
		qualifies bool
	}{
		{"stale_first_fresh_second", `UPDATE observations SET observed_at=observed_at-interval '2 minutes' WHERE run_id=$1 AND metric='DCGM_FI_DEV_GPU_TEMP'`, true},
		{"stale_only", `UPDATE observations SET observed_at=observed_at-interval '2 minutes' WHERE run_id=$1`, false},
		{"reviewed_celsius_alias", `UPDATE observations SET unit='C' WHERE run_id=$1`, true},
		{"dcgm_integer_sentinel", `UPDATE observations SET value=140737488355328 WHERE run_id=$1`, false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			f := newMonitoringFleetFixture(t, 1)
			store := NewMonitoringStore(f.pool)
			policy := f.policy("fleet-witness-" + f.cluster)
			policy.Rule, policy.EntityKey, policy.Metric, policy.Unit = monitoring.RuleTelemetryLoss, "source/"+f.source, "", ""
			policy.Binding.InventoryRevisionID = ""
			policy.FreshForSeconds, policy.ConfirmCount, policy.ConfirmMinDurationSeconds, policy.RecoverCount, policy.RecoverMinDurationSeconds, policy.OpenThreshold, policy.RecoverBelow = 60, 1, 0, 1, 0, 0, 0
			if _, err := store.Enroll(context.Background(), policy, 0, "fixture-local-operator"); err != nil {
				t.Fatal(err)
			}
			status := f.refresh(t, store, policy.ID)
			if !status.Enrollment.State.Open {
				t.Fatal("fixture silent source did not open")
			}
			if err := f.pool.QueryRow(context.Background(), `SELECT clock_timestamp()`).Scan(&f.base); err != nil {
				t.Fatal(err)
			}
			run, _ := f.attempt(t, 0, 40)
			f.exec(t, fixture.edit, run)
			status = f.refresh(t, store, policy.ID)
			if status.Enrollment.LastFailureCode != "" || status.Enrollment.State.Open == fixture.qualifies || status.Enrollment.State.LastRelevantSuccessAt.IsZero() == fixture.qualifies {
				t.Fatalf("qualified source witness mismatch: qualifies=%v state=%+v failure=%s", fixture.qualifies, status.Enrollment.State, status.Enrollment.LastFailureCode)
			}
			if fixture.qualifies && (len(status.Episodes) != 1 || status.Episodes[0].ClosedReason != monitoring.ReasonFreshRecovery) {
				t.Fatal("fresh relevant source contact did not recover its own episode")
			}
		})
	}
}

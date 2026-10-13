//go:build integration

package adminview_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adminview"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestPostgresStoreScopesAndAggregatesCurrentResources(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := "admin-resource-cluster-" + suffix
	sourceID := "admin-resource-source-" + suffix
	missingSourceID := "admin-resource-missing-source-" + suffix
	onDemandSourceID := "admin-resource-on-demand-source-" + suffix
	collectorID := "admin-resource-collector-" + suffix
	runID := "admin-resource-run-" + suffix
	now := time.Now().UTC().Truncate(time.Microsecond)
	mustExec(t, pool, `INSERT INTO clusters (cluster_id,display_name,expected_collectors,created_at) VALUES ($1,'Resource cluster',ARRAY['Headnode','Backup headnode'],$2)`, clusterID, now)
	mustExec(t, pool, `INSERT INTO sources (source_id,cluster_id,kind,display_name,availability,last_attempt_at,last_success_at,created_at) VALUES ($1,$2,'prometheus','DCGM','AVAILABLE',$3,$3,$3)`, sourceID, clusterID, now)
	mustExec(t, pool, `INSERT INTO sources (source_id,cluster_id,kind,display_name,availability,last_attempt_at,last_failure_code,created_at) VALUES ($1,$2,'prometheus','Kernel events','UNAVAILABLE',$3,'SOURCE_OFFLINE',$3)`, missingSourceID, clusterID, now)
	mustExec(t, pool, `INSERT INTO sources (source_id,cluster_id,kind,display_name,availability,created_at) VALUES ($1,$2,'model','Model call audit','UNKNOWN',$3)`, onDemandSourceID, clusterID, now)
	mustExec(t, pool, `INSERT INTO collectors (collector_id,cluster_id,display_name,status,version,build_commit,protocol_min,protocol_max,operating_system,architecture,last_heartbeat_at,created_at) VALUES ($1,$2,'Headnode','ACTIVE','1.0.0','test',1,1,'linux','amd64',$3,$3)`, collectorID, clusterID, now)
	jobID := "admin-resource-job-" + suffix
	mustExec(t, pool, `INSERT INTO collection_jobs (job_id,cluster_id,source_id,query_kind,interval_seconds,next_run_at)
		VALUES ($1,$2,$3,'DCGM_GPU_UTILIZATION',30,$4)`, jobID, clusterID, sourceID, now)
	mustExec(t, pool, `INSERT INTO desired_schedules (cluster_id,source_id,operation,enabled,mode,interval_seconds,timeout_ms,jitter_ms,max_targets,max_bytes,priority,legacy_query_kind,legacy_job_id)
		VALUES ($1,$2,'prometheus.gpu_utilization.v1',true,'legacy',30,5000,0,100,1048576,50,'DCGM_GPU_UTILIZATION',$3)`, clusterID, sourceID, jobID)
	mustExec(t, pool, `INSERT INTO collection_runs (run_id,cluster_id,source_id,query_kind,idempotency_key,status,scheduled_for,started_at,completed_at,series_returned,bytes_read,coverage_complete) VALUES ($1,$2,$3,'DCGM_GPU_UTILIZATION',$1,'SUCCEEDED',$4,$4,$4,3,300,true)`, runID, clusterID, sourceID, now)
	for index, fixture := range []struct {
		entity string
		value  float64
	}{{"node/comp001/gpu/0", 20}, {"node/comp001/gpu/1", 40}, {"node/comp002/gpu/0", 60}} {
		observationID := runID + "-observation-" + string(rune('1'+index))
		fingerprint := []byte{byte(index + 1)}
		mustExec(t, pool, `INSERT INTO observations (observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,observed_at,collected_at,source_reference,sample_fingerprint) VALUES ($1,$2,$3,$4,1,'GAUGE',$5,'DCGM_FI_DEV_GPU_UTIL','[]'::jsonb,$6,'percent',$7,$7,'integration',$8)`, observationID, runID, clusterID, sourceID, fixture.entity, fixture.value, now, fingerprint)
		mustExec(t, pool, `INSERT INTO current_projections (cluster_id,source_id,entity_key,metric,observation_id,observed_at,last_success_at,updated_at) VALUES ($1,$2,$3,'DCGM_FI_DEV_GPU_UTIL',$4,$5,$5,$5)`, clusterID, sourceID, fixture.entity, observationID, now)
	}
	// Reconcile one legacy indexed sample using explicit UUID proof, then
	// coexist with its canonical migration alias without inflating the average.
	mustExec(t, pool, `UPDATE observations SET labels='[{"Name":"UUID","Value":"GPU-1"}]'::jsonb WHERE observation_id=$1`, runID+"-observation-1")
	for index, key := range []string{clusterID + "/GPU/comp001/GPU-1/", "foreign-cluster/GPU/foreign-node/GPU-x/"} {
		id := runID + "-migration-" + string(rune('a'+index))
		mustExec(t, pool, `INSERT INTO observations (observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,observed_at,collected_at,source_reference,sample_fingerprint) VALUES ($1,$2,$3,$4,1,'GAUGE',$5,'DCGM_FI_DEV_GPU_UTIL','[]'::jsonb,20,'percent',$6,$6,'integration',$7)`, id, runID, clusterID, sourceID, key, now, []byte(id))
		mustExec(t, pool, `INSERT INTO current_projections (cluster_id,source_id,entity_key,metric,observation_id,observed_at,last_success_at,updated_at) VALUES ($1,$2,$3,'DCGM_FI_DEV_GPU_UTIL',$4,$5,$5,$5)`, clusterID, sourceID, key, id, now)
	}
	mustExec(t, pool, `INSERT INTO evidence_envelopes (evidence_id,schema_version,cluster_id,status,source_id,run_id,operation,definition_version,source_reference,observed_start,observed_end,collected_at,coverage_expected,coverage_covered) VALUES ($1,1,$2,'UNAVAILABLE',$3,$4,'gpu.health','v1','integration',$5,$5,$5,'[{"Kind":"GPU","ID":"gpu-0"}]'::jsonb,'null'::jsonb)`, runID+"-evidence", clusterID, sourceID, runID, now)
	// This stream is current for the shared five-minute policy but historical
	// under the legacy public API's one-minute freshness setting.
	mustExec(t, pool, `INSERT INTO evidence_envelopes (evidence_id,schema_version,cluster_id,status,source_id,operation,definition_version,source_reference,observed_start,observed_end,collected_at,coverage_expected,coverage_covered) VALUES ($1,1,$2,'PARTIAL',$3,'recent.gpu.health','v1','integration',$4,$4,$4,'[]'::jsonb,'[]'::jsonb)`, runID+"-recent-evidence", clusterID, sourceID, now.Add(-3*time.Minute))
	// An old distinct stream remains in the full administrator history, but
	// cannot become a current or historical warning in the bounded health view.
	mustExec(t, pool, `INSERT INTO evidence_envelopes (evidence_id,schema_version,cluster_id,status,source_id,operation,definition_version,source_reference,observed_start,observed_end,collected_at,coverage_expected,coverage_covered) VALUES ($1,1,$2,'PARTIAL',$3,'old.gpu.health','v1','integration',$4,$4,$4,'[]'::jsonb,'[]'::jsonb)`, runID+"-old-evidence", clusterID, sourceID, now.Add(-48*time.Hour))
	for _, item := range []struct{ class, id string }{{"EXPECTED", "expected-" + suffix}, {"OBSERVED", "observed-" + suffix}} {
		mustExec(t, pool, `INSERT INTO goodput_inventory_revisions
			(revision_id,cluster_id,source_id,inventory_class,schema_version,content_digest,source_at,effective_at,observed_at)
			VALUES ($1,$2,$3,$4,1,decode(repeat('00',32),'hex'),$5,$5,$5)`, item.id, clusterID, sourceID, item.class, now)
		mustExec(t, pool, `INSERT INTO goodput_inventory_revision_validity (cluster_id,revision_id,valid_from) VALUES ($1,$2,$3)`, clusterID, item.id, now.Add(-time.Second))
		mustExec(t, pool, `INSERT INTO goodput_inventory_revision_entities (cluster_id,revision_id,entity_kind,stable_node_id)
			VALUES ($1,$2,'NODE','comp001')`, clusterID, item.id)
		mustExec(t, pool, `INSERT INTO goodput_inventory_revision_entities (cluster_id,revision_id,entity_kind,stable_node_id,physical_gpu_uuid)
			VALUES ($1,$2,'GPU','comp001','GPU-1'),($1,$2,'GPU','comp001','GPU-2')`, clusterID, item.id)
		if item.class == "EXPECTED" {
			mustExec(t, pool, `INSERT INTO goodput_inventory_revision_entities (cluster_id,revision_id,entity_kind,stable_node_id)
				VALUES ($1,$2,'NODE','comp002')`, clusterID, item.id)
			mustExec(t, pool, `INSERT INTO goodput_inventory_revision_entities (cluster_id,revision_id,entity_kind,stable_node_id,physical_gpu_uuid)
				VALUES ($1,$2,'GPU','comp002','GPU-3')`, clusterID, item.id)
		}
	}

	store, err := adminview.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := adminview.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	dashboard, err := service.Snapshot(ctx, adminview.Query{At: now, ClusterID: clusterID, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(dashboard.Clusters) != 1 {
		t.Fatalf("clusters = %+v", dashboard.Clusters)
	}
	resources := dashboard.Clusters[0].Resources
	if resources.State != adminview.StateHealthy || resources.ObservedNodes != 2 || resources.ObservedGPUs != 3 || resources.GPUUtilizationSamples != 3 || resources.GPUUtilizationPercent == nil || *resources.GPUUtilizationPercent != 40 {
		t.Fatalf("resources = %+v", resources)
	}
	if resources.CPUUtilizationPercent != nil || resources.CPUUtilizationSamples != 0 {
		t.Fatalf("unsupported CPU telemetry was inferred: %+v", resources)
	}
	shared := dashboard.Clusters[0].Health
	if shared.SchemaVersion != 1 || shared.Capacity.ExpectedNodes == nil || *shared.Capacity.ExpectedNodes != 2 ||
		shared.Capacity.ObservedNodes == nil || *shared.Capacity.ObservedNodes != 1 || shared.Capacity.Condition != "DEGRADED" ||
		shared.Monitoring.CollectorCondition != "UNAVAILABLE" || shared.Monitoring.CoverageCondition != "DEGRADED" ||
		shared.Workload != "UNKNOWN" || shared.Progress != "UNMEASURED" {
		t.Fatalf("shared health mixed capacity, collector, metric, or workload evidence: %+v", shared)
	}
	if shared.Monitoring.ExpectedOperations != 1 || shared.Monitoring.FreshOperations != 1 || shared.Monitoring.LateOperations != 0 {
		t.Fatalf("schedule-policy freshness was not projected: %+v", shared.Monitoring)
	}
	if shared.Monitoring.HistoricalStreams != 0 || shared.Monitoring.UnavailableStreams != 1 || shared.Monitoring.PartialStreams != 1 {
		t.Fatalf("out-of-window evidence affected shared health: %+v", shared.Monitoring)
	}
	publicStore, err := storepg.NewPublicQueryStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	publicHealth, found, err := publicStore.GetHealth(ctx, domain.ClusterID(clusterID), now, time.Minute)
	if err != nil || !found || publicHealth.Shared == nil {
		t.Fatalf("public health=%+v found=%t err=%v", publicHealth, found, err)
	}
	adminWire, _ := json.Marshal(shared)
	publicWire, _ := json.Marshal(publicHealth.Shared)
	if string(adminWire) != string(publicWire) {
		t.Fatalf("admin and tenant health differ: admin=%s public=%s", adminWire, publicWire)
	}
	connectivity := dashboard.Clusters[0].Connectivity
	if connectivity.Collectors != 2 || connectivity.ActiveCollectors != 1 || connectivity.FreshCollectors != 1 || connectivity.StaleCollectors != 1 || len(connectivity.MissingCollectorLabels) != 1 || !strings.Contains(connectivity.MissingCollectorLabels[0], "Backup headnode") || !strings.Contains(connectivity.MissingCollectorLabels[0], "NEVER REGISTERED") {
		t.Fatalf("expected collector projection = %+v", connectivity)
	}
	if len(connectivity.SourceGapLabels) != 1 || !strings.Contains(connectivity.SourceGapLabels[0], missingSourceID) || !strings.Contains(connectivity.SourceGapLabels[0], "NO DATA") || !strings.Contains(connectivity.SourceGapLabels[0], "SOURCE_OFFLINE") {
		t.Fatalf("source gap projection = %+v", connectivity.SourceGapLabels)
	}
	if len(connectivity.OnDemandSourceLabels) != 1 || !strings.Contains(connectivity.OnDemandSourceLabels[0], onDemandSourceID) || !strings.Contains(connectivity.OnDemandSourceLabels[0], "freshness not tracked") {
		t.Fatalf("on-demand source projection = %+v", connectivity.OnDemandSourceLabels)
	}
	evidence := dashboard.Clusters[0].Evidence
	if evidence.CurrentTotal != 3 || evidence.CurrentUnavailable != 1 || evidence.CurrentPartial != 2 || evidence.Total != 2 || evidence.Partial != 1 || evidence.Unavailable != 1 || evidence.ExpectedTargets != 1 || evidence.CoveredTargets != 0 {
		t.Fatalf("evidence = %+v", evidence)
	}
}

func TestPostgresStoreShowsSlurmPartialOutsideEvidenceEnvelopeCoverage(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	now = now.UTC().Truncate(time.Microsecond)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID, sourceID := "admin-slurm-cluster-"+suffix, "admin-slurm-source-"+suffix
	mustExec(t, pool, `INSERT INTO clusters (cluster_id,display_name) VALUES ($1,'Slurm cluster')`, clusterID)
	mustExec(t, pool, `INSERT INTO sources (source_id,cluster_id,kind,display_name,availability) VALUES ($1,$2,'slurm','Slurm','AVAILABLE')`, sourceID, clusterID)
	for _, operation := range []string{"slurm.inventory.v1", "slurm.snapshot.v1"} {
		mustExec(t, pool, `INSERT INTO desired_schedules (cluster_id,source_id,operation,enabled,mode,interval_seconds,timeout_ms,jitter_ms,max_targets,max_bytes,priority)
			VALUES ($1,$2,$3,true,'durable',300,60000,0,256,1048576,50)`, clusterID, sourceID, operation)
	}
	mustExec(t, pool, `INSERT INTO collection_runs (run_id,cluster_id,source_id,query_kind,idempotency_key,status,scheduled_for,started_at,completed_at,series_returned,bytes_read,coverage_complete)
		VALUES ($1,$2,$3,'slurm.snapshot.v1',$1,'PARTIAL',$4,$4,$4,0,0,false)`, "admin-slurm-run-"+suffix, clusterID, sourceID, now)
	store, err := adminview.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := adminview.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	read := func(at time.Time) adminview.ClusterSummary {
		t.Helper()
		page, err := service.Snapshot(ctx, adminview.Query{At: at, ClusterID: clusterID, Limit: 1})
		if err != nil || len(page.Clusters) != 1 {
			t.Fatalf("Slurm summary at %s = %+v, %v", at, page, err)
		}
		return page.Clusters[0]
	}
	cluster := read(now.Add(time.Second))
	if len(cluster.SlurmOperations) != 2 || cluster.SlurmOperations[0].Operation != "slurm.inventory.v1" ||
		cluster.SlurmOperations[0].Status != "NOT_RUN" || cluster.SlurmOperations[0].LastCompletedAt != nil ||
		cluster.SlurmOperations[1].Operation != "slurm.snapshot.v1" || cluster.SlurmOperations[1].Status != "PARTIAL" ||
		!cluster.SlurmOperations[1].Fresh || cluster.SlurmOperations[1].LastCompletedAt == nil {
		t.Fatalf("Slurm operation projection = %+v", cluster.SlurmOperations)
	}
	if cluster.Evidence.CurrentTotal != 0 {
		t.Fatalf("typed Slurm run was invented as an evidence envelope: %+v", cluster.Evidence)
	}
	stale := read(now.Add(12 * time.Minute))
	if stale.SlurmOperations[1].Fresh {
		t.Fatalf("stale Slurm snapshot remained fresh: %+v", stale.SlurmOperations[1])
	}
}

func TestPostgresStoreSeparatesCurrentEvidenceHealthFromHistoryAndScope(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := "admin-evidence-cluster-" + suffix
	sourceID := "admin-evidence-source-" + suffix
	now := time.Now().UTC().Truncate(time.Microsecond)
	mustExec(t, pool, `INSERT INTO clusters (cluster_id,display_name,created_at) VALUES ($1,'Evidence cluster',$2)`, clusterID, now)
	mustExec(t, pool, `INSERT INTO sources (source_id,cluster_id,kind,display_name,availability,created_at) VALUES ($1,$2,'prometheus','DCGM','AVAILABLE',$3)`, sourceID, clusterID, now)
	targetGPU1 := `[{"Kind":"GPU","ID":"GPU-1"}]`
	targetGPU2 := `[{"Kind":"GPU","ID":"GPU-2"}]`
	targetBoth := `[{"Kind":"GPU","ID":"GPU-1"},{"Kind":"GPU","ID":"GPU-2"}]`
	insertEvidence := func(id, status, operation, expected, covered string, collected time.Time) {
		t.Helper()
		mustExec(t, pool, `INSERT INTO evidence_envelopes (evidence_id,schema_version,cluster_id,status,source_id,operation,definition_version,source_reference,observed_start,observed_end,collected_at,coverage_expected,coverage_covered) VALUES ($1,1,$2,$3,$4,$5,'v1','integration',$6,$6,$6,$7::jsonb,$8::jsonb)`, id, clusterID, status, sourceID, operation, collected, expected, covered)
	}
	insertEvidence("old-unavailable-"+suffix, "UNAVAILABLE", "dcgm_gpu_utilization", targetGPU1, `[]`, now.Add(-4*time.Hour))
	insertEvidence("fresh-complete-"+suffix, "COMPLETE", "dcgm_gpu_utilization", targetGPU1, targetGPU1, now.Add(-time.Hour))
	insertEvidence("scope-partial-"+suffix, "PARTIAL", "dcgm_gpu_xid", targetBoth, targetGPU1, now.Add(-30*time.Minute))
	insertEvidence("scope-complete-"+suffix, "COMPLETE", "dcgm_gpu_xid", targetGPU2, targetGPU2, now.Add(-20*time.Minute))
	// A collection committed after a summary request begins must not replace
	// that request's as-of stream or make admin and tenant health disagree.
	insertEvidence("future-unavailable-"+suffix, "UNAVAILABLE", "dcgm_gpu_utilization", targetGPU1, `[]`, now.Add(time.Minute))

	store, err := adminview.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	dashboard, _, err := store.Load(ctx, adminview.Query{At: now, Window: 24 * time.Hour, FreshFor: 5 * time.Minute, Limit: 1, ClusterID: clusterID})
	if err != nil {
		t.Fatal(err)
	}
	if len(dashboard) != 1 {
		t.Fatalf("dashboard=%+v", dashboard)
	}
	evidence := dashboard[0].Evidence
	if evidence.Total != 4 || evidence.Complete != 2 || evidence.Partial != 1 || evidence.Unavailable != 1 || evidence.CurrentTotal != 3 || evidence.CurrentComplete != 2 || evidence.CurrentPartial != 1 || evidence.CurrentUnavailable != 0 || evidence.HistoricalSuperseded != 1 {
		t.Fatalf("evidence summary=%+v", evidence)
	}
	if len(evidence.CurrentStreams) != 3 {
		t.Fatalf("current streams=%+v", evidence.CurrentStreams)
	}
	foundMissing := false
	for _, stream := range evidence.CurrentStreams {
		if stream.Operation == "dcgm_gpu_xid" && len(stream.MissingTargets) == 1 && stream.MissingTargets[0] == "GPU:GPU-2" {
			foundMissing = strings.Contains(stream.Condition, "incomplete target coverage") && strings.Contains(stream.RecommendedAction, "Restore exporter coverage")
		}
		if stream.Operation == "dcgm_gpu_utilization" && stream.Status != "COMPLETE" {
			t.Fatalf("older unavailable state still affects current health: %+v", stream)
		}
	}
	if !foundMissing {
		t.Fatalf("missing-target repair was not projected: %+v", evidence.CurrentStreams)
	}
	service, err := adminview.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	adminHealth, err := service.Snapshot(ctx, adminview.Query{At: now, Window: 24 * time.Hour, FreshFor: 5 * time.Minute, Limit: 1, ClusterID: clusterID})
	if err != nil {
		t.Fatal(err)
	}
	publicStore, err := storepg.NewPublicQueryStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	publicHealth, found, err := publicStore.GetHealth(ctx, domain.ClusterID(clusterID), now, time.Minute)
	if err != nil || !found || publicHealth.Shared == nil {
		t.Fatalf("public health=%+v found=%t err=%v", publicHealth, found, err)
	}
	adminWire, _ := json.Marshal(adminHealth.Clusters[0].Health)
	publicWire, _ := json.Marshal(publicHealth.Shared)
	if string(adminWire) != string(publicWire) {
		t.Fatalf("as-of admin and tenant health differ: admin=%s public=%s", adminWire, publicWire)
	}
}

func TestPostgresStoreNodeOnlyObservedRevisionLeavesGPUCapacityUnknown(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID, sourceID := "admin-node-only-"+suffix, "admin-node-only-source-"+suffix
	now := time.Now().UTC().Truncate(time.Microsecond)
	mustExec(t, pool, `INSERT INTO clusters (cluster_id,display_name,created_at) VALUES ($1,'Node-only observed cluster',$2)`, clusterID, now)
	mustExec(t, pool, `INSERT INTO sources (source_id,cluster_id,kind,display_name,availability,created_at) VALUES ($1,$2,'slurm','Slurm node inventory','AVAILABLE',$3)`, sourceID, clusterID, now)
	for _, item := range []struct{ class, id string }{{"EXPECTED", "node-only-expected-" + suffix}, {"OBSERVED", "node-only-observed-" + suffix}} {
		mustExec(t, pool, `INSERT INTO goodput_inventory_revisions
			(revision_id,cluster_id,source_id,inventory_class,schema_version,content_digest,source_at,effective_at,observed_at)
			VALUES ($1,$2,$3,$4,1,decode(repeat('00',32),'hex'),$5,$5,$5)`, item.id, clusterID, sourceID, item.class, now)
		mustExec(t, pool, `INSERT INTO goodput_inventory_revision_validity (cluster_id,revision_id,valid_from) VALUES ($1,$2,$3)`, clusterID, item.id, now.Add(-time.Second))
		mustExec(t, pool, `INSERT INTO goodput_inventory_revision_entities (cluster_id,revision_id,entity_kind,stable_node_id)
			VALUES ($1,$2,'NODE','comp001')`, clusterID, item.id)
		if item.class == "EXPECTED" {
			mustExec(t, pool, `INSERT INTO goodput_inventory_revision_entities (cluster_id,revision_id,entity_kind,stable_node_id,physical_gpu_uuid)
				VALUES ($1,$2,'GPU','comp001','GPU-1')`, clusterID, item.id)
		}
	}
	store, err := adminview.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	view, found, err := store.SharedHealth(ctx, adminview.Query{At: now, ClusterID: clusterID})
	if err != nil || !found {
		t.Fatalf("shared health found=%t err=%v", found, err)
	}
	if view.Capacity.ExpectedNodes == nil || *view.Capacity.ExpectedNodes != 1 || view.Capacity.ExpectedGPUs == nil || *view.Capacity.ExpectedGPUs != 1 ||
		view.Capacity.ObservedNodes == nil || *view.Capacity.ObservedNodes != 1 || view.Capacity.ObservedGPUs != nil ||
		view.Capacity.Condition != "UNKNOWN" || strings.Contains(strings.Join(view.Attention, ","), "CAPACITY_MISMATCH") {
		t.Fatalf("node-only inventory was treated as zero GPUs: %+v", view)
	}
}

func TestPostgresResourceSummaryStatesProjectionBound(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID, sourceID, runID := "resource-bound-"+suffix, "resource-source-"+suffix, "resource-run-"+suffix
	now := time.Now().UTC().Truncate(time.Microsecond)
	mustExec(t, pool, `INSERT INTO clusters(cluster_id,display_name,created_at) VALUES($1,'Bounded resource fixture',$2)`, clusterID, now)
	mustExec(t, pool, `INSERT INTO sources(source_id,cluster_id,kind,display_name,created_at) VALUES($1,$2,'prometheus','Fixture',$3)`, sourceID, clusterID, now)
	mustExec(t, pool, `INSERT INTO collection_runs(run_id,cluster_id,source_id,query_kind,idempotency_key,status,scheduled_for,started_at,completed_at,series_returned,bytes_read,coverage_complete) VALUES($1,$2,$3,'dcgm_gpu_utilization',$1,'SUCCEEDED',$4,$4,$4,20001,0,true)`, runID, clusterID, sourceID, now)
	mustExec(t, pool, `INSERT INTO observations(observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,observed_at,collected_at,source_reference,sample_fingerprint)
 SELECT $1||'-'||i,$1,$2,$3,1,'GAUGE',$2||'/GPU/node-1/GPU-'||i||'/','DCGM_FI_DEV_GPU_UTIL','[]'::jsonb,50,'percent',$4,$4,'synthetic',convert_to(i::text,'UTF8') FROM generate_series(1,20001) i`, runID, clusterID, sourceID, now)
	mustExec(t, pool, `INSERT INTO current_projections(cluster_id,source_id,entity_key,metric,observation_id,observed_at,last_success_at,updated_at)
 SELECT cluster_id,source_id,entity_key,metric,observation_id,observed_at,observed_at,observed_at FROM observations WHERE run_id=$1`, runID)
	store, err := adminview.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := adminview.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Snapshot(ctx, adminview.Query{ClusterID: clusterID, At: now, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	resources := snapshot.Clusters[0].Resources
	if !resources.Truncated || resources.State != adminview.StateDegraded || resources.ObservedGPUs != 20000 || resources.GPUUtilizationPercent != nil {
		t.Fatalf("bounded resource subset claimed complete usage: %+v", resources)
	}
}

func mustExec(t *testing.T, pool *pgxpool.Pool, query string, arguments ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), query, arguments...); err != nil {
		t.Fatal(err)
	}
}

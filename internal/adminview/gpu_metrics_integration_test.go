//go:build integration

package adminview_test

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adminview"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// This fixture seeds two clusters so the projection's cluster scoping is
// exercised, and deliberately leaves one reviewed operation without any run so
// the absent case can be distinguished from a zero value.
func TestPostgresStoreProjectsGPUFieldEvidenceWithoutInventingValues(t *testing.T) {
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
	clusterID := "gpu-metrics-cluster-" + suffix
	foreignClusterID := "gpu-metrics-foreign-" + suffix
	sourceID := "gpu-metrics-source-" + suffix
	secondSourceID := "gpu-metrics-source-" + suffix + "-b"
	foreignSourceID := "gpu-metrics-foreign-source-" + suffix
	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := make([]byte, 32)

	seedCluster := func(cluster, source string) {
		mustExec(t, pool, `INSERT INTO clusters (cluster_id,display_name,created_at) VALUES ($1,'GPU metrics cluster',$2)`, cluster, now)
		mustExec(t, pool, `INSERT INTO sources (source_id,cluster_id,kind,display_name,availability,created_at) VALUES ($1,$2,'prometheus','DCGM','AVAILABLE',$3)`, source, cluster, now)
	}
	seedCluster(clusterID, sourceID)
	seedCluster(foreignClusterID, foreignSourceID)
	// A second Prometheus source with no expected revision: the GPU table
	// follows one source, so this source's GPUs must be named, not omitted.
	mustExec(t, pool, `INSERT INTO sources (source_id,cluster_id,kind,display_name,availability,created_at) VALUES ($1,$2,'prometheus','DCGM B','AVAILABLE',$3)`,
		secondSourceID, clusterID, now)

	// Expected inventory revisions are scoped per cluster and source.
	seedRevision := func(cluster, source, revision string, entities [][3]string) {
		mustExec(t, pool, `INSERT INTO goodput_inventory_revisions (revision_id,cluster_id,source_id,inventory_class,schema_version,content_digest,source_at,effective_at,observed_at) VALUES ($1,$2,$3,'EXPECTED',1,$4,$5,$5,$5)`,
			revision, cluster, source, digest, now.Add(-time.Hour))
		for _, entity := range entities {
			mustExec(t, pool, `INSERT INTO goodput_inventory_revision_entities (cluster_id,revision_id,entity_kind,stable_node_id,physical_gpu_uuid,mig_identity) VALUES ($1,$2,$3,$4,$5,$6)`,
				cluster, revision, entity[0], entity[1], entity[2], map[string]string{"MIG": "mig-0"}[entity[0]])
		}
	}
	seedRevision(clusterID, sourceID, "revision-"+suffix, [][3]string{
		{"NODE", "node-1", ""},
		{"NODE", "node-missing", ""},
		{"GPU", "node-1", "GPU-aaa"},
		{"GPU", "node-1", "GPU-bbb"},
		{"GPU", "node-1", "GPU-ddd"},
		{"MIG", "node-1", "GPU-aaa"},
	})
	seedRevision(foreignClusterID, foreignSourceID, "foreign-revision-"+suffix, [][3]string{{"GPU", "foreign-node", "GPU-zzz"}})

	// Observed target cache: GPU-bbb is expected but never observed, GPU-ccc is
	// observed without appearing in the expected revision.
	for _, observed := range [][2]string{{"GPU", "GPU-aaa"}, {"GPU", "GPU-ccc"}, {"NODE", "node-1"}} {
		mustExec(t, pool, `INSERT INTO collection_target_inventory (cluster_id,source_id,target_kind,target_id,node_id,last_observed_at) VALUES ($1,$2,$3,$4,$5,$6)`,
			clusterID, sourceID, observed[0], observed[1], "node-1", now.Add(-20*time.Second))
	}
	// GPU-ddd is expected and present in the never-pruned target cache, but its
	// newest observation is three weeks old: presence is not coverage.
	mustExec(t, pool, `INSERT INTO collection_target_inventory (cluster_id,source_id,target_kind,target_id,node_id,last_observed_at) VALUES ($1,$2,'GPU','GPU-ddd','node-1',$3)`,
		clusterID, sourceID, now.Add(-21*24*time.Hour))
	mustExec(t, pool, `INSERT INTO collection_target_inventory (cluster_id,source_id,target_kind,target_id,node_id,last_observed_at) VALUES ($1,$2,'GPU','GPU-eee','node-2',$3)`,
		clusterID, secondSourceID, now)
	mustExec(t, pool, `INSERT INTO collection_target_inventory (cluster_id,source_id,target_kind,target_id,node_id,last_observed_at) VALUES ($1,$2,'GPU','GPU-zzz','foreign-node',$3)`,
		foreignClusterID, foreignSourceID, now)

	// A durable desired schedule enrols power and ECC; temperature stays
	// unenrolled and uncollected, which must project as NO_DATA, never zero.
	seedSchedule := func(operation string, interval int) {
		mustExec(t, pool, `INSERT INTO desired_schedules (cluster_id,source_id,operation,enabled,mode,interval_seconds,timeout_ms,jitter_ms,max_targets,max_bytes,priority) VALUES ($1,$2,$3,true,'durable',$4,5000,1000,100,1048576,50)`,
			clusterID, sourceID, operation, interval)
	}
	seedSchedule("prometheus.gpu_power.v1", 30)
	seedSchedule("prometheus.gpu_ecc.v1", 30)

	seedRun := func(cluster, source, runID, queryKind string, completed time.Time, fields any) {
		encoded, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		mustExec(t, pool, `INSERT INTO collection_runs (run_id,cluster_id,source_id,query_kind,idempotency_key,status,scheduled_for,started_at,completed_at,series_returned,bytes_read,coverage_complete,metric_fields) VALUES ($1,$2,$3,$4,$1,'PARTIAL',$5,$5,$5,2,200,false,$6::jsonb)`,
			runID, cluster, source, queryKind, completed, string(encoded))
	}
	type evidence struct {
		NodeID string `json:"node_id"`
		GPU    string `json:"gpu_uuid"`
		Metric string `json:"metric"`
		State  string `json:"state"`
		Reason string `json:"reason"`
	}
	seedRun(clusterID, sourceID, "power-run-"+suffix, "dcgm_gpu_power", now.Add(-20*time.Second), []evidence{
		{"node-1", "GPU-aaa", "DCGM_FI_DEV_POWER_USAGE", "SUPPORTED", "fresh_sample"},
		{"node-1", "GPU-aaa", "DCGM_FI_DEV_POWER_MGMT_LIMIT", "NOT_SUPPORTED", "dcgm_fp64_not_supported"},
		{"node-1", "GPU-bbb", "DCGM_FI_DEV_POWER_USAGE", "UNKNOWN", "missing_or_unavailable"},
		{"node-1", "GPU-bbb", "DCGM_FI_DEV_POWER_MGMT_LIMIT", "UNKNOWN", "missing_or_unavailable"},
	})
	seedRun(clusterID, sourceID, "ecc-run-"+suffix, "dcgm_gpu_ecc", now.Add(-20*time.Second), []evidence{
		{"node-1", "GPU-aaa", "DCGM_FI_DEV_ECC_SBE_VOL_TOTAL", "SUPPORTED", "fresh_sample"},
		{"node-1", "GPU-aaa", "DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", "SUPPORTED", "fresh_sample"},
		{"node-1", "GPU-aaa", "DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS", "SUPPORTED", "fresh_sample"},
		{"node-1", "GPU-aaa", "DCGM_FI_DEV_ROW_REMAP_FAILURE", "SUPPORTED", "fresh_sample"},
	})
	seedRun(foreignClusterID, foreignSourceID, "foreign-run-"+suffix, "dcgm_gpu_power", now, []evidence{
		{"foreign-node", "GPU-zzz", "DCGM_FI_DEV_POWER_USAGE", "SUPPORTED", "fresh_sample"},
	})

	seedObservation := func(cluster, source, runID, observationID, entityKey, metric, unit string, value float64, observedAt time.Time, semantics string) {
		mustExec(t, pool, `INSERT INTO observations (observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,observed_at,collected_at,source_reference,sample_fingerprint,metric_semantics) VALUES ($1,$2,$3,$4,1,'GAUGE',$5,$6,'{}'::jsonb,$7,$8,$9,$9,'prometheus:dcgm-fields-v1',$10,$11::jsonb)`,
			observationID, runID, cluster, source, entityKey, metric, value, unit, observedAt, []byte(observationID), semantics)
		mustExec(t, pool, `INSERT INTO current_projections (cluster_id,source_id,entity_key,metric,observation_id,observed_at,last_success_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$6,$6)`,
			cluster, source, entityKey, metric, observationID, observedAt)
	}
	entityKey := clusterID + "/GPU/node-1/GPU-aaa/"
	seedObservation(clusterID, sourceID, "power-run-"+suffix, "power-observation-"+suffix, entityKey,
		"DCGM_FI_DEV_POWER_USAGE", "watts", 210.5, now.Add(-20*time.Second), `{"kind":"gauge","reset":"not_applicable"}`)
	// A counter whose newest projection predates twice the enrolled interval
	// must project as STALE, not as its last absolute value.
	seedObservation(clusterID, sourceID, "ecc-run-"+suffix, "ecc-observation-"+suffix, entityKey,
		"DCGM_FI_DEV_ECC_SBE_VOL_TOTAL", "count", 0, now.Add(-time.Hour), `{"kind":"counter","reset":"driver_reload_or_explicit_clear;epoch_unknown","reset_observed":true}`)
	seedObservation(clusterID, sourceID, "ecc-run-"+suffix, "correctable-remap-observation-"+suffix, entityKey,
		"DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", "count", 0, now.Add(-20*time.Second), `{"kind":"counter","reset":"source_or_device_reset;epoch_unknown"}`)
	seedObservation(clusterID, sourceID, "ecc-run-"+suffix, "uncorrectable-remap-observation-"+suffix, entityKey,
		"DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS", "count", 0, now.Add(-20*time.Second), `{"kind":"counter","reset":"source_or_device_reset;epoch_unknown"}`)
	seedObservation(clusterID, sourceID, "ecc-run-"+suffix, "remap-failure-observation-"+suffix, entityKey,
		"DCGM_FI_DEV_ROW_REMAP_FAILURE", "boolean", 0, now.Add(-20*time.Second), `{"kind":"gauge","reset":"not_applicable"}`)
	// GPU-bbb carries a current projection but the newest run assessed the field
	// UNKNOWN for it. The newer assessment must win over the older number.
	seedObservation(clusterID, sourceID, "power-run-"+suffix, "stale-power-observation-"+suffix,
		clusterID+"/GPU/node-1/GPU-bbb/", "DCGM_FI_DEV_POWER_USAGE", "watts", 175, now.Add(-20*time.Second),
		`{"kind":"gauge","reset":"not_applicable"}`)
	seedObservation(foreignClusterID, foreignSourceID, "foreign-run-"+suffix, "foreign-observation-"+suffix,
		foreignClusterID+"/GPU/foreign-node/GPU-zzz/", "DCGM_FI_DEV_POWER_USAGE", "watts", 99, now, `{"kind":"gauge","reset":"not_applicable"}`)
	// A UUID-proven migration alias supplies the newer sample from the exact
	// same operation run. The GPU row remains one physical identity.
	seedObservation(clusterID, sourceID, "power-run-"+suffix, "legacy-power-"+suffix,
		"node/node-1/gpu/GPU-aaa", "DCGM_FI_DEV_POWER_USAGE", "watts", 210.5, now.Add(-10*time.Second), `{"kind":"gauge","reset":"not_applicable"}`)

	store, err := adminview.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := adminview.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.GPUMetrics(ctx, adminview.GPUMetricsQuery{ClusterID: clusterID, Now: now})
	if err != nil {
		t.Fatal(err)
	}

	if len(snapshot.Sources) != 2 || snapshot.Sources[0].SourceID != sourceID || !snapshot.Sources[0].Primary {
		t.Fatalf("sources = %+v", snapshot.Sources)
	}
	if len(snapshot.OtherSources) != 1 || snapshot.OtherSources[0].SourceID != secondSourceID ||
		snapshot.OtherSources[0].ObservedGPUs != 1 {
		t.Fatalf("a second source's GPUs must be stated, not omitted: %+v", snapshot.OtherSources)
	}
	operations := map[string]adminview.GPUMetricsOperation{}
	for _, operation := range snapshot.Sources[0].Operations {
		operations[operation.OperationID] = operation
	}
	power := operations["prometheus.gpu_power.v1"]
	if !power.Enrolled || !power.Enabled || power.IntervalSeconds != 30 || power.Revision != 1 || power.Freshness != adminview.GPUMetricsFresh {
		t.Fatalf("power operation = %+v", power)
	}
	if power.LastRun == nil || power.LastRun.Status != "PARTIAL" || power.LastRun.CoverageComplete {
		t.Fatalf("power run = %+v", power.LastRun)
	}
	summaries := map[string]adminview.GPUMetricsFieldSummary{}
	for _, summary := range power.FieldSummaries {
		summaries[summary.Field] = summary
	}
	// Two of three expected GPUs were assessed, so the third is UNKNOWN and the
	// summary carries its own denominator.
	if usage := summaries["DCGM_FI_DEV_POWER_USAGE"]; usage.Supported != 1 || usage.Unknown != 2 ||
		usage.Assessed != 2 || usage.Expected != 3 || usage.UnassessedExpected != 1 ||
		usage.Dominant != adminview.GPUMetricUnknown {
		t.Fatalf("power usage summary = %+v", usage)
	}
	if limit := summaries["DCGM_FI_DEV_POWER_MGMT_LIMIT"]; limit.NotSupported != 1 || limit.Supported != 0 {
		t.Fatalf("power limit summary = %+v", limit)
	}
	temperature := operations["prometheus.gpu_temperature.v1"]
	if temperature.Enrolled || temperature.LastRun != nil || temperature.Freshness != adminview.GPUMetricsNoData {
		t.Fatalf("unenrolled temperature operation = %+v", temperature)
	}

	rows := map[string]adminview.GPUMetricsRow{}
	for _, row := range snapshot.GPUs {
		if row.NodeID == "foreign-node" || row.GPUUUID == "GPU-zzz" || row.GPUUUID == "GPU-eee" {
			t.Fatalf("a foreign cluster or secondary source GPU leaked into the table: %+v", row)
		}
		key := row.GPUUUID
		if row.MIGIdentity != "" {
			key += "/" + row.MIGIdentity
		}
		rows[key] = row
	}
	if len(rows) != 5 {
		t.Fatalf("GPU rows = %+v", snapshot.GPUs)
	}
	mig := rows["GPU-aaa/mig-0"]
	if !mig.Expected || mig.Observed {
		t.Fatalf("MIG row = %+v", mig)
	}
	for field, value := range mig.Values {
		if value.State != adminview.GPUMetricAmbiguousMIG || value.Value != nil {
			t.Fatalf("a MIG entity must carry no physical field evidence: %s = %+v", field, value)
		}
	}
	observed := rows["GPU-aaa"]
	if !observed.Expected || !observed.Observed || observed.ObservedAt == nil ||
		observed.ObservedState != adminview.GPUMetricsObserved {
		t.Fatalf("GPU-aaa row = %+v", observed)
	}
	// GPU-ddd is in the never-pruned target cache with a three-week-old
	// observation: the row must say so instead of showing a healthy badge.
	if stale := rows["GPU-ddd"]; !stale.Expected || !stale.Observed ||
		stale.ObservedState != adminview.GPUMetricsObservedStale {
		t.Fatalf("a long-unobserved expected GPU must project OBSERVED_STALE: %+v", stale)
	}
	if usage := observed.Values["DCGM_FI_DEV_POWER_USAGE"]; usage.State != adminview.GPUMetricSupported || usage.Value == nil || *usage.Value != 210.5 || usage.Unit != "watts" {
		t.Fatalf("supported power value = %+v", usage)
	}
	if limit := observed.Values["DCGM_FI_DEV_POWER_MGMT_LIMIT"]; limit.State != adminview.GPUMetricNotSupported || limit.Value != nil {
		t.Fatalf("an unsupported field must not project a number: %+v", limit)
	}
	if ecc := observed.Values["DCGM_FI_DEV_ECC_SBE_VOL_TOTAL"]; ecc.State != adminview.GPUMetricStale || ecc.Value != nil {
		t.Fatalf("a stale counter must not project its last value: %+v", ecc)
	}
	if remapped := observed.Values["DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS"]; remapped.State != adminview.GPUMetricSupported || remapped.Value == nil || *remapped.Value != 0 || remapped.Unit != "count" {
		t.Fatalf("a supported zero remap count must remain visible: %+v", remapped)
	}
	if failure := observed.Values["DCGM_FI_DEV_ROW_REMAP_FAILURE"]; failure.State != adminview.GPUMetricSupported || failure.Value == nil || *failure.Value != 0 || failure.Unit != "boolean" {
		t.Fatalf("a supported false remap-failure value must remain visible: %+v", failure)
	}
	if temp := observed.Values["DCGM_FI_DEV_GPU_TEMP"]; temp.State != adminview.GPUMetricNoData || temp.Value != nil {
		t.Fatalf("an uncollected field must project NO_DATA: %+v", temp)
	}
	missing := rows["GPU-bbb"]
	if !missing.Expected || missing.Observed {
		t.Fatalf("GPU-bbb row = %+v", missing)
	}
	if usage := missing.Values["DCGM_FI_DEV_POWER_USAGE"]; usage.State != adminview.GPUMetricUnknown || usage.Value != nil {
		t.Fatalf("a newer UNKNOWN assessment must beat an older projection: %+v", usage)
	}
	extra := rows["GPU-ccc"]
	if extra.Expected || !extra.Observed {
		t.Fatalf("GPU-ccc row = %+v", extra)
	}

	inventory := snapshot.Inventory
	if !inventory.HasExpectedRevision || inventory.RevisionID != "revision-"+suffix || inventory.SourceID != sourceID {
		t.Fatalf("inventory revision = %+v", inventory)
	}
	if inventory.ExpectedGPUs != 3 || inventory.ExpectedNodes != 2 || inventory.MIGCount != 1 ||
		inventory.ObservedGPUs != 3 || inventory.ObservedNodes != 1 {
		t.Fatalf("inventory counts = %+v", inventory)
	}
	if inventory.CoverageComplete || inventory.CoveredGPUs != 1 ||
		inventory.FreshObservedGPUs != 2 || inventory.StaleObservedGPUs != 1 {
		t.Fatalf("only fresh observations may count as coverage: %+v", inventory)
	}
	missingRefs := map[string]adminview.GPUMetricsEntityRef{}
	for _, ref := range inventory.ExpectedNotObserved {
		missingRefs[ref.NodeID+"/"+ref.GPUUUID] = ref
	}
	if len(inventory.ExpectedNotObserved) != 3 {
		t.Fatalf("expected-not-observed = %+v", inventory.ExpectedNotObserved)
	}
	if _, ok := missingRefs["node-1/GPU-bbb"]; !ok {
		t.Fatalf("a never-observed expected GPU must be a gap: %+v", inventory.ExpectedNotObserved)
	}
	if _, ok := missingRefs["node-missing/"]; !ok {
		t.Fatalf("a never-observed expected node must be a gap: %+v", inventory.ExpectedNotObserved)
	}
	if ref, ok := missingRefs["node-1/GPU-ddd"]; !ok || !ref.Stale || ref.ObservedAt == nil {
		t.Fatalf("a stale expected GPU must be a gap marked stale: %+v", inventory.ExpectedNotObserved)
	}
	if len(inventory.ObservedNotExpected) != 1 || inventory.ObservedNotExpected[0].GPUUUID != "GPU-ccc" {
		t.Fatalf("observed-not-expected = %+v", inventory.ObservedNotExpected)
	}

	foreign, err := service.GPUMetrics(ctx, adminview.GPUMetricsQuery{ClusterID: foreignClusterID, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(foreign.GPUs) != 1 || foreign.GPUs[0].GPUUUID != "GPU-zzz" {
		t.Fatalf("foreign cluster projection = %+v", foreign.GPUs)
	}
	if observed.Values["DCGM_FI_DEV_POWER_USAGE"].ObservedAt == nil || !observed.Values["DCGM_FI_DEV_POWER_USAGE"].ObservedAt.Equal(now.Add(-10*time.Second)) {
		t.Fatal("newest UUID-proven legacy sample did not reconcile with canonical field row")
	}
	// After preserving the earlier GP-06a false-value assertions above, prove
	// a true row-remap failure reaches both actual persistence readers without
	// borrowing another source or manufacturing missing expected evidence.
	seedObservation(clusterID, sourceID, "ecc-run-"+suffix, "legacy-remap-failure-"+suffix,
		"node/node-1/gpu/GPU-aaa", "DCGM_FI_DEV_ROW_REMAP_FAILURE", "boolean", 1, now.Add(-5*time.Second), `{"kind":"gauge","reset":"not_applicable"}`)
	snapshot, err = service.GPUMetrics(ctx, adminview.GPUMetricsQuery{ClusterID: clusterID, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	public, err := storepg.NewPublicQueryStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	summariesGPU, more, err := public.ListGPUSummaries(ctx, domain.ClusterID(clusterID), application.GPUFilters{}, 100, 0, now, application.DefaultGPUHealthThresholds().FreshFor)
	if err != nil || more {
		t.Fatalf("public GPU read: more=%v err=%v", more, err)
	}
	publicByIdentity := map[string][]domain.HealthSignal{}
	for _, summary := range summariesGPU {
		publicByIdentity[string(summary.SourceID)+"\x00"+summary.EntityKey] = summary.Signals
	}
	critical, expectedUnknown := false, false
	for _, row := range snapshot.GPUs {
		if row.MIGIdentity != "" {
			if len(row.Conditions) != 0 {
				t.Fatal("MIG borrowed physical conditions")
			}
			continue
		}
		identity := clusterID + "/GPU/" + row.NodeID + "/" + row.GPUUUID + "/"
		conditions, found := publicByIdentity[row.SourceID+"\x00"+identity]
		// Cached GPU-ccc with no actual sample or authoritative expected entry
		// can legitimately have no condition projection; this remains unmeasured.
		if !found && row.Expected {
			t.Fatalf("expected GPU absent from public projection: %s", identity)
		}
		if !reflect.DeepEqual(row.Conditions, conditions) {
			t.Fatalf("API/page conditions differ for %s: private=%+v public=%+v", identity, row.Conditions, conditions)
		}
		for _, signal := range conditions {
			if row.GPUUUID == "GPU-aaa" && signal.Type == domain.HealthSignalECC && signal.Severity == domain.HealthSeverityCritical {
				critical = true
				if !reflect.DeepEqual(signal.Evidence, []domain.ObservationID{domain.ObservationID("legacy-remap-failure-" + suffix)}) {
					t.Fatalf("remap evidence lost: %+v", signal.Evidence)
				}
			}
			if row.GPUUUID == "GPU-bbb" && signal.Severity == domain.HealthSeverityUnknown {
				expectedUnknown = true
			}
		}
	}
	if !critical || !expectedUnknown {
		t.Fatalf("shared projection lost fault or expected gap: critical=%v unknown=%v", critical, expectedUnknown)
	}
	// Runtime policy, rather than a private-page default, governs conditions.
	// The same 90-second-old hot sensor is stale at 60s and critical at 120s.
	seedRun(clusterID, sourceID, "temperature-run-"+suffix, "dcgm_gpu_temperature", now.Add(-90*time.Second), []evidence{
		{"node-1", "GPU-aaa", "DCGM_FI_DEV_GPU_TEMP", "SUPPORTED", "fresh_sample"},
	})
	seedObservation(clusterID, sourceID, "temperature-run-"+suffix, "temperature-observation-"+suffix, entityKey,
		"DCGM_FI_DEV_GPU_TEMP", "celsius", 86, now.Add(-90*time.Second), `{"kind":"gauge","reset":"not_applicable"}`)
	for _, freshness := range []time.Duration{time.Minute, 2 * time.Minute} {
		configured, err := adminview.NewService(store, adminview.WithGPUHealthFreshness(freshness))
		if err != nil {
			t.Fatal(err)
		}
		privateSnapshot, err := configured.GPUMetrics(ctx, adminview.GPUMetricsQuery{ClusterID: clusterID, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		publicRows, _, err := public.ListGPUSummaries(ctx, domain.ClusterID(clusterID), application.GPUFilters{}, 100, 0, now, freshness)
		if err != nil {
			t.Fatal(err)
		}
		var privateConditions, publicConditions []domain.HealthSignal
		for _, row := range privateSnapshot.GPUs {
			if row.GPUUUID == "GPU-aaa" && row.MIGIdentity == "" {
				privateConditions = row.Conditions
			}
		}
		for _, row := range publicRows {
			if row.SourceID == domain.SourceID(sourceID) && row.EntityKey == entityKey {
				publicConditions = row.Signals
			}
		}
		if !reflect.DeepEqual(privateConditions, publicConditions) {
			t.Fatalf("configured API/page conditions differ at %s", freshness)
		}
		found := false
		for _, signal := range privateConditions {
			if signal.Category != domain.HealthSignalThermal || signal.Metric != "DCGM_FI_DEV_GPU_TEMP" {
				continue
			}
			if freshness == time.Minute && signal.Type == domain.HealthSignalStale {
				found = true
			}
			if freshness == 2*time.Minute && signal.Type == domain.HealthSignalThermal && signal.Severity == domain.HealthSeverityCritical {
				found = true
			}
		}
		if !found {
			t.Fatalf("90s sensor did not respect %s condition policy: %+v", freshness, privateConditions)
		}
	}
}

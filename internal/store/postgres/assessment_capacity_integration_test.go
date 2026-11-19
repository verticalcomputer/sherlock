//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/metrics"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
)

func TestAssessmentCapacityCountersAndClosedMutation(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	f.seedRun(t, at)
	for _, column := range []string{"payload_bytes", "record_count", "fact_count", "physical_count"} {
		if _, err := f.admin.Exec(ctx, `UPDATE assessment_runs SET `+column+`=0 WHERE run_id=$1`, f.config.RunID); err == nil && (column == "payload_bytes" || column == "record_count") {
			t.Fatalf("derived %s overwritten", column)
		}
		if _, err := f.admin.Exec(ctx, `UPDATE assessment_runs SET `+column+`=10 WHERE run_id=$1`, f.config.RunID); err == nil {
			t.Fatalf("derived %s overwritten", column)
		}
	}
	f.exec(t, `UPDATE assessment_runs SET state='DRAINING',stopped_at=admission_end_at,stop_reason='DURATION' WHERE run_id=$1`, f.config.RunID)
	if _, err := f.admin.Exec(ctx, `UPDATE assessment_runs SET stopped_at=clock_timestamp() WHERE run_id=$1`, f.config.RunID); err == nil {
		t.Fatal("stop time rewritten")
	}
	f.exec(t, `UPDATE assessment_runs SET state='CLOSED',closed_at=clock_timestamp() WHERE run_id=$1`, f.config.RunID)
	fact, _ := a.NewFact(f.config.Category, f.config.RunID, f.config.Assets[0].EntityKey, "COVERAGE", at, a.Coverage{Metric: "DCGM_FI_DEV_GPU_TEMP", From: at, Through: at, Code: "UNKNOWN", SourceRecord: "fixture"})
	body, _ := a.Canonical(fact)
	if _, err := f.admin.Exec(ctx, `INSERT INTO assessment_facts(run_id,id,asset,kind,available_at,body) VALUES($1,$2,$3,'COVERAGE',$4,$5)`, f.config.RunID, fact.ID, fact.Asset, at, body); err == nil {
		t.Fatal("closed evidence changed")
	}
	source, err := OpenAssessmentArchive(ctx, f.dsn, f.config.RunID)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close(ctx)
	var bytes, rows int64
	for {
		row, err := source.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		n, err := a.ArchiveRowPayloadBytes(row)
		if err != nil {
			t.Fatal(err)
		}
		bytes += n
		rows++
	}
	if source.Metadata().SourcePayloadBytes != bytes || source.Metadata().RecordCount != rows {
		t.Fatalf("accounting SQL=%+v computed rows=%d bytes=%d", source.Metadata(), rows, bytes)
	}
}
func TestAssessmentRetentionSnapshotSurvivesCleanup(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-8 * 24 * time.Hour)
	f.seedRun(t, at)
	expires := time.Now().UTC().Add(1500 * time.Millisecond)
	closed := expires.Add(-7 * 24 * time.Hour)
	f.exec(t, `UPDATE assessment_runs SET state='CLOSED',stopped_at=admission_end_at,stop_reason='DURATION',closed_at=$2 WHERE run_id=$1`, f.config.RunID, closed)
	source, err := OpenAssessmentArchive(ctx, f.dsn, f.config.RunID)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close(ctx)
	time.Sleep(time.Until(expires) + 10*time.Millisecond)
	s := &AssessmentStore{pool: f.admin}
	if n, err := s.Cleanup(ctx); err != nil || n != 1 {
		t.Fatalf("cleanup %d %v", n, err)
	}
	row, err := source.Next(ctx)
	if err != nil || row.Table != "run" {
		t.Fatalf("snapshot lost row: %v", err)
	}
	if _, err = source.Next(ctx); err != io.EOF {
		t.Fatalf("snapshot end: %v", err)
	}
}

const assessmentProfileFacts = 100000
const assessmentProfileGPUs = 8
const assessmentProfilePoints = 256

type assessmentProfileMetric struct {
	metric, operation, query, kind, unit string
	value                                float64
}

var assessmentProfileMetrics = []assessmentProfileMetric{
	{cooling.Temperature, string(domain.OperationPrometheusGPUTemperature), string(domain.QueryGPUTemperature), "gpu_temperature", "celsius", 72},
	{cooling.Utilization, string(domain.OperationPrometheusGPUUtilization), string(domain.QueryGPUUtilization), "gpu_metric", "percent", 45},
	{cooling.Power, string(domain.OperationPrometheusGPUPower), string(domain.QueryGPUPower), "gpu_power", "watts", 200},
}

func prepareAssessmentProfile(t *testing.T, f *assessmentFixture, at time.Time) {
	t.Helper()
	c := &f.config
	c.Assets, c.Bindings = []a.Asset{}, []a.Binding{}
	c.Limits = a.Limits{GPUCount: 8, NodeCount: 2, PhysicalCandidates: 256, FactCount: 200000, PayloadBytes: 512 << 20}
	c.RunDurationSeconds = 86400
	for i := range assessmentProfileGPUs {
		node, gpu := fmt.Sprintf("fixture-node-%d", i/4), fmt.Sprintf("GPU-%012d", i+1)
		c.Assets = append(c.Assets, a.Asset{EntityKey: c.ClusterID + "/GPU/" + node + "/" + gpu + "/", NodeID: node, GPUUUID: gpu})
	}
	for _, m := range assessmentProfileMetrics {
		c.Bindings = append(c.Bindings, a.Binding{Metric: m.metric, Operation: m.operation, ScheduleRevision: 1, ScopeNodes: []string{}})
	}
	sort.Slice(c.Bindings, func(i, j int) bool { return c.Bindings[i].Metric < c.Bindings[j].Metric })
	f.exec(t, `INSERT INTO clusters(cluster_id,display_name) VALUES($1,'Synthetic assessment maximum profile')`, c.ClusterID)
	f.exec(t, `INSERT INTO sources(source_id,cluster_id,kind,display_name,availability) VALUES($1,$2,'prometheus','Synthetic assessment maximum profile','UNKNOWN')`, c.SourceID, c.ClusterID)
	old := at.Add(-24 * time.Hour)
	f.exec(t, `INSERT INTO goodput_inventory_revisions(revision_id,cluster_id,source_id,inventory_class,schema_version,content_digest,source_at,effective_at,observed_at) VALUES($1,$2,$3,'EXPECTED',1,decode(repeat('ab',32),'hex'),$4,$4,$4)`, c.InventoryRevision, c.ClusterID, c.SourceID, old)
	f.exec(t, `INSERT INTO goodput_inventory_revision_validity(cluster_id,revision_id,valid_from) VALUES($1,$2,$3)`, c.ClusterID, c.InventoryRevision, old)
	for _, asset := range c.Assets {
		f.exec(t, `INSERT INTO goodput_inventory_revision_entities(cluster_id,revision_id,entity_kind,stable_node_id,physical_gpu_uuid) VALUES($1,$2,'GPU',$3,$4)`, c.ClusterID, c.InventoryRevision, asset.NodeID, asset.GPUUUID)
	}
	for mi, m := range assessmentProfileMetrics {
		job := fmt.Sprintf("profile-job-%d", mi)
		f.exec(t, `INSERT INTO collection_jobs(job_id,cluster_id,source_id,query_kind,interval_seconds,next_run_at) VALUES($1,$2,$3,$4,15,clock_timestamp())`, job, c.ClusterID, c.SourceID, m.query)
		f.exec(t, `INSERT INTO desired_schedules(cluster_id,source_id,operation,enabled,mode,interval_seconds,timeout_ms,jitter_ms,max_targets,max_bytes,priority,legacy_query_kind,legacy_job_id) VALUES($1,$2,$3,true,'legacy',15,5000,0,1000,1048576,50,$4,$5)`, c.ClusterID, c.SourceID, m.operation, m.query, job)
	}
}

func seedAssessmentProfileHistory(t *testing.T, ctx context.Context, f *assessmentFixture, start time.Time) {
	t.Helper()
	c := f.config
	body, err := a.Canonical(c)
	if err != nil {
		t.Fatal(err)
	}
	_, desc, descriptorHash, err := f.registry.LookupVersion(c.Category, c.Implementation)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := a.Canonical(desc)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := c.Hash()
	if err != nil {
		t.Fatal(err)
	}
	end := start.Add(time.Duration(c.RunDurationSeconds) * time.Second)
	f.exec(t, `INSERT INTO assessment_runs(run_id,config,config_hash,descriptor,descriptor_hash,build_hash,mode,state,start_at,admission_end_at) VALUES($1,$2,$3,$4,$5,$5,'shadow','ACTIVE',$6,$7)`, c.RunID, body, hash, descriptor, descriptorHash, start, end)
	bindings, err := a.Canonical(c.Bindings)
	if err != nil {
		t.Fatal(err)
	}
	for _, asset := range c.Assets {
		f.exec(t, `INSERT INTO assessment_enrollments(run_id,category,asset,node_id,gpu_uuid,inventory_revision,bindings,discovery_floor,next_due_at,sequence,revision,rearm_eligible) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,0,1,true)`, c.RunID, c.Category, asset.EntityKey, asset.NodeID, asset.GPUUUID, c.InventoryRevision, bindings, start)
	}
	// Synthetic retained rows use normal INSERT triggers and capacity counters.
	// The rolling source observations are seeded separately after this history.
	const chunk = 512
	for base := 0; base < assessmentProfileFacts; base += chunk {
		n := min(chunk, assessmentProfileFacts-base)
		rows, err := f.admin.CopyFrom(ctx, pgx.Identifier{"public", "assessment_facts"}, []string{"run_id", "id", "asset", "kind", "available_at", "body"}, pgx.CopyFromSlice(n, func(i int) ([]any, error) {
			id := base + i
			asset := c.Assets[id%len(c.Assets)]
			m := assessmentProfileMetrics[id/len(c.Assets)%len(assessmentProfileMetrics)]
			at := start.Add(time.Duration(id/(len(c.Assets)*len(assessmentProfileMetrics))) * 19 * time.Second)
			ref := fmt.Sprintf("synthetic-retained-%06d", id)
			f, err := a.NewFact(c.Category, c.RunID, asset.EntityKey, "SAMPLE", at, a.Sample{Metric: m.metric, Unit: m.unit, SourceAt: at, CollectedAt: at, CompletedAt: at, Value: m.value, SourceRecord: ref,
				Provenance: a.Provenance{Mode: "fixture", CollectionRunID: ref, Operation: m.operation, ScheduleRevision: 1, InventoryRevision: c.InventoryRevision, SourceRecord: ref}})
			if err != nil {
				return nil, err
			}
			body, err := a.Canonical(f)
			return []any{c.RunID, f.ID, f.Asset, f.Kind, f.AvailableAt, body}, err
		}))
		if err != nil || rows != int64(n) {
			t.Fatalf("retained fixture facts [%d,%d): %d, %v", base, base+n, rows, err)
		}
	}
	var facts int64
	if err := f.admin.QueryRow(ctx, `SELECT fact_count FROM assessment_runs WHERE run_id=$1`, c.RunID).Scan(&facts); err != nil || facts != assessmentProfileFacts {
		t.Fatalf("fixture fact count = %d, %v", facts, err)
	}
}

func seedAssessmentProfileSource(t *testing.T, ctx context.Context, f *assessmentFixture, at time.Time) {
	t.Helper()
	c := f.config
	for mi, m := range assessmentProfileMetrics {
		fields := make([]domain.DCGMFieldEvidence, 0, len(c.Assets))
		for _, a := range c.Assets {
			fields = append(fields, domain.DCGMFieldEvidence{NodeID: domain.StableNodeID(a.NodeID), GPU: domain.PhysicalGPUUUID(a.GPUUUID), Metric: m.metric, State: "SUPPORTED"})
		}
		fieldBody, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		job := fmt.Sprintf("profile-job-%d", mi)
		var revision int64
		if err := f.admin.QueryRow(ctx, `SELECT configuration_revision FROM collection_jobs WHERE job_id=$1`, job).Scan(&revision); err != nil {
			t.Fatal(err)
		}
		batch := &pgx.Batch{}
		for i := range assessmentProfilePoints {
			stamp := at.Add(time.Duration(i+1-assessmentProfilePoints) * 2 * time.Second)
			run := fmt.Sprintf("profile-source-%d-%03d", mi, i)
			batch.Queue(`INSERT INTO collection_runs(run_id,job_id,cluster_id,source_id,query_kind,idempotency_key,status,scheduled_for,started_at,completed_at,series_returned,bytes_read,coverage_complete,metric_fields) VALUES($1,$2,$3,$4,$5,$1,'SUCCEEDED',$6,$6,$6,$7,100,true,$8)`, run, job, c.ClusterID, c.SourceID, m.query, stamp, len(c.Assets), fieldBody)
			batch.Queue(`INSERT INTO collection_run_jobs(run_id,job_id,cluster_id,source_id,query_kind,node_filter,scheduled_for,configuration_revision,lease_generation) VALUES($1,$2,$3,$4,$5,'',$6,$7,1)`, run, job, c.ClusterID, c.SourceID, m.query, stamp, revision)
			var value = m.value
			if m.metric == cooling.Temperature && i >= assessmentProfilePoints-17 {
				value = 75
			}
			for ai, a := range c.Assets {
				id := fmt.Sprintf("%s-%d", run, ai)
				batch.Queue(`INSERT INTO observations(observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,observed_at,collected_at,source_reference,sample_fingerprint) VALUES($1,$2,$3,$4,1,$5,$6,$7,'[]'::jsonb,$8,$9,$10,$10,'synthetic-assessment-profile',$11)`, id, run, c.ClusterID, c.SourceID, m.kind, a.EntityKey, m.metric, value, m.unit, stamp, []byte(id))
			}
		}
		r := f.admin.SendBatch(ctx, batch)
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func assessmentProfileInput(t *testing.T, ctx context.Context, f *assessmentFixture, store *AssessmentStore) (int, int) {
	t.Helper()
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	var at time.Time
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	var all []a.Fact
	for _, asset := range f.config.Assets {
		facts, err := loadAssessmentInput(ctx, tx, f.config, asset, at.UTC())
		if err != nil {
			t.Fatal(err)
		}
		counts := make(map[string]int)
		for _, fact := range facts {
			var sample a.Sample
			if fact.Kind != "SAMPLE" {
				t.Fatalf("unexpected maximum-profile input fact kind %s", fact.Kind)
			}
			if err := json.Unmarshal(fact.Body, &sample); err != nil {
				t.Fatal(err)
			}
			counts[sample.Metric]++
		}
		for _, m := range assessmentProfileMetrics {
			if counts[m.metric] != assessmentProfilePoints {
				t.Fatalf("asset %s metric %s input points = %d", asset.EntityKey, m.metric, counts[m.metric])
			}
		}
		all = append(all, facts...)
	}
	body, err := a.Canonical(all)
	if err != nil {
		t.Fatal(err)
	}
	return len(all), len(body)
}

// Test instrumentation leaves the cooling descriptor, policy and results intact.
// A GPU callback group is the set of invocations sharing the host's deadline.
// Its wall time includes the host work before/between callbacks, and excludes
// whatever host work occurs after the last callback. The full host distribution
// below also includes attempted groups that never reach a callback.
type assessmentProfileCategory struct {
	cooling.Category
	mu        sync.Mutex
	groups    map[time.Time]time.Duration
	assets    map[string]bool
	phases    map[string][]time.Duration
	succeeded map[string]int
	failed    int
}

func (c *assessmentProfileCategory) observe(ctx context.Context, req a.Request, phase string, started time.Time, ok bool) {
	due, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		return
	}
	elapsed := time.Since(due.Add(-50 * time.Millisecond))
	c.mu.Lock()
	defer c.mu.Unlock()
	c.groups[due] = max(c.groups[due], elapsed)
	c.assets[req.Asset] = true
	key := req.Purpose + "/" + phase
	if ok && ctx.Err() == nil {
		c.succeeded[key]++
	} else {
		c.failed++
	}
	if c.phases != nil {
		c.phases[key] = append(c.phases[key], time.Since(started))
	}
}
func (c *assessmentProfileCategory) Evaluate(ctx context.Context, r a.Request) (result a.Result, err error) {
	started := time.Now()
	defer func() { c.observe(ctx, r, "evaluate", started, err == nil) }()
	return c.Category.Evaluate(ctx, r)
}
func (c *assessmentProfileCategory) ValidateResult(ctx context.Context, r a.Request, x a.Result) (err error) {
	started := time.Now()
	defer func() { c.observe(ctx, r, "validate", started, err == nil) }()
	return c.Category.ValidateResult(ctx, r, x)
}

type assessmentQueryTraceKey struct{}
type assessmentQuerySpan struct {
	stage   string
	started time.Time
}
type assessmentQueryTrace struct {
	mu       sync.Mutex
	byStage  map[string][]time.Duration
	failures map[string]int
}

func (p *assessmentQueryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	stage := "other"
	switch {
	case q.SQL == assessmentRetainedLookbackSQL:
		stage = "retained_lookback"
	case q.SQL == assessmentAttemptSQL:
		stage = "source_attempts"
	case q.SQL == assessmentObservationSQL:
		stage = "source_observations"
	case strings.HasPrefix(q.SQL, "INSERT INTO assessment_facts"):
		stage = "insert_facts"
	case strings.HasPrefix(q.SQL, "INSERT INTO assessment_bundles"):
		stage = "insert_bundles"
	case strings.HasPrefix(q.SQL, "SELECT incoming.id,f.body FROM unnest"):
		stage = "prefetch_admissions"
	case q.SQL == "SELECT body FROM assessment_facts WHERE run_id=$1 AND id=$2":
		stage = "lookup_fact"
	case q.SQL == "SELECT body FROM assessment_bundles WHERE run_id=$1 AND id=$2":
		stage = "lookup_bundle"
	case q.SQL == "commit":
		stage = "commit"
	}
	return context.WithValue(ctx, assessmentQueryTraceKey{}, assessmentQuerySpan{stage: stage, started: time.Now()})
}

func (p *assessmentQueryTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryEndData) {
	span := ctx.Value(assessmentQueryTraceKey{}).(assessmentQuerySpan)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.byStage[span.stage] = append(p.byStage[span.stage], time.Since(span.started))
	if q.Err != nil {
		p.failures[span.stage]++
	}
}

func profilePercentile(d []time.Duration, percentile int) time.Duration {
	if len(d) == 0 {
		return 0
	}
	return d[(len(d)*percentile+99)/100-1]
}

func assessmentProfileDistribution(t *testing.T, name string, times []time.Duration) time.Duration {
	t.Helper()
	if len(times) == 0 {
		t.Logf("ASSESSMENT_PROFILE lane=%s n=0 distribution_unavailable=true", name)
		return 0
	}
	times = slices.Clone(times)
	slices.Sort(times)
	p99 := profilePercentile(times, 99)
	t.Logf("ASSESSMENT_PROFILE lane=%s n=%d p50=%s p95=%s p99=%s max=%s", name, len(times), profilePercentile(times, 50), profilePercentile(times, 95), p99, profilePercentile(times, 100))
	return p99
}

func assessmentHeapBytes() uint64 {
	samples := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(samples)
	return samples[0].Value.Uint64()
}

func TestAssessmentMaximumProfileContention(t *testing.T) {
	if os.Getenv("SHERLOCK_ENABLE_ASSESSMENT_PERF") != "1" {
		t.Skip("set SHERLOCK_ENABLE_ASSESSMENT_PERF=1 for the disposable maximum-profile qualification")
	}
	runAssessmentMaximumProfile(t, 100)
}

func TestAssessmentMaximumProfileDiagnostic(t *testing.T) {
	if os.Getenv("SHERLOCK_ENABLE_ASSESSMENT_DIAGNOSTIC") != "1" {
		t.Skip("set SHERLOCK_ENABLE_ASSESSMENT_DIAGNOSTIC=1 for the short disposable profile")
	}
	t.Log("ASSESSMENT_PROFILE diagnostic: eight pairs, no contention qualification")
	runAssessmentMaximumProfile(t, 8)
}

func runAssessmentMaximumProfile(t *testing.T, trials int) {
	t.Helper()
	f := newAssessmentFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	var now time.Time
	var dbVersion string
	if err := f.admin.QueryRow(ctx, `SELECT clock_timestamp(),current_setting('server_version')`).Scan(&now, &dbVersion); err != nil {
		t.Fatal(err)
	}
	now = now.UTC().Truncate(time.Microsecond)
	t.Logf("ASSESSMENT_PROFILE environment=%s/%s go=%s cpus=%d gomaxprocs=%d database=%s", runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU(), runtime.GOMAXPROCS(0), dbVersion)
	prepareAssessmentProfile(t, f, now)
	seedAssessmentProfileHistory(t, ctx, f, now.Add(-23*time.Hour-30*time.Minute))
	category := &assessmentProfileCategory{groups: make(map[time.Time]time.Duration), assets: make(map[string]bool), succeeded: make(map[string]int)}
	registry, err := a.NewRegistry(category)
	if err != nil {
		t.Fatal(err)
	}
	pool := f.restrictedPool(t)
	var trace *assessmentQueryTrace
	if trials < 100 {
		category.phases = make(map[string][]time.Duration)
		trace = &assessmentQueryTrace{byStage: make(map[string][]time.Duration), failures: make(map[string]int)}
		connection := pool.Config()
		connection.ConnConfig.Tracer = trace
		pool, err = pgxpool.NewWithConfig(ctx, connection)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
	}
	store, err := NewAssessmentStore(ctx, pool, registry, f.config, "synthetic-maximum-profile")
	if err != nil {
		t.Fatal(err)
	}
	var gpuFullTimes []time.Duration
	store.observeGPU = func(_ string, elapsed time.Duration) {
		gpuFullTimes = append(gpuFullTimes, elapsed)
	}
	if err := store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	monitor := NewMonitoringStore(f.admin)
	for i, asset := range f.config.Assets {
		p := monitoring.Policy{ID: fmt.Sprintf("assessment-profile-monitor-%02d", i), ClusterID: domain.ClusterID(f.config.ClusterID), SourceID: domain.SourceID(f.config.SourceID), EntityKey: asset.EntityKey, Rule: monitoring.RuleGPUThermal, RuleVersion: 1, Metric: cooling.Temperature, Unit: "celsius", Binding: monitoring.Binding{Operation: domain.OperationPrometheusGPUTemperature, Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{}}, ScheduleRevision: 1, InventoryRevisionID: f.config.InventoryRevision},
			FreshForSeconds: 900, ConfirmCount: 2, ConfirmWindowSeconds: 60, RecoverCount: 2, RecoverWindowSeconds: 60, MaxSampleGapSeconds: 30, OpenThreshold: 95, RecoverBelow: 90, Severity: domain.HealthSeverityWarning}
		if _, err := monitor.Enroll(ctx, p, 0, "synthetic-profile"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.admin.QueryRow(ctx, `SELECT clock_timestamp()-interval '2 seconds'`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	seedAssessmentProfileSource(t, ctx, f, now.UTC())
	sourceStarted := time.Now()
	points, bytes := assessmentProfileInput(t, ctx, f, store)
	sourceElapsed := time.Since(sourceStarted)
	if trials < 100 {
		tx, err := beginAssessmentTx(ctx, store.pool)
		if err != nil {
			t.Fatal(err)
		}
		loadStarted := time.Now()
		_, _, err = store.loadEngine(ctx, tx, time.Now().UTC())
		rollbackMonitoringTx(tx)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("ASSESSMENT_PROFILE diagnostic source_all_eight=%s retained_snapshot=%s", sourceElapsed, time.Since(loadStarted))
	}
	t.Logf("ASSESSMENT_PROFILE fixture retained_facts=%d source_points=%d source_bytes=%d gpus=%d nodes=%d configured_hours=24", assessmentProfileFacts, points, bytes, len(f.config.Assets), 2)
	if points != 8*3*256 || bytes > a.MaxInputBytes {
		t.Fatalf("maximum profile input points=%d bytes=%d", points, bytes)
	}
	monitorRefresh := func() (time.Duration, error) {
		start := time.Now()
		err := monitor.Refresh(ctx)
		return time.Since(start), err
	}
	resetMonitoring := func() {
		f.exec(t, `UPDATE gp09_monitor_enrollments SET next_due_at=clock_timestamp(),last_attempt_at=NULL,last_failure_code='',evaluator_state=jsonb_build_object('version',1,'policy_id',policy_id,'enrollment_revision',enrollment_revision),state_evidence='[]'::jsonb,history_coverage='{}'::jsonb`)
	}
	checkMonitoring := func() {
		var count int
		if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM gp09_monitor_enrollments WHERE last_attempt_at IS NOT NULL AND last_failure_code=''`).Scan(&count); err != nil || count != assessmentProfileGPUs {
			t.Fatalf("monitor refresh completed %d of %d policies: %v", count, assessmentProfileGPUs, err)
		}
	}
	for range 3 {
		resetMonitoring()
		if _, err := monitorRefresh(); err != nil {
			t.Fatal(err)
		}
		checkMonitoring()
	}
	baseline, treatment, passes := make([]time.Duration, 0, trials), make([]time.Duration, 0, trials), make([]time.Duration, 0, trials)
	runtime.GC()
	heapBefore := assessmentHeapBytes()
	maxHeap := heapBefore
	var memoryWG sync.WaitGroup
	memoryCtx, stopMemory := context.WithCancel(ctx)
	defer stopMemory()
	memoryWG.Go(func() {
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-memoryCtx.Done():
				return
			case <-tick.C:
				maxHeap = max(maxHeap, assessmentHeapBytes())
			}
		}
	})
	passErrors := make(map[string]int)
	monitorErrors := 0
	type refreshResult struct {
		duration time.Duration
		err      error
	}
	// The host runs at most once per second, serially, on its dedicated pool.
	// Reset the same production-monitor fixture before each paired measurement.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range trials {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		resetMonitoring()
		isolated, err := monitorRefresh()
		if err != nil {
			t.Fatal(err)
		}
		baseline = append(baseline, isolated)
		checkMonitoring()
		resetMonitoring()
		done := make(chan refreshResult, 1)
		go func() { start := time.Now(); err := store.Refresh(ctx); done <- refreshResult{time.Since(start), err} }()
		elapsed, monitorErr := monitorRefresh()
		measured := <-done
		treatment = append(treatment, elapsed)
		passes = append(passes, measured.duration)
		if measured.err != nil {
			passErrors[measured.err.Error()]++
		}
		if monitorErr != nil {
			monitorErrors++
		} else {
			checkMonitoring()
		}
	}
	var tail []time.Duration
	if trials >= 100 {
		// Keep the 100 paired measurements distinct from the 120-second arm's
		// final expiry. Continue the same serial scheduler until that cutoff.
		var finalDue *time.Time
		if err := f.admin.QueryRow(ctx, `SELECT max(due_at) FROM assessment_candidates WHERE run_id=$1 AND phase='OBSERVING'`, f.config.RunID).Scan(&finalDue); err != nil {
			t.Fatal(err)
		}
		if finalDue != nil {
			stop := finalDue.Add(2 * time.Second)
			for time.Now().Before(stop) {
				select {
				case <-ticker.C:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				started := time.Now()
				err := store.Refresh(ctx)
				tail = append(tail, time.Since(started))
				if err != nil {
					passErrors[err.Error()]++
				}
				var pending bool
				if err := f.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM assessment_candidates WHERE run_id=$1 AND phase='OBSERVING')`, f.config.RunID).Scan(&pending); err != nil {
					t.Fatal(err)
				}
				if !pending {
					break
				}
			}
		}
	}
	stopMemory()
	memoryWG.Wait()
	runtime.GC()
	heapAfter := assessmentHeapBytes()
	baseP99 := assessmentProfileDistribution(t, "monitoring_baseline", baseline)
	activeP99 := assessmentProfileDistribution(t, "monitoring_treatment", treatment)
	passP99 := assessmentProfileDistribution(t, "assessment_refresh", passes)
	if len(tail) != 0 {
		assessmentProfileDistribution(t, "assessment_expiry_tail", tail)
	}
	gpuTimes := make([]time.Duration, 0, len(category.groups))
	for _, d := range category.groups {
		gpuTimes = append(gpuTimes, d)
	}
	assessmentProfileDistribution(t, "gpu_through_last_callback", gpuTimes)
	// The p99 gate uses the host samples, including failed preparation and due
	// fallback groups that do not enter a category callback.
	gpuP99 := assessmentProfileDistribution(t, "gpu_full_host", gpuFullTimes)
	if trace != nil {
		for stage, values := range trace.byStage {
			assessmentProfileDistribution(t, "sql/"+stage, values)
		}
		for phase, values := range category.phases {
			assessmentProfileDistribution(t, "callback/"+phase, values)
		}
		t.Logf("ASSESSMENT_PROFILE diagnostic SQL query failures=%v", trace.failures)
	}
	var gpuFailures int
	var facts int64
	if err := f.admin.QueryRow(ctx, `SELECT fact_count,(SELECT coalesce(sum(count),0) FROM assessment_failures WHERE run_id=$1 AND code='TIME_BUDGET') FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&facts, &gpuFailures); err != nil {
		t.Fatal(err)
	}
	var physical, observing, overdue, terminals, invalidRefs, monitoringTransitions int
	if err := f.admin.QueryRow(ctx, `SELECT (SELECT physical_count FROM assessment_runs WHERE run_id=$1),(SELECT count(*) FROM assessment_candidates WHERE phase='OBSERVING'),(SELECT count(*) FROM assessment_candidates WHERE phase='OBSERVING' AND due_at<=clock_timestamp()),(SELECT count(*) FROM assessment_decisions WHERE kind='TERMINAL'),(SELECT count(*) FROM assessment_decisions d LEFT JOIN assessment_bundles b ON b.run_id=d.run_id AND b.id=d.bundle_id WHERE b.id IS NULL),(SELECT count(*) FROM gp09_monitor_transitions)`, f.config.RunID).Scan(&physical, &observing, &overdue, &terminals, &invalidRefs, &monitoringTransitions); err != nil {
		t.Fatal(err)
	}
	var breaches []int64
	if err := f.admin.QueryRow(ctx, `SELECT coalesce(array_agg(lateness_us ORDER BY lateness_us),'{}') FROM assessment_decisions WHERE kind='TERMINAL' AND lateness_us>0`).Scan(&breaches); err != nil {
		t.Fatal(err)
	}
	extra := max(int64(0), int64(heapAfter)-int64(heapBefore))
	t.Logf("ASSESSMENT_PROFILE callback_success=%v callback_failures=%d physical_candidates=%d terminal_decisions=%d", category.succeeded, category.failed, physical, terminals)
	t.Logf("ASSESSMENT_PROFILE facts_after=%d gpu_assets=%d gpu_budget_failures=%d refresh_errors=%v monitoring_errors=%d heap_before=%d heap_peak_sampled=%d heap_after_gc=%d heap_extra=%d observing=%d overdue=%d deadline_breaches_us=%v missing_decision_bundle=%d production_transitions=%d monitor_p99_delta=%s", facts, len(category.assets), gpuFailures, passErrors, monitorErrors, heapBefore, maxHeap, heapAfter, extra, observing, overdue, breaches, invalidRefs, monitoringTransitions, activeP99-baseP99)
	if trials >= 100 && (baseP99 == 0 || activeP99-baseP99 > baseP99/10 || activeP99-baseP99 > 100*time.Millisecond) {
		t.Errorf("monitor p99 exceeded the 10%% and 100ms contention thresholds")
	}
	if len(passErrors) > 0 || monitorErrors > 0 || len(category.assets) != assessmentProfileGPUs || physical != assessmentProfileGPUs || gpuFailures > 0 || category.failed > 0 || len(gpuFullTimes) == 0 || gpuP99 > a.ShadowGPUBudget || passP99 > a.ShadowRefreshBudget {
		t.Errorf("maximum-profile assessment did not complete within the aggregate GPU/pass budgets")
	}
	if extra > 64<<20 || invalidRefs != 0 || monitoringTransitions != 0 || overdue != 0 || trials >= 100 && (observing != 0 || terminals != assessmentProfileGPUs*len(a.Budgets)) {
		t.Errorf("retained memory or integrity failed the maximum-profile qualification")
	}
}

func TestAssessmentCapacityRejectsWholeBatchAtConfiguredBound(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second)
	f.config.Limits.FactCount = 2
	f.seedRun(t, at)
	batch := func(n int) error {
		tx, err := f.admin.Begin(ctx)
		if err != nil {
			return err
		}
		defer rollbackMonitoringTx(tx)
		for i := range n {
			fact, err := a.NewFact(f.config.Category, f.config.RunID, f.config.Assets[0].EntityKey, "COVERAGE", at, a.Coverage{Metric: cooling.Temperature, From: at, Through: at, Code: "UNKNOWN", SourceRecord: fmt.Sprintf("fixture-limit-%d", i)})
			if err != nil {
				return err
			}
			body, err := a.Canonical(fact)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO assessment_facts(run_id,id,asset,kind,available_at,body) VALUES($1,$2,$3,'COVERAGE',$4,$5)`, fact.Run, fact.ID, fact.Asset, at, body); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	}
	assertCount := func(want int) {
		t.Helper()
		var actual, count int
		if err := f.admin.QueryRow(ctx, `SELECT fact_count,(SELECT count(*) FROM assessment_facts WHERE run_id=$1) FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&count, &actual); err != nil || actual != want || count != want {
			t.Fatalf("fact rows=%d counter=%d want=%d: %v", actual, count, want, err)
		}
	}
	if err := batch(3); err == nil || !strings.Contains(err.Error(), "assessment capacity exceeded") {
		t.Fatalf("configured fact bound failure = %v", err)
	}
	assertCount(0)
	if err := batch(2); err != nil {
		t.Fatal(err)
	}
	assertCount(2)
}

func TestAssessmentBatchedSourcePinsHistoricalInventory(t *testing.T) {
	f := newAssessmentFixture(t)
	f.seedSource(t, false)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	cutover := at.Add(-5 * time.Minute)
	asset := f.config.Assets[0]
	f.config.InventoryRevision = "fixture-revised"
	f.exec(t, `INSERT INTO goodput_inventory_revisions(revision_id,cluster_id,source_id,inventory_class,schema_version,content_digest,source_at,effective_at,observed_at) VALUES($1,$2,$3,'EXPECTED',1,decode(repeat('ac',32),'hex'),$4,$4,$4)`, f.config.InventoryRevision, f.config.ClusterID, f.config.SourceID, cutover)
	f.exec(t, `INSERT INTO goodput_inventory_revision_entities(cluster_id,revision_id,entity_kind,stable_node_id,physical_gpu_uuid) VALUES($1,$2,'GPU',$3,$4)`, f.config.ClusterID, f.config.InventoryRevision, asset.NodeID, asset.GPUUUID)
	f.exec(t, `UPDATE observations SET unit='C' WHERE observation_id='assessment-observation-0-900'`)
	f.exec(t, `UPDATE observations SET metric_semantics='{"kind":"counter"}' WHERE observation_id='assessment-observation-0-885'`)
	tx, err := beginAssessmentTx(ctx, f.restrictedPool(t))
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	facts, err := loadAssessmentInput(ctx, tx, f.config, asset, at)
	if err != nil {
		t.Fatal(err)
	}
	var recent, early, normalized int
	for _, f := range facts {
		switch f.Kind {
		case "SAMPLE":
			var s a.Sample
			if err := json.Unmarshal(f.Body, &s); err != nil {
				t.Fatal(err)
			}
			if s.SourceAt.Before(cutover) || s.Provenance.InventoryRevision != "fixture-revised" || s.SourceRecord == "assessment-observation-0-885" {
				t.Fatalf("admitted source with incompatible historical inventory or semantics: %+v", s)
			}
			if s.SourceRecord == "assessment-observation-0-900" && s.Unit == "celsius" {
				normalized++
			}
			recent++
		case "COVERAGE":
			var c a.Coverage
			if err := json.Unmarshal(f.Body, &c); err != nil {
				t.Fatal(err)
			}
			if c.From.Before(cutover) && c.Code == "UNSUPPORTED" {
				early++
			}
		}
	}
	if recent == 0 || early == 0 || normalized != 1 {
		t.Fatalf("batch retained recent=%d historical gaps=%d normalized unit=%d", recent, early, normalized)
	}
	known := make(map[string]a.Fact, len(facts))
	for _, fact := range facts {
		known[fact.ID] = fact
	}
	repeated, err := loadAssessmentInput(ctx, tx, f.config, asset, at, known)
	if err != nil {
		t.Fatal(err)
	}
	for _, fact := range repeated {
		if fact.Kind == "SAMPLE" {
			t.Fatal("identical sample was rematerialized")
		}
	}
	rollbackMonitoringTx(tx)
	f.exec(t, `UPDATE observations SET value=value+1 WHERE observation_id='assessment-observation-0-900'`)
	tx, err = beginAssessmentTx(ctx, f.restricted)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	repeated, err = loadAssessmentInput(ctx, tx, f.config, asset, at, known)
	if err != nil {
		t.Fatal(err)
	}
	changed := 0
	for _, fact := range repeated {
		if fact.Kind != "SAMPLE" {
			continue
		}
		var sample a.Sample
		if err := json.Unmarshal(fact.Body, &sample); err != nil {
			t.Fatal(err)
		}
		if sample.SourceRecord != "assessment-observation-0-900" || sample.Value != 41 {
			t.Fatalf("unexpected rematerialized sample %+v", sample)
		}
		changed++
	}
	if changed != 1 {
		t.Fatalf("changed immutable ID sample count = %d", changed)
	}
}

func TestAssessmentIndexedLookbackPreservesDelayedSourceAndActiveQualifications(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	old := at.Add(-20 * time.Minute)
	f.seedRun(t, old)
	asset := f.config.Assets[0].EntityKey
	newFact := func(kind string, available time.Time, value any) a.Fact {
		t.Helper()
		fact, err := a.NewFact(f.config.Category, f.config.RunID, asset, kind, available, value)
		if err != nil {
			t.Fatal(err)
		}
		body, err := a.Canonical(fact)
		if err != nil {
			t.Fatal(err)
		}
		f.exec(t, `INSERT INTO assessment_facts(run_id,id,asset,kind,available_at,body) VALUES($1,$2,$3,$4,$5,$6)`, fact.Run, fact.ID, fact.Asset, fact.Kind, fact.AvailableAt, body)
		return fact
	}
	sample := func(ref string, source, available time.Time) a.Fact {
		return newFact("SAMPLE", available, a.Sample{Metric: cooling.Temperature, Unit: "celsius", SourceAt: source, CollectedAt: available, CompletedAt: available, Value: 42, SourceRecord: ref,
			Provenance: a.Provenance{Mode: "fixture", CollectionRunID: ref, Operation: string(domain.OperationPrometheusGPUTemperature), ScheduleRevision: 1, InventoryRevision: f.config.InventoryRevision, SourceRecord: ref}})
	}
	_ = sample("old", old, old)
	delayed := sample("delayed", at.Add(time.Second), old)
	recent := sample("recent", at, at)
	qualified := newFact("QUALIFIED", old, a.Qualified{PolicyID: "fixture-qualified", Occurrence: 1, Transition: "OPEN", Rule: "gpu_thermal", RuleVersion: 1, EnrollmentRevision: 1, Severity: "CRITICAL", QualifiedAt: old, Snapshot: []a.SnapshotEntry{}})
	_ = newFact("QUALIFIED", old, a.Qualified{PolicyID: "fixture-warning", Occurrence: 1, Transition: "OPEN", Rule: "gpu_thermal", RuleVersion: 1, EnrollmentRevision: 1, Severity: "WARNING", QualifiedAt: old, Snapshot: []a.SnapshotEntry{}})
	_ = newFact("QUALIFIED", old.Add(time.Second), a.Qualified{PolicyID: "fixture-qualified", Occurrence: 1, Transition: "RECOVER", Rule: "gpu_thermal", RuleVersion: 1, EnrollmentRevision: 1, Severity: "CRITICAL", QualifiedAt: old.Add(time.Second), Snapshot: []a.SnapshotEntry{}})
	tx, err := beginAssessmentTx(ctx, f.restrictedPool(t))
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	for _, active := range []bool{false, true} {
		rows, err := tx.Query(ctx, assessmentRetainedLookbackSQL, f.config.RunID, asset, at.Add(-15*time.Minute), active, old, at)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for rows.Next() {
			var body []byte
			var fact a.Fact
			if err := rows.Scan(&body); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			if err := a.DecodeStrict(body, &fact, 65536); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			got = append(got, fact.ID)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		want := []string{delayed.ID, recent.ID}
		if active {
			want = append(a.SortedUnique([]string{delayed.ID, qualified.ID}), recent.ID)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("active=%v retained=%v want=%v", active, got, want)
		}
	}
	e, err := a.NewEngine(ctx, f.config, old, f.registry)
	if err != nil {
		t.Fatal(err)
	}
	fallbacks := 0
	e.LookupFact = func(ctx context.Context, id string) (a.Fact, bool) {
		fallbacks++
		return recent, id == recent.ID
	}
	incoming := delayed
	incoming.AvailableAt = at
	unseen, err := a.NewFact(f.config.Category, f.config.RunID, asset, "COVERAGE", at, a.Coverage{Metric: cooling.Temperature, From: old, Through: at, Code: "UNKNOWN", SourceRecord: "unseen"})
	if err != nil {
		t.Fatal(err)
	}
	if err := prefetchAssessmentAdmissions(ctx, tx, e, []a.Fact{incoming, unseen}); err != nil {
		t.Fatal(err)
	}
	if fact, ok := e.LookupFact(ctx, incoming.ID); !ok || !fact.AvailableAt.Equal(old) {
		t.Fatal("prefetch changed admitted availability")
	}
	if _, ok := e.LookupFact(ctx, unseen.ID); ok || fallbacks != 0 {
		t.Fatal("prefetch repeated a known absent lookup")
	}
	if _, ok := e.LookupFact(ctx, recent.ID); !ok || fallbacks != 1 {
		t.Fatal("prefetch suppressed an unrelated closure lookup")
	}
}

func TestAssessmentOverdueReloadUsesOriginalRetainedHistory(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	entry := time.Now().UTC().Truncate(time.Microsecond).Add(-20 * time.Minute)
	f.seedRun(t, entry)
	asset := f.config.Assets[0]
	bindings, err := a.Canonical(f.config.Bindings)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO assessment_enrollments(run_id,category,asset,node_id,gpu_uuid,inventory_revision,bindings,discovery_floor,next_due_at,sequence,revision,rearm_eligible) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,0,1,true)`, f.config.RunID, f.config.Category, asset.EntityKey, asset.NodeID, asset.GPUUUID, f.config.InventoryRevision, bindings, entry)
	engine, err := a.NewEngine(ctx, f.config, entry, f.registry)
	if err != nil {
		t.Fatal(err)
	}
	sample := func(offset time.Duration, available time.Time, value float64) a.Fact {
		t.Helper()
		ref := fmt.Sprintf("overdue-sample-%s-%g", offset, value)
		fct, err := a.NewFact(f.config.Category, f.config.RunID, asset.EntityKey, "SAMPLE", available,
			a.Sample{Metric: cooling.Temperature, Unit: "celsius", SourceAt: entry.Add(offset), CollectedAt: available, CompletedAt: available, Value: value, SourceRecord: ref,
				Provenance: a.Provenance{Mode: "fixture", CollectionRunID: ref, Operation: string(domain.OperationPrometheusGPUTemperature), ScheduleRevision: 1, InventoryRevision: f.config.InventoryRevision, SourceRecord: ref}})
		if err != nil {
			t.Fatal(err)
		}
		return fct
	}
	initial := []a.Fact{sample(-30*time.Second, entry, 75), sample(-15*time.Second, entry, 75), sample(0, entry, 75)}
	if err := engine.Advance(ctx, entry, entry, entry, initial, nil); err != nil {
		t.Fatal(err)
	}
	var budget30 *a.Candidate
	for _, c := range engine.Candidates {
		if c.BudgetMS == 30000 {
			budget30 = c
		}
	}
	if budget30 == nil || budget30.Phase != "OBSERVING" {
		t.Fatal("fixture needs a pending 30-second arm before restart")
	}
	store := &AssessmentStore{pool: f.admin, registry: f.registry, config: f.config}
	snapshot := newAssessmentSnapshot()
	snapshot.enrollmentRevision[asset.EntityKey] = 1
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	if err := store.saveEngine(ctx, tx, engine, snapshot, entry, []string{asset.EntityKey}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	posting := sample(30*time.Second, entry.Add(30*time.Second), 75)
	for _, fct := range []a.Fact{sample(15*time.Second, entry.Add(15*time.Second), 75), posting} {
		body, err := a.Canonical(fct)
		if err != nil {
			t.Fatal(err)
		}
		f.exec(t, `INSERT INTO assessment_facts(run_id,id,asset,kind,available_at,body) VALUES($1,$2,$3,'SAMPLE',$4,$5)`, fct.Run, fct.ID, fct.Asset, fct.AvailableAt, body)
	}
	wake := entry.Add(20 * time.Minute)
	tx, err = beginAssessmentTx(ctx, f.admin)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	restored, snap, err := store.loadEngine(ctx, tx, wake, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := restored.Facts[posting.ID]; !ok {
		t.Fatal("historical cutoff dropped retained post-entry evidence")
	}
	restored.Shadow = false // This case tests semantic cutoff recovery independently of elapsed CPU.
	if err := restored.AdvanceAssets(ctx, wake, wake, wake, nil, nil, []string{}); err != nil {
		t.Fatal(err)
	}
	var accepted *a.Decision
	for i := range restored.Decisions {
		d := &restored.Decisions[i]
		if d.CandidateID == budget30.ID {
			accepted = d
		}
	}
	if accepted == nil || accepted.Outcome != cooling.CategoryID+"/COOLING_SUSPECTED" || !accepted.LogicalAt.Equal(budget30.DueAt) {
		t.Fatalf("overdue terminal = %+v", accepted)
	}
	var before time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	restored.Shadow = true // Persist this validated result using actual DB statement time.
	if err := store.saveEngine(ctx, tx, restored, snap, wake, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var stamped time.Time
	var lateness int64
	if err := f.admin.QueryRow(ctx, `SELECT committed_at,lateness_us FROM assessment_decisions WHERE run_id=$1 AND id=$2`, f.config.RunID, accepted.ID).Scan(&stamped, &lateness); err != nil {
		t.Fatal(err)
	}
	if stamped.Before(before) || lateness != stamped.Sub(budget30.DueAt).Microseconds() {
		t.Fatalf("terminal statement time=%s before=%s lateness=%d", stamped, before, lateness)
	}
}

func TestAssessmentRefreshLoadsOnlyFairlySelectedAssets(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	prepareAssessmentProfile(t, f, at)
	f.seedRun(t, at.Add(-time.Minute))
	bindings, err := a.Canonical(f.config.Bindings)
	if err != nil {
		t.Fatal(err)
	}
	for index, asset := range f.config.Assets {
		due := at.Add(-time.Second)
		var previous *time.Time
		switch index {
		case 0:
			attempt := at.Add(-2 * time.Second)
			previous = &attempt
		case 1:
			// Never attempted. This asset wins the first same-time slot.
		case 2:
			attempt := at.Add(-3 * time.Second)
			previous = &attempt
		default:
			attempt := at.Add(-time.Second)
			previous = &attempt
		}
		f.exec(t, `INSERT INTO assessment_enrollments(run_id,category,asset,node_id,gpu_uuid,inventory_revision,bindings,discovery_floor,next_due_at,last_attempt_at,sequence,revision,rearm_eligible) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,0,1,true)`, f.config.RunID, f.config.Category, asset.EntityKey, asset.NodeID, asset.GPUUUID, f.config.InventoryRevision, bindings, at.Add(-time.Minute), due, previous)
		fact, err := a.NewFact(f.config.Category, f.config.RunID, asset.EntityKey, "COVERAGE", at, a.Coverage{Metric: cooling.Temperature, From: at, Through: at, Code: "UNKNOWN", SourceRecord: "selection-fixture"})
		if err != nil {
			t.Fatal(err)
		}
		body, err := a.Canonical(fact)
		if err != nil {
			t.Fatal(err)
		}
		f.exec(t, `INSERT INTO assessment_facts(run_id,id,asset,kind,available_at,body) VALUES($1,$2,$3,$4,$5,$6)`, fact.Run, fact.ID, fact.Asset, fact.Kind, at, body)
	}
	store := &AssessmentStore{pool: f.admin, registry: f.registry, config: f.config}
	tx, err := beginAssessmentTx(ctx, f.admin)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	for _, index := range []int{1, 2, 0, 3, 4, 5, 6, 7} {
		engine, snapshot, err := store.loadEngine(ctx, tx, at, false)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{f.config.Assets[index].EntityKey}
		if !slices.Equal(snapshot.selected, want) || len(engine.Facts) != 1 {
			t.Fatalf("selected %v with %d facts, want %v", snapshot.selected, len(engine.Facts), want)
		}
		for _, fact := range engine.Facts {
			if !slices.Contains(want, fact.Asset) {
				t.Fatal("loaded unselected asset evidence", fact.Asset)
			}
		}
		// Leave the old logical hint intact, as a failed discovery does. Its
		// already elapsed scheduling time should not let it monopolize a slot.
		if err := store.saveEngine(ctx, tx, engine, snapshot, at, snapshot.selected); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAssessmentSourceClockToleranceRequiresExactContract(t *testing.T) {
	f := newAssessmentFixture(t)
	f.seedSource(t, true)
	ctx := context.Background()
	f.exec(t, `UPDATE observations SET source_reference=$1,observed_at=collected_at+interval '1 second' WHERE observation_id='assessment-observation-0-900'`, domain.DCGMSourceReference(domain.QueryGPUTemperature))
	f.exec(t, `UPDATE observations SET source_reference=$1,observed_at=collected_at+interval '2 seconds' WHERE observation_id='assessment-observation-0-885'`, domain.DCGMSourceReference(domain.QueryGPUTemperature))
	f.exec(t, `UPDATE observations SET observed_at=collected_at+interval '1 second' WHERE observation_id='assessment-observation-1-900'`)
	var at time.Time
	if err := f.admin.QueryRow(ctx, `SELECT collected_at+interval '250 milliseconds' FROM observations WHERE observation_id='assessment-observation-0-900'`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	at = at.UTC()
	tx, err := beginAssessmentTx(ctx, f.restrictedPool(t))
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	facts, err := loadAssessmentInput(ctx, tx, f.config, f.config.Assets[0], at)
	if err != nil {
		t.Fatal(err)
	}
	seenQualified := false
	for _, fact := range facts {
		if fact.Kind != "SAMPLE" {
			continue
		}
		var sample a.Sample
		if err := json.Unmarshal(fact.Body, &sample); err != nil {
			t.Fatal(err)
		}
		switch sample.SourceRecord {
		case "assessment-observation-0-885", "assessment-observation-1-900":
			t.Fatalf("accepted a source clock outside its contract: %s", sample.SourceRecord)
		case "assessment-observation-0-900":
			seenQualified = sample.SourceAt.After(at) && fact.AvailableAt.Equal(at)
		}
	}
	if !seenQualified {
		t.Fatal("qualified one-second DCGM offset lost its deferred eligibility")
	}
}

func TestAssessmentQualifiedSourceIgnoresUnadmittedHistoricalRecoveries(t *testing.T) {
	f := newAssessmentFixture(t)
	f.seedSource(t, true)
	ctx := context.Background()
	asset := f.config.Assets[0]
	p := monitoring.Policy{ID: "assessment-qualified-policy", ClusterID: domain.ClusterID(f.config.ClusterID), SourceID: domain.SourceID(f.config.SourceID), EntityKey: asset.EntityKey,
		Rule: monitoring.RuleGPUThermal, RuleVersion: 1, Metric: cooling.Temperature, Unit: "celsius",
		Binding:         monitoring.Binding{Operation: domain.OperationPrometheusGPUTemperature, Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{}}, ScheduleRevision: 1, InventoryRevisionID: f.config.InventoryRevision},
		FreshForSeconds: 900, ConfirmCount: 2, ConfirmWindowSeconds: 60, RecoverCount: 2, RecoverWindowSeconds: 60, MaxSampleGapSeconds: 30, OpenThreshold: 95, RecoverBelow: 90, Severity: domain.HealthSeverityCritical}
	enrollment, err := NewMonitoringStore(f.admin).Enroll(ctx, p, 0, "qualified-source-fixture")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	start := at.Add(-30 * time.Second)
	f.seedRun(t, start)
	old := at.Add(-time.Hour)
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	for i := int64(1); i <= 41; i++ {
		opened := old.Add(time.Duration(i) * time.Second)
		severity := domain.HealthSeverityWarning
		if i == 41 {
			opened, severity = at.Add(-time.Second), domain.HealthSeverityCritical
		}
		if err := publishMonitoringTransition(ctx, tx, enrollment.Policy, monitoring.Transition{Kind: monitoring.TransitionOpen, Occurrence: i, At: opened, Severity: severity, Reason: monitoring.ReasonThermalThreshold}, nil); err != nil {
			t.Fatal(err)
		}
		if i < 41 {
			if err := publishMonitoringTransition(ctx, tx, enrollment.Policy, monitoring.Transition{Kind: monitoring.TransitionRecover, Occurrence: i, At: opened.Add(time.Millisecond), Severity: severity, Reason: monitoring.ReasonFreshRecovery}, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	open, err := a.NewFact(f.config.Category, f.config.RunID, asset.EntityKey, "QUALIFIED", start.Add(time.Second), a.Qualified{
		PolicyID: p.ID, Occurrence: 7, Transition: "OPEN", Rule: string(p.Rule), RuleVersion: 1, EnrollmentRevision: 1, Severity: "WARNING", QualifiedAt: old.Add(7 * time.Second), Snapshot: []a.SnapshotEntry{}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := a.Canonical(open)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO assessment_facts(run_id,id,asset,kind,available_at,body) VALUES($1,$2,$3,$4,$5,$6)`, open.Run, open.ID, open.Asset, open.Kind, open.AvailableAt, body)
	tx, err = beginAssessmentTx(ctx, f.restrictedPool(t))
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	facts, err := loadAssessmentQualified(ctx, tx, f.config, asset, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 2 {
		t.Fatalf("qualification includes unrelated closed episodes: %d facts", len(facts))
	}
	for i, want := range []struct {
		transition string
		occurrence int64
	}{{"OPEN", 41}, {"RECOVER", 7}} {
		var q a.Qualified
		if err := json.Unmarshal(facts[i].Body, &q); err != nil || q.Transition != want.transition || q.Occurrence != want.occurrence {
			t.Fatalf("qualified %d = %+v, want %+v (%v)", i, q, want, err)
		}
	}
}

func stageAssessmentWarmEntries(t *testing.T, f *assessmentFixture, store *AssessmentStore) time.Time {
	t.Helper()
	ctx := context.Background()
	if err := store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	var start time.Time
	if err := f.admin.QueryRow(ctx, `SELECT start_at FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&start); err != nil {
		t.Fatal(err)
	}
	start = start.UTC()
	engine, err := a.NewEngine(ctx, f.config, start, f.registry)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := newAssessmentSnapshot()
	var facts []a.Fact
	var selected []string
	for _, asset := range f.config.Assets {
		snapshot.enrollmentRevision[asset.EntityKey] = 1
		selected = append(selected, asset.EntityKey)
		for _, offset := range []time.Duration{-30 * time.Second, -15 * time.Second, 0} {
			facts = append(facts, assessmentWarmSample(t, f.config, asset.EntityKey, start.Add(offset), start))
		}
	}
	if err := engine.Advance(ctx, start, start, start, facts, nil); err != nil {
		t.Fatal(err)
	}
	if len(engine.Candidates) != len(selected)*len(a.Budgets) {
		t.Fatal("fixture did not stage complete candidate cohorts")
	}
	tx, err := beginAssessmentTx(ctx, f.admin)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	if err := store.saveEngine(ctx, tx, engine, snapshot, start, selected); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return start
}

func assessmentWarmSample(t *testing.T, c a.Config, asset string, source, available time.Time) a.Fact {
	t.Helper()
	ref := fmt.Sprintf("warm-fixture-%d", source.UnixMicro())
	f, err := a.NewFact(c.Category, c.RunID, asset, "SAMPLE", available, a.Sample{Metric: cooling.Temperature, Unit: "celsius",
		SourceAt: source, CollectedAt: available, CompletedAt: available, Value: 75, SourceRecord: ref,
		Provenance: a.Provenance{Mode: "fixture", CollectionRunID: ref, Operation: string(domain.OperationPrometheusGPUTemperature), ScheduleRevision: 1, InventoryRevision: c.InventoryRevision, SourceRecord: ref}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestAssessmentRetainedOverflowPreservesPeerDeadline(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	prepareAssessmentProfile(t, f, time.Now().UTC())
	f.config.Assets = f.config.Assets[:2]
	store, err := NewAssessmentStore(ctx, f.restrictedPool(t), f.registry, f.config, "overflow-fixture")
	if err != nil {
		t.Fatal(err)
	}
	start := stageAssessmentWarmEntries(t, f, store)
	blocked, peer := f.config.Assets[0].EntityKey, f.config.Assets[1].EntityKey
	for base := range 2 {
		n := a.MaxFacts/2 + 1
		_, err := f.admin.CopyFrom(ctx, pgx.Identifier{"public", "assessment_facts"}, []string{"run_id", "id", "asset", "kind", "available_at", "body"}, pgx.CopyFromSlice(n, func(i int) ([]any, error) {
			fact, err := a.NewFact(f.config.Category, f.config.RunID, blocked, "COVERAGE", start.Add(time.Second),
				a.Coverage{Metric: cooling.Temperature, From: start, Through: start, Code: "OVERFLOW_FIXTURE", SourceRecord: fmt.Sprintf("assessment-cap-%d-%d", base, i)})
			if err != nil {
				return nil, err
			}
			body, err := a.Canonical(fact)
			return []any{fact.Run, fact.ID, fact.Asset, fact.Kind, fact.AvailableAt, body}, err
		}))
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, offset := range []time.Duration{15 * time.Second, 30 * time.Second} {
		fact := assessmentWarmSample(t, f.config, peer, start.Add(offset), start.Add(offset))
		body, err := a.Canonical(fact)
		if err != nil {
			t.Fatal(err)
		}
		f.exec(t, `INSERT INTO assessment_facts(run_id,id,asset,kind,available_at,body) VALUES($1,$2,$3,$4,$5,$6)`, fact.Run, fact.ID, fact.Asset, fact.Kind, fact.AvailableAt, body)
	}
	wake := start.Add(31 * time.Second)
	tx, err := beginAssessmentTx(ctx, store.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	engine, _, err := store.loadEngine(ctx, tx, wake, true)
	if err != nil {
		t.Fatal(err)
	}
	if engine.ExpiryFailure[blocked] != "CAPACITY" || engine.ExpiryFailure[peer] != "" {
		t.Fatalf("persisted load failure lost scope: %v", engine.ExpiryFailure)
	}
	engine.Shadow = false
	if err := engine.AdvanceAssets(ctx, wake, wake, wake, nil, nil, []string{}); err != nil {
		t.Fatal(err)
	}
	var foundBlocked, foundPeer bool
	for _, d := range engine.Decisions {
		if d.BudgetMS != 30000 {
			continue
		}
		if d.Asset == blocked {
			foundBlocked = d.DecisionSource == "HOST_FALLBACK" && d.FailureCode == "CAPACITY" && d.TerminalEndpoint == nil
		} else if d.Asset == peer {
			foundPeer = d.DecisionSource == "CATEGORY" && d.Outcome == cooling.CategoryID+"/COOLING_SUSPECTED"
		}
	}
	if !foundBlocked || !foundPeer {
		t.Fatalf("deadline outcomes failed independence: blocked=%t peer=%t, decisions=%+v", foundBlocked, foundPeer, engine.Decisions)
	}
}

func TestAssessmentMissingCategoryAllowsOnlyMatchingRunRecovery(t *testing.T) {
	for _, token := range []string{"1e1", "1.00000000000000001e1"} {
		t.Run(token, func(t *testing.T) { checkAssessmentMissingCategoryRecovery(t, token) })
	}
}

func checkAssessmentMissingCategoryRecovery(t *testing.T, originalNumber string) {
	t.Helper()
	f := newAssessmentFixture(t)
	ctx := context.Background()
	configFile, err := os.ReadFile("../../../test/assessment/v1/config.json")
	if err != nil {
		t.Fatal(err)
	}
	inputPolicyToken := []byte(`"stable_watts": ` + originalNumber)
	original := bytes.Replace(configFile, []byte(`"stable_watts": 10`), inputPolicyToken, 1)
	if bytes.Equal(original, configFile) {
		t.Fatal("fixture did not acquire exponent spelling")
	}
	f.config, err = a.ParseConfig(ctx, original, f.registry)
	if err != nil || !bytes.Contains(f.config.Policy, []byte(`"stable_watts":10`)) {
		t.Fatalf("typed admission did not pin the canonical policy: %v", err)
	}
	f.seedSource(t, true)
	pool := f.restrictedPool(t)
	installed, err := NewAssessmentStore(ctx, pool, f.registry, f.config, "installed-fixture")
	if err != nil {
		t.Fatal(err)
	}
	start := stageAssessmentWarmEntries(t, f, installed)
	missing, err := a.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	changed := f.config
	changed.RunDurationSeconds++
	if _, err := NewAssessmentStore(ctx, pool, missing, changed, "missing-fixture"); !errors.Is(err, ErrAssessmentRunBusy) {
		t.Fatalf("unmatched recovery config = %v", err)
	}
	changed.RunID = "unknown-run-fixture"
	if _, err := NewAssessmentStore(ctx, pool, missing, changed, "missing-fixture"); !errors.Is(err, errAssessmentUnsupportedVersion) {
		t.Fatalf("unregistered new run = %v", err)
	}
	stale := f.config
	stale.Policy = bytes.Replace(stale.Policy, []byte(`"stable_watts":10`), []byte(`"stable_watts":11`), 1)
	if _, err := NewAssessmentStore(ctx, pool, missing, stale, "missing-fixture"); !errors.Is(err, ErrAssessmentRunBusy) {
		t.Fatalf("mutated typed policy retained a usable input witness: %v", err)
	}
	differentNumber := bytes.Replace(original, inputPolicyToken, []byte(`"stable_watts": 1.00000000000000002e1`), 1)
	different, err := a.ParseRecoveryConfig(differentNumber)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAssessmentStore(ctx, pool, missing, different, "missing-fixture"); !errors.Is(err, ErrAssessmentRunBusy) {
		t.Fatalf("unadmitted float token accepted as old policy: %v", err)
	}
	differentInteger := bytes.Replace(original, []byte(`"persistence_samples": 3`), []byte(`"persistence_samples": 4`), 1)
	if bytes.Equal(differentInteger, original) {
		t.Fatal("integer policy fixture did not change")
	}
	different, err = a.ParseRecoveryConfig(differentInteger)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAssessmentStore(ctx, pool, missing, different, "missing-fixture"); !errors.Is(err, ErrAssessmentRunBusy) {
		t.Fatalf("unadmitted integer token accepted as old policy: %v", err)
	}
	recoveryInput, err := a.ParseRecoveryConfig(original)
	if err != nil || !bytes.Contains(recoveryInput.Policy, []byte(`"stable_watts":`+originalNumber)) {
		t.Fatalf("recovery input did not retain the original number token: %v", err)
	}
	var pinnedInput string
	if err := f.admin.QueryRow(ctx, `SELECT input_config_hash FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&pinnedInput); err != nil {
		t.Fatal(err)
	}
	inputHash, err := recoveryInput.InputConfigHash()
	if err != nil || pinnedInput != inputHash {
		t.Fatalf("typed admission did not persist the original input witness: %s vs %s (%v)", pinnedInput, inputHash, err)
	}
	if _, err := NewAssessmentStore(ctx, pool, missing, f.config, "missing-fixture"); err != nil {
		t.Fatalf("exact canonical recovery rejected: %v", err)
	}
	recovered, err := NewAssessmentStore(ctx, pool, missing, recoveryInput, "missing-fixture")
	if err != nil {
		t.Fatal(err)
	}
	wantHash, err := f.config.Hash()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := recovered.config.Hash()
	if err != nil || hash != wantHash || !bytes.Equal(recovered.config.Policy, f.config.Policy) {
		t.Fatalf("recovery changed the pinned config identity: %s vs %s (%v)", hash, wantHash, err)
	}
	if err := recovered.Start(ctx); err != nil {
		t.Fatal(err)
	}
	var state, stopReason string
	if err := f.admin.QueryRow(ctx, `SELECT state,stop_reason FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&state, &stopReason); err != nil || state != "DRAINING" || stopReason != "UNSUPPORTED_VERSION" {
		t.Fatalf("recovery run = %s/%s (%v)", state, stopReason, err)
	}
	tx, err := beginAssessmentTx(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	wake := start.Add(130 * time.Second)
	engine, _, err := recovered.loadEngine(ctx, tx, wake, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(engine.Facts) != 0 || engine.ExpiryFailure[""] != "UNSUPPORTED_VERSION" {
		t.Fatal("missing-category drain loaded bulk evidence or lost typed fallback cause")
	}
	engine.Shadow = false // Explicit fixture epoch, independent of the real database clock.
	if err := engine.AdvanceAssets(ctx, wake, wake, wake, nil, nil, []string{}); err != nil {
		t.Fatal(err)
	}
	if engine.State != "CLOSED" || len(engine.Decisions) != len(a.Budgets)-1 {
		t.Fatalf("missing-category drain = %s, %d decisions", engine.State, len(engine.Decisions))
	}
	for _, decision := range engine.Decisions {
		if decision.DecisionSource != "HOST_FALLBACK" || decision.FailureCode != "UNSUPPORTED_VERSION" || decision.TerminalEndpoint != nil || decision.Outcome != "" {
			t.Fatalf("invalid host-only fallback: %+v", decision)
		}
	}
}

func TestAssessmentSnapshotMemoizesOnlyValidatedImmutableLookups(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	f.seedRun(t, at)
	asset := f.config.Assets[0].EntityKey
	initial := assessmentWarmSample(t, f.config, asset, at, at)
	newFact := assessmentWarmSample(t, f.config, asset, at.Add(time.Microsecond), at.Add(time.Microsecond))
	corrupt := initial
	corrupt.ID = strings.Repeat("a", 64) // Projection matches its row, but its identity does not.
	const insertFact = `INSERT INTO assessment_facts(run_id,id,asset,kind,available_at,body) VALUES($1,$2,$3,$4,$5,$6)`
	for _, fact := range []a.Fact{initial, corrupt} {
		body, err := a.Canonical(fact)
		if err != nil {
			t.Fatal(err)
		}
		f.exec(t, insertFact, fact.Run, fact.ID, fact.Asset, fact.Kind, fact.AvailableAt, body)
	}
	bundle, err := a.NewBundle(f.config.Category, f.config.RunID, asset, at, []a.Fact{initial})
	if err != nil {
		t.Fatal(err)
	}
	body, err := a.Canonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO assessment_bundles(run_id,id,asset,logical_at,availability_cutoff,body) VALUES($1,$2,$3,$4,$5,$6)`, bundle.Run, bundle.ID, bundle.Asset, bundle.LogicalAt, bundle.AvailabilityCutoff, body)

	trace := &assessmentQueryTrace{byStage: make(map[string][]time.Duration), failures: make(map[string]int)}
	config := f.restrictedPool(t).Config()
	config.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := beginAssessmentTx(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	store := &AssessmentStore{pool: pool, registry: f.registry, config: f.config}
	engine, _, err := store.loadEngineForFallback(ctx, tx, at, "CAPACITY")
	if err != nil {
		t.Fatal(err)
	}
	fact, ok := engine.LookupFact(ctx, initial.ID)
	if !ok {
		t.Fatal("valid fact missing")
	}
	fact.Body[0] = 'x'
	if restored, ok := engine.LookupFact(ctx, initial.ID); !ok || !bytes.Equal(restored.Body, initial.Body) {
		t.Fatal("mutated fact result poisoned the cached body")
	}
	loaded, ok := engine.LookupBundle(ctx, bundle.ID)
	if !ok {
		t.Fatal("valid bundle missing")
	}
	loaded.Facts[0] = corrupt.ID
	if restored, ok := engine.LookupBundle(ctx, bundle.ID); !ok || !slices.Equal(restored.Facts, bundle.Facts) {
		t.Fatal("mutated bundle result poisoned the cached manifest")
	}
	for range 2 {
		if _, ok := engine.LookupFact(ctx, corrupt.ID); ok {
			t.Fatal("invalid fact passed validation")
		}
	}
	if _, ok := engine.LookupFact(ctx, newFact.ID); ok {
		t.Fatal("unadmitted fact passed lookup")
	}
	body, err = a.Canonical(newFact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, insertFact, newFact.Run, newFact.ID, newFact.Asset, newFact.Kind, newFact.AvailableAt, body); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, ok := engine.LookupFact(ctx, newFact.ID); !ok {
			t.Fatal("earlier miss hid a new write in the transaction")
		}
	}
	if factReads, bundleReads := len(trace.byStage["lookup_fact"]), len(trace.byStage["lookup_bundle"]); factReads != 5 || bundleReads != 1 {
		t.Fatalf("snapshot queries fact=%d bundle=%d, want 5 and 1", factReads, bundleReads)
	}
}

func TestAssessmentLegacyRunRecoversOnlyExactCanonicalConfig(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	config, err := a.Canonical(f.config)
	if err != nil {
		t.Fatal(err)
	}
	configHash, err := f.config.Hash()
	if err != nil {
		t.Fatal(err)
	}
	_, desc, descriptorHash, err := f.registry.LookupVersion(f.config.Category, f.config.Implementation)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := a.Canonical(desc)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO assessment_runs(run_id,config,config_hash,descriptor,descriptor_hash,build_hash,mode,state,start_at,admission_end_at) VALUES($1,$2,$3,$4,$5,$5,'shadow','ACTIVE',transaction_timestamp(),transaction_timestamp()+interval '1 minute')`, f.config.RunID, config, configHash, descriptor, descriptorHash)
	unavailable, err := a.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	pool := f.restrictedPool(t)
	otherSpelling := bytes.Replace(config, []byte(`"stable_watts":10`), []byte(`"stable_watts":1e1`), 1)
	if bytes.Equal(config, otherSpelling) {
		t.Fatal("legacy spelling fixture did not change")
	}
	input, err := a.ParseRecoveryConfig(otherSpelling)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAssessmentStore(ctx, pool, unavailable, input, "legacy-missing-fixture"); !errors.Is(err, ErrAssessmentRunBusy) {
		t.Fatalf("legacy run accepted a different config without an input witness: %v", err)
	}
	recovered, err := NewAssessmentStore(ctx, pool, unavailable, f.config, "legacy-missing-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := recovered.Start(ctx); err != nil {
		t.Fatal(err)
	}
	var state string
	var witness *string
	if err := f.admin.QueryRow(ctx, `SELECT state,input_config_hash FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&state, &witness); err != nil || state != "DRAINING" || witness != nil {
		t.Fatalf("legacy recovery state=%s witness=%v (%v)", state, witness, err)
	}
}

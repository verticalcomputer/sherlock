//go:build integration

package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type assessmentFixture struct {
	admin      *pgxpool.Pool
	restricted *pgxpool.Pool
	config     a.Config
	registry   *a.Registry
	role       string
	dsn        string
}

func newAssessmentFixture(t *testing.T) *assessmentFixture {
	t.Helper()
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires the disposable PostgreSQL17 integration harness")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("disposable fixture connection failed")
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	name := fmt.Sprintf("assessment_test_%d", time.Now().UnixNano())
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	parsed, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("fixture DSN invalid")
	}
	parsed.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, parsed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	})
	paths, err := filepath.Glob("../../../migrations/*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, string(body)); err != nil {
			t.Fatalf("migration %s: %v", filepath.Base(path), err)
		}
	}
	registry, err := a.NewRegistry(cooling.Category{})
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("../../../test/assessment/v1/config.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := a.ParseConfig(ctx, body, registry)
	if err != nil {
		t.Fatal(err)
	}
	u, parseErr := url.Parse(dsn)
	if parseErr != nil {
		t.Fatal("fixture URL")
	}
	u.Path = "/" + name
	return &assessmentFixture{admin: pool, config: cfg, registry: registry, dsn: u.String()}
}
func (f *assessmentFixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := f.admin.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}
func (f *assessmentFixture) seedRun(t *testing.T, at time.Time, modes ...string) {
	t.Helper()
	mode := "replay"
	if len(modes) > 0 {
		mode = modes[0]
	}
	config, err := a.Canonical(f.config)
	if err != nil {
		t.Fatal(err)
	}
	_, d, dh, _ := f.registry.Lookup(f.config.Category)
	descriptor, _ := a.Canonical(d)
	ch, _ := f.config.Hash()
	f.exec(t, `INSERT INTO assessment_runs(run_id,config,config_hash,descriptor,descriptor_hash,build_hash,mode,state,start_at,admission_end_at) VALUES($1,$2,$3,$4,$5,$5,$6,'ACTIVE',$7,$8)`, f.config.RunID, config, ch, descriptor, dh, mode, at, at.Add(time.Duration(f.config.RunDurationSeconds)*time.Second))
}
func (f *assessmentFixture) restrictedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	grants, err := os.ReadFile("../../../scripts/assessment-grants.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, string(grants)); err != nil {
		t.Fatal(err)
	}
	// Only this disposable database is hardened. Existing PUBLIC routine grants
	// are deliberately removed, not mistaken for least privilege by role name.
	f.exec(t, `REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC`)
	f.exec(t, "REVOKE TEMPORARY ON DATABASE "+pgx.Identifier{f.admin.Config().ConnConfig.Database}.Sanitize()+" FROM PUBLIC")
	raw := make([]byte, 24)
	if _, err = rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(raw)
	role := fmt.Sprintf("assessment_login_%d", time.Now().UnixNano())
	f.role = role
	f.exec(t, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN PASSWORD '"+password+"' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION")
	f.exec(t, "GRANT sherlock_assessment TO "+pgx.Identifier{role}.Sanitize())
	pc := f.admin.Config().Copy()
	pc.ConnConfig.User = role
	pc.ConnConfig.Password = password
	pc.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	f.restricted = pool
	t.Cleanup(pool.Close)
	return pool
}
func TestAssessmentMigrationAndImmutableEvidence(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	down, err := os.ReadFile("../../../migrations/000082_alert_assessment.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("../../../migrations/000082_alert_assessment.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, string(down))
	f.exec(t, string(up))
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-8 * 24 * time.Hour)
	f.seedRun(t, at)
	if _, err = f.admin.Exec(ctx, string(down)); err == nil {
		t.Fatal("nonempty down accepted")
	}
	asset := f.config.Assets[0].EntityKey
	s := a.Sample{Metric: cooling.Temperature, Unit: "celsius", SourceAt: at, CollectedAt: at, CompletedAt: at, Value: 70, SourceRecord: "sample", Provenance: a.Provenance{Mode: "fixture", CollectionRunID: "run", Operation: "fixture", ScheduleRevision: 1, InventoryRevision: "inventory", SourceRecord: "sample"}}
	fact, err := a.NewFact(f.config.Category, f.config.RunID, asset, "SAMPLE", at, s)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := a.Canonical(fact)
	f.exec(t, `INSERT INTO assessment_facts(run_id,id,asset,kind,available_at,body) VALUES($1,$2,$3,'SAMPLE',$4,$5)`, f.config.RunID, fact.ID, asset, at, body)
	if _, err = f.admin.Exec(ctx, `UPDATE assessment_facts SET available_at=available_at WHERE run_id=$1`, f.config.RunID); err == nil {
		t.Fatal("immutable fact accepted update")
	}
	if _, err = f.admin.Exec(ctx, `DELETE FROM assessment_facts WHERE run_id=$1`, f.config.RunID); err == nil {
		t.Fatal("active fact deleted")
	}
	feature := a.Feature{FeatureKind: "temperature_endpoint", SourceAt: at, Value: 70, Unit: "celsius", Support: []string{fact.ID}}
	derived, err := a.NewFact(f.config.Category, f.config.RunID, asset, "FEATURE", at, feature)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = a.Canonical(derived)
	f.exec(t, `INSERT INTO assessment_facts(run_id,id,asset,kind,available_at,body) VALUES($1,$2,$3,'FEATURE',$4,$5)`, f.config.RunID, derived.ID, asset, at, body)
	feature.Support = []string{derived.ID}
	invalid, _ := a.NewFact(f.config.Category, f.config.RunID, asset, "FEATURE", at, feature)
	body, _ = a.Canonical(invalid)
	if _, err = f.admin.Exec(ctx, `INSERT INTO assessment_facts(run_id,id,asset,kind,available_at,body) VALUES($1,$2,$3,'FEATURE',$4,$5)`, f.config.RunID, invalid.ID, asset, at, body); err == nil {
		t.Fatal("feature-to-feature edge accepted")
	}
	var count, bytes int64
	if err = f.admin.QueryRow(ctx, `SELECT fact_count,payload_bytes FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&count, &bytes); err != nil {
		t.Fatal(err)
	}
	if count != 2 || bytes <= 0 {
		t.Fatalf("accounting count=%d bytes=%d", count, bytes)
	}
	f.exec(t, `UPDATE assessment_runs SET state='CLOSED',stopped_at=admission_end_at,stop_reason='DURATION',closed_at=admission_end_at WHERE run_id=$1`, f.config.RunID)
	store := &AssessmentStore{pool: f.admin}
	n, err := store.Cleanup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("deleted %d", n)
	}
}
func TestAssessmentEffectivePrivileges(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	pool := f.restrictedPool(t)
	store := &AssessmentStore{pool: pool}
	if err := store.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `SELECT cluster_id,removed_at FROM clusters LIMIT 1`); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{`SELECT * FROM clusters LIMIT 1`, `UPDATE sources SET kind=kind`, `SELECT * FROM gp09_alert_outbox LIMIT 1`} {
		if _, err := pool.Exec(ctx, sql); err == nil {
			t.Fatalf("forbidden access accepted: %s", sql)
		}
	}
	f.exec(t, "GRANT UPDATE(kind) ON sources TO "+pgx.Identifier{f.role}.Sanitize())
	if err := store.Preflight(ctx); err == nil {
		t.Fatal("inherited extra privilege admitted")
	}
}
func TestAssessmentExportClosedAge(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-8 * 24 * time.Hour)
	f.seedRun(t, at)
	dsn := f.dsn
	if _, err := OpenAssessmentArchive(ctx, dsn, f.config.RunID); err == nil || !strings.Contains(err.Error(), "RUN_NOT_CLOSED") {
		t.Fatalf("active export: %v", err)
	}
	f.exec(t, `UPDATE assessment_runs SET state='CLOSED',stopped_at=admission_end_at,stop_reason='DURATION',closed_at=admission_end_at WHERE run_id=$1`, f.config.RunID)
	if _, err := OpenAssessmentArchive(ctx, dsn, f.config.RunID); err == nil || !strings.Contains(err.Error(), "RUN_EXPIRED") {
		t.Fatalf("expired export: %v", err)
	}
}

func (f *assessmentFixture) seedSource(t *testing.T, warm bool) {
	t.Helper()
	c := f.config
	asset := c.Assets[0]
	now := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Second)
	f.exec(t, `INSERT INTO clusters(cluster_id,display_name) VALUES($1,'Assessment fixture')`, c.ClusterID)
	f.exec(t, `INSERT INTO sources(source_id,cluster_id,kind,display_name,availability) VALUES($1,$2,'prometheus','Assessment fixture','UNKNOWN')`, c.SourceID, c.ClusterID)
	old := now.Add(-time.Hour)
	f.exec(t, `INSERT INTO goodput_inventory_revisions(revision_id,cluster_id,source_id,inventory_class,schema_version,content_digest,source_at,effective_at,observed_at) VALUES($1,$2,$3,'EXPECTED',1,decode(repeat('00',32),'hex'),$4,$4,$4)`, c.InventoryRevision, c.ClusterID, c.SourceID, old)
	f.exec(t, `INSERT INTO goodput_inventory_revision_validity(cluster_id,revision_id,valid_from) VALUES($1,$2,$3)`, c.ClusterID, c.InventoryRevision, old)
	f.exec(t, `INSERT INTO goodput_inventory_revision_entities(cluster_id,revision_id,entity_kind,stable_node_id,physical_gpu_uuid) VALUES($1,$2,'GPU',$3,$4)`, c.ClusterID, c.InventoryRevision, asset.NodeID, asset.GPUUUID)
	for bi, b := range c.Bindings {
		query := "dcgm_gpu_temperature"
		kind, unit := "gpu_temperature", "celsius"
		value := float64(40)
		if warm {
			value = 75
		}
		if b.Metric == cooling.Power {
			query = "dcgm_gpu_power"
			kind = "gpu_power"
			unit = "watts"
			value = 200
		}
		job := fmt.Sprintf("assessment-job-%d", bi)
		f.exec(t, `INSERT INTO collection_jobs(job_id,cluster_id,source_id,query_kind,interval_seconds,next_run_at) VALUES($1,$2,$3,$4,15,clock_timestamp())`, job, c.ClusterID, c.SourceID, query)
		f.exec(t, `INSERT INTO desired_schedules(cluster_id,source_id,operation,enabled,mode,interval_seconds,timeout_ms,jitter_ms,max_targets,max_bytes,priority,legacy_query_kind,legacy_job_id) VALUES($1,$2,$3,true,'legacy',15,5000,0,1000,1048576,50,$4,$5)`, c.ClusterID, c.SourceID, b.Operation, query, job)
		var revision int64
		if err := f.admin.QueryRow(context.Background(), `SELECT configuration_revision FROM collection_jobs WHERE job_id=$1`, job).Scan(&revision); err != nil {
			t.Fatal(err)
		}
		fields := fmt.Sprintf(`[{"node_id":%q,"gpu_uuid":%q,"metric":%q,"state":"SUPPORTED"}]`, asset.NodeID, asset.GPUUUID, b.Metric)
		// Use domain's actual field contract rather than relying on object key guesses.
		fieldBody, err := json.Marshal([]domain.DCGMFieldEvidence{{NodeID: domain.StableNodeID(asset.NodeID), GPU: domain.PhysicalGPUUUID(asset.GPUUUID), Metric: b.Metric, State: "SUPPORTED"}})
		if err != nil {
			t.Fatal(err)
		}
		fields = string(fieldBody)
		startSec := 0
		if warm {
			startSec = 840
		}
		for sec := startSec; sec <= 900; sec += 15 {
			at := now.Add(time.Duration(sec-900) * time.Second)
			id := fmt.Sprintf("assessment-observation-%d-%d", bi, sec)
			run := fmt.Sprintf("assessment-collection-%d-%d", bi, sec)
			f.exec(t, `INSERT INTO collection_runs(run_id,job_id,cluster_id,source_id,query_kind,idempotency_key,status,scheduled_for,started_at,completed_at,series_returned,bytes_read,coverage_complete,metric_fields) VALUES($1,$2,$3,$4,$5,$1,'SUCCEEDED',$6,$6,$6,1,100,true,$7)`, run, job, c.ClusterID, c.SourceID, query, at, fields)
			f.exec(t, `INSERT INTO collection_run_jobs(run_id,job_id,cluster_id,source_id,query_kind,node_filter,scheduled_for,configuration_revision,lease_generation) VALUES($1,$2,$3,$4,$5,'',$6,$7,1)`, run, job, c.ClusterID, c.SourceID, query, at, revision)
			f.exec(t, `INSERT INTO observations(observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,observed_at,collected_at,source_reference,sample_fingerprint) VALUES($1,$2,$3,$4,1,$5,$6,$7,'[]'::jsonb,$8,$9,$10,$10,'synthetic-assessment',$11)`, id, run, c.ClusterID, c.SourceID, kind, asset.EntityKey, b.Metric, value, unit, at, []byte(id))
		}
	}
}
func TestAssessmentShadowRefreshAndRestart(t *testing.T) {
	f := newAssessmentFixture(t)
	f.seedSource(t, true)
	pool := f.restrictedPool(t)
	ctx := context.Background()
	store, err := NewAssessmentStore(ctx, pool, f.registry, f.config, "test-build")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err = store.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	var physical, candidates, decisions int64
	if err = f.admin.QueryRow(ctx, `SELECT physical_count,(SELECT count(*) FROM assessment_candidates),(SELECT count(*) FROM assessment_decisions) FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&physical, &candidates, &decisions); err != nil {
		t.Fatal(err)
	}
	if physical != 1 || candidates != 5 || decisions < 1 || decisions > 5 {
		t.Fatalf("physical=%d candidates=%d decisions=%d", physical, candidates, decisions)
	}
	if decisions < 5 {
		var failures int
		if err = f.admin.QueryRow(ctx, `SELECT count(*) FROM assessment_failures WHERE code='TIME_BUDGET'`).Scan(&failures); err != nil {
			t.Fatal(err)
		}
		if failures == 0 {
			t.Fatal("unfinished arms without budget failure")
		}
	}
	var zeroFinal bool
	if err = f.admin.QueryRow(ctx, `SELECT phase='FINAL' FROM assessment_candidates WHERE budget_ms=0`).Scan(&zeroFinal); err != nil || !zeroFinal {
		t.Fatal("zero arm must terminal even if evaluation exhausts budget")
	}

	restarted, err := NewAssessmentStore(ctx, pool, f.registry, f.config, "test-build")
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err = restarted.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err = f.admin.QueryRow(ctx, `SELECT count(*) FROM assessment_decisions`).Scan(&decisions); err != nil {
		t.Fatal(err)
	}
	if decisions > 5 {
		t.Fatalf("restart duplicated decision: %d", decisions)
	}
	var candidatesAfter int
	if err = f.admin.QueryRow(ctx, `SELECT count(*) FROM assessment_candidates`).Scan(&candidatesAfter); err != nil {
		t.Fatal(err)
	}
	if candidatesAfter != 5 {
		t.Fatalf("restart changed physical sequence: %d", candidatesAfter)
	}
}

func TestAssessmentFirstFailureEvidenceImmutable(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	f.seedRun(t, at)
	id, _ := a.Identity("failure", f.config.Category, map[string]any{"run": f.config.RunID, "asset": f.config.Assets[0].EntityKey, "code": "COVERAGE", "scope_key": "fixture"})
	body, _ := a.Canonical(assessmentFailureBody{Schema: 1, FactIDs: []string{}, Message: "first", From: at, Through: at})
	f.exec(t, `INSERT INTO assessment_failures(run_id,id,category,asset,kind,code,scope_key,first_at,last_at,count,body) VALUES($1,$2,$3,$4,'COVERAGE','COVERAGE','fixture',$5,$5,1,$6)`, f.config.RunID, id, f.config.Category, f.config.Assets[0].EntityKey, at, body)
	changed, _ := a.Canonical(assessmentFailureBody{Schema: 1, FactIDs: []string{}, Message: "replacement", From: at, Through: at})
	if _, err := f.admin.Exec(ctx, `UPDATE assessment_failures SET body=$2 WHERE id=$1`, id, changed); err == nil {
		t.Fatal("first evidence rewritten")
	}
	f.exec(t, `UPDATE assessment_failures SET last_at=clock_timestamp(),count=count+1 WHERE id=$1`, id)
}

func TestAssessmentRetentionUpdateReservationsAcrossBatches(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	f.config.Limits.PhysicalCandidates = 256
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-8 * 24 * time.Hour)
	f.seedRun(t, at)
	asset := f.config.Assets[0]
	bindings, _ := a.Canonical(f.config.Bindings)
	f.exec(t, `INSERT INTO assessment_enrollments(run_id,category,asset,node_id,gpu_uuid,inventory_revision,bindings,discovery_floor,next_due_at,sequence,revision,rearm_eligible) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,102,1,false)`, f.config.RunID, f.config.Category, asset.EntityKey, asset.NodeID, asset.GPUUUID, f.config.InventoryRevision, bindings, at)
	sample := a.Sample{Metric: cooling.Temperature, Unit: "celsius", SourceAt: at, CollectedAt: at, CompletedAt: at, Value: 75, SourceRecord: "sql-fixture", Provenance: a.Provenance{Mode: "fixture", CollectionRunID: "fixture", Operation: "fixture", ScheduleRevision: 1, InventoryRevision: "fixture", SourceRecord: "sql-fixture"}}
	fact, _ := a.NewFact(f.config.Category, f.config.RunID, asset.EntityKey, "SAMPLE", at, sample)
	body, _ := a.Canonical(fact)
	f.exec(t, `INSERT INTO assessment_facts(run_id,id,asset,kind,available_at,body) VALUES($1,$2,$3,'SAMPLE',$4,$5)`, f.config.RunID, fact.ID, asset.EntityKey, at, body)
	bundle, _ := a.NewBundle(f.config.Category, f.config.RunID, asset.EntityKey, at, []a.Fact{fact})
	bb, _ := a.Canonical(bundle)
	f.exec(t, `INSERT INTO assessment_bundles(run_id,id,asset,logical_at,availability_cutoff,body) VALUES($1,$2,$3,$4,$4,$5)`, f.config.RunID, bundle.ID, asset.EntityKey, at, bb)
	state, _ := a.NewPayload(f.config.Category, "candidate", 1, map[string]any{"schema": int64(1), "branches": []string{}})
	metadata, _ := a.Canonical(map[string]any{"schema": int64(1), "route": "hardware_investigation", "urgent_occurrences": []a.Occurrence{}})
	chosenCandidate, chosenUpdate := "", ""
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for seq := int64(1); seq <= 102; seq++ {
		id, _ := a.Identity("candidate", f.config.Category, map[string]any{"run": f.config.RunID, "category": f.config.Category, "asset": asset.EntityKey, "sequence": seq, "budget_ms": int64(0)})
		terminalID, _ := a.Identity("terminal", f.config.Category, map[string]any{"candidate": id})
		updateID, _ := a.Identity("update", f.config.Category, map[string]any{"candidate": id, "codes": []string{"higher_temperature"}})
		if chosenUpdate == "" || updateID < chosenUpdate {
			chosenCandidate, chosenUpdate = id, updateID
		}
		entry := a.Entry{Basis: "CATEGORY_CONCERN", AvailableAt: at, BundleID: bundle.ID, Support: []string{fact.ID}, Fallback: a.Fallback{Schema: 1, DueAt: at, Action: "INVESTIGATE", Route: "hardware_investigation", Summary: "SQL invariant fixture", TerminalID: terminalID}}
		eb, _ := a.Canonical(entry)
		terminal := a.Terminal{DecisionID: terminalID, LogicalAt: at, Action: "INVESTIGATE", UrgentOccurrences: []a.Occurrence{}}
		tb, _ := a.Canonical(terminal)
		if _, err = tx.Exec(ctx, `INSERT INTO assessment_candidates(run_id,id,category,asset,sequence,budget_ms,revision,phase,entered_at,due_at,entry_bundle,entry,initial_state,initial_hash,state,state_hash,terminal_id,terminal,reserved_codes) VALUES($1,$2,$3,$4,$5,0,1,'FINAL',$6,$6,$7,$8,$9,$10,$9,$10,$11,$12,'{}')`, f.config.RunID, id, f.config.Category, asset.EntityKey, seq, at, bundle.ID, eb, state.Body, state.Hash, terminalID, tb); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO assessment_decisions(run_id,id,candidate_id,kind,logical_at,executed_at,committed_at,lateness_us,action,decision_source,outcome,bundle_id,codes,reasons,support,summary,metadata) VALUES($1,$2,$3,'TERMINAL',$4,$4,$4,0,'INVESTIGATE','CATEGORY','gpu_cooling/UNRESOLVED_WARMING',$5,'{}','{}',$6,'SQL invariant fixture',$7)`, f.config.RunID, terminalID, id, at, bundle.ID, []string{fact.ID}, metadata); err != nil {
			t.Fatal(err)
		}
	}

	// A real comparison cohort arrives in one SQL statement. AFTER ROW triggers
	// see that statement's completed table, so each row must not recount it.
	cohortIDs, terminalIDs, entryBodies, terminalBodies := []string{}, []string{}, []string{}, []string{}
	budgets := []int64{0, 15000, 30000, 60000, 120000}
	for _, budget := range budgets {
		id, _ := a.Identity("candidate", f.config.Category, map[string]any{"run": f.config.RunID, "category": f.config.Category, "asset": asset.EntityKey, "sequence": int64(103), "budget_ms": budget})
		tid, _ := a.Identity("terminal", f.config.Category, map[string]any{"candidate": id})
		due := at.Add(time.Duration(budget) * time.Millisecond)
		entry := a.Entry{Basis: "CATEGORY_CONCERN", AvailableAt: at, BundleID: bundle.ID, Support: []string{fact.ID}, Fallback: a.Fallback{Schema: 1, DueAt: due, Action: "INVESTIGATE", Route: "hardware_investigation", Summary: "SQL cohort fixture", TerminalID: tid}}
		eb, _ := a.Canonical(entry)
		tb, _ := a.Canonical(a.Terminal{DecisionID: tid, LogicalAt: at, Action: "INVESTIGATE", UrgentOccurrences: []a.Occurrence{}})
		cohortIDs = append(cohortIDs, id)
		terminalIDs = append(terminalIDs, tid)
		entryBodies = append(entryBodies, string(eb))
		terminalBodies = append(terminalBodies, string(tb))
	}
	if _, err = tx.Exec(ctx, `INSERT INTO assessment_candidates(run_id,id,category,asset,sequence,budget_ms,revision,phase,entered_at,due_at,entry_bundle,entry,initial_state,initial_hash,state,state_hash,terminal_id,terminal,reserved_codes) SELECT $1,x.id,$2,$3,103,x.budget,1,'FINAL',$4,$4::timestamptz+x.budget*interval '1 millisecond',$5,convert_to(x.entry,'UTF8'),$6,$7,$6,$7,x.terminal_id,convert_to(x.terminal,'UTF8'),'{}' FROM unnest($8::text[],$9::bigint[],$10::text[],$11::text[],$12::text[]) x(id,budget,entry,terminal_id,terminal)`, f.config.RunID, f.config.Category, asset.EntityKey, at, bundle.ID, state.Body, state.Hash, cohortIDs, budgets, entryBodies, terminalIDs, terminalBodies); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO assessment_decisions(run_id,id,candidate_id,kind,logical_at,executed_at,committed_at,lateness_us,action,decision_source,outcome,bundle_id,codes,reasons,support,summary,metadata) SELECT $1,x.tid,x.cid,'TERMINAL',$2,$2,$2,0,'INVESTIGATE','CATEGORY','gpu_cooling/COOLING_SUSPECTED',$3,'{}','{}',$4,'SQL cohort fixture',$5 FROM unnest($6::text[],$7::text[]) x(tid,cid)`, f.config.RunID, at, bundle.ID, []string{fact.ID}, metadata, terminalIDs, cohortIDs); err != nil {
		t.Fatal(err)
	}
	var physical int64
	if err = tx.QueryRow(ctx, `SELECT physical_count FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&physical); err != nil || physical != 103 {
		t.Fatalf("multirow physical count=%d error=%v", physical, err)
	}
	if _, err = tx.Exec(ctx, `UPDATE assessment_candidates SET reserved_codes=ARRAY['higher_temperature'],revision=revision+1 WHERE run_id=$1 AND id=$2`, f.config.RunID, chosenCandidate); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO assessment_decisions(run_id,id,candidate_id,kind,logical_at,executed_at,committed_at,lateness_us,action,decision_source,bundle_id,codes,reasons,support,summary,metadata) VALUES($1,$2,$3,'UPDATE',$4,$4,$4,0,'INVESTIGATE','CATEGORY',$5,ARRAY['higher_temperature'],'{}',$6,'SQL invariant fixture',$7)`, f.config.RunID, chosenUpdate, chosenCandidate, at, bundle.ID, []string{fact.ID}, metadata); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE assessment_runs SET state='CLOSED',stopped_at=admission_end_at,stop_reason='DURATION',closed_at=admission_end_at WHERE run_id=$1`, f.config.RunID)
	store := &AssessmentStore{pool: f.admin}
	n, err := store.Cleanup(ctx)
	if err != nil || n != 100 {
		t.Fatalf("first bounded cleanup %d %v", n, err)
	}
	var updateExists, candidateExists bool
	if err = f.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM assessment_decisions WHERE id=$1),EXISTS(SELECT 1 FROM assessment_candidates WHERE id=$2)`, chosenUpdate, chosenCandidate).Scan(&updateExists, &candidateExists); err != nil {
		t.Fatal(err)
	}
	if updateExists || !candidateExists {
		t.Fatal("fixture did not exercise surviving reservation after update removal")
	}
	for i := 0; i < 5; i++ {
		n, err = store.Cleanup(ctx)
		if err != nil || n > 100 {
			t.Fatalf("cleanup %d %v", n, err)
		}
		if n == 0 {
			return
		}
	}
	t.Fatal("retention did not finish")
}

func TestAssessmentDeferredSourceEligibilityAfterReload(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	f.seedRun(t, at)
	asset := f.config.Assets[0]
	bindings, _ := a.Canonical(f.config.Bindings)
	f.exec(t, `INSERT INTO assessment_enrollments(run_id,category,asset,node_id,gpu_uuid,inventory_revision,bindings,discovery_floor,next_due_at,sequence,revision,rearm_eligible) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,0,1,true)`, f.config.RunID, f.config.Category, asset.EntityKey, asset.NodeID, asset.GPUUUID, f.config.InventoryRevision, bindings, at)
	engine, err := a.NewEngine(ctx, f.config, at, f.registry)
	if err != nil {
		t.Fatal(err)
	}
	facts := []a.Fact{}
	for _, sec := range []int64{-30, -15, 0, 15} {
		source := at.Add(time.Duration(sec) * time.Second)
		value := 75.0
		if sec == -30 {
			value = 74.9
		}
		sample := a.Sample{Metric: cooling.Temperature, Unit: "celsius", SourceAt: source, CollectedAt: at, CompletedAt: at, Value: value, SourceRecord: fmt.Sprintf("future-%d", sec), Provenance: a.Provenance{Mode: "fixture", CollectionRunID: "fixture", Operation: string(domain.OperationPrometheusGPUTemperature), ScheduleRevision: 1, InventoryRevision: f.config.InventoryRevision, SourceRecord: fmt.Sprintf("future-%d", sec)}}
		fact, err := a.NewFact(f.config.Category, f.config.RunID, asset.EntityKey, "SAMPLE", at, sample)
		if err != nil {
			t.Fatal(err)
		}
		facts = append(facts, fact)
	}
	if err = engine.Advance(ctx, at, at, at, facts, nil); err != nil {
		t.Fatal(err)
	}
	if len(engine.Candidates) != 0 {
		t.Fatal("future sample qualified early")
	}
	store := &AssessmentStore{pool: f.admin, registry: f.registry, config: f.config}
	snapshot := newAssessmentSnapshot()
	snapshot.enrollmentRevision[asset.EntityKey] = 1
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.saveEngine(ctx, tx, engine, snapshot, at, []string{asset.EntityKey}); err != nil {
		tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	wake := at.Add(25 * time.Second)
	tx, err = f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	restored, snap, err := store.loadEngine(ctx, tx, wake)
	if err != nil {
		t.Fatal(err)
	}
	restored.Shadow = false // Logical simulation; resource budget is qualified separately.
	if err = restored.AdvanceAssets(ctx, wake, wake, wake, nil, nil, []string{asset.EntityKey}); err != nil {
		t.Fatal(err)
	}
	if len(restored.Candidates) != 5 {
		t.Fatalf("deferred restart candidates=%d failures=%+v", len(restored.Candidates), restored.Failures)
	}
	for _, candidate := range restored.Candidates {
		if !candidate.EnteredAt.Equal(at.Add(15 * time.Second)) {
			t.Fatalf("entry moved on restart: %s", candidate.EnteredAt)
		}
		if !candidate.DueAt.Equal(candidate.EnteredAt.Add(time.Duration(candidate.BudgetMS) * time.Millisecond)) {
			t.Fatal("deadline changed")
		}
	}
	if err = store.saveEngine(ctx, tx, restored, snap, wake, []string{asset.EntityKey}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestAssessmentAccountingIndependentOfSessionEncoding(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	f.seedRun(t, at)
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL bytea_output='escape'`); err != nil {
		t.Fatal(err)
	}
	fact, err := a.NewFact(f.config.Category, f.config.RunID, f.config.Assets[0].EntityKey, "COVERAGE", at, a.Coverage{Metric: cooling.Temperature, From: at, Through: at, Code: "UNKNOWN", SourceRecord: "encoding-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := a.Canonical(fact)
	if err != nil {
		t.Fatal(err)
	}
	var before, after int64
	if err = tx.QueryRow(ctx, `SELECT payload_bytes FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO assessment_facts(run_id,id,asset,kind,available_at,body) VALUES($1,$2,$3,$4,$5,$6)`, fact.Run, fact.ID, fact.Asset, fact.Kind, fact.AvailableAt, body); err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRow(ctx, `SELECT payload_bytes FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	want := len(fact.Run) + len(fact.ID) + len(fact.Asset) + len(fact.Kind) + 8 + len(body)
	if after-before != int64(want) {
		t.Fatalf("session-dependent bytes=%d want=%d", after-before, want)
	}
	codes := []string{"<&>\u2028\u2029", "quote\"and\\slash"}
	encoded, err := a.Canonical(codes)
	if err != nil {
		t.Fatal(err)
	}
	var counted int64
	if err = tx.QueryRow(ctx, `SELECT assessment_row_bytes('assessment_decisions',jsonb_build_object('codes',$1::text[]))`, codes).Scan(&counted); err != nil {
		t.Fatal(err)
	}
	if counted != int64(len(encoded)) {
		t.Fatalf("array bytes=%d canonical=%d", counted, len(encoded))
	}
}

func TestAssessmentDueCommitSurvivesSourceReadFailure(t *testing.T) {
	f := newAssessmentFixture(t)
	f.config.RunDurationSeconds = 600
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-3 * time.Minute)
	f.seedRun(t, at)
	asset := f.config.Assets[0]
	bindings, _ := a.Canonical(f.config.Bindings)
	f.exec(t, `INSERT INTO assessment_enrollments(run_id,category,asset,node_id,gpu_uuid,inventory_revision,bindings,discovery_floor,next_due_at,sequence,revision,rearm_eligible) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,0,1,true)`, f.config.RunID, f.config.Category, asset.EntityKey, asset.NodeID, asset.GPUUUID, f.config.InventoryRevision, bindings, at)
	engine, err := a.NewEngine(ctx, f.config, at, f.registry)
	if err != nil {
		t.Fatal(err)
	}
	facts := []a.Fact{}
	for _, sec := range []int64{-30, -15, 0} {
		record := fmt.Sprintf("due-%d", sec)
		sample := a.Sample{Metric: cooling.Temperature, Unit: "celsius", SourceAt: at.Add(time.Duration(sec) * time.Second), CollectedAt: at, CompletedAt: at, Value: 75, SourceRecord: record, Provenance: a.Provenance{Mode: "fixture", CollectionRunID: "fixture", Operation: string(domain.OperationPrometheusGPUTemperature), ScheduleRevision: 1, InventoryRevision: f.config.InventoryRevision, SourceRecord: record}}
		fact, err := a.NewFact(f.config.Category, f.config.RunID, asset.EntityKey, "SAMPLE", at, sample)
		if err != nil {
			t.Fatal(err)
		}
		facts = append(facts, fact)
	}
	if err = engine.Advance(ctx, at, at, at, facts, nil); err != nil {
		t.Fatal(err)
	}
	if len(engine.Candidates) != 5 {
		t.Fatalf("entry candidates=%d", len(engine.Candidates))
	}
	s := &AssessmentStore{pool: f.admin, registry: f.registry, config: f.config}
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	snap := newAssessmentSnapshot()
	snap.enrollmentRevision[asset.EntityKey] = 1
	if err = s.saveEngine(ctx, tx, engine, snap, at, []string{asset.EntityKey}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	s.pool = f.restrictedPool(t)
	f.exec(t, `REVOKE SELECT ON desired_schedules FROM sherlock_assessment`)
	if err = s.Refresh(ctx); err == nil {
		t.Fatal("source permission failure was not surfaced")
	}
	var terminal int
	if err = f.admin.QueryRow(ctx, `SELECT count(*) FROM assessment_decisions WHERE kind='TERMINAL'`).Scan(&terminal); err != nil {
		t.Fatal(err)
	}
	if terminal != 5 {
		t.Fatalf("source rollback lost due dispositions: %d", terminal)
	}
	var gap []byte
	if err = f.admin.QueryRow(ctx, `SELECT coverage FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&gap); err != nil {
		t.Fatal(err)
	}
	var spans []assessmentCoverageInterval
	if err = a.DecodeStrict(gap, &spans, 256<<10); err != nil {
		t.Fatal(err)
	}
	if len(spans) != 2 || spans[0].Code != "COVERAGE" || !spans[0].From.Equal(at) || spans[1].Code != "STORE_UNAVAILABLE" || spans[1].Through.Sub(spans[1].From) >= 5*time.Second {
		t.Fatalf("missed acquisition interval=%s", gap)
	}
}

func TestAssessmentLiveObservingCannotCommitAfterDeadline(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-20 * time.Second)
	f.seedRun(t, at, "shadow")
	asset := f.config.Assets[0]
	bindings, _ := a.Canonical(f.config.Bindings)
	f.exec(t, `INSERT INTO assessment_enrollments(run_id,category,asset,node_id,gpu_uuid,inventory_revision,bindings,discovery_floor,next_due_at,sequence,revision,rearm_eligible) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,1,1,false)`, f.config.RunID, f.config.Category, asset.EntityKey, asset.NodeID, asset.GPUUUID, f.config.InventoryRevision, bindings, at)
	bundle, _ := a.NewBundle(f.config.Category, f.config.RunID, asset.EntityKey, at, nil)
	body, _ := a.Canonical(bundle)
	f.exec(t, `INSERT INTO assessment_bundles(run_id,id,asset,logical_at,availability_cutoff,body) VALUES($1,$2,$3,$4,$4,$5)`, f.config.RunID, bundle.ID, asset.EntityKey, at, body)
	id, _ := a.Identity("candidate", f.config.Category, map[string]any{"run": f.config.RunID, "category": f.config.Category, "asset": asset.EntityKey, "sequence": int64(1), "budget_ms": int64(15000)})
	state, _ := a.NewPayload(f.config.Category, "candidate", 1, map[string]any{})
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO assessment_candidates(run_id,id,category,asset,sequence,budget_ms,revision,phase,entered_at,due_at,entry_bundle,entry,initial_state,initial_hash,state,state_hash) VALUES($1,$2,$3,$4,1,15000,1,'OBSERVING',$5,$6,$7,$8,$9,$10,$9,$10)`, f.config.RunID, id, f.config.Category, asset.EntityKey, at, at.Add(15*time.Second), bundle.ID, []byte(`{}`), state.Body, state.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err == nil || !strings.Contains(err.Error(), "assessment deadline crossed") {
		t.Fatalf("stale observing commit=%v", err)
	}
	var count int
	if err = f.admin.QueryRow(ctx, `SELECT count(*) FROM assessment_candidates`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed disposition retained rows=%d err=%v", count, err)
	}
}

// This opt-in exercise runs the actual CLI against a disposable SQL snapshot.
// It is separate from performance qualification and may invoke the Go compiler.
func TestAssessmentClosedLargeDatabaseCLIArchive(t *testing.T) {
	if os.Getenv("SHERLOCK_ENABLE_ASSESSMENT_ARCHIVE") != "1" {
		t.Skip("explicit large SQL/CLI archive exercise")
	}
	f := newAssessmentFixture(t)
	ctx := context.Background()
	f.config.RunDurationSeconds = 3601
	f.config.Limits.PayloadBytes = 64 << 20
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-2 * time.Hour)
	end := at.Add(3601 * time.Second)
	f.seedRun(t, at)
	asset := f.config.Assets[0]
	bindings, _ := a.Canonical(f.config.Bindings)
	f.exec(t, `INSERT INTO assessment_enrollments(run_id,category,asset,node_id,gpu_uuid,inventory_revision,bindings,discovery_floor,next_due_at,sequence,revision,rearm_eligible) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,0,1,true)`, f.config.RunID, f.config.Category, asset.EntityKey, asset.NodeID, asset.GPUUUID, f.config.InventoryRevision, bindings, at, end)
	const count = 1500
	for base := 0; base < count; base += 50 {
		n := min(50, count-base)
		copied, err := f.admin.CopyFrom(ctx, pgx.Identifier{"assessment_facts"}, []string{"run_id", "id", "asset", "kind", "available_at", "body"}, pgx.CopyFromSlice(n, func(i int) ([]any, error) {
			n := base + i
			stamp := at.Add(time.Duration(n/550) * 901 * time.Second)
			snapshot := make([]a.SnapshotEntry, 32)
			for j := range snapshot {
				snapshot[j] = a.SnapshotEntry{Metric: strings.Repeat("m", 128), Unit: strings.Repeat("u", 128), SourceAt: stamp, Support: "UNKNOWN"}
			}
			fact, err := a.NewFact(f.config.Category, f.config.RunID, asset.EntityKey, "QUALIFIED", stamp, a.Qualified{PolicyID: "inert-warning", Occurrence: int64(n + 1), Transition: "OPEN", Rule: "gpu_thermal", RuleVersion: 1, EnrollmentRevision: 1, Severity: "WARNING", QualifiedAt: stamp, Snapshot: snapshot})
			if err != nil {
				return nil, err
			}
			body, err := a.Canonical(fact)
			return []any{fact.Run, fact.ID, fact.Asset, fact.Kind, fact.AvailableAt, body}, err
		}))
		if err != nil || copied != int64(n) {
			t.Fatalf("archive seed count=%d err=%v", copied, err)
		}
	}
	f.exec(t, `UPDATE assessment_runs SET state='CLOSED',stopped_at=admission_end_at,stop_reason='DURATION',closed_at=$2 WHERE run_id=$1`, f.config.RunID, end)
	var payload int64
	if err := f.admin.QueryRow(ctx, `SELECT payload_bytes FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&payload); err != nil || payload <= 16<<20 {
		t.Fatalf("payload=%d err=%v", payload, err)
	}
	pool := f.restrictedPool(t)
	u, err := url.Parse(f.dsn)
	if err != nil {
		t.Fatal("fixture URL invalid")
	}
	u.User = url.UserPassword(f.role, pool.Config().ConnConfig.Password)
	root := t.TempDir()
	if output := os.Getenv("SHERLOCK_ASSESSMENT_ARTIFACT_DIR"); output != "" {
		root, err = os.MkdirTemp(output, "sql-cli-archive-")
		if err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(root, "archive")
	first, second := filepath.Join(root, "first"), filepath.Join(root, "second")
	runCLI := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "go", append([]string{"run", "./cmd/sherlock-assessment"}, args...)...)
		cmd.Dir = "../../.."
		cmd.Env = append(os.Environ(), "SHERLOCK_ASSESSMENT_DATABASE_URL="+u.String())
		body, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("CLI failed: %v; %s", err, strings.ReplaceAll(string(body), u.String(), "[disposable database]"))
		}
	}
	runCLI("export", "-run", f.config.RunID, "-out", archive)
	runCLI("replay", "-archive", archive, "-out", first)
	runCLI("replay", "-archive", archive, "-out", second)
	for _, name := range []string{"report.md", "comparison.json", "labels.ndjson", "evidence.ndjson", "manifest.json", "semantic.json", "observed.json", "execution.json"} {
		left, err := os.ReadFile(filepath.Join(first, name))
		if err != nil {
			t.Fatal(err)
		}
		right, err := os.ReadFile(filepath.Join(second, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(left) != string(right) {
			t.Fatalf("SQL archive replay %s differs", name)
		}
	}
	manifest, err := os.ReadFile(filepath.Join(archive, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m a.ArchiveManifest
	if err = a.DecodeStrict(manifest, &m, 256<<10); err != nil {
		t.Fatal(err)
	}
	if !m.Complete || m.SourcePayloadBytes != payload || len(m.Chunks) < 3 || m.Provenance != "SYNTHETIC" {
		t.Fatalf("SQL archive manifest=%+v", m)
	}
	for _, chunk := range m.Chunks {
		if chunk.Bytes > 8<<20 {
			t.Fatal("oversized archive chunk")
		}
	}
	t.Logf("SQL_ARCHIVE canonical_payload_bytes=%d records=%d chunks=%d repeated_report_identical=true artifact_directory=%s", payload, m.RecordCount, len(m.Chunks), root)
}

func TestAssessmentClosedRestartContinuesRetention(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	var now time.Time
	if err := f.admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	at := now.UTC().Add(-8 * 24 * time.Hour)
	body, err := a.Canonical(assessmentFailureBody{Schema: 1, FactIDs: []string{}, Message: "Retention fixture", From: at.UTC(), Through: at.UTC()})
	if err != nil {
		t.Fatal(err)
	}
	seed := func(runID string) {
		t.Helper()
		f.config.RunID = runID
		f.seedRun(t, at, "shadow")
		f.seedEnrollment(t, at)
		f.exec(t, `INSERT INTO assessment_failures(run_id,id,category,kind,code,scope_key,first_at,last_at,count,body)
		    SELECT $1,lpad(n::text,64,'0'),$2,'COVERAGE','COVERAGE','fixture-'||n,$3,$3,1,$4 FROM generate_series(1,101) n`, runID, f.config.Category, at, body)
	}
	closeRun := func(closedAt time.Time) {
		t.Helper()
		f.exec(t, `UPDATE assessment_runs SET state='CLOSED',stopped_at=admission_end_at,stop_reason='DURATION',
		    closed_at=$2 WHERE run_id=$1`, f.config.RunID, closedAt)
	}
	pool := f.restrictedPool(t)
	start := func(registry *a.Registry) *AssessmentStore {
		t.Helper()
		store, err := NewAssessmentStore(ctx, pool, registry, f.config, "retention-fixture")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Start(ctx); err != nil {
			t.Fatal(err)
		}
		return store
	}
	pass := func(store *AssessmentStore, want int) {
		t.Helper()
		if err := store.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		if n, err := store.Cleanup(ctx); err != nil || n != want {
			t.Fatalf("cleanup removed %d rows, want %d: %v", n, want, err)
		}
	}

	seed("retention-unexpired")
	closeRun(now)
	pass(start(f.registry), 0)
	var state string
	var count int
	if err := f.admin.QueryRow(ctx, `SELECT state,record_count FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&state, &count); err != nil || state != "CLOSED" || count != 103 {
		t.Fatalf("unexpired run state=%s rows=%d: %v", state, count, err)
	}
	mismatch := f.config
	mismatch.RunDurationSeconds++
	rejected, err := NewAssessmentStore(ctx, pool, f.registry, mismatch, "retention-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := rejected.Start(ctx); !errors.Is(err, ErrAssessmentRunBusy) {
		t.Fatalf("changed config accepted for retained run: %v", err)
	}

	const expiredRun = "retention-expired"
	seed(expiredRun)
	original := start(f.registry)
	end := at.Add(time.Duration(f.config.RunDurationSeconds) * time.Second)
	closeRun(end)
	restarted := start(f.registry)
	unavailable, err := a.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	rollback := start(unavailable)

	f.config.RunID = "retention-backlog"
	f.seedRun(t, at.Add(time.Hour), "shadow")
	closeRun(end.Add(time.Hour))
	f.config.RunID = "retention-active"
	f.seedRun(t, at, "shadow")
	f.seedEnrollment(t, at)

	pass(restarted, 100)
	pass(rollback, 3)

	// Even after another worker deletes the configured run, every started
	// store remains usable for retention and cannot create a new enrollment.
	original.noteAssessmentFailure(time.Now(), errors.New("synthetic delayed failure"))
	for _, store := range []*AssessmentStore{original, restarted, rollback} {
		if err := store.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		if err := store.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM assessment_runs WHERE run_id=$1`, expiredRun).Scan(&count); err != nil || count != 0 {
		t.Fatalf("assessment run recreated, rows=%d: %v", count, err)
	}
	pass(restarted, 1)
	pass(restarted, 0)
	if err := f.admin.QueryRow(ctx, `SELECT record_count FROM assessment_runs WHERE run_id=$1 AND state='ACTIVE'`, f.config.RunID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("active run rows=%d: %v", count, err)
	}
}

func TestAssessmentClockUsesDatabaseEpoch(t *testing.T) {
	sample := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := assessmentDatabaseClock(sample)
	actual := clock()
	if actual.Before(sample) || actual.After(sample.Add(time.Second)) || actual.Location() != time.UTC || actual.Nanosecond()%1000 != 0 {
		t.Fatalf("clock substituted host epoch: %s", actual)
	}
}

func (f *assessmentFixture) seedEnrollment(t *testing.T, at time.Time) {
	t.Helper()
	asset := f.config.Assets[0]
	bindings, err := a.Canonical(f.config.Bindings)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO assessment_enrollments(run_id,category,asset,node_id,gpu_uuid,inventory_revision,bindings,discovery_floor,next_due_at,sequence,revision,rearm_eligible) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,0,1,true)`, f.config.RunID, f.config.Category, asset.EntityKey, asset.NodeID, asset.GPUUUID, f.config.InventoryRevision, bindings, at)
}

func TestAssessmentEmptyLiveRunClosesAtAdmissionEnd(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-2 * time.Minute)
	f.seedRun(t, at, "shadow")
	f.seedEnrollment(t, at)
	pool := f.restrictedPool(t)
	s := &AssessmentStore{pool: pool, registry: f.registry, config: f.config}
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	var state string
	var ordered bool
	if err := f.admin.QueryRow(ctx, `SELECT state,closed_at>=stopped_at AND stopped_at>=start_at FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&state, &ordered); err != nil || state != "CLOSED" || !ordered {
		t.Fatalf("state=%s ordered=%v err=%v", state, ordered, err)
	}
	pool.Close()
	if err := s.Refresh(ctx); err != nil {
		t.Fatal("closed run attempted another refresh", err)
	}
}

func TestAssessmentShortSourceFailureIsDurableWithoutGap(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	f.seedRun(t, at)
	f.seedEnrollment(t, at)
	s := &AssessmentStore{pool: f.restrictedPool(t), registry: f.registry, config: f.config}
	f.exec(t, `REVOKE SELECT ON desired_schedules FROM sherlock_assessment`)
	for range 2 {
		if err := s.Refresh(ctx); err == nil {
			t.Fatal("missing source permission unexpectedly succeeded")
		}
	}
	var count int64
	var body []byte
	if err := f.admin.QueryRow(ctx, `SELECT count,body FROM assessment_failures WHERE run_id=$1 AND scope_key='refresh' AND code='STORE_UNAVAILABLE'`, f.config.RunID).Scan(&count, &body); err != nil {
		t.Fatal(err)
	}
	var failure assessmentFailureBody
	if err := a.DecodeStrict(body, &failure, 16384); err != nil {
		t.Fatal(err)
	}
	if count != 2 || failure.Through.Sub(failure.From) >= 5*time.Second {
		t.Fatalf("count=%d interval=%s", count, failure.Through.Sub(failure.From))
	}
	var coverage []byte
	if err := f.admin.QueryRow(ctx, `SELECT coverage FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&coverage); err != nil {
		t.Fatal(err)
	}
	var spans []assessmentCoverageInterval
	if err := a.DecodeStrict(coverage, &spans, 256<<10); err != nil {
		t.Fatal(err)
	}
	if len(spans) != 2 {
		t.Fatalf("attempt intervals=%s", coverage)
	}
}

func TestAssessmentDueFactCapRetriesTrustedFallback(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	f.config.RunDurationSeconds = 7200
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-3 * time.Minute)
	runStart := at.Add(-time.Hour)
	asset := f.config.Assets[0]
	makeSample := func(sec int64) a.Fact {
		stamp := at.Add(time.Duration(sec) * time.Second)
		record := fmt.Sprintf("fact-cap-%d", sec)
		sample := a.Sample{Metric: cooling.Temperature, Unit: "celsius", SourceAt: stamp, CollectedAt: at, CompletedAt: at, Value: 75, SourceRecord: record, Provenance: a.Provenance{Mode: "fixture", CollectionRunID: "fixture", Operation: string(domain.OperationPrometheusGPUTemperature), ScheduleRevision: 1, InventoryRevision: f.config.InventoryRevision, SourceRecord: record}}
		available := at
		if sec > 0 {
			available = stamp
		}
		fact, err := a.NewFact(f.config.Category, f.config.RunID, asset.EntityKey, "SAMPLE", available, sample)
		if err != nil {
			t.Fatal(err)
		}
		return fact
	}
	initial := []a.Fact{makeSample(-30), makeSample(-15), makeSample(0)}
	makeEngine := func() *a.Engine {
		engine, err := a.NewEngine(ctx, f.config, runStart, f.registry)
		if err != nil {
			t.Fatal(err)
		}
		if err = engine.Advance(ctx, at, at, at, initial, nil); err != nil {
			t.Fatal(err)
		}
		if len(engine.Candidates) != 5 {
			t.Fatalf("fixture candidates=%d", len(engine.Candidates))
		}
		return engine
	}
	probe := makeEngine()
	f.config.Limits.FactCount = int64(len(probe.Facts) + 21)
	engine := makeEngine()
	f.seedRun(t, runStart)
	f.seedEnrollment(t, runStart)
	s := &AssessmentStore{pool: f.admin, registry: f.registry, config: f.config}
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	snap := newAssessmentSnapshot()
	snap.enrollmentRevision[asset.EntityKey] = 1
	if err = s.saveEngine(ctx, tx, engine, snap, at, []string{asset.EntityKey}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	later := makeSample(15)
	body, err := a.Canonical(later)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO assessment_facts(run_id,id,asset,kind,available_at,body) VALUES($1,$2,$3,$4,$5,$6)`, later.Run, later.ID, later.Asset, later.Kind, later.AvailableAt, body)
	for i := 0; i < 20; i++ {
		stamp := runStart.Add(time.Duration(i) * time.Second)
		record := fmt.Sprintf("old-padding-%d", i)
		oldSample := a.Sample{Metric: cooling.Temperature, Unit: "celsius", SourceAt: stamp, CollectedAt: stamp, CompletedAt: stamp, Value: 70, SourceRecord: record, Provenance: a.Provenance{Mode: "fixture", CollectionRunID: record, Operation: string(domain.OperationPrometheusGPUTemperature), ScheduleRevision: 1, InventoryRevision: f.config.InventoryRevision, SourceRecord: record}}
		old, err := a.NewFact(f.config.Category, f.config.RunID, asset.EntityKey, "SAMPLE", stamp, oldSample)
		if err != nil {
			t.Fatal(err)
		}
		oldBody, err := a.Canonical(old)
		if err != nil {
			t.Fatal(err)
		}
		f.exec(t, `INSERT INTO assessment_facts(run_id,id,asset,kind,available_at,body) VALUES($1,$2,$3,$4,$5,$6)`, old.Run, old.ID, old.Asset, old.Kind, old.AvailableAt, oldBody)
	}
	s.pool = f.restrictedPool(t)
	if err = s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	var state string
	var facts, terminals, fallbacks, markers int64
	if err = f.admin.QueryRow(ctx, `SELECT state,fact_count,(SELECT count(*) FROM assessment_decisions WHERE kind='TERMINAL'),(SELECT count(*) FROM assessment_decisions WHERE decision_source='HOST_FALLBACK' AND failure_code='CAPACITY'),(SELECT count(*) FROM assessment_failures WHERE scope_key='deadline_capacity') FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&state, &facts, &terminals, &fallbacks, &markers); err != nil {
		t.Fatal(err)
	}
	if state != "CLOSED" || facts != f.config.Limits.FactCount || terminals != 5 || fallbacks != 4 || markers != 1 {
		t.Fatalf("state=%s facts=%d terminals=%d capacity_fallbacks=%d markers=%d", state, facts, terminals, fallbacks, markers)
	}
}

func TestAssessmentCapacityMarkerSurvivesUnavailableWrite(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	f.seedRun(t, at)
	f.seedEnrollment(t, at)
	s := &AssessmentStore{pool: f.restrictedPool(t), registry: f.registry, config: f.config}
	s.noteAssessmentFailure(time.Now(), errors.Join(ErrAssessmentCapacity, context.DeadlineExceeded), "deadline_capacity")
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.flushAssessmentFailure(canceled); err == nil || s.pendingFailure == nil {
		t.Fatal("failed metadata write lost pending cause")
	}
	if err := s.flushAssessmentFailure(ctx); err != nil {
		t.Fatal(err)
	}
	var state, reason string
	var markers int
	if err := f.admin.QueryRow(ctx, `SELECT state,stop_reason,(SELECT count(*) FROM assessment_failures WHERE scope_key='deadline_capacity' AND code='CAPACITY') FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&state, &reason, &markers); err != nil || state != "DRAINING" || reason != "CAPACITY" || markers != 1 {
		t.Fatalf("state=%s reason=%s markers=%d err=%v", state, reason, markers, err)
	}
}

func TestAssessmentOuterDeadlineRetainsFailure(t *testing.T) {
	f := newAssessmentFixture(t)
	at := time.Now().UTC().Truncate(time.Microsecond)
	f.seedRun(t, at)
	f.seedEnrollment(t, at)
	pool := f.restrictedPool(t)
	ctx := context.Background()
	// Exhaust the dedicated two-connection pool so the scheduler's own context,
	// rather than a PostgreSQL statement timeout, ends the attempt.
	held := []*pgxpool.Conn{}
	for range pool.Config().MaxConns {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
	}
	s := &AssessmentStore{pool: pool, registry: f.registry, config: f.config}
	outer, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	err := s.Refresh(outer)
	cancel()
	for _, conn := range held {
		conn.Release()
	}
	if !errors.Is(err, context.DeadlineExceeded) || s.pendingFailure == nil || s.pendingFailure.code != "TIME_BUDGET" {
		t.Fatalf("lost outer deadline: %v pending=%+v", err, s.pendingFailure)
	}
	if err := s.flushAssessmentFailure(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM assessment_failures WHERE code='TIME_BUDGET' AND scope_key='refresh'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("durable timeout=%d err=%v", count, err)
	}
}

func TestAssessmentPendingFailureDefersClosure(t *testing.T) {
	f := newAssessmentFixture(t)
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-2 * time.Minute)
	f.seedRun(t, at, "shadow")
	f.seedEnrollment(t, at)
	s := &AssessmentStore{pool: f.restrictedPool(t), registry: f.registry, config: f.config}
	s.noteAssessmentFailure(time.Now(), context.DeadlineExceeded)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.flushAssessmentFailure(canceled); err == nil {
		t.Fatal("expected failed initial flush")
	}
	// The due transaction is still allowed to finish its work after that failure,
	// but closure must wait until the pending attempt has been durably recorded.
	if err := s.refreshAssessment(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := f.admin.QueryRow(context.Background(), `SELECT state FROM assessment_runs`).Scan(&state); err != nil || state != "DRAINING" {
		t.Fatalf("premature close=%s %v", state, err)
	}
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	var failures int
	if err := f.admin.QueryRow(context.Background(), `SELECT state,(SELECT count(*) FROM assessment_failures WHERE code='TIME_BUDGET') FROM assessment_runs`).Scan(&state, &failures); err != nil || state != "CLOSED" || failures != 1 {
		t.Fatalf("final=%s failures=%d %v", state, failures, err)
	}
}

func TestAssessmentDeadlineCapacitySurvivesFullDiagnostics(t *testing.T) {
	f := newAssessmentFixture(t)
	f.seedSource(t, true)
	ctx := context.Background()
	pool := f.restrictedPool(t)
	s, err := NewAssessmentStore(ctx, pool, f.registry, f.config, "full-diagnostics")
	if err != nil {
		t.Fatal(err)
	}
	start := stageAssessmentWarmEntries(t, f, s)
	spans := make([]assessmentCoverageInterval, 1024)
	body, _ := a.Canonical(assessmentFailureBody{Schema: 1, FactIDs: []string{}, Message: "fixture", From: start, Through: start})
	batch := &pgx.Batch{}
	for i := range spans {
		// Deliberately non-contiguous intervals exercise interior-gap preservation.
		from := start.Add(time.Duration(i) * time.Microsecond)
		spans[i] = assessmentCoverageInterval{from, from, "COVERAGE", 1}
		scope := fmt.Sprintf("full-%d", i)
		id, _ := a.Identity("failure", f.config.Category, map[string]any{"run": f.config.RunID, "code": "COVERAGE", "scope_key": scope})
		batch.Queue(`INSERT INTO assessment_failures(run_id,id,category,kind,code,scope_key,first_at,last_at,count,body) VALUES($1,$2,$3,'COVERAGE','COVERAGE',$4,$5,$5,1,$6)`, f.config.RunID, id, f.config.Category, scope, start, body)
	}
	results := f.admin.SendBatch(ctx, batch)
	if err := results.Close(); err != nil {
		t.Fatal(err)
	}
	encoded, _ := a.Canonical(spans)
	f.exec(t, `UPDATE assessment_runs SET coverage=$2 WHERE run_id=$1`, f.config.RunID, encoded)
	s.noteAssessmentFailure(time.Now(), ErrAssessmentCapacity, "deadline_capacity")
	if err := s.flushAssessmentFailure(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.QueryRow(ctx, `SELECT coverage FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	if err := a.DecodeStrict(encoded, &spans, 256<<10); err != nil {
		t.Fatal(err)
	}
	markers := 0
	count := int64(0)
	for _, span := range spans {
		count += span.Count
		if span.Code == "DEADLINE_CAPACITY" {
			markers++
		}
	}
	if len(spans) != 1024 || markers != 1 || count != 1025 {
		t.Fatalf("summary rows=%d markers=%d count=%d", len(spans), markers, count)
	}
	restarted := &AssessmentStore{pool: pool, registry: f.registry, config: f.config}
	tx, err := beginAssessmentTx(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	wake := start.Add(130 * time.Second)
	engine, _, err := restarted.loadEngine(ctx, tx, wake, true)
	if err != nil {
		t.Fatal(err)
	}
	if engine.ExpiryFailure[""] != "CAPACITY" || len(engine.Facts) != 0 {
		t.Fatalf("marker not restored: %v facts=%d", engine.ExpiryFailure, len(engine.Facts))
	}
	engine.Shadow = false
	if err := engine.AdvanceAssets(ctx, wake, wake, wake, nil, nil, []string{}); err != nil {
		t.Fatal(err)
	}
	if len(engine.Decisions) != 4 || engine.State != "CLOSED" {
		t.Fatalf("fallback decisions=%d state=%s", len(engine.Decisions), engine.State)
	}
	for _, d := range engine.Decisions {
		if d.DecisionSource != "HOST_FALLBACK" || d.FailureCode != "CAPACITY" {
			t.Fatalf("category invoked after capacity: %+v", d)
		}
	}
}

func TestAssessmentDiscoveryOverflowIsDurable(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	f.seedRun(t, at)
	f.seedEnrollment(t, at)
	asset := f.config.Assets[0].EntityKey
	_, err := f.admin.CopyFrom(ctx, pgx.Identifier{"assessment_facts"}, []string{"run_id", "id", "asset", "kind", "available_at", "body"}, pgx.CopyFromSlice(1025, func(i int) ([]any, error) {
		fact, err := a.NewFact(f.config.Category, f.config.RunID, asset, "COVERAGE", at, a.Coverage{Metric: cooling.Temperature, From: at, Through: at, Code: "UNKNOWN", SourceRecord: fmt.Sprintf("overflow-%d", i)})
		if err != nil {
			return nil, err
		}
		body, err := a.Canonical(fact)
		return []any{fact.Run, fact.ID, fact.Asset, fact.Kind, fact.AvailableAt, body}, err
	}))
	if err != nil {
		t.Fatal(err)
	}
	s := &AssessmentStore{pool: f.restrictedPool(t), registry: f.registry, config: f.config}
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	var floor time.Time
	var failures, candidates int
	if err := f.admin.QueryRow(ctx, `SELECT discovery_floor,(SELECT count(*) FROM assessment_failures WHERE code='CAPACITY' AND asset=$2 AND scope_key='DISCOVER/0'),(SELECT count(*) FROM assessment_candidates) FROM assessment_enrollments WHERE run_id=$1 AND asset=$2`, f.config.RunID, asset).Scan(&floor, &failures, &candidates); err != nil {
		t.Fatal(err)
	}
	if !floor.Equal(at) || failures != 1 || candidates != 0 {
		t.Fatalf("floor=%s want=%s failures=%d invented_candidates=%d", floor, at, failures, candidates)
	}
}

func TestAssessmentAdmissionInputWitnessImmutableAndArchived(t *testing.T) {
	f := newAssessmentFixture(t)
	f.seedSource(t, true)
	ctx := context.Background()
	store, err := NewAssessmentStore(ctx, f.restrictedPool(t), f.registry, f.config, "input-witness")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	var witness string
	if err = f.admin.QueryRow(ctx, `SELECT input_config_hash FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&witness); err != nil || !a.ValidHash(witness) {
		t.Fatalf("missing admission witness: %v", err)
	}
	if _, err = f.admin.Exec(ctx, `UPDATE assessment_runs SET input_config_hash=$2 WHERE run_id=$1`, f.config.RunID, strings.Repeat("f", 64)); err == nil {
		t.Fatal("admission witness rewritten")
	}
	f.exec(t, `UPDATE assessment_runs SET state='CLOSED',stopped_at=clock_timestamp(),closed_at=clock_timestamp(),stop_reason='CAPACITY' WHERE run_id=$1`, f.config.RunID)
	archive, err := OpenAssessmentArchive(ctx, f.dsn, f.config.RunID)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close(ctx)
	var total int64
	for {
		row, err := archive.Next(ctx)
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
		total += n
		if row.Table == "run" {
			var run map[string]json.RawMessage
			if err := json.Unmarshal(row.Body, &run); err != nil {
				t.Fatal(err)
			}
			var got string
			if err := json.Unmarshal(run["input_config_hash"], &got); err != nil || got != witness {
				t.Fatalf("archive lost input identity: %v", err)
			}
		}
	}
	if total != archive.Metadata().SourcePayloadBytes {
		t.Fatalf("physical bytes=%d metadata=%d", total, archive.Metadata().SourcePayloadBytes)
	}
}

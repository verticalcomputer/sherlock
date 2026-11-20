//go:build integration && !race

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestProductionAssessmentFleetDeepHistoryBudget(t *testing.T) {
	const fleetSize = 128
	const historicSlots = 58 // Leave one complete slot of margin at the admission cutoff.

	f, s, c, profile, hash, now := productionFleetFixture(t, fleetSize)
	var hasOldIndex bool
	if err := f.admin.QueryRow(t.Context(), `SELECT to_regclass('public.observations_cooling_run_entity_idx') IS NOT NULL`).Scan(&hasOldIndex); err != nil {
		t.Fatal(err)
	}
	if hasOldIndex {
		t.Fatal("fresh migrations installed the old cooling observations index")
	}
	seedUnrelatedFleetObservations(t, f, c.Assessment, now.Add(-2*time.Hour))
	seedFleetSnapshots(t, f, s, c, now.Add(-30*time.Minute), true)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	f.exec(t, `UPDATE prometheus_cooling_upload_profiles SET registered_at=starts_at-interval '1 second' WHERE profile_id=$1 AND revision=$2`, profile.ProfileID, profile.Revision)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`)

	writer, err := NewCollectionStore(f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.admin.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	last := now.Truncate(domain.CoolingUploadInterval)
	var priorRuns []string
	for slot := last.Add(-historicSlots * domain.CoolingUploadInterval); slot.Before(last); slot = slot.Add(domain.CoolingUploadInterval) {
		for _, query := range domain.CoolingUploadQueries() {
			if accepted, err := writer.RecordCoolingUpload(t.Context(), profile.CollectorID, profile.ClusterID, fleetHistoryReport(profile, hash, query, slot)); err != nil || !accepted {
				t.Fatalf("seed %s at %s accepted=%t: %v", query, slot, accepted, err)
			}
			if slot.Equal(last.Add(-domain.CoolingUploadInterval)) {
				priorRuns = append(priorRuns, string(profile.Task(query, slot).RunID))
			}
		}
	}
	f.exec(t, `ANALYZE public.observations; ANALYZE public.collection_runs; ANALYZE public.prometheus_cooling_upload_receipts; ANALYZE public.prometheus_cooling_receipt_observations`)

	// Pause the real upload immediately before commit, after its rows and receipt
	// exist in the transaction. The assessment's first sample read releases it.
	// The upload has a separate connection and a bounded context on every path.
	uploadReady := make(chan struct{})
	releaseUpload := make(chan struct{})
	uploadDone := make(chan error, 1)
	writeTrace := fleetHistoryTrace{before: func(ctx context.Context, q pgx.TraceQueryStartData) {
		if q.SQL == "commit" {
			close(uploadReady)
			select {
			case <-releaseUpload:
			case <-ctx.Done():
			}
		}
	}}
	writer, err = NewCollectionStore(fleetHistoryTracePool(t, f.admin, writeTrace))
	if err != nil {
		t.Fatal(err)
	}

	var sampleQuery pgx.TraceQueryStartData
	s.pool = fleetHistoryTracePool(t, f.admin, fleetHistoryTrace{before: func(_ context.Context, q pgx.TraceQueryStartData) {
		if sampleQuery.SQL == "" && q.SQL == productionUploadObservationSQL {
			sampleQuery = q
			close(releaseUpload)
		}
	}})

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	report := fleetHistoryReport(profile, hash, domain.QueryGPUTemperature, last)
	go func() {
		accepted, err := writer.RecordCoolingUpload(ctx, profile.CollectorID, profile.ClusterID, report)
		if err == nil && !accepted {
			err = fmt.Errorf("concurrent upload was not admitted")
		}
		uploadDone <- err
	}()
	select {
	case <-uploadReady:
	case err := <-uploadDone:
		t.Fatalf("upload did not reach commit: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	var cycleStart time.Time
	if err = f.admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&cycleStart); err != nil {
		t.Fatal(err)
	}
	cycle := time.Now()
	var passes []time.Duration
	remaining := fleetSize
	for remaining > 0 && time.Since(cycle) < 15*time.Second {
		began := time.Now()
		err := s.Refresh(ctx)
		elapsed := time.Since(began)
		passes = append(passes, elapsed)
		if err != nil || elapsed > a.ShadowRefreshBudget {
			t.Fatalf("fleet refresh %s: %v diagnostics=%v", elapsed, err, AssessmentDiagnosticFields(err))
		}
		if err = f.admin.QueryRow(ctx, `SELECT count(*) FROM production_assessment_states WHERE enrollment_id=$1 AND (last_acquire_attempt_at IS NULL OR last_acquire_attempt_at<$2)`, c.Assessment.RunID, cycleStart).Scan(&remaining); err != nil {
			t.Fatal(err)
		}
	}
	cycleElapsed := time.Since(cycle)
	assessmentProfileDistribution(t, "fleet_deep_history_refresh", passes)
	if remaining != 0 || cycleElapsed > 15*time.Second {
		t.Fatalf("fleet cycle remaining=%d elapsed=%s", remaining, cycleElapsed)
	}
	select {
	case err := <-uploadDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	// Refresh enforces the 250ms per-GPU deadline and counts timed-out attempts.
	// Require actual admitted temperature and power facts in every saved state.
	var failures, withProof int
	if err := f.admin.QueryRow(t.Context(), `
SELECT coalesce(sum(failure_count),0), count(*) FILTER(WHERE (
 SELECT count(DISTINCT fact#>>'{body,provenance,collection_run_id}')
 FROM jsonb_array_elements(convert_from(snapshot,'UTF8')::jsonb->'facts') fact
 WHERE fact->>'kind'='SAMPLE' AND fact#>>'{body,provenance,collection_run_id}'=ANY($2)
)=cardinality($2))
FROM production_assessment_states WHERE enrollment_id=$1`, c.Assessment.RunID, priorRuns).Scan(&failures, &withProof); err != nil {
		t.Fatal(err)
	}
	if failures != 0 || withProof != fleetSize {
		t.Fatalf("fleet failures=%d states with admitted temperature and power proof=%d", failures, withProof)
	}
	t.Logf("%d GPUs acquired in %s across %d passes with zero GPU budget failures and concurrent same-profile admission", fleetSize, cycleElapsed, len(passes))

	// Bound rows examined by both custom and generic plans so a warm cache
	// cannot mask a scan of the archive or of every GPU in each admitted run.
	assertFleetObservationLookupWork(t, f.admin, sampleQuery, 2*historicSlots)
}

func assertFleetObservationLookupWork(t *testing.T, pool *pgxpool.Pool, query pgx.TraceQueryStartData, rowLimit int) {
	t.Helper()
	if query.SQL == "" {
		t.Fatal("production assessment did not read admitted observations")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	const statement = "fleet_history_samples"
	if _, err = tx.Conn().Prepare(ctx, statement, query.SQL); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Conn().Deallocate(ctx, statement) }()

	parameters := make([]string, len(query.Args))
	for i := range parameters {
		parameters[i] = fmt.Sprintf("$%d", i+1)
	}
	explain := "EXPLAIN (ANALYZE, BUFFERS, TIMING OFF, FORMAT JSON) EXECUTE " + statement + "(" + strings.Join(parameters, ",") + ")"
	// EXECUTE expects SQL literals. pgx's simple protocol safely encodes the
	// captured arguments, including the text array of admitted run IDs.
	args := append([]any{pgx.QueryExecModeSimpleProtocol}, query.Args...)
	for _, mode := range []string{"force_custom_plan", "force_generic_plan"} {
		if _, err = tx.Exec(ctx, `SELECT set_config('plan_cache_mode',$1,true)`, mode); err != nil {
			t.Fatal(err)
		}
		var planJSON []byte
		if err = tx.QueryRow(ctx, explain, args...).Scan(&planJSON); err != nil {
			t.Fatalf("explain %s: %v", mode, err)
		}
		var plans []struct {
			Plan          fleetObservationPlan
			ExecutionTime float64 `json:"Execution Time"`
		}
		if err = json.Unmarshal(planJSON, &plans); err != nil || len(plans) != 1 || plans[0].Plan.Rows == 0 {
			t.Fatalf("decode %s sample plan with admitted rows: %v", mode, err)
		}
		plan := plans[0].Plan
		for _, index := range []string{"prometheus_cooling_receipt_observations_pkey", "observations_pkey"} {
			if !plan.usedIndex(index) {
				t.Fatalf("%s sample lookup did not use %s: %s", mode, index, planJSON)
			}
		}
		rows := plan.maxRows()
		if rows > rowLimit {
			t.Fatalf("%s sample lookup visited %d rows in one plan node, limit %d for one GPU in admitted runs", mode, rows, rowLimit)
		}
		t.Logf("%s sample lookup visited at most %d rows in any plan node, shared hits=%d reads=%d, execution=%.3fms", mode, rows, plan.SharedHits, plan.SharedReads, plans[0].ExecutionTime)
	}
}

func fleetHistoryReport(profile domain.CoolingUploadProfile, hash string, query domain.QueryKind, slot time.Time) domain.CoolingUploadReport {
	report := assessmentUploadReport(profile, hash, query, slot)
	report.Version = 3
	return report
}

func seedUnrelatedFleetObservations(t *testing.T, f *assessmentFixture, c a.Config, end time.Time) {
	t.Helper()
	// Four canonical GPUs have 192,000 same-source observations each. Batches
	// of 32 samples per GPU model retained, receipt-free range runs.
	var entities, nodes, gpus []string
	for _, asset := range c.Assets[:4] {
		entities = append(entities, asset.EntityKey)
		nodes = append(nodes, asset.NodeID)
		gpus = append(gpus, asset.GPUUUID)
	}
	for _, query := range domain.CoolingUploadQueries() {
		field, _ := domain.CoolingUploadField(query)
		f.exec(t, `
WITH archived_runs AS (
 INSERT INTO collection_runs(run_id,cluster_id,source_id,query_kind,idempotency_key,status,
   scheduled_for,started_at,completed_at,series_returned,bytes_read,coverage_complete,
   range_start,range_end,range_step_seconds)
 SELECT 'fixture-archive-'||$3::text||'-'||n,$1,$2,$3,'fixture-archive-'||$3::text||'-'||n,'SUCCEEDED',
   at,at,at,128,0,true,at-interval '8 minutes',at,15
 FROM generate_series(1,3000) n
 CROSS JOIN LATERAL (SELECT $4::timestamptz-n*interval '8 minutes' AS at) stamp
 RETURNING run_id,completed_at
)
INSERT INTO observations(observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,
 labels,value,unit,observed_at,collected_at,source_reference,sample_fingerprint)
SELECT 'fixture-archive-sample-'||digest,r.run_id,$1,$2,1,$5,asset.entity_key,$6,
 jsonb_build_array(jsonb_build_object('name','Hostname','value',asset.node_id),jsonb_build_object('name','UUID','value',asset.gpu)),
 98,$7,r.completed_at-slot*interval '15 seconds',r.completed_at,$8,decode(digest,'hex')
FROM archived_runs r
CROSS JOIN unnest($9::text[],$10::text[],$11::text[]) AS asset(entity_key,node_id,gpu)
CROSS JOIN generate_series(0,31) slot
CROSS JOIN LATERAL (SELECT md5(r.run_id||'/'||asset.entity_key||'/'||slot) AS digest) d`,
			c.ClusterID, c.SourceID, query, end, strings.TrimPrefix(string(query), "dcgm_"), field.Name, field.Unit,
			domain.DCGMSourceReference(query), entities, nodes, gpus)
	}
}

type fleetHistoryTrace struct {
	before func(context.Context, pgx.TraceQueryStartData)
}

func (trace fleetHistoryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	trace.before(ctx, data)
	return ctx
}
func (fleetHistoryTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func fleetHistoryTracePool(t *testing.T, pool *pgxpool.Pool, trace fleetHistoryTrace) *pgxpool.Pool {
	t.Helper()
	config := pool.Config()
	config.MaxConns = 2
	config.ConnConfig.Tracer = trace
	traced, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(traced.Close)
	return traced
}

type fleetObservationPlan struct {
	Rows         int                    `json:"Actual Rows"`
	Loops        int                    `json:"Actual Loops"`
	Filtered     int                    `json:"Rows Removed by Filter"`
	IndexRecheck int                    `json:"Rows Removed by Index Recheck"`
	IndexName    string                 `json:"Index Name"`
	SharedHits   int                    `json:"Shared Hit Blocks"`
	SharedReads  int                    `json:"Shared Read Blocks"`
	Children     []fleetObservationPlan `json:"Plans"`
}

func (p fleetObservationPlan) maxRows() int {
	rows := (p.Rows + p.Filtered + p.IndexRecheck) * p.Loops
	for _, child := range p.Children {
		rows = max(rows, child.maxRows())
	}
	return rows
}

func (p fleetObservationPlan) usedIndex(name string) bool {
	if p.Loops > 0 && p.IndexName == name {
		return true
	}
	for _, child := range p.Children {
		if child.usedIndex(name) {
			return true
		}
	}
	return false
}

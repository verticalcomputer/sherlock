//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	adapter "github.com/verticalcomputer/sherlock/internal/adapters/prometheus"
	"github.com/verticalcomputer/sherlock/internal/application"
	execution "github.com/verticalcomputer/sherlock/internal/collectorexecution/prometheus"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestDCGMCollectionDiscoveryEnrollmentAndRecurringEvidence(t *testing.T) {
	pool := durableTestDatabase(t)
	ctx := context.Background()
	store, _ := storepg.NewCollectionStore(pool)
	goodput, _ := storepg.NewGoodputStore(pool)
	for _, scope := range []string{"a", "b"} {
		if err := store.EnsureSource(ctx, domain.ClusterID(scope), scope, domain.SourceID(scope+"-source"), scope); err != nil {
			t.Fatal(err)
		}
	}
	var response atomic.Value
	response.Store(`{"status":"success","data":{"resultType":"vector","result":[]}}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Query().Get("query"), "timestamp(") {
			t.Error("expanded query omitted freshness gate")
		}
		_, _ = w.Write([]byte(response.Load().(string)))
	}))
	defer server.Close()
	client, _ := adapter.NewClient(adapter.Config{BaseURL: server.URL, Timeout: time.Second})
	executor, _ := execution.New(client, platform.SystemClock{}, platform.RandomIDGenerator{})
	collector, _ := application.NewCollector(executor, store, platform.SystemClock{}, 0, 0)
	var sampleOffset int64
	setFieldResponse := func(query domain.QueryKind, values map[string]float64) {
		var samples []any
		for _, field := range domain.DCGMFields(query) {
			value, ok := values[field.Name]
			if !ok {
				continue
			}
			samples = append(samples, map[string]any{"metric": map[string]string{"__name__": field.Name, "Hostname": "node-a", "UUID": "GPU-a", "token": "secret"}, "value": []any{time.Now().Unix() + sampleOffset, fmt.Sprint(value)}})
		}
		if samples == nil {
			samples = []any{}
		}
		body, _ := json.Marshal(map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": samples}})
		response.Store(string(body))
	}
	setResponse := func(query domain.QueryKind, values ...float64) {
		fields := domain.DCGMFields(query)
		named := make(map[string]float64, len(values))
		for i, value := range values {
			named[fields[i].Name] = value
		}
		setFieldResponse(query, named)
	}
	sequence := 0
	collect := func(scope string, query domain.QueryKind) domain.CollectionResult {
		sequence++
		now := time.Now().UTC()
		id := fmt.Sprintf("dcgm-%d", sequence)
		task := domain.CollectionTask{RunID: domain.RunID(id), ClusterID: domain.ClusterID(scope), SourceID: domain.SourceID(scope + "-source"), Query: query, ScheduledFor: now, Deadline: now.Add(time.Second), MaxSeries: 100, MaxBytes: 10000, IdempotencyKey: id}
		out, err := collector.Collect(ctx, task)
		if err != nil {
			t.Fatal(err)
		}
		out.Result.Status, out.Result.Coverage, err = store.DCGMCollectionState(ctx, task.ClusterID, task.SourceID, task.RunID)
		if err != nil {
			t.Fatal(err)
		}
		return out.Result
	}
	seed := func(scope string, q domain.QueryKind) domain.DesiredSchedule {
		op, _ := domain.CollectionOperationForQuery(q)
		return domain.DesiredSchedule{ScheduleKey: domain.ScheduleKey{ClusterID: domain.ClusterID(scope), SourceID: domain.SourceID(scope + "-source"), Operation: op.ID}, Enabled: true, Mode: domain.SchedulingLegacy, Interval: 30 * time.Second, Timeout: time.Second, MaxTargets: 100, MaxBytes: 10000}
	}
	setResponse(domain.QueryGPUPower, 20, 300)
	unknown := collect("a", domain.QueryGPUPower)
	if unknown.Status != domain.ResultPartial || unknown.Coverage.SeriesExpected != nil {
		t.Fatalf("unmapped support: %+v", unknown)
	}
	if yes, err := store.EnrollDiscoveredDCGM(ctx, unknown.Task.RunID, seed("a", domain.QueryGPUPower), time.Now()); err != nil || yes {
		t.Fatalf("unknown enrollment %v %v", yes, err)
	}
	for _, scope := range []string{"a", "b"} {
		now := time.Now().UTC().Add(-time.Minute)
		_, err := goodput.RecordExpectedInventoryRevision(ctx, domain.InventoryRevision{SchemaVersion: 1, ID: domain.InventoryRevisionID(scope + "-expected"), ClusterID: domain.ClusterID(scope), SourceID: domain.SourceID(scope + "-source"), SourceAt: now, EffectiveAt: now, ObservedAt: now, Entities: []domain.EntityIdentity{{ClusterID: domain.ClusterID(scope), Kind: domain.EntityGPU, NodeID: "node-a", PhysicalGPUUUID: "GPU-a"}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	r := collect("a", domain.QueryGPUPower)
	if r.Status != domain.ResultSucceeded || !r.Coverage.Complete || len(r.Coverage.MetricFields) != 2 {
		t.Fatalf("supported: %+v", r)
	}
	if yes, err := store.EnrollDiscoveredDCGM(ctx, r.Task.RunID, seed("b", domain.QueryGPUPower), time.Now()); err != nil || yes {
		t.Fatalf("foreign enrollment %v %v", yes, err)
	}
	var enrolled atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			yes, err := store.EnrollDiscoveredDCGM(ctx, r.Task.RunID, seed("a", domain.QueryGPUPower), time.Now().Add(-time.Second))
			if err != nil {
				t.Error(err)
			}
			if yes {
				enrolled.Add(1)
			}
		}()
	}
	wg.Wait()
	if enrolled.Load() != 1 {
		t.Fatalf("duplicate ownership: %d", enrolled.Load())
	}
	var labels, entity, unit, semantics string
	if err := pool.QueryRow(ctx, `SELECT labels::text,entity_key,unit,metric_semantics::text FROM observations WHERE run_id=$1 ORDER BY metric LIMIT 1`, r.Task.RunID).Scan(&labels, &entity, &unit, &semantics); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(labels, "secret") || entity != "a/GPU/node-a/GPU-a/" || unit != "watts" || !strings.Contains(semantics, "gauge") {
		t.Fatalf("stored normalization %s %s %s %s", labels, entity, unit, semantics)
	}
	// Exercise the actual revisioned legacy claim, run binding and completion.
	job, found, err := store.ClaimDueClusterSourceJob(ctx, "worker", time.Minute, "a", "a-source")
	if err != nil || !found || job.Query != domain.QueryGPUPower || job.DesiredRevision != 1 {
		t.Fatalf("claim %+v %v %v", job, found, err)
	}
	runID, err := store.BindCollectionJob(ctx, job, "worker", "recurring-dcgm")
	if err != nil {
		t.Fatal(err)
	}
	setResponse(domain.QueryGPUPower, 21) // The second field disappears on recurrence.
	task := domain.CollectionTask{RunID: runID, ClusterID: job.ClusterID, SourceID: job.SourceID, Query: job.Query, Node: job.Node, ScheduledFor: job.ScheduledFor, Deadline: time.Now().Add(job.Timeout), MaxSeries: job.MaxTargets, MaxBytes: job.MaxBytes, IdempotencyKey: "recurring-dcgm"}
	if _, err = collector.Collect(ctx, task); err != nil {
		t.Fatal(err)
	}
	status, coverage, err := store.DCGMCollectionState(ctx, "a", "a-source", runID)
	if err != nil || status != domain.ResultPartial || coverage.Complete || coverage.MetricFields[1].State != "UNKNOWN" {
		t.Fatalf("disappearance %s %+v %v", status, coverage, err)
	}
	if err = store.CompleteJob(ctx, job, "worker"); err != nil {
		t.Fatal(err)
	}
	desired, err := store.DesiredSchedule(ctx, seed("a", domain.QueryGPUPower).ScheduleKey)
	if err != nil {
		t.Fatal(err)
	}
	desired.Enabled = false
	desired.Interval = time.Minute
	desired, err = store.UpdateDesiredSchedule(ctx, desired)
	if err != nil {
		t.Fatal(err)
	}
	setResponse(domain.QueryGPUPower, 20, 300)
	r = collect("a", domain.QueryGPUPower)
	if yes, err := store.EnrollDiscoveredDCGM(ctx, r.Task.RunID, seed("a", domain.QueryGPUPower), time.Now()); err != nil || yes {
		t.Fatalf("re-enrollment %v %v", yes, err)
	}
	after, err := store.DesiredSchedule(ctx, desired.ScheduleKey)
	if err != nil || after.Enabled || after.Interval != time.Minute || after.Revision != desired.Revision {
		t.Fatalf("overrode operator %+v %v", after, err)
	}
	if _, found, err := store.ClaimDueClusterSourceJob(ctx, "worker", time.Minute, "a", "a-source"); err != nil || found {
		t.Fatalf("disabled claim %v %v", found, err)
	}
	// Source B remains independent and can enroll its own same-UUID mapping.
	setResponse(domain.QueryGPUPower, 140737488355330, 140737488355330)
	ub := collect("b", domain.QueryGPUPower)
	if yes, err := store.EnrollDiscoveredDCGM(ctx, ub.Task.RunID, seed("b", domain.QueryGPUPower), time.Now()); err != nil || yes {
		t.Fatalf("unsupported enrollment %v %v", yes, err)
	}
	setResponse(domain.QueryGPUPower, 20, 300)
	rb := collect("b", domain.QueryGPUPower)
	bSeed := seed("b", domain.QueryGPUPower)
	bSeed.Mode = domain.SchedulingDurable
	if yes, err := store.EnrollDiscoveredDCGM(ctx, rb.Task.RunID, bSeed, time.Now()); err != nil || !yes {
		t.Fatalf("B enrollment %v %v", yes, err)
	}
	if _, found, err := store.ClaimDueClusterSourceJob(ctx, "worker", time.Minute, "b", "b-source"); err != nil || found {
		t.Fatalf("durable claimed via legacy %v %v", found, err)
	}
	if _, found, err := store.AdmitDueSchedule(ctx, domain.DurableAdmissionPolicy{GlobalLimit: 4, ClusterLimit: 2}); err != nil || found {
		t.Fatalf("discovery bypassed durable grants %v %v", found, err)
	}
	// An exact double not-supported marker is distinct from absent data.
	setResponse(domain.QueryGPUPower, 140737488355330, 140737488355330)
	unsupported := collect("a", domain.QueryGPUPower)
	for _, f := range unsupported.Coverage.MetricFields {
		if f.State != "NOT_SUPPORTED" {
			t.Fatalf("unsupported %+v", unsupported)
		}
	}
	setResponse(domain.QueryGPUPower)
	empty := collect("a", domain.QueryGPUPower)
	for _, f := range empty.Coverage.MetricFields {
		if f.State != "UNKNOWN" {
			t.Fatalf("empty %+v", empty)
		}
	}
	// The pilot's H100 exporter exposes row-remap evidence without the four
	// legacy ECC counters. Those three fields are sufficient for explicit
	// enrollment while the absent legacy fields remain UNKNOWN.
	setFieldResponse(domain.QueryGPUECC, map[string]float64{
		"DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS":   0,
		"DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS": 0,
		"DCGM_FI_DEV_ROW_REMAP_FAILURE":           0,
	})
	rowRemap := collect("a", domain.QueryGPUECC)
	if rowRemap.Status != domain.ResultPartial || rowRemap.Coverage.Complete || rowRemap.Coverage.SeriesExpected == nil || *rowRemap.Coverage.SeriesExpected != 7 || len(rowRemap.Observations) != 3 {
		t.Fatalf("row-remap discovery: %+v", rowRemap)
	}
	states := map[string]string{}
	for _, field := range rowRemap.Coverage.MetricFields {
		states[field.Metric] = field.State
	}
	for _, name := range []string{"DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", "DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS", "DCGM_FI_DEV_ROW_REMAP_FAILURE"} {
		if states[name] != "SUPPORTED" {
			t.Fatalf("row-remap field %s state=%s", name, states[name])
		}
	}
	if states["DCGM_FI_DEV_ECC_SBE_VOL_TOTAL"] != "UNKNOWN" {
		t.Fatalf("absent legacy ECC field state=%s", states["DCGM_FI_DEV_ECC_SBE_VOL_TOTAL"])
	}
	if yes, err := store.EnrollDiscoveredDCGM(ctx, rowRemap.Task.RunID, seed("a", domain.QueryGPUECC), time.Now()); err != nil || !yes {
		t.Fatalf("row-remap enrollment %v %v", yes, err)
	}
	var rowCounterKind, rowFailureKind, rowFailureUnit string
	if err = pool.QueryRow(ctx, `SELECT metric_semantics->>'kind' FROM observations WHERE run_id=$1 AND metric='DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS'`, rowRemap.Task.RunID).Scan(&rowCounterKind); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT metric_semantics->>'kind',unit FROM observations WHERE run_id=$1 AND metric='DCGM_FI_DEV_ROW_REMAP_FAILURE'`, rowRemap.Task.RunID).Scan(&rowFailureKind, &rowFailureUnit); err != nil {
		t.Fatal(err)
	}
	if rowCounterKind != "counter" || rowFailureKind != "gauge" || rowFailureUnit != "boolean" {
		t.Fatalf("row-remap semantics counter=%s failure=%s/%s", rowCounterKind, rowFailureKind, rowFailureUnit)
	}
	// ECC decreases retain the absolute count and an explicit epoch gap.
	sampleOffset = -1
	setResponse(domain.QueryGPUECC, 9, 9, 9, 9)
	collect("a", domain.QueryGPUECC)
	sampleOffset = 0
	setResponse(domain.QueryGPUECC, 2, 2, 2, 2)
	ecc := collect("a", domain.QueryGPUECC)
	var reset bool
	var value float64
	if err = pool.QueryRow(ctx, `SELECT value,(metric_semantics->>'reset_observed')::boolean FROM observations WHERE run_id=$1 AND metric='DCGM_FI_DEV_ECC_SBE_VOL_TOTAL'`, ecc.Task.RunID).Scan(&value, &reset); err != nil || value != 2 || !reset {
		t.Fatalf("counter reset %v %v %v", value, reset, err)
	}
	// The four default imports and their production cadence remain unchanged.
	defaults := application.LegacyPrometheusSchedules("a", "a-source", domain.SchedulingLegacy, 30*time.Second, 10*time.Second, 10000, 10<<20)
	if len(defaults) != 4 {
		t.Fatal("default set changed")
	}
	if err = store.ImportLegacyPrometheusSchedules(ctx, defaults, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, d := range defaults {
		got, err := store.DesiredSchedule(ctx, d.ScheduleKey)
		if err != nil || got.Interval != 30*time.Second || got.Timeout != 10*time.Second {
			t.Fatalf("default %+v %v", got, err)
		}
	}
}

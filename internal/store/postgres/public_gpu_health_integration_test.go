//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adminview"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestPublicGPUHealthCanonicalLegacyScopesAndLatestGaps(t *testing.T) {
	pool := durableTestDatabase(t)
	ctx := context.Background()
	collection, _ := storepg.NewCollectionStore(pool)
	goodput, _ := storepg.NewGoodputStore(pool)
	public, _ := storepg.NewPublicQueryStore(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	base := now.Add(-30 * time.Second)
	for _, scope := range []struct{ cluster, source string }{{"gpu-cluster", "source-a"}, {"gpu-cluster", "source-b"}, {"foreign", "foreign-source"}} {
		if err := collection.EnsureSource(ctx, domain.ClusterID(scope.cluster), scope.cluster, domain.SourceID(scope.source), scope.source); err != nil {
			t.Fatal(err)
		}
		entities := []domain.EntityIdentity{{ClusterID: domain.ClusterID(scope.cluster), Kind: domain.EntityGPU, NodeID: "node-a", PhysicalGPUUUID: "GPU-a"}, {ClusterID: domain.ClusterID(scope.cluster), Kind: domain.EntityGPU, NodeID: "node-b", PhysicalGPUUUID: "GPU-b"}}
		if _, err := goodput.RecordExpectedInventoryRevision(ctx, domain.InventoryRevision{SchemaVersion: 1, ID: domain.InventoryRevisionID(scope.source + "-expected"), ClusterID: domain.ClusterID(scope.cluster), SourceID: domain.SourceID(scope.source), SourceAt: base.Add(-time.Minute), EffectiveAt: base.Add(-time.Minute), ObservedAt: base.Add(-time.Minute), Entities: entities}); err != nil {
			t.Fatal(err)
		}
	}
	seq := 0
	record := func(cluster, source string, q domain.QueryKind, status domain.ResultStatus, values map[string]float64, legacy bool) {
		t.Helper()
		seq++
		at := base.Add(time.Duration(seq) * time.Millisecond)
		id := fmt.Sprintf("gpu-health-%d", seq)
		result := domain.CollectionResult{Task: domain.CollectionTask{RunID: domain.RunID(id), ClusterID: domain.ClusterID(cluster), SourceID: domain.SourceID(source), Query: q, ScheduledFor: at, IdempotencyKey: id, MaxSeries: 100, MaxBytes: 10000}, Status: status, StartedAt: at, CompletedAt: at, Coverage: domain.Coverage{Complete: true}}
		for metric, value := range values {
			key := cluster + "/GPU/node-a/GPU-a/"
			labels := []domain.Label{{Name: "Hostname", Value: "node-a"}, {Name: "UUID", Value: "GPU-a"}}
			if legacy {
				key = "node/node-a/gpu/0"
			}
			unit := "percent"
			kind := "gpu_utilization"
			reference := "prometheus:fixture"
			if q == domain.QueryGPUXID {
				unit = "xid_code"
				kind = "gpu_xid"
			}
			for _, field := range domain.DCGMFields(q) {
				if field.Name == metric {
					unit = field.Unit
					kind = string(q)
					reference = domain.DCGMSourceReference(q)
				}
			}
			result.Observations = append(result.Observations, domain.Observation{ID: domain.ObservationID(id + "-" + metric), SchemaVersion: 1, ClusterID: result.Task.ClusterID, SourceID: result.Task.SourceID, Kind: kind, EntityKey: key, Metric: metric, Labels: labels, Value: value, Unit: unit, ObservedAt: at, CollectedAt: at, SourceReference: reference})
		}
		if q == domain.QueryGPUUtilization && source == "source-a" {
			result.Observations = append(result.Observations, domain.Observation{ID: domain.ObservationID(id + "-unproven"), SchemaVersion: 1, ClusterID: result.Task.ClusterID, SourceID: result.Task.SourceID, Kind: "gpu_utilization", EntityKey: "node/node-a/gpu/1", Metric: "DCGM_FI_DEV_GPU_UTIL", Value: 30, Unit: "percent", ObservedAt: at, CollectedAt: at, SourceReference: "prometheus:fixture"})
		}
		result.Coverage.SeriesReturned = len(result.Observations)
		if inserted, err := collection.RecordResult(ctx, result); err != nil || !inserted {
			t.Fatalf("record %s: %v %v", id, inserted, err)
		}
	}
	record("gpu-cluster", "source-a", domain.QueryGPUTemperature, domain.ResultSucceeded, map[string]float64{"DCGM_FI_DEV_GPU_TEMP": 90, "DCGM_FI_DEV_MEMORY_TEMP": 60}, false)
	record("gpu-cluster", "source-a", domain.QueryGPUUtilization, domain.ResultSucceeded, map[string]float64{"DCGM_FI_DEV_GPU_UTIL": 95}, true)
	record("gpu-cluster", "source-a", domain.QueryGPUXID, domain.ResultSucceeded, map[string]float64{"DCGM_FI_DEV_XID_ERRORS": 79}, true)
	record("gpu-cluster", "source-b", domain.QueryGPUTemperature, domain.ResultSucceeded, map[string]float64{"DCGM_FI_DEV_GPU_TEMP": 40}, false)
	record("foreign", "foreign-source", domain.QueryGPUTemperature, domain.ResultSucceeded, map[string]float64{"DCGM_FI_DEV_GPU_TEMP": 99}, false)
	load := func(at time.Time, filter application.GPUFilters) []application.GPUSummaryProjection {
		t.Helper()
		items, more, err := public.ListGPUSummaries(ctx, "gpu-cluster", filter, 200, 0, at, 2*time.Minute)
		if err != nil || more {
			t.Fatalf("load: more=%v %v", more, err)
		}
		return items
	}
	items := load(now, application.GPUFilters{})
	if len(items) != 5 {
		t.Fatalf("expected two same-UUID sources plus independent missing expected devices, got %+v", items)
	}
	find := func(items []application.GPUSummaryProjection, source, key string) application.GPUSummaryProjection {
		t.Helper()
		for _, item := range items {
			if string(item.SourceID) == source && item.EntityKey == key {
				return item
			}
		}
		t.Fatalf("missing %s/%s", source, key)
		return application.GPUSummaryProjection{}
	}
	unproven := find(items, "source-a", "node/node-a/gpu/1")
	if len(unproven.Observations) != 1 {
		t.Fatalf("unproven index merged or vanished: %+v", unproven)
	}
	a := find(items, "source-a", "gpu-cluster/GPU/node-a/GPU-a/")
	if len(a.Observations) != 4 {
		t.Fatalf("canonical/legacy did not merge with original observations: %+v", a)
	}
	assertSignal := func(item application.GPUSummaryProjection, typ domain.HealthSignalType) {
		t.Helper()
		for _, s := range item.Signals {
			if s.Type == typ {
				return
			}
		}
		t.Fatalf("missing %s: %+v", typ, item.Signals)
	}
	assertSignal(a, domain.HealthSignalThermal)
	assertSignal(a, domain.HealthSignalXID)
	assertSignal(a, domain.HealthSignalPartial)
	missing := find(items, "source-a", "gpu-cluster/GPU/node-b/GPU-b/")
	if len(missing.Observations) != 0 || missing.Freshness != domain.FreshnessUnknown {
		t.Fatalf("invented missing GPU observations: %+v", missing)
	}
	assertSignal(missing, domain.HealthSignalPartial)
	if filtered := load(now, application.GPUFilters{NodeID: "node-b"}); len(filtered) != 2 {
		t.Fatalf("canonical node filter: %+v", filtered)
	}
	page, more, err := public.ListGPUSummaries(ctx, "gpu-cluster", application.GPUFilters{}, 1, 1, now, time.Minute)
	if err != nil || !more || len(page) != 1 {
		t.Fatalf("pagination: %+v %v %v", page, more, err)
	}
	// A later successful partial attempt omits a field which remains physically
	// present in current_projections. It is excluded from current health.
	record("gpu-cluster", "source-a", domain.QueryGPUTemperature, domain.ResultSucceeded, map[string]float64{"DCGM_FI_DEV_GPU_TEMP": 45}, false)
	a = find(load(now, application.GPUFilters{}), "source-a", "gpu-cluster/GPU/node-a/GPU-a/")
	for _, o := range a.Observations {
		if o.Metric == "DCGM_FI_DEV_MEMORY_TEMP" {
			t.Fatal("old supported cell filled latest missing field")
		}
	}
	for _, signal := range a.Signals {
		if signal.Type == domain.HealthSignalThermal {
			t.Fatalf("old hot sample survived new scoped attempt: %+v", signal)
		}
	}
	assertSignal(a, domain.HealthSignalXID)
	assertSignal(a, domain.HealthSignalPartial)
	var retained int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM current_projections WHERE cluster_id='gpu-cluster' AND source_id='source-a' AND metric='DCGM_FI_DEV_MEMORY_TEMP'`).Scan(&retained); err != nil || retained != 1 {
		t.Fatalf("read changed retained history %d %v", retained, err)
	}
	// One failed source operation cannot hide independent fresh XID evidence.
	record("gpu-cluster", "source-a", domain.QueryGPUTemperature, domain.ResultFailed, nil, false)
	a = find(load(now, application.GPUFilters{}), "source-a", "gpu-cluster/GPU/node-a/GPU-a/")
	assertSignal(a, domain.HealthSignalUnavailable)
	assertSignal(a, domain.HealthSignalXID)
	stale := find(load(now.Add(3*time.Minute), application.GPUFilters{}), "source-a", "gpu-cluster/GPU/node-a/GPU-a/")
	assertSignal(stale, domain.HealthSignalStale)
	// Both public and private consumers use the exact same scoped signals.
	reader, _ := adminview.NewPostgresStore(pool)
	summaries, err := reader.LoadGPUHealthSummaries(ctx, "gpu-cluster", now, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service, _ := adminview.NewService(reader)
	snapshot, err := service.GPUMetrics(ctx, adminview.GPUMetricsQuery{ClusterID: "gpu-cluster", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	parityRows := 0
	for _, row := range snapshot.GPUs {
		if row.MIGIdentity != "" {
			continue
		}
		key := "gpu-cluster/GPU/" + row.NodeID + "/" + row.GPUUUID + "/"
		expected := find(load(now, application.GPUFilters{}), row.SourceID, key)
		want, _ := json.Marshal(expected.Signals)
		got, _ := json.Marshal(row.Conditions)
		if string(want) != string(got) {
			t.Fatalf("public/private conditions differ for %s: %s != %s", key, want, got)
		}
		parityRows++
	}
	if parityRows != 2 {
		t.Fatalf("expected primary source physical+missing placeholders: %+v", snapshot.GPUs)
	}
	b := find(summaries, "source-a", "gpu-cluster/GPU/node-a/GPU-a/")
	aJSON, _ := json.Marshal(a.Signals)
	bJSON, _ := json.Marshal(b.Signals)
	if string(aJSON) != string(bJSON) {
		t.Fatal("shared reader/public conditions differ")
	}
	// A superseding future-clock attempt is uncertainty, never an invitation to
	// reuse the older still-fresh successful projection.
	future := now.Add(time.Hour)
	if _, err := collection.RecordResult(ctx, domain.CollectionResult{Task: domain.CollectionTask{RunID: "future-xid", ClusterID: "gpu-cluster", SourceID: "source-a", Query: domain.QueryGPUXID, ScheduledFor: future, IdempotencyKey: "future-xid", MaxSeries: 100, MaxBytes: 10000}, Status: domain.ResultFailed, StartedAt: future, CompletedAt: future}); err != nil {
		t.Fatal(err)
	}
	a = find(load(now, application.GPUFilters{}), "source-a", "gpu-cluster/GPU/node-a/GPU-a/")
	for _, s := range a.Signals {
		if s.Type == domain.HealthSignalXID {
			t.Fatalf("older XID appeared current behind future latest attempt: %+v", s)
		}
	}
	assertSignal(a, domain.HealthSignalPartial)
}

func TestPublicGPUHealthDurableNodeScopeFailurePreservesSibling(t *testing.T) {
	pool := durableTestDatabase(t)
	ctx := context.Background()
	collection, _ := storepg.NewCollectionStore(pool)
	public, _ := storepg.NewPublicQueryStore(pool)
	goodput, _ := storepg.NewGoodputStore(pool)
	if err := collection.EnsureSource(ctx, "scope-cluster", "scope-cluster", "scope-source", "scope-source"); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	if _, err := goodput.RecordExpectedInventoryRevision(ctx, domain.InventoryRevision{SchemaVersion: 1, ID: "scope-inventory", ClusterID: "scope-cluster", SourceID: "scope-source", EffectiveAt: at.Add(-time.Minute), SourceAt: at.Add(-time.Minute), ObservedAt: at.Add(-time.Minute), Entities: []domain.EntityIdentity{{ClusterID: "scope-cluster", Kind: domain.EntityGPU, NodeID: "node-a", PhysicalGPUUUID: "GPU-node-a"}, {ClusterID: "scope-cluster", Kind: domain.EntityGPU, NodeID: "node-b", PhysicalGPUUUID: "GPU-node-b"}}}); err != nil {
		t.Fatal(err)
	}

	result := domain.CollectionResult{Task: domain.CollectionTask{RunID: "scope-wide", ClusterID: "scope-cluster", SourceID: "scope-source", Query: domain.QueryGPUTemperature, ScheduledFor: at, IdempotencyKey: "scope-wide", MaxSeries: 100, MaxBytes: 10000}, Status: domain.ResultSucceeded, StartedAt: at, CompletedAt: at, Coverage: domain.Coverage{Complete: true}}
	for _, node := range []string{"node-a", "node-b"} {
		result.Observations = append(result.Observations, domain.Observation{ID: domain.ObservationID("util-" + node), SchemaVersion: 1, ClusterID: "scope-cluster", SourceID: "scope-source", Kind: "gpu_temperature", EntityKey: "scope-cluster/GPU/" + node + "/GPU-" + node + "/", Metric: "DCGM_FI_DEV_GPU_TEMP", Unit: "celsius", Value: 90, ObservedAt: at, CollectedAt: at, Labels: []domain.Label{{Name: "Hostname", Value: node}, {Name: "UUID", Value: "GPU-" + node}}, SourceReference: domain.DCGMSourceReference(domain.QueryGPUTemperature)})
	}
	result.Coverage.SeriesReturned = 2
	if _, err := collection.RecordResult(ctx, result); err != nil {
		t.Fatal(err)
	}
	later := at.Add(time.Second)
	if _, err := pool.Exec(ctx, `INSERT INTO collection_jobs(job_id,cluster_id,source_id,query_kind,node_filter,interval_seconds,next_run_at) VALUES('scope-job','scope-cluster','scope-source',$1,'node-a',30,$2)`, domain.QueryGPUTemperature, later); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO collection_run_jobs(run_id,job_id,cluster_id,source_id,query_kind,node_filter,scheduled_for,configuration_revision,lease_generation) VALUES('scope-failed','scope-job','scope-cluster','scope-source',$1,'node-a',$2,0,1)`, domain.QueryGPUTemperature, later); err != nil {
		t.Fatal(err)
	}
	failed := domain.CollectionResult{Task: domain.CollectionTask{RunID: "scope-failed", ClusterID: "scope-cluster", SourceID: "scope-source", Query: domain.QueryGPUTemperature, Node: "node-a", ScheduledFor: later, IdempotencyKey: "scope-failed", MaxSeries: 100, MaxBytes: 10000}, Status: domain.ResultFailed, StartedAt: later, CompletedAt: later}
	if _, err := collection.RecordResult(ctx, failed); err != nil {
		t.Fatal(err)
	}
	items, _, err := public.ListGPUSummaries(ctx, "scope-cluster", application.GPUFilters{}, 100, 0, time.Now(), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("device scope lost: %+v", items)
	}
	for _, item := range items {
		switch item.EntityKey {
		case "scope-cluster/GPU/node-a/GPU-node-a/":
			if len(item.Observations) != 0 {
				t.Fatalf("old node-a borrowed failed attempt: %+v", item)
			}
			found := false
			for _, s := range item.Signals {
				if s.Type == domain.HealthSignalUnavailable {
					found = true
				}
			}
			if !found {
				t.Fatalf("node-a failure hidden: %+v", item)
			}
		case "scope-cluster/GPU/node-b/GPU-node-b/":
			if len(item.Observations) != 1 {
				t.Fatalf("node-a failure hid sibling: %+v", item)
			}
		default:
			t.Fatalf("unexpected identity: %+v", item)
		}
	}
	reader, _ := adminview.NewPostgresStore(pool)
	service, _ := adminview.NewService(reader)
	snapshot, err := service.GPUMetrics(ctx, adminview.GPUMetricsQuery{ClusterID: "scope-cluster", Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.GPUs) != 2 {
		t.Fatalf("private expected sibling rows disappeared: %+v", snapshot.GPUs)
	}
	for _, row := range snapshot.GPUs {
		cell := row.Values["DCGM_FI_DEV_GPU_TEMP"]
		if row.NodeID == "node-b" {
			if cell.State != adminview.GPUMetricSupported || cell.Value == nil || *cell.Value != 90 {
				t.Fatalf("node-a failure hid sibling field value: %+v", cell)
			}
		} else if cell.Value != nil || cell.State != adminview.GPUMetricUnknown {
			t.Fatalf("node-a failed field borrowed old numeric: %+v", cell)
		}
	}

}

// The tracer pauses before the health-only query is sent to PostgreSQL. Earlier
// value reads have already established the repeatable-read snapshot. This
// avoids timing tests against the production 250ms lock timeout.
type gpuSnapshotQueryTracer struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (tracer *gpuSnapshotQueryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "w.typed_plan IS NOT NULL AS finite") {
		tracer.once.Do(func() {
			close(tracer.entered)
			select {
			case <-tracer.release:
			case <-ctx.Done():
			}
		})
	}
	return ctx
}
func (*gpuSnapshotQueryTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestGPUHealthPrivateCombinedSnapshotSurvivesConcurrentCommit(t *testing.T) {
	pool := durableTestDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	collection, _ := storepg.NewCollectionStore(pool)
	goodput, _ := storepg.NewGoodputStore(pool)
	if err := collection.EnsureSource(ctx, "snapshot-cluster", "snapshot-cluster", "snapshot-source", "snapshot-source"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	at := now.Add(-30 * time.Second)
	if _, err := goodput.RecordExpectedInventoryRevision(ctx, domain.InventoryRevision{SchemaVersion: 1, ID: "snapshot-inventory", ClusterID: "snapshot-cluster", SourceID: "snapshot-source", EffectiveAt: at.Add(-time.Minute), SourceAt: at.Add(-time.Minute), ObservedAt: at.Add(-time.Minute), Entities: []domain.EntityIdentity{{ClusterID: "snapshot-cluster", Kind: domain.EntityGPU, NodeID: "node-a", PhysicalGPUUUID: "GPU-a"}}}); err != nil {
		t.Fatal(err)
	}
	result := domain.CollectionResult{Task: domain.CollectionTask{RunID: "snapshot-good", ClusterID: "snapshot-cluster", SourceID: "snapshot-source", Query: domain.QueryGPUTemperature, ScheduledFor: at, IdempotencyKey: "snapshot-good", MaxSeries: 100, MaxBytes: 10000}, Status: domain.ResultSucceeded, StartedAt: at, CompletedAt: at, Coverage: domain.Coverage{Complete: true}}
	for metric, value := range map[string]float64{"DCGM_FI_DEV_GPU_TEMP": 90, "DCGM_FI_DEV_MEMORY_TEMP": 60} {
		result.Observations = append(result.Observations, domain.Observation{ID: domain.ObservationID(metric), SchemaVersion: 1, ClusterID: "snapshot-cluster", SourceID: "snapshot-source", EntityKey: "node/node-a/gpu/0", Kind: "gpu_temperature", Metric: metric, Labels: []domain.Label{{Name: "Hostname", Value: "node-a"}, {Name: "UUID", Value: "GPU-a"}}, Value: value, Unit: "celsius", ObservedAt: at, CollectedAt: at, SourceReference: domain.DCGMSourceReference(domain.QueryGPUTemperature)})
	}
	result.Coverage.SeriesReturned = 2
	if _, err := collection.RecordResult(ctx, result); err != nil {
		t.Fatal(err)
	}
	tracer := &gpuSnapshotQueryTracer{entered: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-tracer.release:
		default:
			close(tracer.release)
		}
	}()
	cfg := pool.Config()
	cfg.ConnConfig.Tracer = tracer
	readerPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer readerPool.Close()
	reader, _ := adminview.NewPostgresStore(readerPool)
	type answer struct {
		snapshot adminview.GPUMetricsSnapshot
		err      error
	}
	done := make(chan answer, 1)
	go func() {
		snapshot, err := reader.LoadGPUMetricsWithHealth(ctx, "snapshot-cluster", now, 2*time.Minute)
		done <- answer{snapshot, err}
	}()
	select {
	case <-tracer.entered:
	case <-ctx.Done():
		t.Fatal("reader did not reach health query")
	}
	later := at.Add(time.Second)
	// Synthetic immutable failed attempt, committed while the reader is paused.
	if _, err := pool.Exec(ctx, `INSERT INTO collection_runs(run_id,cluster_id,source_id,query_kind,idempotency_key,status,scheduled_for,started_at,completed_at,series_returned,bytes_read,coverage_complete) VALUES('snapshot-failed','snapshot-cluster','snapshot-source',$1,'snapshot-failed','FAILED',$2,$2,$2,0,0,false)`, domain.QueryGPUTemperature, later); err != nil {
		t.Fatal(err)
	}
	close(tracer.release)
	var first answer
	select {
	case first = <-done:
	case <-ctx.Done():
		t.Fatal("snapshot read did not finish")
	}
	if first.err != nil {
		t.Fatal(first.err)
	}
	assert := func(snapshot adminview.GPUMetricsSnapshot, supported, thermal bool) {
		t.Helper()
		if len(snapshot.GPUs) != 1 {
			t.Fatalf("unexpected GPU rows: %+v", snapshot.GPUs)
		}
		row := snapshot.GPUs[0]
		cell := row.Values["DCGM_FI_DEV_GPU_TEMP"]
		if supported {
			if cell.State != adminview.GPUMetricSupported || cell.Value == nil || *cell.Value != 90 {
				t.Fatalf("snapshot value changed mid-read: %+v", cell)
			}
		} else if cell.Value != nil || cell.State == adminview.GPUMetricSupported {
			t.Fatalf("later failed attempt retained old value: %+v", cell)
		}
		found := false
		for _, s := range row.Conditions {
			if s.Type == domain.HealthSignalThermal {
				found = true
			}
		}
		if found != thermal {
			t.Fatalf("mixed value/condition snapshot: %+v", row.Conditions)
		}
	}
	assert(first.snapshot, true, true)
	second, err := reader.LoadGPUMetricsWithHealth(ctx, "snapshot-cluster", now, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	assert(second, false, false)
}

package application

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	adapter "github.com/verticalcomputer/sherlock/internal/adapters/prometheus"
	prometheusexecution "github.com/verticalcomputer/sherlock/internal/collectorexecution/prometheus"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type sequenceIDs struct{ next int }

func (g *sequenceIDs) NewID() (string, error) {
	g.next++
	return fmt.Sprintf("observation-%d", g.next), nil
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type sequenceExecutor struct {
	results []domain.CollectionResult
	calls   int
}

func (e *sequenceExecutor) Execute(_ context.Context, _ domain.CollectionTask) domain.CollectionResult {
	result := e.results[e.calls]
	e.calls++
	return result
}

type memoryStore struct{ calls int }

func (s *memoryStore) RecordResult(_ context.Context, _ domain.CollectionResult) (bool, error) {
	s.calls++
	return true, nil
}

func TestCollectorRetriesOnlyTransientFailures(t *testing.T) {
	task := validTask()
	retryable := domain.CollectionResult{Task: task, Status: domain.ResultFailed, Failures: []domain.CollectionFailure{{Code: domain.FailureSourceUnavailable, Retryable: true}}}
	success := domain.CollectionResult{Task: task, Status: domain.ResultSucceeded}
	executor := &sequenceExecutor{results: []domain.CollectionResult{retryable, success}}
	store := &memoryStore{}
	collector, err := NewCollector(executor, store, fixedClock{}, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := collector.Collect(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Attempts != 2 || executor.calls != 2 || store.calls != 1 {
		t.Fatalf("unexpected retry outcome: %+v", outcome)
	}
}

func TestCollectorDoesNotRetryMalformedResponse(t *testing.T) {
	task := validTask()
	failed := domain.CollectionResult{Task: task, Status: domain.ResultFailed, Failures: []domain.CollectionFailure{{Code: domain.FailureMalformedResponse}}}
	executor := &sequenceExecutor{results: []domain.CollectionResult{failed}}
	store := &memoryStore{}
	collector, _ := NewCollector(executor, store, fixedClock{}, 2, 0)
	outcome, err := collector.Collect(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Attempts != 1 || executor.calls != 1 {
		t.Fatalf("unexpected retry: %+v", outcome)
	}
}

func validTask() domain.CollectionTask {
	now := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	return domain.CollectionTask{RunID: "run", ClusterID: "cluster", SourceID: "source", Query: domain.QuerySourceHealth, ScheduledFor: now, Deadline: now.Add(10 * time.Second), MaxSeries: 10_000, MaxBytes: 10 << 20, IdempotencyKey: "key"}
}

func TestPrometheusExecutorReturnsExplicitPartialResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"DCGM_FI_DEV_GPU_UTIL","Hostname":"comp001","gpu":"0"},"value":[1787133600,"42.5"]}]},"warnings":["not persisted"]}`))
	}))
	defer server.Close()
	client, err := adapter.NewClient(adapter.Config{BaseURL: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	executor, err := prometheusexecution.New(client, fixedClock{now: now}, &sequenceIDs{})
	if err != nil {
		t.Fatal(err)
	}
	task := validTask()
	task.ScheduledFor = now
	task.Deadline = time.Now().Add(10 * time.Second)
	result := executor.Execute(context.Background(), task)
	if result.Status != domain.ResultPartial || result.Coverage.Complete || len(result.Observations) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(result.Failures) != 1 || result.Failures[0].Code != domain.FailurePartialData {
		t.Fatalf("unexpected failures: %+v", result.Failures)
	}
}

func TestPrometheusExecutorProvesSourceHealthTargetInventory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"up","instance":"comp001:9400"},"value":[1787133600,"1"]},{"metric":{"__name__":"up","instance":"comp002:9400"},"value":[1787133600,"0"]}]}}`))
	}))
	defer server.Close()
	client, err := adapter.NewClient(adapter.Config{BaseURL: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	executor, err := prometheusexecution.New(client, fixedClock{now: now}, &sequenceIDs{})
	if err != nil {
		t.Fatal(err)
	}
	task := validTask()
	task.ScheduledFor = now
	task.Deadline = time.Now().Add(10 * time.Second)
	result := executor.Execute(context.Background(), task)
	if result.Status != domain.ResultSucceeded || result.Coverage.SeriesExpected == nil || *result.Coverage.SeriesExpected != 2 || len(result.Coverage.ExpectedTargets) != 2 {
		t.Fatalf("source-health coverage=%+v status=%s", result.Coverage, result.Status)
	}
	evidence, present, err := domain.CollectionEvidenceForCollection(result)
	if err != nil || !present || evidence.Status() != domain.EvidenceComplete {
		t.Fatalf("source-health evidence=%+v present=%t err=%v", evidence, present, err)
	}
}

func TestPrometheusExecutorCollectsRangeSamples(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query_range" {
			t.Errorf("path=%q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"DCGM_FI_DEV_GPU_UTIL","Hostname":"comp001","gpu":"0"},"values":[[1787133570,"40"],[1787133600,"42.5"]]}]}}`))
	}))
	defer server.Close()
	client, err := adapter.NewClient(adapter.Config{BaseURL: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	executor, err := prometheusexecution.New(client, fixedClock{now: now}, &sequenceIDs{})
	if err != nil {
		t.Fatal(err)
	}
	task := validTask()
	task.Query = domain.QueryGPUUtilization
	task.ScheduledFor = now
	task.Deadline = time.Now().Add(10 * time.Second)
	task.Range = &domain.CollectionRange{Start: now.Add(-time.Minute), End: now, Step: 30 * time.Second}
	result := executor.Execute(context.Background(), task)
	if result.Status != domain.ResultSucceeded || result.Coverage.SeriesReturned != 1 || len(result.Observations) != 2 {
		t.Fatalf("unexpected range result: %+v", result)
	}
	if !result.Observations[1].ObservedAt.After(result.Observations[0].ObservedAt) {
		t.Fatalf("observations are not time ordered: %+v", result.Observations)
	}
}

func TestPrometheusExecutorNormalizesM3GPUObservations(t *testing.T) {
	tests := []struct {
		query    domain.QueryKind
		metric   string
		value    string
		wantKind string
		wantUnit string
	}{
		{domain.QueryGPUIdentity, "", "1", "gpu_identity", "count"},
		{domain.QueryGPUUtilization, "DCGM_FI_DEV_GPU_UTIL", "42.5", "gpu_utilization", "percent"},
		{domain.QueryGPUTemperature, "DCGM_FI_DEV_GPU_TEMP", "83", "gpu_temperature", "celsius"},
		{domain.QueryGPUPower, "DCGM_FI_DEV_POWER_USAGE", "612.5", "gpu_power", "watts"},
		{domain.QueryGPUMemory, "DCGM_FI_DEV_FB_USED", "4096", "gpu_memory", "mebibytes"},
		{domain.QueryGPUECC, "DCGM_FI_DEV_ECC_DBE_VOL_TOTAL", "2", "gpu_ecc", "count"},
		{domain.QueryGPUXID, "DCGM_FI_DEV_XID_ERRORS", "79", "gpu_xid", "xid_code"},
	}
	for _, tt := range tests {
		t.Run(string(tt.query), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				metricLabel := ""
				if tt.metric != "" {
					metricLabel = `"__name__":"` + tt.metric + `",`
				}
				_, _ = fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{%s"Hostname":"comp001","gpu":"3","UUID":"GPU-abc","modelName":"H100"},"value":[1787133600,%q]}]}}`, metricLabel, tt.value)
			}))
			defer server.Close()
			client, err := adapter.NewClient(adapter.Config{BaseURL: server.URL, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
			executor, _ := prometheusexecution.New(client, fixedClock{now: now}, &sequenceIDs{})
			task := validTask()
			task.Query = tt.query
			task.ScheduledFor = now
			task.Deadline = time.Now().Add(10 * time.Second)
			result := executor.Execute(context.Background(), task)
			if result.Status != domain.ResultSucceeded || len(result.Observations) != 1 {
				t.Fatalf("unexpected result: %+v", result)
			}
			observation := result.Observations[0]
			wantEntity := "node/comp001/gpu/3"
			if len(domain.DCGMFields(tt.query)) > 0 {
				wantEntity = "node/comp001/gpu/GPU-abc"
			}
			if observation.Kind != tt.wantKind || observation.Unit != tt.wantUnit || observation.EntityKey != wantEntity {
				t.Fatalf("observation = %+v", observation)
			}
		})
	}
}

func TestPrometheusExecutorNormalizesCurrentAndLegacyDCGMIdentityLabels(t *testing.T) {
	tests := []struct {
		name   string
		labels string
		want   string
	}{
		{name: "current lowercase", labels: `"hostname":"comp002","uuid":"GPU-current"`, want: "node/comp002/gpu/GPU-current"},
		{name: "pilot uppercase", labels: `"Hostname":"comp001","UUID":"GPU-pilot"`, want: "node/comp001/gpu/GPU-pilot"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"DCGM_FI_DEV_GPU_TEMP",%s},"value":[1787133600,"30"]}]}}`, tt.labels)
			}))
			defer server.Close()
			client, _ := adapter.NewClient(adapter.Config{BaseURL: server.URL, Timeout: time.Second})
			executor, _ := prometheusexecution.New(client, fixedClock{now: time.Now().UTC()}, &sequenceIDs{})
			task := validTask()
			task.Query = domain.QueryGPUTemperature
			task.Deadline = time.Now().Add(time.Second)
			result := executor.Execute(context.Background(), task)
			if result.Status != domain.ResultSucceeded || len(result.Observations) != 1 || result.Observations[0].EntityKey != tt.want {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestPrometheusExecutorDoesNotTreatMissingGPUIdentityAsHealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"DCGM_FI_DEV_GPU_TEMP"},"value":[1787133600,"30"]}]}}`))
	}))
	defer server.Close()
	client, _ := adapter.NewClient(adapter.Config{BaseURL: server.URL, Timeout: time.Second})
	executor, _ := prometheusexecution.New(client, fixedClock{now: time.Now().UTC()}, &sequenceIDs{})
	task := validTask()
	task.Query = domain.QueryGPUTemperature
	task.Deadline = time.Now().Add(time.Second)
	result := executor.Execute(context.Background(), task)
	if result.Status != domain.ResultPartial || result.Coverage.Complete || len(result.Observations) != 0 {
		t.Fatalf("identity-deficient sample was treated as complete: %+v", result)
	}
}

func TestCollectorPreservesFailureWhenRetryBudgetExpired(t *testing.T) {
	task := validTask()
	for _, remaining := range []time.Duration{0, time.Millisecond} {
		t.Run(remaining.String(), func(t *testing.T) {
			failed := domain.CollectionResult{Task: task, Status: domain.ResultFailed, Failures: []domain.CollectionFailure{{Code: domain.FailureCollectorUnavailable, Retryable: true}}}
			executor := &sequenceExecutor{results: []domain.CollectionResult{failed}}
			store := &memoryStore{}
			collector, _ := NewCollector(executor, store, fixedClock{now: task.Deadline.Add(-remaining)}, 2, time.Second)
			outcome, err := collector.Collect(context.Background(), task)
			if err != nil || outcome.Attempts != 1 || executor.calls != 1 || store.calls != 1 || outcome.Result.Failures[0].Code != domain.FailureCollectorUnavailable {
				t.Fatalf("original failure not preserved: %+v, %v", outcome, err)
			}
		})
	}
}

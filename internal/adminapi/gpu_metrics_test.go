package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminview"
)

type fakeGPUMetricsProvider struct {
	snapshot adminview.GPUMetricsSnapshot
	err      error
	queries  []adminview.GPUMetricsQuery
}

func (provider *fakeGPUMetricsProvider) GPUMetrics(_ context.Context, query adminview.GPUMetricsQuery) (adminview.GPUMetricsSnapshot, error) {
	provider.queries = append(provider.queries, query)
	return provider.snapshot, provider.err
}

func newGPUMetricsServer(t *testing.T, provider *fakeGPUMetricsProvider, now time.Time) *Server {
	t.Helper()
	options := Options{
		Provider: &fakeProvider{}, Management: &fakeManagement{}, Auditor: &fakeAuditor{},
		ServiceToken: []byte(testServiceToken), Clock: fixedClock{now: now},
	}
	if provider != nil {
		options.GPUMetrics = provider
	}
	server, err := New(options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return server
}

// serveWithoutToken exercises the shared bearer gate on this new route.
func serveWithoutToken(server *Server, target string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}

func TestPrivateAdminServesGPUMetricsWithExplicitStates(t *testing.T) {
	now := time.Date(2026, 9, 21, 9, 0, 0, 0, time.UTC)
	observed := now.Add(-10 * time.Second)
	provider := &fakeGPUMetricsProvider{snapshot: adminview.GPUMetricsSnapshot{
		ClusterID: "cluster-a", GeneratedAt: now,
		Sources: []adminview.GPUMetricsSource{{SourceID: "source-a", Operations: []adminview.GPUMetricsOperation{{
			OperationID: "prometheus.gpu_power.v1", Enrolled: true, Enabled: true, IntervalSeconds: 30,
			Freshness: adminview.GPUMetricsFresh,
			LastRun:   &adminview.GPUMetricsRun{RunID: "run-1", Status: "PARTIAL", CompletedAt: observed},
		}}}},
		GPUs: []adminview.GPUMetricsRow{{SourceID: "source-a", NodeID: "node-1", GPUUUID: "GPU-a", Expected: true, Values: map[string]adminview.GPUMetricValue{
			"DCGM_FI_DEV_POWER_MGMT_LIMIT": {State: adminview.GPUMetricNotSupported},
		}}},
	}}
	response := serve(newGPUMetricsServer(t, provider, now), http.MethodGet, "/internal/admin/v1/clusters/cluster-a/gpu-metrics", nil, "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	assertSecurityHeaders(t, response)
	if len(provider.queries) != 1 || provider.queries[0].ClusterID != "cluster-a" || !provider.queries[0].Now.Equal(now) {
		t.Fatalf("provider queries = %+v", provider.queries)
	}
	body := response.Body.String()
	if !strings.Contains(body, `"state":"NOT_SUPPORTED"`) || strings.Contains(body, `"value":0`) {
		t.Fatalf("unsupported field must serialize as a state without a value: %s", body)
	}
	if !strings.Contains(body, observed.Format(time.RFC3339)) {
		t.Fatalf("timestamps must be RFC3339: %s", body)
	}
	var decoded adminview.GPUMetricsSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if value := decoded.GPUs[0].Values["DCGM_FI_DEV_POWER_MGMT_LIMIT"]; value.Value != nil {
		t.Fatalf("decoded unsupported value = %+v", value)
	}
}

func TestPrivateAdminGPUMetricsRejectsQueriesTokensAndInvalidClusters(t *testing.T) {
	now := time.Date(2026, 9, 21, 9, 0, 0, 0, time.UTC)
	server := newGPUMetricsServer(t, &fakeGPUMetricsProvider{}, now)
	if response := serve(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-a/gpu-metrics?now=1", nil, ""); response.Code != http.StatusBadRequest {
		t.Fatalf("query parameters must be rejected: %d", response.Code)
	}
	if response := serve(server, http.MethodGet, "/internal/admin/v1/clusters/cluster%20a/gpu-metrics", nil, ""); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid cluster ID status = %d", response.Code)
	}
	unauthenticated := serveWithoutToken(server, "/internal/admin/v1/clusters/cluster-a/gpu-metrics")
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticated.Code)
	}
	assertSecurityHeaders(t, unauthenticated)
}

func TestPrivateAdminGPUMetricsRedactsBackendFailureAndStatesMissingProvider(t *testing.T) {
	now := time.Date(2026, 9, 21, 9, 0, 0, 0, time.UTC)
	failing := newGPUMetricsServer(t, &fakeGPUMetricsProvider{err: errors.New("pq: relation observations does not exist")}, now)
	response := serve(failing, http.MethodGet, "/internal/admin/v1/clusters/cluster-a/gpu-metrics", nil, "")
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "observations") {
		t.Fatalf("backend error leaked: %s", response.Body.String())
	}
	disabled := serve(newGPUMetricsServer(t, nil, now), http.MethodGet, "/internal/admin/v1/clusters/cluster-a/gpu-metrics", nil, "")
	if disabled.Code != http.StatusServiceUnavailable || !strings.Contains(disabled.Body.String(), "GPU_METRICS_DISABLED") {
		t.Fatalf("missing provider must be explicit: %d %s", disabled.Code, disabled.Body.String())
	}
}

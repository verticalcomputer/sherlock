package adminapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type fakeProgressProvider struct {
	query  application.ProgressQuery
	result application.ProgressWindowResult
	err    error
	calls  int
}

func (provider *fakeProgressProvider) Evaluate(_ context.Context, query application.ProgressQuery) (application.ProgressWindowResult, error) {
	provider.query, provider.calls = query, provider.calls+1
	return provider.result, provider.err
}

func TestPrivateProgressQueryIsExactAndUnmeasured(t *testing.T) {
	provider := &fakeProgressProvider{result: application.ProgressWindowResult{State: domain.ProgressUnmeasured,
		Quality: []application.ProgressQuality{application.ProgressMissingSamples}}}
	server, err := New(Options{Provider: &fakeProvider{}, Management: &fakeManagement{}, Auditor: &fakeAuditor{},
		ServiceToken: []byte(testServiceToken), Progress: provider})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	query := url.Values{"source_id": {"prom"}, "allocation_source_id": {"slurm"}, "inventory_source_id": {"prom"}, "scheduler_namespace": {"slurm"},
		"job_id": {"42"}, "submit_at": {start.Add(-time.Hour).Format(time.RFC3339Nano)}, "attempt": {"1"},
		"start": {start.Format(time.RFC3339Nano)}, "end": {start.Add(time.Hour).Format(time.RFC3339Nano)}, "max_gap_seconds": {"300"}}
	path := "/internal/admin/v1/clusters/cluster-a/progress?" + query.Encode()
	response := serve(server, http.MethodGet, path, nil, "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"UNMEASURED"`) ||
		strings.Contains(response.Body.String(), `"committed_per_gpu_second":0`) || provider.calls != 1 || provider.query.ClusterID != "cluster-a" || provider.query.InventorySourceID != "prom" {
		t.Fatalf("response=%d %s query=%+v", response.Code, response.Body.String(), provider.query)
	}
	assertSecurityHeaders(t, response)
	if unauthenticated := serveWithoutToken(server, path); unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", unauthenticated.Code)
	}
	query.Set("metric", "up")
	if invalid := serve(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-a/progress?"+query.Encode(), nil, ""); invalid.Code != http.StatusBadRequest {
		t.Fatalf("unexpected query accepted: %d", invalid.Code)
	}
	query.Del("metric")
	query.Add("job_id", "43")
	if invalid := serve(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-a/progress?"+query.Encode(), nil, ""); invalid.Code != http.StatusBadRequest {
		t.Fatalf("duplicate job ID accepted: %d", invalid.Code)
	}
	if provider.calls != 1 {
		t.Fatalf("invalid queries reached provider: %d", provider.calls)
	}
}

func TestPrivateProgressFailureIsRedacted(t *testing.T) {
	provider := &fakeProgressProvider{err: errors.New("pq: secret database detail")}
	server, err := New(Options{Provider: &fakeProvider{}, Management: &fakeManagement{}, Auditor: &fakeAuditor{},
		ServiceToken: []byte(testServiceToken), Progress: provider})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	query := url.Values{"source_id": {"prom"}, "allocation_source_id": {"slurm"}, "inventory_source_id": {"prom"}, "scheduler_namespace": {"slurm"},
		"job_id": {"42"}, "submit_at": {start.Add(-time.Hour).Format(time.RFC3339Nano)}, "attempt": {"1"},
		"start": {start.Format(time.RFC3339Nano)}, "end": {start.Add(time.Hour).Format(time.RFC3339Nano)}, "max_gap_seconds": {"300"}}
	response := serve(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-a/progress?"+query.Encode(), nil, "")
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "secret database detail") {
		t.Fatalf("backend failure leaked: %d %s", response.Code, response.Body.String())
	}
}

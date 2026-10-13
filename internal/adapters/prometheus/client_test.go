package prometheus

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// This fixture is independently executed by promtool (see GP06A docs). Keep
// its exact expressions connected to production rather than a copied query.
func TestDCGMRealPromQLFixtureMatchesRenderedQueries(t *testing.T) {
	encoded, err := os.ReadFile("testdata/dcgm_freshness.yml")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Tests []struct {
			Name        string `json:"name"`
			Expressions []struct {
				Expr string `json:"expr"`
			} `json:"promql_expr_test"`
		} `json:"tests"`
	}
	if err = json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Tests) != 8 {
		t.Fatal("missing operation/node fixture coverage")
	}
	for _, test := range fixture.Tests {
		q, node, _ := strings.Cut(test.Name, ":")
		got, err := RenderQuery(domain.QueryKind(q), node)
		if err != nil {
			t.Fatal(err)
		}
		if len(test.Expressions) != 2 {
			t.Fatal("fresh and stale evaluations required")
		}
		for _, expression := range test.Expressions {
			if got != expression.Expr {
				t.Fatalf("%s: production query differs from promtool fixture", test.Name)
			}
		}
	}
}

func TestTaskBoundsPreserveLocalCeilingsAndClientImmutability(t *testing.T) {
	client, err := NewClient(Config{BaseURL: "http://fixture.test", Timeout: 10 * time.Second, MaxSeries: 10, MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	bounded, err := client.WithTaskBounds(100, 10000, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if bounded.maxSeries != 10 || bounded.maxBytes != 1024 || bounded.http.Timeout != 10*time.Second {
		t.Fatal("task relaxed collector local ceiling")
	}
	short, err := client.WithTaskBounds(1, 128, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if short.maxSeries != 1 || short.maxBytes != 128 || short.http.Timeout > time.Second || client.http.Timeout != 10*time.Second || client.maxSeries != 10 || client.maxBytes != 1024 {
		t.Fatal("task bounds mutated shared client")
	}
	for _, limits := range []struct {
		series int
		bytes  int64
	}{{0, 1}, {10001, 1}, {1, 0}, {1, 10<<20 + 1}} {
		if _, err := client.WithTaskBounds(limits.series, limits.bytes, time.Time{}); err == nil {
			t.Fatal("invalid task limits accepted")
		}
	}
}

func TestRenderQueryRejectsPromQLInjection(t *testing.T) {
	if _, err := RenderQuery(domain.QueryGPUUtilization, `node1"} or vector(1)`); err == nil {
		t.Fatal("RenderQuery() accepted an unsafe node")
	}
	got, err := RenderQuery(domain.QueryGPUUtilization, "comp001")
	if err != nil {
		t.Fatal(err)
	}
	if got != `(DCGM_FI_DEV_GPU_UTIL{Hostname="comp001"} or DCGM_FI_DEV_GPU_UTIL{hostname="comp001"})` {
		t.Fatalf("RenderQuery() = %q", got)
	}
}

func TestRenderQueryUsesOnlyBoundedDCGMTemplates(t *testing.T) {
	tests := []struct {
		kind domain.QueryKind
		want string
	}{
		{kind: domain.QueryGPUIdentity, want: `count by (Hostname, hostname, UUID, uuid, device, gpu, modelName, pci_bus_id) ((DCGM_FI_DEV_GPU_UTIL{Hostname="comp001"} or DCGM_FI_DEV_GPU_UTIL{hostname="comp001"}))`},
		{kind: domain.QueryGPUUtilization, want: `(DCGM_FI_DEV_GPU_UTIL{Hostname="comp001"} or DCGM_FI_DEV_GPU_UTIL{hostname="comp001"})`},
		{kind: domain.QueryGPUTemperature, want: `((DCGM_FI_DEV_GPU_TEMP{Hostname="comp001"} or DCGM_FI_DEV_GPU_TEMP{hostname="comp001"}) or (DCGM_FI_DEV_MEMORY_TEMP{Hostname="comp001"} or DCGM_FI_DEV_MEMORY_TEMP{hostname="comp001"}))`},
		{kind: domain.QueryGPUPower, want: `((DCGM_FI_DEV_POWER_USAGE{Hostname="comp001"} or DCGM_FI_DEV_POWER_USAGE{hostname="comp001"}) or (DCGM_FI_DEV_POWER_MGMT_LIMIT{Hostname="comp001"} or DCGM_FI_DEV_POWER_MGMT_LIMIT{hostname="comp001"}))`},
		{kind: domain.QueryGPUMemory, want: `((DCGM_FI_DEV_FB_USED{Hostname="comp001"} or DCGM_FI_DEV_FB_USED{hostname="comp001"}) or (DCGM_FI_DEV_FB_FREE{Hostname="comp001"} or DCGM_FI_DEV_FB_FREE{hostname="comp001"}) or (DCGM_FI_DEV_FB_RESERVED{Hostname="comp001"} or DCGM_FI_DEV_FB_RESERVED{hostname="comp001"}))`},
		{kind: domain.QueryGPUECC, want: `((DCGM_FI_DEV_ECC_SBE_VOL_TOTAL{Hostname="comp001"} or DCGM_FI_DEV_ECC_SBE_VOL_TOTAL{hostname="comp001"}) or (DCGM_FI_DEV_ECC_DBE_VOL_TOTAL{Hostname="comp001"} or DCGM_FI_DEV_ECC_DBE_VOL_TOTAL{hostname="comp001"}) or (DCGM_FI_DEV_ECC_SBE_AGG_TOTAL{Hostname="comp001"} or DCGM_FI_DEV_ECC_SBE_AGG_TOTAL{hostname="comp001"}) or (DCGM_FI_DEV_ECC_DBE_AGG_TOTAL{Hostname="comp001"} or DCGM_FI_DEV_ECC_DBE_AGG_TOTAL{hostname="comp001"}) or (DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS{Hostname="comp001"} or DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS{hostname="comp001"}) or (DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS{Hostname="comp001"} or DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS{hostname="comp001"}) or (DCGM_FI_DEV_ROW_REMAP_FAILURE{Hostname="comp001"} or DCGM_FI_DEV_ROW_REMAP_FAILURE{hostname="comp001"}))`},
		{kind: domain.QueryGPUXID, want: `(DCGM_FI_DEV_XID_ERRORS{Hostname="comp001"} or DCGM_FI_DEV_XID_ERRORS{hostname="comp001"})`},
	}
	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			got, err := RenderQuery(tt.kind, "comp001")
			if err != nil {
				t.Fatal(err)
			}
			if len(domain.DCGMFields(tt.kind)) > 0 {
				// Pin the original fields and selector aliases, adding freshness
				// at each leaf and keeping distinct metric names in the union.
				tt.want = strings.ReplaceAll(tt.want, ") or (", ") or on(__name__) (")
				tt.want = regexp.MustCompile(`DCGM_[A-Z0-9_]+\{[^}]+\}`).ReplaceAllStringFunc(tt.want, func(s string) string {
					return "(" + s + " and (timestamp(" + s + ") >= time() - 120) and (timestamp(" + s + ") <= time()))"
				})
			}
			if got != tt.want {
				t.Fatalf("RenderQuery() = %q, want %q", got, tt.want)
			}
		})
	}
	if _, err := RenderQuery(domain.QueryKind("DCGM_FI_DEV_GPU_UTIL or vector(1)"), ""); err == nil {
		t.Fatal("non-allow-listed query kind was accepted")
	}
}

func TestInstantSuccessAndNoData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("query") != "DCGM_FI_DEV_GPU_UTIL" {
			t.Errorf("query = %q", r.URL.Query().Get("query"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"DCGM_FI_DEV_GPU_UTIL","Hostname":"comp001","gpu":"0"},"value":[1787133600,"42.5"]}]}}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Instant(context.Background(), domain.QueryGPUUtilization, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Samples) != 1 || result.Samples[0].Value != 42.5 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestInstantFailureClassification(t *testing.T) {
	tests := []struct {
		name string
		body string
		code domain.FailureCode
	}{
		{name: "malformed", body: `{`, code: domain.FailureMalformedResponse},
		{name: "bad value", body: `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"bad"]}]}}`, code: domain.FailureMalformedResponse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(tt.body)) }))
			defer server.Close()
			client, _ := NewClient(Config{BaseURL: server.URL, Timeout: time.Second})
			_, err := client.Instant(context.Background(), domain.QuerySourceHealth, "", time.Now())
			var sourceErr *Error
			if !errors.As(err, &sourceErr) || sourceErr.Code != tt.code {
				t.Fatalf("error = %#v, want code %s", err, tt.code)
			}
		})
	}
}

func TestInstantEnforcesByteLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 101)))
	}))
	defer server.Close()
	client, _ := NewClient(Config{BaseURL: server.URL, Timeout: time.Second, MaxBytes: 100})
	_, err := client.Instant(context.Background(), domain.QuerySourceHealth, "", time.Now())
	var sourceErr *Error
	if !errors.As(err, &sourceErr) || sourceErr.Code != domain.FailureResultLimit {
		t.Fatalf("error = %#v, want RESULT_LIMIT_EXCEEDED", err)
	}
}

func TestInstantEnforcesSeriesLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"gpu":"0"},"value":[1,"1"]},{"metric":{"gpu":"1"},"value":[1,"2"]}]}}`))
	}))
	defer server.Close()
	client, _ := NewClient(Config{BaseURL: server.URL, Timeout: time.Second, MaxSeries: 1})
	_, err := client.Instant(context.Background(), domain.QueryGPUUtilization, "", time.Now())
	var sourceErr *Error
	if !errors.As(err, &sourceErr) || sourceErr.Code != domain.FailureResultLimit {
		t.Fatalf("error = %#v, want RESULT_LIMIT_EXCEEDED", err)
	}
}

func TestInstantDistinguishesEmptyTimeoutAndUnavailable(t *testing.T) {
	tests := []struct {
		name      string
		handler   http.HandlerFunc
		wantCode  domain.FailureCode
		wantEmpty bool
	}{
		{name: "empty", handler: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
		}, wantEmpty: true},
		{name: "timeout", handler: func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(50 * time.Millisecond)
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
		}, wantCode: domain.FailureDeadlineExceeded},
		{name: "unavailable", handler: func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "not fixture data", http.StatusServiceUnavailable)
		}, wantCode: domain.FailureSourceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()
			timeout := time.Second
			if tt.name == "timeout" {
				timeout = 5 * time.Millisecond
			}
			client, _ := NewClient(Config{BaseURL: server.URL, Timeout: timeout})
			result, err := client.Instant(context.Background(), domain.QuerySourceHealth, "", time.Now())
			if tt.wantEmpty {
				if err != nil || len(result.Samples) != 0 {
					t.Fatalf("empty result=%+v err=%v", result, err)
				}
				return
			}
			var sourceErr *Error
			if !errors.As(err, &sourceErr) || sourceErr.Code != tt.wantCode {
				t.Fatalf("error=%#v want=%s", err, tt.wantCode)
			}
		})
	}
}

func TestRangeReturnsBoundedMatrixSamples(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query_range" {
			t.Errorf("path=%q", r.URL.Path)
		}
		if r.URL.Query().Get("step") != "30.000" {
			t.Errorf("step=%q", r.URL.Query().Get("step"))
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"DCGM_FI_DEV_GPU_UTIL","gpu":"0"},"values":[[1787133570,"40"],[1787133600,"42.5"]]}]}}`))
	}))
	defer server.Close()
	client, _ := NewClient(Config{BaseURL: server.URL, Timeout: time.Second})
	end := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	result, err := client.Range(context.Background(), domain.QueryGPUUtilization, "", domain.CollectionRange{Start: end.Add(-time.Minute), End: end, Step: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if result.SeriesReturned != 1 || len(result.Samples) != 2 || result.Samples[1].Value != 42.5 {
		t.Fatalf("unexpected range result: %+v", result)
	}
}

func TestRangeRejectsUnsafeBoundsWithoutRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	client, _ := NewClient(Config{BaseURL: server.URL, Timeout: time.Second})
	end := time.Now().UTC()
	_, err := client.Range(context.Background(), domain.QueryGPUUtilization, "", domain.CollectionRange{Start: end.Add(-25 * time.Hour), End: end, Step: time.Second})
	var sourceErr *Error
	if !errors.As(err, &sourceErr) || sourceErr.Code != domain.FailureInvalidArgument {
		t.Fatalf("error=%#v", err)
	}
	if requests != 0 {
		t.Fatalf("unsafe range made %d requests", requests)
	}
}

func TestInstantPreservesPartialWarningWithoutRawText(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"gpu":"0"},"value":[1,"2"]}]},"warnings":["sensitive upstream warning"]}`))
	}))
	defer server.Close()
	client, _ := NewClient(Config{BaseURL: server.URL, Timeout: time.Second})
	result, err := client.Instant(context.Background(), domain.QueryGPUUtilization, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if result.WarningCount != 1 || result.SeriesReturned != 1 {
		t.Fatalf("unexpected partial result: %+v", result)
	}
}

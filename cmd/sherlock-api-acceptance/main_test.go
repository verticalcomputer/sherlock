package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunPassesBoundedConsumerMatrix(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer secret" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Request-ID", "req-test")
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": []any{}, "path": request.URL.Path})
	}))
	defer server.Close()
	cfg := configuration{BaseURL: server.URL + "/api/v1", APIKey: "secret", ClusterID: "cluster-a", Requests: 40, Concurrency: 4, RequestTimeout: time.Second, P95Limit: time.Second, MaxErrorRate: 0, AllowHTTP: true}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	report := run(context.Background(), cfg, server.Client())
	if !report.Passed || report.Succeeded != 40 || report.Failed != 0 || report.StatusCounts["200"] != 40 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestRunFailsStatusAndContractViolations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/clusters" {
			http.Error(writer, "busy", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()
	cfg := configuration{BaseURL: server.URL + "/api/v1", APIKey: "secret", ClusterID: "cluster-a", Requests: 8, Concurrency: 2, RequestTimeout: time.Second, P95Limit: time.Second, MaxErrorRate: 0, AllowHTTP: true}
	report := run(context.Background(), cfg, server.Client())
	if report.Passed || report.Failed != 8 {
		t.Fatalf("expected all contract/status failures, got %+v", report)
	}
}

func TestConfigurationRejectsUnboundedOrInsecureRuns(t *testing.T) {
	base := configuration{BaseURL: "https://sherlock.test/api/v1", APIKey: "secret", ClusterID: "cluster-a", Requests: 4, Concurrency: 1, RequestTimeout: time.Second, P95Limit: time.Second}
	cases := []configuration{base, base, base}
	cases[0].BaseURL = "http://sherlock.test/api/v1"
	cases[1].Requests = maxRequests + 1
	cases[2].Concurrency = maxConcurrency + 1
	for _, cfg := range cases {
		if err := cfg.validate(); err == nil {
			t.Fatalf("accepted unsafe configuration: %+v", cfg)
		}
	}
}

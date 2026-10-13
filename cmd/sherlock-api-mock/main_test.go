package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMockServesContractExample(t *testing.T) {
	examples := map[string]json.RawMessage{"SourceListPartial": json.RawMessage(`{"data":[],"meta":{},"errors":[]}`)}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/c1/sources", nil)
	response := httptest.NewRecorder()
	mockHandler(examples).ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body.String())
	}
}

func TestMockServesDiagnosticPostExample(t *testing.T) {
	examples := map[string]json.RawMessage{"DiagnosticRunQueued": json.RawMessage(`{"run_id":"run-1"}`)}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/clusters/c1/diagnostic-runs", nil)
	response := httptest.NewRecorder()
	mockHandler(examples).ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != `{"run_id":"run-1"}` {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body.String())
	}
}

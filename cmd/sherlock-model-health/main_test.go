package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunReportsSafeDeploymentHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("api-key") != "health-secret" {
			t.Fatal("missing API key")
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"model": "gpt-5.6-sol", "status": "completed", "output": []any{map[string]any{"type": "message", "content": []any{map[string]any{"type": "output_text", "text": `{"ok":true}`}}}}, "usage": map[string]any{"input_tokens": 1, "output_tokens": 1}})
	}))
	defer server.Close()
	t.Setenv("SHERLOCK_MODEL_PROVIDER", "azure-openai")
	t.Setenv("SHERLOCK_AZURE_OPENAI_ENDPOINT", server.URL+"/openai/v1")
	t.Setenv("SHERLOCK_AZURE_OPENAI_API_KEY", "health-secret")
	t.Setenv("SHERLOCK_AZURE_OPENAI_DEPLOYMENT", "gpt-5.6-sol")
	t.Setenv("SHERLOCK_MODEL_CONFIGURATION_ID", "config-v1")
	t.Setenv("SHERLOCK_MODEL_INPUT_MICROS_PER_MILLION_TOKENS", "5000000")
	t.Setenv("SHERLOCK_MODEL_OUTPUT_MICROS_PER_MILLION_TOKENS", "30000000")
	t.Setenv("SHERLOCK_MODEL_MAX_RETRIES", "0")
	var output bytes.Buffer
	if err := run(context.Background(), &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "health-secret") || strings.Contains(output.String(), server.URL) {
		t.Fatalf("health output disclosed configuration: %s", output.String())
	}
	var report healthReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || !report.Healthy || report.Deployment != "gpt-5.6-sol" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func TestRunFailsClosedWithoutModelConfiguration(t *testing.T) {
	for _, name := range []string{"SHERLOCK_MODEL_PROVIDER", "SHERLOCK_AZURE_OPENAI_ENDPOINT", "SHERLOCK_AZURE_OPENAI_API_KEY", "SHERLOCK_AZURE_OPENAI_DEPLOYMENT", "SHERLOCK_MODEL_CONFIGURATION_ID", "SHERLOCK_MODEL_INPUT_MICROS_PER_MILLION_TOKENS", "SHERLOCK_MODEL_OUTPUT_MICROS_PER_MILLION_TOKENS"} {
		t.Setenv(name, "")
	}
	var output bytes.Buffer
	if err := run(context.Background(), &output); err == nil {
		t.Fatal("unconfigured health check succeeded")
	}
	var report healthReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.ErrorCode != "MODEL_NOT_CONFIGURED" {
		t.Fatalf("report=%+v error=%v", report, err)
	}
}

func TestRunReportsSafeProviderFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"secret":"upstream-body"}`))
	}))
	defer server.Close()
	t.Setenv("SHERLOCK_MODEL_PROVIDER", "azure-openai")
	t.Setenv("SHERLOCK_AZURE_OPENAI_ENDPOINT", server.URL+"/openai/v1")
	t.Setenv("SHERLOCK_AZURE_OPENAI_API_KEY", "health-secret")
	t.Setenv("SHERLOCK_AZURE_OPENAI_DEPLOYMENT", "gpt-5.6-sol")
	t.Setenv("SHERLOCK_MODEL_CONFIGURATION_ID", "config-v1")
	t.Setenv("SHERLOCK_MODEL_INPUT_MICROS_PER_MILLION_TOKENS", "5000000")
	t.Setenv("SHERLOCK_MODEL_OUTPUT_MICROS_PER_MILLION_TOKENS", "30000000")
	t.Setenv("SHERLOCK_MODEL_MAX_RETRIES", "0")
	var output bytes.Buffer
	if err := run(context.Background(), &output); err == nil {
		t.Fatal("unauthorized provider succeeded")
	}
	if strings.Contains(output.String(), "health-secret") || strings.Contains(output.String(), "upstream-body") || strings.Contains(output.String(), server.URL) {
		t.Fatalf("failure output disclosed sensitive configuration: %s", output.String())
	}
	var report healthReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.ErrorCode != "UNAUTHORIZED" || report.HTTPStatus != http.StatusUnauthorized || report.Healthy {
		t.Fatalf("report=%+v error=%v", report, err)
	}
}

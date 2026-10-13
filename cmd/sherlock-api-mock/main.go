// Code generated from api/openapi/sherlock-v1.yaml; DO NOT EDIT BY HAND.
// This executable serves the checked-in examples for consumer development.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	address := flag.String("address", "127.0.0.1:8090", "mock listen address")
	contractPath := flag.String("contract", "api/openapi/sherlock-v1.yaml", "OpenAPI contract path")
	flag.Parse()
	examples, err := loadExamples(*contractPath)
	if err != nil {
		log.Fatal(err)
	}
	handler := mockHandler(examples)
	server := &http.Server{Addr: *address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 64 << 10}
	log.Printf("Sherlock contract mock listening on %s", *address)
	log.Fatal(server.ListenAndServe())
}

func loadExamples(path string) (map[string]json.RawMessage, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read contract: %w", err)
	}
	var document struct {
		Components struct {
			Examples map[string]struct {
				Value json.RawMessage `json:"value"`
			} `json:"examples"`
		} `json:"components"`
	}
	if err := json.Unmarshal(payload, &document); err != nil {
		return nil, fmt.Errorf("parse contract: %w", err)
	}
	result := make(map[string]json.RawMessage, len(document.Components.Examples))
	for name, example := range document.Components.Examples {
		result[name] = example.Value
	}
	return result, nil
}

func mockHandler(examples map[string]json.RawMessage) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodPost {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := strings.TrimPrefix(request.URL.Path, "/api/v1")
		if strings.HasSuffix(path, "/events") {
			writer.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprint(writer, "id: evt_42\nevent: source.updated\ndata: {\"schema_version\":1,\"cluster_id\":\"cluster_h100_prod\",\"occurred_at\":\"2026-08-19T12:00:05Z\",\"source_id\":\"prometheus-main\",\"status\":\"DEGRADED\",\"freshness\":\"STALE\"}\n\n")
			return
		}
		name := exampleFor(request.Method, path)
		payload, ok := examples[name]
		if !ok {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(payload)
	})
}

func exampleFor(method, path string) string {
	switch {
	case method == http.MethodPost && strings.HasSuffix(path, "/diagnostic-runs/preview"):
		return "DiagnosticPreviewAllowed"
	case strings.Contains(path, "/diagnostic-runs"):
		return "DiagnosticRunQueued"
	case path == "/clusters":
		return "ClusterListSuccess"
	case strings.HasSuffix(path, "/health"):
		return "HealthPartial"
	case strings.HasSuffix(path, "/sources"):
		return "SourceListPartial"
	case strings.HasSuffix(path, "/observations"):
		return "ObservationListSuccess"
	case strings.HasSuffix(path, "/gpus"):
		return "GPUSummaryIncident"
	case strings.HasSuffix(path, "/collection-runs"):
		return "CollectionRunPartial"
	case strings.HasSuffix(path, "/evidence"):
		return "EvidenceListPartial"
	case strings.Contains(path, "/evidence/"):
		return "EvidencePartial"
	case strings.HasPrefix(path, "/clusters/"):
		return "ClusterPartial"
	default:
		return ""
	}
}

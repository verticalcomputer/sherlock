package adminclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminui"
)

const clientPreviewDigest = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

const clientPreviewJSON = `{"preview_id":"ipv_abc","cluster_id":"cluster-1","source_id":"head-prometheus",
"digest":"` + clientPreviewDigest + `","blocking":false,"generated_by":"access-a",
"generated_at":"2026-09-21T12:00:00Z","expires_at":"2026-09-22T12:00:00Z",
"discovery_test_id":"ctest_inv","discovery_completed_at":"2026-09-21T11:00:00Z",
"credential_id":"cred_1","credential_version":2,"bcm_version":"10.0",
"node_count":1,"gpu_count":1,"additions":2,
"entities":[{"kind":"NODE","node_id":"node001"},{"kind":"GPU","node_id":"node001","physical_gpu_uuid":"GPU-1"}],
"devices":[{"type":"PhysicalNode","hostname":"node001","category":"asus-h100-compute-category","status":"UP","managed":true,"observed_gpus":1,"included":true}],
"discrepancies":[{"code":"UNMANAGED_DEVICE","blocking":false,"device_type":"HeadNode","detail":"excluded"}],
"removals":[{"kind":"NODE","node_id":"node999"}],
"excluded_nodes":["fixture1-zone1-loginnode"],"excluded_categories":["login-default-category"]}`

func TestClientExpectedInventoryPassesActorAndDecodesStrictly(t *testing.T) {
	var seen []string
	var bodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seen = append(seen, request.Method+" "+request.URL.Path+" subject="+request.Header.Get("X-Sherlock-Access-Subject"))
		raw, _ := io.ReadAll(request.Body)
		if len(raw) > 0 {
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			bodies = append(bodies, body)
		}
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(request.URL.Path, "/import"):
			_, _ = writer.Write([]byte(`{"preview_id":"ipv_abc","revision_id":"exp_abc","already_imported":false}`))
		case strings.HasSuffix(request.URL.Path, "/previews"):
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(clientPreviewJSON))
		default:
			_, _ = writer.Write([]byte(`{"cluster_id":"cluster-1","source_id":"head-prometheus","discovery_available":true,
				"discovery_test_id":"ctest_inv","discovery_completed_at":"2026-09-21T11:00:00Z",
				"current":{"revision_id":"exp_old","source_at":"2026-09-20T10:00:00Z","effective_at":"2026-09-20T10:00:00Z","observed_at":"2026-09-20T10:00:00Z","node_count":11,"gpu_count":80},
				"latest_preview":` + clientPreviewJSON + `}`))
		}
	}))
	defer server.Close()
	client, err := New(server.URL, []byte(strings.Repeat("t", 40)), &http.Client{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	mutation := adminui.MutationContext{SessionFingerprint: make([]byte, 32), RequestID: "request-1", OccurredAt: time.Now().UTC(), ActorSubject: "access-a"}

	state, err := client.GetExpectedInventory(context.Background(), "cluster-1", "access-a")
	if err != nil || state.Current == nil || state.Current.RevisionID != "exp_old" || state.Current.GPUCount != 80 {
		t.Fatalf("state: %v %+v", err, state)
	}
	if !state.DiscoveryAvailable || state.LatestPreview == nil || state.LatestPreview.Digest != clientPreviewDigest {
		t.Fatalf("state preview: %+v", state)
	}
	if len(state.LatestPreview.Entities) != 2 || len(state.LatestPreview.Devices) != 1 ||
		len(state.LatestPreview.Discrepancies) != 1 || len(state.LatestPreview.Removals) != 1 {
		t.Fatalf("preview projection: %+v", state.LatestPreview)
	}
	if state.LatestPreview.Imported() {
		t.Fatal("an unimported preview reported an import")
	}

	preview, err := client.GenerateExpectedInventoryPreview(context.Background(), "cluster-1", "access-a", "head-prometheus", []string{"fixture1-zone1-loginnode"}, []string{"login-default-category"}, mutation)
	if err != nil || preview.PreviewID != "ipv_abc" || preview.Blocking {
		t.Fatalf("generate: %v %+v", err, preview)
	}
	if len(preview.ExcludedNodes) != 1 || preview.ExcludedNodes[0] != "fixture1-zone1-loginnode" {
		t.Fatalf("excluded nodes were not projected: %+v", preview.ExcludedNodes)
	}
	if len(preview.ExcludedCategories) != 1 || preview.ExcludedCategories[0] != "login-default-category" {
		t.Fatalf("excluded categories were not projected: %+v", preview.ExcludedCategories)
	}
	if len(preview.Devices) != 1 || preview.Devices[0].Category != "asus-h100-compute-category" {
		t.Fatalf("the device category was not projected: %+v", preview.Devices)
	}

	result, err := client.ImportExpectedInventoryPreview(context.Background(), "cluster-1", "access-a", "ipv_abc", clientPreviewDigest, mutation)
	if err != nil || result.RevisionID != "exp_abc" || result.AlreadyImported {
		t.Fatalf("import: %v %+v", err, result)
	}
	if len(bodies) != 2 || bodies[1]["digest"] != clientPreviewDigest || bodies[1]["actor_subject"] != "access-a" {
		t.Fatalf("request bodies: %+v", bodies)
	}
	if bodies[0]["source_id"] != "head-prometheus" {
		t.Fatalf("preview body: %+v", bodies[0])
	}
	// The operator's exclusion list travels to the private API unchanged: it
	// is part of the reconciliation the returned digest identifies.
	excluded, ok := bodies[0]["exclude_nodes"].([]any)
	if !ok || len(excluded) != 1 || excluded[0] != "fixture1-zone1-loginnode" {
		t.Fatalf("exclusions were not forwarded: %+v", bodies[0])
	}
	excludedCategories, ok := bodies[0]["exclude_categories"].([]any)
	if !ok || len(excludedCategories) != 1 || excludedCategories[0] != "login-default-category" {
		t.Fatalf("category exclusions were not forwarded: %+v", bodies[0])
	}
	if seen[0] != "GET /internal/admin/v1/clusters/cluster-1/expected-inventory subject=access-a" {
		t.Fatalf("requests: %v", seen)
	}
	if !strings.Contains(seen[2], "/expected-inventory/previews/ipv_abc/import") {
		t.Fatalf("import path: %v", seen)
	}
}

func TestClientExpectedInventoryRefusesInvalidApprovalsBeforeSending(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		t.Error("an invalid approval reached the private API")
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := New(server.URL, []byte(strings.Repeat("t", 40)), &http.Client{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	mutation := adminui.MutationContext{SessionFingerprint: make([]byte, 32), RequestID: "request-1", OccurredAt: time.Now().UTC(), ActorSubject: "access-a"}
	cases := []struct {
		name      string
		previewID string
		digest    string
	}{
		{"short digest", "ipv_abc", "abcd"},
		{"uppercase digest", "ipv_abc", strings.ToUpper(clientPreviewDigest)},
		{"foreign preview", "exp_abc", clientPreviewDigest},
		{"empty preview", "", clientPreviewDigest},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := client.ImportExpectedInventoryPreview(context.Background(), "cluster-1", "access-a", testCase.previewID, testCase.digest, mutation); err == nil {
				t.Fatal("expected a refusal before any request")
			}
		})
	}
	if _, err := client.GetExpectedInventory(context.Background(), "cluster-1", ""); err == nil {
		t.Fatal("an empty subject must be refused before any request")
	}
	for _, invalid := range [][]string{{""}, {"fixture1 bom"}, {strings.Repeat("n", 129)}} {
		if _, err := client.GenerateExpectedInventoryPreview(context.Background(), "cluster-1", "access-a", "", invalid, nil, mutation); err == nil {
			t.Fatalf("an invalid exclusion %q must be refused before any request", invalid)
		}
		if _, err := client.GenerateExpectedInventoryPreview(context.Background(), "cluster-1", "access-a", "", nil, invalid, mutation); err == nil {
			t.Fatalf("an invalid category exclusion %q must be refused before any request", invalid)
		}
	}
}

func TestClientExpectedInventoryRejectsUnknownResponseFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"preview_id":"ipv_abc","surprise":"value"}`))
	}))
	defer server.Close()
	client, err := New(server.URL, []byte(strings.Repeat("t", 40)), &http.Client{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	mutation := adminui.MutationContext{SessionFingerprint: make([]byte, 32), RequestID: "request-1", OccurredAt: time.Now().UTC(), ActorSubject: "access-a"}
	if _, err := client.GenerateExpectedInventoryPreview(context.Background(), "cluster-1", "access-a", "", nil, nil, mutation); err == nil {
		t.Fatal("an unknown response field must be refused")
	}
}

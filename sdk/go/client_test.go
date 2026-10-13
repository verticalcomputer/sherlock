package sherlock

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGeneratedClientPreservesPartialStateAndPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/clusters/cluster-1/sources" || r.URL.Query().Get("page_size") != "25" || r.URL.Query().Get("page_token") != "opaque" || r.URL.Query().Get("status") != "DEGRADED" {
			t.Fatalf("unexpected request: %s", r.URL.String())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer shk_test" {
			t.Fatalf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[{"source_id":"prometheus","kind":"PROMETHEUS","status":"DEGRADED","observed_at":"2026-08-19T12:00:00Z","collected_at":"2026-08-19T12:00:04Z","freshness":"STALE","coverage":{"requested":80,"successful":78,"failed":2,"complete":false},"collection_status":"PARTIAL"}],"meta":{"request_id":"req_1","generated_at":"2026-08-19T12:00:05Z","collection_status":"PARTIAL","freshness":"STALE","coverage":{"requested":80,"successful":78,"failed":2,"complete":false},"warnings":[],"next_page_token":"next"},"errors":[{"code":"PARTIAL_DATA","retryable":true}]}`)
	}))
	defer server.Close()

	client, err := NewClient(server.URL+"/api/v1", "shk_test", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.ListSources(context.Background(), "cluster-1", ListOptions{PageSize: 25, PageToken: "opaque"}, SourceStatus("DEGRADED"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Meta.CollectionStatus != CollectionStatusPartial || result.Meta.Freshness != FreshnessStale || result.Meta.Coverage.Complete || len(result.Errors) != 1 || result.Meta.NextPageToken != "next" {
		t.Fatalf("partial response semantics lost: %#v", result)
	}
}

func TestGeneratedClientDecodesProblem(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"type":"https://sherlock.dev/problems/forbidden","title":"Forbidden","status":403,"code":"CLUSTER_SCOPE_DENIED","detail":"wrong cluster","request_id":"req_2"}`)
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "shk_test", server.Client())
	_, err := client.GetHealth(context.Background(), "cluster-2")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Problem.Code != "CLUSTER_SCOPE_DENIED" || apiErr.Problem.RequestID != "req_2" {
		t.Fatalf("error = %#v", err)
	}
}

func TestGeneratedClientResumesSSE(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Last-Event-ID") != "evt_41" || r.URL.Query().Get("event_type") != "source.updated" {
			t.Fatalf("resume request = %#v", r)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "id: evt_42\nevent: source.updated\ndata: {\"schema_version\":1,\"source_id\":\"prometheus\"}\n\n")
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "shk_test", server.Client())
	events, errs, err := client.StreamEvents(context.Background(), "cluster-1", StreamOptions{LastEventID: "evt_41", EventTypes: []EventType{EventTypeSourceUpdated}})
	if err != nil {
		t.Fatal(err)
	}
	event := <-events
	if event.ID != "evt_42" || event.Type != EventTypeSourceUpdated {
		t.Fatalf("event = %#v", event)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
}

func TestGeneratedClientStartsSignedDiagnosticWithIdempotency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/clusters/cluster-1/diagnostic-runs" || r.Header.Get("Idempotency-Key") != "request-1" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected request: %#v", r)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"run_id":"run-1","cluster_id":"cluster-1","definition":{"pack_id":"base","pack_version":"2.0.0","definition_id":"gpu-query","definition_version":"1.3.0","definition_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"privilege":"UNPRIVILEGED","status":"QUEUED","requested_by":"key-1","requested_at":"2026-08-20T12:00:00Z","deadline":"2026-08-20T12:10:00Z","version":1,"attempts":[]}`)
	}))
	defer server.Close()
	client, _ := NewClient(server.URL+"/api/v1", "shk_test", server.Client())
	deadline := time.Date(2026, 8, 20, 12, 10, 0, 0, time.UTC)
	run, err := client.StartDiagnosticRun(context.Background(), "cluster-1", "request-1", DiagnosticRunRequest{Definition: DiagnosticDefinitionReference{PackID: "base", PackVersion: "2.0.0", DefinitionID: "gpu-query", DefinitionVersion: "1.3.0", DefinitionSHA256: strings.Repeat("a", 64)}, Targets: []string{"comp001"}, Arguments: []DiagnosticArgument{}, Deadline: &deadline, MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	if run.RunID != "run-1" || run.Status != "QUEUED" {
		t.Fatalf("run = %+v", run)
	}
}

func TestGeneratedClientStartsAndApprovesBoundedInvestigation(t *testing.T) {
	var requests []*http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"investigation_id":"investigation-1","cluster_id":"cluster-1","incident_id":"incident-1","question":"explain XID","scope":{"entity_kind":"NODE","entity_ids":["comp001"],"start":"2026-08-20T11:00:00Z","end":"2026-08-20T12:00:00Z"},"success_criteria":["identify cause"],"status":"PLANNING","budget":{"max_decisions":5,"max_tool_calls":10,"max_privileged_calls":1,"max_fan_out":2,"max_model_tokens":0,"max_cost_micros":0,"decisions_used":0,"tool_calls_used":0,"privileged_calls_used":0,"fan_out_used":0,"model_tokens_used":0,"cost_micros_used":0},"finding_ids":[],"created_by":"key-1","created_at":"2026-08-20T12:00:00Z","deadline":"2026-08-20T13:00:00Z","updated_at":"2026-08-20T12:00:00Z","version":2}`)
	}))
	defer server.Close()
	client, _ := NewClient(server.URL+"/api/v1", "shk_test", server.Client())
	start, deadline := time.Date(2026, 8, 20, 11, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 13, 0, 0, 0, time.UTC)
	result, err := client.StartInvestigation(context.Background(), "request-1", StartInvestigationRequest{ClusterID: "cluster-1", IncidentID: "incident-1", Question: "explain XID", Scope: InvestigationScope{EntityKind: "NODE", EntityIDs: []string{"comp001"}, Start: start, End: start.Add(time.Hour)}, SuccessCriteria: []string{"identify cause"}, Budget: InvestigationBudget{MaxDecisions: 5, MaxToolCalls: 10, MaxPrivilegedCalls: 1, MaxFanOut: 2}, Deadline: deadline})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "PLANNING" || requests[0].URL.Path != "/api/v1/investigations" || requests[0].Header.Get("Idempotency-Key") != "request-1" {
		t.Fatalf("result=%+v request=%+v", result, requests[0])
	}
	expires := time.Date(2026, 8, 20, 12, 10, 0, 0, time.UTC)
	_, err = client.ApproveInvestigationAction(context.Background(), "investigation-1", ApproveInvestigationRequest{ApprovalID: "approval-1", ActionID: "action-1", ActionSHA256: strings.Repeat("a", 64), ExpectedVersion: 1, ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	if requests[1].URL.Path != "/api/v1/investigations/investigation-1/approvals" {
		t.Fatalf("approval path=%s", requests[1].URL.Path)
	}
}

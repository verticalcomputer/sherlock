package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminui"
	"github.com/verticalcomputer/sherlock/internal/adminview"
	"github.com/verticalcomputer/sherlock/internal/auth"
)

const testToken = "private-service-token-0123456789abcdef"

type humanSessionAccessVerifier struct{}

func (humanSessionAccessVerifier) Verify(_ context.Context, assertion string) (adminui.AccessIdentity, error) {
	if assertion != "signed-test-assertion" {
		return adminui.AccessIdentity{}, adminui.ErrCloudflareAccessDenied
	}
	return adminui.AccessIdentity{Issuer: "https://vertical.cloudflareaccess.com", Subject: "subject-1", Email: "operator@example.com"}, nil
}

type humanSessionErrorReporter struct{}

func (humanSessionErrorReporter) ReportAdminError(context.Context, adminui.AuditDeliveryError) {}

type clientTestClock struct{ now time.Time }

func (clock clientTestClock) Now() time.Time { return clock.now }

func TestClientBindsDashboardAPIRequestToVerifiedAccessIdentity(t *testing.T) {
	var sawHuman, sawSessionCheck bool
	api := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+testToken {
			t.Error("private service token absent")
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch request.URL.Path {
		case "/internal/admin/v1/human-access", "/internal/admin/v1/clusters":
			session, err := auth.VerifyHumanSession([]byte(testToken), request.Header.Get(auth.HumanSessionHeader), request.Method, request.URL.RequestURI(), time.Now().UTC())
			if err != nil || session.Principal.Issuer != "https://vertical.cloudflareaccess.com" || session.Principal.Subject != "subject-1" {
				t.Errorf("missing verified human: %+v err=%v", session, err)
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			if request.URL.Path == "/internal/admin/v1/human-access" {
				sawSessionCheck = true
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write([]byte(`{"clusters":[{"cluster_id":"cluster-1","role":"CLUSTER_VIEWER"}]}`))
				return
			}
			sawHuman = true
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"clusters":[]}`))
		case "/internal/admin/v1/audit":
			writer.WriteHeader(http.StatusNoContent)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer api.Close()
	client, err := New(api.URL, []byte(testToken), &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ui, err := adminui.New(adminui.Options{Provider: client, Auditor: client, ErrorReporter: humanSessionErrorReporter{}, AccessVerifier: humanSessionAccessVerifier{}, Clock: clientTestClock{now: time.Now().UTC()}, RequireHumanAuthorization: true})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://admin.example/admin/clusters", nil)
	request.Header.Set("Cf-Access-Jwt-Assertion", "signed-test-assertion")
	response := httptest.NewRecorder()
	ui.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !sawHuman || !sawSessionCheck || strings.Contains(response.Body.String(), testToken) {
		t.Fatalf("dashboard status=%d saw_human=%v saw_session_check=%v", response.Code, sawHuman, sawSessionCheck)
	}
}

func TestClientLoadsAndMapsDashboard(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 9, 30, 0, 0, time.UTC)
	snapshot := adminview.Dashboard{GeneratedAt: now, Clusters: []adminview.ClusterSummary{{
		ClusterID: "cluster-1", DisplayName: "Mumbai H100", Overall: adminview.StateDegraded,
		Resources:      adminview.ResourceSummary{State: adminview.StateHealthy, ObservedNodes: 10, ObservedGPUs: 80, GPUUtilizationPercent: floatPointer(50), GPUUtilizationSamples: 80},
		Connectivity:   adminview.ConnectivitySummary{State: adminview.StateDegraded, RegisteredCollectors: 3, Collectors: 1, FreshCollectors: 1, MissingCollectorLabels: []string{"comp008 (collector-comp008)"}, ExcludedCollectorLabels: []string{"headnode (collector-old) · REVOKED"}, Sources: 3, LastCollectorContact: timePointer(now.Add(-time.Minute))},
		Freshness:      adminview.FreshnessSummary{State: adminview.StateDegraded, FreshSources: 2, StaleSources: 1, LastSuccessAt: timePointer(now.Add(-2 * time.Minute))},
		Queue:          adminview.QueueSummary{State: adminview.StateDegraded, Overdue: 1, DiagnosticBlocked: 1},
		Investigations: adminview.InvestigationSummary{State: adminview.StateHealthy, Active: 2, Completed: 3, LastUpdate: timePointer(now.Add(-3 * time.Minute))},
		ModelUsage:     adminview.ModelUsageSummary{State: adminview.StateDegraded, Calls: 4, Rejected: 1, InputTokens: 10, OutputTokens: 5, CostMicrounits: 9, LastCallAt: timePointer(now.Add(-4 * time.Minute))},
		Evidence:       adminview.EvidenceCoverageSummary{State: adminview.StateDegraded, CurrentTotal: 2, CurrentComplete: 1, CurrentPartial: 1, CurrentExpectedTargets: 8, CurrentCoveredTargets: 7, Total: 4, Complete: 3, Partial: 1, ExpectedTargets: 16, CoveredTargets: 15, LastCollectedAt: timePointer(now.Add(-5 * time.Minute))},
		Audit:          adminview.AuditSummary{State: adminview.StateDegraded, Events: 5, DeniedOrFailed: 1},
		SlurmOperations: []adminview.SlurmOperationStatus{{
			SourceID: "slurm-source", Operation: "slurm.snapshot.v1", Status: "PARTIAL", Fresh: true, LastCompletedAt: timePointer(now),
		}},
	}}}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/internal/admin/v1/dashboard" {
			t.Errorf("path = %q", request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("Authorization = %q", got)
		}
		if got := request.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
		}
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(snapshot); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	dashboard, err := client.LoadDashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if dashboard.GeneratedAt != now || dashboard.State != adminui.StateDegraded || len(dashboard.Clusters) != 1 {
		t.Fatalf("dashboard = %+v", dashboard)
	}
	cluster := dashboard.Clusters[0]
	if cluster.ID != "cluster-1" || cluster.Name != "Mumbai H100" || cluster.EvidenceExpected != 8 || cluster.EvidenceCovered != 7 || cluster.Resources.ObservedNodes != 10 || cluster.Resources.ObservedGPUs != 80 || strings.Join(cluster.MissingCollectorLabels, ",") != "comp008 (collector-comp008)" || strings.Join(cluster.ExcludedCollectorLabels, ",") != "headnode (collector-old) · REVOKED" {
		t.Fatalf("cluster = %+v", cluster)
	}
	if len(cluster.SlurmOperations) != 1 || cluster.SlurmOperations[0].Status != "PARTIAL" || !cluster.SlurmOperations[0].Fresh {
		t.Fatalf("typed Slurm operation was lost between API and dashboard: %+v", cluster.SlurmOperations)
	}
	wantDimensions := []string{"Connectivity", "Freshness", "Queue", "Investigations", "Model usage", "Evidence", "Diagnostic audit"}
	if len(cluster.Dimensions) != len(wantDimensions) {
		t.Fatalf("dimensions = %+v", cluster.Dimensions)
	}
	for index, want := range wantDimensions {
		if cluster.Dimensions[index].Label != want {
			t.Errorf("dimension %d label = %q, want %q", index, cluster.Dimensions[index].Label, want)
		}
	}
	if len(dashboard.Metrics) != 5 || len(dashboard.Activity) != 3 {
		t.Fatalf("metrics/activity = %d/%d", len(dashboard.Metrics), len(dashboard.Activity))
	}
}

func TestClientRecordsAuditWithServerSideAuthentication(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 9, 30, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/internal/admin/v1/audit" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("Authorization = %q", got)
		}
		if got := request.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		var event auditEvent
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.Kind != adminui.EventDashboardViewed || event.Outcome != adminui.OutcomeSucceeded || event.RequestID != "request-1" || event.OccurredAt != now {
			t.Errorf("event = %+v", event)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	err := client.RecordAdminEvent(context.Background(), adminui.AuditEvent{
		Kind: adminui.EventDashboardViewed, Outcome: adminui.OutcomeSucceeded,
		ReasonCode: "healthy", RequestID: "request-1", OccurredAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestClientClusterManagementAndOperations(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 9, 30, 0, 0, time.UTC)
	fingerprint := bytes.Repeat([]byte{7}, 32)
	requests := make([]string, 0, 7)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.Method+" "+request.URL.RequestURI())
		if request.Header.Get("Authorization") != "Bearer "+testToken {
			t.Errorf("missing service authorization")
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/internal/admin/v1/clusters":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(clustersResponse{Clusters: []clusterResponse{{ID: "cluster-1", DisplayName: "Mumbai", CreatedAt: now}}})
		case request.Method == http.MethodGet && request.URL.Path == "/internal/admin/v1/clusters/cluster-1/summary":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(adminview.ClusterSummary{ClusterID: "cluster-1", DisplayName: "Mumbai", Overall: adminview.StateDegraded,
				Resources: adminview.ResourceSummary{State: adminview.StateHealthy, ObservedNodes: 10, ObservedGPUs: 80, GPUUtilizationPercent: floatPointer(52.5), GPUUtilizationSamples: 80}})
		case request.Method == http.MethodPatch && request.URL.Path == "/internal/admin/v1/clusters/cluster-1":
			var body map[string]json.RawMessage
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body) != 4 || string(body["display_name"]) != `"New Mumbai"` || string(body["expected_collectors"]) != `["fixture1-zone1-headnode"]` || body["occurred_at"] != nil {
				t.Errorf("update body = %s", mustJSON(t, body))
			}
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodDelete && request.URL.Path == "/internal/admin/v1/clusters/cluster-1":
			var body removeClusterRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Confirmation != "cluster-1" || body.RequestID != "request-1" || !bytes.Equal(body.SessionFingerprint, fingerprint) {
				t.Errorf("remove body = %+v", body)
			}
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodGet && request.URL.Path == "/internal/admin/v1/operations":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(operationsResponse{
				Repairs:        repairOverviewDTO{Available: true, ActiveRequests: 3, Decisions: []repairDecisionDTO{{Code: "SOURCE_UNAVAILABLE", Count: 2}}},
				GeneratedAt:    now,
				Tickets:        []ticketResponse{{ID: "ticket-1", ClusterID: "cluster-1", RuleID: "dcgm.xid.nonzero.v1", Title: "XID", Summary: "GPU fault", Severity: "HIGH", Status: "OPEN", UpdatedAt: now, AutoStartStatus: "BLOCKED", AutoStartDecision: "POLICY_DISABLED", AutoStartUpdatedAt: &now}},
				Investigations: []investigationResponse{{ID: "inv-1", ClusterID: "cluster-1", IncidentID: "ticket-1", Question: "Why?", Status: "RUNNING", EntityKind: "gpu", EntityIDs: []string{"node/comp007/gpu/3"}, AuditedTokens: 59_537, AuditedCostMicrounits: 431_510, UpdatedAt: now}},
			})
		case request.Method == http.MethodGet && request.URL.Path == "/internal/admin/v1/clusters/cluster-1/operations":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(operationsResponse{GeneratedAt: now, Tickets: []ticketResponse{{ID: "ticket-1", ClusterID: "cluster-1", Title: "XID"}}, Investigations: []investigationResponse{{ID: "inv-1", ClusterID: "cluster-1", Question: "Why?"}}})
		case request.Method == http.MethodGet && request.URL.Path == "/internal/admin/v1/investigations/inv-1/shared":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(investigationReportResponse{Shared: true, Version: 3, ID: "inv-1", ClusterID: "cluster-1", Question: "Why?", Status: "PARTIAL", WindowStart: now.Add(-time.Hour), WindowEnd: now, UpdatedAt: now,
				ModelUsage: reportModelUsageResponse{MaxTokens: 60_000, AdmittedTokens: 54_922, AuditedTokens: 96_846, MaxCostMicrounits: 2_000_000, AdmittedCostMicrounits: 361_585, AuditedCostMicrounits: 606_655},
				Findings:   []reportFindingResponse{{ID: "finding-1", Statement: "Validated", EvidenceIDs: []string{"evidence-1"}}},
				Evidence:   []reportEvidenceResponse{{ID: "evidence-1", Kind: "OBSERVATION", Status: "COMPLETE", ExactScope: ""}},
				ModelCalls: []modelCallResponse{}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := newTestClient(t, server.URL)

	clusters, err := client.ListClusters(context.Background())
	if err != nil || len(clusters) != 1 || clusters[0].ID != "cluster-1" || clusters[0].State != adminui.StateNoData {
		t.Fatalf("ListClusters() = %+v, %v", clusters, err)
	}
	cluster, err := client.GetCluster(context.Background(), "cluster-1")
	if err != nil || cluster.DisplayName != "Mumbai" {
		t.Fatalf("GetCluster() = %+v, %v", cluster, err)
	}
	summary, err := client.GetClusterSummary(context.Background(), "cluster-1")
	if err != nil || summary.Resources.ObservedNodes != 10 || summary.Resources.ObservedGPUs != 80 || summary.Resources.GPUUtilizationPercent == nil || *summary.Resources.GPUUtilizationPercent != 52.5 {
		t.Fatalf("GetClusterSummary() = %+v, %v", summary, err)
	}
	mutation := adminui.MutationContext{SessionFingerprint: fingerprint, RequestID: "request-1", OccurredAt: now.Add(-time.Hour)}
	if err := client.UpdateCluster(context.Background(), "cluster-1", adminui.ClusterUpdate{DisplayName: "New Mumbai", ExpectedCollectors: []string{"fixture1-zone1-headnode"}}, mutation); err != nil {
		t.Fatal(err)
	}
	if err := client.RemoveCluster(context.Background(), "cluster-1", mutation); err != nil {
		t.Fatal(err)
	}
	operations, err := client.LoadOperations(context.Background())
	if !operations.Repairs.Available || operations.Repairs.ActiveRequests != 3 || len(operations.Repairs.Decisions) != 1 || operations.Repairs.Decisions[0].Code != "SOURCE_UNAVAILABLE" {
		t.Fatalf("repair mapping = %+v", operations.Repairs)
	}
	if err != nil || operations.GeneratedAt != now || len(operations.Tickets) != 1 || operations.Tickets[0].Summary != "GPU fault" || operations.Tickets[0].RuleID != "dcgm.xid.nonzero.v1" || operations.Tickets[0].AutoStartDecision != "POLICY_DISABLED" || len(operations.Investigations) != 1 || operations.Investigations[0].EntityKind != "gpu" || len(operations.Investigations[0].EntityIDs) != 1 || operations.Investigations[0].EntityIDs[0] != "node/comp007/gpu/3" || operations.Investigations[0].AuditedTokens != 59_537 || operations.Investigations[0].AuditedCostMicrounits != 431_510 {
		t.Fatalf("LoadOperations() = %+v, %v", operations, err)
	}
	clusterOperations, err := client.LoadClusterOperations(context.Background(), "cluster-1")
	if err != nil || len(clusterOperations.Tickets) != 1 || len(clusterOperations.Investigations) != 1 {
		t.Fatalf("LoadClusterOperations() = %+v, %v", clusterOperations, err)
	}
	report, err := client.LoadInvestigationReport(context.Background(), "inv-1")
	if err != nil || report.ID != "inv-1" || len(report.Findings) != 1 || report.Findings[0].EvidenceIDs[0] != "evidence-1" || len(report.Evidence) != 1 || len(report.ModelCalls) != 0 || !report.Shared || report.Version != 3 || report.ModelUsage.AuditedTokens != 96_846 {
		t.Fatalf("LoadInvestigationReport() = %+v, %v", report, err)
	}
	if len(requests) != 8 {
		t.Fatalf("requests = %#v", requests)
	}
}

func TestClientRejectsInvalidClusterIDsWithoutRequest(t *testing.T) {
	t.Parallel()
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer server.Close()
	client := newTestClient(t, server.URL)
	mutation := adminui.MutationContext{SessionFingerprint: bytes.Repeat([]byte{1}, 32)}
	if _, err := client.GetCluster(context.Background(), "bad/id"); err == nil {
		t.Fatal("GetCluster() error = nil")
	}
	if _, err := client.GetClusterSummary(context.Background(), "bad/id"); err == nil {
		t.Fatal("GetClusterSummary() error = nil")
	}
	if _, err := client.LoadClusterOperations(context.Background(), "bad/id"); err == nil {
		t.Fatal("LoadClusterOperations() error = nil")
	}
	if err := client.UpdateCluster(context.Background(), "bad id", adminui.ClusterUpdate{}, mutation); err == nil {
		t.Fatal("UpdateCluster() error = nil")
	}
	if err := client.RemoveCluster(context.Background(), "", mutation); err == nil {
		t.Fatal("RemoveCluster() error = nil")
	}
	if called {
		t.Fatal("server called for invalid cluster ID")
	}
}

func TestClientStartsBoundedInvestigationWithoutPrivilegedCalls(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/internal/admin/v1/clusters/cluster-1/investigations" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		var body investigationStartRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Budget.MaxPrivilegedCalls != 0 || body.Budget.MaxDiagnosticCalls != 2 || body.IdempotencyKey != "admin-run-1" || len(body.SessionFingerprint) != 32 {
			t.Fatalf("request body = %+v", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		_, _ = writer.Write([]byte(`{"investigation_id":"investigation-new","status":"PLANNING","replayed":false}`))
	}))
	defer server.Close()
	result, err := newTestClient(t, server.URL).StartInvestigation(t.Context(), "cluster-1", adminui.InvestigationStart{
		IncidentID: "ticket-1", Question: "Why?", EntityKind: "node", EntityIDs: []string{"comp007"},
		WindowStart: now.Add(-time.Hour), WindowEnd: now, SuccessCriteria: []string{"Reach a conclusion"},
		MaxDecisions: 10, MaxToolCalls: 12, MaxDiagnosticCalls: 2, MaxFanOut: 1,
		MaxModelTokens: 80000, MaxCostMicrounits: 1_000_000, Deadline: now.Add(20 * time.Minute),
		IdempotencyKey: "admin-run-1",
	}, adminui.MutationContext{SessionFingerprint: make([]byte, 32), RequestID: "request-1"})
	if err != nil || result.ID != "investigation-new" || result.Status != "PLANNING" || result.Replayed {
		t.Fatalf("StartInvestigation() = %+v, %v", result, err)
	}
}

func TestInvestigationReportDistinguishesMissingRecordFromMissingRoute(t *testing.T) {
	for _, test := range []struct {
		name, contentType, body string
		wantNotFound            bool
	}{
		{"record", "application/problem+json", `{"status":404,"code":"NOT_FOUND"}`, true},
		{"stale API route", "text/plain; charset=utf-8", "404 page not found", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", test.contentType)
				writer.WriteHeader(http.StatusNotFound)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			_, err := newTestClient(t, server.URL).LoadInvestigationReport(t.Context(), "inv-1")
			if errors.Is(err, adminui.ErrRecordNotFound) != test.wantNotFound {
				t.Fatalf("err=%v wantNotFound=%t", err, test.wantNotFound)
			}
		})
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestClientRejectsUnsafeConstruction(t *testing.T) {
	t.Parallel()
	httpClient := &http.Client{Timeout: time.Second}
	for _, test := range []struct {
		name, baseURL string
		token         []byte
		client        *http.Client
	}{
		{name: "missing token", baseURL: "https://api.example.com", client: httpClient},
		{name: "short token", baseURL: "https://api.example.com", token: []byte("short"), client: httpClient},
		{name: "oversize token", baseURL: "https://api.example.com", token: []byte(strings.Repeat("x", 513)), client: httpClient},
		{name: "invalid token characters", baseURL: "https://api.example.com", token: []byte(strings.Repeat("x", 31) + " "), client: httpClient},
		{name: "non-loopback HTTP", baseURL: "http://api.example.com", token: []byte(testToken), client: httpClient},
		{name: "base path", baseURL: "https://api.example.com/base", token: []byte(testToken), client: httpClient},
		{name: "credentials", baseURL: "https://user@example.com", token: []byte(testToken), client: httpClient},
		{name: "missing client", baseURL: "https://api.example.com", token: []byte(testToken)},
		{name: "missing timeout", baseURL: "https://api.example.com", token: []byte(testToken), client: &http.Client{}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(test.baseURL, test.token, test.client); err == nil {
				t.Fatal("New() error = nil")
			}
		})
	}
}

func TestClientRejectsRedirect(t *testing.T) {
	t.Parallel()
	targetCalled := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalled = true }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	_, err := newTestClient(t, server.URL).LoadDashboard(context.Background())
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("error = %v", err)
	}
	if targetCalled {
		t.Fatal("redirect target was called")
	}
}

func TestClientRejectsBadResponsesWithoutLeakingThem(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{name: "non success", status: http.StatusInternalServerError, contentType: "text/plain", body: "sensitive database failure"},
		{name: "oversize", status: http.StatusOK, contentType: "application/json", body: strings.Repeat("x", int(maximumResponseBytes)+1)},
		{name: "malformed", status: http.StatusOK, contentType: "application/json", body: `{"generated_at":`},
		{name: "unknown field", status: http.StatusOK, contentType: "application/json", body: `{"generated_at":"2026-08-20T09:30:00Z","unexpected":true}`},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", test.contentType)
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			_, err := newTestClient(t, server.URL).LoadDashboard(context.Background())
			if err == nil {
				t.Fatal("LoadDashboard() error = nil")
			}
			if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), test.body) {
				t.Fatalf("unsafe error = %q", err)
			}
		})
	}
}

func TestClientUsesRequestContext(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newTestClient(t, server.URL).LoadDashboard(ctx)
	if err == nil {
		t.Fatal("LoadDashboard() error = nil")
	}
}

func newTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	client, err := New(baseURL, []byte(testToken), &http.Client{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func timePointer(value time.Time) *time.Time { return &value }
func floatPointer(value float64) *float64    { return &value }

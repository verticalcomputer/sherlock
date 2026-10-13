package adminapi

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

	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/adminui"
	"github.com/verticalcomputer/sherlock/internal/adminview"
	publicapi "github.com/verticalcomputer/sherlock/internal/api"
	"github.com/verticalcomputer/sherlock/internal/auth"
)

const testServiceToken = "admin-api-service-token-with-at-least-32-bytes"

type fakeProvider struct {
	dashboard adminview.Dashboard
	err       error
	queries   []adminview.Query
}

func (provider *fakeProvider) Snapshot(_ context.Context, query adminview.Query) (adminview.Dashboard, error) {
	provider.queries = append(provider.queries, query)
	return provider.dashboard, provider.err
}

type fakeAuditor struct {
	events []adminui.AuditEvent
	err    error
}

type fakeManagement struct {
	clusters       []adminmanage.Cluster
	operations     adminmanage.Operations
	report         adminmanage.InvestigationReport
	err            error
	includeRemoved bool
	limit          int
	clusterID      string
	updatedID      string
	displayName    string
	expected       []string
	updateAudit    adminmanage.MutationAudit
	removedID      string
	removedAt      time.Time
	removeAudit    adminmanage.MutationAudit
}

func (management *fakeManagement) ListClusters(_ context.Context, includeRemoved bool, limit int) ([]adminmanage.Cluster, error) {
	management.includeRemoved, management.limit = includeRemoved, limit
	return management.clusters, management.err
}

func (management *fakeManagement) ListOperations(_ context.Context, limit int) (adminmanage.Operations, error) {
	management.limit = limit
	return management.operations, management.err
}

func (management *fakeManagement) ListClusterOperations(_ context.Context, clusterID string, limit int) (adminmanage.Operations, error) {
	management.clusterID, management.limit = clusterID, limit
	return management.operations, management.err
}

func (management *fakeManagement) GetInvestigationReport(_ context.Context, _ string) (adminmanage.InvestigationReport, error) {
	return management.report, management.err
}

func (management *fakeManagement) UpdateCluster(_ context.Context, id, displayName string, expected []string, audit adminmanage.MutationAudit) error {
	management.updatedID, management.displayName, management.expected, management.updateAudit = id, displayName, append([]string(nil), expected...), audit
	return management.err
}

func (management *fakeManagement) RemoveCluster(_ context.Context, id string, at time.Time, audit adminmanage.MutationAudit) error {
	management.removedID, management.removedAt, management.removeAudit = id, at, audit
	return management.err
}

func (auditor *fakeAuditor) RecordAdminEvent(_ context.Context, event adminui.AuditEvent) error {
	auditor.events = append(auditor.events, event)
	return auditor.err
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type fakeInvestigationStarter struct {
	input    publicapi.StartInvestigationInput
	replayed bool
	err      error
}

func (starter *fakeInvestigationStarter) StartInvestigation(_ context.Context, input publicapi.StartInvestigationInput) (publicapi.InvestigationResource, bool, error) {
	starter.input = input
	return publicapi.InvestigationResource{InvestigationID: "investigation-new", Status: "PLANNING"}, starter.replayed, starter.err
}

type fakeInvestigationCanceller struct {
	calls int
	input publicapi.CancelInvestigationInput
	err   error
}

func (canceller *fakeInvestigationCanceller) CancelInvestigation(_ context.Context, input publicapi.CancelInvestigationInput) (publicapi.InvestigationResource, error) {
	canceller.calls++
	canceller.input = input
	if canceller.err != nil {
		return publicapi.InvestigationResource{}, canceller.err
	}
	return publicapi.InvestigationResource{InvestigationID: input.InvestigationID, Status: "CANCELLED"}, nil
}

func TestPrivateAdminCancelsAttributedInvestigation(t *testing.T) {
	now := time.Date(2026, 9, 11, 18, 30, 0, 0, time.UTC)
	canceller := &fakeInvestigationCanceller{}
	server, err := New(Options{Provider: &fakeProvider{}, Management: &fakeManagement{}, Cancellations: canceller, Auditor: &fakeAuditor{}, ServiceToken: []byte(testServiceToken), Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatal(err)
	}
	target := "/internal/admin/v1/investigations/investigation-1/cancel"
	cancel := func(body investigationCancelDTO) *httptest.ResponseRecorder {
		encoded, _ := json.Marshal(body)
		return serve(server, http.MethodPost, target, encoded, "application/json")
	}
	valid := investigationCancelDTO{ExpectedVersion: 10, Reason: " stuck synthesis loop ", SessionFingerprint: bytes.Repeat([]byte{0x2a}, 32), RequestID: "request-1"}

	response := cancel(valid)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"CANCELLED"`) {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	if canceller.input.InvestigationID != "investigation-1" || canceller.input.ActorID != "admin-ui-2a2a2a2a2a2a2a2a" || canceller.input.ExpectedVersion != 10 || canceller.input.Reason != "stuck synthesis loop" {
		t.Fatalf("canceller input = %+v", canceller.input)
	}

	for name, body := range map[string]investigationCancelDTO{
		"missing version":   {Reason: valid.Reason, SessionFingerprint: valid.SessionFingerprint},
		"blank reason":      {ExpectedVersion: 10, Reason: "  ", SessionFingerprint: valid.SessionFingerprint},
		"short fingerprint": {ExpectedVersion: 10, Reason: valid.Reason, SessionFingerprint: []byte{1}},
		"oversized reason":  {ExpectedVersion: 10, Reason: strings.Repeat("x", 513), SessionFingerprint: valid.SessionFingerprint},
	} {
		if response := cancel(body); response.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d %s", name, response.Code, response.Body.String())
		}
	}
	if canceller.calls != 1 {
		t.Fatalf("invalid requests reached the canceller: calls = %d", canceller.calls)
	}
	if response := serve(server, http.MethodPost, "/internal/admin/v1/investigations/bad%20id/cancel", []byte(`{}`), "application/json"); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid path status = %d", response.Code)
	}

	canceller.err = publicapi.ErrInvestigationConflict
	if response := cancel(valid); response.Code != http.StatusConflict {
		t.Fatalf("conflict status = %d %s", response.Code, response.Body.String())
	}
	canceller.err = errors.New("database password=secret")
	if response := cancel(valid); response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "secret") {
		t.Fatalf("backend error = %d %s", response.Code, response.Body.String())
	}

	unconfigured := newTestServer(t, &fakeProvider{}, &fakeAuditor{}, now)
	encoded, _ := json.Marshal(valid)
	if response := serve(unconfigured, http.MethodPost, target, encoded, "application/json"); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured status = %d", response.Code)
	}
}

func TestNewValidatesDependencies(t *testing.T) {
	provider := &fakeProvider{}
	auditor := &fakeAuditor{}
	management := &fakeManagement{}
	tests := []struct {
		name    string
		options Options
		want    string
	}{
		{"provider", Options{Management: management, Auditor: auditor, ServiceToken: []byte(testServiceToken)}, "provider"},
		{"auditor", Options{Provider: provider, Management: management, ServiceToken: []byte(testServiceToken)}, "auditor"},
		{"management", Options{Provider: provider, Auditor: auditor, ServiceToken: []byte(testServiceToken)}, "management"},
		{"token", Options{Provider: provider, Management: management, Auditor: auditor, ServiceToken: []byte("short")}, "between 32 and 512"},
		{"token characters", Options{Provider: provider, Management: management, Auditor: auditor, ServiceToken: []byte(strings.Repeat("x", 32) + " ")}, "invalid characters"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(test.options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("New() error = %v, want text %q", err, test.want)
			}
		})
	}
}

func TestManagementListingsUseBoundedServerSideQueries(t *testing.T) {
	now := time.Date(2026, 8, 20, 7, 8, 9, 0, time.UTC)
	management := &fakeManagement{
		clusters: []adminmanage.Cluster{{ID: "cluster-1", DisplayName: "Mumbai", CreatedAt: now}},
		operations: adminmanage.Operations{
			Repairs:        adminmanage.RepairOverview{Available: true, ActiveRequests: 3, Decisions: []adminmanage.RepairDecision{{Code: "SOURCE_UNAVAILABLE", Count: 2}}},
			Tickets:        []adminmanage.Ticket{{ID: "ticket-1", ClusterID: "cluster-1", RuleID: "dcgm.xid.nonzero.v1", Title: "GPU alert", Severity: "HIGH", Status: "OPEN", UpdatedAt: now, AutoStartStatus: "BLOCKED", AutoStartDecision: "POLICY_DISABLED", AutoStartUpdatedAt: &now}},
			Investigations: []adminmanage.Investigation{{ID: "inv-1", ClusterID: "cluster-1", IncidentID: "ticket-1", Question: "Why?", Status: "RUNNING", EntityKind: "gpu", EntityIDs: []string{"node/comp007/gpu/3"}, AuditedTokens: 59_537, AuditedCostMicrounits: 431_510, UpdatedAt: now}},
		},
	}
	server := newTestServerWithManagement(t, &fakeProvider{}, &fakeAuditor{}, management, now)

	clusters := serve(server, http.MethodGet, "/internal/admin/v1/clusters", nil, "")
	if clusters.Code != http.StatusOK || management.includeRemoved || management.limit != clusterListLimit {
		t.Fatalf("clusters status/options = %d/%t/%d, body = %s", clusters.Code, management.includeRemoved, management.limit, clusters.Body.String())
	}
	if !strings.Contains(clusters.Body.String(), `"cluster_id":"cluster-1"`) || strings.Contains(clusters.Body.String(), "ClusterID") {
		t.Fatalf("cluster wire format = %s", clusters.Body.String())
	}

	operations := serve(server, http.MethodGet, "/internal/admin/v1/operations", nil, "")
	if !strings.Contains(operations.Body.String(), `"active_requests":3`) || !strings.Contains(operations.Body.String(), `"code":"SOURCE_UNAVAILABLE"`) {
		t.Fatalf("missing repair projection: %s", operations.Body.String())
	}
	if operations.Code != http.StatusOK || management.limit != operationsListLimit {
		t.Fatalf("operations status/limit = %d/%d, body = %s", operations.Code, management.limit, operations.Body.String())
	}
	if !strings.Contains(operations.Body.String(), `"ticket_id":"ticket-1"`) || !strings.Contains(operations.Body.String(), `"rule_id":"dcgm.xid.nonzero.v1"`) || !strings.Contains(operations.Body.String(), `"investigation_id":"inv-1"`) || !strings.Contains(operations.Body.String(), `"entity_kind":"gpu"`) || !strings.Contains(operations.Body.String(), `"node/comp007/gpu/3"`) || !strings.Contains(operations.Body.String(), `"audited_tokens":59537`) || !strings.Contains(operations.Body.String(), `"audited_cost_microunits":431510`) || !strings.Contains(operations.Body.String(), `"auto_start_decision":"POLICY_DISABLED"`) {
		t.Fatalf("operations wire format = %s", operations.Body.String())
	}

	clusterOperations := serve(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-1/operations", nil, "")
	if clusterOperations.Code != http.StatusOK || management.clusterID != "cluster-1" || management.limit != operationsListLimit {
		t.Fatalf("cluster operations = %d/%q/%d, body = %s", clusterOperations.Code, management.clusterID, management.limit, clusterOperations.Body.String())
	}
}

func TestPrivateAdminStartsBoundedAttributedInvestigation(t *testing.T) {
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	starter := &fakeInvestigationStarter{}
	server, err := New(Options{Provider: &fakeProvider{}, Management: &fakeManagement{}, Investigations: starter, Auditor: &fakeAuditor{}, ServiceToken: []byte(testServiceToken), Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(investigationStartDTO{
		IncidentID: "ticket-1", Question: "Is the fault active?",
		Scope:           publicapi.InvestigationScopeResource{EntityKind: "node", EntityIDs: []string{"comp007"}, Start: now.Add(-time.Hour), End: now},
		SuccessCriteria: []string{"Reach a cited conclusion"},
		Budget:          publicapi.InvestigationBudgetResource{MaxDecisions: 10, MaxToolCalls: 12, MaxDiagnosticCalls: 2, MaxFanOut: 1, MaxModelTokens: 80000, MaxCostMicros: 1_000_000},
		Deadline:        now.Add(20 * time.Minute), IdempotencyKey: "admin-run-1",
		SessionFingerprint: bytes.Repeat([]byte{0x2a}, 32), RequestID: "request-1",
	})
	response := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/investigations", body, "application/json")
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"investigation_id":"investigation-new"`) {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	if starter.input.ClusterID != "cluster-1" || starter.input.ActorID != "admin-ui-2a2a2a2a2a2a2a2a" || starter.input.Budget.MaxPrivilegedCalls != 0 || starter.input.Budget.MaxDiagnosticCalls != 2 {
		t.Fatalf("starter input = %+v", starter.input)
	}
}

func TestInvestigationReportUsesRedactedWireContract(t *testing.T) {
	now := time.Date(2026, 8, 20, 7, 8, 9, 0, time.UTC)
	confidence := .92
	management := &fakeManagement{report: adminmanage.InvestigationReport{
		ID: "inv-1", ClusterID: "cluster-1", Question: "What happened?", Status: "PARTIAL",
		WindowStart: now.Add(-time.Hour), WindowEnd: now, UpdatedAt: now,
		ModelUsage: adminmanage.ReportModelUsage{MaxTokens: 60_000, AdmittedTokens: 54_922, AuditedTokens: 96_846, MaxCostMicrounits: 2_000_000, AdmittedCostMicrounits: 361_585, AuditedCostMicrounits: 606_655},
		Findings:   []adminmanage.ReportFinding{{ID: "finding-1", Kind: "CONCLUSION", Statement: "Validated", Confidence: &confidence, EvidenceIDs: []string{"evidence-1"}}},
		Evidence:   []adminmanage.ReportEvidence{{ID: "evidence-1", Kind: "OBSERVATION", Status: "COMPLETE", ExactScope: `{}`}},
		ModelCalls: []adminmanage.ModelCall{{ID: "call-1", Kind: "SYNTHESIS", Provider: "azure-openai", Model: "gpt", PromptSchemaVersion: "synthesis-v1", Outcome: "SUCCEEDED", OccurredAt: now, Input: adminmanage.ModelPayload{Availability: adminmanage.PayloadAvailable, Content: `{"question":"why"}`}, Output: adminmanage.ModelPayload{Availability: adminmanage.PayloadAvailable, Content: `{"answer":"because"}`}}},
	}}
	server := newTestServerWithManagement(t, &fakeProvider{}, &fakeAuditor{}, management, now)
	response := serve(server, http.MethodGet, "/internal/admin/v1/investigations/inv-1", nil, "")
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, `"finding_id":"finding-1"`) || !strings.Contains(body, `"evidence_ids":["evidence-1"]`) || !strings.Contains(body, `"call_id":"call-1"`) || !strings.Contains(body, `"audited_tokens":96846`) || !strings.Contains(body, `\"answer\":\"because\"`) {
		t.Fatalf("report = %d %s", response.Code, body)
	}
	for _, forbidden := range []string{"actor_id", "requested_by", "api_key"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("report leaked forbidden field %q: %s", forbidden, body)
		}
	}
}

func TestClusterMutationsValidateAndAttachServerAudit(t *testing.T) {
	now := time.Date(2026, 8, 20, 7, 8, 9, 0, time.UTC)
	management := &fakeManagement{}
	server := newTestServerWithManagement(t, &fakeProvider{}, &fakeAuditor{}, management, now)
	fingerprint := bytes.Repeat([]byte{9}, 32)

	update, _ := json.Marshal(updateClusterDTO{DisplayName: " New name ", ExpectedCollectors: []string{"headnode-a", "headnode-b"}, SessionFingerprint: fingerprint, RequestID: "request-update"})
	response := serve(server, http.MethodPatch, "/internal/admin/v1/clusters/cluster-1", update, "application/json")
	if response.Code != http.StatusNoContent {
		t.Fatalf("update status = %d, body = %s", response.Code, response.Body.String())
	}
	if management.updatedID != "cluster-1" || management.displayName != "New name" || strings.Join(management.expected, ",") != "headnode-a,headnode-b" || management.updateAudit.EventKind != adminmanage.EventClusterUpdated || management.updateAudit.OccurredAt != now {
		t.Fatalf("update = %q/%q/%+v", management.updatedID, management.displayName, management.updateAudit)
	}
	if management.updateAudit.EventID == "" || management.updateAudit.RequestID != "request-update" || !bytes.Equal(management.updateAudit.SessionFingerprint, fingerprint) {
		t.Fatalf("update audit = %+v", management.updateAudit)
	}

	remove, _ := json.Marshal(removeClusterDTO{Confirmation: "cluster-1", SessionFingerprint: fingerprint, RequestID: "request-remove"})
	response = serve(server, http.MethodDelete, "/internal/admin/v1/clusters/cluster-1", remove, "application/json")
	if response.Code != http.StatusNoContent {
		t.Fatalf("remove status = %d, body = %s", response.Code, response.Body.String())
	}
	if management.removedID != "cluster-1" || management.removedAt != now || management.removeAudit.EventKind != adminmanage.EventClusterRemoved || management.removeAudit.OccurredAt != now {
		t.Fatalf("remove = %q/%v/%+v", management.removedID, management.removedAt, management.removeAudit)
	}
}

func TestClusterMutationsRejectUnsafeBodiesAndMapErrors(t *testing.T) {
	server := newTestServer(t, &fakeProvider{}, &fakeAuditor{}, time.Now())
	fingerprint := bytes.Repeat([]byte{1}, 32)
	tests := []struct {
		method, target, body, contentType string
		status                            int
	}{
		{http.MethodPatch, "/internal/admin/v1/clusters/bad%2Fid", `{}`, "application/json", http.StatusBadRequest},
		{http.MethodPatch, "/internal/admin/v1/clusters/cluster-1", `{"display_name":"x","unexpected":true}`, "application/json", http.StatusBadRequest},
		{http.MethodPatch, "/internal/admin/v1/clusters/cluster-1", `{}`, "text/plain", http.StatusUnsupportedMediaType},
		{http.MethodDelete, "/internal/admin/v1/clusters/cluster-1", `{"confirmation":"wrong"}`, "application/json", http.StatusBadRequest},
	}
	for _, test := range tests {
		response := serve(server, test.method, test.target, []byte(test.body), test.contentType)
		if response.Code != test.status {
			t.Errorf("%s %s: status = %d, want %d, body = %s", test.method, test.target, response.Code, test.status, response.Body.String())
		}
	}

	for backend, want := range map[error]int{adminmanage.ErrInvalid: http.StatusBadRequest, adminmanage.ErrNotFound: http.StatusNotFound, adminmanage.ErrConflict: http.StatusConflict, errors.New("postgres://secret"): http.StatusServiceUnavailable} {
		management := &fakeManagement{err: backend}
		server := newTestServerWithManagement(t, &fakeProvider{}, &fakeAuditor{}, management, time.Now())
		body, _ := json.Marshal(updateClusterDTO{DisplayName: "Name", SessionFingerprint: fingerprint})
		response := serve(server, http.MethodPatch, "/internal/admin/v1/clusters/cluster-1", body, "application/json")
		if response.Code != want || strings.Contains(response.Body.String(), "postgres") || strings.Contains(response.Body.String(), "secret") {
			t.Errorf("backend %v: status/body = %d/%s", backend, response.Code, response.Body.String())
		}
	}
}

func TestDashboardReturnsSnapshotAtClockTime(t *testing.T) {
	now := time.Date(2026, 8, 20, 4, 5, 6, 0, time.FixedZone("test", 5*60*60+30*60))
	want := adminview.Dashboard{GeneratedAt: now.UTC(), Clusters: []adminview.ClusterSummary{{ClusterID: "cluster-safe", DisplayName: "Mumbai"}}}
	provider := &fakeProvider{dashboard: want}
	server := newTestServer(t, provider, &fakeAuditor{}, now)

	response := serve(server, http.MethodGet, "/internal/admin/v1/dashboard", nil, "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(provider.queries) != 1 || !provider.queries[0].At.Equal(now.UTC()) {
		t.Fatalf("queries = %#v, want UTC clock time", provider.queries)
	}
	var got adminview.Dashboard
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode dashboard: %v", err)
	}
	if len(got.Clusters) != 1 || got.Clusters[0].ClusterID != "cluster-safe" {
		t.Fatalf("dashboard = %#v", got)
	}
	assertSecurityHeaders(t, response)
}

func TestClusterSummaryScopesSnapshotToRequestedCluster(t *testing.T) {
	now := time.Date(2026, 8, 20, 4, 5, 6, 0, time.UTC)
	gpuUtilization := 61.25
	provider := &fakeProvider{dashboard: adminview.Dashboard{Clusters: []adminview.ClusterSummary{{
		ClusterID: "cluster-1", DisplayName: "Mumbai", Resources: adminview.ResourceSummary{
			State: adminview.StateHealthy, ObservedNodes: 10, ObservedGPUs: 80,
			GPUUtilizationPercent: &gpuUtilization, GPUUtilizationSamples: 80,
		},
	}}}}
	server := newTestServer(t, provider, &fakeAuditor{}, now)
	response := serve(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-1/summary", nil, "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"observed_nodes":10`) || !strings.Contains(response.Body.String(), `"gpu_utilization_percent":61.25`) {
		t.Fatalf("summary = %d %s", response.Code, response.Body.String())
	}
	if len(provider.queries) != 1 || provider.queries[0].ClusterID != "cluster-1" || provider.queries[0].Limit != 1 || !provider.queries[0].At.Equal(now) {
		t.Fatalf("queries = %#v", provider.queries)
	}

	provider.dashboard.Clusters = nil
	response = serve(server, http.MethodGet, "/internal/admin/v1/clusters/missing/summary", nil, "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing summary = %d %s", response.Code, response.Body.String())
	}
}

func TestAuthenticationRejectsMissingMalformedAndIncorrectTokens(t *testing.T) {
	server := newTestServer(t, &fakeProvider{}, &fakeAuditor{}, time.Now())
	values := []string{"", "Basic abc", "Bearer short", "Bearer " + strings.Repeat("x", 40), "Bearer " + testServiceToken + ",other", "Bearer " + testServiceToken + " extra"}
	for _, value := range values {
		request := httptest.NewRequest(http.MethodGet, "/internal/admin/v1/dashboard", nil)
		request.Header.Set("Authorization", value)
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q: status = %d", value, response.Code)
		}
		if strings.Contains(response.Body.String(), testServiceToken) {
			t.Errorf("Authorization %q was reflected in response", value)
		}
		assertSecurityHeaders(t, response)
	}
}

func TestRoutesRejectQueriesAndWrongMethods(t *testing.T) {
	provider := &fakeProvider{}
	server := newTestServer(t, provider, &fakeAuditor{}, time.Now())
	for _, target := range []string{"/internal/admin/v1/dashboard?limit=1", "/internal/admin/v1/clusters/cluster-1/summary?limit=1", "/internal/admin/v1/clusters/cluster-1/operations?limit=1", "/internal/admin/v1/audit?x=1"} {
		method := http.MethodGet
		var body []byte
		contentType := ""
		if strings.Contains(target, "audit") {
			method, body, contentType = http.MethodPost, []byte(`{}`), "application/json"
		}
		response := serve(server, method, target, body, contentType)
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, body = %s", target, response.Code, response.Body.String())
		}
	}
	response := serve(server, http.MethodPost, "/internal/admin/v1/dashboard", nil, "")
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method status = %d", response.Code)
	}
	if len(provider.queries) != 0 {
		t.Fatalf("provider called for rejected requests: %#v", provider.queries)
	}
}

func TestAuditStrictDecodingAndBounds(t *testing.T) {
	auditor := &fakeAuditor{}
	server := newTestServer(t, &fakeProvider{}, auditor, time.Now())
	tests := []struct {
		name        string
		body        []byte
		contentType string
		status      int
	}{
		{"content type", []byte(`{}`), "text/plain", http.StatusUnsupportedMediaType},
		{"unknown field", []byte(`{"unexpected":true}`), "application/json", http.StatusBadRequest},
		{"trailing value", []byte(`{} {}`), "application/json", http.StatusBadRequest},
		{"malformed", []byte(`{"kind":`), "application/json", http.StatusBadRequest},
		{"too large", bytes.Repeat([]byte(" "), int(maxAuditBodySize)+1), "application/json", http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := serve(server, http.MethodPost, "/internal/admin/v1/audit", test.body, test.contentType)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d, body = %s", response.Code, test.status, response.Body.String())
			}
		})
	}
	if len(auditor.events) != 0 {
		t.Fatalf("auditor received invalid events: %#v", auditor.events)
	}
}

func TestAuditValidatesAndDelegates(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	auditor := &fakeAuditor{}
	server := newTestServer(t, &fakeProvider{}, auditor, now)
	valid := adminui.AuditEvent{
		Kind: adminui.EventDashboardViewed, Outcome: adminui.OutcomeSucceeded,
		ReasonCode: "healthy", SessionFingerprint: bytes.Repeat([]byte{7}, 32),
		RequestID: "request-1", OccurredAt: now,
	}
	body, err := json.Marshal(auditEventDTO{
		Kind: valid.Kind, Outcome: valid.Outcome, ReasonCode: valid.ReasonCode,
		SessionFingerprint: valid.SessionFingerprint, RequestID: valid.RequestID, OccurredAt: valid.OccurredAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(server, http.MethodPost, "/internal/admin/v1/audit", body, "application/json; charset=utf-8")
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
	if len(auditor.events) != 1 || auditor.events[0].RequestID != valid.RequestID || !bytes.Equal(auditor.events[0].SessionFingerprint, valid.SessionFingerprint) {
		t.Fatalf("events = %#v", auditor.events)
	}

	invalid := []adminui.AuditEvent{
		{Outcome: adminui.OutcomeSucceeded, OccurredAt: now},
		{Kind: adminui.EventDashboardViewed, Outcome: "UNKNOWN", OccurredAt: now},
		{Kind: adminui.EventDashboardViewed, Outcome: adminui.OutcomeSucceeded},
		{Kind: adminui.EventDashboardViewed, Outcome: adminui.OutcomeSucceeded, OccurredAt: now, SessionFingerprint: []byte{1}},
		{Kind: adminui.EventDashboardViewed, Outcome: adminui.OutcomeSucceeded, OccurredAt: now, ReasonCode: strings.Repeat("r", 129)},
		{Kind: adminui.EventDashboardViewed, Outcome: adminui.OutcomeSucceeded, OccurredAt: now, RequestID: strings.Repeat("r", 129)},
	}
	for index, event := range invalid {
		body, _ := json.Marshal(auditEventDTO{
			Kind: event.Kind, Outcome: event.Outcome, ReasonCode: event.ReasonCode,
			SessionFingerprint: event.SessionFingerprint, RequestID: event.RequestID, OccurredAt: event.OccurredAt,
		})
		response := serve(server, http.MethodPost, "/internal/admin/v1/audit", body, "application/json")
		if response.Code != http.StatusBadRequest {
			t.Errorf("invalid event %d: status = %d", index, response.Code)
		}
	}
	if len(auditor.events) != 1 {
		t.Fatalf("auditor received invalid events: %#v", auditor.events[1:])
	}
}

func TestBackendErrorsAreRedacted(t *testing.T) {
	const sensitive = "postgres://admin:secret@database/private"
	provider := &fakeProvider{err: errors.New(sensitive)}
	auditor := &fakeAuditor{err: errors.New(sensitive)}
	server := newTestServer(t, provider, auditor, time.Now())

	dashboardResponse := serve(server, http.MethodGet, "/internal/admin/v1/dashboard", nil, "")
	event := adminui.AuditEvent{Kind: adminui.EventDashboardViewed, Outcome: adminui.OutcomeSucceeded, OccurredAt: time.Now()}
	body, _ := json.Marshal(auditEventDTO{Kind: event.Kind, Outcome: event.Outcome, OccurredAt: event.OccurredAt})
	auditResponse := serve(server, http.MethodPost, "/internal/admin/v1/audit", body, "application/json")
	for _, response := range []*httptest.ResponseRecorder{dashboardResponse, auditResponse} {
		if response.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, body = %s", response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), sensitive) || strings.Contains(response.Body.String(), "postgres") {
			t.Errorf("backend error leaked: %s", response.Body.String())
		}
	}
}

func TestPrivateAPIHumanSessionGateBindsMethodAndPath(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	server, err := New(Options{Provider: &fakeProvider{}, Management: &fakeManagement{}, Auditor: &fakeAuditor{},
		ServiceToken: []byte(testServiceToken), Clock: fixedClock{now: now}, RequireHumanSession: true})
	if err != nil {
		t.Fatal(err)
	}
	path := "/internal/admin/v1/clusters"
	principal := auth.HumanPrincipal{Issuer: "https://vertical.cloudflareaccess.com", Subject: "operator"}
	sealed, err := auth.SealHumanSession([]byte(testServiceToken), auth.HumanSession{Principal: principal}, http.MethodGet, path, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, method, route, proof string
		duplicate, bearer          bool
		want                       int
	}{
		{"verified", http.MethodGet, path, sealed, false, true, http.StatusOK},
		{"missing", http.MethodGet, path, "", false, true, http.StatusUnauthorized},
		{"forged subject", http.MethodGet, path, "operator", false, true, http.StatusUnauthorized},
		{"duplicate", http.MethodGet, path, sealed, true, true, http.StatusUnauthorized},
		{"wrong method", http.MethodPost, path, sealed, false, true, http.StatusUnauthorized},
		{"wrong path", http.MethodGet, "/internal/admin/v1/operations", sealed, false, true, http.StatusUnauthorized},
		{"no service token", http.MethodGet, path, sealed, false, false, http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.route, nil)
			if test.bearer {
				request.Header.Set("Authorization", "Bearer "+testServiceToken)
			}
			if test.proof != "" {
				request.Header.Add(auth.HumanSessionHeader, test.proof)
				if test.duplicate {
					request.Header.Add(auth.HumanSessionHeader, test.proof)
				}
			}
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
		})
	}
}

func newTestServer(t *testing.T, provider SnapshotProvider, auditor adminui.Auditor, now time.Time) *Server {
	return newTestServerWithManagement(t, provider, auditor, &fakeManagement{}, now)
}

func newTestServerWithManagement(t *testing.T, provider SnapshotProvider, auditor adminui.Auditor, management Management, now time.Time) *Server {
	t.Helper()
	server, err := New(Options{Provider: provider, Management: management, Auditor: auditor, ServiceToken: []byte(testServiceToken), Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return server
}

func serve(server *Server, method, target string, body []byte, contentType string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testServiceToken)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}

func assertSecurityHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	for _, name := range []string{"Cache-Control", "Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options", "X-Frame-Options"} {
		if response.Header().Get(name) == "" {
			t.Errorf("missing %s header", name)
		}
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
}

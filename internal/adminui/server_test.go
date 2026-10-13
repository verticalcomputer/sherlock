package adminui

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const testAssertion = "verified-cloudflare-access-assertion"

type fakeAccessVerifier struct{}

func (fakeAccessVerifier) Verify(_ context.Context, assertion string) (AccessIdentity, error) {
	if assertion != testAssertion {
		return AccessIdentity{}, ErrCloudflareAccessDenied
	}
	return AccessIdentity{Issuer: "https://vertical.cloudflareaccess.com", Subject: "access-user-1", Email: "operator@example.com"}, nil
}

func TestVerifiedAccessIdentityBindsServerHumanSession(t *testing.T) {
	server := &Server{accessVerifier: fakeAccessVerifier{}}
	var saw bool
	handler := server.requireCloudflareAccess(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := HumanSessionFromContext(request.Context())
		if !ok || session.Principal.Issuer != "https://vertical.cloudflareaccess.com" ||
			session.Principal.Subject != "access-user-1" || session.Fingerprint != sha256.Sum256([]byte("sherlock-admin-access\x00"+testAssertion)) {
			t.Errorf("unbound human session: %+v ok=%v", session, ok)
		}
		saw = true
		writer.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/admin/clusters", nil)
	request.Header.Set(accessAssertionHeader, testAssertion)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if !saw || response.Code != http.StatusNoContent {
		t.Fatalf("verified session not observed: status=%d", response.Code)
	}
	if _, ok := HumanSessionFromContext(context.Background()); ok {
		t.Fatal("unverified context acquired a human session")
	}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

type fakeProvider struct {
	clusters     []ClusterRecord
	summary      Cluster
	operations   Operations
	report       InvestigationReport
	err          error
	updatedID    string
	update       ClusterUpdate
	removedID    string
	mutation     MutationContext
	started      InvestigationStart
	startResult  InvestigationStartResult
	humanErr     error
	humanChecked int
}

func (p *fakeProvider) LoadHumanAccess(context.Context) ([]ClusterAccess, error) {
	p.humanChecked++
	return []ClusterAccess{{ClusterID: "cluster-1", Role: "CLUSTER_VIEWER"}}, p.humanErr
}

func (p *fakeProvider) CheckHumanSession(context.Context) error {
	p.humanChecked++
	return p.humanErr
}

func TestDashboardRequiresActiveHumanMembershipWhenEnabled(t *testing.T) {
	provider := &fakeProvider{}
	server, err := New(Options{Provider: provider, AccessVerifier: fakeAccessVerifier{}, Auditor: &fakeAuditor{},
		ErrorReporter: &fakeErrorReporter{}, Clock: &fakeClock{now: time.Now().UTC()}, RequireHumanAuthorization: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		err  error
		want int
	}{
		{"no membership", ErrHumanAccessDenied, http.StatusForbidden},
		{"backend failure", errors.New("private store unavailable"), http.StatusServiceUnavailable},
		{"active membership", nil, http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider.humanErr = test.err
			request := httptest.NewRequest(http.MethodGet, "https://admin.example/admin/clusters", nil)
			request.Header.Set(accessAssertionHeader, testAssertion)
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			if response.Code != test.want || strings.Contains(response.Body.String(), "private store unavailable") {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
		})
	}
	if provider.humanChecked != 3 {
		t.Fatalf("membership checks=%d", provider.humanChecked)
	}
}

func (p *fakeProvider) ListClusters(context.Context) ([]ClusterRecord, error) {
	return p.clusters, p.err
}
func (p *fakeProvider) GetCluster(_ context.Context, id string) (ClusterRecord, error) {
	for _, c := range p.clusters {
		if c.ID == id {
			return c, p.err
		}
	}
	return ClusterRecord{}, errors.New("not found")
}
func (p *fakeProvider) GetClusterSummary(_ context.Context, id string) (Cluster, error) {
	if p.err != nil {
		return Cluster{}, p.err
	}
	if p.summary.ID == id {
		return p.summary, nil
	}
	return Cluster{}, errors.New("not found")
}
func (p *fakeProvider) UpdateCluster(_ context.Context, id string, u ClusterUpdate, m MutationContext) error {
	p.updatedID, p.update, p.mutation = id, u, m
	return p.err
}
func (p *fakeProvider) RemoveCluster(_ context.Context, id string, m MutationContext) error {
	p.removedID, p.mutation = id, m
	return p.err
}
func (p *fakeProvider) LoadOperations(context.Context) (Operations, error) {
	return p.operations, p.err
}
func (p *fakeProvider) LoadClusterOperations(_ context.Context, id string) (Operations, error) {
	operations := Operations{GeneratedAt: p.operations.GeneratedAt}
	for _, ticket := range p.operations.Tickets {
		if ticket.ClusterID == id {
			operations.Tickets = append(operations.Tickets, ticket)
		}
	}
	for _, investigation := range p.operations.Investigations {
		if investigation.ClusterID == id {
			operations.Investigations = append(operations.Investigations, investigation)
		}
	}
	return operations, p.err
}
func (p *fakeProvider) LoadInvestigationReport(context.Context, string) (InvestigationReport, error) {
	return p.report, p.err
}
func (p *fakeProvider) StartInvestigation(_ context.Context, _ string, input InvestigationStart, mutation MutationContext) (InvestigationStartResult, error) {
	p.started, p.mutation = input, mutation
	if p.startResult.ID == "" {
		p.startResult = InvestigationStartResult{ID: "investigation-new", Status: "PLANNING"}
	}
	return p.startResult, p.err
}

type fakeAuditor struct {
	events []AuditEvent
	err    error
}

func (a *fakeAuditor) RecordAdminEvent(_ context.Context, event AuditEvent) error {
	a.events = append(a.events, event)
	return a.err
}

type fakeErrorReporter struct{ failures []AuditDeliveryError }

func (r *fakeErrorReporter) ReportAdminError(_ context.Context, failure AuditDeliveryError) {
	r.failures = append(r.failures, failure)
}

func sampleProvider() *fakeProvider {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	return &fakeProvider{
		clusters: []ClusterRecord{{ID: "cluster-1", DisplayName: "Mumbai H100", State: StateHealthy, CreatedAt: now.Add(-time.Hour), LastSeenAt: now, Description: "10 compute nodes"}},
		summary: Cluster{ID: "cluster-1", Name: "Mumbai H100", State: StateDegraded,
			Resources: ResourceSummary{State: StateHealthy, ObservedNodes: 10, ObservedGPUs: 80, GPUUtilizationPercent: floatPointer(62.5), GPUUtilizationSamples: 80, LastObservedAt: &now},
			Dimensions: []Metric{
				{Label: "Connectivity", Value: "2 / 2", Detail: "fresh collectors", State: StateHealthy},
				{Label: "Freshness", Value: "2 fresh", Detail: "0 stale · 0 no data", State: StateHealthy},
				{Label: "Queue", Value: "0 overdue", Detail: "0 diagnostic blocked", State: StateHealthy},
				{Label: "Investigations", Value: "1 active", Detail: "0 partial · 0 blocked", State: StateHealthy},
				{Label: "Model usage", Value: "1 call", Detail: "0 rejected · 0 failed", State: StateHealthy},
				{Label: "Evidence", Value: "1 complete", Detail: "0 partial · 0 unavailable", State: StateHealthy},
				{Label: "Diagnostic audit", Value: "1 event", Detail: "0 denied or failed", State: StateHealthy},
			}},
		operations: Operations{GeneratedAt: now, Tickets: []Ticket{{ID: "ticket-1", ClusterID: "cluster-1", RuleID: "dcgm.xid.nonzero.v1", Title: "GPU fault", Summary: "XID observed", Severity: "HIGH", Status: "OPEN", UpdatedAt: now, AutoStartStatus: "BLOCKED", AutoStartDecision: "POLICY_DISABLED", AutoStartUpdatedAt: &now}}, Investigations: []Investigation{{ID: "inv-1", ClusterID: "cluster-1", IncidentID: "ticket-1", Question: "Why did the GPU fail?", Status: "COLLECTING", EntityKind: "gpu", EntityIDs: []string{"node/comp007/gpu/3"}, AuditedTokens: 59_537, AuditedCostMicrounits: 431_510, UpdatedAt: now}}},
		report: InvestigationReport{ID: "inv-1", ClusterID: "cluster-1", IncidentID: "ticket-1", Question: "Why did the GPU fail?", Status: "PARTIAL", WindowStart: now.Add(-time.Hour), WindowEnd: now, UpdatedAt: now,
			ModelUsage: ReportModelUsage{MaxTokens: 60_000, AdmittedTokens: 54_922, AuditedTokens: 96_846, MaxCostMicrounits: 2_000_000, AdmittedCostMicrounits: 361_585, AuditedCostMicrounits: 606_655},
			Findings:   []ReportFinding{{ID: "finding-1", Kind: "CONCLUSION", Statement: "A validated finding", EvidenceIDs: []string{"evidence-1"}}},
			Evidence:   []ReportEvidence{{ID: "evidence-1", Kind: "OBSERVATION", Status: "COMPLETE", ExactScope: `{"node":"node-1"}`, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now}},
			ModelCalls: []ModelCall{{ID: "call-1", Kind: "SYNTHESIS", Provider: "azure-openai", Model: "gpt", Outcome: "SUCCEEDED", OccurredAt: now, Input: ModelPayload{EvidenceID: "input-1", Availability: "AVAILABLE", MediaType: "application/json", Content: `{"question":"<script>unsafe</script>"}`}, Output: ModelPayload{EvidenceID: "output-1", Availability: "AVAILABLE", MediaType: "application/json", Content: `{"answer":"validated"}`}}}},
	}
}

func floatPointer(value float64) *float64 { return &value }

func newTestServer(t *testing.T, provider *fakeProvider, capacity int) (*Server, *fakeClock, *fakeAuditor, *fakeErrorReporter) {
	t.Helper()
	_ = capacity
	clock := &fakeClock{now: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)}
	auditor, reporter := &fakeAuditor{}, &fakeErrorReporter{}
	server, err := New(Options{Provider: provider, AccessVerifier: fakeAccessVerifier{}, Auditor: auditor, ErrorReporter: reporter, Clock: clock})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return server, clock, auditor, reporter
}

func authenticateWithAccess(t *testing.T, server *Server, assertion string) (*httptest.ResponseRecorder, *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://admin.example/admin", nil)
	req.Header.Set(accessAssertionHeader, assertion)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, req)
	return response, &http.Cookie{Name: "CF_Authorization", Value: assertion}
}

func doRequest(server *Server, cookie *http.Cookie, method, target string, form url.Values) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, "https://admin.example"+target, body)
	req.Header.Set(accessAssertionHeader, testAssertion)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://admin.example")
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, req)
	return response
}

func TestAdminEntryRoutesRedirectToOverview(t *testing.T) {
	server, _, _, _ := newTestServer(t, sampleProvider(), 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	for _, path := range []string{"/", "/admin"} {
		t.Run(path, func(t *testing.T) {
			response := doRequest(server, cookie, http.MethodGet, path, nil)
			if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/admin/operations" {
				t.Fatalf("entry route = %d %q", response.Code, response.Header().Get("Location"))
			}
		})
	}
}

func TestBootstrapLoginAndSherlockSessionCookieAreRemoved(t *testing.T) {
	server, _, _, _ := newTestServer(t, sampleProvider(), 2)
	request := httptest.NewRequest(http.MethodGet, "https://admin.example/admin/login", nil)
	request.Header.Set(accessAssertionHeader, testAssertion)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("removed login route = %d Set-Cookie=%q", response.Code, response.Header().Get("Set-Cookie"))
	}
	page := doRequest(server, nil, http.MethodGet, "/admin/clusters", nil)
	if !strings.Contains(page.Body.String(), `href="/cdn-cgi/access/logout"`) || page.Header().Get("Set-Cookie") != "" {
		t.Fatalf("Access session boundary missing: %d %q", page.Code, page.Header().Get("Set-Cookie"))
	}
}

func TestCloudflareAccessAssertionMustBeSingleValued(t *testing.T) {
	server, _, _, _ := newTestServer(t, sampleProvider(), 2)
	request := httptest.NewRequest(http.MethodGet, "https://admin.example/admin/clusters", nil)
	request.Header.Add(accessAssertionHeader, testAssertion)
	request.Header.Add(accessAssertionHeader, testAssertion)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate Access assertions = %d", response.Code)
	}
}

func TestClusterPageListsEveryClusterAndEscapesContent(t *testing.T) {
	provider := sampleProvider()
	provider.clusters = append(provider.clusters, ClusterRecord{ID: "cluster-2", DisplayName: `<script>alert(1)</script>`, State: StateUnavailable})
	server, _, auditor, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	response := doRequest(server, cookie, http.MethodGet, "/admin/clusters", nil)
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "Mumbai H100") || !strings.Contains(body, "cluster-2") || strings.Contains(body, "<script>") {
		t.Fatalf("clusters = %d %q", response.Code, body)
	}
	if !hasEvent(auditor.events, EventDashboardViewed, OutcomeSucceeded) || strings.Contains(body, cookie.Value) {
		t.Fatal("missing audit or session token leaked")
	}
}

func TestClusterDetailViewsSeparateSummaryGatesInvestigationsAndHealth(t *testing.T) {
	provider := sampleProvider()
	provider.summary.ExpectedCollectorNames = []string{"comp007", "comp008", "comp009"}
	provider.summary.MissingCollectorLabels = []string{"comp008 (collector-comp008)", "comp009 (collector-comp009)"}
	provider.summary.ExcludedCollectorLabels = []string{"headnode (collector-old) · REVOKED"}
	provider.summary.SourceGapLabels = []string{"DCGM (source-dcgm, prometheus) · NO DATA · UNKNOWN"}
	provider.summary.OnDemandSourceLabels = []string{"Model call audit (source-model, model) · ON DEMAND · freshness not tracked"}
	provider.operations.Tickets = append(provider.operations.Tickets, Ticket{ID: "other-ticket", ClusterID: "cluster-2", Title: "Must not appear"})
	server, _, auditor, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	views := []struct {
		path            string
		present, absent []string
	}{
		{"/admin/clusters/cluster-1",
			[]string{"Action needed", "Next step", "Path to healthy", "GPU fault", "Automatic investigation:", "POLICY_DISABLED", "Why did the GPU fail?"},
			[]string{"Missing expected collectors", "Observed nodes", `id="custom-investigation"`}},
		{"/admin/clusters/cluster-1/gates",
			[]string{"Path to healthy", "Missing expected collectors", "collector-comp008", "collector-comp009", "Periodic telemetry sources requiring attention", "source-dcgm", "On-demand sources", "source-model", "Registration history", "collector-old"},
			[]string{"Next step", "Observed nodes", `id="custom-investigation"`}},
		{"/admin/clusters/cluster-1/investigations",
			[]string{"Why did the GPU fail?", "node/comp007/gpu/3", "59,537 tokens", "$0.43", "Custom investigation", `id="custom-investigation"`},
			[]string{"Next step", "Missing expected collectors", "Observed nodes"}},
		{"/admin/clusters/cluster-1/health",
			[]string{"Monitoring signals", "Workflow activity", "Observed nodes", "<strong>10</strong>", "Observed GPUs", "<strong>80</strong>", "62.5%", "CPU usage", "No data"},
			[]string{"Next step", "Missing expected collectors", `id="custom-investigation"`}},
	}
	for _, view := range views {
		response := doRequest(server, cookie, http.MethodGet, view.path, nil)
		body := response.Body.String()
		if response.Code != http.StatusOK || !strings.Contains(body, `aria-current="page" href="`+view.path+`"`) {
			t.Fatalf("%s = %d without its current tab: %s", view.path, response.Code, body)
		}
		for _, value := range view.present {
			if !strings.Contains(body, value) {
				t.Fatalf("%s missing %q: %s", view.path, value, body)
			}
		}
		for _, value := range view.absent {
			if strings.Contains(body, value) {
				t.Fatalf("%s should leave %q to another view: %s", view.path, value, body)
			}
		}
		if strings.Contains(body, "Must not appear") || strings.Contains(body, cookie.Value) {
			t.Fatalf("%s leaked another cluster or its session token", view.path)
		}
		if strings.Contains(body, "Collection repair") || strings.Contains(body, "Global repair gate") {
			t.Fatalf("global repair overview belongs on operations, not a cluster page: %s", body)
		}
	}
	summary := doRequest(server, cookie, http.MethodGet, "/admin/clusters/cluster-1", nil).Body.String()
	if strings.Count(summary, "GPU fault") != 1 || strings.Count(summary, "POLICY_DISABLED") != 2 {
		t.Fatalf("incident facts are repeated across panels: %s", summary)
	}
	if !hasEvent(auditor.events, EventDashboardViewed, OutcomeSucceeded) {
		t.Fatal("cluster detail view was not audited")
	}
}

func TestClusterDetailRendersConcreteEvidenceRepairAndHistoricalContext(t *testing.T) {
	provider := sampleProvider()
	expected, returned := 80, 79
	provider.summary.EvidenceStreams = []EvidenceStreamHealth{{
		SourceID: "prometheus-pilot", Operation: "dcgm_gpu_utilization", Scope: "collection:cluster",
		Status: "PARTIAL", State: StatePartial, RunID: "run-latest", LatestAttempt: time.Date(2026, 8, 20, 11, 59, 0, 0, time.UTC),
		MissingTargets: []string{"GPU:GPU-missing"}, SeriesExpected: &expected, SeriesReturned: &returned,
		Condition: "incomplete target coverage", FailureCode: "PARTIAL_DATA", SafeFailureReason: "one registered GPU returned no series",
		RecommendedAction: "Restore exporter coverage for the listed targets, then run this operation again.",
	}}
	provider.summary.EvidenceHistory = EvidenceHistory{Total: 5812, Complete: 2, Partial: 0, Unavailable: 5810, Superseded: 5810}
	for index := range provider.summary.Dimensions {
		if provider.summary.Dimensions[index].Label == "Evidence" {
			provider.summary.Dimensions[index] = Metric{Label: "Evidence", Value: "2 / 3 current", Detail: "1 partial · 0 unavailable", State: StatePartial}
		}
	}
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	response := doRequest(server, cookie, http.MethodGet, "/admin/clusters/cluster-1/gates", nil)
	body := response.Body.String()
	for _, value := range []string{"incomplete target coverage", "GPU:GPU-missing", "run-latest", "PARTIAL_DATA", "one registered GPU returned no series", "79 / 80", "Recommended fix:", "Restore exporter coverage", "5810 older degraded envelopes no longer affect current health", "historical records are retained"} {
		if !strings.Contains(body, value) {
			t.Fatalf("evidence repair missing %q: %s", value, body)
		}
	}
	if strings.Contains(body, "Wait for a fresh collection") {
		t.Fatalf("generic non-actionable repair remains: %s", body)
	}
}

func TestClusterDetailMakesMissingCollectorAbsenceExplicit(t *testing.T) {
	provider := sampleProvider()
	provider.summary.ExpectedCollectorNames = []string{"headnode"}
	provider.summary.ExcludedCollectorLabels = []string{"headnode (collector-old) · REVOKED"}
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	response := doRequest(server, cookie, http.MethodGet, "/admin/clusters/cluster-1/gates", nil)
	body := response.Body.String()
	for _, value := range []string{"Missing expected collectors", "None. All expected collectors are fresh (1 configured).", "Every expected collector and periodically collected telemetry source is fresh.", "Registration history", "collector-old"} {
		if !strings.Contains(body, value) {
			t.Fatalf("cluster detail missing %q: %s", value, body)
		}
	}
}

func TestOperatorCanStartBoundedNonPrivilegedInvestigation(t *testing.T) {
	provider := sampleProvider()
	provider.operations.Investigations[0].EntityIDs = []string{"d1-bom-comp007"}
	server, clock, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	form := url.Values{
		"csrf_token": {server.csrfToken(cookie.Value)}, "incident_id": {"ticket-1"},
		"idempotency_key": {"admin-rerun-1"}, "question": {"Is the XID fault still active?"},
		"entity_kind": {"node"}, "entity_ids": {"d1-bom-comp007"},
		"success_criteria": {"Determine whether the fault is active.\nRecommend a safe next action."},
		"lookback_minutes": {"90"}, "max_decisions": {"10"}, "max_tool_calls": {"14"},
		"max_diagnostic_calls": {"2"}, "max_fan_out": {"1"}, "max_model_tokens": {"80000"},
		"max_cost_usd": {"1.25"}, "deadline_minutes": {"20"},
	}
	response := doRequest(server, cookie, http.MethodPost, "/admin/clusters/cluster-1/investigations", form)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/admin/clusters/cluster-1?investigation_started=investigation-new" {
		t.Fatalf("start response = %d %q, body = %s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	started := provider.started
	if started.MaxDecisions != 10 || started.MaxToolCalls != 14 || started.MaxDiagnosticCalls != 2 || started.MaxFanOut != 1 || started.MaxModelTokens != 80000 || started.MaxCostMicrounits != 1_250_000 {
		t.Fatalf("bounded input = %+v", started)
	}
	if !started.WindowStart.Equal(clock.now.Add(-90*time.Minute)) || !started.WindowEnd.Equal(clock.now) || !started.Deadline.Equal(clock.now.Add(20*time.Minute)) {
		t.Fatalf("bounded times = %s..%s deadline %s", started.WindowStart, started.WindowEnd, started.Deadline)
	}
	if len(provider.mutation.SessionFingerprint) != sha256.Size {
		t.Fatalf("session attribution length = %d", len(provider.mutation.SessionFingerprint))
	}
}

func TestClusterGlanceUsesExplicitDimensionsAndRelatedInvestigation(t *testing.T) {
	provider := sampleProvider()
	glance := buildClusterGlance(provider.summary, provider.operations.Tickets, provider.operations.Investigations)
	if glance.Headline != "GPU fault" || glance.Connectivity.Value != "2 / 2" || glance.Queue.Value != "0 overdue" || glance.PrimaryInvestigation == nil || glance.PrimaryInvestigation.EntityIDs[0] != "node/comp007/gpu/3" {
		t.Fatalf("cluster glance = %+v", glance)
	}
	if missing := dimensionByLabel(nil, "Evidence"); missing.State != StateNoData || missing.Value != "No data" {
		t.Fatalf("missing dimension = %+v", missing)
	}
}

func TestFocusedPagesPreserveTicketsAndInvestigations(t *testing.T) {
	server, _, _, _ := newTestServer(t, sampleProvider(), 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	body := doRequest(server, cookie, http.MethodGet, "/admin/incidents", nil).Body.String() + doRequest(server, cookie, http.MethodGet, "/admin/investigations", nil).Body.String()
	for _, value := range []string{"Live tickets", "GPU fault", "Investigations", "Why did the GPU fail?"} {
		if !strings.Contains(body, value) {
			t.Fatalf("missing %q", value)
		}
	}
	if !strings.Contains(body, `href="/admin/investigations/inv-1"`) || !strings.Contains(body, `href="/admin/clusters/cluster-1"`) {
		t.Fatal("investigation report or cluster link is missing")
	}
	if !strings.Contains(body, "59,537 tokens") || !strings.Contains(body, "$0.43") || !strings.Contains(body, `title="$0.431510"`) {
		t.Fatalf("investigation usage is missing: %s", body)
	}
	if !strings.Contains(body, `<span class="severity unavailable">HIGH</span>`) || !strings.Contains(body, `<span class="status neutral">COLLECTING</span>`) {
		t.Fatalf("status and severity do not share the state palette: %s", body)
	}
}

func TestAutomaticIssuesAreConsolidatedByClusterAndRule(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 37, 0, 0, time.UTC)
	provider := sampleProvider()
	provider.operations.Tickets = []Ticket{
		{ID: "incident-new", ClusterID: "cluster-1", RuleID: "dcgm.xid.nonzero.v1", Title: "DCGM XID error detected", Status: "OPEN", UpdatedAt: now},
		{ID: "incident-old", ClusterID: "cluster-1", RuleID: "dcgm.xid.nonzero.v1", Title: "DCGM XID error detected", Status: "OPEN", UpdatedAt: now.Add(-time.Hour)},
		{ID: "manual-incident", ClusterID: "cluster-1", Title: "Operator note", Status: "OPEN", UpdatedAt: now.Add(-time.Minute)},
	}
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	body := doRequest(server, cookie, http.MethodGet, "/admin/incidents", nil).Body.String()
	if strings.Count(body, "DCGM XID error detected") != 1 || !strings.Contains(body, "2 correlated incident records") || !strings.Contains(body, "Operator note") {
		t.Fatalf("automatic issue consolidation mismatch: %s", body)
	}
}

func TestOldXIDEdgesLeaveCurrentViewButRemainReviewable(t *testing.T) {
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	provider := sampleProvider()
	provider.operations.Tickets = []Ticket{
		{ID: "old-xid", ClusterID: "cluster-1", RuleID: "dcgm.xid.nonzero.v1", Title: "Old XID occurrence", Status: "OPEN", LastSignalAt: now.Add(-25 * time.Hour), UpdatedAt: now},
		{ID: "recent-xid", ClusterID: "cluster-1", RuleID: "dcgm.xid.nonzero.v1", Title: "Recent XID occurrence", Status: "OPEN", LastSignalAt: now.Add(-time.Hour), UpdatedAt: now},
		{ID: "old-investigating", ClusterID: "cluster-1", RuleID: "dcgm.xid.nonzero.v1", Title: "Investigating XID", Status: "INVESTIGATING", LastSignalAt: now.Add(-25 * time.Hour), UpdatedAt: now},
		{ID: "old-other", ClusterID: "cluster-1", RuleID: "other.rule.v1", Title: "Other issue", Status: "OPEN", LastSignalAt: now.Add(-25 * time.Hour), UpdatedAt: now},
	}
	current, historical := splitHistoricalXIDTickets(provider.operations.Tickets, now)
	if len(current) != 3 || len(historical) != 1 || historical[0].ID != "old-xid" {
		t.Fatalf("current=%+v historical=%+v", current, historical)
	}
	server, clock, _, _ := newTestServer(t, provider, 2)
	clock.now = now
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	body := doRequest(server, cookie, http.MethodGet, "/admin/incidents", nil).Body.String()
	if !strings.Contains(body, "older XID incident records") || !strings.Contains(body, "Old XID occurrence") || !strings.Contains(body, "last detected change") {
		t.Fatalf("historical XID explanation missing: %s", body)
	}
}

func TestBrowserLocalTimeUsesSameOriginStaticScript(t *testing.T) {
	server, _, _, _ := newTestServer(t, sampleProvider(), 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	page := doRequest(server, cookie, http.MethodGet, "/admin/operations", nil)
	if !strings.Contains(page.Body.String(), `src="/admin/assets/dashboard.js"`) || !strings.Contains(page.Body.String(), `data-local-time datetime="2026-08-20T12:00:00Z"`) {
		t.Fatalf("local-time markup missing: %s", page.Body.String())
	}
	if !strings.Contains(page.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("same-origin script is not allowed by CSP: %s", page.Header().Get("Content-Security-Policy"))
	}
	script := doRequest(server, nil, http.MethodGet, "/admin/assets/dashboard.js", nil)
	if script.Code != http.StatusOK || !strings.Contains(script.Body.String(), "Intl.DateTimeFormat") || script.Header().Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Fatalf("local-time script = %d %q", script.Code, script.Body.String())
	}
}

func TestInvestigationReportRendersValidatedFindingsAndEscapesContent(t *testing.T) {
	provider := sampleProvider()
	provider.report.Findings[0].Statement = `<script>unsafe</script>`
	confidence := 0.82
	provider.report.Findings[0].Confidence = &confidence
	server, _, auditor, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	response := doRequest(server, cookie, http.MethodGet, "/admin/investigations/inv-1", nil)
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "Investigation report") || !strings.Contains(body, "Evidence") || !strings.Contains(body, "AI call input and output") || !strings.Contains(body, "96,846 audited") || !strings.Contains(body, "$0.61</span> audited") || !strings.Contains(body, `title="$0.606655 audited"`) || !strings.Contains(body, "evidence-1") || !strings.Contains(body, "validated") || !strings.Contains(body, "confidence 0.82") || strings.Contains(body, "<script>") || strings.Contains(body, "%!") {
		t.Fatalf("report = %d %q", response.Code, body)
	}
	if !hasEvent(auditor.events, EventDashboardViewed, OutcomeSucceeded) || strings.Contains(body, cookie.Value) {
		t.Fatal("missing report audit or session token leaked")
	}
}

func TestInvestigationReportDoesNotMaskProviderFailureAsNotFound(t *testing.T) {
	provider := sampleProvider()
	provider.err = errors.New("private API route missing")
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	response := doRequest(server, cookie, http.MethodGet, "/admin/investigations/inv-1", nil)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "private API is current") {
		t.Fatalf("response=%d %q", response.Code, response.Body.String())
	}
}

func TestEditAndUpdateRequireSessionDerivedCSRF(t *testing.T) {
	provider := sampleProvider()
	provider.clusters[0].ExpectedCollectors = []string{"headnode-a", "headnode-b"}
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	page := doRequest(server, cookie, http.MethodGet, "/admin/clusters/cluster-1/edit", nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `value="Mumbai H100"`) || !strings.Contains(page.Body.String(), "headnode-a\nheadnode-b") {
		t.Fatalf("edit page = %d", page.Code)
	}
	bad := doRequest(server, cookie, http.MethodPost, "/admin/clusters/cluster-1/edit", url.Values{"csrf_token": {"bad"}, "display_name": {"New name"}})
	if bad.Code != http.StatusForbidden || provider.updatedID != "" {
		t.Fatalf("bad csrf = %d", bad.Code)
	}
	good := doRequest(server, cookie, http.MethodPost, "/admin/clusters/cluster-1/edit", url.Values{"csrf_token": {server.csrfToken(cookie.Value)}, "display_name": {"New name"}, "expected_collectors": {"headnode-a\nheadnode-c"}})
	if good.Code != http.StatusSeeOther || provider.updatedID != "cluster-1" || provider.update.DisplayName != "New name" || strings.Join(provider.update.ExpectedCollectors, ",") != "headnode-a,headnode-c" || len(provider.mutation.SessionFingerprint) != 32 || provider.mutation.RequestID == "" {
		t.Fatalf("update = %d %#v", good.Code, provider)
	}
}

func TestDeleteRequiresExactClusterIDConfirmation(t *testing.T) {
	provider := sampleProvider()
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	csrf := server.csrfToken(cookie.Value)
	bad := doRequest(server, cookie, http.MethodPost, "/admin/clusters/cluster-1/delete", url.Values{"csrf_token": {csrf}, "confirmation": {"Cluster-1"}})
	if bad.Code != http.StatusBadRequest || provider.removedID != "" {
		t.Fatalf("bad confirmation = %d", bad.Code)
	}
	good := doRequest(server, cookie, http.MethodPost, "/admin/clusters/cluster-1/delete", url.Values{"csrf_token": {csrf}, "confirmation": {"cluster-1"}})
	if good.Code != http.StatusSeeOther || provider.removedID != "cluster-1" {
		t.Fatalf("delete = %d", good.Code)
	}
}

func TestCloudflareAccessAndSecurityBoundary(t *testing.T) {
	server, _, auditor, _ := newTestServer(t, sampleProvider(), 2)
	missing := httptest.NewRequest(http.MethodGet, "https://admin.example/admin/clusters", nil)
	missingResponse := httptest.NewRecorder()
	server.ServeHTTP(missingResponse, missing)
	if missingResponse.Code != http.StatusUnauthorized || !hasEvent(auditor.events, EventAuthentication, OutcomeRejected) {
		t.Fatalf("missing Access assertion = %d %#v", missingResponse.Code, auditor.events)
	}
	req := httptest.NewRequest(http.MethodGet, "https://admin.example/admin/clusters", nil)
	req.Header.Set("Authorization", "Bearer tenant-key")
	req.Header.Set(accessAssertionHeader, testAssertion)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("API credential = %d", response.Code)
	}
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "Cache-Control", "X-Request-ID"} {
		if response.Header().Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
}

func TestAuditFailureFailsClosedBeforeRenderingRecords(t *testing.T) {
	server, _, auditor, reporter := newTestServer(t, sampleProvider(), 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	auditor.err = io.ErrClosedPipe
	response := doRequest(server, cookie, http.MethodGet, "/admin/clusters", nil)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "Mumbai H100") || len(reporter.failures) != 1 {
		t.Fatalf("response = %d %q %#v", response.Code, response.Body.String(), reporter.failures)
	}
}

func TestInvalidAccessAssertionDoesNotLeak(t *testing.T) {
	server, _, _, _ := newTestServer(t, sampleProvider(), 2)
	invalid := "invalid-cloudflare-assertion-that-must-not-leak"
	request := httptest.NewRequest(http.MethodGet, "https://admin.example/admin/clusters", nil)
	request.Header.Set(accessAssertionHeader, invalid)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), invalid) {
		t.Fatalf("invalid Access assertion = %d %q", response.Code, response.Body.String())
	}
}

func hasEvent(events []AuditEvent, kind EventKind, outcome EventOutcome) bool {
	for _, event := range events {
		if event.Kind == kind && event.Outcome == outcome {
			return true
		}
	}
	return false
}

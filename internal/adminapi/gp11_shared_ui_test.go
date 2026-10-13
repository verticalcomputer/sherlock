package adminapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminclient"
	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/adminui"
	"github.com/verticalcomputer/sherlock/internal/adminview"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type gp11AccessVerifier struct{}

func (gp11AccessVerifier) Verify(_ context.Context, assertion string) (adminui.AccessIdentity, error) {
	if assertion != "gp11-fixture" {
		return adminui.AccessIdentity{}, adminui.ErrCloudflareAccessDenied
	}
	return adminui.AccessIdentity{Issuer: "https://vertical.cloudflareaccess.com", Subject: "user-1"}, nil
}

type gp11Reporter struct{}

func (gp11Reporter) ReportAdminError(context.Context, adminui.AuditDeliveryError) {}

type gp11HealthProvider struct{ health application.ClusterHealthView }

func (p gp11HealthProvider) Snapshot(_ context.Context, q adminview.Query) (adminview.Dashboard, error) {
	return adminview.Dashboard{GeneratedAt: p.health.GeneratedAt, Clusters: []adminview.ClusterSummary{{ClusterID: "cluster-1", DisplayName: "Fixture cluster", Health: p.health, Overall: adminview.StateDegraded}}}, nil
}

func TestGP11ScopedUIThroughPrivateAPI(t *testing.T) {
	grants := &fakeHumanGrants{role: auth.RoleClusterViewer}
	api, _ := humanAuthorizationServer(t, grants)
	now := time.Now().UTC()
	api.clock = fixedClock{now: now}
	nodes, gpus := int64(14), int64(112)
	health := application.ClusterHealthView{SchemaVersion: 1, ClusterID: "cluster-1", GeneratedAt: now, WindowStart: now.Add(-5 * time.Minute), WindowEnd: now,
		Capacity: application.ClusterCapacityView{Condition: application.ConditionUnknown, ExpectedNodes: &nodes, ExpectedGPUs: &gpus},
		Workload: application.ConditionUnknown, Progress: domain.ProgressUnmeasured, Attention: []string{"METRIC_COVERAGE_GAP"}}
	api.provider = gp11HealthProvider{health}
	management := api.management.(*fakeManagement)
	management.operations.Investigations = []adminmanage.Investigation{{ID: "report-1", ClusterID: "cluster-1", Status: "PLANNING", UpdatedAt: now}}
	management.report = adminmanage.InvestigationReport{ID: "report-1", ClusterID: "cluster-1", Status: "PLANNING", Version: 7, Question: "Check telemetry", UpdatedAt: now,
		Findings:         []adminmanage.ReportFinding{{ID: "finding-1", Statement: "Read-only finding", EvidenceIDs: []string{"evidence-1"}}},
		Evidence:         []adminmanage.ReportEvidence{{ID: "evidence-1", ExactScope: `{"raw":"RAW_SCOPE_CANARY"}`}},
		ModelCalls:       []adminmanage.ModelCall{{Input: adminmanage.ModelPayload{Content: "RAW_INPUT_CANARY"}, Output: adminmanage.ModelPayload{Content: "RAW_OUTPUT_CANARY"}}},
		ContextManifests: []adminmanage.ContextManifest{{ExclusionReasons: "RAW_CONTEXT_CANARY"}}}
	starter, canceller := &fakeInvestigationStarter{}, &fakeInvestigationCanceller{}
	api.investigations, api.cancellations = starter, canceller
	private := httptest.NewServer(api)
	defer private.Close()
	httpClient := private.Client()
	httpClient.Timeout = 5 * time.Second
	client, err := adminclient.New(private.URL, []byte(testServiceToken), httpClient)
	if err != nil {
		t.Fatal(err)
	}
	ui, err := adminui.New(adminui.Options{Provider: client, Auditor: client, ErrorReporter: gp11Reporter{}, AccessVerifier: gp11AccessVerifier{}, RequireHumanAuthorization: true})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path string, body url.Values) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://admin.example"+path, strings.NewReader(body.Encode()))
		r.Header.Set("Cf-Access-Jwt-Assertion", "gp11-fixture")
		r.Header.Set("Origin", "https://admin.example")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		ui.ServeHTTP(w, r)
		return w
	}
	viewer := request("GET", "/admin/clusters/cluster-1", nil)
	if viewer.Code != 200 {
		t.Fatalf("viewer status=%d body=%s", viewer.Code, viewer.Body.String())
	}
	for _, want := range []string{"Shared cluster health", "UNKNOWN / 14 nodes", "UNKNOWN / 112 GPUs", "Progress UNMEASURED", "METRIC_COVERAGE_GAP"} {
		if !strings.Contains(viewer.Body.String(), want) {
			t.Fatalf("missing shared fact %s", want)
		}
	}
	for _, forbidden := range []string{"Edit cluster", "evidence-repair-proposals", "Start bounded investigation"} {
		if strings.Contains(viewer.Body.String(), forbidden) {
			t.Fatalf("viewer action leaked %s", forbidden)
		}
	}
	for _, path := range []string{"/admin/clusters/cluster-1/edit", "/admin/clusters/cluster-1/investigations", "/admin/clusters/cluster-1/evidence-repair-proposals", "/admin/clusters/cluster-1/credentials", "/admin/clusters/cluster-1/delete"} {
		method := "POST"
		if strings.HasSuffix(path, "/edit") {
			method = "GET"
		}
		if w := request(method, path, nil); w.Code != 403 {
			t.Fatalf("viewer direct route %s status=%d", path, w.Code)
		}
	}
	if w := request("GET", "/admin/clusters/cluster-2", nil); w.Code != 404 {
		t.Fatalf("foreign status=%d", w.Code)
	}
	report := request("GET", "/admin/investigations/report-1", nil)
	if report.Code != 200 || !strings.Contains(report.Body.String(), "Read-only finding") {
		t.Fatalf("shared report status=%d body=%s", report.Code, report.Body.String())
	}
	for _, forbidden := range []string{"RAW_SCOPE_CANARY", "RAW_INPUT_CANARY", "RAW_OUTPUT_CANARY", "RAW_CONTEXT_CANARY", "Cancel investigation"} {
		if strings.Contains(report.Body.String(), forbidden) {
			t.Fatalf("shared report leaked %s", forbidden)
		}
	}
	var csrf []string
	// Viewer cancellation is denied even with an otherwise valid browser CSRF.
	adminGrant := auth.RoleClusterAdmin
	grants.role = adminGrant
	admin := request("GET", "/admin/clusters/cluster-1", nil)
	if admin.Code != 200 || !strings.Contains(admin.Body.String(), "Edit cluster") {
		t.Fatalf("admin controls status=%d", admin.Code)
	}
	section := regexp.MustCompile(`(?s)<section class="panel shared-health".*?</section>`)
	if section.FindString(admin.Body.String()) != section.FindString(viewer.Body.String()) {
		t.Fatal("viewer/admin shared health differs")
	}
	report = request("GET", "/admin/investigations/report-1", nil)
	csrf = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(report.Body.String())
	if len(csrf) != 2 || !strings.Contains(report.Body.String(), "Cancel investigation") {
		t.Fatal("admin cancel absent")
	}
	form := url.Values{"csrf_token": {csrf[1]}, "expected_version": {"7"}}
	grants.role = auth.RoleClusterViewer
	if w := request("POST", "/admin/investigations/report-1/cancel", form); w.Code != 403 || canceller.calls != 0 {
		t.Fatalf("viewer cancel status=%d calls=%d", w.Code, canceller.calls)
	}
	grants.role = adminGrant
	if w := request("POST", "/admin/investigations/report-1/cancel", url.Values{"csrf_token": {csrf[1]}, "expected_version": {"6"}}); w.Code != 409 || canceller.calls != 0 {
		t.Fatalf("stale cancel status=%d calls=%d", w.Code, canceller.calls)
	}
	if w := request("POST", "/admin/investigations/report-1/cancel", form); w.Code != 303 || canceller.calls != 1 || canceller.input.ExpectedVersion != 7 {
		t.Fatalf("admin cancel status=%d calls=%d", w.Code, canceller.calls)
	}
	start := url.Values{"csrf_token": {csrf[1]}, "incident_id": {"allowed-ticket"}, "idempotency_key": {"gp11-start-1"}, "question": {"Explain missing telemetry read-only"}, "entity_kind": {"node"}, "entity_ids": {"node-1"}, "success_criteria": {"Explain the evidence gap"}, "lookback_minutes": {"30"}, "max_decisions": {"1"}, "max_tool_calls": {"1"}, "max_diagnostic_calls": {"0"}, "max_fan_out": {"1"}, "max_model_tokens": {"0"}, "max_cost_usd": {"0"}, "deadline_minutes": {"5"}}
	if w := request("POST", "/admin/clusters/cluster-1/investigations", start); w.Code != 303 || starter.input.ClusterID != "cluster-1" {
		t.Fatalf("start status=%d input=%+v body=%s", w.Code, starter.input, w.Body.String())
	}
	grants.revoked = true
	if w := request("POST", "/admin/clusters/cluster-1/investigations", start); w.Code != 403 {
		t.Fatalf("revoked status=%d", w.Code)
	}
	r := httptest.NewRequest("GET", "/admin/clusters", nil)
	r.Header.Set("Cf-Access-Jwt-Assertion", "expired")
	w := httptest.NewRecorder()
	ui.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("expired assertion status=%d", w.Code)
	}
}

func TestGP11SharedReportAndAccessProjection(t *testing.T) {
	grants := &fakeHumanGrants{role: auth.RoleClusterViewer}
	api, now := humanAuthorizationServer(t, grants)
	m := api.management.(*fakeManagement)
	m.report.Version = 5
	m.report.Question = `password=DO_NOT_SHOW shk_live_DO_NOT_SHOW {"password":"DO_NOT_SHOW"}`
	m.report.Findings = []adminmanage.ReportFinding{{Statement: "Bearer DO_NOT_SHOW"}}
	m.report.Evidence = []adminmanage.ReportEvidence{{ID: "evidence-1", ExactScope: "RAW_CANARY"}}
	m.report.ModelCalls = []adminmanage.ModelCall{{Input: adminmanage.ModelPayload{Content: "RAW_CANARY"}}}
	safe := serveHuman(t, api, now, "user-1", "GET", "/internal/admin/v1/investigations/report-1/shared", "")
	if safe.Code != 200 || strings.Contains(safe.Body.String(), "DO_NOT_SHOW") || strings.Contains(safe.Body.String(), "RAW_CANARY") {
		t.Fatalf("unsafe shared report status=%d body=%s", safe.Code, safe.Body.String())
	}
	if raw := serveHuman(t, api, now, "user-1", "GET", "/internal/admin/v1/investigations/report-1", ""); raw.Code != 403 {
		t.Fatalf("raw viewer status=%d", raw.Code)
	}
	for _, role := range []auth.HumanRole{auth.RoleClusterViewer, auth.RoleClusterAdmin} {
		grants.role = role
		w := serveHuman(t, api, now, "user-1", "GET", "/internal/admin/v1/human-access", "")
		var result struct {
			Clusters []adminui.ClusterAccess `json:"clusters"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.Clusters) != 1 {
			t.Fatalf("access projection status=%d", w.Code)
		}
		row := result.Clusters[0]
		if row.CanInvestigate != (role == auth.RoleClusterAdmin) || row.CanManageCredentials || row.CanManagePolicy || row.CanRemove {
			t.Fatalf("excessive grant %+v", row)
		}
	}
	grants.credential, grants.policy, grants.platform = true, true, true
	w := serveHuman(t, api, now, "user-1", "GET", "/internal/admin/v1/human-access", "")
	if !strings.Contains(w.Body.String(), `"can_remove":true`) {
		t.Fatal("separate grant missing")
	}
	grants.revoked = true
	if w := serveHuman(t, api, now, "user-1", "GET", "/internal/admin/v1/human-access", ""); w.Code != 403 {
		t.Fatalf("revoked access status=%d", w.Code)
	}
}

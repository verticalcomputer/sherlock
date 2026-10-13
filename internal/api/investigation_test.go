package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
	contract "github.com/verticalcomputer/sherlock/sdk/go"
)

type investigationAPIFake struct {
	incident      IncidentResource
	investigation InvestigationResource
	start         StartInvestigationInput
	approval      ApproveInvestigationInput
	events        []InvestigationEventResource
}

func (fake *investigationAPIFake) CreateIncident(_ context.Context, input CreateIncidentInput) (IncidentResource, bool, error) {
	fake.incident = IncidentResource{IncidentID: "incident-1", ClusterID: string(input.ClusterID), Title: input.Title, Summary: input.Summary, Severity: contract.IncidentSeverity(input.Severity), Status: "OPEN", TargetIDs: input.TargetIDs, EvidenceIDs: input.EvidenceIDs, CreatedBy: input.ActorID, CreatedAt: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC), Version: 1, InvestigationIDs: []string{}}
	return fake.incident, false, nil
}
func (fake *investigationAPIFake) ListIncidents(context.Context, domain.ClusterID, IncidentListOptions) ([]IncidentResource, string, error) {
	return []IncidentResource{fake.incident}, "", nil
}
func (fake *investigationAPIFake) GetIncident(_ context.Context, id string) (IncidentResource, bool, error) {
	return fake.incident, fake.incident.IncidentID == id, nil
}
func (fake *investigationAPIFake) StartInvestigation(_ context.Context, input StartInvestigationInput) (InvestigationResource, bool, error) {
	fake.start = input
	fake.investigation = InvestigationResource{InvestigationID: "investigation-1", ClusterID: string(input.ClusterID), IncidentID: input.IncidentID, Question: input.Question, Scope: input.Scope, SuccessCriteria: input.SuccessCriteria, Status: "RUNNING", Budget: input.Budget, FindingIDs: []string{}, CreatedBy: input.ActorID, CreatedAt: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC), Deadline: input.Deadline, UpdatedAt: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC), Version: 1}
	return fake.investigation, false, nil
}
func (fake *investigationAPIFake) GetInvestigation(_ context.Context, id string) (InvestigationResource, bool, error) {
	return fake.investigation, fake.investigation.InvestigationID == id, nil
}
func (fake *investigationAPIFake) CancelInvestigation(_ context.Context, _ CancelInvestigationInput) (InvestigationResource, error) {
	fake.investigation.Status = "CANCELLED"
	return fake.investigation, nil
}
func (fake *investigationAPIFake) ApproveInvestigation(_ context.Context, input ApproveInvestigationInput) (InvestigationResource, error) {
	fake.approval = input
	fake.investigation.Status = "RUNNING"
	return fake.investigation, nil
}
func (fake *investigationAPIFake) ListInvestigationEvents(context.Context, string, string, int) ([]InvestigationEventResource, error) {
	return fake.events, nil
}
func (*investigationAPIFake) ListInvestigationEvidence(context.Context, string) ([]InvestigationEvidenceResource, error) {
	return nil, nil
}
func (*investigationAPIFake) ListInvestigationHypotheses(context.Context, string) ([]HypothesisResource, error) {
	return nil, nil
}
func (*investigationAPIFake) ListInvestigationFindings(context.Context, string) ([]FindingResource, error) {
	return nil, nil
}

func newInvestigationAPIServer(t *testing.T, fake *investigationAPIFake, clusterID string) http.Handler {
	t.Helper()
	clock := apiClock{value: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)}
	queries, err := application.NewPublicQueries(&apiReader{}, clock, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	principal := auth.Principal{KeyID: "key-1", ClusterID: domain.ClusterID(clusterID), Capabilities: []auth.Capability{auth.CapabilityIncidentsRead, auth.CapabilityIncidentsWrite, auth.CapabilityInvestigationsRead, auth.CapabilityInvestigationsRun, auth.CapabilityDiagnosticsPrivileged}}
	server, err := NewServerWithInvestigations(apiAuthenticator{principal: principal}, queries, apiEvents{}, fake, clock, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestInvestigationStartIsStrictScopedAndIdempotent(t *testing.T) {
	fake := &investigationAPIFake{}
	body := `{"cluster_id":"cluster-a","incident_id":"incident-1","question":"explain GPU XID","scope":{"entity_kind":"NODE","entity_ids":["comp001"],"start":"2026-08-20T11:00:00Z","end":"2026-08-20T12:00:00Z"},"success_criteria":["identify a cited cause"],"budget":{"max_decisions":5,"max_tool_calls":10,"max_privileged_calls":1,"max_fan_out":2,"max_model_tokens":0,"max_cost_micros":0,"decisions_used":0,"tool_calls_used":0,"privileged_calls_used":0,"fan_out_used":0,"model_tokens_used":0,"cost_micros_used":0},"deadline":"2026-08-20T13:00:00Z"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/investigations", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer shk_test")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "investigate-1")
	response := httptest.NewRecorder()
	newInvestigationAPIServer(t, fake, "cluster-a").ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Location") != "/api/v1/investigations/investigation-1" {
		t.Fatalf("Location=%q", response.Header().Get("Location"))
	}
	if fake.start.ActorID != "key-1" || fake.start.IdempotencyKey != "investigate-1" || fake.start.ClusterID != "cluster-a" {
		t.Fatalf("input=%+v", fake.start)
	}

	wrongCluster := httptest.NewRequest(http.MethodPost, "/api/v1/investigations", strings.NewReader(strings.Replace(body, "cluster-a", "cluster-b", 1)))
	wrongCluster.Header = request.Header.Clone()
	denied := httptest.NewRecorder()
	newInvestigationAPIServer(t, fake, "cluster-a").ServeHTTP(denied, wrongCluster)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("cross-cluster status=%d body=%s", denied.Code, denied.Body.String())
	}
}

func TestInvestigationApprovalIsVersionAndActionBound(t *testing.T) {
	fake := &investigationAPIFake{investigation: InvestigationResource{InvestigationID: "investigation-1", ClusterID: "cluster-a", Status: "AWAITING_APPROVAL", Version: 4}}
	body := `{"approval_id":"approval-1","action_id":"action-1","action_sha256":"` + strings.Repeat("a", 64) + `","expected_version":4,"expires_at":"2026-08-20T12:10:00Z"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/investigations/investigation-1/approvals", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer shk_test")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	newInvestigationAPIServer(t, fake, "cluster-a").ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if fake.approval.ApprovalID != "approval-1" || fake.approval.ActionID != "action-1" || fake.approval.ActionSHA256 != strings.Repeat("a", 64) || fake.approval.ExpectedVersion != 4 || fake.approval.ActorID != "key-1" {
		t.Fatalf("approval=%+v", fake.approval)
	}
}

func TestInvestigationLedgersReturnArraysAndDoNotLeakSensitiveFields(t *testing.T) {
	fake := &investigationAPIFake{investigation: InvestigationResource{InvestigationID: "investigation-1", ClusterID: "cluster-a", Status: "RUNNING", Version: 1}}
	for _, suffix := range []string{"evidence", "hypotheses", "findings"} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/investigations/investigation-1/"+suffix, nil)
		request.Header.Set("Authorization", "Bearer shk_test")
		response := httptest.NewRecorder()
		newInvestigationAPIServer(t, fake, "cluster-a").ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", suffix, response.Code, response.Body.String())
		}
		var payload struct {
			Data []json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Data == nil {
			t.Fatalf("%s did not return an array: %s", suffix, response.Body.String())
		}
		for _, forbidden := range []string{"credential", "password", "raw_output", "command"} {
			if strings.Contains(response.Body.String(), forbidden) {
				t.Fatalf("%s leaked %s", suffix, forbidden)
			}
		}
	}
}

// The public boundary must carry the diagnostic grant without changing what a
// request that predates it means: an omitted field is no execution authority,
// never an implicit default.
func TestInvestigationStartCarriesDiagnosticBudgetAndOmissionMeansZero(t *testing.T) {
	body := func(budget string) string {
		return `{"cluster_id":"cluster-a","incident_id":"incident-1","question":"is the ECC fault degrading","scope":{"entity_kind":"NODE","entity_ids":["comp001"],"start":"2026-08-20T11:00:00Z","end":"2026-08-20T12:00:00Z"},"success_criteria":["identify a cited cause"],"budget":` + budget + `,"deadline":"2026-08-20T13:00:00Z"}`
	}
	post := func(t *testing.T, fake *investigationAPIFake, payload string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/investigations", strings.NewReader(payload))
		request.Header.Set("Authorization", "Bearer shk_test")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "investigate-1")
		response := httptest.NewRecorder()
		newInvestigationAPIServer(t, fake, "cluster-a").ServeHTTP(response, request)
		return response
	}

	granted := &investigationAPIFake{}
	if code := post(t, granted, body(`{"max_decisions":5,"max_tool_calls":10,"max_diagnostic_calls":2,"max_privileged_calls":1,"max_fan_out":2,"max_model_tokens":0,"max_cost_micros":0,"decisions_used":0,"tool_calls_used":0,"diagnostic_calls_used":0,"privileged_calls_used":0,"fan_out_used":0,"model_tokens_used":0,"cost_micros_used":0}`)).Code; code != http.StatusAccepted {
		t.Fatalf("granted status=%d", code)
	}
	if granted.start.Budget.MaxDiagnosticCalls != 2 {
		t.Fatalf("MaxDiagnosticCalls did not reach the application: %+v", granted.start.Budget)
	}

	omitted := &investigationAPIFake{}
	if code := post(t, omitted, body(`{"max_decisions":5,"max_tool_calls":10,"max_privileged_calls":1,"max_fan_out":2,"max_model_tokens":0,"max_cost_micros":0,"decisions_used":0,"tool_calls_used":0,"privileged_calls_used":0,"fan_out_used":0,"model_tokens_used":0,"cost_micros_used":0}`)).Code; code != http.StatusAccepted {
		t.Fatalf("omitted status=%d", code)
	}
	if omitted.start.Budget.MaxDiagnosticCalls != 0 {
		t.Fatalf("an omitted diagnostic budget must mean zero: %+v", omitted.start.Budget)
	}

	rejected := &investigationAPIFake{}
	if code := post(t, rejected, body(`{"max_decisions":5,"max_tool_calls":10,"max_diagnostic_calls":-1,"max_privileged_calls":1,"max_fan_out":2,"max_model_tokens":0,"max_cost_micros":0,"decisions_used":0,"tool_calls_used":0,"privileged_calls_used":0,"fan_out_used":0,"model_tokens_used":0,"cost_micros_used":0}`)).Code; code != http.StatusBadRequest {
		t.Fatalf("a negative diagnostic budget must be rejected: status=%d", code)
	}
}

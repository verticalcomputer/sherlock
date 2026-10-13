package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type diagnosticStoreFake struct{ run domain.DiagnosticRun }

func (store *diagnosticStoreFake) CreateDiagnosticRun(_ context.Context, run domain.DiagnosticRun, _ domain.DiagnosticWorkID, _ application.DiagnosticAuditEvent) (domain.DiagnosticRun, bool, error) {
	store.run = run
	return run, true, nil
}
func (store *diagnosticStoreFake) LoadDiagnosticRun(context.Context, domain.DiagnosticRunID) (domain.DiagnosticRun, bool, error) {
	return store.run, store.run.Request().RunID != "", nil
}
func (*diagnosticStoreFake) ApproveDiagnosticRun(context.Context, domain.DiagnosticRun, domain.DiagnosticApproval, application.DiagnosticAuditEvent) error {
	return nil
}

type diagnosticVerifierFake struct{}

func (diagnosticVerifierFake) VerifyDiagnosticDefinition(_ context.Context, _ domain.ClusterID, reference domain.DiagnosticDefinitionRef, _ []domain.DiagnosticTarget, _ []domain.DiagnosticArgument) (application.VerifiedDiagnosticDefinition, error) {
	return application.VerifiedDiagnosticDefinition{Reference: reference, Privilege: domain.DiagnosticUnprivileged, Issuer: "test", ExpiresAt: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}, nil
}

type diagnosticAuthorizerFake struct{}

func (diagnosticAuthorizerFake) AuthorizeDiagnostic(context.Context, application.DiagnosticAuthorizationRequest) (application.DiagnosticAuthorizationDecision, error) {
	return application.DiagnosticAuthorizationDecision{Allowed: true}, nil
}

type diagnosticAuditFake struct{}

func (diagnosticAuditFake) AppendDiagnosticAudit(context.Context, application.DiagnosticAuditEvent) error {
	return nil
}

type diagnosticIDs struct{ value int }

func (ids *diagnosticIDs) NewID() (string, error) {
	ids.value++
	return fmt.Sprintf("id-%d", ids.value), nil
}

type diagnosticProjectionFake struct {
	projection application.DiagnosticRunProjection
}

func (reader diagnosticProjectionFake) GetDiagnosticRunProjection(_ context.Context, clusterID domain.ClusterID, runID domain.DiagnosticRunID) (application.DiagnosticRunProjection, bool, error) {
	if reader.projection.ClusterID != clusterID || reader.projection.RunID != runID {
		return application.DiagnosticRunProjection{}, false, nil
	}
	return reader.projection, true, nil
}

func newDiagnosticAPIServer(t *testing.T, projection application.DiagnosticRunProjection) http.Handler {
	t.Helper()
	clock := apiClock{value: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)}
	publicQueries, err := application.NewPublicQueries(&apiReader{}, clock, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	diagnostics, err := application.NewDiagnosticService(&diagnosticStoreFake{}, diagnosticVerifierFake{}, diagnosticAuthorizerFake{}, diagnosticAuditFake{}, clock, &diagnosticIDs{})
	if err != nil {
		t.Fatal(err)
	}
	queries, err := application.NewDiagnosticQueries(diagnosticProjectionFake{projection: projection})
	if err != nil {
		t.Fatal(err)
	}
	principal := auth.Principal{KeyID: "key-1", ClusterID: "cluster-a", Capabilities: []auth.Capability{auth.CapabilityClusterRead, auth.CapabilityInvestigationsRead, auth.CapabilityInvestigationsRun, auth.CapabilityDiagnosticsPrivileged}}
	server, err := NewServerWithDiagnostics(apiAuthenticator{principal: principal}, publicQueries, apiEvents{}, diagnostics, queries, clock, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestDiagnosticStartIsStrictAndReturnsAttributableRun(t *testing.T) {
	deadline := "2026-08-20T12:10:00Z"
	body := `{"definition":{"pack_id":"base","pack_version":"2.0.0","definition_id":"gpu-query","definition_version":"1.3.0","definition_sha256":"` + strings.Repeat("a", 64) + `"},"targets":["comp001"],"arguments":[{"name":"fields","value":"temperature.gpu"}],"deadline":"` + deadline + `","max_attempts":1}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/clusters/cluster-a/diagnostic-runs", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer shk_test")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "request-1")
	response := httptest.NewRecorder()
	newDiagnosticAPIServer(t, application.DiagnosticRunProjection{}).ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.HasSuffix(response.Header().Get("Location"), "/id-1") {
		t.Fatalf("Location = %q", response.Header().Get("Location"))
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["run_id"] != "id-1" || payload["requested_by"] != "key-1" || payload["status"] != "QUEUED" {
		t.Fatalf("response = %#v", payload)
	}
	if bytes.Contains(response.Body.Bytes(), []byte("credential")) {
		t.Fatal("response exposed credential-shaped data")
	}
}

func TestDiagnosticRunReturnsOnlySafePerTargetMetadata(t *testing.T) {
	zero := domain.ChecksumSHA256(nil)
	plan := domain.ChecksumSHA256([]byte("plan"))
	projection := application.DiagnosticRunProjection{RunID: "run-1", ClusterID: "cluster-a", Definition: domain.DiagnosticDefinitionRef{PackID: "base", PackVersion: "2.0.0", DefinitionID: "gpu-query", DefinitionVersion: "1.3.0", DefinitionDigest: domain.ChecksumSHA256([]byte("definition"))}, Privilege: domain.DiagnosticUnprivileged, Status: domain.DiagnosticSucceeded, RequestedBy: "key-1", RequestedAt: time.Now(), Deadline: time.Now().Add(time.Minute), Version: 2, WorkID: "work-1", Attempts: []application.DiagnosticAttemptProjection{{Attempt: 1, RunnerID: "runner-1", Status: domain.DiagnosticAttemptSucceeded, LeaseExpires: time.Now(), PlanDigest: &plan, Targets: []domain.DiagnosticTargetResult{{Target: "comp001", Status: domain.DiagnosticTargetSucceeded, ExitCode: intPointerAPI(0), StdoutBytes: 12, StdoutSHA256: zero, StderrSHA256: zero}}}}}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/cluster-a/diagnostic-runs/run-1", nil)
	request.Header.Set("Authorization", "Bearer shk_test")
	response := httptest.NewRecorder()
	newDiagnosticAPIServer(t, projection).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	for _, forbidden := range []string{"stdout\"", "stderr\"", "lease_token", "arguments", "credential"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("response contains forbidden field %q: %s", forbidden, response.Body.String())
		}
	}
	if !strings.Contains(response.Body.String(), `"stdout_sha256"`) || !strings.Contains(response.Body.String(), `"runner_id":"runner-1"`) {
		t.Fatalf("safe attribution missing: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"stdout_transformation_state":"UNKNOWN"`) {
		t.Fatalf("legacy projection gained capture proof: %s", response.Body.String())
	}
}

func intPointerAPI(value int) *int { return &value }

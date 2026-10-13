package adminapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type fakeAccessTesting struct {
	subject   string
	requested string
	operation string
	version   int64
	cancelled string
	audit     adminmanage.MutationAudit
	err       error
	noLatest  bool
}

func (f *fakeAccessTesting) RequestCredentialAccessTest(_ context.Context, cluster, subject, credentialID string, version int64, audit adminmanage.MutationAudit) (adminmanage.CredentialAccessTest, error) {
	return f.request(domain.CredentialAccessTestOperation, cluster, subject, credentialID, version, audit)
}

func (f *fakeAccessTesting) RequestCredentialInventoryDiscovery(_ context.Context, cluster, subject, credentialID string, version int64, audit adminmanage.MutationAudit) (adminmanage.CredentialAccessTest, error) {
	return f.request(domain.CredentialInventoryDiscoveryOperation, cluster, subject, credentialID, version, audit)
}

func (f *fakeAccessTesting) request(operation, cluster, subject, credentialID string, version int64, audit adminmanage.MutationAudit) (adminmanage.CredentialAccessTest, error) {
	f.subject, f.requested, f.version, f.audit, f.operation = subject, credentialID, version, audit, operation
	if f.err != nil {
		return adminmanage.CredentialAccessTest{}, f.err
	}
	return adminmanage.CredentialAccessTest{ID: "ctest_new", ClusterID: cluster, CredentialID: credentialID, CredentialVersion: version, Host: "head-1", Purpose: "BCM_READ_ONLY", Username: "fixture_user_1", Operation: operation, Status: domain.CredentialAccessTestRequested, RequestedBy: subject, RequestedAt: time.Now().UTC(), Deadline: time.Now().Add(time.Minute).UTC(), CredentialCurrent: true, CredentialStatus: "ACTIVE"}, nil
}

func (f *fakeAccessTesting) LatestInventoryDiscovery(_ context.Context, cluster, subject string) (adminmanage.CredentialInventoryDiscovery, bool, error) {
	f.subject = subject
	if f.err != nil {
		return adminmanage.CredentialInventoryDiscovery{}, false, f.err
	}
	if f.noLatest {
		return adminmanage.CredentialInventoryDiscovery{}, false, nil
	}
	return adminmanage.CredentialInventoryDiscovery{
		TestID: "ctest_inv", ClusterID: cluster, CredentialID: "cred_active", CredentialVersion: 2, Host: "head-1",
		BCMVersion: "10.24", CompletedAt: time.Now().UTC(), CredentialCurrent: true,
		Devices: []domain.CredentialAccessDevice{{Type: "physicalnode", Hostname: "node001", Status: "UP"}},
	}, true, nil
}
func (f *fakeAccessTesting) ListCredentialAccessTests(_ context.Context, cluster, subject string, _ int) ([]adminmanage.CredentialAccessTest, error) {
	f.subject = subject
	return []adminmanage.CredentialAccessTest{{ID: "ctest_old", ClusterID: cluster, CredentialID: "cred_old", CredentialVersion: 1, Status: domain.CredentialAccessTestSucceeded, OutcomeCode: "BCM_ACCESS_VERIFIED", OutcomeSummary: "sudo authenticated and cmsh listed 8 devices.", BCMVersion: "10.24", DevicesListed: 8, CredentialCurrent: false, CredentialStatus: "REVOKED"}}, nil
}
func (f *fakeAccessTesting) CancelCredentialAccessTest(_ context.Context, _, subject, testID string, audit adminmanage.MutationAudit) error {
	f.subject, f.cancelled, f.audit = subject, testID, audit
	return f.err
}

func TestCredentialAccessTestPrivateAPIUsesTrustedActorAndRedactedProjection(t *testing.T) {
	access := &fakeAccessTesting{}
	server, err := New(Options{Provider: &fakeProvider{}, Management: &fakeManagement{}, Credentials: &fakeCredentialManagement{}, AccessTests: access, Auditor: &fakeAuditor{}, ServiceToken: []byte(testServiceToken), Clock: fixedClock{now: time.Now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := base64.StdEncoding.EncodeToString(make([]byte, 32))
	body, _ := json.Marshal(map[string]any{"expected_version": 2, "actor_subject": "access-a", "session_fingerprint": fingerprint, "request_id": "request-1"})
	request := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/credentials/cred_active/access-tests", body, "application/json")
	if request.Code != http.StatusOK || access.subject != "access-a" || access.requested != "cred_active" || access.version != 2 || access.audit.EventKind != adminmanage.EventAccessTestRequested || access.audit.ActorSubject != "access-a" {
		t.Fatalf("request code=%d body=%s fake=%+v", request.Code, request.Body.String(), access)
	}
	if !strings.Contains(request.Body.String(), `"status":"REQUESTED"`) || strings.Contains(request.Body.String(), "password") {
		t.Fatalf("request response: %s", request.Body.String())
	}
	invalid, _ := json.Marshal(map[string]any{"expected_version": 0, "actor_subject": "access-a", "session_fingerprint": fingerprint, "request_id": "request-1"})
	if response := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/credentials/cred_active/access-tests", invalid, "application/json"); response.Code != http.StatusBadRequest {
		t.Fatalf("zero version accepted: %d", response.Code)
	}
	if response := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/credentials/notcred/access-tests", body, "application/json"); response.Code != http.StatusBadRequest {
		t.Fatalf("bad credential id accepted: %d", response.Code)
	}
	list := serveWithHeaders(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-1/credential-access-tests", nil, "", map[string]string{"X-Sherlock-Access-Subject": "access-b"})
	if list.Code != http.StatusOK || access.subject != "access-b" || !strings.Contains(list.Body.String(), `"credential_current":false`) || !strings.Contains(list.Body.String(), `"outcome_code":"BCM_ACCESS_VERIFIED"`) {
		t.Fatalf("list code=%d body=%s subject=%q", list.Code, list.Body.String(), access.subject)
	}
	if noSubject := serveWithHeaders(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-1/credential-access-tests", nil, "", nil); noSubject.Code != http.StatusForbidden {
		t.Fatalf("missing subject: %d", noSubject.Code)
	}
	cancelBody, _ := json.Marshal(map[string]any{"actor_subject": "access-c", "session_fingerprint": fingerprint, "request_id": "request-2"})
	if cancel := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/credential-access-tests/ctest_new/cancel", cancelBody, "application/json"); cancel.Code != http.StatusNoContent || access.cancelled != "ctest_new" || access.subject != "access-c" || access.audit.EventKind != adminmanage.EventAccessTestCancelled {
		t.Fatalf("cancel code=%d fake=%+v", cancel.Code, access)
	}
	access.err = adminmanage.ErrCredentialAccessDenied
	if denied := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/credentials/cred_active/access-tests", body, "application/json"); denied.Code != http.StatusForbidden {
		t.Fatalf("denied grant: %d", denied.Code)
	}
	access.err = adminmanage.ErrConflict
	if conflict := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/credentials/cred_active/access-tests", body, "application/json"); conflict.Code != http.StatusConflict {
		t.Fatalf("conflict: %d", conflict.Code)
	}
	disabled, err := New(Options{Provider: &fakeProvider{}, Management: &fakeManagement{}, Auditor: &fakeAuditor{}, ServiceToken: []byte(testServiceToken), Clock: fixedClock{now: time.Now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	if response := serve(disabled, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/credentials/cred_active/access-tests", body, "application/json"); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled access tests: %d", response.Code)
	}
}

func TestCredentialInventoryDiscoveryPrivateAPIRoutes(t *testing.T) {
	access := &fakeAccessTesting{}
	server, err := New(Options{Provider: &fakeProvider{}, Management: &fakeManagement{}, Credentials: &fakeCredentialManagement{}, AccessTests: access, Auditor: &fakeAuditor{}, ServiceToken: []byte(testServiceToken), Clock: fixedClock{now: time.Now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := base64.StdEncoding.EncodeToString(make([]byte, 32))
	body, _ := json.Marshal(map[string]any{"expected_version": 2, "actor_subject": "access-a", "session_fingerprint": fingerprint, "request_id": "request-1"})
	request := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/credentials/cred_active/inventory-discoveries", body, "application/json")
	if request.Code != http.StatusOK || access.operation != domain.CredentialInventoryDiscoveryOperation || access.requested != "cred_active" || access.version != 2 || access.audit.ActorSubject != "access-a" {
		t.Fatalf("discovery request code=%d body=%s fake=%+v", request.Code, request.Body.String(), access)
	}
	if !strings.Contains(request.Body.String(), `"operation":"bcm.inventory_discovery.v1"`) {
		t.Fatalf("discovery response: %s", request.Body.String())
	}
	// The access-test route must still schedule the access-test operation.
	if response := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/credentials/cred_active/access-tests", body, "application/json"); response.Code != http.StatusOK || access.operation != domain.CredentialAccessTestOperation {
		t.Fatalf("access test route operation=%q code=%d", access.operation, response.Code)
	}
	invalid, _ := json.Marshal(map[string]any{"expected_version": 0, "actor_subject": "access-a", "session_fingerprint": fingerprint, "request_id": "request-1"})
	if response := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/credentials/cred_active/inventory-discoveries", invalid, "application/json"); response.Code != http.StatusBadRequest {
		t.Fatalf("zero version accepted: %d", response.Code)
	}
	if response := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/credentials/notcred/inventory-discoveries", body, "application/json"); response.Code != http.StatusBadRequest {
		t.Fatalf("bad credential id accepted: %d", response.Code)
	}

	latest := serveWithHeaders(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-1/inventory-discovery/latest", nil, "", map[string]string{"X-Sherlock-Access-Subject": "access-b"})
	if latest.Code != http.StatusOK || access.subject != "access-b" || !strings.Contains(latest.Body.String(), `"hostname":"node001"`) || !strings.Contains(latest.Body.String(), `"credential_current":true`) {
		t.Fatalf("latest code=%d body=%s", latest.Code, latest.Body.String())
	}
	if noSubject := serveWithHeaders(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-1/inventory-discovery/latest", nil, "", nil); noSubject.Code != http.StatusForbidden {
		t.Fatalf("missing subject: %d", noSubject.Code)
	}
	access.noLatest = true
	if none := serveWithHeaders(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-1/inventory-discovery/latest", nil, "", map[string]string{"X-Sherlock-Access-Subject": "access-b"}); none.Code != http.StatusNotFound {
		t.Fatalf("absent discovery code=%d body=%s", none.Code, none.Body.String())
	}
	access.err = adminmanage.ErrCredentialAccessDenied
	if denied := serveWithHeaders(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-1/inventory-discovery/latest", nil, "", map[string]string{"X-Sherlock-Access-Subject": "access-b"}); denied.Code != http.StatusForbidden {
		t.Fatalf("denied grant: %d", denied.Code)
	}
	if denied := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/credentials/cred_active/inventory-discoveries", body, "application/json"); denied.Code != http.StatusForbidden {
		t.Fatalf("denied discovery request: %d", denied.Code)
	}
	disabled, err := New(Options{Provider: &fakeProvider{}, Management: &fakeManagement{}, Auditor: &fakeAuditor{}, ServiceToken: []byte(testServiceToken), Clock: fixedClock{now: time.Now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/internal/admin/v1/clusters/cluster-1/credentials/cred_active/inventory-discoveries", "/internal/admin/v1/clusters/cluster-1/inventory-discovery/latest"} {
		if response := serveWithHeaders(disabled, http.MethodGet, path, nil, "", map[string]string{"X-Sherlock-Access-Subject": "access-b"}); response.Code != http.StatusServiceUnavailable && response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("disabled %s: %d", path, response.Code)
		}
	}
}

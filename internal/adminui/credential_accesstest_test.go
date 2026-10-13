package adminui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type accessTestUIProvider struct {
	*credentialUIProvider
	tests     []CredentialAccessTest
	subject   string
	requested string
	operation string
	version   int64
	cancelled string
	mutation  MutationContext
}

func (provider *accessTestUIProvider) ListCredentialAccessTests(_ context.Context, _ string, subject string) ([]CredentialAccessTest, error) {
	provider.subject = subject
	return provider.tests, nil
}
func (provider *accessTestUIProvider) RequestCredentialAccessTest(_ context.Context, _ string, subject string, credentialID string, version int64, mutation MutationContext) (CredentialAccessTest, error) {
	provider.subject, provider.requested, provider.version, provider.mutation = subject, credentialID, version, mutation
	provider.operation = "bcm.access_test.v1"
	return CredentialAccessTest{ID: "ctest_new", Status: "REQUESTED"}, nil
}
func (provider *accessTestUIProvider) RequestCredentialInventoryDiscovery(_ context.Context, _ string, subject string, credentialID string, version int64, mutation MutationContext) (CredentialAccessTest, error) {
	provider.subject, provider.requested, provider.version, provider.mutation = subject, credentialID, version, mutation
	provider.operation = CredentialInventoryDiscoveryOperation
	return CredentialAccessTest{ID: "ctest_inv", Operation: CredentialInventoryDiscoveryOperation, Status: "REQUESTED"}, nil
}
func (provider *accessTestUIProvider) CancelCredentialAccessTest(_ context.Context, _ string, subject string, testID string, mutation MutationContext) error {
	provider.subject, provider.cancelled, provider.mutation = subject, testID, mutation
	return nil
}

func TestCredentialAccessTestUIDistinguishesSavedFromVerifiedAndStale(t *testing.T) {
	provider := &accessTestUIProvider{credentialUIProvider: &credentialUIProvider{fakeProvider: sampleProvider()}}
	clock := &fakeClock{now: time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)}
	server, err := New(Options{Provider: provider, AccessVerifier: fakeAccessVerifier{}, Auditor: &fakeAuditor{}, ErrorReporter: &fakeErrorReporter{}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	render := func() string {
		get := httptest.NewRequest(http.MethodGet, "https://admin.example/admin/clusters/cluster-1/edit?credential=saved", nil)
		get.Header.Set(accessAssertionHeader, testAssertion)
		response := httptest.NewRecorder()
		server.ServeHTTP(response, get)
		if response.Code != http.StatusOK {
			t.Fatalf("edit page code=%d", response.Code)
		}
		return response.Body.String()
	}
	untested := render()
	if !strings.Contains(untested, "Credential saved. Connection has not been tested.") || !strings.Contains(untested, "Test BCM access</button>") || !strings.Contains(untested, "Access test: not run for this record") || strings.Contains(untested, "BCM ACCESS VERIFIED") {
		t.Fatalf("untested page did not distinguish saved from verified:\n%s", untested)
	}
	if provider.subject != "access-user-1" {
		t.Fatalf("list used subject %q", provider.subject)
	}
	completed := clock.now
	provider.tests = []CredentialAccessTest{{ID: "ctest_ok", CredentialID: "cred_active", CredentialVersion: 1, Status: "SUCCEEDED", OutcomeCode: "BCM_ACCESS_VERIFIED", OutcomeSummary: "sudo authenticated and cmsh listed 8 devices read-only on BCM 10.24.", BCMVersion: "10.24", DevicesListed: 8, CompletedAt: &completed, CredentialCurrent: true, CredentialStatus: "ACTIVE"}}
	verified := render()
	if !strings.Contains(verified, "BCM ACCESS VERIFIED") || !strings.Contains(verified, "listed 8 devices") || strings.Contains(verified, `http-equiv="refresh"`) {
		t.Fatalf("verified page:\n%s", verified)
	}
	provider.tests[0].CredentialCurrent = false
	provider.tests[0].CredentialStatus = "REVOKED"
	stale := render()
	if !strings.Contains(stale, "STALE RESULT") || strings.Contains(stale, "BCM ACCESS VERIFIED") || !strings.Contains(stale, "current credential has not been tested") {
		t.Fatalf("stale page:\n%s", stale)
	}
	provider.tests = []CredentialAccessTest{{ID: "ctest_pending", CredentialID: "cred_active", CredentialVersion: 1, Status: "RUNNING", CollectorID: "head-collector", Attempt: 1, RequestedAt: clock.now, CredentialCurrent: true, CredentialStatus: "ACTIVE"}}
	pending := render()
	if !strings.Contains(pending, `http-equiv="refresh"`) || !strings.Contains(pending, "ACCESS TEST RUNNING") || !strings.Contains(pending, "Cancel test") || strings.Contains(pending, "Test BCM access</button>") {
		t.Fatalf("pending page:\n%s", pending)
	}
	provider.tests = []CredentialAccessTest{{ID: "ctest_failed", CredentialID: "cred_active", CredentialVersion: 1, Status: "FAILED", OutcomeCode: "SUDO_AUTH_FAILED", OutcomeSummary: "sudo rejected the stored password; the credential is not valid for this head.", CompletedAt: &completed, CredentialCurrent: true, CredentialStatus: "ACTIVE"}}
	failed := render()
	if !strings.Contains(failed, "SUDO_AUTH_FAILED") || !strings.Contains(failed, "Test BCM access</button>") {
		t.Fatalf("failed page:\n%s", failed)
	}

	form := url.Values{"csrf_token": {server.csrfToken(testAssertion)}, "expected_version": {"1"}, "actor_subject": {"forged"}}
	post := httptest.NewRequest(http.MethodPost, "https://admin.example/admin/clusters/cluster-1/credentials/cred_active/test", strings.NewReader(form.Encode()))
	post.Header.Set(accessAssertionHeader, testAssertion)
	post.Header.Set("Origin", "https://admin.example")
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	posted := httptest.NewRecorder()
	server.ServeHTTP(posted, post)
	if posted.Code != http.StatusSeeOther || provider.subject != "access-user-1" || provider.requested != "cred_active" || provider.version != 1 || provider.mutation.ActorSubject != "access-user-1" || !strings.Contains(posted.Header().Get("Location"), "credential=test_requested") {
		t.Fatalf("test request code=%d location=%q provider=%+v", posted.Code, posted.Header().Get("Location"), provider)
	}
	noCSRF := httptest.NewRequest(http.MethodPost, "https://admin.example/admin/clusters/cluster-1/credentials/cred_active/test", strings.NewReader(url.Values{"expected_version": {"1"}}.Encode()))
	noCSRF.Header.Set(accessAssertionHeader, testAssertion)
	noCSRF.Header.Set("Origin", "https://admin.example")
	noCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rejected := httptest.NewRecorder()
	server.ServeHTTP(rejected, noCSRF)
	if rejected.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF token accepted: %d", rejected.Code)
	}
	badOrigin := httptest.NewRequest(http.MethodPost, "https://admin.example/admin/clusters/cluster-1/credentials/cred_active/test", strings.NewReader(form.Encode()))
	badOrigin.Header.Set(accessAssertionHeader, testAssertion)
	badOrigin.Header.Set("Origin", "https://evil.example")
	badOrigin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crossOrigin := httptest.NewRecorder()
	server.ServeHTTP(crossOrigin, badOrigin)
	if crossOrigin.Code == http.StatusSeeOther {
		t.Fatalf("cross-origin request accepted: %d", crossOrigin.Code)
	}
	cancelForm := url.Values{"csrf_token": {server.csrfToken(testAssertion)}}
	cancel := httptest.NewRequest(http.MethodPost, "https://admin.example/admin/clusters/cluster-1/credential-tests/ctest_pending/cancel", strings.NewReader(cancelForm.Encode()))
	cancel.Header.Set(accessAssertionHeader, testAssertion)
	cancel.Header.Set("Origin", "https://admin.example")
	cancel.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cancelled := httptest.NewRecorder()
	server.ServeHTTP(cancelled, cancel)
	if cancelled.Code != http.StatusSeeOther || provider.cancelled != "ctest_pending" || !strings.Contains(cancelled.Header().Get("Location"), "credential=test_cancelled") {
		t.Fatalf("cancel code=%d provider=%+v", cancelled.Code, provider)
	}
}

// TestCredentialInventoryDiscoveryUIIsDistinctFromAccessTest mirrors the
// access-test handler test: the two operations have separate buttons, separate
// status lines and separate keys, and a discovery is never called verification.
func TestCredentialInventoryDiscoveryUIIsDistinctFromAccessTest(t *testing.T) {
	provider := &accessTestUIProvider{credentialUIProvider: &credentialUIProvider{fakeProvider: sampleProvider()}}
	clock := &fakeClock{now: time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)}
	server, err := New(Options{Provider: provider, AccessVerifier: fakeAccessVerifier{}, Auditor: &fakeAuditor{}, ErrorReporter: &fakeErrorReporter{}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	render := func() string {
		get := httptest.NewRequest(http.MethodGet, "https://admin.example/admin/clusters/cluster-1/edit", nil)
		get.Header.Set(accessAssertionHeader, testAssertion)
		response := httptest.NewRecorder()
		server.ServeHTTP(response, get)
		if response.Code != http.StatusOK {
			t.Fatalf("edit page code=%d", response.Code)
		}
		return response.Body.String()
	}
	none := render()
	if !strings.Contains(none, "Discover BCM inventory</button>") || !strings.Contains(none, "BCM inventory: not discovered for this record") {
		t.Fatalf("page without a discovery:\n%s", none)
	}

	completed := clock.now
	discovery := CredentialAccessTest{
		ID: "ctest_inv", CredentialID: "cred_active", CredentialVersion: 1, Operation: CredentialInventoryDiscoveryOperation,
		Status: "SUCCEEDED", OutcomeCode: "BCM_ACCESS_VERIFIED", OutcomeSummary: "cmsh listed 3 devices read-only on BCM 10.24 and the inventory rows were retained.",
		BCMVersion: "10.24", DevicesListed: 3, CompletedAt: &completed, CredentialCurrent: true, CredentialStatus: "ACTIVE",
		Devices: []CredentialAccessDevice{
			{Type: "headnode", Hostname: "fixture1-zone1-headnode", Status: "UP"},
			{Type: "physicalnode", Hostname: "node001", Status: "UP"},
			{Type: "physicalnode", Hostname: "node002", Status: "DOWN"},
		},
	}
	// An access test and a discovery for the same credential are separate
	// results; neither may replace the other in the projection.
	accessTest := CredentialAccessTest{ID: "ctest_ok", CredentialID: "cred_active", CredentialVersion: 1, Status: "SUCCEEDED", OutcomeCode: "BCM_ACCESS_VERIFIED", OutcomeSummary: "sudo authenticated and cmsh listed 3 devices read-only on BCM 10.24.", BCMVersion: "10.24", DevicesListed: 3, CompletedAt: &completed, CredentialCurrent: true, CredentialStatus: "ACTIVE"}
	provider.tests = []CredentialAccessTest{discovery, accessTest}
	listed := render()
	for _, want := range []string{"BCM INVENTORY LISTED (3 DEVICES)", "it is not an access verification", "physicalnode 2, headnode 1", "fixture1-zone1-headnode", "node002", "DOWN", "BCM ACCESS VERIFIED"} {
		if !strings.Contains(listed, want) {
			t.Fatalf("listed page missing %q:\n%s", want, listed)
		}
	}
	if !discovery.Listed() || discovery.Verified() {
		t.Fatal("a succeeded discovery must be Listed and never Verified")
	}

	// Replacement makes the retained listing stale, exactly like a test.
	provider.tests[0].CredentialCurrent = false
	provider.tests[0].CredentialStatus = "REVOKED"
	stale := render()
	if !strings.Contains(stale, "STALE RESULT") || strings.Contains(stale, "BCM INVENTORY LISTED") {
		t.Fatalf("stale discovery page:\n%s", stale)
	}

	// A pending discovery refreshes the page and offers cancellation.
	provider.tests = []CredentialAccessTest{{ID: "ctest_inv", CredentialID: "cred_active", CredentialVersion: 1, Operation: CredentialInventoryDiscoveryOperation, Status: "RUNNING", CollectorID: "head-collector", Attempt: 1, RequestedAt: clock.now, CredentialCurrent: true, CredentialStatus: "ACTIVE"}}
	pending := render()
	if !strings.Contains(pending, `http-equiv="refresh"`) || !strings.Contains(pending, "INVENTORY DISCOVERY RUNNING") || !strings.Contains(pending, "Cancel discovery") || strings.Contains(pending, "Discover BCM inventory</button>") {
		t.Fatalf("pending discovery page:\n%s", pending)
	}
	// The access-test button is unaffected by a pending discovery.
	if !strings.Contains(pending, "Test BCM access</button>") {
		t.Fatalf("pending discovery hid the access test button:\n%s", pending)
	}

	form := url.Values{"csrf_token": {server.csrfToken(testAssertion)}, "expected_version": {"1"}, "actor_subject": {"forged"}}
	post := httptest.NewRequest(http.MethodPost, "https://admin.example/admin/clusters/cluster-1/credentials/cred_active/inventory-discovery", strings.NewReader(form.Encode()))
	post.Header.Set(accessAssertionHeader, testAssertion)
	post.Header.Set("Origin", "https://admin.example")
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	posted := httptest.NewRecorder()
	server.ServeHTTP(posted, post)
	if posted.Code != http.StatusSeeOther || provider.operation != CredentialInventoryDiscoveryOperation || provider.subject != "access-user-1" || provider.requested != "cred_active" || provider.version != 1 || provider.mutation.ActorSubject != "access-user-1" || !strings.Contains(posted.Header().Get("Location"), "credential=discovery_requested") {
		t.Fatalf("discovery request code=%d location=%q provider=%+v", posted.Code, posted.Header().Get("Location"), provider)
	}
	noCSRF := httptest.NewRequest(http.MethodPost, "https://admin.example/admin/clusters/cluster-1/credentials/cred_active/inventory-discovery", strings.NewReader(url.Values{"expected_version": {"1"}}.Encode()))
	noCSRF.Header.Set(accessAssertionHeader, testAssertion)
	noCSRF.Header.Set("Origin", "https://admin.example")
	noCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rejected := httptest.NewRecorder()
	server.ServeHTTP(rejected, noCSRF)
	if rejected.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF token accepted: %d", rejected.Code)
	}
	badOrigin := httptest.NewRequest(http.MethodPost, "https://admin.example/admin/clusters/cluster-1/credentials/cred_active/inventory-discovery", strings.NewReader(form.Encode()))
	badOrigin.Header.Set(accessAssertionHeader, testAssertion)
	badOrigin.Header.Set("Origin", "https://evil.example")
	badOrigin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crossOrigin := httptest.NewRecorder()
	server.ServeHTTP(crossOrigin, badOrigin)
	if crossOrigin.Code == http.StatusSeeOther {
		t.Fatalf("cross-origin discovery accepted: %d", crossOrigin.Code)
	}
}

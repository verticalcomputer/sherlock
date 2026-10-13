package adminui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

type credentialUIProvider struct {
	*fakeProvider
	subject  string
	input    CredentialInput
	metadata []CredentialMetadata
}

func (provider *credentialUIProvider) ListCredentialMetadata(_ context.Context, _ string, subject string) ([]CredentialMetadata, error) {
	provider.subject = subject
	if provider.metadata != nil {
		return provider.metadata, nil
	}
	return []CredentialMetadata{{ID: "cred_active", ClusterID: "cluster-1", Host: "head-1", Purpose: "BCM_READ_ONLY", Username: "operator", Status: "ACTIVE", Version: 1, CreatedAt: time.Now().UTC()}}, nil
}
func (provider *credentialUIProvider) PutCredential(_ context.Context, _ string, subject string, input CredentialInput, _ MutationContext) (CredentialMetadata, error) {
	provider.subject = subject
	provider.input = input
	return CredentialMetadata{ID: "cred-new", ClusterID: "cluster-1", Host: input.Host, Purpose: input.Purpose, Username: input.Username, Status: "ACTIVE", Version: 2, CreatedAt: time.Now().UTC()}, nil
}
func (provider *credentialUIProvider) RevokeCredential(_ context.Context, _ string, _ string, _ int64, _ MutationContext) error {
	return nil
}

func TestCredentialUIUsesVerifiedAccessSubjectAndNeverRendersSecrets(t *testing.T) {
	provider := &credentialUIProvider{fakeProvider: sampleProvider()}
	clock := &fakeClock{now: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)}
	server, err := New(Options{Provider: provider, AccessVerifier: fakeAccessVerifier{}, Auditor: &fakeAuditor{}, ErrorReporter: &fakeErrorReporter{}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRequest(http.MethodGet, "https://admin.example/admin/clusters/cluster-1/edit", nil)
	get.Header.Set(accessAssertionHeader, testAssertion)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, get)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "sudo-secret") || !strings.Contains(response.Body.String(), "Revoke") {
		t.Fatalf("credential edit page code=%d body missing redacted form", response.Code)
	}
	if strings.Contains(response.Body.String(), `type="hidden" name="username"`) || !strings.Contains(response.Body.String(), `type="text" name="username" value="operator"`) {
		t.Fatal("active replacement did not expose an editable username")
	}
	if os.Getenv("SHERLOCK_GP20_PREVIEW") == "1" {
		if err := os.WriteFile("/tmp/gp20-credentials-preview.html", response.Body.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	provider.metadata = []CredentialMetadata{{ID: "cred_revoked", ClusterID: "cluster-1", Host: "head-1", Purpose: "BCM_READ_ONLY", Username: "operator", Status: "REVOKED", Version: 2, CreatedAt: time.Now().UTC()}}
	reenroll := httptest.NewRequest(http.MethodGet, "https://admin.example/admin/clusters/cluster-1/edit", nil)
	reenroll.Header.Set(accessAssertionHeader, testAssertion)
	reenrollResponse := httptest.NewRecorder()
	server.ServeHTTP(reenrollResponse, reenroll)
	if reenrollResponse.Code != http.StatusOK || !strings.Contains(reenrollResponse.Body.String(), "Re-enroll credential") || !strings.Contains(reenrollResponse.Body.String(), `name="expected_credential_id" value="cred_revoked"`) {
		t.Fatalf("revoked credential did not render re-enrollment form: code=%d", reenrollResponse.Code)
	}
	form := url.Values{"csrf_token": {server.csrfToken(testAssertion)}, "host": {"head-2"}, "purpose": {"BCM_READ_ONLY"}, "username": {"operator"}, "ssh_password": {"synthetic-ssh"}, "sudo_password": {"synthetic-sudo"}, "expected_version": {"0"}, "actor_subject": {"forged-subject"}}
	post := httptest.NewRequest(http.MethodPost, "https://admin.example/admin/clusters/cluster-1/credentials", strings.NewReader(form.Encode()))
	post.Header.Set(accessAssertionHeader, testAssertion)
	post.Header.Set("Origin", "https://admin.example")
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	posted := httptest.NewRecorder()
	server.ServeHTTP(posted, post)
	if posted.Code != http.StatusSeeOther || provider.subject != "access-user-1" {
		t.Fatalf("post code=%d subject=%q", posted.Code, provider.subject)
	}
	if provider.input.SudoPassword != "synthetic-sudo" {
		t.Fatalf("sudo input was not delivered to provider")
	}
}

func TestCredentialUIPasswordlessAuthorizationRequiresNoPassword(t *testing.T) {
	provider := &credentialUIProvider{fakeProvider: sampleProvider()}
	server, err := New(Options{Provider: provider, AccessVerifier: fakeAccessVerifier{}, Auditor: &fakeAuditor{}, ErrorReporter: &fakeErrorReporter{}, Clock: &fakeClock{now: time.Now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"csrf_token": {server.csrfToken(testAssertion)}, "host": {"fixture2-zone1-headnode"}, "purpose": {"BCM_READ_ONLY_PASSWORDLESS"}, "username": {"fixture_user_2"}, "expected_version": {"0"}}
	post := httptest.NewRequest(http.MethodPost, "https://admin.example/admin/clusters/cluster-1/credentials", strings.NewReader(form.Encode()))
	post.Header.Set(accessAssertionHeader, testAssertion)
	post.Header.Set("Origin", "https://admin.example")
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, post)
	if response.Code != http.StatusSeeOther || provider.subject != "access-user-1" || provider.input.Purpose != "BCM_READ_ONLY_PASSWORDLESS" || provider.input.SudoPassword != "" || provider.input.SSHPassword != "" {
		t.Fatalf("passwordless authorization was not accepted without a secret: status=%d", response.Code)
	}
}

package adminapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminmanage"
)

type fakeCredentialManagement struct {
	metadata []adminmanage.CredentialMetadata
	input    adminmanage.CredentialInput
	subject  string
	revoked  string
}

func (m *fakeCredentialManagement) ListCredentialMetadata(_ context.Context, _ string, subject string) ([]adminmanage.CredentialMetadata, error) {
	m.subject = subject
	return m.metadata, nil
}
func (m *fakeCredentialManagement) PutCredential(_ context.Context, _ string, subject string, input adminmanage.CredentialInput, _ adminmanage.MutationAudit) (adminmanage.CredentialMetadata, error) {
	m.subject, m.input = subject, input
	m.input.SSHPassword = append([]byte(nil), input.SSHPassword...)
	m.input.SudoPassword = append([]byte(nil), input.SudoPassword...)
	return adminmanage.CredentialMetadata{ID: "cred_new", ClusterID: "cluster-1", Host: input.Host, Purpose: input.Purpose, Username: input.Username, Status: "ACTIVE", Version: 1, CreatedAt: time.Now().UTC()}, nil
}
func (m *fakeCredentialManagement) RevokeCredential(_ context.Context, _ string, subject, id string, _ int64, _ adminmanage.MutationAudit) error {
	m.subject, m.revoked = subject, id
	return nil
}

func TestCredentialPrivateAPIIsWriteOnlyAndPassesTrustedActor(t *testing.T) {
	cred := &fakeCredentialManagement{metadata: []adminmanage.CredentialMetadata{{ID: "cred_old", ClusterID: "cluster-1", Host: "head-1", Purpose: "BCM_READ_ONLY", Username: "operator", Status: "ACTIVE", Version: 1, CreatedAt: time.Now().UTC()}}}
	server, err := New(Options{Provider: &fakeProvider{}, Management: &fakeManagement{}, Credentials: cred, Auditor: &fakeAuditor{}, ServiceToken: []byte(testServiceToken), Clock: fixedClock{now: time.Now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	list := serveWithHeaders(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-1/credentials", nil, "", map[string]string{"X-Sherlock-Access-Subject": "access-a"})
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), "password") || strings.Contains(list.Body.String(), "ciphertext") {
		t.Fatalf("list exposed secret or failed: %d %s", list.Code, list.Body.String())
	}
	body, _ := json.Marshal(map[string]any{"host": "head-1", "purpose": "BCM_READ_ONLY", "username": "operator", "ssh_password": "ssh-secret", "sudo_password": "sudo-secret", "expected_version": 1, "expected_credential_id": "cred_old", "actor_subject": "access-a", "session_fingerprint": base64.StdEncoding.EncodeToString(make([]byte, 32)), "request_id": "request-1"})
	put := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/credentials", body, "application/json")
	if put.Code != http.StatusOK || strings.Contains(put.Body.String(), "sudo-secret") || string(cred.input.SudoPassword) != "sudo-secret" || cred.subject != "access-a" {
		t.Fatalf("put body/actor mismatch code=%d body=%s subject=%q", put.Code, put.Body.String(), cred.subject)
	}
	for i := range cred.input.SSHPassword {
		cred.input.SSHPassword[i] = 0
	}
	for i := range cred.input.SudoPassword {
		cred.input.SudoPassword[i] = 0
	}
}

func serveWithHeaders(server *Server, method, target string, body []byte, contentType string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testServiceToken)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}

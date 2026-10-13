package collectorcontrol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

var transportNow = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

type transportClock struct{}

func (transportClock) Now() time.Time { return transportNow }

type fakeIdentityOperations struct {
	enrollmentRequest EnrollmentRequest
	renewedCollector  domain.CollectorID
}

func (f *fakeIdentityOperations) Enroll(_ context.Context, request EnrollmentRequest) (Enrollment, error) {
	f.enrollmentRequest = request
	return Enrollment{CollectorID: "collector-1", Identity: issuedTestIdentity()}, nil
}

func (f *fakeIdentityOperations) Renew(_ context.Context, collectorID domain.CollectorID, _ []byte) (IssuedIdentity, error) {
	f.renewedCollector = collectorID
	return issuedTestIdentity(), nil
}

type fakeAuthenticator struct {
	certificate *x509.Certificate
	err         error
	calls       int
}

func (f *fakeAuthenticator) AuthenticateCollectorIdentity(_ context.Context, serial string, fingerprint [32]byte) (AuthenticatedIdentity, error) {
	f.calls++
	if f.err != nil {
		return AuthenticatedIdentity{}, f.err
	}
	wantFingerprint := sha256.Sum256(f.certificate.Raw)
	if serial != hex.EncodeToString(f.certificate.SerialNumber.Bytes()) || fingerprint != wantFingerprint {
		return AuthenticatedIdentity{}, errors.New("unexpected certificate identity")
	}
	return AuthenticatedIdentity{CollectorID: "collector-1", ClusterID: "cluster-1"}, nil
}

type fakeHeartbeatRecorder struct{ heartbeat Heartbeat }

func (f *fakeHeartbeatRecorder) RecordHeartbeat(_ context.Context, heartbeat Heartbeat) error {
	f.heartbeat = heartbeat
	return nil
}

type fakeWorkOperations struct {
	lease          domain.WorkLease
	found          bool
	claimedToken   string
	startedToken   string
	renewedFor     time.Duration
	renewedToken   string
	operationError error
}

type fakeResultOperations struct {
	chunk        ResultChunk
	finalization ResultFinalization
	chunkOutcome ChunkOutcome
	finalOutcome FinalizeOutcome
	err          error
}

func (f *fakeResultOperations) UploadResultChunk(_ context.Context, _ domain.CollectorID, chunk ResultChunk) (ChunkOutcome, error) {
	f.chunk = chunk
	return f.chunkOutcome, f.err
}

func (f *fakeResultOperations) FinalizeResult(_ context.Context, _ domain.CollectorID, finalization ResultFinalization) (FinalizeOutcome, error) {
	f.finalization = finalization
	return f.finalOutcome, f.err
}

func (f *fakeWorkOperations) ClaimWork(_ context.Context, _ domain.CollectorID, token string, _ time.Duration) (domain.WorkLease, bool, error) {
	f.claimedToken = token
	if f.operationError != nil {
		return domain.WorkLease{}, false, f.operationError
	}
	f.lease.LeaseToken = token
	return f.lease, f.found, nil
}

func (f *fakeWorkOperations) AcknowledgeWorkStart(_ context.Context, _ domain.CollectorID, _ domain.WorkID, _ int, token string) error {
	f.startedToken = token
	return f.operationError
}

func (f *fakeWorkOperations) RenewWorkLease(_ context.Context, _ domain.CollectorID, _ domain.WorkID, _ int, token string, duration time.Duration) error {
	f.renewedToken, f.renewedFor = token, duration
	return f.operationError
}

func TestTransportEnrollmentUsesBootstrapAuthorization(t *testing.T) {
	transport, identity, _, _, _ := newTestTransport(t)
	csrJSON, err := json.Marshal(string(testCollectorCSR(t)))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"csr_pem":` + string(csrJSON) + `,"metadata":{"display_name":"site collector","version":"1.2.3","build_commit":"abc","protocol_min":1,"protocol_max":1,"operating_system":"linux","architecture":"amd64"}}`
	request := collectorRequest(http.MethodPost, "/collector/v1/enroll", body, false)
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("b", 43))
	response := httptest.NewRecorder()
	transport.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("expected enrollment success, got %d: %s", response.Code, response.Body.String())
	}
	if identity.enrollmentRequest.BootstrapToken != strings.Repeat("b", 43) {
		t.Fatal("bootstrap token was not passed to enrollment service")
	}
	if strings.Contains(response.Body.String(), strings.Repeat("b", 43)) {
		t.Fatal("bootstrap secret was reflected in response")
	}
}

func TestTransportRejectsAuthenticatedOperationWithoutVerifiedMTLS(t *testing.T) {
	transport, _, _, _, _ := newTestTransport(t)
	request := collectorRequest(http.MethodPost, "/collector/v1/heartbeat", `{}`, false)
	response := httptest.NewRecorder()
	transport.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", response.Code)
	}
}

func TestDirectMTLSIgnoresCloudflareHeaders(t *testing.T) {
	transport, _, _, _, _ := newTestTransport(t)
	request := collectorRequest(http.MethodPost, "/collector/v1/heartbeat", `{}`, true)
	request.Header.Set(accessAssertionHeader, "untrusted")
	request.Header.Set(forwardedDERHeader, "untrusted")
	request.Header.Set(forwardedSHAHeader, "untrusted")
	response := httptest.NewRecorder()
	transport.ServeHTTP(response, request)
	if response.Code == http.StatusUnauthorized {
		t.Fatalf("direct mode considered proxy headers instead of its TLS certificate: %d: %s", response.Code, response.Body.String())
	}
}

func TestTransportRecordsBoundedHeartbeat(t *testing.T) {
	transport, _, heartbeats, _, _ := newTestTransport(t)
	body := `{"version":"1.2.3","build_commit":"abc123","capabilities":[{"name":"prometheus_source_health","version":"v1"}],"command_packs":[{"pack_id":"base","version":"2026.08","digest_sha256":"` + strings.Repeat("a", 64) + `"}],"source_health":[{"source_id":"prom-1","availability":"AVAILABLE","safe_message":"reachable","checked_at":"2026-08-19T11:59:00Z"}]}`
	request := collectorRequest(http.MethodPost, "/collector/v1/heartbeat", body, true)
	response := httptest.NewRecorder()
	transport.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected heartbeat success, got %d: %s", response.Code, response.Body.String())
	}
	if heartbeats.heartbeat.CollectorID != "collector-1" || heartbeats.heartbeat.ReportedAt != transportNow || len(heartbeats.heartbeat.CommandPacks) != 1 || len(heartbeats.heartbeat.SourceHealth) != 1 {
		t.Fatalf("unexpected heartbeat mapping: %#v", heartbeats.heartbeat)
	}
}

func TestTransportClaimMapsCompleteWorkLease(t *testing.T) {
	transport, _, _, work, _ := newTestTransport(t)
	work.found = true
	work.lease = testLease()
	request := collectorRequest(http.MethodGet, "/collector/v1/work/claim?wait_seconds=0", "", true)
	response := httptest.NewRecorder()
	transport.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected claim success, got %d: %s", response.Code, response.Body.String())
	}
	var body claimResponseDTO
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.WorkID != "work-1" || body.Attempt != 2 || body.LeaseToken == "" || body.WorkExpiresAt.IsZero() || body.Task.IdempotencyKey != "key-1" || body.Task.Range == nil || body.Task.Range.StepSeconds != 15 {
		t.Fatalf("incomplete claim response: %#v", body)
	}
	if body.LeaseToken != work.claimedToken {
		t.Fatal("returned lease token does not match claimed token")
	}
}

func TestClaimWaitDefaultsToArchitectureLongPoll(t *testing.T) {
	wait, err := parseWait("")
	if err != nil {
		t.Fatal(err)
	}
	if wait != 25*time.Second {
		t.Fatalf("default claim wait = %s, want 25s", wait)
	}
}

func TestTransportStartsAndRenewsLease(t *testing.T) {
	transport, _, _, work, _ := newTestTransport(t)
	token := strings.Repeat("t", 43)
	start := collectorRequest(http.MethodPost, "/collector/v1/work/work-1/attempts/2/start", `{"lease_token":"`+token+`"}`, true)
	startResponse := httptest.NewRecorder()
	transport.ServeHTTP(startResponse, start)
	if startResponse.Code != http.StatusNoContent || work.startedToken != token {
		t.Fatalf("start failed: %d token=%q", startResponse.Code, work.startedToken)
	}
	renew := collectorRequest(http.MethodPost, "/collector/v1/work/work-1/attempts/2/renew", `{"lease_token":"`+token+`","duration_seconds":120}`, true)
	renewResponse := httptest.NewRecorder()
	transport.ServeHTTP(renewResponse, renew)
	if renewResponse.Code != http.StatusNoContent || work.renewedToken != token || work.renewedFor != 2*time.Minute {
		t.Fatalf("renew failed: %d token=%q duration=%s", renewResponse.Code, work.renewedToken, work.renewedFor)
	}
}

func TestTransportRejectsUnknownFieldsAndProtocolMismatch(t *testing.T) {
	transport, _, _, _, _ := newTestTransport(t)
	request := collectorRequest(http.MethodPost, "/collector/v1/heartbeat", `{"unknown":true}`, true)
	response := httptest.NewRecorder()
	transport.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected strict JSON rejection, got %d", response.Code)
	}
	request = collectorRequest(http.MethodGet, "/collector/v1/work/claim", "", true)
	request.Header.Set(protocolHeader, "2")
	response = httptest.NewRecorder()
	transport.ServeHTTP(response, request)
	if response.Code != http.StatusUpgradeRequired {
		t.Fatalf("expected protocol rejection, got %d", response.Code)
	}
}

func TestTransportDoesNotExposeOperationErrorOrLeaseToken(t *testing.T) {
	transport, _, _, work, _ := newTestTransport(t)
	secret := strings.Repeat("s", 43)
	work.operationError = errors.New("database failed with secret " + secret)
	request := collectorRequest(http.MethodPost, "/collector/v1/work/work-1/attempts/1/start", `{"lease_token":"`+secret+`"}`, true)
	response := httptest.NewRecorder()
	transport.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected internal error, got %d", response.Code)
	}
	if strings.Contains(response.Body.String(), secret) || strings.Contains(response.Body.String(), "database") {
		t.Fatalf("unsafe error response: %s", response.Body.String())
	}
}

func TestTransportMapsInvalidLeaseToSafeConflict(t *testing.T) {
	transport, _, _, work, _ := newTestTransport(t)
	work.operationError = ErrWorkLeaseInvalid
	request := collectorRequest(http.MethodPost, "/collector/v1/work/work-1/attempts/1/start", `{"lease_token":"`+strings.Repeat("s", 43)+`"}`, true)
	response := httptest.NewRecorder()
	transport.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("expected conflict, got %d: %s", response.Code, response.Body.String())
	}
}

func TestTransportUploadsBase64ResultChunk(t *testing.T) {
	transport, _, _, _, results := newTestTransport(t)
	payload := []byte(`{"schema_version":1}`)
	digest := sha256.Sum256(payload)
	token := strings.Repeat("t", 43)
	body := `{"lease_token":"` + token + `","payload_base64":"` + base64.StdEncoding.EncodeToString(payload) + `","sha256":"` + hex.EncodeToString(digest[:]) + `"}`
	request := collectorRequest(http.MethodPut, "/collector/v1/work/work-1/attempts/2/results/chunks/0", body, true)
	response := httptest.NewRecorder()
	transport.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("expected chunk creation, got %d: %s", response.Code, response.Body.String())
	}
	if results.chunk.WorkID != "work-1" || results.chunk.Attempt != 2 || results.chunk.Index != 0 || !bytes.Equal(results.chunk.Payload, payload) || results.chunk.LeaseToken != token {
		t.Fatalf("unexpected chunk mapping: %#v", results.chunk)
	}
}

func TestTransportFinalizesResultAndMapsOutcome(t *testing.T) {
	transport, _, _, _, results := newTestTransport(t)
	results.finalOutcome = FinalizeOutcome{RunID: "run-1", Status: domain.ResultSucceeded, SHA256: strings.Repeat("a", 64), PreviouslyFinalized: true}
	body := `{"lease_token":"` + strings.Repeat("t", 43) + `","run_id":"run-1","status":"SUCCEEDED","chunk_count":1,"sha256":"` + strings.Repeat("a", 64) + `","bytes":100}`
	request := collectorRequest(http.MethodPost, "/collector/v1/work/work-1/attempts/2/results/finalize", body, true)
	response := httptest.NewRecorder()
	transport.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected finalization success, got %d: %s", response.Code, response.Body.String())
	}
	if results.finalization.RunID != "run-1" || results.finalization.Status != domain.ResultSucceeded || results.finalization.Bytes != 100 {
		t.Fatalf("unexpected finalization mapping: %#v", results.finalization)
	}
	if !strings.Contains(response.Body.String(), `"previously_finalized":true`) {
		t.Fatalf("missing idempotent outcome: %s", response.Body.String())
	}
}

func TestTransportRejectsOversizedDecodedChunk(t *testing.T) {
	transport, _, _, _, _ := newTestTransport(t)
	payload := bytes.Repeat([]byte("x"), MaxResultChunkBytes+1)
	digest := sha256.Sum256(payload)
	body := `{"lease_token":"` + strings.Repeat("t", 43) + `","payload_base64":"` + base64.StdEncoding.EncodeToString(payload) + `","sha256":"` + hex.EncodeToString(digest[:]) + `"}`
	request := collectorRequest(http.MethodPut, "/collector/v1/work/work-1/attempts/2/results/chunks/0", body, true)
	response := httptest.NewRecorder()
	transport.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected oversized chunk rejection, got %d", response.Code)
	}
}

func TestValidateHeartbeatRejectsDuplicatesAndFutureChecks(t *testing.T) {
	report := Heartbeat{
		CollectorID: "collector-1", Version: "1", ReportedAt: transportNow,
		Capabilities: []CapabilityReport{{Name: "health", Version: "1"}, {Name: "health", Version: "2"}},
	}
	if err := ValidateHeartbeat(report, transportNow); err == nil {
		t.Fatal("expected duplicate capability rejection")
	}
	report.Capabilities = report.Capabilities[:1]
	report.SourceHealth = []SourceHealthReport{{SourceID: "source-1", Availability: SourceAvailable, CheckedAt: transportNow.Add(6 * time.Minute)}}
	if err := ValidateHeartbeat(report, transportNow); err == nil {
		t.Fatal("expected future source check rejection")
	}
}

func newTestTransport(t *testing.T) (*Transport, *fakeIdentityOperations, *fakeHeartbeatRecorder, *fakeWorkOperations, *fakeResultOperations) {
	t.Helper()
	certificate := &x509.Certificate{Raw: []byte("verified collector certificate"), SerialNumber: big.NewInt(42)}
	identity := &fakeIdentityOperations{}
	heartbeats := &fakeHeartbeatRecorder{}
	work := &fakeWorkOperations{}
	results := &fakeResultOperations{}
	random := bytes.NewReader(bytes.Repeat([]byte{0x5a}, 1024))
	transport, err := NewTransport(identity, &fakeAuthenticator{certificate: certificate}, heartbeats, work, results, transportClock{}, random)
	if err != nil {
		t.Fatal(err)
	}
	testCertificate = certificate
	return transport, identity, heartbeats, work, results
}

var testCertificate *x509.Certificate

func collectorRequest(method, target, body string, authenticated bool) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set(protocolHeader, "1")
	request.Header.Set(correlationHeader, "test-correlation-1")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{testCertificate}, VerifiedChains: [][]*x509.Certificate{{testCertificate}}}
	}
	return request
}

func issuedTestIdentity() IssuedIdentity {
	return IssuedIdentity{CertificatePEM: []byte("CERTIFICATE"), CAChainPEM: []byte("CA"), NotBefore: transportNow, NotAfter: transportNow.Add(time.Hour)}
}

func testCollectorCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "collector"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func testLease() domain.WorkLease {
	start := transportNow.Add(-time.Minute)
	return domain.WorkLease{
		CollectorID: "collector-1", Attempt: 2, LeaseExpires: transportNow.Add(2 * time.Minute),
		Work: domain.CollectorWork{
			WorkID: "work-1", Status: domain.WorkLeased, AvailableAt: start, WorkExpiresAt: transportNow.Add(time.Hour),
			Task: domain.CollectionTask{
				RunID: "run-1", ClusterID: "cluster-1", SourceID: "source-1", Query: domain.QueryGPUUtilization,
				Node: "node-1", Range: &domain.CollectionRange{Start: start, End: transportNow, Step: 15 * time.Second},
				ScheduledFor: start, Deadline: transportNow.Add(time.Minute), MaxSeries: 100, MaxBytes: 1024, IdempotencyKey: "key-1",
			},
		},
	}
}

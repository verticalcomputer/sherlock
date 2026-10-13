package collectorcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const credentialCanary = "synthetic-control-canary-77"

type fakeCredentialTestOperations struct {
	plan       domain.CredentialAccessTestPlan
	token      string
	found      bool
	claims     int
	deliveries int
	delivered  CredentialAccessTestRef
	digest     domain.SHA256
	completed  domain.CredentialAccessTestResult
	refuse     error
}

func (f *fakeCredentialTestOperations) ClaimCredentialAccessTest(_ context.Context, cluster domain.ClusterID, collector domain.CollectorID, token string, _ time.Duration) (CredentialAccessTestLease, bool, error) {
	f.claims++
	if f.refuse != nil {
		return CredentialAccessTestLease{}, false, f.refuse
	}
	if !f.found {
		return CredentialAccessTestLease{}, false, nil
	}
	f.token = token
	return CredentialAccessTestLease{TestID: f.plan.TestID, Attempt: 1, LeaseToken: token, LeaseExpires: transportNow.Add(time.Minute), Plan: f.plan}, true, nil
}
func (f *fakeCredentialTestOperations) StartCredentialAccessTest(_ context.Context, _ domain.ClusterID, _ domain.CollectorID, ref CredentialAccessTestRef, _ time.Duration) (time.Time, error) {
	if ref.LeaseToken != f.token {
		return time.Time{}, ErrWorkLeaseInvalid
	}
	return transportNow.Add(time.Minute), nil
}
func (f *fakeCredentialTestOperations) RenewCredentialAccessTestLease(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, ref CredentialAccessTestRef, d time.Duration) (time.Time, error) {
	return f.StartCredentialAccessTest(ctx, cluster, collector, ref, d)
}
func (f *fakeCredentialTestOperations) DeliverCredentialForAccessTest(_ context.Context, cluster domain.ClusterID, collector domain.CollectorID, ref CredentialAccessTestRef, digest domain.SHA256) (CredentialDelivery, error) {
	f.deliveries++
	f.delivered, f.digest = ref, digest
	if f.refuse != nil {
		return CredentialDelivery{}, f.refuse
	}
	if ref.LeaseToken != f.token || cluster != f.plan.ClusterID || collector != "collector-1" {
		return CredentialDelivery{}, ErrWorkLeaseInvalid
	}
	return CredentialDelivery{Host: f.plan.Host, Username: f.plan.Username, CredentialVersion: f.plan.CredentialVersion, SudoPassword: []byte(credentialCanary)}, nil
}
func (f *fakeCredentialTestOperations) CompleteCredentialAccessTest(_ context.Context, _ domain.ClusterID, _ domain.CollectorID, ref CredentialAccessTestRef, result domain.CredentialAccessTestResult) (CredentialTestCompletion, error) {
	if ref.LeaseToken != f.token {
		return CredentialTestCompletion{}, ErrWorkLeaseInvalid
	}
	f.completed = result
	return CredentialTestCompletion{Status: domain.CredentialAccessTestSucceeded, Outcome: result.Outcome}, nil
}

func credentialTestPlan() domain.CredentialAccessTestPlan {
	return domain.CredentialAccessTestPlan{
		SchemaVersion: domain.CredentialAccessTestSchemaVersion, TestID: "ctest_transport", ClusterID: "cluster-1", Operation: domain.CredentialAccessTestOperation,
		Host: "head-1", Purpose: domain.CredentialAccessTestPurpose, Username: "fixture_user_1", CredentialID: "cred_transport", CredentialVersion: 2,
		RequestedAt: transportNow, Deadline: transportNow.Add(10 * time.Minute), Limits: domain.CredentialAccessTestLimits{TimeoutSeconds: 30, MaxOutputBytes: 4096},
	}
}

func TestCredentialTestTransportIsOptInAndAuthenticated(t *testing.T) {
	transport, _, _, _, _ := newTestTransport(t)
	if w := serveTyped(transport, "GET", "/collector/v2/credential-tests/claim?wait_seconds=0", "", "2", true); w.Code != 404 {
		t.Fatalf("unconfigured claim must not exist: %d", w.Code)
	}
	ops := &fakeCredentialTestOperations{plan: credentialTestPlan(), found: true}
	if err := transport.ConfigureCredentialAccessTests(ops); err != nil {
		t.Fatal(err)
	}
	if err := transport.ConfigureCredentialAccessTests(ops); err == nil {
		t.Fatal("double configuration must fail")
	}
	if w := serveTyped(transport, "GET", "/collector/v2/credential-tests/claim?wait_seconds=0", "", "2", false); w.Code != 401 {
		t.Fatalf("unauthenticated: %d", w.Code)
	}
	if w := serveTyped(transport, "GET", "/collector/v2/credential-tests/claim?wait_seconds=0", "", "1", true); w.Code != 426 {
		t.Fatalf("protocol v1 must be refused: %d", w.Code)
	}
	ops.refuse = ErrCredentialTestNotPermitted
	if w := serveTyped(transport, "GET", "/collector/v2/credential-tests/claim?wait_seconds=0", "", "2", true); w.Code != 403 {
		t.Fatalf("ineligible collector: %d %s", w.Code, w.Body.String())
	}
	ops.refuse = nil
}

func TestCredentialTestTransportDeliversOnlyToBoundLeaseWithoutCaching(t *testing.T) {
	transport, _, _, _, _ := newTestTransport(t)
	ops := &fakeCredentialTestOperations{plan: credentialTestPlan(), found: true}
	if err := transport.ConfigureCredentialAccessTests(ops); err != nil {
		t.Fatal(err)
	}
	claim := serveTyped(transport, "GET", "/collector/v2/credential-tests/claim?wait_seconds=0", "", "2", true)
	if claim.Code != 200 || strings.Contains(claim.Body.String(), credentialCanary) {
		t.Fatalf("claim: %d %s", claim.Code, claim.Body.String())
	}
	var lease CredentialAccessTestLease
	if err := json.Unmarshal(claim.Body.Bytes(), &lease); err != nil || lease.LeaseToken != ops.token || lease.Plan.TestID != "ctest_transport" {
		t.Fatalf("lease decode: %v %+v", err, lease)
	}
	digest, err := domain.CredentialAccessTestPlanDigest(lease.Plan)
	if err != nil {
		t.Fatal(err)
	}
	base := "/collector/v2/credential-tests/ctest_transport/attempts/1"
	if w := serveTyped(transport, "POST", base+"/start", `{"lease_token":"`+lease.LeaseToken+`"}`, "2", true); w.Code != 200 {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	wrong := serveTyped(transport, "POST", base+"/credential", `{"lease_token":"`+strings.Repeat("z", 40)+`","plan_digest":"`+digest.String()+`"}`, "2", true)
	if wrong.Code != 409 || strings.Contains(wrong.Body.String(), credentialCanary) {
		t.Fatalf("wrong token must be refused: %d %s", wrong.Code, wrong.Body.String())
	}
	if w := serveTyped(transport, "POST", base+"/credential", `{"lease_token":"`+lease.LeaseToken+`","plan_digest":"nothex"}`, "2", true); w.Code != 400 {
		t.Fatalf("bad digest: %d", w.Code)
	}
	delivery := serveTyped(transport, "POST", base+"/credential", `{"lease_token":"`+lease.LeaseToken+`","plan_digest":"`+digest.String()+`"}`, "2", true)
	if delivery.Code != 200 || delivery.Body.String() != credentialCanary {
		t.Fatalf("delivery: %d %q", delivery.Code, delivery.Body.String())
	}
	if delivery.Header().Get("Cache-Control") != "no-store" || delivery.Header().Get("Content-Type") != "application/octet-stream" || delivery.Header().Get(credentialDeliveryUsernameHeader) != "fixture_user_1" || delivery.Header().Get(credentialDeliveryVersionHeader) != "2" {
		t.Fatalf("delivery headers: %v", delivery.Header())
	}
	if ops.digest != digest || ops.delivered.TestID != "ctest_transport" || ops.delivered.Attempt != 1 {
		t.Fatalf("delivery binding not passed: %+v", ops.delivered)
	}
	if w := serveTyped(transport, "POST", "/collector/v2/credential-tests/ctest_transport/attempts/3/credential", `{"lease_token":"`+lease.LeaseToken+`","plan_digest":"`+digest.String()+`"}`, "2", true); w.Code != 400 {
		t.Fatalf("attempt bound: %d", w.Code)
	}
	result := domain.CredentialAccessTestResult{SchemaVersion: 1, TestID: "ctest_transport", Attempt: 1, PlanDigest: digest.String(), Outcome: domain.CredentialAccessVerified, Summary: "sudo authenticated and cmsh listed 3 devices.", BCMVersion: "10.24", DevicesListed: 3, StartedAt: transportNow, CompletedAt: transportNow.Add(time.Second), Checks: []domain.CredentialAccessCheck{{Name: "sudo_listing", Status: domain.CredentialAccessCheckPassed}}}
	document, _ := json.Marshal(result)
	sum := sha256.Sum256(document)
	body, _ := json.Marshal(map[string]any{"lease_token": lease.LeaseToken, "document": json.RawMessage(document), "sha256": hex.EncodeToString(sum[:])})
	if w := serveTyped(transport, "POST", base+"/result", string(body), "2", true); w.Code != 200 || !strings.Contains(w.Body.String(), `"outcome":"BCM_ACCESS_VERIFIED"`) {
		t.Fatalf("result: %d %s", w.Code, w.Body.String())
	}
	if ops.completed.Outcome != domain.CredentialAccessVerified {
		t.Fatal("result was not passed to the store")
	}
	tampered, _ := json.Marshal(map[string]any{"lease_token": lease.LeaseToken, "document": json.RawMessage(document), "sha256": strings.Repeat("0", 64)})
	if w := serveTyped(transport, "POST", base+"/result", string(tampered), "2", true); w.Code != 400 {
		t.Fatalf("checksum mismatch: %d", w.Code)
	}
	leaked := domain.CredentialAccessTestResult{SchemaVersion: 1, TestID: "ctest_transport", Attempt: 1, PlanDigest: digest.String(), Outcome: domain.CredentialAccessSudoAuthFailed, Summary: "bad " + credentialCanary + "\x00", StartedAt: transportNow, CompletedAt: transportNow}
	leakedDocument, _ := json.Marshal(leaked)
	leakedSum := sha256.Sum256(leakedDocument)
	leakedBody, _ := json.Marshal(map[string]any{"lease_token": lease.LeaseToken, "document": json.RawMessage(leakedDocument), "sha256": hex.EncodeToString(leakedSum[:])})
	if w := serveTyped(transport, "POST", base+"/result", string(leakedBody), "2", true); w.Code != 400 {
		t.Fatalf("unsanitized summary must be refused: %d", w.Code)
	}
	if w := serveTyped(transport, "GET", "/collector/v2/credential-tests/claim?wait_seconds=0", "", "2", true); w.Code != http.StatusOK {
		t.Fatalf("second claim: %d", w.Code)
	}
}

// The result submission path alone carries the retained inventory rows, so
// only it was raised to 256 KiB. Other credential-test bodies keep the
// smaller bound, and an over-sized result is still refused.
func TestCredentialTestResultBodyLimitIsRaisedOnlyForResults(t *testing.T) {
	transport, _, _, _, _ := newTestTransport(t)
	plan := credentialTestPlan()
	plan.Operation = domain.CredentialInventoryDiscoveryOperation
	ops := &fakeCredentialTestOperations{plan: plan, found: true}
	if err := transport.ConfigureCredentialAccessTests(ops); err != nil {
		t.Fatal(err)
	}
	claim := serveTyped(transport, "GET", "/collector/v2/credential-tests/claim?wait_seconds=0", "", "2", true)
	if claim.Code != 200 {
		t.Fatalf("claim: %d %s", claim.Code, claim.Body.String())
	}
	var lease CredentialAccessTestLease
	if err := json.Unmarshal(claim.Body.Bytes(), &lease); err != nil {
		t.Fatal(err)
	}
	digest, err := domain.CredentialAccessTestPlanDigest(lease.Plan)
	if err != nil {
		t.Fatal(err)
	}
	base := "/collector/v2/credential-tests/ctest_transport/attempts/1"
	submit := func(devices []domain.CredentialAccessDevice) *httptest.ResponseRecorder {
		t.Helper()
		result := domain.CredentialAccessTestResult{
			SchemaVersion: domain.CredentialAccessTestSchemaVersion, TestID: plan.TestID, Attempt: 1, PlanDigest: digest.String(),
			Outcome: domain.CredentialAccessVerified, Summary: "listed devices", BCMVersion: "10.0", DevicesListed: len(devices),
			StartedAt: transportNow, CompletedAt: transportNow, Devices: devices,
		}
		document, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(document)
		body, err := json.Marshal(credentialTestResultRequestDTO{LeaseToken: lease.LeaseToken, Document: document, SHA256: hex.EncodeToString(sum[:])})
		if err != nil {
			t.Fatal(err)
		}
		if len(body) <= 64<<10 {
			t.Fatalf("fixture does not exercise the raised bound: %d bytes", len(body))
		}
		return serveTyped(transport, "POST", base+"/result", string(body), "2", true)
	}
	// A full 512-row inventory does not fit the old 64 KiB bound but must fit
	// the raised one.
	full := make([]domain.CredentialAccessDevice, 0, domain.CredentialAccessTestMaxDevices)
	for i := 0; i < domain.CredentialAccessTestMaxDevices; i++ {
		full = append(full, domain.CredentialAccessDevice{Type: strings.Repeat("t", 40), Hostname: strings.Repeat("h", 60) + strconv.Itoa(i), Status: strings.Repeat("s", 20)})
	}
	if response := submit(full); response.Code != 200 || ops.completed.DevicesListed != domain.CredentialAccessTestMaxDevices || len(ops.completed.Devices) != domain.CredentialAccessTestMaxDevices {
		t.Fatalf("full inventory result: %d %s", response.Code, response.Body.String())
	}
	// Past the raised bound the body is still refused rather than truncated.
	oversized := strings.Repeat("p", maxCredentialResultBytes+1)
	if response := serveTyped(transport, "POST", base+"/result", `{"lease_token":"`+lease.LeaseToken+`","sha256":"`+oversized+`"}`, "2", true); response.Code != 400 {
		t.Fatalf("oversized result body accepted: %d", response.Code)
	}
	// Other credential-test bodies keep the smaller bound.
	if response := serveTyped(transport, "POST", base+"/start", `{"lease_token":"`+strings.Repeat("q", 65<<10)+`"}`, "2", true); response.Code != 400 {
		t.Fatalf("oversized start body accepted: %d", response.Code)
	}
}

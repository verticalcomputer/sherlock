package collectorcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ErrCredentialTestNotPermitted means the authenticated collector is not
// eligible for credential access tests (inactive, foreign cluster, missing
// capability or protocol range). It is a 403, not an empty claim.
var ErrCredentialTestNotPermitted = errors.New("collector is not permitted to run credential access tests")

// CredentialAccessTestLease is the claim response shared by control and the
// collector runtime. It never contains a secret.
type CredentialAccessTestLease struct {
	TestID       string                          `json:"test_id"`
	Attempt      int                             `json:"attempt"`
	LeaseToken   string                          `json:"lease_token"`
	LeaseExpires time.Time                       `json:"lease_expires_at"`
	Plan         domain.CredentialAccessTestPlan `json:"plan"`
}

// CredentialAccessTestRef identifies one attempt with its bearer lease token.
type CredentialAccessTestRef struct {
	TestID     string
	Attempt    int
	LeaseToken string
}

// CredentialDelivery is the decrypted, operation-bound secret handed to the
// authorized head. It is written as a raw non-cacheable body, never JSON, so
// the collector can hold it in a clearable byte buffer.
type CredentialDelivery struct {
	Host              string
	Username          string
	CredentialVersion int64
	SudoPassword      []byte
}

// CredentialTestCompletion is the durable outcome of a result submission.
type CredentialTestCompletion struct {
	Status   domain.CredentialAccessTestStatus
	Outcome  domain.CredentialAccessOutcome
	Rejected bool
}

// CredentialAccessTestOperations is implemented by the durable store behind
// the keyring. Implementations MUST re-prove collector eligibility, lease
// ownership and expiry, test state, plan digest and exact credential version
// inside each call; the transport supplies only the authenticated identity.
type CredentialAccessTestOperations interface {
	ClaimCredentialAccessTest(context.Context, domain.ClusterID, domain.CollectorID, string, time.Duration) (CredentialAccessTestLease, bool, error)
	StartCredentialAccessTest(context.Context, domain.ClusterID, domain.CollectorID, CredentialAccessTestRef, time.Duration) (time.Time, error)
	RenewCredentialAccessTestLease(context.Context, domain.ClusterID, domain.CollectorID, CredentialAccessTestRef, time.Duration) (time.Time, error)
	DeliverCredentialForAccessTest(context.Context, domain.ClusterID, domain.CollectorID, CredentialAccessTestRef, domain.SHA256) (CredentialDelivery, error)
	CompleteCredentialAccessTest(context.Context, domain.ClusterID, domain.CollectorID, CredentialAccessTestRef, domain.CredentialAccessTestResult) (CredentialTestCompletion, error)
}

const (
	credentialDeliveryHostHeader     = "X-Sherlock-Credential-Host"
	credentialDeliveryUsernameHeader = "X-Sherlock-Credential-Username"
	credentialDeliveryVersionHeader  = "X-Sherlock-Credential-Version"
	maxCredentialDeliveryBytes       = 8 << 10

	// maxCredentialResultBytes bounds the result submission body only. The
	// inventory discovery operation carries up to 512 bounded device rows in
	// the result document, which does not fit the 64 KiB bound the other
	// credential-test bodies keep.
	maxCredentialResultBytes = 256 << 10
)

// ConfigureCredentialAccessTests mounts the endpoint family. It is opt-in: a
// control plane without the credential keyring never exposes delivery.
func (t *Transport) ConfigureCredentialAccessTests(operations CredentialAccessTestOperations) error {
	if t == nil || operations == nil {
		return fmt.Errorf("credential access test operations are required")
	}
	if t.credentialTests != nil {
		return fmt.Errorf("credential access test operations are already configured")
	}
	t.credentialTests = operations
	t.mux.HandleFunc("GET /collector/v2/credential-tests/claim", t.claimCredentialTest)
	t.mux.HandleFunc("POST /collector/v2/credential-tests/{test_id}/attempts/{attempt}/start", t.credentialTestLease(true))
	t.mux.HandleFunc("POST /collector/v2/credential-tests/{test_id}/attempts/{attempt}/renew", t.credentialTestLease(false))
	t.mux.HandleFunc("POST /collector/v2/credential-tests/{test_id}/attempts/{attempt}/credential", t.deliverCredential)
	t.mux.HandleFunc("POST /collector/v2/credential-tests/{test_id}/attempts/{attempt}/result", t.completeCredentialTest)
	return nil
}

func (t *Transport) claimCredentialTest(w http.ResponseWriter, r *http.Request) {
	id, ok := validateProtocolVersion(w, r, domain.CollectionProtocolVersion)
	if !ok {
		return
	}
	identity, ok := t.authenticate(w, r, id)
	if !ok {
		return
	}
	wait, err := parseWait(r.URL.Query().Get("wait_seconds"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "wait_seconds is invalid", id)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), wait+defaultRequestTimeout)
	defer cancel()
	deadline := t.clock.Now().Add(wait)
	for {
		token, err := t.randomToken()
		if err != nil {
			writeOperationError(w, err, id)
			return
		}
		lease, found, err := t.credentialTests.ClaimCredentialAccessTest(ctx, identity.ClusterID, identity.CollectorID, token, defaultLeaseDuration)
		if err != nil {
			writeCredentialTestError(w, err, id)
			return
		}
		if found {
			if domain.ValidateCredentialAccessTestPlan(lease.Plan) != nil || lease.Plan.ClusterID != identity.ClusterID || lease.Plan.TestID != lease.TestID || lease.LeaseToken != token || lease.Attempt < 1 {
				writeOperationError(w, ErrWorkLeaseInvalid, id)
				return
			}
			lease.LeaseExpires = lease.LeaseExpires.UTC()
			writeJSON(w, http.StatusOK, lease)
			return
		}
		remaining := deadline.Sub(t.clock.Now())
		if remaining <= 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		timer := time.NewTimer(min(remaining, longPollInterval))
		select {
		case <-ctx.Done():
			timer.Stop()
			writeOperationError(w, ctx.Err(), id)
			return
		case <-timer.C:
		}
	}
}

type credentialTestLeaseRequestDTO struct {
	LeaseToken string `json:"lease_token"`
}

type credentialTestLeaseResponseDTO struct {
	LeaseExpires time.Time `json:"lease_expires_at"`
}

func (t *Transport) credentialTestLease(start bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, identity, ref, ok := t.credentialTestRequest(w, r)
		if !ok {
			return
		}
		var body credentialTestLeaseRequestDTO
		if !decodeJSON(w, r, &body) || !validLeaseToken(body.LeaseToken) {
			writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "lease token is invalid", id)
			return
		}
		ref.LeaseToken = body.LeaseToken
		ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
		defer cancel()
		var expires time.Time
		var err error
		if start {
			expires, err = t.credentialTests.StartCredentialAccessTest(ctx, identity.ClusterID, identity.CollectorID, ref, defaultLeaseDuration)
		} else {
			expires, err = t.credentialTests.RenewCredentialAccessTestLease(ctx, identity.ClusterID, identity.CollectorID, ref, defaultLeaseDuration)
		}
		if err != nil {
			writeCredentialTestError(w, err, id)
			return
		}
		writeJSON(w, http.StatusOK, credentialTestLeaseResponseDTO{LeaseExpires: expires.UTC()})
	}
}

type credentialDeliveryRequestDTO struct {
	LeaseToken string `json:"lease_token"`
	PlanDigest string `json:"plan_digest"`
}

// deliverCredential is the only handler that ever writes a secret. The body
// is the raw sudo password; metadata travels in headers. Errors are RFC 7807
// problems with no secret material and no reason detail beyond a code.
func (t *Transport) deliverCredential(w http.ResponseWriter, r *http.Request) {
	id, identity, ref, ok := t.credentialTestRequest(w, r)
	if !ok {
		return
	}
	var body credentialDeliveryRequestDTO
	if !decodeJSON(w, r, &body) || !validLeaseToken(body.LeaseToken) {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "delivery request is invalid", id)
		return
	}
	digest, err := domain.ParseSHA256(body.PlanDigest)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "plan digest is invalid", id)
		return
	}
	ref.LeaseToken = body.LeaseToken
	ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
	defer cancel()
	delivery, err := t.credentialTests.DeliverCredentialForAccessTest(ctx, identity.ClusterID, identity.CollectorID, ref, digest)
	if err != nil {
		writeCredentialTestError(w, err, id)
		return
	}
	defer clear(delivery.SudoPassword)
	if len(delivery.SudoPassword) == 0 || len(delivery.SudoPassword) > maxCredentialDeliveryBytes {
		writeProblem(w, http.StatusInternalServerError, "INTERNAL", "collector control operation failed", id)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set(credentialDeliveryHostHeader, delivery.Host)
	w.Header().Set(credentialDeliveryUsernameHeader, delivery.Username)
	w.Header().Set(credentialDeliveryVersionHeader, strconv.FormatInt(delivery.CredentialVersion, 10))
	w.Header().Set("Content-Length", strconv.Itoa(len(delivery.SudoPassword)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(delivery.SudoPassword)
}

type credentialTestResultRequestDTO struct {
	LeaseToken string          `json:"lease_token"`
	Document   json.RawMessage `json:"document"`
	SHA256     string          `json:"sha256"`
}

type credentialTestResultResponseDTO struct {
	Status   string `json:"status"`
	Outcome  string `json:"outcome"`
	Rejected bool   `json:"rejected"`
}

func (t *Transport) completeCredentialTest(w http.ResponseWriter, r *http.Request) {
	id, identity, ref, ok := t.credentialTestRequest(w, r)
	if !ok {
		return
	}
	var body credentialTestResultRequestDTO
	if !decodeJSONLimit(w, r, &body, maxCredentialResultBytes) || !validLeaseToken(body.LeaseToken) {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "result request is invalid", id)
		return
	}
	digest := sha256.Sum256(body.Document)
	var result domain.CredentialAccessTestResult
	if body.SHA256 != hex.EncodeToString(digest[:]) || json.Unmarshal(body.Document, &result) != nil || domain.ValidateCredentialAccessTestResult(result) != nil || result.TestID != ref.TestID || result.Attempt != ref.Attempt {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "result identity, schema, or checksum is invalid", id)
		return
	}
	ref.LeaseToken = body.LeaseToken
	ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
	defer cancel()
	completion, err := t.credentialTests.CompleteCredentialAccessTest(ctx, identity.ClusterID, identity.CollectorID, ref, result)
	if err != nil {
		writeCredentialTestError(w, err, id)
		return
	}
	writeJSON(w, http.StatusOK, credentialTestResultResponseDTO{Status: string(completion.Status), Outcome: string(completion.Outcome), Rejected: completion.Rejected})
}

func (t *Transport) credentialTestRequest(w http.ResponseWriter, r *http.Request) (string, AuthenticatedIdentity, CredentialAccessTestRef, bool) {
	id, ok := validateProtocolVersion(w, r, domain.CollectionProtocolVersion)
	if !ok {
		return "", AuthenticatedIdentity{}, CredentialAccessTestRef{}, false
	}
	identity, ok := t.authenticate(w, r, id)
	if !ok {
		return "", AuthenticatedIdentity{}, CredentialAccessTestRef{}, false
	}
	if t.credentialTests == nil {
		writeProblem(w, http.StatusServiceUnavailable, "CREDENTIAL_TESTS_UNAVAILABLE", "credential access tests are not configured", id)
		return "", AuthenticatedIdentity{}, CredentialAccessTestRef{}, false
	}
	attempt, err := strconv.Atoi(r.PathValue("attempt"))
	testID := r.PathValue("test_id")
	if err != nil || attempt < 1 || attempt > domain.CredentialAccessTestMaxAttempts || !domain.ValidCredentialAccessTestID(testID) {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "credential test reference is invalid", id)
		return "", AuthenticatedIdentity{}, CredentialAccessTestRef{}, false
	}
	return id, identity, CredentialAccessTestRef{TestID: testID, Attempt: attempt}, true
}

func validLeaseToken(token string) bool {
	return len(token) >= 32 && len(token) <= 256
}

func writeCredentialTestError(w http.ResponseWriter, err error, correlationID string) {
	if errors.Is(err, ErrCredentialTestNotPermitted) {
		writeProblem(w, http.StatusForbidden, "FORBIDDEN", "collector is not permitted to run credential access tests", correlationID)
		return
	}
	writeOperationError(w, err, correlationID)
}

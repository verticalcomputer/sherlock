package collectorruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const maxCredentialDeliveryBytes = 8 << 10

// CredentialDelivery is the head's in-memory copy of a delivered sudo
// password. Destroy it as soon as the reviewed child process has consumed it.
type CredentialDelivery struct {
	Host              string
	Username          string
	CredentialVersion int64
	SudoPassword      []byte
}

func (delivery *CredentialDelivery) Destroy() {
	if delivery == nil {
		return
	}
	clear(delivery.SudoPassword)
	delivery.SudoPassword = nil
}

func (delivery CredentialDelivery) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}
func (delivery CredentialDelivery) MarshalJSON() ([]byte, error) {
	return nil, errors.New("credential delivery cannot be JSON encoded")
}

// CredentialTestControlClient is the collector-side port for the
// credential-test endpoint family. It shares transport identity with the
// collection client and exposes nothing else.
type CredentialTestControlClient interface {
	ClaimCredentialTest(context.Context, time.Duration) (*collectorcontrol.CredentialAccessTestLease, error)
	StartCredentialTest(context.Context, collectorcontrol.CredentialAccessTestRef) (time.Time, error)
	RenewCredentialTest(context.Context, collectorcontrol.CredentialAccessTestRef) (time.Time, error)
	FetchCredential(context.Context, collectorcontrol.CredentialAccessTestRef, domain.SHA256) (*CredentialDelivery, error)
	SubmitCredentialTestResult(context.Context, collectorcontrol.CredentialAccessTestRef, domain.CredentialAccessTestResult) (collectorcontrol.CredentialTestCompletion, error)
}

func credentialTestPath(ref collectorcontrol.CredentialAccessTestRef, suffix string) string {
	return "/collector/v2/credential-tests/" + url.PathEscape(ref.TestID) + "/attempts/" + strconv.Itoa(ref.Attempt) + suffix
}

func (c *HTTPClient) ClaimCredentialTest(ctx context.Context, wait time.Duration) (*collectorcontrol.CredentialAccessTestLease, error) {
	var lease collectorcontrol.CredentialAccessTestLease
	status, err := c.doV2(ctx, http.MethodGet, "/collector/v2/credential-tests/claim?wait_seconds="+strconv.Itoa(int(wait/time.Second)), nil, &lease, http.StatusOK, http.StatusNoContent)
	if err != nil || status == http.StatusNoContent {
		return nil, err
	}
	if err := domain.ValidateCredentialAccessTestPlan(lease.Plan); err != nil || lease.Plan.TestID != lease.TestID || lease.Attempt < 1 || lease.Attempt > domain.CredentialAccessTestMaxAttempts || len(lease.LeaseToken) < 32 {
		return nil, errors.New("credential test claim is invalid")
	}
	return &lease, nil
}

type credentialLeaseWire struct {
	LeaseToken string `json:"lease_token"`
}
type credentialLeaseResponseWire struct {
	LeaseExpires time.Time `json:"lease_expires_at"`
}

func (c *HTTPClient) StartCredentialTest(ctx context.Context, ref collectorcontrol.CredentialAccessTestRef) (time.Time, error) {
	var response credentialLeaseResponseWire
	_, err := c.doV2(ctx, http.MethodPost, credentialTestPath(ref, "/start"), credentialLeaseWire{LeaseToken: ref.LeaseToken}, &response, http.StatusOK)
	return response.LeaseExpires.UTC(), err
}

func (c *HTTPClient) RenewCredentialTest(ctx context.Context, ref collectorcontrol.CredentialAccessTestRef) (time.Time, error) {
	var response credentialLeaseResponseWire
	_, err := c.doV2(ctx, http.MethodPost, credentialTestPath(ref, "/renew"), credentialLeaseWire{LeaseToken: ref.LeaseToken}, &response, http.StatusOK)
	return response.LeaseExpires.UTC(), err
}

type credentialDeliveryWire struct {
	LeaseToken string `json:"lease_token"`
	PlanDigest string `json:"plan_digest"`
}

// FetchCredential retrieves the operation-bound secret as raw bytes. The
// response is read into one bounded buffer that the caller must Destroy; it is
// never decoded as JSON, logged or retained by the client.
func (c *HTTPClient) FetchCredential(ctx context.Context, ref collectorcontrol.CredentialAccessTestRef, planDigest domain.SHA256) (*CredentialDelivery, error) {
	encoded, err := json.Marshal(credentialDeliveryWire{LeaseToken: ref.LeaseToken, PlanDigest: planDigest.String()})
	if err != nil {
		return nil, err
	}
	target := c.baseURL.ResolveReference(&url.URL{Path: credentialTestPath(ref, "/credential")})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("create credential delivery request: %w", err)
	}
	request.Header.Set(protocolHeader, "2")
	request.Header.Set(correlationHeader, correlationID())
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/octet-stream, application/problem+json")
	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("send credential delivery request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumBodyBytes))
		failure := fmt.Errorf("collector control returned HTTP %d", response.StatusCode)
		if response.StatusCode == http.StatusConflict || response.StatusCode == http.StatusGone || response.StatusCode == http.StatusForbidden {
			return nil, errors.Join(ErrLeaseLost, failure)
		}
		return nil, failure
	}
	if response.Header.Get("Content-Type") != "application/octet-stream" {
		return nil, errors.New("credential delivery has an unexpected content type")
	}
	secret, err := io.ReadAll(io.LimitReader(response.Body, maxCredentialDeliveryBytes+1))
	if err != nil || len(secret) == 0 || len(secret) > maxCredentialDeliveryBytes {
		clear(secret)
		return nil, errors.New("credential delivery body is missing or exceeds its bound")
	}
	version, err := strconv.ParseInt(response.Header.Get("X-Sherlock-Credential-Version"), 10, 64)
	if err != nil || version < 1 {
		clear(secret)
		return nil, errors.New("credential delivery version header is invalid")
	}
	return &CredentialDelivery{Host: response.Header.Get("X-Sherlock-Credential-Host"), Username: response.Header.Get("X-Sherlock-Credential-Username"), CredentialVersion: version, SudoPassword: secret}, nil
}

type credentialResultWire struct {
	LeaseToken string          `json:"lease_token"`
	Document   json.RawMessage `json:"document"`
	SHA256     string          `json:"sha256"`
}

type credentialResultResponseWire struct {
	Status   string `json:"status"`
	Outcome  string `json:"outcome"`
	Rejected bool   `json:"rejected"`
}

func (c *HTTPClient) SubmitCredentialTestResult(ctx context.Context, ref collectorcontrol.CredentialAccessTestRef, result domain.CredentialAccessTestResult) (collectorcontrol.CredentialTestCompletion, error) {
	if err := domain.ValidateCredentialAccessTestResult(result); err != nil {
		return collectorcontrol.CredentialTestCompletion{}, err
	}
	document, err := json.Marshal(result)
	if err != nil {
		return collectorcontrol.CredentialTestCompletion{}, err
	}
	digest := sha256.Sum256(document)
	var response credentialResultResponseWire
	if _, err := c.doV2(ctx, http.MethodPost, credentialTestPath(ref, "/result"), credentialResultWire{LeaseToken: ref.LeaseToken, Document: document, SHA256: hex.EncodeToString(digest[:])}, &response, http.StatusOK); err != nil {
		return collectorcontrol.CredentialTestCompletion{}, err
	}
	return collectorcontrol.CredentialTestCompletion{Status: domain.CredentialAccessTestStatus(response.Status), Outcome: domain.CredentialAccessOutcome(response.Outcome), Rejected: response.Rejected}, nil
}

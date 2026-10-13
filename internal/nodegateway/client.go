package nodegateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

// Client holds one node key epoch. Runtime retains a separate client for an old
// verify-only key while replaying its immutable spool. It has no cloud identity.
type Client struct {
	base      *url.URL
	http      *http.Client
	principal Principal
	public    map[string]ed25519.PublicKey
}

func NewClient(endpoint string, identity tls.Certificate, gatewayCA *x509.CertPool, gatewayPin string) (*Client, error) {
	base, err := url.Parse(endpoint)
	pin, pinErr := hex.DecodeString(gatewayPin)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.Path != "" && base.Path != "/" || gatewayCA == nil || len(identity.Certificate) == 0 || identity.PrivateKey == nil || pinErr != nil || len(pin) != 32 || hex.EncodeToString(pin) != gatewayPin {
		return nil, telemetry.ErrInvalid
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		return nil, telemetry.ErrInvalid
	}
	principal, err := certificatePrincipal(leaf)
	if err != nil {
		return nil, telemetry.ErrInvalid
	}
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, telemetry.ErrInvalid
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: gatewayCA, Certificates: []tls.Certificate{identity}, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return telemetry.ErrUnauthorized
		}
		actual := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if !bytes.Equal(actual[:], pin) {
			return telemetry.ErrUnauthorized
		}
		return nil
	}}, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, MaxIdleConns: 1, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableCompression: true}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{base: base, http: client, principal: principal, public: map[string]ed25519.PublicKey{principal.KeyID: public}}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) SubmitBatch(ctx context.Context, wire []byte) (telemetry.Receipt, error) {
	var receipt telemetry.Receipt
	batch, err := telemetry.DecodeNodeBatch(wire, "")
	if err != nil || telemetry.ValidateNodeBatch(batch) != nil {
		return receipt, telemetry.ErrInvalid
	}
	if batch.Key.ClusterID != c.principal.ClusterID || batch.Key.NodeID != c.principal.NodeID || batch.Key.EnrollmentID != c.principal.EnrollmentID || telemetry.VerifyBatchSignature(batch, c.public[batch.SigningKeyID]) != nil {
		return receipt, telemetry.ErrUnauthorized
	}
	if err := c.request(ctx, "/node-telemetry/v1/batches", wire, &receipt); err != nil {
		return telemetry.Receipt{}, err
	}
	if receipt.ProtocolVersion != 1 || !identityID(receipt.ID) || receipt.Durability != "GATEWAY" || receipt.Key != batch.Key || receipt.Digest != batch.Digest || receipt.StoredAt.IsZero() {
		return telemetry.Receipt{}, telemetry.ErrConflict
	}
	return receipt, nil
}
func (c *Client) RegisterSession(ctx context.Context, message telemetry.SessionMessage) (telemetry.SessionReceipt, error) {
	var receipt telemetry.SessionReceipt
	if message.ClusterID != c.principal.ClusterID || message.NodeID != c.principal.NodeID || message.EnrollmentID != c.principal.EnrollmentID || telemetry.VerifySessionSignature(message, c.public[message.SigningKeyID]) != nil {
		return receipt, telemetry.ErrUnauthorized
	}
	wire, err := json.Marshal(message)
	if err != nil {
		return receipt, telemetry.ErrInvalid
	}
	if err := c.request(ctx, "/node-telemetry/v1/sessions", wire, &receipt); err != nil {
		return telemetry.SessionReceipt{}, err
	}
	if receipt.ProtocolVersion != 1 || !identityID(receipt.ID) || receipt.Durability != "GATEWAY" || receipt.ClusterID != message.ClusterID || receipt.NodeID != message.NodeID || receipt.EnrollmentID != message.EnrollmentID || receipt.EnrollmentRevision != message.EnrollmentRevision || receipt.SessionEpoch != message.SessionEpoch || receipt.SessionID != message.SessionID || receipt.BootID != message.BootID || receipt.Kind != message.Kind || receipt.Digest != message.Digest || receipt.StoredAt.IsZero() {
		return telemetry.SessionReceipt{}, telemetry.ErrConflict
	}
	return receipt, nil
}
func (c *Client) request(ctx context.Context, path string, wire []byte, target any) error {
	if len(wire) == 0 || len(wire) > telemetry.MaxBatchBytes {
		return telemetry.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	destination := c.base.ResolveReference(&url.URL{Path: path})
	request, err := http.NewRequestWithContext(bounded, http.MethodPost, destination.String(), bytes.NewReader(wire))
	if err != nil {
		return telemetry.ErrInvalid
	}
	request.Header.Set("X-Sherlock-Telemetry-Version", "1")
	if strings.Contains(path, "/retirement/") {
		request.Header.Set("X-Sherlock-Release-Version", "1")
		if len(wire) > telemetry.MaxReleaseBytes {
			return telemetry.ErrInvalid
		}
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := c.http.Do(request)
	if err != nil {
		return telemetry.ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		switch response.StatusCode {
		case 400, 413, 415, 426:
			return telemetry.ErrInvalid
		case 401, 403:
			return telemetry.ErrUnauthorized
		case 409:
			return telemetry.ErrConflict
		case 410:
			return telemetry.ErrReplayExpired
		case 429:
			return telemetry.ErrBackpressure
		default:
			return telemetry.ErrUnavailable
		}
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return telemetry.ErrInvalid
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (8<<10)+1))
	if err != nil || len(body) > 8<<10 || telemetry.DecodeStrictJSON(body, "", target) != nil {
		return telemetry.ErrInvalid
	}
	return nil
}

// NewClientWithSigningKeys permits an active node certificate to relay immutable
// old-key batches for the same enrollment. Both signatures remain independently
// checked against current gateway/cloud authority and the persisted session key.
// The bounded public key list is local verification material, never a grant.
func NewClientWithSigningKeys(endpoint string, identity tls.Certificate, gatewayCA *x509.CertPool, gatewayPin string, keys []telemetry.NodeKey) (*Client, error) {
	if len(keys) == 0 || len(keys) > 2 {
		return nil, telemetry.ErrInvalid
	}
	client, err := NewClient(endpoint, identity, gatewayCA, gatewayPin)
	if err != nil {
		return nil, err
	}
	parsed := map[string]ed25519.PublicKey{}
	for _, key := range keys {
		pub, err := telemetry.ParseNodePublicKey(key)
		if err != nil || !identityID(key.ID) || parsed[key.ID] != nil {
			return nil, telemetry.ErrInvalid
		}
		parsed[key.ID] = pub
	}
	if !bytes.Equal(parsed[client.principal.KeyID], client.public[client.principal.KeyID]) {
		return nil, telemetry.ErrInvalid
	}
	client.public = parsed
	return client, nil
}

package collectorruntime

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

// TelemetryClient adds unsolicited signed node intake to the existing gateway
// HTTP transport. Composition supplies its authenticated collector mTLS/PoP
// client; no cloud credentials are sent to compute nodes. It has no lease API.
type TelemetryClient struct {
	control            *HTTPClient
	cluster, collector string
}

func NewTelemetryClient(control *HTTPClient, cluster, collector string) (*TelemetryClient, error) {
	if control == nil || control.client == nil || control.baseURL.Scheme != "https" || control.baseURL.User != nil || control.baseURL.RawQuery != "" || control.baseURL.Fragment != "" || !telemetryIdentifier(cluster) || !telemetryIdentifier(collector) {
		return nil, telemetry.ErrInvalid
	}
	return &TelemetryClient{control: control, cluster: cluster, collector: collector}, nil
}
func (c *TelemetryClient) Grant(ctx context.Context, id string) (telemetry.Grant, error) {
	var grant telemetry.Grant
	if !telemetryIdentifier(id) {
		return grant, telemetry.ErrInvalid
	}
	err := c.request(ctx, "GET", "/collector/telemetry/v1/enrollments/"+url.PathEscape(id)+"/grant", nil, &grant, 32<<10)
	if err != nil {
		return telemetry.Grant{}, err
	}
	if telemetry.ValidateGrant(grant, time.Now()) != nil || grant.ClusterID != c.cluster || grant.GatewayCollectorID != c.collector || grant.EnrollmentID != id {
		return telemetry.Grant{}, telemetry.ErrUnauthorized
	}
	return grant, nil
}
func (c *TelemetryClient) RegisterSession(ctx context.Context, m telemetry.SessionMessage) (telemetry.SessionReceipt, error) {
	var receipt telemetry.SessionReceipt
	if m.ClusterID != c.cluster {
		return receipt, telemetry.ErrUnauthorized
	}
	digest, err := telemetry.CanonicalSessionDigest(m)
	if err != nil || hex.EncodeToString(digest[:]) != m.Digest {
		return receipt, telemetry.ErrInvalid
	}
	if err = c.request(ctx, "POST", "/collector/telemetry/v1/sessions", m, &receipt, 8<<10); err != nil {
		return telemetry.SessionReceipt{}, err
	}
	if receipt.ProtocolVersion != 1 || !telemetryIdentifier(receipt.ID) || receipt.Durability != "CLOUD" || receipt.ClusterID != m.ClusterID || receipt.NodeID != m.NodeID || receipt.EnrollmentID != m.EnrollmentID || receipt.EnrollmentRevision != m.EnrollmentRevision || receipt.SessionEpoch != m.SessionEpoch || receipt.SessionID != m.SessionID || receipt.BootID != m.BootID || receipt.Kind != m.Kind || receipt.Digest != m.Digest || receipt.StoredAt.IsZero() {
		return telemetry.SessionReceipt{}, telemetry.ErrConflict
	}
	return receipt, nil
}
func (c *TelemetryClient) SubmitBatch(ctx context.Context, b telemetry.NodeBatch, gatewayReceiptID string) (telemetry.CloudReceipt, error) {
	var receipt telemetry.CloudReceipt
	if b.Key.ClusterID != c.cluster {
		return receipt, telemetry.ErrUnauthorized
	}
	if telemetry.ValidateNodeBatch(b) != nil || !telemetryIdentifier(gatewayReceiptID) {
		return receipt, telemetry.ErrInvalid
	}
	digest, err := telemetry.CanonicalDigest(b)
	if err != nil || hex.EncodeToString(digest[:]) != b.Digest {
		return receipt, telemetry.ErrInvalid
	}
	envelope := telemetry.CloudBatchEnvelope{Batch: b, GatewayReceiptID: gatewayReceiptID}
	if err := c.request(ctx, "POST", "/collector/telemetry/v1/batches", envelope, &receipt, 8<<10); err != nil {
		return telemetry.CloudReceipt{}, err
	}
	if receipt.ProtocolVersion != 1 || !telemetryIdentifier(receipt.ID) || receipt.Durability != "CLOUD" || receipt.Key != b.Key || receipt.Digest != b.Digest || receipt.GatewayReceiptID != gatewayReceiptID || receipt.StoredAt.IsZero() {
		return telemetry.CloudReceipt{}, telemetry.ErrConflict
	}
	return receipt, nil
}
func (c *TelemetryClient) Status(ctx context.Context, id string) (telemetry.EnrollmentStatus, error) {
	var status telemetry.EnrollmentStatus
	if !telemetryIdentifier(id) {
		return status, telemetry.ErrInvalid
	}
	if err := c.request(ctx, "GET", "/collector/telemetry/v1/enrollments/"+url.PathEscape(id)+"/status", nil, &status, telemetry.MaxStatusBytes); err != nil {
		return telemetry.EnrollmentStatus{}, err
	}
	if status.Grant.ClusterID != c.cluster || status.Grant.GatewayCollectorID != c.collector || status.Grant.EnrollmentID != id || len(status.Sessions) > telemetry.MaxStatusSessions || len(status.Receipts) > telemetry.MaxStatusReceipts || len(status.History) > telemetry.MaxStatusHistory {
		return telemetry.EnrollmentStatus{}, telemetry.ErrConflict
	}
	return status, nil
}
func (c *TelemetryClient) request(ctx context.Context, method, path string, body, target any, responseLimit int64) error {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil || len(encoded) > telemetry.MaxBatchBytes {
			return telemetry.ErrInvalid
		}
	}
	relative, err := url.Parse(path)
	if err != nil {
		return telemetry.ErrInvalid
	}
	endpoint := c.control.baseURL.ResolveReference(relative)
	request, err := http.NewRequestWithContext(bounded, method, endpoint.String(), bytes.NewReader(encoded))
	if err != nil {
		return telemetry.ErrInvalid
	}
	request.Header.Set(protocolHeader, "1")
	request.Header.Set("X-Sherlock-Telemetry-Version", "1")
	if strings.Contains(path, "/retirement/") || strings.HasSuffix(path, "/retirement-capabilities") {
		request.Header.Set("X-Sherlock-Release-Version", "1")
		if len(encoded) > telemetry.MaxReleaseBytes {
			return telemetry.ErrInvalid
		}
	}
	request.Header.Set(correlationHeader, correlationID())
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	client := *c.control.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
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
	wire, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if err != nil || int64(len(wire)) > responseLimit {
		return telemetry.ErrInvalid
	}
	if telemetry.DecodeStrictJSON(wire, "", target) != nil {
		return telemetry.ErrInvalid
	}
	return nil
}
func telemetryIdentifier(v string) bool {
	if len(v) == 0 || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}

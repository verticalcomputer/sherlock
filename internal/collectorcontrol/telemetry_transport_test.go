package collectorcontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

type fakeTelemetryIntake struct {
	calls              int
	cluster, collector string
	batch              telemetry.NodeBatch
	err                error
}

func (f *fakeTelemetryIntake) Grant(_ context.Context, c domain.ClusterID, g domain.CollectorID, id string) (telemetry.Grant, error) {
	f.calls++
	f.cluster, f.collector = string(c), string(g)
	return telemetry.Grant{EnrollmentID: id}, f.err
}
func (f *fakeTelemetryIntake) RegisterSession(_ context.Context, c domain.ClusterID, g domain.CollectorID, m telemetry.SessionMessage) (telemetry.SessionReceipt, error) {
	f.calls++
	f.cluster, f.collector = string(c), string(g)
	return telemetry.SessionReceipt{ID: "session-receipt", SessionID: m.SessionID}, f.err
}
func (f *fakeTelemetryIntake) AcceptBatch(_ context.Context, c domain.ClusterID, g domain.CollectorID, b telemetry.NodeBatch, id string) (telemetry.CloudReceipt, error) {
	f.calls++
	f.cluster, f.collector, f.batch = string(c), string(g), b
	return telemetry.CloudReceipt{ProtocolVersion: 1, ID: "cloud-receipt", Key: b.Key, Digest: b.Digest, GatewayReceiptID: id, Durability: "CLOUD"}, f.err
}
func (f *fakeTelemetryIntake) Status(_ context.Context, c domain.ClusterID, g domain.CollectorID, id string) (telemetry.EnrollmentStatus, error) {
	f.calls++
	f.cluster, f.collector = string(c), string(g)
	return telemetry.EnrollmentStatus{Grant: telemetry.Grant{EnrollmentID: id}}, f.err
}
func telemetryEnvelope(t *testing.T) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := telemetry.NewFixtureFrame("source-1", "cluster-1", "node-a", "sample", transportNow, 7)
	if err != nil {
		t.Fatal(err)
	}
	b := telemetry.NodeBatch{ProtocolVersion: 1, Key: telemetry.BatchKey{ClusterID: "cluster-1", NodeID: "node-a", EnrollmentID: "enrollment-a", SessionEpoch: "1", SessionID: "session-a", Sequence: "1"}, EnrollmentRevision: 1, InventoryRevisionID: "inventory-a", BootID: "boot-a", SigningKeyID: "key-a", AgentVersion: "fixture.v1", BuildSHA256: strings.Repeat("a", 64), CreatedAt: transportNow, Sources: []telemetry.SourceFrame{frame}}
	if err := telemetry.SignBatch(&b, key); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(struct {
		Batch            telemetry.NodeBatch `json:"batch"`
		GatewayReceiptID string              `json:"gateway_receipt_id"`
	}{b, "gateway-receipt"})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
func telemetryRequest(t *testing.T, tr *Transport, path, body string, authenticated bool, modify func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	method := "POST"
	if strings.Contains(path, "enrollments/") {
		method = "GET"
	}
	req := collectorRequest(method, path, body, authenticated)
	req.Header.Set("X-Sherlock-Telemetry-Version", "1")
	if modify != nil {
		modify(req)
	}
	w := httptest.NewRecorder()
	tr.ServeHTTP(w, req)
	return w
}
func TestTelemetryTransportBindsAuthenticatedGatewayAndPreservesOldProtocols(t *testing.T) {
	tr, _, _, _, _ := newTestTransport(t)
	store := &fakeTelemetryIntake{}
	if err := tr.ConfigureTelemetry(store); err != nil {
		t.Fatal(err)
	}
	w := telemetryRequest(t, tr, "/collector/telemetry/v1/batches", telemetryEnvelope(t), true, nil)
	if w.Code != 200 || store.cluster != "cluster-1" || store.collector != "collector-1" || store.batch.Key.NodeID != "node-a" || !strings.Contains(w.Body.String(), "gateway-receipt") {
		t.Fatal("telemetry principal/receipt wrong", w.Code, w.Body.String())
	}
	for _, suffix := range []string{"grant", "status"} {
		w = telemetryRequest(t, tr, "/collector/telemetry/v1/enrollments/enrollment-a/"+suffix, "", true, nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	req := collectorRequest("GET", "/collector/v1/work/claim?wait_seconds=0", "", true)
	w = httptest.NewRecorder()
	tr.ServeHTTP(w, req)
	if w.Code == 404 || w.Code == 426 || w.Code == 401 {
		t.Fatal("legacy protocol route changed", w.Code)
	}
	req = collectorRequest("GET", "/collector/v2/work/claim?wait_seconds=0", "", true)
	req.Header.Set(protocolHeader, "2")
	w = httptest.NewRecorder()
	tr.ServeHTTP(w, req)
	if w.Code != 503 {
		t.Fatal("typed route behavior changed", w.Code)
	}
}
func TestTelemetryTransportRejectsAmbiguousOrOversizeBodiesBeforeStore(t *testing.T) {
	valid := telemetryEnvelope(t)
	cases := []struct {
		name, body string
		auth       bool
		change     func(*http.Request)
		code       int
	}{
		{"unauthenticated", valid, false, nil, 401},
		{"wrong-version", valid, true, func(r *http.Request) { r.Header.Set("X-Sherlock-Telemetry-Version", "2") }, 426},
		{"compressed", valid, true, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, 415},
		{"unknown-key", strings.Replace(valid, `"gateway_receipt_id":`, `"unexpected":1,"gateway_receipt_id":`, 1), true, nil, 400},
		{"duplicate-key", strings.Replace(valid, `"gateway_receipt_id":`, `"gateway_receipt_id":"other","gateway_receipt_id":`, 1), true, nil, 400},
		{"case-alias", strings.Replace(valid, `"gateway_receipt_id":`, `"Gateway_receipt_id":`, 1), true, nil, 400},
		{"null-batch", `{"batch":null,"gateway_receipt_id":"receipt"}`, true, nil, 400},
		{"oversize", strings.Repeat("x", telemetry.MaxBatchBytes+1), true, nil, 413},
		{"query", valid, true, func(r *http.Request) { r.URL.RawQuery = "cluster_id=foreign" }, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr, _, _, _, _ := newTestTransport(t)
			store := &fakeTelemetryIntake{}
			if err := tr.ConfigureTelemetry(store); err != nil {
				t.Fatal(err)
			}
			w := telemetryRequest(t, tr, "/collector/telemetry/v1/batches", tc.body, tc.auth, tc.change)
			if w.Code != tc.code || store.calls != 0 {
				t.Fatal("rejected envelope reached store", w.Code, store.calls, w.Body.String())
			}
		})
	}
}
func TestTelemetryTransportMapsClosedErrorsWithoutDriverDetail(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{{telemetry.ErrInvalid, 400}, {telemetry.ErrUnauthorized, 403}, {telemetry.ErrConflict, 409}, {telemetry.ErrBackpressure, 429}, {telemetry.ErrReplayExpired, 410}, {errors.New("private-driver-credential-value"), 503}} {
		tr, _, _, _, _ := newTestTransport(t)
		store := &fakeTelemetryIntake{err: tc.err}
		if err := tr.ConfigureTelemetry(store); err != nil {
			t.Fatal(err)
		}
		w := telemetryRequest(t, tr, "/collector/telemetry/v1/enrollments/enrollment-a/grant", "", true, nil)
		if w.Code != tc.code || strings.Contains(w.Body.String(), "private-driver") || strings.Contains(w.Body.String(), tc.err.Error()) {
			t.Fatal("unsafe operation response", w.Code, w.Body.String())
		}
	}
}

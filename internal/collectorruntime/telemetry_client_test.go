package collectorruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func telemetryClientFixture(t *testing.T) (telemetry.NodeBatch, telemetry.SessionMessage, telemetry.Grant) {
	t.Helper()
	at := time.Now().UTC()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := telemetry.NewFixtureFrame("source-a", "cluster-a", "node-a", "record", at, 1)
	if err != nil {
		t.Fatal(err)
	}
	b := telemetry.NodeBatch{ProtocolVersion: 1, Key: telemetry.BatchKey{ClusterID: "cluster-a", NodeID: "node-a", EnrollmentID: "enrollment-a", SessionEpoch: "1", SessionID: "session-a", Sequence: "1"}, EnrollmentRevision: 1, InventoryRevisionID: "inventory-a", BootID: "boot-a", SigningKeyID: "key-a", AgentVersion: "fixture.v1", BuildSHA256: strings.Repeat("a", 64), CreatedAt: at, Sources: []telemetry.SourceFrame{frame}}
	if err := telemetry.SignBatch(&b, key); err != nil {
		t.Fatal(err)
	}
	m := telemetry.SessionMessage{ProtocolVersion: 1, Kind: "OPEN", ClusterID: b.Key.ClusterID, NodeID: b.Key.NodeID, EnrollmentID: b.Key.EnrollmentID, EnrollmentRevision: 1, SessionEpoch: "1", SessionID: "session-a", BootID: "boot-a", SigningKeyID: "key-a", CreatedAt: at}
	if err := telemetry.SignSessionMessage(&m, key); err != nil {
		t.Fatal(err)
	}
	g := telemetry.Grant{ProtocolVersion: 1, EnrollmentID: b.Key.EnrollmentID, EnrollmentRevision: 1, ControlRevision: 1, Status: "ACTIVE", ClusterID: b.Key.ClusterID, NodeID: b.Key.NodeID, InventoryRevisionID: b.InventoryRevisionID, GatewayCollectorID: "gateway-a", Sources: []telemetry.SourceGrant{{SourceID: "source-a", SchemaVersion: 1, ProfileID: telemetry.FixtureProfile}}, AgentVersion: b.AgentVersion, BuildSHA256: b.BuildSHA256, GatewaySPKISHA256: strings.Repeat("b", 64), Keys: []telemetry.NodeKey{{ID: "key-a", Epoch: "1", PublicKeyBase64: base64.RawStdEncoding.EncodeToString(pub), State: "ACTIVE"}}, NotBefore: at.Add(-time.Second), NotAfter: at.Add(time.Minute)}
	return b, m, g
}
func newTelemetryTestClient(t *testing.T, server *httptest.Server) *TelemetryClient {
	t.Helper()
	control, err := NewHTTPClient(server.URL, server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewTelemetryClient(control, "cluster-a", "gateway-a")
	if err != nil {
		t.Fatal(err)
	}
	return client
}
func TestTelemetryClientExactReceiptFlowAndProtocolHeaders(t *testing.T) {
	b, m, g := telemetryClientFixture(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(protocolHeader) != "1" || r.Header.Get("X-Sherlock-Telemetry-Version") != "1" || r.Header.Get(correlationHeader) == "" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("telemetry transport headers missing")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/collector/telemetry/v1/enrollments/enrollment-a/grant":
			_ = json.NewEncoder(w).Encode(g)
		case "/collector/telemetry/v1/sessions":
			var got telemetry.SessionMessage
			if json.NewDecoder(r.Body).Decode(&got) != nil || got.Digest != m.Digest {
				t.Error("session changed")
			}
			_ = json.NewEncoder(w).Encode(telemetry.SessionReceipt{ProtocolVersion: 1, ID: "session-receipt", ClusterID: m.ClusterID, NodeID: m.NodeID, EnrollmentID: m.EnrollmentID, EnrollmentRevision: 1, SessionEpoch: m.SessionEpoch, SessionID: m.SessionID, BootID: m.BootID, Kind: m.Kind, Digest: m.Digest, Durability: "CLOUD", StoredAt: time.Now()})
		case "/collector/telemetry/v1/batches":
			var got telemetry.CloudBatchEnvelope
			if json.NewDecoder(r.Body).Decode(&got) != nil || got.Batch.Digest != b.Digest || got.GatewayReceiptID != "gateway-receipt" {
				t.Error("immutable batch changed")
			}
			_ = json.NewEncoder(w).Encode(telemetry.CloudReceipt{ProtocolVersion: 1, ID: "cloud-receipt", Key: b.Key, Digest: b.Digest, GatewayReceiptID: "gateway-receipt", StoredAt: time.Now(), Durability: "CLOUD", HistoryOnly: true})
		case "/collector/telemetry/v1/enrollments/enrollment-a/status":
			_ = json.NewEncoder(w).Encode(telemetry.EnrollmentStatus{Grant: g})
		default:
			t.Error("unexpected path")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client := newTelemetryTestClient(t, server)
	if _, err := client.Grant(context.Background(), g.EnrollmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RegisterSession(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SubmitBatch(context.Background(), b, "gateway-receipt"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Status(context.Background(), g.EnrollmentID); err != nil {
		t.Fatal(err)
	}
}
func TestTelemetryClientRejectsForeignReceiptsAndAmbiguousResponses(t *testing.T) {
	b, _, _ := telemetryClientFixture(t)
	good, _ := json.Marshal(telemetry.CloudReceipt{ProtocolVersion: 1, ID: "receipt", Key: b.Key, Digest: b.Digest, GatewayReceiptID: "gateway-receipt", StoredAt: time.Now(), Durability: "CLOUD", HistoryOnly: true})
	cases := []string{strings.Replace(string(good), `"gateway-receipt"`, `"foreign"`, 1), strings.Replace(string(good), `"node-a"`, `"node-b"`, 1), strings.Replace(string(good), `"id":"receipt"`, `"id":"receipt","id":"other"`, 1), string(good) + `{}`, strings.Repeat("x", (8<<10)+1), `{"private_driver_detail":"secret"}`}
	for _, response := range cases {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(response)) }))
		client := newTelemetryTestClient(t, server)
		_, err := client.SubmitBatch(context.Background(), b, "gateway-receipt")
		server.Close()
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("foreign/ambiguous response admitted or leaked", err)
		}
	}
}
func TestTelemetryClientNeverFollowsRedirectOrLeaksResponseError(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(307)
		_, _ = w.Write([]byte("private response credentials"))
	}))
	defer server.Close()
	client := newTelemetryTestClient(t, server)
	_, err := client.Grant(context.Background(), "enrollment-a")
	if !errors.Is(err, telemetry.ErrUnavailable) || redirected.Load() != 0 || strings.Contains(err.Error(), "private") {
		t.Fatal("redirect or unsafe failure", err, redirected.Load())
	}
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer plain.Close()
	control, _ := NewHTTPClient(plain.URL, plain.Client(), time.Minute)
	if _, err := NewTelemetryClient(control, "cluster-a", "gateway-a"); err == nil {
		t.Fatal("plaintext telemetry admitted")
	}
}

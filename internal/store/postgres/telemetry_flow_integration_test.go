//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/nodegateway"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetryjournal"
)

// This is synthetic preconfigured PKI, not node bootstrap/CSR issuance or an
// installation candidate. Both TLS boundaries, durable journals, collector
// identity authentication and cloud persistence are actual implementations.
func TestTelemetryActualTLSJournalsToCloudPersistence(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	caPEM, caKeyPEM := m15TestCA(t, time.Now())
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("synthetic CA")
	}
	gatewayKey, _ := m15CollectorCSR(t)
	gatewayIdentity := flowLeaf(t, caPEM, caKeyPEM, gatewayKey, nil, true)
	serverTLS, gatewayPin, err := nodegateway.ServerTLSConfig(gatewayIdentity, roots)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture's placeholder pin was immutable authority. Revoke it and create
	// an explicitly new enrollment approved for the actual gateway SPKI.
	if _, err = f.store.RevokeEnrollment(ctx, f.request.ClusterID, f.request.EnrollmentID, 1, "synthetic-flow-operator"); err != nil {
		t.Fatal(err)
	}
	f.request.EnrollmentID += "-flow"
	f.request.GatewaySPKISHA256 = gatewayPin
	if _, err = f.store.CreateEnrollment(ctx, f.request, 0, "synthetic-flow-operator"); err != nil {
		t.Fatal(err)
	}
	control, err := storepg.NewCollectorControlStore(f.pool)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := collectorcontrol.NewCAIssuer(caPEM, caKeyPEM, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := collectorcontrol.NewIdentityService(control, issuer, platform.SystemClock{}, platform.RandomIDGenerator{}, rand.Reader, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Renew the preconfigured synthetic gateway through the real identity service;
	// its exact certificate fingerprint and validity are persisted by the store.
	f.exec(t, `UPDATE collectors SET identity_serial=$2 WHERE collector_id=$1`, f.request.GatewayCollectorID, "synthetic-placeholder-"+f.request.EnrollmentID)
	collectorKey, csr := m15CollectorCSR(t)
	issued, err := identities.Renew(ctx, f.request.GatewayCollectorID, csr)
	if err != nil {
		t.Fatal("actual collector identity", err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(collectorKey)
	collectorIdentity, err := tls.X509KeyPair(append(append([]byte(nil), issued.CertificatePEM...), issued.CAChainPEM...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	var dropCloud atomic.Bool
	dropCloud.Store(true)
	startCloud := func() (*httptest.Server, *collectorruntime.TelemetryClient) {
		t.Helper()
		transport, e := collectorcontrol.NewTransport(identities, control, control, control, control, platform.SystemClock{}, rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		if e = transport.ConfigureTelemetry(storepg.NewTelemetryStore(f.pool)); e != nil {
			t.Fatal(e)
		}
		server := httptest.NewUnstartedServer(flowLostResponse(transport, "/collector/telemetry/v1/batches", &dropCloud))
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
		server.StartTLS()
		httpClient := server.Client()
		httpTransport := httpClient.Transport.(*http.Transport).Clone()
		httpTransport.TLSClientConfig = httpTransport.TLSClientConfig.Clone()
		httpTransport.TLSClientConfig.MinVersion = tls.VersionTLS13
		httpTransport.TLSClientConfig.Certificates = []tls.Certificate{collectorIdentity}
		cloudPin := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
		httpTransport.TLSClientConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
				return telemetry.ErrUnauthorized
			}
			actual := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if actual != cloudPin {
				return telemetry.ErrUnauthorized
			}
			return nil
		}
		httpClient.Transport = httpTransport
		t.Cleanup(httpClient.CloseIdleConnections)
		protocol, e := collectorruntime.NewHTTPClient(server.URL, httpClient, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		client, e := collectorruntime.NewTelemetryClient(protocol, string(f.request.ClusterID), string(f.request.GatewayCollectorID))
		if e != nil {
			t.Fatal(e)
		}
		return server, client
	}
	cloud, cloudClient := startCloud()
	defer func() { cloud.Close() }()
	grant, err := cloudClient.Grant(ctx, f.request.EnrollmentID)
	if err != nil {
		t.Fatal("authenticated cloud grant", err)
	}
	uri, err := nodegateway.NodeIdentityURI(string(f.request.ClusterID), string(f.request.NodeID), f.request.EnrollmentID, f.request.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	nodeIdentity := flowLeaf(t, caPEM, caKeyPEM, f.private, uri, false)
	localVerifier := flowLocalAdmission{grant: grant}
	scope := telemetryjournal.Scope{ClusterID: grant.ClusterID, NodeID: grant.NodeID, EnrollmentID: grant.EnrollmentID}
	root := t.TempDir()
	nodeRoot, gatewayRoot := filepath.Join(root, "node"), filepath.Join(root, "gateway")
	nodeOptions := telemetryjournal.Options{SourceIDs: []string{grant.Sources[0].SourceID}, Role: telemetryjournal.Node, Scope: scope, Limits: telemetryjournal.NodeLimits(), Verifier: localVerifier, SessionVerifier: localVerifier, RequireSessions: true, Now: time.Now}
	nodeQueue, err := telemetryjournal.Open(nodeRoot, nodeOptions)
	if err != nil {
		t.Fatal("node journal", err)
	}
	defer func() { _ = nodeQueue.Close() }()
	var gatewayQueue *telemetryjournal.Queue
	var nodeServer *httptest.Server
	var nodeClient *nodegateway.Client
	var dropGateway atomic.Bool
	dropGateway.Store(true)
	startGateway := func() {
		t.Helper()
		authority, e := nodegateway.NewAuthority(grant.ClusterID, grant.GatewayCollectorID, gatewayPin, []string{grant.EnrollmentID}, cloudClient)
		if e != nil {
			t.Fatal(e)
		}
		admission, e := nodegateway.NewGatewayAdmission(authority)
		if e != nil {
			t.Fatal(e)
		}
		gatewayQueue, e = telemetryjournal.Open(gatewayRoot, telemetryjournal.Options{SourceIDs: []string{grant.Sources[0].SourceID}, Role: telemetryjournal.Gateway, Scope: scope, Limits: telemetryjournal.GatewayLimits(), Verifier: admission, SessionVerifier: admission, RequireSessions: true, Now: time.Now})
		if e != nil {
			t.Fatal("gateway journal", e)
		}
		ingress, e := nodegateway.NewJournalIngress(map[string]*telemetryjournal.Queue{grant.EnrollmentID: gatewayQueue})
		if e != nil {
			t.Fatal(e)
		}
		handler, e := nodegateway.NewHandler(authority, ingress)
		if e != nil {
			t.Fatal(e)
		}
		nodeServer = httptest.NewUnstartedServer(flowLostResponse(handler, "/node-telemetry/v1/batches", &dropGateway))
		nodeServer.TLS = serverTLS.Clone()
		nodeServer.StartTLS()
		nodeClient, e = nodegateway.NewClient(nodeServer.URL, nodeIdentity, roots, gatewayPin)
		if e != nil {
			t.Fatal(e)
		}
	}
	startGateway()
	defer func() { nodeClient.Close(); nodeServer.Close(); _ = gatewayQueue.Close() }()
	open := f.session(t, 1, f.private, f.request.KeyID)
	if _, err = nodeQueue.RegisterSession(ctx, open); err != nil {
		t.Fatal("node lifecycle durability", err)
	}
	if _, err = nodeClient.RegisterSession(ctx, open); err != nil {
		t.Fatal("node TLS lifecycle", err)
	}
	cloudSession, err := cloudClient.RegisterSession(ctx, open)
	if err != nil || cloudSession.Durability != "CLOUD" {
		t.Fatal("cloud TLS lifecycle", err)
	}
	batch := f.batch(t, 1, 1)
	wire, _ := json.Marshal(batch)
	localReceipt, err := nodeQueue.Put(ctx, wire)
	if err != nil || localReceipt.Durability != "NODE" {
		t.Fatal("node durability", err)
	}
	if _, err = nodeClient.SubmitBatch(ctx, wire); !errors.Is(err, telemetry.ErrUnavailable) {
		t.Fatal("gateway response loss not injected", err)
	}
	entries, err := gatewayQueue.Next(ctx, 1)
	if err != nil || len(entries) != 1 {
		t.Fatal("lost gateway response discarded ownership", err)
	}
	originalGatewayReceipt := entries[0].Receipt
	flowStats(t, ctx, nodeQueue, 1, 0)
	flowStats(t, ctx, gatewayQueue, 1, 0)
	// Restart both journals and the gateway authority/listener while neither
	// side has received an upstream acknowledgement. Startup must poll cloud.
	nodeClient.Close()
	nodeServer.Close()
	if err = gatewayQueue.Close(); err != nil {
		t.Fatal(err)
	}
	if err = nodeQueue.Close(); err != nil {
		t.Fatal(err)
	}
	nodeQueue, err = telemetryjournal.Open(nodeRoot, nodeOptions)
	if err != nil {
		t.Fatal("node restart", err)
	}
	startGateway()
	replayLocal, err := nodeQueue.Put(ctx, wire)
	if err != nil || replayLocal != localReceipt {
		t.Fatal("node replay changed receipt", err)
	}
	gatewayReceipt, err := nodeClient.SubmitBatch(ctx, wire)
	if err != nil || gatewayReceipt != originalGatewayReceipt {
		t.Fatal("gateway replay changed receipt", err)
	}
	if err = nodeQueue.Acknowledge(ctx, gatewayReceipt, ""); err != nil {
		t.Fatal("node acknowledged gateway durability", err)
	}
	flowStats(t, ctx, nodeQueue, 0, 1)
	ownedWire, err := gatewayQueue.Read(ctx, batch.Key)
	if err != nil || !bytes.Equal(ownedWire, wire) {
		t.Fatal("gateway replay recollected/mutated bytes", err)
	}
	if _, err = cloudClient.SubmitBatch(ctx, batch, gatewayReceipt.ID); !errors.Is(err, telemetry.ErrUnavailable) {
		t.Fatal("cloud response loss not injected", err)
	}
	flowStats(t, ctx, gatewayQueue, 1, 0)
	var committedID, digest string
	var committedAt time.Time
	if err = f.pool.QueryRow(ctx, `SELECT receipt_id,digest,stored_at FROM gp06f_telemetry_batches WHERE enrollment_id=$1`, f.request.EnrollmentID).Scan(&committedID, &digest, &committedAt); err != nil {
		t.Fatal("cloud commit lost with response", err)
	}
	// A cloud process restart has no in-memory dedupe authority. Persisted receipt
	// plus current enrollment/source/key authority decide the exact replay.
	cloud.Close()
	cloud, cloudClient = startCloud()
	replay, err := cloudClient.SubmitBatch(ctx, batch, gatewayReceipt.ID)
	if err != nil || replay.ID != committedID || replay.Digest != digest || !replay.StoredAt.Equal(committedAt) || !replay.HistoryOnly {
		t.Fatal("cloud restart replay changed committed receipt", err)
	}
	cloudAck := telemetry.Receipt{ProtocolVersion: replay.ProtocolVersion, ID: replay.ID, Key: replay.Key, Digest: replay.Digest, StoredAt: replay.StoredAt, Durability: replay.Durability}
	if err = gatewayQueue.Acknowledge(ctx, cloudAck, replay.GatewayReceiptID); err != nil {
		t.Fatal("gateway responsibility transfer", err)
	}
	flowStats(t, ctx, gatewayQueue, 0, 1)
	exactReplay, err := cloudClient.SubmitBatch(ctx, batch, gatewayReceipt.ID)
	if err != nil || exactReplay != replay {
		t.Fatal("exact durable cloud replay", err)
	}
	status, err := cloudClient.Status(ctx, f.request.EnrollmentID)
	if err != nil || len(status.Receipts) != 1 || len(status.History) != 1 || status.Receipts[0] != replay || status.History[0].Digest != batch.Digest {
		t.Fatal("authenticated scoped API history", err)
	}
	for _, source := range status.History[0].Sources {
		for _, record := range source.Records {
			if !record.CollectedAt.Equal(f.now) || !record.ObservedAt.Equal(f.now) {
				t.Fatal("replay refreshed source timestamps")
			}
		}
	}
	foreignURI, _ := nodegateway.NodeIdentityURI(grant.ClusterID, "foreign-node", grant.EnrollmentID, f.request.KeyID)
	foreignIdentity := flowLeaf(t, caPEM, caKeyPEM, f.private, foreignURI, false)
	foreignClient, err := nodegateway.NewClient(nodeServer.URL, foreignIdentity, roots, gatewayPin)
	if err != nil {
		t.Fatal(err)
	}
	defer foreignClient.Close()
	foreign := batch
	foreign.Key.NodeID = "foreign-node"
	frame, err := telemetry.NewFixtureFrame(grant.Sources[0].SourceID, grant.ClusterID, "foreign-node", "foreign-record", f.now, 1)
	if err != nil {
		t.Fatal(err)
	}
	foreign.Sources = []telemetry.SourceFrame{frame}
	if err = telemetry.SignBatch(&foreign, f.private); err != nil {
		t.Fatal(err)
	}
	foreignWire, _ := json.Marshal(foreign)
	if _, err = foreignClient.SubmitBatch(ctx, foreignWire); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("real TLS foreign-node certificate admitted", err)
	}
	for _, table := range []string{"observations", "collection_runs", "current_projections"} {
		var count int
		if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE cluster_id=$1`, f.request.ClusterID).Scan(&count); err != nil || count != 0 {
			t.Fatal("fixture transport produced ordinary health", table, err)
		}
	}
	var batches int
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM gp06f_telemetry_batches WHERE enrollment_id=$1`, f.request.EnrollmentID).Scan(&batches); err != nil || batches != 1 {
		t.Fatal("replay/foreign node duplicated history", err)
	}
	t.Log("synthetic preconfigured PKI: NODE durability -> real pinned TLS1.3 gateway -> GATEWAY durability -> real collector mTLS/fingerprint -> CLOUD durability -> durable ownership transfer; both lost acknowledgements/restarts preserved exact receipts")
}

func flowLostResponse(handler http.Handler, path string, drop *atomic.Bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path && drop.CompareAndSwap(true, false) {
			recorded := httptest.NewRecorder()
			handler.ServeHTTP(recorded, r)
			if recorded.Code == http.StatusOK {
				connection, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = connection.Close()
				}
				return
			}
			for key, values := range recorded.Header() {
				w.Header()[key] = values
			}
			w.WriteHeader(recorded.Code)
			_, _ = w.Write(recorded.Body.Bytes())
			return
		}
		handler.ServeHTTP(w, r)
	})
}
func flowLeaf(t *testing.T, caPEM, keyPEM []byte, private crypto.Signer, uri *url.URL, server bool) tls.Certificate {
	t.Helper()
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(keyPEM)
	rootKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Synthetic telemetry TLS fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		template.DNSNames = []string{"localhost"}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		template.URIs = []*url.URL{uri}
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, ca, private.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

// Local node verification uses only its explicitly approved public scope/key;
// it holds no outbound collector transport, credential or cloud client.
type flowLocalAdmission struct{ grant telemetry.Grant }

func (v flowLocalAdmission) Verify(_ context.Context, wire []byte) (telemetryjournal.Envelope, error) {
	batch, err := telemetry.DecodeNodeBatch(wire, "")
	if err != nil || telemetry.ValidateBatchForGrant(batch, v.grant, time.Now()) != nil {
		return telemetryjournal.Envelope{}, telemetry.ErrUnauthorized
	}
	key, err := telemetry.ParseNodePublicKey(v.grant.Keys[0])
	if err != nil || telemetry.VerifyBatchSignature(batch, key) != nil {
		return telemetryjournal.Envelope{}, telemetry.ErrUnauthorized
	}
	var sources []string
	for _, source := range batch.Sources {
		sources = append(sources, source.SourceID)
	}
	return telemetryjournal.Envelope{Key: batch.Key, Digest: batch.Digest, CreatedAt: batch.CreatedAt, Lane: telemetryjournal.Data, Sources: sources, BootID: batch.BootID, SigningKeyID: batch.SigningKeyID, EnrollmentRevision: batch.EnrollmentRevision}, nil
}
func (v flowLocalAdmission) VerifySession(_ context.Context, message telemetry.SessionMessage) (telemetryjournal.SessionAuthorization, error) {
	if telemetry.ValidateSessionForGrant(message, v.grant, time.Now()) != nil {
		return telemetryjournal.SessionAuthorization{}, telemetry.ErrUnauthorized
	}
	return telemetryjournal.SessionAuthorization{SignerActive: true}, nil
}
func flowStats(t *testing.T, ctx context.Context, q *telemetryjournal.Queue, owned, transferred int) {
	t.Helper()
	stats, err := q.Stats(ctx)
	if err != nil || stats.Owned != owned || stats.Transferred != transferred || stats.Corrupt {
		t.Fatal("durable ownership state", stats, err)
	}
}

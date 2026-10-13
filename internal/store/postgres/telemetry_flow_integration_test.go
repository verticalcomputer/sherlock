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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/gatewaytelemetry"
	"github.com/verticalcomputer/sherlock/internal/nodegateway"
	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetryjournal"
)

// Synthetic trust roots exercise actual protected CSR issuance/import, both TLS
// boundaries, durable journals and cloud persistence. This is not installation
// or native host/workload qualification.
func TestTelemetryActualTLSJournalsToCloudPersistence(t *testing.T) {
	for _, profile := range []string{telemetry.FixtureProfile, telemetry.LinuxHostProfile, telemetry.LinuxRootProfile} {
		t.Run(profile, func(t *testing.T) { telemetryTLSProfileFlow(t, profile) })
	}
}
func telemetryTLSProfileFlow(t *testing.T, profile string) {
	f, initialRequest, nodeIssuer := nodeBootstrapFixture(t)
	// Obtain the independently configured synthetic node CA, not a trust anchor
	// learned from a relay response. This local candidate is never admitted.
	initial, err := nodeIssuer.Issue(initialRequest, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	nodeRoots := x509.NewCertPool()
	if !nodeRoots.AppendCertsFromPEM([]byte(initial.NodeCAPEM)) {
		t.Fatal("node root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	caPEM, caKeyPEM := m15TestCA(t, time.Now())
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("synthetic CA")
	}
	gatewayKey, _ := m15CollectorCSR(t)
	gatewayIdentity := flowLeaf(t, caPEM, caKeyPEM, gatewayKey, nil, true)
	serverTLS, gatewayPin, err := nodegateway.ServerTLSConfig(gatewayIdentity, nodeRoots)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture's placeholder pin was immutable authority. Revoke it and create
	// an explicitly new enrollment approved for the actual gateway SPKI.
	if _, err = f.store.RevokeEnrollment(ctx, f.request.ClusterID, f.request.EnrollmentID, 1, "synthetic-flow-operator"); err != nil {
		t.Fatal(err)
	}
	f.request.EnrollmentID += "-flow"
	identityDir := t.TempDir()
	if err := os.Chmod(identityDir, 0700); err != nil {
		t.Fatal(err)
	}
	request, err := nodeidentity.CreateIdentityRequest(identityDir, nodeidentity.Scope{ClusterID: string(f.request.ClusterID), NodeID: string(f.request.NodeID), EnrollmentID: f.request.EnrollmentID, KeyID: f.request.KeyID})
	if err != nil {
		t.Fatal("local CSR", err)
	}
	f.request.PublicKeyBase64 = request.PublicKeyBase64
	f.request.GatewaySPKISHA256 = gatewayPin
	if profile != telemetry.FixtureProfile {
		f.request.SourceProfiles = map[string]string{string(f.request.SourceIDs[0]): profile}
	}
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
	controlServerKey, _ := m15CollectorCSR(t)
	controlServerIdentity := flowLeaf(t, caPEM, caKeyPEM, controlServerKey, nil, true)
	var dropIdentity atomic.Bool
	dropIdentity.Store(true)
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
		if e = transport.ConfigureNodeIdentity(storepg.NewTelemetryStore(f.pool), nodeIssuer); e != nil {
			t.Fatal(e)
		}
		server := httptest.NewUnstartedServer(flowLostResponse(flowLostResponse(transport, "/collector/telemetry/v1/node-certificates", &dropIdentity), "/collector/telemetry/v1/batches", &dropCloud))
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Certificates: []tls.Certificate{controlServerIdentity}}
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
	// Relay with the actual selected gateway mode. Neither node listener nor
	// journal paths are supplied: identity relay must not need/open either.
	files := t.TempDir()
	write := func(name string, body []byte) string {
		path := filepath.Join(files, name)
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cloudPin := sha256.Sum256(cloud.Certificate().RawSubjectPublicKeyInfo)
	relayConfig := gatewaytelemetry.ServiceConfig{ProtocolVersion: 1, FixtureOnly: profile == telemetry.FixtureProfile, ResidentSources: profile != telemetry.FixtureProfile, ClusterID: grant.ClusterID, CollectorID: grant.GatewayCollectorID, EnrollmentIDs: []string{grant.EnrollmentID}, NodeCAFile: write("node-ca.pem", []byte(initial.NodeCAPEM)), ControlURL: cloud.URL, ControlCAFile: write("control-ca.pem", caPEM), ControlSPKISHA256: hex.EncodeToString(cloudPin[:]), CollectorCertificateFile: write("collector.pem", issued.CertificatePEM), CollectorKeyFile: write("collector-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), AuthMode: "direct_mtls"}
	token := mintBootstrap(t, f, request)
	for _, invalid := range []gatewaytelemetry.ServiceConfig{
		func() gatewaytelemetry.ServiceConfig {
			c := relayConfig
			c.FixtureOnly = false
			c.ResidentSources = false
			return c
		}(),
		func() gatewaytelemetry.ServiceConfig {
			c := relayConfig
			c.FixtureOnly = true
			c.ResidentSources = true
			return c
		}(),
		func() gatewaytelemetry.ServiceConfig {
			c := relayConfig
			c.EnrollmentIDs = []string{"foreign"}
			return c
		}(),
		func() gatewaytelemetry.ServiceConfig { c := relayConfig; c.ClusterID = "foreign"; return c }(),
	} {
		if _, err := gatewaytelemetry.RelayIdentity(ctx, invalid, token, request); !errors.Is(err, telemetry.ErrUnauthorized) {
			t.Fatal("relay scope/mode accepted", err)
		}
	}
	if profile != telemetry.FixtureProfile {
		fixtureOnly := relayConfig
		fixtureOnly.FixtureOnly = true
		fixtureOnly.ResidentSources = false
		if _, err := gatewaytelemetry.RelayIdentity(ctx, fixtureOnly, token, request); !errors.Is(err, telemetry.ErrUnauthorized) {
			t.Fatal("fixture relay admitted Linux source", err)
		}
	}
	for _, badRequest := range []nodeidentity.Request{
		func() nodeidentity.Request { r := request; r.Scope.NodeID = "foreign-node"; return r }(),
		func() nodeidentity.Request { r := request; r.CSRSHA256 = fmt.Sprintf("%064x", 0); return r }(),
	} {
		if _, err := gatewaytelemetry.RelayIdentity(ctx, relayConfig, token, badRequest); !errors.Is(err, telemetry.ErrUnauthorized) {
			t.Fatal("foreign/tampered request admitted", err)
		}
	}
	badPin := relayConfig
	badPin.ControlSPKISHA256 = fmt.Sprintf("%064x", 0)
	if _, err := gatewaytelemetry.RelayIdentity(ctx, badPin, token, request); !errors.Is(err, telemetry.ErrUnavailable) {
		t.Fatal("incorrect control pin admitted", err)
	}
	var beforeIssuance int
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM gp06f_node_identity_audit WHERE enrollment_id=$1 AND action='CERTIFICATE_ISSUED'`, grant.EnrollmentID).Scan(&beforeIssuance); err != nil || beforeIssuance != 0 {
		t.Fatal("denial consumed token", err, beforeIssuance)
	}
	if _, err := gatewaytelemetry.RelayIdentity(ctx, relayConfig, token, request); !errors.Is(err, telemetry.ErrUnavailable) {
		t.Fatal("issuance response loss not injected", err)
	}
	// Restart cloud transport/store after committed issuance and lost response.
	cloud.Close()
	cloud, cloudClient = startCloud()
	relayConfig.ControlURL = cloud.URL
	bundle, err := gatewaytelemetry.RelayIdentity(ctx, relayConfig, token, request)
	if err != nil {
		t.Fatal("resident certificate relay replay", err)
	}
	again, err := gatewaytelemetry.RelayIdentity(ctx, relayConfig, token, request)
	if err != nil || bundle != again {
		t.Fatal("issuance replay changed", err)
	}
	var issuanceCount int
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM gp06f_node_identity_audit WHERE enrollment_id=$1 AND action='CERTIFICATE_ISSUED'`, grant.EnrollmentID).Scan(&issuanceCount); err != nil || issuanceCount != 1 {
		t.Fatal("issuance not atomic", err, issuanceCount)
	}
	if err = nodeidentity.ImportIdentity(identityDir, bundle, nodeIssuer.NodeCAFingerprint(), time.Now()); err != nil {
		t.Fatal("import issued identity", err)
	}
	loaded, nodePrivate, err := nodeidentity.LoadIdentity(identityDir, nodeIssuer.NodeCAFingerprint(), time.Now())
	if err != nil || loaded != bundle {
		t.Fatal("load issued identity", err)
	}
	f.private = nodePrivate
	nodeKeyDER, err := x509.MarshalPKCS8PrivateKey(nodePrivate)
	if err != nil {
		t.Fatal(err)
	}
	nodeIdentity, err := tls.X509KeyPair([]byte(bundle.CertificatePEM+bundle.NodeCAPEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: nodeKeyDER}))
	if err != nil {
		t.Fatal(err)
	}
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
		if source.ProfileID != profile || profile != telemetry.FixtureProfile && (source.Status != "PARTIAL" || source.Fields[len(source.Fields)-1].Reason != "MISSING") {
			t.Fatal("profile/partial support lost")
		}
		for _, record := range source.Records {
			if !record.CollectedAt.Equal(f.now) || !record.ObservedAt.Equal(f.now) {
				t.Fatal("replay refreshed source timestamps")
			}
		}
	}
	foreignRequest, err := nodeidentity.NewRequest(nodeidentity.Scope{ClusterID: grant.ClusterID, NodeID: "foreign-node", EnrollmentID: grant.EnrollmentID, KeyID: f.request.KeyID}, f.private)
	if err != nil {
		t.Fatal(err)
	}
	foreignBundle, err := nodeIssuer.Issue(foreignRequest, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	foreignIdentity, err := tls.X509KeyPair([]byte(foreignBundle.CertificatePEM+foreignBundle.NodeCAPEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: nodeKeyDER}))
	if err != nil {
		t.Fatal(err)
	}
	foreignClient, err := nodegateway.NewClient(nodeServer.URL, foreignIdentity, roots, gatewayPin)
	if err != nil {
		t.Fatal(err)
	}
	defer foreignClient.Close()
	foreign := batch
	foreign.Key.NodeID = "foreign-node"
	frame := residentFixtureFrame(t, profile, grant.Sources[0].SourceID, grant.ClusterID, "foreign-node", "foreign-record", f.now, 1)
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
	relayConfig.ControlURL = cloud.URL
	if _, err = f.store.RevokeEnrollment(ctx, f.request.ClusterID, f.request.EnrollmentID, 1, "synthetic-flow-operator"); err != nil {
		t.Fatal(err)
	}
	if _, err = gatewaytelemetry.RelayIdentity(ctx, relayConfig, token, request); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("revoked issuance replay admitted", err)
	}
	t.Log("synthetic roots with real CSR/token/relay/import and lost issuance response: NODE durability -> real pinned TLS1.3 gateway -> GATEWAY durability -> real collector mTLS/fingerprint -> CLOUD durability -> durable ownership transfer; both lost acknowledgements/restarts preserved exact receipts")
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

//go:build integration

package postgres_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/gatewaytelemetry"
	"github.com/verticalcomputer/sherlock/internal/nodegateway"
	"github.com/verticalcomputer/sherlock/internal/nodetelemetry"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetryjournal"
)

// This uses actual runtime objects, durable journals and both real TLS servers.
// PKI is synthetic and preconfigured; this is not a native binary/install test.
func TestTelemetryRetirementActualTLSRuntimeRecovery(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	caPEM, caKeyPEM := m15TestCA(t, time.Now())
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("synthetic CA")
	}
	gatewayKey, _ := m15CollectorCSR(t)
	gatewayIdentity := flowLeaf(t, caPEM, caKeyPEM, gatewayKey, nil, true)
	nodeCA, nodeCAKey := m15TestCA(t, time.Now())
	nodeRoots := x509.NewCertPool()
	if !nodeRoots.AppendCertsFromPEM(nodeCA) {
		t.Fatal("node CA")
	}
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
	drops := map[string]*atomic.Bool{}
	for _, path := range []string{"prepare", "commit", "complete"} {
		flag := &atomic.Bool{}
		flag.Store(true)
		drops["/collector/telemetry/v1/retirement/"+path] = flag
	}
	startCloud := func() (*httptest.Server, *collectorruntime.TelemetryClient) {
		t.Helper()
		transport, e := collectorcontrol.NewTransport(identities, control, control, control, control, platform.SystemClock{}, rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		if e = transport.ConfigureTelemetry(storepg.NewTelemetryStore(f.pool)); e != nil {
			t.Fatal(e)
		}
		server := httptest.NewUnstartedServer(retirementLostResponses(transport, drops))
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

	uri, err := nodegateway.NodeIdentityURI(grant.ClusterID, grant.NodeID, grant.EnrollmentID, f.request.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	nodeIdentity := flowLeaf(t, nodeCA, nodeCAKey, f.private, uri, false)
	root := t.TempDir()
	gatewayRoot := filepath.Join(root, "gateway")
	nodeRoot := filepath.Join(root, "node")
	gatewayClock := f.now.Add(time.Second)
	var gatewayQueue *telemetryjournal.Queue
	var nodeServer *httptest.Server
	var nodeClient *nodegateway.Client
	var gatewayRuntime *gatewaytelemetry.Runtime
	var nodeRuntime *nodetelemetry.Runtime
	bootID := "synthetic-retirement-boot"
	start := func() {
		t.Helper()
		authority, e := nodegateway.NewAuthority(grant.ClusterID, grant.GatewayCollectorID, gatewayPin, []string{grant.EnrollmentID}, cloudClient)
		if e != nil {
			t.Fatal(e)
		}
		admission, e := nodegateway.NewGatewayAdmission(authority)
		if e != nil {
			t.Fatal(e)
		}
		gatewayQueue, e = telemetryjournal.Open(gatewayRoot, telemetryjournal.Options{Role: telemetryjournal.Gateway, Scope: telemetryjournal.Scope{ClusterID: grant.ClusterID, NodeID: grant.NodeID, EnrollmentID: grant.EnrollmentID}, SourceIDs: []string{grant.Sources[0].SourceID}, PublicKeys: grant.Keys, Limits: telemetryjournal.GatewayLimits(), Verifier: admission, SessionVerifier: admission, ReleaseVerifier: admission, RequireSessions: true, Now: func() time.Time { return gatewayClock }})
		if e != nil {
			t.Fatal("gateway durable restart", e)
		}
		ingress, e := nodegateway.NewJournalIngress(map[string]*telemetryjournal.Queue{grant.EnrollmentID: gatewayQueue})
		if e != nil {
			t.Fatal(e)
		}
		handler, e := nodegateway.NewHandler(authority, ingress)
		if e != nil {
			t.Fatal(e)
		}
		nodeServer = httptest.NewUnstartedServer(handler)
		nodeServer.TLS = serverTLS.Clone()
		nodeServer.StartTLS()
		nodeClient, e = nodegateway.NewClient(nodeServer.URL, nodeIdentity, roots, gatewayPin)
		if e != nil {
			t.Fatal(e)
		}
		gatewayRuntime, e = gatewaytelemetry.New(map[string]gatewaytelemetry.Queue{grant.EnrollmentID: gatewayQueue}, cloudClient, nil)
		if e != nil {
			t.Fatal(e)
		}
		nodeRuntime, e = nodetelemetry.Open(ctx, nodetelemetry.Config{Root: nodeRoot, Scope: nodetelemetry.LocalScope{ClusterID: grant.ClusterID, NodeID: grant.NodeID, EnrollmentID: grant.EnrollmentID, InventoryRevisionID: grant.InventoryRevisionID, SourceIDs: []string{grant.Sources[0].SourceID}, AgentVersion: grant.AgentVersion, BuildSHA256: grant.BuildSHA256, GatewaySPKISHA256: grant.GatewaySPKISHA256, Keys: grant.Keys}, SigningKeyID: f.request.KeyID, SigningKey: f.private, Gateway: nodeClient, Interval: 30 * time.Second, Now: func() time.Time { return f.now }, BootID: func() (string, error) { return bootID, nil }})
		if e != nil {
			t.Fatal("node durable restart", e)
		}
	}
	stop := func() {
		t.Helper()
		if nodeRuntime != nil {
			if e := nodeRuntime.Close(); e != nil {
				t.Fatal(e)
			}
			nodeRuntime = nil
		}
		if nodeClient != nil {
			nodeClient.Close()
			nodeClient = nil
		}
		if nodeServer != nil {
			nodeServer.Close()
			nodeServer = nil
		}
		if gatewayQueue != nil {
			if e := gatewayQueue.Close(); e != nil {
				t.Fatal(e)
			}
			gatewayQueue = nil
		}
	}
	start()
	defer stop()
	if err = nodeRuntime.CollectOnce(ctx); err != nil {
		t.Fatal("first fixture allocation", err)
	}
	// Drive actual lifecycle/batch transfer before sealing a release.
	for i := 0; i < 12; i++ {
		if _, err = nodeRuntime.DrainOnce(ctx); err != nil {
			t.Fatal("node initial drain", err)
		}
		if _, err = gatewayRuntime.Pass(ctx); err != nil {
			t.Fatal("gateway initial drain", err)
		}
	}
	status, err := cloudClient.Status(ctx, grant.EnrollmentID)
	if err != nil || len(status.Receipts) != 1 {
		t.Fatal("initial cloud persistence", err, len(status.Receipts))
	}
	first := status.Receipts[0]
	ackAt := gatewayClock
	if first.StoredAt.After(ackAt) {
		ackAt = first.StoredAt
	}
	originals := map[string]json.RawMessage{}
	restarted := map[string]bool{}
	done := false
	for i := 0; i < 160; i++ {
		if _, err = nodeRuntime.RetireOnce(ctx); err != nil && !errors.Is(err, telemetry.ErrBackpressure) && !errors.Is(err, telemetry.ErrUnavailable) {
			t.Fatal("node retirement", i, err)
		}
		_, _ = gatewayRuntime.Pass(ctx) // lost cloud responses deliberately return unavailable
		for path, flag := range drops {
			if flag.Load() || restarted[path] {
				continue
			}
			column := "prepared_receipt"
			if path == "/collector/telemetry/v1/retirement/commit" {
				column = "final_receipt"
			}
			if path == "/collector/telemetry/v1/retirement/complete" {
				column = "completion_receipt"
			}
			var body []byte
			if err = f.pool.QueryRow(ctx, `SELECT `+column+` FROM gp06f_telemetry_retirements WHERE enrollment_id=$1`, grant.EnrollmentID).Scan(&body); err != nil {
				t.Fatal("lost response must retain committed phase", path, err)
			}
			originals[column] = append([]byte(nil), body...)
			restarted[path] = true
			stop()
			start()
		}
		records, more, e := gatewayQueue.PendingReleases(ctx, "", 8)
		if e != nil || more {
			t.Fatal("bounded release state", e)
		}
		var completed string
		if e = f.pool.QueryRow(ctx, `SELECT node_completed_through::text FROM gp06f_telemetry_sessions WHERE enrollment_id=$1`, grant.EnrollmentID).Scan(&completed); e != nil {
			t.Fatal(e)
		}
		if completed == "1" && len(records) == 0 && len(restarted) == 3 {
			done = true
			break
		}
	}
	if !done {
		t.Fatal("retirement failed to converge across all lost responses/restarts", len(restarted))
	}
	if _, err = nodeRuntime.RetireOnce(ctx); err != nil {
		t.Fatal("node receives final completion proof", err)
	}
	for column, want := range originals {
		var got []byte
		if err = f.pool.QueryRow(ctx, `SELECT `+column+` FROM gp06f_telemetry_retirements WHERE enrollment_id=$1`, grant.EnrollmentID).Scan(&got); err != nil {
			t.Fatal(err)
		}
		var a, b any
		if json.Unmarshal(want, &a) != nil || json.Unmarshal(got, &b) != nil || !reflect.DeepEqual(a, b) {
			t.Fatal("replay changed immutable phase", column)
		}
	}
	// Prefix completion does not finalize a live session or reset its allocator.
	if err = nodeRuntime.CollectOnce(ctx); err != nil {
		t.Fatal("continue active session", err)
	}
	for i := 0; i < 12; i++ {
		if _, err = nodeRuntime.DrainOnce(ctx); err != nil {
			t.Fatal("continued node drain", err)
		}
		if _, err = gatewayRuntime.Pass(ctx); err != nil {
			t.Fatal("continued gateway drain", err)
		}
	}
	status, err = cloudClient.Status(ctx, grant.EnrollmentID)
	if err != nil || len(status.Receipts) != 2 || len(status.Sessions) != 1 || status.Sessions[0].Finalized || status.Sessions[0].Retired {
		t.Fatal("active session continuity", err, status.Sessions)
	}
	found := false
	for _, r := range status.Receipts {
		if r.Key.Sequence == "2" && r.Key.SessionEpoch == first.Key.SessionEpoch && r.Key.SessionID == first.Key.SessionID {
			found = true
		}
	}
	if !found {
		t.Fatal("continuation reused or changed sequence/session")
	}
	// A new boot closes the prior allocator session. Its remaining live prefix
	// must complete before the gateway can compact that finalized session.
	bootID = "synthetic-retirement-next-boot"
	stop()
	start()
	for i := 0; i < 12; i++ {
		if _, err = nodeRuntime.DrainOnce(ctx); err != nil {
			t.Fatal("finalized node lifecycle", err)
		}
		if _, err = gatewayRuntime.Pass(ctx); err != nil {
			t.Fatal("finalized cloud lifecycle", err)
		}
	}
	messages, err := gatewayQueue.SessionMessages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	oldPresent := false
	for _, message := range messages {
		if message.SessionEpoch == first.Key.SessionEpoch {
			oldPresent = true
		}
	}
	if !oldPresent {
		t.Fatal("session compacted before remaining prefix completion")
	}
	compacted := false
	for i := 0; i < 120; i++ {
		if _, err = nodeRuntime.RetireOnce(ctx); err != nil && !errors.Is(err, telemetry.ErrBackpressure) && !errors.Is(err, telemetry.ErrUnavailable) {
			t.Fatal("finalized prefix retirement", err)
		}
		if _, err = gatewayRuntime.Pass(ctx); err != nil {
			t.Fatal("finalized gateway retirement", err)
		}
		messages, err = gatewayQueue.SessionMessages(ctx)
		if err != nil {
			t.Fatal(err)
		}
		oldPresent = false
		for _, message := range messages {
			if message.SessionEpoch == first.Key.SessionEpoch {
				oldPresent = true
			}
		}
		if !oldPresent {
			compacted = true
			break
		}
	}
	if !compacted {
		t.Fatal("gateway did not compact finalized node-completed session")
	}
	status, err = cloudClient.Status(ctx, grant.EnrollmentID)
	if err != nil {
		t.Fatal(err)
	}
	retired := false
	for _, session := range status.Sessions {
		if session.SessionEpoch == first.Key.SessionEpoch {
			retired = session.Retired
		}
	}
	if !retired {
		t.Fatal("cloud did not preserve exact retired session history")
	}
	// Local journal clock is controlled solely to qualify the exact seven-day
	// receipt retention boundary; PostgreSQL/source time is not advanced.
	gatewayClock = ackAt.Add(telemetry.ReleaseReceiptHorizon).Add(-time.Nanosecond)
	if n, e := gatewayQueue.PruneRetiredReceipts(ctx, gatewayClock, 128); e != nil || n != 0 {
		t.Fatal("receipt pruned before seven days", n, e)
	}
	gatewayClock = ackAt.Add(telemetry.ReleaseReceiptHorizon)
	if n, e := gatewayQueue.PruneRetiredReceipts(ctx, gatewayClock, 128); e != nil || n != 1 {
		t.Fatal("receipt not pruned at seven-day completed boundary", n, e)
	}
	ownership, e := gatewayQueue.LookupOwnership(ctx, first.Key)
	if e != nil || ownership.Disposition != telemetryjournal.OwnershipExpired || ownership.Entry != nil {
		t.Fatal("pruned receipt must have explicit expired disposition", ownership, e)
	}
	for _, table := range []string{"observations", "collection_runs", "current_projections"} {
		var n int
		if e = f.pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE cluster_id=$1`, f.request.ClusterID).Scan(&n); e != nil || n != 0 {
			t.Fatal("synthetic runtime produced ordinary health", table, n, e)
		}
	}
	t.Log("actual node/gateway runtimes + pinned node TLS + collector mTLS + PostgreSQL79: lost PREPARED, FINAL and completion responses survive durable restarts; live session continues; synthetic seven-day gateway receipt boundary is explicit")
}

func retirementLostResponses(handler http.Handler, drops map[string]*atomic.Bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if flag := drops[r.URL.Path]; flag != nil {
			flowLostResponse(handler, r.URL.Path, flag).ServeHTTP(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

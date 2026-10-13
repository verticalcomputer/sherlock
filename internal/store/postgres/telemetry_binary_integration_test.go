//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/gatewaytelemetry"
	"github.com/verticalcomputer/sherlock/internal/nodegateway"
	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
	"github.com/verticalcomputer/sherlock/internal/nodetelemetry"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

type binaryLog struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (l *binaryLog) Write(data []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.data.Write(data)
}
func (l *binaryLog) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.data.String() }

type fixtureProcess struct {
	cmd     *exec.Cmd
	done    chan error
	log     *binaryLog
	stopped bool
}

func startFixtureProcess(t *testing.T, path string, args ...string) *fixtureProcess {
	t.Helper()
	log := &binaryLog{}
	cmd := exec.Command(path, args...)
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		t.Fatal("fixture process start", err)
	}
	p := &fixtureProcess{cmd: cmd, done: make(chan error, 1), log: log}
	go func() { p.done <- cmd.Wait() }()
	t.Cleanup(func() {
		if !p.stopped {
			p.stop(t)
		}
	})
	return p
}
func (p *fixtureProcess) stop(t *testing.T) {
	t.Helper()
	if p.stopped {
		return
	}
	p.stopped = true
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-p.done:
		if err != nil {
			t.Errorf("fixture process stopped unexpectedly: %v; %s", err, p.log.String())
		}
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
		t.Error("fixture process did not join on cancellation")
	}
}
func (p *fixtureProcess) alive(t *testing.T) {
	t.Helper()
	select {
	case err := <-p.done:
		p.stopped = true
		t.Fatalf("fixture process exited: %v; %s", err, p.log.String())
	default:
	}
}

func protectedFixtureFile(t *testing.T, root, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
func fixtureJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func fixturePrivatePEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// Actual host binaries run a declared synthetic boot/source. This is repository
// transport/persistence proof, not Linux hardware, workload overhead or install
// qualification. All PKI/files/processes belong only to this disposable fixture.
func TestTelemetryActualBinariesCSRAndOutageRestart(t *testing.T) {
	f, _, nodeIssuer := nodeBootstrapFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	root := t.TempDir()
	nodeBinary := filepath.Join(root, "sherlock-node-agent")
	gatewayBinary := filepath.Join(root, "sherlock-gateway")
	for _, build := range []struct{ path, pkg string }{{nodeBinary, "./cmd/sherlock-node-agent"}, {gatewayBinary, "./cmd/sherlock-gateway"}} {
		cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", build.path, build.pkg)
		cmd.Dir = "../../.."
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture binary build: %v; %s", err, output)
		}
	}
	// Three distinct trust roots: collector/cloud, gateway server, node client.
	collectorCA, collectorCAKey := m15TestCA(t, time.Now())
	gatewayCA, gatewayCAKey := m15TestCA(t, time.Now())
	collectorRoots := x509.NewCertPool()
	collectorRoots.AppendCertsFromPEM(collectorCA)
	gatewayRoots := x509.NewCertPool()
	gatewayRoots.AppendCertsFromPEM(gatewayCA)
	serverKey, _ := m15CollectorCSR(t)
	gatewayIdentity := flowLeaf(t, gatewayCA, gatewayCAKey, serverKey, nil, true)
	nodeRoots := x509.NewCertPool()
	nodeCAPEM := []byte(nodeIssuerCA(t, nodeIssuer, f))
	nodeRoots.AppendCertsFromPEM(nodeCAPEM)
	_, gatewayPin, err := nodegateway.ServerTLSConfig(gatewayIdentity, nodeRoots)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.RevokeEnrollment(ctx, f.request.ClusterID, f.request.EnrollmentID, 1, "synthetic-binary-operator"); err != nil {
		t.Fatal(err)
	}
	f.request.EnrollmentID += "-binary"
	f.request.GatewaySPKISHA256 = gatewayPin
	nodeIdentityDir := filepath.Join(root, "node-identity")
	requestCmd := exec.CommandContext(ctx, nodeBinary, "identity-request", "--directory", nodeIdentityDir, "--cluster", string(f.request.ClusterID), "--node", string(f.request.NodeID), "--enrollment", f.request.EnrollmentID, "--key", f.request.KeyID)
	requestBytes, err := requestCmd.Output()
	if err != nil {
		t.Fatal("node binary identity request", err)
	}
	var request nodeidentity.Request
	if err = json.Unmarshal(requestBytes, &request); err != nil {
		t.Fatal(err)
	}
	if _, err = nodeidentity.ValidateRequest(request); err != nil {
		t.Fatal(err)
	}
	f.request.PublicKeyBase64 = request.PublicKeyBase64
	grant, err := f.store.CreateEnrollment(ctx, f.request, 0, "synthetic-binary-operator")
	if err != nil {
		t.Fatal(err)
	}
	control, err := storepg.NewCollectorControlStore(f.pool)
	if err != nil {
		t.Fatal(err)
	}
	collectorIssuer, err := collectorcontrol.NewCAIssuer(collectorCA, collectorCAKey, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := collectorcontrol.NewIdentityService(control, collectorIssuer, platform.SystemClock{}, platform.RandomIDGenerator{}, rand.Reader, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE collectors SET identity_serial=$2 WHERE collector_id=$1`, f.request.GatewayCollectorID, "synthetic-binary-placeholder")
	collectorKey, csr := m15CollectorCSR(t)
	issued, err := identities.Renew(ctx, f.request.GatewayCollectorID, csr)
	if err != nil {
		t.Fatal(err)
	}
	collectorIdentity, err := tls.X509KeyPair(issued.CertificatePEM, fixturePrivatePEM(t, collectorKey))
	if err != nil {
		t.Fatal(err)
	}
	transport, err := collectorcontrol.NewTransport(identities, control, control, control, control, platform.SystemClock{}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = transport.ConfigureTelemetry(f.store); err != nil {
		t.Fatal(err)
	}
	if err = transport.ConfigureNodeIdentity(f.store, nodeIssuer); err != nil {
		t.Fatal(err)
	}
	var outage atomic.Bool
	var blockedSequence atomic.Int64
	cloudKey, _ := m15CollectorCSR(t)
	cloudIdentity := flowLeaf(t, collectorCA, collectorCAKey, cloudKey, nil, true)
	cloud := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if outage.Load() && r.URL.Path == "/collector/telemetry/v1/batches" {
			body, _ := io.ReadAll(io.LimitReader(r.Body, telemetry.MaxBatchBytes+1))
			var envelope telemetry.CloudBatchEnvelope
			if telemetry.DecodeStrictJSON(body, "", &envelope) == nil && envelope.Batch.Key.EnrollmentID == grant.EnrollmentID {
				if sequence, e := strconv.ParseInt(envelope.Batch.Key.Sequence, 10, 64); e == nil {
					blockedSequence.Store(sequence)
				}
			}
			http.Error(w, "fixture cloud unavailable", http.StatusServiceUnavailable)
			return
		}
		transport.ServeHTTP(w, r)
	}))
	cloud.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: collectorRoots, Certificates: []tls.Certificate{cloudIdentity}}
	cloud.StartTLS()
	defer cloud.Close()
	cloudPin := sha256.Sum256(cloud.Certificate().RawSubjectPublicKeyInfo)
	httpTransport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: collectorRoots, Certificates: []tls.Certificate{collectorIdentity}, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo) != cloudPin {
			return fmt.Errorf("fixture cloud pin mismatch")
		}
		return nil
	}}}
	defer httpTransport.CloseIdleConnections()
	protocol, err := collectorruntime.NewHTTPClient(cloud.URL, &http.Client{Transport: httpTransport, Timeout: 3 * time.Second}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cloudClient, err := collectorruntime.NewTelemetryClient(protocol, string(f.request.ClusterID), string(f.request.GatewayCollectorID))
	if err != nil {
		t.Fatal(err)
	}
	token, err := f.store.MintNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, 1, "synthetic-binary-operator")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := cloudClient.IssueNodeCertificate(ctx, token, request)
	if err != nil {
		t.Fatal("authenticated CSR relay", err)
	}
	bundlePath := protectedFixtureFile(t, root, "node-bundle.json", fixtureJSON(t, bundle))
	importCmd := exec.CommandContext(ctx, nodeBinary, "identity-import", "--directory", nodeIdentityDir, "--bundle", bundlePath, "--node-ca-sha256", nodeIssuer.NodeCAFingerprint())
	if output, err := importCmd.CombinedOutput(); err != nil {
		t.Fatalf("node binary identity import: %v; %s", err, output)
	}
	if _, _, err = nodeidentity.LoadIdentity(nodeIdentityDir, nodeIssuer.NodeCAFingerprint(), time.Now()); err != nil {
		t.Fatal("independently approved node CA import", err)
	}
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listen.Addr().String()
	_ = listen.Close()
	gatewayConfig := gatewaytelemetry.ServiceConfig{ProtocolVersion: 1, FixtureOnly: true, ClusterID: grant.ClusterID, CollectorID: grant.GatewayCollectorID, EnrollmentIDs: []string{grant.EnrollmentID}, Root: filepath.Join(root, "gateway-spool"), ListenAddress: address, ServerCertificateFile: protectedFixtureFile(t, root, "gateway-cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: gatewayIdentity.Certificate[0]})), ServerKeyFile: protectedFixtureFile(t, root, "gateway-key.pem", fixturePrivatePEM(t, serverKey)), NodeCAFile: protectedFixtureFile(t, root, "node-ca.pem", nodeCAPEM), ControlURL: cloud.URL, ControlCAFile: protectedFixtureFile(t, root, "control-ca.pem", collectorCA), ControlSPKISHA256: hex.EncodeToString(cloudPin[:]), CollectorCertificateFile: protectedFixtureFile(t, root, "collector-cert.pem", issued.CertificatePEM), CollectorKeyFile: protectedFixtureFile(t, root, "collector-key.pem", fixturePrivatePEM(t, collectorKey)), AuthMode: "direct_mtls"}
	gatewayConfigPath := protectedFixtureFile(t, root, "gateway.json", fixtureJSON(t, gatewayConfig))
	nodeConfig := map[string]any{"root": filepath.Join(root, "node-spool"), "scope": nodetelemetry.LocalScope{ClusterID: grant.ClusterID, NodeID: grant.NodeID, EnrollmentID: grant.EnrollmentID, InventoryRevisionID: grant.InventoryRevisionID, SourceIDs: []string{grant.Sources[0].SourceID}, AgentVersion: grant.AgentVersion, BuildSHA256: grant.BuildSHA256, GatewaySPKISHA256: grant.GatewaySPKISHA256, Keys: grant.Keys}, "signing_key_id": f.request.KeyID, "gateway_url": "https://" + address, "identity_dir": nodeIdentityDir, "node_ca_sha256": nodeIssuer.NodeCAFingerprint(), "gateway_ca_file": protectedFixtureFile(t, root, "gateway-ca.pem", gatewayCA), "interval_seconds": 10, "fixture_boot_id": "declared-synthetic-boot"}
	nodeConfigPath := protectedFixtureFile(t, root, "node.json", fixtureJSON(t, nodeConfig))
	gateway := startFixtureProcess(t, gatewayBinary, "--fixture", "--config", gatewayConfigPath)
	waitBinaryCondition(t, ctx, 5*time.Second, func() bool {
		gateway.alive(t)
		connection, e := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if e == nil {
			connection.Close()
			return true
		}
		return false
	}, "gateway listener")
	node := startFixtureProcess(t, nodeBinary, "--fixture", "--config", nodeConfigPath)
	count := func() int {
		var n int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM gp06f_telemetry_batches WHERE enrollment_id=$1`, grant.EnrollmentID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	waitBinaryCondition(t, ctx, 20*time.Second, func() bool { gateway.alive(t); node.alive(t); return count() >= 2 }, "two actual binary batches")
	node.stop(t)
	before := count()
	var sessionID string
	var epoch string
	if err = f.pool.QueryRow(ctx, `SELECT session_id,session_epoch::text FROM gp06f_telemetry_sessions WHERE enrollment_id=$1`, grant.EnrollmentID).Scan(&sessionID, &epoch); err != nil || epoch != "1" {
		t.Fatal("initial durable session", err)
	}
	outage.Store(true)
	node = startFixtureProcess(t, nodeBinary, "--fixture", "--config", nodeConfigPath)
	waitBinaryCondition(t, ctx, 6*time.Second, func() bool { gateway.alive(t); node.alive(t); return blockedSequence.Load() > int64(before) }, "gateway owned batch attempted during cloud outage")
	node.stop(t)
	gateway.stop(t)
	if count() != before {
		t.Fatal("unavailable cloud admitted fixture batch")
	}
	outage.Store(false)
	gateway = startFixtureProcess(t, gatewayBinary, "--fixture", "--config", gatewayConfigPath)
	waitBinaryCondition(t, ctx, 8*time.Second, func() bool { gateway.alive(t); return count() > before }, "gateway restart recovered owned batch with node stopped")
	ownedCount := count()
	node = startFixtureProcess(t, nodeBinary, "--fixture", "--config", nodeConfigPath)
	waitBinaryCondition(t, ctx, 8*time.Second, func() bool { gateway.alive(t); node.alive(t); return count() > ownedCount }, "node restart continued durable allocation")
	node.stop(t)
	gateway.stop(t)
	var sessions, total, distinctSequences int
	var maxSequence string
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM gp06f_telemetry_sessions WHERE enrollment_id=$1 AND session_id=$2 AND session_epoch=1 AND boot_id='declared-synthetic-boot'`, grant.EnrollmentID, sessionID).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatal("restart changed boot/session", err)
	}
	if err = f.pool.QueryRow(ctx, `SELECT count(*),count(DISTINCT sequence),max(sequence)::text FROM gp06f_telemetry_batches WHERE enrollment_id=$1 AND session_id=$2 AND session_epoch=1`, grant.EnrollmentID, sessionID).Scan(&total, &distinctSequences, &maxSequence); err != nil || total != distinctSequences || fmt.Sprint(total) != maxSequence || total < 4 {
		t.Fatal("allocation not monotonic/contiguous", err, total, maxSequence)
	}
	for _, table := range []string{"observations", "collection_runs", "current_projections"} {
		var n int
		if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE cluster_id=$1`, f.request.ClusterID).Scan(&n); err != nil || n != 0 {
			t.Fatal("synthetic binary data leaked to health", table, err)
		}
	}
}

func waitBinaryCondition(t *testing.T, ctx context.Context, timeout time.Duration, condition func() bool, description string) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("fixture canceled waiting for", description)
		case <-deadline.C:
			t.Fatal("fixture timed out waiting for", description)
		case <-ticker.C:
		}
	}
}

// Obtain only the public CA from a candidate certificate; no issuer key reaches
// gateway/node files. The independently supplied fingerprint verifies it later.
func nodeIssuerCA(t *testing.T, issuer *nodeidentity.Issuer, f *telemetryFixture) string {
	t.Helper()
	request, err := nodeidentity.NewRequest(nodeidentity.Scope{ClusterID: string(f.request.ClusterID), NodeID: string(f.request.NodeID), EnrollmentID: f.request.EnrollmentID, KeyID: f.request.KeyID}, f.private)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := issuer.Issue(request, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return bundle.NodeCAPEM
}

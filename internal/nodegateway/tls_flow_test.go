package nodegateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

type flowCA struct {
	certificate *x509.Certificate
	key         ed25519.PrivateKey
	pool        *x509.CertPool
}

func newFlowCA(t *testing.T, serial int64) flowCA {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "fixture CA"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return flowCA{certificate, key, pool}
}

func issueFlowCertificate(t *testing.T, ca flowCA, serial int64, key ed25519.PrivateKey, principal *Principal) tls.Certificate {
	t.Helper()
	at := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "fixture identity"}, NotBefore: at.Add(-time.Minute), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if principal == nil {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		template.DNSNames = []string{"localhost"}
	} else {
		uri, err := NodeIdentityURI(principal.ClusterID, principal.NodeID, principal.EnrollmentID, principal.KeyID)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = append(template.URIs, uri)
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// flowIngress is intentionally an in-memory transport seam. It checks that
// verified original identities reach a known session, but proves no durability,
// crash recovery, journal capacity, cloud persistence or agent installation.
type flowIngress struct {
	mu       sync.Mutex
	sessions map[string]telemetry.SessionMessage
	states   map[string]string
	err      error
	calls    atomic.Int32
	entered  chan string
	release  chan struct{}
}

func flowSessionKey(cluster, node, enrollment, epoch, id string) string {
	return strings.Join([]string{cluster, node, enrollment, epoch, id}, "/")
}
func (f *flowIngress) RegisterSession(ctx context.Context, m telemetry.SessionMessage) (telemetry.SessionReceipt, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return telemetry.SessionReceipt{}, f.err
	}
	key := flowSessionKey(m.ClusterID, m.NodeID, m.EnrollmentID, m.SessionEpoch, m.SessionID)
	prior, known := f.sessions[key]
	if known {
		if prior.BootID != m.BootID || m.Kind == "OPEN" && prior.SigningKeyID != m.SigningKeyID {
			return telemetry.SessionReceipt{}, telemetry.ErrUnauthorized
		}
	} else {
		if m.Kind != "OPEN" || f.states[m.SigningKeyID] != "ACTIVE" {
			return telemetry.SessionReceipt{}, telemetry.ErrUnauthorized
		}
		f.sessions[key] = m
	}
	return telemetry.SessionReceipt{ProtocolVersion: 1, ID: "gateway-session-receipt", ClusterID: m.ClusterID, NodeID: m.NodeID, EnrollmentID: m.EnrollmentID, EnrollmentRevision: m.EnrollmentRevision, SessionEpoch: m.SessionEpoch, SessionID: m.SessionID, BootID: m.BootID, Kind: m.Kind, Digest: m.Digest, StoredAt: time.Now().UTC(), Durability: "GATEWAY"}, nil
}
func (f *flowIngress) Accept(ctx context.Context, b telemetry.NodeBatch, wire []byte) (telemetry.Receipt, error) {
	f.calls.Add(1)
	f.mu.Lock()
	err := f.err
	prior, known := f.sessions[flowSessionKey(b.Key.ClusterID, b.Key.NodeID, b.Key.EnrollmentID, b.Key.SessionEpoch, b.Key.SessionID)]
	f.mu.Unlock()
	if err != nil {
		return telemetry.Receipt{}, err
	}
	if !known || prior.BootID != b.BootID || prior.SigningKeyID != b.SigningKeyID {
		return telemetry.Receipt{}, telemetry.ErrUnauthorized
	}
	if f.entered != nil {
		select {
		case f.entered <- b.Key.EnrollmentID:
		case <-ctx.Done():
			return telemetry.Receipt{}, ctx.Err()
		}
		select {
		case <-f.release:
		case <-ctx.Done():
			return telemetry.Receipt{}, ctx.Err()
		}
	}
	return telemetry.Receipt{ProtocolVersion: 1, ID: "gateway-batch-receipt", Key: b.Key, Digest: b.Digest, StoredAt: time.Now().UTC(), Durability: "GATEWAY"}, nil
}

type tlsFlow struct {
	server           *httptest.Server
	serverCA, nodeCA flowCA
	serverIdentity   tls.Certificate
	nodeKey          ed25519.PrivateKey
	identity         tls.Certificate
	grant            telemetry.Grant
	ingress          *flowIngress
	pin              string
	version          atomic.Uint32
	replyMode        atomic.Int32
}

func newTLSFlow(t *testing.T) *tlsFlow {
	t.Helper()
	f := &tlsFlow{serverCA: newFlowCA(t, 1), nodeCA: newFlowCA(t, 2)}
	_, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.serverIdentity = issueFlowCertificate(t, f.serverCA, 3, serverKey, nil)
	config, pin, err := ServerTLSConfig(f.serverIdentity, f.nodeCA.pool)
	if err != nil {
		t.Fatal(err)
	}
	f.pin = pin
	pub, nodeKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.nodeKey = nodeKey
	f.grant, _ = authFixture(t, time.Now())
	f.grant.GatewaySPKISHA256 = pin
	f.grant.Keys[0].PublicKeyBase64 = base64.RawStdEncoding.EncodeToString(pub)
	p := Principal{f.grant.ClusterID, f.grant.NodeID, f.grant.EnrollmentID, f.grant.Keys[0].ID}
	f.identity = issueFlowCertificate(t, f.nodeCA, 4, nodeKey, &p)
	f.ingress = &flowIngress{sessions: map[string]telemetry.SessionMessage{}, states: map[string]string{"key-a": "ACTIVE"}}
	a, err := NewAuthority(f.grant.ClusterID, f.grant.GatewayCollectorID, pin, []string{f.grant.EnrollmentID}, loaderFunc(func(context.Context, string) (telemetry.Grant, error) { return f.grant, nil }))
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(a, f.ingress)
	if err != nil {
		t.Fatal(err)
	}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			f.version.Store(uint32(r.TLS.Version))
		}
		if mode := f.replyMode.Load(); mode != 0 {
			response := httptest.NewRecorder()
			h.ServeHTTP(response, r)
			if response.Code == 200 {
				if mode == 1 && strings.HasSuffix(r.URL.Path, "sessions") {
					var receipt telemetry.SessionReceipt
					if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil {
						t.Error(err)
					}
					receipt.Digest = strings.Repeat("0", 64)
					respond(w, receipt)
					return
				}
				if mode == 2 && strings.HasSuffix(r.URL.Path, "batches") {
					var receipt telemetry.Receipt
					if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil {
						t.Error(err)
					}
					receipt.Key.Sequence = "999"
					respond(w, receipt)
					return
				}
			}
			for key, values := range response.Header() {
				w.Header()[key] = values
			}
			w.WriteHeader(response.Code)
			_, _ = w.Write(response.Body.Bytes())
			return
		}
		h.ServeHTTP(w, r)
	}))
	f.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.server.TLS = config
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	return f
}

func (f *tlsFlow) signed(t *testing.T) (telemetry.SessionMessage, telemetry.NodeBatch, []byte) {
	t.Helper()
	at := time.Now().UTC()
	g := f.grant
	m := telemetry.SessionMessage{ProtocolVersion: 1, Kind: "OPEN", ClusterID: g.ClusterID, NodeID: g.NodeID, EnrollmentID: g.EnrollmentID, EnrollmentRevision: 1, SessionEpoch: "1", SessionID: "session-a", BootID: "boot-a", SigningKeyID: "key-a", CreatedAt: at}
	if err := telemetry.SignSessionMessage(&m, f.nodeKey); err != nil {
		t.Fatal(err)
	}
	frame, err := telemetry.NewFixtureFrame(g.Sources[0].SourceID, g.ClusterID, g.NodeID, "fixture", at, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	b := telemetry.NodeBatch{ProtocolVersion: 1, Key: telemetry.BatchKey{ClusterID: g.ClusterID, NodeID: g.NodeID, EnrollmentID: g.EnrollmentID, SessionEpoch: m.SessionEpoch, SessionID: m.SessionID, Sequence: "1"}, EnrollmentRevision: 1, InventoryRevisionID: g.InventoryRevisionID, BootID: m.BootID, SigningKeyID: m.SigningKeyID, AgentVersion: g.AgentVersion, BuildSHA256: g.BuildSHA256, CreatedAt: at, Sources: []telemetry.SourceFrame{frame}}
	if err := telemetry.SignBatch(&b, f.nodeKey); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return m, b, wire
}

func TestTLS13MTLSFixtureSessionAndBatchFlow(t *testing.T) {
	f := newTLSFlow(t)
	client, err := NewClient(f.server.URL, f.identity, f.serverCA.pool, f.pin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	m, b, wire := f.signed(t)
	session, err := client.RegisterSession(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := client.SubmitBatch(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	if f.version.Load() != tls.VersionTLS13 || session.Digest != m.Digest || receipt.Digest != b.Digest || receipt.Key != b.Key || receipt.Durability != "GATEWAY" || f.ingress.calls.Load() != 2 {
		t.Fatal("real TLS or identity/receipt binding failed")
	}
}

func TestTLSRejectsWrongCAWrongPinAndNoClientCertificate(t *testing.T) {
	f := newTLSFlow(t)
	_, _, wire := f.signed(t)
	for _, test := range []struct {
		name string
		pool *x509.CertPool
		pin  string
	}{{"wrong-ca", newFlowCA(t, 10).pool, f.pin}, {"wrong-pin", f.serverCA.pool, strings.Repeat("f", 64)}} {
		t.Run(test.name, func(t *testing.T) {
			c, err := NewClient(f.server.URL, f.identity, test.pool, test.pin)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_, err = c.SubmitBatch(context.Background(), wire)
			if !errors.Is(err, telemetry.ErrUnavailable) || strings.Contains(err.Error(), f.server.URL) {
				t.Fatal("untrusted gateway accepted or endpoint leaked", err)
			}
		})
	}
	for _, config := range []*tls.Config{{MinVersion: tls.VersionTLS13, RootCAs: f.serverCA.pool}, {MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, RootCAs: f.serverCA.pool, Certificates: []tls.Certificate{f.identity}}} {
		transport := &http.Transport{TLSClientConfig: config}
		c := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		request, _ := http.NewRequest(http.MethodPost, f.server.URL+"/node-telemetry/v1/batches", bytes.NewReader(wire))
		response, err := c.Do(request)
		if response != nil {
			response.Body.Close()
		}
		transport.CloseIdleConnections()
		if err == nil {
			t.Fatal("missing client certificate or old TLS version accepted")
		}
	}
	if f.ingress.calls.Load() != 0 {
		t.Fatal("TLS failures reached ingress")
	}
}

func TestTLSRejectsForeignNodeAndCertificateKeyBeforeIngress(t *testing.T) {
	f := newTLSFlow(t)
	_, _, wire := f.signed(t)
	foreignPub, foreignKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = foreignPub
	for _, test := range []struct {
		name, node string
		key        ed25519.PrivateKey
	}{{"foreign-node", "node-b", f.nodeKey}, {"foreign-certificate-key", f.grant.NodeID, foreignKey}} {
		t.Run(test.name, func(t *testing.T) {
			p := Principal{f.grant.ClusterID, test.node, f.grant.EnrollmentID, "key-a"}
			cert := issueFlowCertificate(t, f.nodeCA, 20, test.key, &p)
			transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.serverCA.pool, Certificates: []tls.Certificate{cert}}}
			defer transport.CloseIdleConnections()
			c := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			r, _ := http.NewRequest(http.MethodPost, f.server.URL+"/node-telemetry/v1/batches", bytes.NewReader(wire))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Sherlock-Telemetry-Version", "1")
			response, err := c.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusForbidden {
				t.Fatal("foreign verified certificate accepted", response.StatusCode)
			}
		})
	}
	if f.ingress.calls.Load() != 0 {
		t.Fatal("foreign identity reached ingress")
	}
}

func TestTLSActiveCertificateReplaysExactKnownOldSignature(t *testing.T) {
	f := newTLSFlow(t)
	m, b, wire := f.signed(t)
	f.ingress.sessions[flowSessionKey(m.ClusterID, m.NodeID, m.EnrollmentID, m.SessionEpoch, m.SessionID)] = m
	f.ingress.states["key-a"] = "VERIFY_ONLY"
	pub, newKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.grant.Keys[0].State = "VERIFY_ONLY"
	f.grant.Keys = append(f.grant.Keys, telemetry.NodeKey{ID: "key-b", Epoch: "2", PublicKeyBase64: base64.RawStdEncoding.EncodeToString(pub), State: "ACTIVE"})
	f.ingress.states["key-b"] = "ACTIVE"
	p := Principal{f.grant.ClusterID, f.grant.NodeID, f.grant.EnrollmentID, "key-b"}
	identity := issueFlowCertificate(t, f.nodeCA, 30, newKey, &p)
	client, err := NewClientWithSigningKeys(f.server.URL, identity, f.serverCA.pool, f.pin, f.grant.Keys)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.RegisterSession(context.Background(), m); err != nil {
		t.Fatal("known old OPEN replay rejected under active TLS certificate", err)
	}
	if _, err := client.SubmitBatch(context.Background(), wire); err != nil {
		t.Fatal("old sealed batch replay rejected under active TLS certificate", err)
	}
	unknown := m
	unknown.SessionEpoch = "2"
	unknown.SessionID = "unregistered"
	unknown.BootID = "boot-b"
	if err := telemetry.SignSessionMessage(&unknown, f.nodeKey); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RegisterSession(context.Background(), unknown); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("verify-only key opened a new session", err)
	}
	_, foreignKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := b
	if err := telemetry.SignBatch(&forged, foreignKey); err != nil {
		t.Fatal(err)
	}
	forgedWire, _ := json.Marshal(forged)
	configured := append([]telemetry.NodeKey(nil), f.grant.Keys...)
	configured[0].PublicKeyBase64 = base64.RawStdEncoding.EncodeToString(foreignKey.Public().(ed25519.PublicKey))
	foreignClient, err := NewClientWithSigningKeys(f.server.URL, identity, f.serverCA.pool, f.pin, configured)
	if err != nil {
		t.Fatal(err)
	}
	defer foreignClient.Close()
	before := f.ingress.calls.Load()
	if _, err := foreignClient.SubmitBatch(context.Background(), forgedWire); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("client-local foreign old key gained gateway authority", err)
	}
	if f.ingress.calls.Load() != before {
		t.Fatal("foreign old signature reached ingress")
	}
}

func TestTLSIngressFailureIsClosedAndRedacted(t *testing.T) {
	f := newTLSFlow(t)
	m, _, wire := f.signed(t)
	f.ingress.sessions[flowSessionKey(m.ClusterID, m.NodeID, m.EnrollmentID, m.SessionEpoch, m.SessionID)] = m
	f.ingress.err = errors.New("private SQL /secret/node/key.pem payload=private")
	client, err := NewClient(f.server.URL, f.identity, f.serverCA.pool, f.pin)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.SubmitBatch(context.Background(), wire)
	if !errors.Is(err, telemetry.ErrUnavailable) || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "secret") {
		t.Fatal("backend failure acknowledged or leaked private detail", err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.serverCA.pool, Certificates: []tls.Certificate{f.identity}}}
	defer transport.CloseIdleConnections()
	raw := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request, _ := http.NewRequest(http.MethodPost, f.server.URL+"/node-telemetry/v1/batches", bytes.NewReader(wire))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Sherlock-Telemetry-Version", "1")
	response, err := raw.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil || response.StatusCode != 503 || bytes.Contains(body, []byte("private")) || bytes.Contains(body, []byte("secret")) || bytes.Contains(body, []byte("SQL")) {
		t.Fatal("HTTP error body exposed backend details", response.StatusCode, string(body), err)
	}
}

func TestTLSClientRejectsWrongSessionAndBatchReceiptBinding(t *testing.T) {
	f := newTLSFlow(t)
	client, err := NewClient(f.server.URL, f.identity, f.serverCA.pool, f.pin)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	m, _, wire := f.signed(t)
	f.replyMode.Store(1)
	if _, err := client.RegisterSession(context.Background(), m); !errors.Is(err, telemetry.ErrConflict) {
		t.Fatal("client accepted mismatched session receipt over trusted TLS", err)
	}
	f.replyMode.Store(2)
	if _, err := client.SubmitBatch(context.Background(), wire); !errors.Is(err, telemetry.ErrConflict) {
		t.Fatal("client accepted foreign batch receipt over trusted TLS", err)
	}
}

func TestTLSHandlerCapsFourGlobalAndOnePerEnrollment(t *testing.T) {
	f := newTLSFlow(t)
	grants := map[string]telemetry.Grant{}
	var identities []tls.Certificate
	var wires [][]byte
	var enrollmentIDs []string
	for i := 0; i < 5; i++ {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		g := f.grant
		g.EnrollmentID = fmt.Sprintf("enrollment-%d", i)
		g.NodeID = fmt.Sprintf("node-%d", i)
		g.Keys = []telemetry.NodeKey{{ID: "key-a", Epoch: "1", PublicKeyBase64: base64.RawStdEncoding.EncodeToString(pub), State: "ACTIVE"}}
		grants[g.EnrollmentID] = g
		enrollmentIDs = append(enrollmentIDs, g.EnrollmentID)
		p := Principal{g.ClusterID, g.NodeID, g.EnrollmentID, "key-a"}
		identities = append(identities, issueFlowCertificate(t, f.nodeCA, int64(50+i), key, &p))
		fixture := &tlsFlow{grant: g, nodeKey: key}
		m, _, wire := fixture.signed(t)
		f.ingress.sessions[flowSessionKey(m.ClusterID, m.NodeID, m.EnrollmentID, m.SessionEpoch, m.SessionID)] = m
		wires = append(wires, wire)
	}
	f.ingress.entered = make(chan string, 4)
	f.ingress.release = make(chan struct{})
	var release sync.Once
	unblock := func() { release.Do(func() { close(f.ingress.release) }) }
	a, err := NewAuthority(f.grant.ClusterID, f.grant.GatewayCollectorID, f.pin, enrollmentIDs, loaderFunc(func(_ context.Context, id string) (telemetry.Grant, error) { return grants[id], nil }))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(a, f.ingress)
	if err != nil {
		t.Fatal(err)
	}
	config, _, err := ServerTLSConfig(f.serverIdentity, f.nodeCA.pool)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = config
	server.StartTLS()
	t.Cleanup(server.Close)
	t.Cleanup(unblock)
	clients := make([]*Client, 5)
	for i := range clients {
		clients[i], err = NewClient(server.URL, identities[i], f.serverCA.pool, f.pin)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(clients[i].Close)
	}
	done := make(chan error, 4)
	var workers sync.WaitGroup
	start := func(i int) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, err := clients[i].SubmitBatch(context.Background(), wires[i])
			done <- err
		}()
	}
	waitEntered := func() {
		t.Helper()
		select {
		case <-f.ingress.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("request did not reach blocking ingress")
		}
	}
	start(0)
	waitEntered()
	duplicate, err := NewClient(server.URL, identities[0], f.serverCA.pool, f.pin)
	if err != nil {
		t.Fatal(err)
	}
	defer duplicate.Close()
	if _, err := duplicate.SubmitBatch(context.Background(), wires[0]); !errors.Is(err, telemetry.ErrBackpressure) {
		t.Fatal("same-enrollment second inflight admitted", err)
	}
	for i := 1; i < 4; i++ {
		start(i)
		waitEntered()
	}
	if _, err := clients[4].SubmitBatch(context.Background(), wires[4]); !errors.Is(err, telemetry.ErrBackpressure) {
		t.Fatal("fifth global inflight admitted", err)
	}
	unblock()
	workers.Wait()
	close(done)
	for err := range done {
		if err != nil {
			t.Fatal("admitted bounded request failed after release", err)
		}
	}
	if f.ingress.calls.Load() != 4 {
		t.Fatal("backpressured requests reached ingress", f.ingress.calls.Load())
	}
}

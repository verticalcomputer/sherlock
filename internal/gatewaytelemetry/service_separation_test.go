package gatewaytelemetry

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func serviceSeparationKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func serviceSeparationCert(t *testing.T, serial int64, ca bool, name string, key ed25519.PrivateKey, parent *x509.Certificate, signer ed25519.PrivateKey) *x509.Certificate {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	if parent == nil {
		parent = template
		signer = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
func TestCloudTransportRejectsNodeAuthorityInVerifiedPeerChain(t *testing.T) {
	rootKey, nodeKey, serverKey, clientKey := serviceSeparationKey(t), serviceSeparationKey(t), serviceSeparationKey(t), serviceSeparationKey(t)
	root := serviceSeparationCert(t, 1, true, "Synthetic collector root", rootKey, nil, nil)
	node := serviceSeparationCert(t, 2, true, "Synthetic node root", nodeKey, nil, nil)
	cross := serviceSeparationCert(t, 3, true, "Synthetic node root", nodeKey, root, rootKey)
	serverCert := serviceSeparationCert(t, 4, false, "Synthetic control server", serverKey, cross, nodeKey)
	clientCert := serviceSeparationCert(t, 5, false, "Synthetic collector", clientKey, root, rootKey)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{serverCert.Raw, cross.Raw}, PrivateKey: serverKey}}}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	dir := t.TempDir()
	write := func(name string, body []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	certPEM := func(cert *x509.Certificate) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(serverCert.RawSubjectPublicKeyInfo)
	cfg := ServiceConfig{ClusterID: "cluster-a", CollectorID: "gateway-a", ControlURL: server.URL, ControlCAFile: write("control-ca.pem", certPEM(root)), ControlSPKISHA256: hex.EncodeToString(pin[:]), CollectorCertificateFile: write("collector.pem", certPEM(clientCert)), CollectorKeyFile: write("collector-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), AuthMode: "direct_mtls"}
	// Prove this synthetic server satisfies ordinary trust and the exact SPKI pin.
	_, normal, _, err := cloudTransport(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer normal.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := normal.RoundTrip(req)
	if err != nil {
		t.Fatalf("normal verification should pass: %v", err)
	}
	response.Body.Close()
	_, separated, _, err := cloudTransport(cfg, node)
	if err != nil {
		t.Fatal(err)
	}
	defer separated.CloseIdleConnections()
	if response, err = separated.RoundTrip(req); err == nil {
		response.Body.Close()
		t.Fatal("node authority accepted as control peer")
	}
	// Configured identity chains are checked beyond their leaf too.
	if separateNodeCA(tls.Certificate{Certificate: [][]byte{serverCert.Raw, cross.Raw}}, node) {
		t.Fatal("cross-signed node intermediate accepted")
	}
}

package controlplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/config"
)

func TestLoadTLSConfigAllowsNoClientCertAndVerifiesProvidedCert(t *testing.T) {
	directory := t.TempDir()
	ca, caKey := testCA(t, "collector CA")
	serverCertificate := testCertificate(t, ca, caKey, false)
	clientCertificate := testCertificate(t, ca, caKey, true)
	otherCA, otherKey := testCA(t, "other CA")
	untrustedCertificate := testCertificate(t, otherCA, otherKey, true)
	serverCertPath, serverKeyPath := writeKeyPair(t, directory, "server", serverCertificate)
	caPath := filepath.Join(directory, "collector-ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Control{ServerCertificate: serverCertPath, ServerPrivateKey: serverKeyPath, CollectorCA: caPath}
	tlsConfig, err := LoadTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 || tlsConfig.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("unexpected TLS policy: %+v", tlsConfig)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()

	response, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("certificate-less enrollment-compatible request got %d", response.StatusCode)
	}

	trustedClient := server.Client()
	trustedClient.Transport = server.Client().Transport.(*http.Transport).Clone()
	trustedClient.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{clientCertificate}
	response, err = trustedClient.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("verified collector request got %d", response.StatusCode)
	}

	untrustedClient := server.Client()
	untrustedClient.Transport = server.Client().Transport.(*http.Transport).Clone()
	untrustedClient.Transport.(*http.Transport).TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &untrustedCertificate, nil
	}
	if response, err = untrustedClient.Get(server.URL); err == nil {
		_ = response.Body.Close()
		t.Fatal("server accepted an untrusted collector certificate")
	}
}

func TestReadProtectedPrivateKeyRejectsPermissiveMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.key")
	if err := os.WriteFile(path, []byte("secret"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtectedPrivateKey(path); err == nil {
		t.Fatal("accepted a group-readable CA key")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	contents, err := ReadProtectedPrivateKey(path)
	if err != nil || string(contents) != "secret" {
		t.Fatalf("protected key read failed: %q %v", contents, err)
	}
}

func testCA(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func testCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, client bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	extended := x509.ExtKeyUsageServerAuth
	dnsNames := []string{"example.com"}
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1")}
	if client {
		extended = x509.ExtKeyUsageClientAuth
		dnsNames = nil
		ipAddresses = nil
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "test identity"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{extended}, DNSNames: dnsNames, IPAddresses: ipAddresses,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func writeKeyPair(t *testing.T, directory, prefix string, pair tls.Certificate) (string, string) {
	t.Helper()
	certificatePath := filepath.Join(directory, prefix+".crt")
	keyPath := filepath.Join(directory, prefix+".key")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})
	privateKey, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certificatePath, certificate, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificatePath, keyPath
}

package collectorcontrol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/verticalcomputer/sherlock/internal/collectorpop"
)

type memoryReplayStore struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func (s *memoryReplayStore) ConsumeCollectorRequestNonce(_ context.Context, fingerprint [32]byte, correlationID string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hex.EncodeToString(fingerprint[:]) + ":" + correlationID
	if _, exists := s.seen[key]; exists {
		return ErrRequestReplay
	}
	s.seen[key] = struct{}{}
	return nil
}

type popFixture struct {
	auth       *CloudflareAccessServiceTokenPoPAuthenticator
	clock      *mutableClock
	server     *httptest.Server
	signingKey *rsa.PrivateKey
	kid        string
	leaf       *x509.Certificate
	leafKey    *ecdsa.PrivateKey
}

func newPoPFixture(t *testing.T) *popFixture {
	t.Helper()
	now := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	clock := &mutableClock{now: now}
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := &jwksFixture{key: signingKey, kid: "key-1"}
	server := httptest.NewTLSServer(jwks)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "collector CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "collector"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	auth, err := NewCloudflareAccessServiceTokenPoPAuthenticator(context.Background(), CloudflareAccessServiceTokenPoPConfig{
		Issuer: server.URL, Audience: "audience-1", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		CollectorHostname: "collector.example.com", EnrollmentHostname: "collector-enroll.example.com",
		CollectorRoots: roots, ReplayStore: &memoryReplayStore{seen: map[string]struct{}{}}, HTTPClient: server.Client(), Clock: clock,
	})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return &popFixture{auth: auth, clock: clock, server: server, signingKey: signingKey, kid: "key-1", leaf: leaf, leafKey: leafKey}
}

func (f *popFixture) assertion(t *testing.T) string {
	t.Helper()
	claims := jwt.RegisteredClaims{Issuer: f.server.URL, Audience: jwt.ClaimStrings{"audience-1"}, ExpiresAt: jwt.NewNumericDate(f.clock.Now().Add(time.Minute)), IssuedAt: jwt.NewNumericDate(f.clock.Now().Add(-time.Minute))}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = f.kid
	signed, err := token.SignedString(f.signingKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func (f *popFixture) request(t *testing.T, body []byte, correlationID string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://collector.example.com/collector/v1/heartbeat?wait=1", bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set(accessAssertionHeader, f.assertion(t))
	r.Header.Set(collectorpop.ProtocolHeader, "1")
	r.Header.Set(collectorpop.CorrelationHeader, correlationID)
	if len(body) > 0 {
		r.Header.Set("Content-Type", "application/json")
	}
	timestamp := f.clock.Now().Format(time.RFC3339Nano)
	bodyDigest := sha256.Sum256(body)
	canonical, _ := collectorpop.CanonicalRequest(r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Host, "1", correlationID, timestamp, bodyDigest)
	canonicalDigest := sha256.Sum256(canonical)
	signature, _ := ecdsa.SignASN1(rand.Reader, f.leafKey, canonicalDigest[:])
	r.Header.Set(collectorpop.CertificateHeader, base64.StdEncoding.EncodeToString(f.leaf.Raw))
	r.Header.Set(collectorpop.TimestampHeader, timestamp)
	r.Header.Set(collectorpop.ContentHashHeader, hex.EncodeToString(bodyDigest[:]))
	r.Header.Set(collectorpop.SignatureHeader, base64.RawURLEncoding.EncodeToString(signature))
	return r
}

func TestCloudflareAccessServiceTokenPoPAcceptsAndRejectsReplay(t *testing.T) {
	f := newPoPFixture(t)
	r := f.request(t, []byte(`{"version":"1"}`), "correlation-1")
	certificate, err := f.auth.Certificate(r)
	if err != nil || !certificate.Equal(f.leaf) {
		t.Fatalf("certificate=%v err=%v", certificate, err)
	}
	r = f.request(t, []byte(`{"version":"1"}`), "correlation-1")
	if _, err := f.auth.Certificate(r); err == nil {
		t.Fatal("replayed request was accepted")
	}
}

func TestCloudflareAccessServiceTokenPoPFlowsThroughExistingIdentityLookup(t *testing.T) {
	f := newPoPFixture(t)
	identity := &fakeIdentityOperations{}
	databaseAuth := &fakeAuthenticator{certificate: f.leaf}
	transport, err := NewTransportWithRequestAuthenticator(identity, databaseAuth, &fakeHeartbeatRecorder{}, &fakeWorkOperations{}, &fakeResultOperations{}, f.clock, bytes.NewReader(bytes.Repeat([]byte{1}, 1024)), f.auth)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"version":"1.2.3","build_commit":"abc","capabilities":[{"name":"prometheus_source_health","version":"v1"}],"command_packs":[],"source_health":[]}`)
	r := f.request(t, body, "database-binding")
	r.URL.RawQuery = ""
	// Re-sign after removing the fixture query so the canonical target and the
	// request seen by the handler are identical.
	timestamp := r.Header.Get(collectorpop.TimestampHeader)
	bodyDigest := sha256.Sum256(body)
	canonical, _ := collectorpop.CanonicalRequest(r.Method, r.URL.EscapedPath(), "", r.Host, "1", "database-binding", timestamp, bodyDigest)
	canonicalDigest := sha256.Sum256(canonical)
	signature, _ := ecdsa.SignASN1(rand.Reader, f.leafKey, canonicalDigest[:])
	r.Header.Set(collectorpop.SignatureHeader, base64.RawURLEncoding.EncodeToString(signature))
	w := httptest.NewRecorder()
	transport.ServeHTTP(w, r)
	if w.Code != http.StatusOK || databaseAuth.calls != 1 {
		t.Fatalf("status=%d identity lookups=%d body=%s", w.Code, databaseAuth.calls, w.Body.String())
	}
}

func TestCloudflareAccessServiceTokenPoPRejectsTampering(t *testing.T) {
	tests := map[string]func(*http.Request){
		"body":        func(r *http.Request) { r.Body = http.NoBody },
		"method":      func(r *http.Request) { r.Method = http.MethodPut },
		"path":        func(r *http.Request) { r.URL.Path = "/collector/v1/work/claim" },
		"query":       func(r *http.Request) { r.URL.RawQuery = "wait=2" },
		"host":        func(r *http.Request) { r.Host = "other.example.com" },
		"protocol":    func(r *http.Request) { r.Header.Set(collectorpop.ProtocolHeader, "2") },
		"correlation": func(r *http.Request) { r.Header.Set(collectorpop.CorrelationHeader, "different") },
		"timestamp":   func(r *http.Request) { r.Header.Set(collectorpop.TimestampHeader, "2020-01-01T00:00:00Z") },
		"certificate": func(r *http.Request) { r.Header.Set(collectorpop.CertificateHeader, "not-base64") },
		"signature":   func(r *http.Request) { r.Header.Set(collectorpop.SignatureHeader, "invalid") },
		"assertion":   func(r *http.Request) { r.Header.Del(accessAssertionHeader) },
		"duplicate":   func(r *http.Request) { r.Header.Add(collectorpop.SignatureHeader, "duplicate") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newPoPFixture(t)
			r := f.request(t, []byte(`{"version":"1"}`), "correlation-"+name)
			mutate(r)
			if _, err := f.auth.Certificate(r); err == nil {
				t.Fatal("tampered request was accepted")
			}
		})
	}
}

func TestCloudflareAccessServiceTokenPoPEnrollmentRequiresAssertionAndExactBoundary(t *testing.T) {
	f := newPoPFixture(t)
	r := httptest.NewRequest(http.MethodPost, "https://collector-enroll.example.com/collector/v1/enroll", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set(accessAssertionHeader, f.assertion(t))
	if !f.auth.AllowEnrollment(r) {
		t.Fatal("exact asserted enrollment request was rejected")
	}
	r.Header.Del(accessAssertionHeader)
	if f.auth.AllowEnrollment(r) {
		t.Fatal("certificate-less enrollment was admitted without Access assertion")
	}
}

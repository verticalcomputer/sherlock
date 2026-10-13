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
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *mutableClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *mutableClock) Add(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

type jwksFixture struct {
	mu    sync.RWMutex
	key   *rsa.PrivateKey
	kid   string
	fail  bool
	calls atomic.Int64
}

func (f *jwksFixture) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	f.calls.Add(1)
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.fail {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	e := big.NewInt(int64(f.key.PublicKey.E)).Bytes()
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": f.kid, "n": base64.RawURLEncoding.EncodeToString(f.key.PublicKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)}}})
}

type cfFixture struct {
	auth       *CloudflareAccessMTLSAuthenticator
	clock      *mutableClock
	jwks       *jwksFixture
	server     *httptest.Server
	signingKey *rsa.PrivateKey
	kid        string
	leafDER    []byte
}

func newCFFixture(t *testing.T) *cfFixture {
	t.Helper()
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	clock := &mutableClock{now: now}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	j := &jwksFixture{key: key, kid: "key-1"}
	server := httptest.NewTLSServer(j)
	roots, leaf := certificateFixture(t, now, x509.ExtKeyUsageClientAuth)
	auth, err := NewCloudflareAccessMTLSAuthenticator(context.Background(), CloudflareAccessMTLSConfig{
		Issuer: server.URL, Audience: "audience-1", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		CollectorHostname: "collector.example.com", EnrollmentHostname: "collector-enroll.example.com",
		CollectorRoots: roots, HTTPClient: server.Client(), Clock: clock,
	})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return &cfFixture{auth: auth, clock: clock, jwks: j, server: server, signingKey: key, kid: "key-1", leafDER: leaf}
}

func certificateFixture(t *testing.T, now time.Time, usage x509.ExtKeyUsage) (*x509.CertPool, []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "ignored"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return roots, leafDER
}

func (f *cfFixture) assertion(t *testing.T, mutate func(*jwt.RegisteredClaims), key *rsa.PrivateKey, kid string, method jwt.SigningMethod) string {
	t.Helper()
	claims := &jwt.RegisteredClaims{Issuer: f.server.URL, Audience: jwt.ClaimStrings{"audience-1"}, ExpiresAt: jwt.NewNumericDate(f.clock.Now().Add(time.Minute)), NotBefore: jwt.NewNumericDate(f.clock.Now().Add(-time.Minute))}
	if mutate != nil {
		mutate(claims)
	}
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid
	var signed string
	var err error
	if method == jwt.SigningMethodHS256 {
		signed, err = token.SignedString([]byte("wrong-secret"))
	} else {
		signed, err = token.SignedString(key)
	}
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func (f *cfFixture) request(t *testing.T) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://collector.example.com/collector/v1/heartbeat", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set(accessAssertionHeader, f.assertion(t, nil, f.signingKey, f.kid, jwt.SigningMethodRS256))
	r.Header.Set(forwardedDERHeader, base64.StdEncoding.EncodeToString(f.leafDER))
	digest := sha256.Sum256(f.leafDER)
	r.Header.Set(forwardedSHAHeader, hex.EncodeToString(digest[:]))
	return r
}

func TestCloudflareAccessAuthenticatorAcceptsFullyBoundRequest(t *testing.T) {
	f := newCFFixture(t)
	certificate, err := f.auth.Certificate(f.request(t))
	if err != nil || !certificate.Equal(mustCertificate(t, f.leafDER)) {
		t.Fatalf("certificate = %v, %v", certificate, err)
	}
	if calls := f.jwks.calls.Load(); calls != 1 {
		t.Fatalf("JWKS calls = %d, want bootstrap only", calls)
	}
}

func TestCloudflareCertificateFlowsThroughExistingIdentityLookup(t *testing.T) {
	f := newCFFixture(t)
	certificate := mustCertificate(t, f.leafDER)
	identity := &fakeIdentityOperations{}
	heartbeats := &fakeHeartbeatRecorder{}
	work := &fakeWorkOperations{}
	results := &fakeResultOperations{}
	databaseAuth := &fakeAuthenticator{certificate: certificate}
	transport, err := NewTransportWithRequestAuthenticator(identity, databaseAuth, heartbeats, work, results, f.clock, bytes.NewReader(bytes.Repeat([]byte{1}, 1024)), f.auth)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"version":"1.2.3","build_commit":"abc","capabilities":[],"command_packs":[],"source_health":[]}`
	r := f.request(t)
	r.Body = io.NopCloser(strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(protocolHeader, "1")
	r.Header.Set(correlationHeader, "cf-database-binding")
	w := httptest.NewRecorder()
	transport.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || databaseAuth.calls != 1 {
		t.Fatalf("verified certificate did not reach database identity lookup: status=%d calls=%d body=%s", w.Code, databaseAuth.calls, w.Body.String())
	}

	databaseAuth.err = ErrCollectorInactive
	r = f.request(t)
	r.Body = io.NopCloser(strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(protocolHeader, "1")
	r.Header.Set(correlationHeader, "cf-database-revoked")
	w = httptest.NewRecorder()
	transport.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || databaseAuth.calls != 2 {
		t.Fatalf("inactive database identity status=%d calls=%d", w.Code, databaseAuth.calls)
	}
}

func TestCloudflareAccessAuthenticatorAssertionDenials(t *testing.T) {
	tests := map[string]func(*cfFixture, *http.Request){
		"missing":   func(_ *cfFixture, r *http.Request) { r.Header.Del(accessAssertionHeader) },
		"duplicate": func(_ *cfFixture, r *http.Request) { r.Header.Add(accessAssertionHeader, "duplicate") },
		"oversized": func(_ *cfFixture, r *http.Request) {
			r.Header.Set(accessAssertionHeader, strings.Repeat("x", maxAssertionBytes+1))
		},
		"issuer": func(f *cfFixture, r *http.Request) {
			r.Header.Set(accessAssertionHeader, f.assertion(t, func(c *jwt.RegisteredClaims) { c.Issuer = "https://wrong.example" }, f.signingKey, f.kid, jwt.SigningMethodRS256))
		},
		"audience": func(f *cfFixture, r *http.Request) {
			r.Header.Set(accessAssertionHeader, f.assertion(t, func(c *jwt.RegisteredClaims) { c.Audience = jwt.ClaimStrings{"wrong"} }, f.signingKey, f.kid, jwt.SigningMethodRS256))
		},
		"expired": func(f *cfFixture, r *http.Request) {
			r.Header.Set(accessAssertionHeader, f.assertion(t, func(c *jwt.RegisteredClaims) { c.ExpiresAt = jwt.NewNumericDate(f.clock.Now().Add(-time.Second)) }, f.signingKey, f.kid, jwt.SigningMethodRS256))
		},
		"not before": func(f *cfFixture, r *http.Request) {
			r.Header.Set(accessAssertionHeader, f.assertion(t, func(c *jwt.RegisteredClaims) { c.NotBefore = jwt.NewNumericDate(f.clock.Now().Add(time.Minute)) }, f.signingKey, f.kid, jwt.SigningMethodRS256))
		},
		"missing expiry": func(f *cfFixture, r *http.Request) {
			r.Header.Set(accessAssertionHeader, f.assertion(t, func(c *jwt.RegisteredClaims) { c.ExpiresAt = nil }, f.signingKey, f.kid, jwt.SigningMethodRS256))
		},
		"missing not before": func(f *cfFixture, r *http.Request) {
			r.Header.Set(accessAssertionHeader, f.assertion(t, func(c *jwt.RegisteredClaims) { c.NotBefore = nil }, f.signingKey, f.kid, jwt.SigningMethodRS256))
		},
		"unknown key": func(f *cfFixture, r *http.Request) {
			r.Header.Set(accessAssertionHeader, f.assertion(t, nil, f.signingKey, "unknown", jwt.SigningMethodRS256))
		},
		"empty key id": func(f *cfFixture, r *http.Request) {
			r.Header.Set(accessAssertionHeader, f.assertion(t, nil, f.signingKey, "", jwt.SigningMethodRS256))
		},
		"algorithm": func(f *cfFixture, r *http.Request) {
			r.Header.Set(accessAssertionHeader, f.assertion(t, nil, f.signingKey, f.kid, jwt.SigningMethodHS256))
		},
		"signature": func(f *cfFixture, r *http.Request) {
			other, _ := rsa.GenerateKey(rand.Reader, 2048)
			r.Header.Set(accessAssertionHeader, f.assertion(t, nil, other, f.kid, jwt.SigningMethodRS256))
		},
		"peer": func(_ *cfFixture, r *http.Request) { r.RemoteAddr = "192.0.2.1:1234" },
		"host": func(_ *cfFixture, r *http.Request) { r.Host = "collector-enroll.example.com" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newCFFixture(t)
			r := f.request(t)
			mutate(f, r)
			if _, err := f.auth.Certificate(r); err == nil {
				t.Fatal("request was accepted")
			}
		})
	}
}

func TestCloudflareAccessAuthenticatorCertificateDenials(t *testing.T) {
	tests := map[string]func(*cfFixture, *http.Request){
		"missing":         func(_ *cfFixture, r *http.Request) { r.Header.Del(forwardedDERHeader) },
		"duplicate":       func(_ *cfFixture, r *http.Request) { r.Header.Add(forwardedDERHeader, "duplicate") },
		"malformed":       func(_ *cfFixture, r *http.Request) { r.Header.Set(forwardedDERHeader, "***") },
		"digest mismatch": func(_ *cfFixture, r *http.Request) { r.Header.Set(forwardedSHAHeader, strings.Repeat("0", 64)) },
		"wrong CA": func(f *cfFixture, r *http.Request) {
			_, leaf := certificateFixture(t, f.clock.Now(), x509.ExtKeyUsageClientAuth)
			f.leafDER = leaf
			r.Header.Set(forwardedDERHeader, base64.StdEncoding.EncodeToString(leaf))
			d := sha256.Sum256(leaf)
			r.Header.Set(forwardedSHAHeader, hex.EncodeToString(d[:]))
		},
		"wrong usage": func(f *cfFixture, r *http.Request) {
			roots, leaf := certificateFixture(t, f.clock.Now(), x509.ExtKeyUsageServerAuth)
			f.auth.roots = roots
			r.Header.Set(forwardedDERHeader, base64.StdEncoding.EncodeToString(leaf))
			d := sha256.Sum256(leaf)
			r.Header.Set(forwardedSHAHeader, hex.EncodeToString(d[:]))
		},
		"expired": func(f *cfFixture, r *http.Request) {
			f.clock.Add(2 * time.Hour)
			freshJWT := f.assertion(t, nil, f.signingKey, f.kid, jwt.SigningMethodRS256)
			r.Header.Set(accessAssertionHeader, freshJWT)
		},
		"not yet valid": func(f *cfFixture, r *http.Request) {
			roots, leaf := certificateFixture(t, f.clock.Now().Add(2*time.Hour), x509.ExtKeyUsageClientAuth)
			f.auth.roots = roots
			r.Header.Set(forwardedDERHeader, base64.StdEncoding.EncodeToString(leaf))
			d := sha256.Sum256(leaf)
			r.Header.Set(forwardedSHAHeader, hex.EncodeToString(d[:]))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newCFFixture(t)
			r := f.request(t)
			mutate(f, r)
			if _, err := f.auth.Certificate(r); err == nil {
				t.Fatal("certificate was accepted")
			}
		})
	}
}

func TestCloudflareAccessJWKSRotationAndOutageFailClosed(t *testing.T) {
	f := newCFFixture(t)
	rotated, _ := rsa.GenerateKey(rand.Reader, 2048)
	f.jwks.mu.Lock()
	f.jwks.key, f.jwks.kid = rotated, "key-2"
	f.jwks.mu.Unlock()
	f.clock.Add(31 * time.Second)
	r := f.request(t)
	r.Header.Set(accessAssertionHeader, f.assertion(t, nil, rotated, "key-2", jwt.SigningMethodRS256))
	if _, err := f.auth.Certificate(r); err != nil {
		t.Fatalf("rotated key rejected: %v", err)
	}
	f.clock.Add(61 * time.Second)
	f.jwks.mu.Lock()
	f.jwks.fail = true
	f.jwks.mu.Unlock()
	if _, err := f.auth.Certificate(r); err == nil {
		t.Fatal("expired cache was accepted during outage")
	}
}

func TestCloudflareEnrollmentBoundaryIsExact(t *testing.T) {
	f := newCFFixture(t)
	r := httptest.NewRequest(http.MethodPost, "https://collector-enroll.example.com/collector/v1/enroll", nil)
	r.RemoteAddr = "127.0.0.1:1"
	if !f.auth.AllowEnrollment(r) {
		t.Fatal("exact enrollment request rejected")
	}
	for _, change := range []func(){func() { r.Method = http.MethodGet }, func() { r.URL.Path = "/collector/v1/heartbeat" }, func() { r.Host = "collector.example.com" }, func() { r.RemoteAddr = "192.0.2.1:1" }} {
		r = httptest.NewRequest(http.MethodPost, "https://collector-enroll.example.com/collector/v1/enroll", nil)
		r.RemoteAddr = "127.0.0.1:1"
		change()
		if f.auth.AllowEnrollment(r) {
			t.Fatal("inexact enrollment request accepted")
		}
	}
}

func mustCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func FuzzCloudflareJWTHeader(f *testing.F) {
	f.Add("token")
	f.Fuzz(func(t *testing.T, value string) {
		h := http.Header{}
		h.Add(accessAssertionHeader, value)
		_, _ = oneBoundedHeader(h, accessAssertionHeader, maxAssertionBytes)
	})
}

func FuzzCloudflareCertificateHeader(f *testing.F) {
	f.Add("Y2VydA==", strings.Repeat("0", 64))
	f.Fuzz(func(t *testing.T, encoded, digest string) {
		if len(encoded) > 32<<10 || len(digest) > 1024 {
			return
		}
		der, _ := base64.StdEncoding.Strict().DecodeString(encoded)
		_, _ = hex.DecodeString(digest)
		if len(der) <= maxForwardedDERBytes {
			_, _ = x509.ParseCertificates(der)
		}
	})
}

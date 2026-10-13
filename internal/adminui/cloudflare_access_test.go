package adminui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type accessVerifierFixture struct {
	clock  *fakeClock
	key    *rsa.PrivateKey
	kid    string
	aud    string
	server *httptest.Server
}

func newAccessVerifierFixture(t *testing.T) (*accessVerifierFixture, *CloudflareAccessVerifier) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &accessVerifierFixture{
		clock: &fakeClock{now: time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)},
		key:   key, kid: "access-key-1", aud: "admin-audience",
	}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/cdn-cgi/access/certs" {
			http.NotFound(writer, request)
			return
		}
		public := fixture.key.PublicKey
		document := map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": fixture.kid, "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
		}}}
		writer.Header().Set("Cache-Control", "max-age=300")
		_ = json.NewEncoder(writer).Encode(document)
	}))
	t.Cleanup(fixture.server.Close)
	verifier, err := NewCloudflareAccessVerifier(context.Background(), CloudflareAccessConfig{
		Issuer: fixture.server.URL, Audience: fixture.aud, HTTPClient: fixture.server.Client(), Clock: fixture.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture, verifier
}

func (fixture *accessVerifierFixture) assertion(t *testing.T, mutate func(*accessClaims)) string {
	t.Helper()
	claims := &accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: fixture.server.URL, Subject: "access-user-1", Audience: jwt.ClaimStrings{fixture.aud},
			ExpiresAt: jwt.NewNumericDate(fixture.clock.Now().Add(time.Minute)),
			IssuedAt:  jwt.NewNumericDate(fixture.clock.Now().Add(-time.Minute)),
			NotBefore: jwt.NewNumericDate(fixture.clock.Now().Add(-time.Minute)),
		},
		Email: "operator@example.com", Type: "app",
	}
	if mutate != nil {
		mutate(claims)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = fixture.kid
	signed, err := token.SignedString(fixture.key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestCloudflareAccessVerifierAcceptsHumanApplicationToken(t *testing.T) {
	fixture, verifier := newAccessVerifierFixture(t)
	identity, err := verifier.Verify(context.Background(), fixture.assertion(t, nil))
	if err != nil || identity.Issuer != fixture.server.URL || identity.Subject != "access-user-1" || identity.Email != "operator@example.com" {
		t.Fatalf("identity=%+v error=%v", identity, err)
	}
}

func TestCloudflareAccessVerifierRejectsWrongBoundaryAndServiceToken(t *testing.T) {
	fixture, verifier := newAccessVerifierFixture(t)
	tests := map[string]func(*accessClaims){
		"issuer":   func(claims *accessClaims) { claims.Issuer = "https://wrong.cloudflareaccess.com" },
		"audience": func(claims *accessClaims) { claims.Audience = jwt.ClaimStrings{"wrong"} },
		"expired": func(claims *accessClaims) {
			claims.ExpiresAt = jwt.NewNumericDate(fixture.clock.Now().Add(-time.Second))
		},
		"service token":      func(claims *accessClaims) { claims.Subject, claims.Email = "", "" },
		"missing not-before": func(claims *accessClaims) { claims.NotBefore = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Verify(context.Background(), fixture.assertion(t, mutate)); err == nil {
				t.Fatal("invalid Access assertion was accepted")
			}
		})
	}
}

func TestCloudflareAccessVerifierRejectsOversizedJWKS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(bytes.Repeat([]byte("x"), maxAccessJWKS+1))
	}))
	defer server.Close()
	if _, err := NewCloudflareAccessVerifier(context.Background(), CloudflareAccessConfig{
		Issuer: server.URL, Audience: "admin-audience", HTTPClient: server.Client(),
	}); err == nil {
		t.Fatal("oversized JWKS was accepted")
	}
}

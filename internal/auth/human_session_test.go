package auth

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestHumanSessionBindsVerifiedPrincipalAndRequest(t *testing.T) {
	token := []byte(strings.Repeat("s", 40))
	at := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	principal := HumanPrincipal{Issuer: "https://vertical.cloudflareaccess.com", Subject: "subject-1"}
	session := HumanSession{Principal: principal, Fingerprint: sha256.Sum256([]byte("verified assertion"))}
	sealed, err := SealHumanSession(token, session, "POST", "/internal/admin/v1/clusters/pilot-cluster/investigations", at)
	if err != nil || strings.Contains(sealed, string(token)) || strings.Contains(sealed, "verified assertion") {
		t.Fatalf("sealed=%q err=%v", sealed, err)
	}
	got, err := VerifyHumanSession(token, sealed, "POST", "/internal/admin/v1/clusters/pilot-cluster/investigations", at.Add(10*time.Second))
	if err != nil || got != session {
		t.Fatalf("session=%+v err=%v", got, err)
	}
	for _, test := range []struct {
		name, seal, method, uri string
		key                     []byte
		now                     time.Time
	}{
		{"wrong method", sealed, "GET", "/internal/admin/v1/clusters/pilot-cluster/investigations", token, at},
		{"wrong path", sealed, "POST", "/internal/admin/v1/clusters/foreign/investigations", token, at},
		{"wrong key", sealed, "POST", "/internal/admin/v1/clusters/pilot-cluster/investigations", []byte(strings.Repeat("x", 40)), at},
		{"expired", sealed, "POST", "/internal/admin/v1/clusters/pilot-cluster/investigations", token, at.Add(31 * time.Second)},
		{"future", sealed, "POST", "/internal/admin/v1/clusters/pilot-cluster/investigations", token, at.Add(-6 * time.Second)},
		{"trailing bytes", sealed + "x", "POST", "/internal/admin/v1/clusters/pilot-cluster/investigations", token, at},
		{"oversized", strings.Repeat("x", maxHumanSession+1), "POST", "/internal/admin/v1/clusters/pilot-cluster/investigations", token, at},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := VerifyHumanSession(test.key, test.seal, test.method, test.uri, test.now)
			if !errors.Is(err, ErrHumanSession) {
				t.Fatalf("accepted invalid session: %v", err)
			}
		})
	}
}

func TestHumanSessionRejectsUnverifiedOrUnscopedInput(t *testing.T) {
	token := []byte(strings.Repeat("s", 40))
	for _, principal := range []HumanPrincipal{
		{}, {Issuer: "http://untrusted", Subject: "subject"},
		{Issuer: "https://vertical.cloudflareaccess.com", Subject: ""},
	} {
		if _, err := SealHumanSession(token, HumanSession{Principal: principal}, "GET", "/internal/admin/v1/clusters", time.Now()); !errors.Is(err, ErrHumanSession) {
			t.Fatalf("accepted principal %+v: %v", principal, err)
		}
	}
	if _, err := SealHumanSession(token, HumanSession{Principal: HumanPrincipal{Issuer: "https://vertical.cloudflareaccess.com", Subject: "subject"}}, "GET", "/api/v1/clusters", time.Now()); !errors.Is(err, ErrHumanSession) {
		t.Fatalf("accepted foreign route: %v", err)
	}
}

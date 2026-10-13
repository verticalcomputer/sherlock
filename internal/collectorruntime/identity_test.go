package collectorruntime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestBootstrapTokenFileRequiresOwnerOnlyPermissionsAndRedactsFormatting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	tokenValue := strings.Repeat("s", 43)
	if err := os.WriteFile(path, []byte(tokenValue+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Creation permissions are filtered by the process umask; set the unsafe
	// mode explicitly so this exercises rejection even under an owner-only umask.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBootstrapTokenFile(path); err == nil {
		t.Fatal("world-readable token file was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := ReadBootstrapTokenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if formatted := fmt.Sprintf("%v %#v", token, token); strings.Contains(formatted, tokenValue) || !strings.Contains(formatted, "REDACTED") {
		t.Fatalf("token formatting was not redacted: %s", formatted)
	}
	token.Clear()
}

func TestPersistIdentityAtomicallySwitchesCurrentAndPreservesOldOnFailure(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	issuer := testIdentityIssuer(t, now)
	keyOne, csrOne, err := GenerateIdentityRequest()
	if err != nil {
		t.Fatal(err)
	}
	first := issueIdentity(t, issuer, csrOne, "collector-1", now)
	directory := filepath.Join(t.TempDir(), "identity")
	if err := PersistIdentity(directory, first, keyOne, "", now); err != nil {
		t.Fatal(err)
	}
	firstTarget, err := os.Readlink(filepath.Join(directory, "current"))
	if err != nil {
		t.Fatal(err)
	}
	keyInfo, err := os.Stat(filepath.Join(directory, "current", "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions = %v", keyInfo.Mode().Perm())
	}

	keyTwo, csrTwo, err := GenerateIdentityRequest()
	if err != nil {
		t.Fatal(err)
	}
	second := issueIdentity(t, issuer, csrTwo, "collector-1", now.Add(time.Minute))
	if err := PersistIdentity(directory, second, keyOne, "collector-1", now.Add(time.Minute)); err == nil {
		t.Fatal("mismatched renewed certificate and key were accepted")
	}
	targetAfterFailure, _ := os.Readlink(filepath.Join(directory, "current"))
	if targetAfterFailure != firstTarget {
		t.Fatal("failed renewal changed the active identity")
	}
	if err := PersistIdentity(directory, second, keyTwo, "collector-1", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	secondTarget, _ := os.Readlink(filepath.Join(directory, "current"))
	if secondTarget == firstTarget {
		t.Fatal("valid renewal did not atomically switch identity versions")
	}
}

func TestHTTPClientEnrollmentKeepsTokenInAuthorizationOnly(t *testing.T) {
	tokenValue := strings.Repeat("b", 43)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/collector/v1/enroll" || r.Header.Get("Authorization") != "Bearer "+tokenValue {
			t.Errorf("unexpected enrollment request")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		encoded, _ := json.Marshal(body)
		if strings.Contains(string(encoded), tokenValue) {
			t.Error("bootstrap token was copied into request body")
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(identityWire{CollectorID: "collector-1", CertificatePEM: "cert", CAChainPEM: "ca", NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)})
	}))
	defer server.Close()
	client, err := NewHTTPClient(server.URL, server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := ReadBootstrapToken(strings.NewReader(tokenValue))
	if err != nil {
		t.Fatal(err)
	}
	defer token.Clear()
	identity, err := client.Enroll(context.Background(), token, []byte("csr"), DefaultCollectorMetadata("site", "1", "abc"))
	if err != nil || identity.CollectorID != "collector-1" {
		t.Fatalf("Enroll = %+v, %v", identity, err)
	}
}

func TestHTTPClientRenewalUsesPrivateIdentityEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/collector/v1/identity/renew" || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected renewal request: %s %s", r.Method, r.URL.Path)
		}
		var body renewIdentityWire
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.CSRPEM != "renew-csr" {
			t.Errorf("renewal body = %+v, err=%v", body, err)
		}
		_ = json.NewEncoder(w).Encode(identityWire{CertificatePEM: "cert", CAChainPEM: "ca", NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)})
	}))
	defer server.Close()
	client, err := NewHTTPClient(server.URL, server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.RenewIdentity(context.Background(), []byte("renew-csr")); err != nil {
		t.Fatal(err)
	}
}

func testIdentityIssuer(t *testing.T, now time.Time) *collectorcontrol.CAIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := collectorcontrol.NewCAIssuer(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), rand.Reader,
	)
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

func issueIdentity(t *testing.T, issuer *collectorcontrol.CAIssuer, csr []byte, collectorID string, now time.Time) IssuedIdentity {
	t.Helper()
	issued, err := issuer.Issue("cluster-1", domain.CollectorID(collectorID), csr, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return IssuedIdentity{
		CollectorID: collectorID, CertificatePEM: issued.CertificatePEM, CAChainPEM: issued.CAChainPEM,
		NotBefore: issued.NotBefore, NotAfter: issued.NotAfter,
	}
}

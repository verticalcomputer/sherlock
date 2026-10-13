package nodeidentity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

type fixture struct {
	at            time.Time
	scope         Scope
	key           ed25519.PrivateKey
	request       Request
	issuer        *Issuer
	caPEM, keyPEM string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	public, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic dedicated node CA"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(7 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, public, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyBytes, err := privatePEM(caKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewIssuer(caPEM, string(keyBytes))
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{"cluster-a", "node-a", "enrollment-a", "key-a"}
	request, err := NewRequest(scope, key)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{at, scope, key, request, issuer, caPEM, string(keyBytes)}
}

func (f fixture) bundle(t *testing.T) CertificateBundle {
	t.Helper()
	bundle, err := f.issuer.Issue(f.request, f.at, MaxCertificateLifetime)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func TestOfflineCSRAndImportExactBinding(t *testing.T) {
	f := newFixture(t)
	public, err := ValidateRequest(f.request)
	if err != nil || !public.Equal(f.key.Public()) {
		t.Fatalf("request: %v", err)
	}
	bundle := f.bundle(t)
	if err := VerifyImport(bundle, f.request, f.key, f.issuer.NodeCAFingerprint(), f.at); err != nil {
		t.Fatal(err)
	}
	der, _ := singlePEM(bundle.CertificatePEM, "CERTIFICATE")
	cert, _ := x509.ParseCertificate(der)
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://sherlock/node/cluster-a/node-a/enrollment-a/key-a" || cert.NotAfter.Sub(f.at) != MaxCertificateLifetime {
		t.Fatal("unexpected certificate identity or validity")
	}
	for _, change := range []struct {
		name  string
		apply func(*CertificateBundle)
	}{
		{"node", func(b *CertificateBundle) { b.Scope.NodeID = "node-b" }},
		{"csr", func(b *CertificateBundle) { b.CSRSHA256 = strings.Repeat("0", 64) }},
		{"spki", func(b *CertificateBundle) { b.SPKISHA256 = strings.Repeat("0", 64) }},
		{"expiry", func(b *CertificateBundle) { b.NotAfter = b.NotAfter.Add(time.Second) }},
		{"version", func(b *CertificateBundle) { b.ProtocolVersion++ }},
	} {
		t.Run(change.name, func(t *testing.T) {
			bad := bundle
			change.apply(&bad)
			if VerifyImport(bad, f.request, f.key, f.issuer.NodeCAFingerprint(), f.at) == nil {
				t.Fatal("accepted changed binding")
			}
		})
	}
	foreign := newFixture(t)
	if VerifyImport(bundle, f.request, foreign.key, f.issuer.NodeCAFingerprint(), f.at) == nil || VerifyImport(bundle, f.request, f.key, foreign.issuer.NodeCAFingerprint(), f.at) == nil {
		t.Fatal("accepted foreign key/CA")
	}
	if VerifyImport(bundle, f.request, f.key, f.issuer.NodeCAFingerprint(), bundle.NotAfter) == nil {
		t.Fatal("accepted exact expiry")
	}
	if VerifyImport(bundle, f.request, f.key, f.issuer.NodeCAFingerprint(), bundle.NotAfter.Add(-time.Nanosecond)) != nil {
		t.Fatal("rejected before expiry")
	}
}

func TestCSRRejectsMalformedAndRequestedAuthority(t *testing.T) {
	f := newFixture(t)
	for _, change := range []struct {
		name  string
		apply func(*Request)
	}{
		{"hash", func(r *Request) { r.CSRSHA256 = strings.Repeat("0", 64) }},
		{"key", func(r *Request) { r.PublicKeyBase64 = strings.Repeat("x", 43) }},
		{"oversize", func(r *Request) { r.CSRPEM = strings.Repeat("x", MaxPEMBytes+1) }},
		{"preamble", func(r *Request) { r.CSRPEM = "untrusted\n" + r.CSRPEM }},
		{"extra object", func(r *Request) { r.CSRPEM += r.CSRPEM }},
		{"scope", func(r *Request) { r.Scope.NodeID = "../node" }},
		{"version", func(r *Request) { r.ProtocolVersion = 2 }},
	} {
		t.Run(change.name, func(t *testing.T) {
			bad := f.request
			change.apply(&bad)
			if _, err := ValidateRequest(bad); err == nil {
				t.Fatal("accepted malformed request")
			}
		})
	}
	for _, template := range []*x509.CertificateRequest{
		{Subject: pkix.Name{CommonName: "privileged"}},
		{DNSNames: []string{"node-a"}},
		{URIs: []*url.URL{{Scheme: "spiffe", Host: "sherlock", Path: "/node/foreign"}}},
	} {
		der, err := x509.CreateCertificateRequest(rand.Reader, template, f.key)
		if err != nil {
			t.Fatal(err)
		}
		request := f.request
		request.CSRPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
		request.CSRSHA256 = digest(der)
		if _, err := ValidateRequest(request); err == nil {
			t.Fatal("accepted caller-requested identity")
		}
	}
	block, _ := pem.Decode([]byte(f.request.CSRPEM))
	block.Bytes[len(block.Bytes)-1] ^= 1
	bad := f.request
	bad.CSRPEM = string(pem.EncodeToMemory(block))
	bad.CSRSHA256 = digest(block.Bytes)
	if _, err := ValidateRequest(bad); err == nil {
		t.Fatal("accepted invalid proof of possession")
	}
}

func TestIssuerLimitsAndDedicatedKey(t *testing.T) {
	f := newFixture(t)
	foreign := newFixture(t)
	if _, err := NewIssuer(f.caPEM, foreign.keyPEM); err == nil {
		t.Fatal("accepted mismatched CA key")
	}
	for _, lifetime := range []time.Duration{0, -time.Second, MaxCertificateLifetime + time.Second, time.Nanosecond} {
		if _, err := f.issuer.Issue(f.request, f.at, lifetime); err == nil {
			t.Fatalf("accepted lifetime %v", lifetime)
		}
	}
	if _, err := f.issuer.Issue(f.request, f.issuer.certificate.NotAfter.Add(-time.Hour), 2*time.Hour); err == nil {
		t.Fatal("accepted leaf beyond CA validity")
	}
	if _, err := f.issuer.Issue(f.request, f.issuer.certificate.NotBefore.Add(-time.Second), time.Hour); err == nil {
		t.Fatal("accepted not-yet-valid CA")
	}
	var empty *Issuer
	if _, err := empty.Issue(f.request, f.at, time.Hour); err == nil {
		t.Fatal("accepted absent issuer")
	}
}

func TestImportRejectsLeafAuthorityAndUsage(t *testing.T) {
	f := newFixture(t)
	bundle := f.bundle(t)
	uri, _ := IdentityURI(f.scope)
	for _, test := range []struct {
		name   string
		change func(*x509.Certificate)
	}{
		{"server auth", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }},
		{"additional auth", func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) }},
		{"dns", func(c *x509.Certificate) { c.DNSNames = []string{"node-a"} }},
		{"foreign SAN", func(c *x509.Certificate) {
			c.URIs = []*url.URL{{Scheme: "spiffe", Host: "sherlock", Path: "/node/cluster-a/node-b/enrollment-a/key-a"}}
		}},
		{"CA", func(c *x509.Certificate) { c.IsCA = true }},
		{"subject", func(c *x509.Certificate) { c.Subject = pkix.Name{CommonName: "unexpected"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			template := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{}, NotBefore: f.at.Add(-time.Minute), NotAfter: bundle.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, URIs: []*url.URL{uri}}
			test.change(template)
			der, err := x509.CreateCertificate(rand.Reader, template, f.issuer.certificate, f.key.Public(), f.issuer.key)
			if err != nil {
				t.Fatal(err)
			}
			bad := bundle
			bad.CertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			if VerifyImport(bad, f.request, f.key, f.issuer.NodeCAFingerprint(), f.at) == nil {
				t.Fatal("accepted incompatible certificate")
			}
		})
	}
}

func TestRequestGrantCurrentActiveVersusHistoricalRetrieval(t *testing.T) {
	f := newFixture(t)
	grant := telemetry.Grant{ProtocolVersion: 1, EnrollmentID: f.scope.EnrollmentID, EnrollmentRevision: 1, ControlRevision: 1, Status: "ACTIVE", ClusterID: f.scope.ClusterID, NodeID: f.scope.NodeID, InventoryRevisionID: "inventory-a", GatewayCollectorID: "gateway-a", Sources: []telemetry.SourceGrant{{SourceID: "fixture-a", SchemaVersion: 1, ProfileID: telemetry.FixtureProfile}}, AgentVersion: "v1", BuildSHA256: strings.Repeat("1", 64), GatewaySPKISHA256: strings.Repeat("2", 64), Keys: []telemetry.NodeKey{{ID: f.scope.KeyID, Epoch: "1", PublicKeyBase64: f.request.PublicKeyBase64, State: "ACTIVE"}}, NotBefore: f.at, NotAfter: f.at.Add(time.Minute)}
	if err := ValidateRequestForGrant(f.request, grant, f.at, false); err != nil {
		t.Fatal(err)
	}
	active := grant.Keys[0]
	grant.Keys[0].State = "VERIFY_ONLY"
	active.ID = "new-key"
	active.Epoch = "2"
	active.PublicKeyBase64 = newFixture(t).request.PublicKeyBase64
	grant.Keys = append(grant.Keys, active)
	if !errors.Is(ValidateRequestForGrant(f.request, grant, f.at, false), ErrUnauthorized) {
		t.Fatal("verify-only new issuance")
	}
	if err := ValidateRequestForGrant(f.request, grant, f.at, true); err != nil {
		t.Fatal("denied historical retrieval", err)
	}
	grant.Keys[0].State = "REVOKED"
	if ValidateRequestForGrant(f.request, grant, f.at, true) == nil {
		t.Fatal("accepted revoked retrieval")
	}
}

func TestBootstrapTokenCanonicalBoundedAndDomainSeparated(t *testing.T) {
	token, hash, err := NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	second, other, err := NewBootstrapToken()
	if err != nil || second == token || other == hash {
		t.Fatal("token uniqueness")
	}
	if len(token) != 43 || len(hash) != 64 {
		t.Fatal("invalid token shape")
	}
	if got, err := BootstrapTokenHash(token); err != nil || got != hash {
		t.Fatal("unstable token digest")
	}
	if hash == digest([]byte(token)) {
		t.Fatal("missing domain separation")
	}
	for _, bad := range []string{"", token + "=", strings.Repeat("x", 1<<20), strings.Repeat("/", 43), token[:42] + "!"} {
		if _, err := BootstrapTokenHash(bad); err == nil {
			t.Fatal("accepted bad token")
		}
	}
}

func TestURIUsesExactExistingGrammar(t *testing.T) {
	for _, bad := range []string{"", "../node", "node/a", "node%2Fa", "node a", "नोड", strings.Repeat("x", 129)} {
		if _, err := IdentityURI(Scope{"cluster", bad, "enrollment", "key"}); err == nil {
			t.Fatal("accepted invalid URI identifier")
		}
	}
	f := newFixture(t)
	der, _ := singlePEM(f.request.CSRPEM, "CERTIFICATE REQUEST")
	csr, _ := x509.ParseCertificateRequest(der)
	if !bytes.Equal(csr.RawSubject, []byte{0x30, 0}) {
		t.Fatal("CSR subject is not empty")
	}
}

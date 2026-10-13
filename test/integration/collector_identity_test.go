//go:build integration

package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type identityTestClock struct{ now time.Time }

func (c identityTestClock) Now() time.Time { return c.now }

type identityTestIDs struct {
	values []string
	next   int
}

func (g *identityTestIDs) NewID() (string, error) {
	value := g.values[g.next]
	g.next++
	return value, nil
}

func TestCollectorEnrollmentRenewalAndRevocation(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	collectionStore, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	controlStore, err := storepg.NewCollectorControlStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	suffix := now.Format("20060102150405.000000000")
	clusterID := domain.ClusterID("identity-cluster-" + suffix)
	sourceID := domain.SourceID("identity-source-" + suffix)
	collectorID := domain.CollectorID("collector-identity-" + suffix)
	if err := collectionStore.EnsureSource(ctx, clusterID, "Identity integration cluster", sourceID, "Identity Prometheus"); err != nil {
		t.Fatal(err)
	}
	caCertificate, caKey := createTestCA(t, now)
	issuer, err := collectorcontrol.NewCAIssuer(caCertificate, caKey, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service, err := collectorcontrol.NewIdentityService(
		controlStore, issuer, identityTestClock{now: now},
		&identityTestIDs{values: []string{"bootstrap-" + suffix, string(collectorID)}},
		rand.Reader, 10*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}

	bootstrap, err := service.CreateBootstrapKey(ctx, clusterID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap.Token == "" || strings.Contains(bootstrap.Token, bootstrap.BootstrapKeyID) {
		t.Fatal("bootstrap secret is missing or derived from its public identifier")
	}
	firstKey, firstCSR := createCollectorCSR(t)
	enrollment, err := service.Enroll(ctx, collectorcontrol.EnrollmentRequest{
		BootstrapToken: bootstrap.Token, CSRPEM: firstCSR,
		Metadata: collectorcontrol.CollectorMetadata{
			DisplayName: "Integration collector", Version: "0.2.0-test", BuildCommit: "test",
			ProtocolMin: 1, ProtocolMax: 1, OperatingSystem: "linux", Architecture: "amd64",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.CollectorID != collectorID {
		t.Fatalf("collector id=%s", enrollment.CollectorID)
	}
	verifyCollectorCertificate(t, enrollment.Identity, caCertificate, clusterID, collectorID, &firstKey.PublicKey)
	authenticated, err := controlStore.AuthenticateCollectorIdentity(ctx, enrollment.Identity.Serial, enrollment.Identity.Fingerprint)
	if err != nil || authenticated.CollectorID != collectorID || authenticated.ClusterID != clusterID {
		t.Fatalf("authenticated identity=%+v err=%v", authenticated, err)
	}

	_, err = service.Enroll(ctx, collectorcontrol.EnrollmentRequest{
		BootstrapToken: bootstrap.Token, CSRPEM: firstCSR,
		Metadata: collectorcontrol.CollectorMetadata{
			DisplayName: "Replay", Version: "0.2.0-test", ProtocolMin: 1, ProtocolMax: 1,
			OperatingSystem: "linux", Architecture: "amd64",
		},
	})
	if !errors.Is(err, collectorcontrol.ErrBootstrapUnavailable) {
		t.Fatalf("bootstrap replay error=%v", err)
	}

	secondKey, secondCSR := createCollectorCSR(t)
	renewed, err := service.Renew(ctx, collectorID, secondCSR)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Serial == enrollment.Identity.Serial {
		t.Fatal("renewal reused the certificate serial")
	}
	verifyCollectorCertificate(t, renewed, caCertificate, clusterID, collectorID, &secondKey.PublicKey)
	var supersededAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT superseded_at FROM collector_identities WHERE certificate_serial=$1`, enrollment.Identity.Serial).Scan(&supersededAt); err != nil {
		t.Fatal(err)
	}
	if supersededAt == nil {
		t.Fatal("previous identity was not marked superseded")
	}

	if err := service.Revoke(ctx, collectorID); err != nil {
		t.Fatal(err)
	}
	if err := service.Revoke(ctx, collectorID); err != nil {
		t.Fatalf("duplicate revocation was not idempotent: %v", err)
	}
	if _, err := controlStore.AuthenticateCollectorIdentity(ctx, renewed.Serial, renewed.Fingerprint); !errors.Is(err, collectorcontrol.ErrCollectorInactive) {
		t.Fatalf("authentication after revocation error=%v", err)
	}
	_, thirdCSR := createCollectorCSR(t)
	if _, err := service.Renew(ctx, collectorID, thirdCSR); !errors.Is(err, collectorcontrol.ErrCollectorInactive) {
		t.Fatalf("renewal after revocation error=%v", err)
	}
	var status domain.CollectorStatus
	var unrevoked int
	if err := pool.QueryRow(ctx, `
		SELECT c.status, count(*) FILTER (WHERE i.revoked_at IS NULL)
		FROM collectors c JOIN collector_identities i USING (collector_id)
		WHERE c.collector_id=$1 GROUP BY c.status`, collectorID).Scan(&status, &unrevoked); err != nil {
		t.Fatal(err)
	}
	if status != domain.CollectorRevoked || unrevoked != 0 {
		t.Fatalf("revocation status=%s unrevoked_identities=%d", status, unrevoked)
	}
}

func createTestCA(t *testing.T, now time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Sherlock test collector CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func createCollectorCSR(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored-client-value"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func verifyCollectorCertificate(t *testing.T, identity collectorcontrol.IssuedIdentity, caPEM []byte, clusterID domain.ClusterID, collectorID domain.CollectorID, expectedKey *ecdsa.PublicKey) {
	t.Helper()
	block, _ := pem.Decode(identity.CertificatePEM)
	if block == nil {
		t.Fatal("issued certificate is not PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caBlock, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: identity.NotBefore.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	actualKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || !actualKey.Equal(expectedKey) {
		t.Fatal("issued certificate does not contain the CSR public key")
	}
	expectedURI := "spiffe://sherlock/cluster/" + string(clusterID) + "/collector/" + string(collectorID)
	if len(certificate.URIs) != 1 || certificate.URIs[0].String() != expectedURI {
		t.Fatalf("identity URI=%v expected=%s", certificate.URIs, expectedURI)
	}
	if certificate.Subject.CommonName != string(collectorID) {
		t.Fatalf("certificate common name=%s", certificate.Subject.CommonName)
	}
}

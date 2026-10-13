//go:build integration

package postgres_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func nodeBootstrapFixture(t *testing.T) (*telemetryFixture, nodeidentity.Request, *nodeidentity.Issuer) {
	t.Helper()
	f := newTelemetryFixture(t)
	request, err := nodeidentity.NewRequest(nodeidentity.Scope{ClusterID: string(f.request.ClusterID), NodeID: string(f.request.NodeID), EnrollmentID: f.request.EnrollmentID, KeyID: f.request.KeyID}, f.private)
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic node bootstrap CA"}, NotBefore: f.now.Add(-48 * time.Hour), NotAfter: f.now.Add(7 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := nodeidentity.NewIssuer(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))
	if err != nil {
		t.Fatal(err)
	}
	return f, request, issuer
}

func mintBootstrap(t *testing.T, f *telemetryFixture, request nodeidentity.Request) string {
	t.Helper()
	token, err := f.store.MintNodeBootstrap(context.Background(), f.request.ClusterID, f.request.GatewayCollectorID, request, 1, "fixture-operator")
	if err != nil || token == "" {
		t.Fatal("mint bootstrap", err)
	}
	return token
}

func TestNodeBootstrapAtomicIssuanceLostResponseAndScope(t *testing.T) {
	f, request, issuer := nodeBootstrapFixture(t)
	ctx := context.Background()
	token := mintBootstrap(t, f, request)
	// Missing optional issuer cannot consume the token or publish a candidate.
	if bundle, err := f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, token, request, nil); !errors.Is(err, telemetry.ErrUnavailable) || bundle != (nodeidentity.CertificateBundle{}) {
		t.Fatal("absent issuer", err)
	}
	first, err := f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, token, request, issuer)
	if err != nil {
		t.Fatal("consume", err)
	}
	var now time.Time
	_ = f.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now)
	if err := nodeidentity.VerifyImport(first, request, f.private, issuer.NodeCAFingerprint(), now); err != nil {
		t.Fatal("issued identity invalid", err)
	}
	f.store = storepg.NewTelemetryStore(f.pool)
	replay, err := f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, token, request, nil)
	if err != nil || replay != first {
		t.Fatal("lost-response restart replay changed bundle", err)
	}
	var raw, expired int
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE token_hash=$2),count(*) FILTER(WHERE expires_at>minted_at+interval '10 minutes') FROM gp06f_node_bootstrap WHERE enrollment_id=$1`, f.request.EnrollmentID, token).Scan(&raw, &expired); err != nil || raw != 0 || expired != 0 {
		t.Fatal("raw token persisted or TTL widened", err)
	}
	var audit int
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM gp06f_node_identity_audit WHERE enrollment_id=$1 AND action='CERTIFICATE_ISSUED'`, f.request.EnrollmentID).Scan(&audit); err != nil || audit != 1 {
		t.Fatal("duplicate issuance", err)
	}
	foreign := request
	foreign.Scope.NodeID = "foreign-node"
	for _, r := range []nodeidentity.Request{foreign} {
		if _, err = f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, token, r, issuer); !errors.Is(err, telemetry.ErrUnauthorized) {
			t.Fatal("foreign scope", err)
		}
	}
	if _, err = f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, "foreign-collector", token, request, issuer); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("foreign collector", err)
	}
	if _, err = f.store.ConsumeNodeBootstrap(ctx, "foreign-cluster", f.request.GatewayCollectorID, token, request, issuer); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("foreign cluster", err)
	}
	if _, err = f.store.MintNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, 2, "fixture-operator"); !errors.Is(err, telemetry.ErrConflict) {
		t.Fatal("stale operator revision", err)
	}
}

func TestNodeBootstrapConcurrentConsumePublishesOneCertificate(t *testing.T) {
	f, request, issuer := nodeBootstrapFixture(t)
	token := mintBootstrap(t, f, request)
	ctx := context.Background()
	type result struct {
		bundle nodeidentity.CertificateBundle
		err    error
	}
	results := make(chan result, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bundle, err := f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, token, request, issuer)
			results <- result{bundle, err}
		}()
	}
	wg.Wait()
	close(results)
	var first nodeidentity.CertificateBundle
	for r := range results {
		if r.err != nil {
			t.Fatal("concurrent consume", r.err)
		}
		if first.CertificatePEM == "" {
			first = r.bundle
		} else if first != r.bundle {
			t.Fatal("two committed certificates")
		}
	}
	var count int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM gp06f_node_identity_audit WHERE enrollment_id=$1 AND action='CERTIFICATE_ISSUED'`, f.request.EnrollmentID).Scan(&count)
	if count != 1 {
		t.Fatal("multiple issuance audit rows")
	}
}

// Audit failure occurs after candidate signing and consume UPDATE, proving the
// transaction rolls both back without leaking raw token/certificate outputs.
func failIdentityAudit(t *testing.T, f *telemetryFixture, action string) func() {
	t.Helper()
	ctx := context.Background()
	name := fmt.Sprintf("fixture_identity_fail_%d", time.Now().UnixNano())
	var sql string
	if err := f.pool.QueryRow(ctx, `SELECT format('CREATE FUNCTION %I() RETURNS trigger LANGUAGE plpgsql AS $body$ BEGIN IF NEW.enrollment_id=TG_ARGV[0] AND NEW.action=TG_ARGV[1] THEN RAISE EXCEPTION ''private SQL credential /fixture/secret''; END IF; RETURN NEW; END $body$', $1::text)`, name).Scan(&sql); err != nil {
		t.Fatal(err)
	}
	f.exec(t, sql)
	if err := f.pool.QueryRow(ctx, `SELECT format('CREATE TRIGGER %I BEFORE INSERT ON gp06f_node_identity_audit FOR EACH ROW EXECUTE FUNCTION %I(%L,%L)', $1::text,$1::text,$2::text,$3::text)`, name, f.request.EnrollmentID, action).Scan(&sql); err != nil {
		t.Fatal(err)
	}
	f.exec(t, sql)
	return func() {
		var cleanup string
		if err := f.pool.QueryRow(ctx, `SELECT format('DROP TRIGGER %I ON gp06f_node_identity_audit; DROP FUNCTION %I()', $1::text,$1::text)`, name).Scan(&cleanup); err != nil {
			t.Fatal(err)
		}
		f.exec(t, cleanup)
	}
}

func TestNodeBootstrapRollbackDoesNotConsumeOrReturnSecrets(t *testing.T) {
	f, request, issuer := nodeBootstrapFixture(t)
	ctx := context.Background()
	remove := failIdentityAudit(t, f, "BOOTSTRAP_MINTED")
	if token, err := f.store.MintNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, 1, "fixture-operator"); token != "" || !errors.Is(err, telemetry.ErrUnavailable) || strings.Contains(fmt.Sprint(err), "private") {
		t.Fatal("failed mint leaked secret/error", err)
	}
	remove()
	token := mintBootstrap(t, f, request)
	remove = failIdentityAudit(t, f, "CERTIFICATE_ISSUED")
	if bundle, err := f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, token, request, issuer); bundle != (nodeidentity.CertificateBundle{}) || !errors.Is(err, telemetry.ErrUnavailable) {
		t.Fatal("failed consume returned candidate", err)
	}
	remove()
	var consumed int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM gp06f_node_bootstrap WHERE enrollment_id=$1 AND consumed_at IS NOT NULL`, f.request.EnrollmentID).Scan(&consumed)
	if consumed != 0 {
		t.Fatal("rollback consumed token")
	}
	if _, err := f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, token, request, issuer); err != nil {
		t.Fatal("rolled back token cannot retry", err)
	}
}

func TestNodeBootstrapRotationRevocationBeforeReceipt(t *testing.T) {
	for _, compromise := range []bool{false, true} {
		t.Run(fmt.Sprint(compromise), func(t *testing.T) {
			f, request, issuer := nodeBootstrapFixture(t)
			ctx := context.Background()
			consumed := mintBootstrap(t, f, request)
			pending := mintBootstrap(t, f, request)
			bundle, err := f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, consumed, request, issuer)
			if err != nil {
				t.Fatal(err)
			}
			public, _, _ := ed25519.GenerateKey(rand.Reader)
			if _, err = f.store.RotateKey(ctx, f.request.ClusterID, f.request.EnrollmentID, 1, "new-key", base64.RawStdEncoding.EncodeToString(public), "fixture-operator", compromise); err != nil {
				t.Fatal(err)
			}
			replay, err := f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, consumed, request, nil)
			if compromise {
				if !errors.Is(err, telemetry.ErrUnauthorized) {
					t.Fatal("compromise replay allowed", err)
				}
			} else if err != nil || replay != bundle {
				t.Fatal("verify-only immutable historical retrieval", err)
			}
			if _, err = f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, pending, request, issuer); !errors.Is(err, telemetry.ErrUnauthorized) {
				t.Fatal("old key received new certificate", err)
			}
			if _, err = f.store.RevokeEnrollment(ctx, f.request.ClusterID, f.request.EnrollmentID, 2, "fixture-operator"); err != nil {
				t.Fatal(err)
			}
			if _, err = f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, consumed, request, nil); !errors.Is(err, telemetry.ErrUnauthorized) {
				t.Fatal("revoked receipt bypass", err)
			}
		})
	}
}

func TestNodeBootstrapExpiredAndBoundedPending(t *testing.T) {
	f, request, issuer := nodeBootstrapFixture(t)
	ctx := context.Background()
	token, hash, err := nodeidentity.NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(request)
	f.exec(t, `INSERT INTO gp06f_node_bootstrap(token_hash,enrollment_id,key_id,enrollment_revision,minted_control_revision,csr_sha256,spki_sha256,request,minted_at,expires_at) VALUES($1,$2,$3,1,1,$4,$5,$6,clock_timestamp()-interval '11 minutes',clock_timestamp()-interval '1 minute' - interval '1 second')`, hash, f.request.EnrollmentID, request.Scope.KeyID, request.CSRSHA256, request.SPKISHA256, body)
	if _, err = f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, token, request, issuer); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("expired first-use accepted", err)
	}
	for range 8 {
		mintBootstrap(t, f, request)
	}
	if token, err = f.store.MintNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, 1, "fixture-operator"); token != "" || !errors.Is(err, telemetry.ErrBackpressure) {
		t.Fatal("pending token budget bypass", err)
	}
}

func TestNodeIdentityMigrationRollbackPreservesIssuedHistory(t *testing.T) {
	f, request, issuer := nodeBootstrapFixture(t)
	ctx := context.Background()
	token := mintBootstrap(t, f, request)
	if _, err := f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, token, request, issuer); err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/000078_node_identity.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("../../../migrations/000078_node_identity.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, _ = tx.Exec(ctx, `SAVEPOINT identity_rollback`)
	if _, err = tx.Exec(ctx, string(down)); err == nil {
		t.Fatal("populated rollback deleted issuance history")
	}
	_, _ = tx.Exec(ctx, `ROLLBACK TO identity_rollback`)
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM gp06f_node_bootstrap WHERE enrollment_id=$1 AND consumed_at IS NOT NULL`, f.request.EnrollmentID).Scan(&count); err != nil || count != 1 {
		t.Fatal("rollback lost issuance")
	}
	if _, err = tx.Exec(ctx, `TRUNCATE gp06f_node_bootstrap CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, string(down)); err != nil {
		t.Fatal("empty rollback", err)
	}
	if _, err = tx.Exec(ctx, string(up)); err != nil {
		t.Fatal("identity re-expansion", err)
	}
}

func TestNodeBootstrapExpiredCertificateAndRetainedBudget(t *testing.T) {
	f, request, issuer := nodeBootstrapFixture(t)
	ctx := context.Background()
	token, hash, err := nodeidentity.NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	issued := f.now.Add(-25 * time.Hour).Truncate(time.Second)
	bundle, err := issuer.Issue(request, issued, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(request)
	encoded, _ := json.Marshal(bundle)
	f.exec(t, `INSERT INTO gp06f_node_bootstrap(token_hash,enrollment_id,key_id,enrollment_revision,minted_control_revision,csr_sha256,spki_sha256,request,minted_at,expires_at,consumed_at,certificate_expires_at,bundle) VALUES($1,$2,$3,1,1,$4,$5,$6,$7,$8,$9,$10,$11)`, hash, f.request.EnrollmentID, request.Scope.KeyID, request.CSRSHA256, request.SPKISHA256, body, issued.Add(-time.Minute), issued.Add(9*time.Minute), issued, bundle.NotAfter, encoded)
	if got, err := f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, token, request, nil); got != (nodeidentity.CertificateBundle{}) || !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("expired original cert retrieved", err)
	}
	// Immutable historical fixtures are already expired: they do not consume
	// the pending8 budget, but remain counted in the independent retained cap.
	f.exec(t, `INSERT INTO gp06f_node_bootstrap(token_hash,enrollment_id,key_id,enrollment_revision,minted_control_revision,csr_sha256,spki_sha256,request,minted_at,expires_at) SELECT md5('fixture-history-'||i::text)||md5('fixture-history-'||i::text),$1,$2,1,1,$3,$4,$5,clock_timestamp()-interval '12 minutes',clock_timestamp()-interval '3 minutes' FROM generate_series(1,255) i`, f.request.EnrollmentID, request.Scope.KeyID, request.CSRSHA256, request.SPKISHA256, body)
	if token, err := f.store.MintNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, 1, "fixture-operator"); token != "" || !errors.Is(err, telemetry.ErrBackpressure) {
		t.Fatal("retained budget bypass", err)
	}
}

func TestNodeBootstrapCurrentInventoryBeforeMatchingReceipt(t *testing.T) {
	f, request, issuer := nodeBootstrapFixture(t)
	ctx := context.Background()
	token := mintBootstrap(t, f, request)
	if _, err := f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, token, request, issuer); err != nil {
		t.Fatal(err)
	}
	goodput, _ := storepg.NewGoodputStore(f.pool)
	var at time.Time
	_ = f.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at)
	if _, err := goodput.RecordExpectedInventoryRevision(ctx, domain.InventoryRevision{ID: domain.InventoryRevisionID(f.request.InventoryRevisionID + "-replacement"), SchemaVersion: 1, ClusterID: f.request.ClusterID, SourceID: f.request.SourceIDs[0], SourceAt: at, ObservedAt: at, EffectiveAt: at, Entities: []domain.EntityIdentity{{ClusterID: f.request.ClusterID, Kind: domain.EntityNode, NodeID: f.request.NodeID}}}); err != nil {
		t.Fatal(err)
	}
	if bundle, err := f.store.ConsumeNodeBootstrap(ctx, f.request.ClusterID, f.request.GatewayCollectorID, token, request, nil); bundle != (nodeidentity.CertificateBundle{}) || !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("superseded authority bypassed via cert receipt", err)
	}
}

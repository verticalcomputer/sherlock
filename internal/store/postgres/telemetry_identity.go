package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

const maxNodeBootstrapHistory = 256
const maxNodeBootstrapPending = 8

func nodeIdentityError(err error) error {
	if errors.Is(err, nodeidentity.ErrInvalid) {
		return telemetry.ErrInvalid
	}
	if errors.Is(err, nodeidentity.ErrUnauthorized) {
		return telemetry.ErrUnauthorized
	}
	return telemetrySafeError(err)
}

// MintNodeBootstrap is protected local operator work, not a collector endpoint.
// Only the caller receives the secret after commit. Failed commits return none.
func (s *TelemetryStore) MintNodeBootstrap(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, request nodeidentity.Request, expectedControlRevision int64, actor string) (token string, err error) {
	if expectedControlRevision < 1 || !monitoringID(actor, 128) {
		return "", telemetry.ErrInvalid
	}
	if _, err = nodeidentity.ValidateRequest(request); err != nil {
		return "", nodeIdentityError(err)
	}
	raw, hash, err := nodeidentity.NewBootstrapToken()
	if err != nil {
		return "", nodeIdentityError(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = retryTelemetryTransaction(ctx, func() error {
		return s.mintNodeBootstrap(ctx, cluster, collector, request, expectedControlRevision, actor, hash)
	})
	if err != nil {
		return "", nodeIdentityError(err)
	}
	return raw, nil
}

func (s *TelemetryStore) mintNodeBootstrap(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, request nodeidentity.Request, expected int64, actor, hash string) error {
	tx, err := beginTelemetryTx(ctx, s.pool)
	if err != nil {
		return err
	}
	defer rollbackMonitoringTx(tx)
	var at time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return err
	}
	grant, err := loadTelemetryGrant(ctx, tx, cluster, collector, request.Scope.EnrollmentID, at, true)
	if err != nil {
		return err
	}
	if grant.ControlRevision != expected {
		return telemetry.ErrConflict
	}
	if err = nodeidentity.ValidateRequestForGrant(request, grant, at, false); err != nil {
		return err
	}
	// Sample at after authority locks. A contended lock cannot extend the token.
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return err
	}
	if err = validateTelemetryAuthority(ctx, tx, grant, at); err != nil {
		return err
	}
	var retained, pending int
	if err = tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE consumed_at IS NULL AND expires_at>$2) FROM (SELECT consumed_at,expires_at FROM gp06f_node_bootstrap WHERE enrollment_id=$1 LIMIT 257) bounded`, grant.EnrollmentID, at).Scan(&retained, &pending); err != nil {
		return err
	}
	if retained >= maxNodeBootstrapHistory || pending >= maxNodeBootstrapPending {
		return telemetry.ErrBackpressure
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > nodeidentity.MaxRequestBytes {
		return telemetry.ErrInvalid
	}
	if _, err = tx.Exec(ctx, `INSERT INTO gp06f_node_bootstrap(token_hash,enrollment_id,key_id,enrollment_revision,minted_control_revision,csr_sha256,spki_sha256,request,minted_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, hash, grant.EnrollmentID, request.Scope.KeyID, grant.EnrollmentRevision, grant.ControlRevision, request.CSRSHA256, request.SPKISHA256, body, at, at.Add(nodeidentity.MaxBootstrapLifetime)); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO gp06f_node_identity_audit(token_hash,enrollment_id,control_revision,action,actor,actor_kind,occurred_at) VALUES($1,$2,$3,'BOOTSTRAP_MINTED',$4,'LOCAL_OPERATOR',$5)`, hash, grant.EnrollmentID, grant.ControlRevision, actor, at); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ConsumeNodeBootstrap atomically stores the one issued public bundle. Exact
// committed retries need no issuer, but must revalidate current authority first.
func (s *TelemetryStore) ConsumeNodeBootstrap(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, token string, request nodeidentity.Request, issuer *nodeidentity.Issuer) (bundle nodeidentity.CertificateBundle, err error) {
	if _, err = nodeidentity.ValidateRequest(request); err != nil {
		return bundle, nodeIdentityError(err)
	}
	hash, err := nodeidentity.BootstrapTokenHash(token)
	if err != nil {
		return bundle, nodeIdentityError(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = retryTelemetryTransaction(ctx, func() error {
		var e error
		bundle, e = s.consumeNodeBootstrap(ctx, cluster, collector, hash, request, issuer)
		return e
	})
	if err != nil {
		return nodeidentity.CertificateBundle{}, nodeIdentityError(err)
	}
	return bundle, nil
}

func (s *TelemetryStore) consumeNodeBootstrap(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, hash string, request nodeidentity.Request, issuer *nodeidentity.Issuer) (nodeidentity.CertificateBundle, error) {
	tx, err := beginTelemetryTx(ctx, s.pool)
	if err != nil {
		return nodeidentity.CertificateBundle{}, err
	}
	defer rollbackMonitoringTx(tx)
	var at time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return nodeidentity.CertificateBundle{}, err
	}
	grant, err := loadTelemetryGrant(ctx, tx, cluster, collector, request.Scope.EnrollmentID, at, true)
	if err != nil {
		return nodeidentity.CertificateBundle{}, err
	}
	// Verify non-revoked scope/key before token lookup, including matching replay.
	if err = nodeidentity.ValidateRequestForGrant(request, grant, at, true); err != nil {
		return nodeidentity.CertificateBundle{}, err
	}
	var enrollment, key, csr, spki string
	var revision int64
	var expires time.Time
	var consumed, certificateExpires *time.Time
	var storedRequest, storedBundle []byte
	err = tx.QueryRow(ctx, `SELECT enrollment_id,key_id,enrollment_revision,csr_sha256,spki_sha256,expires_at,consumed_at,certificate_expires_at,request,bundle FROM gp06f_node_bootstrap WHERE token_hash=$1 FOR UPDATE`, hash).Scan(&enrollment, &key, &revision, &csr, &spki, &expires, &consumed, &certificateExpires, &storedRequest, &storedBundle)
	if err != nil {
		return nodeidentity.CertificateBundle{}, err
	}
	var original nodeidentity.Request
	if json.Unmarshal(storedRequest, &original) != nil {
		return nodeidentity.CertificateBundle{}, telemetry.ErrUnavailable
	}
	if enrollment != grant.EnrollmentID || key != request.Scope.KeyID || revision != grant.EnrollmentRevision || csr != request.CSRSHA256 || spki != request.SPKISHA256 || original.Scope != request.Scope || original.PublicKeyBase64 != request.PublicKeyBase64 {
		return nodeidentity.CertificateBundle{}, telemetry.ErrUnauthorized
	}
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return nodeidentity.CertificateBundle{}, err
	}
	if err = validateTelemetryAuthority(ctx, tx, grant, at); err != nil {
		return nodeidentity.CertificateBundle{}, err
	}
	if consumed != nil {
		if certificateExpires == nil || !at.Before(*certificateExpires) {
			return nodeidentity.CertificateBundle{}, telemetry.ErrUnauthorized
		}
		var bundle nodeidentity.CertificateBundle
		if json.Unmarshal(storedBundle, &bundle) != nil || bundle.Scope != request.Scope || bundle.CSRSHA256 != csr || bundle.SPKISHA256 != spki || !bundle.NotAfter.Equal(*certificateExpires) {
			return nodeidentity.CertificateBundle{}, telemetry.ErrUnavailable
		}
		return bundle, tx.Commit(ctx)
	}
	if !at.Before(expires) {
		return nodeidentity.CertificateBundle{}, telemetry.ErrUnauthorized
	}
	if err = nodeidentity.ValidateRequestForGrant(request, grant, at, false); err != nil {
		return nodeidentity.CertificateBundle{}, err
	}
	if issuer == nil {
		return nodeidentity.CertificateBundle{}, telemetry.ErrUnavailable
	}
	bundle, err := issuer.Issue(original, at, nodeidentity.MaxCertificateLifetime)
	if err != nil {
		return nodeidentity.CertificateBundle{}, err
	}
	body, err := json.Marshal(bundle)
	if err != nil || len(body) > nodeidentity.MaxBundleBytes {
		return nodeidentity.CertificateBundle{}, telemetry.ErrUnavailable
	}
	if _, err = tx.Exec(ctx, `UPDATE gp06f_node_bootstrap SET consumed_at=$2,certificate_expires_at=$3,bundle=$4 WHERE token_hash=$1 AND consumed_at IS NULL`, hash, at, bundle.NotAfter, body); err != nil {
		return nodeidentity.CertificateBundle{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO gp06f_node_identity_audit(token_hash,enrollment_id,control_revision,action,actor,actor_kind,occurred_at) VALUES($1,$2,$3,'CERTIFICATE_ISSUED',$4,'AUTHENTICATED_COLLECTOR',$5)`, hash, grant.EnrollmentID, grant.ControlRevision, collector, at); err != nil {
		return nodeidentity.CertificateBundle{}, err
	}
	return bundle, tx.Commit(ctx)
}

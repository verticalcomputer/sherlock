package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func (s *CollectorControlStore) CreateBootstrapKey(ctx context.Context, keyID string, clusterID domain.ClusterID, tokenHash [32]byte, expiresAt time.Time) error {
	if keyID == "" || clusterID == "" || expiresAt.IsZero() {
		return fmt.Errorf("bootstrap key, cluster, and expiry are required")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO collector_bootstrap_keys (bootstrap_key_id, cluster_id, token_hash, expires_at)
		VALUES ($1,$2,$3,$4)`, keyID, clusterID, tokenHash[:], expiresAt.UTC())
	if err != nil {
		return fmt.Errorf("create collector bootstrap key %s: %w", keyID, err)
	}
	return nil
}

func (s *CollectorControlStore) FindBootstrapGrant(ctx context.Context, tokenHash [32]byte) (collectorcontrol.BootstrapGrant, error) {
	var grant collectorcontrol.BootstrapGrant
	err := s.pool.QueryRow(ctx, `
		SELECT bootstrap_key_id, cluster_id, expires_at
		FROM collector_bootstrap_keys
		WHERE token_hash=$1 AND consumed_at IS NULL AND expires_at > clock_timestamp()`, tokenHash[:]).Scan(
		&grant.BootstrapKeyID, &grant.ClusterID, &grant.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return collectorcontrol.BootstrapGrant{}, collectorcontrol.ErrBootstrapUnavailable
	}
	if err != nil {
		return collectorcontrol.BootstrapGrant{}, fmt.Errorf("find collector bootstrap grant: %w", err)
	}
	grant.ExpiresAt = grant.ExpiresAt.UTC()
	return grant, nil
}

func (s *CollectorControlStore) ConsumeBootstrapAndEnroll(ctx context.Context, grant collectorcontrol.BootstrapGrant, tokenHash [32]byte, collectorID domain.CollectorID, metadata collectorcontrol.CollectorMetadata, identity collectorcontrol.IssuedIdentity) error {
	if grant.BootstrapKeyID == "" || grant.ClusterID == "" || collectorID == "" || identity.Serial == "" {
		return fmt.Errorf("bootstrap grant, collector, and identity are required")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin collector enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO collectors (
			collector_id, cluster_id, display_name, status, version, build_commit,
			protocol_min, protocol_max, operating_system, architecture,
			identity_serial, identity_not_after
		) VALUES ($1,$2,$3,'ACTIVE',$4,$5,$6,$7,$8,$9,$10,$11)`,
		collectorID, grant.ClusterID, metadata.DisplayName, metadata.Version, metadata.BuildCommit,
		metadata.ProtocolMin, metadata.ProtocolMax, metadata.OperatingSystem, metadata.Architecture,
		identity.Serial, identity.NotAfter.UTC()); err != nil {
		return fmt.Errorf("insert enrolled collector %s: %w", collectorID, err)
	}
	if err := insertCollectorIdentity(ctx, tx, collectorID, identity); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `
		UPDATE collector_bootstrap_keys
		SET consumed_at=clock_timestamp(), collector_id=$3
		WHERE bootstrap_key_id=$1 AND token_hash=$2 AND cluster_id=$4
		  AND consumed_at IS NULL AND expires_at > clock_timestamp()`,
		grant.BootstrapKeyID, tokenHash[:], collectorID, grant.ClusterID)
	if err != nil {
		return fmt.Errorf("consume collector bootstrap key: %w", err)
	}
	if result.RowsAffected() != 1 {
		return collectorcontrol.ErrBootstrapUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit collector enrollment: %w", err)
	}
	return nil
}

func (s *CollectorControlStore) ActiveCollectorCluster(ctx context.Context, collectorID domain.CollectorID) (domain.ClusterID, error) {
	var clusterID domain.ClusterID
	err := s.pool.QueryRow(ctx, `
		SELECT cluster_id FROM collectors
		WHERE collector_id=$1 AND status='ACTIVE'`, collectorID).Scan(&clusterID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", collectorcontrol.ErrCollectorInactive
	}
	if err != nil {
		return "", fmt.Errorf("load active collector %s: %w", collectorID, err)
	}
	return clusterID, nil
}

func (s *CollectorControlStore) AuthenticateCollectorIdentity(ctx context.Context, serial string, fingerprint [32]byte) (collectorcontrol.AuthenticatedIdentity, error) {
	if serial == "" {
		return collectorcontrol.AuthenticatedIdentity{}, collectorcontrol.ErrCollectorInactive
	}
	var identity collectorcontrol.AuthenticatedIdentity
	err := s.pool.QueryRow(ctx, `
		SELECT i.collector_id, c.cluster_id
		FROM collector_identities i
		JOIN collectors c USING (collector_id)
		WHERE i.certificate_serial=$1 AND i.certificate_sha256=$2
		  AND i.revoked_at IS NULL
		  AND i.not_before <= clock_timestamp() AND i.not_after > clock_timestamp()
		  AND c.status='ACTIVE'`, serial, fingerprint[:]).Scan(&identity.CollectorID, &identity.ClusterID)
	if errors.Is(err, pgx.ErrNoRows) {
		return collectorcontrol.AuthenticatedIdentity{}, collectorcontrol.ErrCollectorInactive
	}
	if err != nil {
		return collectorcontrol.AuthenticatedIdentity{}, fmt.Errorf("authenticate collector identity: %w", err)
	}
	return identity, nil
}

func (s *CollectorControlStore) RecordRenewedIdentity(ctx context.Context, collectorID domain.CollectorID, identity collectorcontrol.IssuedIdentity) error {
	if collectorID == "" || identity.Serial == "" {
		return fmt.Errorf("collector and renewed identity are required")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin collector identity renewal: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var currentSerial string
	err = tx.QueryRow(ctx, `
		SELECT identity_serial FROM collectors
		WHERE collector_id=$1 AND status='ACTIVE' FOR UPDATE`, collectorID).Scan(&currentSerial)
	if errors.Is(err, pgx.ErrNoRows) {
		return collectorcontrol.ErrCollectorInactive
	}
	if err != nil {
		return fmt.Errorf("lock collector %s for renewal: %w", collectorID, err)
	}
	if currentSerial != "" {
		if _, err := tx.Exec(ctx, `
			UPDATE collector_identities SET superseded_at=COALESCE(superseded_at, clock_timestamp())
			WHERE certificate_serial=$1 AND collector_id=$2`, currentSerial, collectorID); err != nil {
			return fmt.Errorf("supersede collector identity %s: %w", currentSerial, err)
		}
	}
	if err := insertCollectorIdentity(ctx, tx, collectorID, identity); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE collectors SET identity_serial=$2, identity_not_after=$3
		WHERE collector_id=$1`, collectorID, identity.Serial, identity.NotAfter.UTC()); err != nil {
		return fmt.Errorf("activate renewed identity for collector %s: %w", collectorID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit collector identity renewal: %w", err)
	}
	return nil
}

func (s *CollectorControlStore) RevokeCollector(ctx context.Context, collectorID domain.CollectorID) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin collector revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var status domain.CollectorStatus
	err = tx.QueryRow(ctx, `SELECT status FROM collectors WHERE collector_id=$1 FOR UPDATE`, collectorID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return collectorcontrol.ErrCollectorInactive
	}
	if err != nil {
		return fmt.Errorf("lock collector %s for revocation: %w", collectorID, err)
	}
	if status == domain.CollectorRevoked {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE collectors SET status='REVOKED', revoked_at=clock_timestamp()
		WHERE collector_id=$1`, collectorID); err != nil {
		return fmt.Errorf("revoke collector %s: %w", collectorID, err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE collector_identities SET revoked_at=COALESCE(revoked_at, clock_timestamp())
		WHERE collector_id=$1`, collectorID); err != nil {
		return fmt.Errorf("revoke identities for collector %s: %w", collectorID, err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE collector_work_attempts SET status='REJECTED', completed_at=clock_timestamp()
		WHERE collector_id=$1 AND status IN ('CLAIMED','STARTED')`, collectorID); err != nil {
		return fmt.Errorf("reject active work for collector %s: %w", collectorID, err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE collector_work_items w SET status='AVAILABLE'
		WHERE w.status='LEASED' AND EXISTS (
			SELECT 1 FROM collector_work_attempts a WHERE a.work_id=w.work_id AND a.collector_id=$1
		)
		AND NOT EXISTS (
			SELECT 1 FROM collector_work_attempts a WHERE a.work_id=w.work_id AND a.status IN ('CLAIMED','STARTED')
		)`, collectorID); err != nil {
		return fmt.Errorf("release work from collector %s: %w", collectorID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit collector revocation: %w", err)
	}
	return nil
}

func insertCollectorIdentity(ctx context.Context, tx pgx.Tx, collectorID domain.CollectorID, identity collectorcontrol.IssuedIdentity) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO collector_identities (
			certificate_serial, collector_id, certificate_sha256, not_before, not_after
		) VALUES ($1,$2,$3,$4,$5)`, identity.Serial, collectorID, identity.Fingerprint[:],
		identity.NotBefore.UTC(), identity.NotAfter.UTC())
	if err != nil {
		return fmt.Errorf("insert identity for collector %s: %w", collectorID, err)
	}
	return nil
}

package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type PostgreSQLStore struct {
	pool *pgxpool.Pool
}

func NewPostgreSQLStore(pool *pgxpool.Pool) (*PostgreSQLStore, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL pool is required")
	}
	return &PostgreSQLStore{pool: pool}, nil
}

func (s *PostgreSQLStore) CreateKey(ctx context.Context, key StoredKey) error {
	if key.PublicID == "" || key.ClusterID == "" || len(key.Capabilities) == 0 {
		return errors.New("complete API-key record is required")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return errors.New("begin API-key creation")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO api_keys (public_key_id, cluster_id, label, secret_hash, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6)`, key.PublicID, key.ClusterID, key.Label, key.SecretHash[:], key.ExpiresAt.UTC(), key.CreatedAt.UTC()); err != nil {
		return fmt.Errorf("insert API-key metadata: %w", err)
	}
	for _, capability := range key.Capabilities {
		if _, err := tx.Exec(ctx, `INSERT INTO api_key_capabilities (public_key_id, capability) VALUES ($1,$2)`, key.PublicID, capability); err != nil {
			return fmt.Errorf("insert API-key capability: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.New("commit API-key creation")
	}
	return nil
}

func (s *PostgreSQLStore) FindKey(ctx context.Context, publicID string) (StoredKey, error) {
	var result StoredKey
	var hash []byte
	err := s.pool.QueryRow(ctx, `
		SELECT public_key_id, cluster_id, label, secret_hash, created_at, expires_at, last_used_at, revoked_at
		FROM api_keys WHERE public_key_id=$1`, publicID).Scan(
		&result.PublicID, &result.ClusterID, &result.Label, &hash, &result.CreatedAt,
		&result.ExpiresAt, &result.LastUsedAt, &result.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredKey{}, ErrKeyNotFound
	}
	if err != nil || len(hash) != len(result.SecretHash) {
		return StoredKey{}, errors.New("load API-key metadata")
	}
	copy(result.SecretHash[:], hash)
	rows, err := s.pool.Query(ctx, `SELECT capability FROM api_key_capabilities WHERE public_key_id=$1 ORDER BY capability`, publicID)
	if err != nil {
		return StoredKey{}, errors.New("load API-key capabilities")
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return StoredKey{}, errors.New("scan API-key capability")
		}
		capability, err := ParseCapability(raw)
		if err != nil {
			return StoredKey{}, errors.New("stored API-key capability is invalid")
		}
		result.Capabilities = append(result.Capabilities, capability)
	}
	if err := rows.Err(); err != nil || len(result.Capabilities) == 0 {
		return StoredKey{}, errors.New("load API-key capabilities")
	}
	normalizeKeyTimes(&result.Key)
	return result, nil
}

func (s *PostgreSQLStore) MarkKeyUsed(ctx context.Context, publicID string, usedAt time.Time) error {
	command, err := s.pool.Exec(ctx, `
		UPDATE api_keys SET last_used_at=GREATEST(COALESCE(last_used_at, $2), $2)
		WHERE public_key_id=$1 AND revoked_at IS NULL AND expires_at > $2`, publicID, usedAt.UTC())
	if err != nil {
		return errors.New("record API-key use")
	}
	if command.RowsAffected() != 1 {
		return ErrKeyNotFound
	}
	return nil
}

func (s *PostgreSQLStore) ListKeys(ctx context.Context, clusterID domain.ClusterID) ([]Key, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT k.public_key_id, k.cluster_id, k.label, k.created_at, k.expires_at, k.last_used_at, k.revoked_at, c.capability
		FROM api_keys k JOIN api_key_capabilities c USING (public_key_id)
		WHERE k.cluster_id=$1 ORDER BY k.created_at DESC, k.public_key_id, c.capability`, clusterID)
	if err != nil {
		return nil, errors.New("list API keys")
	}
	defer rows.Close()
	var result []Key
	for rows.Next() {
		var row Key
		var raw string
		if err := rows.Scan(&row.PublicID, &row.ClusterID, &row.Label, &row.CreatedAt, &row.ExpiresAt, &row.LastUsedAt, &row.RevokedAt, &raw); err != nil {
			return nil, errors.New("scan API-key listing")
		}
		capability, err := ParseCapability(raw)
		if err != nil {
			return nil, errors.New("stored API-key capability is invalid")
		}
		if len(result) == 0 || result[len(result)-1].PublicID != row.PublicID {
			normalizeKeyTimes(&row)
			result = append(result, row)
		}
		result[len(result)-1].Capabilities = append(result[len(result)-1].Capabilities, capability)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("list API keys")
	}
	return result, nil
}

func (s *PostgreSQLStore) RevokeKey(ctx context.Context, clusterID domain.ClusterID, publicID string, revokedAt time.Time) (bool, error) {
	command, err := s.pool.Exec(ctx, `
		UPDATE api_keys SET revoked_at=COALESCE(revoked_at, $3)
		WHERE public_key_id=$1 AND cluster_id=$2`, publicID, clusterID, revokedAt.UTC())
	if err != nil {
		return false, errors.New("revoke API key")
	}
	return command.RowsAffected() == 1, nil
}

func normalizeKeyTimes(key *Key) {
	key.CreatedAt = key.CreatedAt.UTC()
	key.ExpiresAt = key.ExpiresAt.UTC()
	if key.LastUsedAt != nil {
		value := key.LastUsedAt.UTC()
		key.LastUsedAt = &value
	}
	if key.RevokedAt != nil {
		value := key.RevokedAt.UTC()
		key.RevokedAt = &value
	}
}

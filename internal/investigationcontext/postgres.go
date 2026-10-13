package investigationcontext

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct{ pool *pgxpool.Pool }

func NewPostgresStore(pool *pgxpool.Pool) (*PostgresStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("context checkpoint PostgreSQL pool is required")
	}
	return &PostgresStore{pool: pool}, nil
}

func (store *PostgresStore) LoadLatestCheckpoint(ctx context.Context, investigationID string, beforeVersion int) (Checkpoint, bool, error) {
	var encoded []byte
	err := store.pool.QueryRow(ctx, `SELECT checkpoint_json FROM investigation_context_checkpoints WHERE investigation_id=$1 AND ledger_version < $2 ORDER BY ledger_version DESC LIMIT 1`, investigationID, beforeVersion).Scan(&encoded)
	if err == pgx.ErrNoRows {
		return Checkpoint{}, false, nil
	}
	if err != nil {
		return Checkpoint{}, false, err
	}
	var projection CheckpointProjection
	if err := json.Unmarshal(encoded, &projection); err != nil {
		return Checkpoint{}, false, fmt.Errorf("decode context checkpoint: %w", err)
	}
	checkpoint, err := sealCheckpoint(projection)
	return checkpoint, err == nil, err
}

func (store *PostgresStore) RecordContextCheckpoint(ctx context.Context, record ContextRecord) error {
	if record.Selected == nil {
		record.Selected = []string{}
	}
	if record.Exclusions == nil {
		record.Exclusions = []EvidenceExclusion{}
	}
	selected, _ := json.Marshal(record.Selected)
	exclusions, _ := json.Marshal(record.Exclusions)
	var deltaJSON []byte
	var parent string
	if record.Delta != nil {
		deltaJSON, _ = json.Marshal(record.Delta)
		parent = record.Delta.ParentDigest
	}
	command, err := store.pool.Exec(ctx, `INSERT INTO investigation_context_checkpoints(investigation_id,cluster_id,ledger_version,checkpoint_digest,parent_digest,checkpoint_json,delta_json,selected_evidence_ids,exclusions,created_at) VALUES($1,$2,$3,decode($4,'hex'),NULLIF($5,''),$6,$7,$8,$9,clock_timestamp()) ON CONFLICT(investigation_id,ledger_version) DO NOTHING`, record.Checkpoint.Projection.InvestigationID, record.Checkpoint.Projection.ClusterID, record.Checkpoint.Projection.LedgerVersion, record.Checkpoint.Digest, parent, record.Checkpoint.CanonicalJSON, deltaJSON, selected, exclusions)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 1 {
		return nil
	}
	var digest []byte
	if err := store.pool.QueryRow(ctx, `SELECT checkpoint_digest FROM investigation_context_checkpoints WHERE investigation_id=$1 AND ledger_version=$2`, record.Checkpoint.Projection.InvestigationID, record.Checkpoint.Projection.LedgerVersion).Scan(&digest); err != nil {
		return err
	}
	if fmt.Sprintf("%x", digest) != record.Checkpoint.Digest {
		return fmt.Errorf("context checkpoint idempotency conflict")
	}
	return nil
}

var _ CheckpointStore = (*PostgresStore)(nil)

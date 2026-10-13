package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type ModelCallAuditStore struct{ pool *pgxpool.Pool }

func NewModelCallAuditStore(pool *pgxpool.Pool) (*ModelCallAuditStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("model call audit pool is required")
	}
	return &ModelCallAuditStore{pool: pool}, nil
}

func (store *ModelCallAuditStore) ReserveModelCall(ctx context.Context, investigationID domain.InvestigationID, clusterID domain.ClusterID, callKey string, kind application.ModelCallKind, now, expiresAt time.Time) error {
	if investigationID == "" || clusterID == "" || callKey == "" || (kind != application.ModelCallPlanning && kind != application.ModelCallSynthesis) || !expiresAt.After(now) {
		return fmt.Errorf("model call reservation is invalid")
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin model call reservation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	command, err := tx.Exec(ctx, `INSERT INTO investigation_model_call_reservations (investigation_id,call_key,cluster_id,call_kind,status,reserved_at,expires_at) VALUES ($1,$2,$3,$4,'RESERVED',$5,$6) ON CONFLICT DO NOTHING`, investigationID, callKey, clusterID, kind, now.UTC(), expiresAt.UTC())
	if err != nil {
		return fmt.Errorf("reserve model call: %w", err)
	}
	if command.RowsAffected() == 1 {
		return tx.Commit(ctx)
	}
	var status application.ModelCallReservationStatus
	var expiry time.Time
	if err := tx.QueryRow(ctx, `SELECT status,expires_at FROM investigation_model_call_reservations WHERE investigation_id=$1 AND call_key=$2 FOR UPDATE`, investigationID, callKey).Scan(&status, &expiry); err != nil {
		return fmt.Errorf("load model call reservation: %w", err)
	}
	if status == application.ModelCallReserved && !expiry.After(now) {
		_, err = tx.Exec(ctx, `UPDATE investigation_model_call_reservations SET status='OUTCOME_UNKNOWN',completed_at=$3 WHERE investigation_id=$1 AND call_key=$2 AND status='RESERVED'`, investigationID, callKey, now.UTC())
		if err != nil {
			return fmt.Errorf("mark uncertain model call: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		return application.ErrModelCallOutcomeUnknown
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if status == application.ModelCallReserved {
		return application.ErrModelCallInFlight
	}
	return application.ErrModelCallAlreadyAttempted
}

func (store *ModelCallAuditStore) CompleteModelCall(ctx context.Context, investigationID domain.InvestigationID, callKey string, status application.ModelCallReservationStatus, now time.Time) error {
	if status != application.ModelCallSucceededState && status != application.ModelCallRejectedState && status != application.ModelCallFailedState {
		return fmt.Errorf("model call completion status is invalid")
	}
	command, err := store.pool.Exec(ctx, `UPDATE investigation_model_call_reservations SET status=$3,completed_at=$4 WHERE investigation_id=$1 AND call_key=$2 AND status='RESERVED'`, investigationID, callKey, status, now.UTC())
	if err != nil {
		return fmt.Errorf("complete model call reservation: %w", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("complete model call reservation: %w", application.ErrModelCallAlreadyAttempted)
	}
	return nil
}

func (store *ModelCallAuditStore) AppendModelCallAudit(ctx context.Context, audit application.ModelCallAudit) error {
	if err := audit.Validate(); err != nil {
		return err
	}
	command, err := store.pool.Exec(ctx, `INSERT INTO investigation_model_calls (call_id,call_key,cluster_id,investigation_id,call_kind,provider,model,model_config_version,prompt_schema_version,tool_schema_version,input_tokens,output_tokens,cost_microunits,latency_milliseconds,outcome,reason_code,input_evidence_id,output_evidence_id,occurred_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NULLIF($17,''),NULLIF($18,''),$19) ON CONFLICT (investigation_id,call_key) DO NOTHING`,
		audit.CallID, audit.CallKey, audit.ClusterID, audit.InvestigationID, audit.Kind,
		audit.Provider, audit.Model, audit.ModelConfigVersion, audit.PromptSchemaVersion,
		audit.ToolSchemaVersion, audit.InputTokens, audit.OutputTokens, audit.CostMicros,
		audit.Latency.Milliseconds(), audit.Outcome, audit.ReasonCode,
		audit.InputEvidenceID, audit.OutputEvidenceID, audit.OccurredAt.UTC())
	if err != nil {
		return fmt.Errorf("append model call audit: %w", err)
	}
	if command.RowsAffected() == 0 {
		return nil
	}
	return nil
}

func (store *ModelCallAuditStore) EnsureModelAuditSource(ctx context.Context, clusterID domain.ClusterID, sourceID domain.SourceID) error {
	if clusterID == "" || sourceID == "" {
		return fmt.Errorf("model audit source identity is required")
	}
	command, err := store.pool.Exec(ctx, `INSERT INTO sources (source_id,cluster_id,kind,display_name) SELECT $1,$2,'model','Model call audit' FROM clusters WHERE cluster_id=$2 ON CONFLICT (source_id) DO NOTHING`, sourceID, clusterID)
	if err != nil {
		return fmt.Errorf("ensure model audit source: %w", err)
	}
	if command.RowsAffected() == 1 {
		return nil
	}
	var storedCluster domain.ClusterID
	var kind string
	if err := store.pool.QueryRow(ctx, `SELECT cluster_id,kind FROM sources WHERE source_id=$1`, sourceID).Scan(&storedCluster, &kind); err != nil {
		return fmt.Errorf("load model audit source: %w", err)
	}
	if storedCluster != clusterID || kind != "model" {
		return fmt.Errorf("model audit source attribution conflict")
	}
	return nil
}

func (store *ModelCallAuditStore) HasModelCallAudit(ctx context.Context, investigationID domain.InvestigationID, callKey string) (bool, error) {
	if investigationID == "" || callKey == "" {
		return false, fmt.Errorf("model call audit identity is required")
	}
	var present bool
	if err := store.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM investigation_model_calls WHERE investigation_id=$1 AND call_key=$2)`, investigationID, callKey).Scan(&present); err != nil {
		return false, fmt.Errorf("check model call audit: %w", err)
	}
	return present, nil
}

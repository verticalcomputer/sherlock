package contextbudget

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresSink struct{ pool *pgxpool.Pool }

func NewPostgresSink(pool *pgxpool.Pool) (*PostgresSink, error) {
	if pool == nil {
		return nil, fmt.Errorf("context manifest PostgreSQL pool is required")
	}
	return &PostgresSink{pool: pool}, nil
}

func (sink *PostgresSink) RecordContextManifest(ctx context.Context, manifest Manifest) error {
	if manifest.CalibrationFactorMillionths == 0 {
		manifest.CalibrationFactorMillionths = 1_000_000
	}
	if manifest.RawEstimatedInputTokens == 0 {
		manifest.RawEstimatedInputTokens = manifest.EstimatedInputTokens
	}
	if manifest.ContextMode == "" {
		manifest.ContextMode = "STATELESS"
	}
	if manifest.SelectedMemoryIDs == nil {
		manifest.SelectedMemoryIDs = []string{}
	}
	if manifest.SelectedEvidenceIDs == nil {
		manifest.SelectedEvidenceIDs = []string{}
	}
	if manifest.ExclusionReasons == nil {
		manifest.ExclusionReasons = map[string]int{}
	}
	if manifest.SectionTokens == nil {
		manifest.SectionTokens = map[string]int64{}
	}
	selected, err := json.Marshal(manifest.SelectedMemoryIDs)
	if err != nil {
		return fmt.Errorf("encode selected memory IDs: %w", err)
	}
	selectedEvidence, err := json.Marshal(manifest.SelectedEvidenceIDs)
	if err != nil {
		return fmt.Errorf("encode selected evidence IDs: %w", err)
	}
	exclusions, err := json.Marshal(manifest.ExclusionReasons)
	if err != nil {
		return fmt.Errorf("encode context exclusion reasons: %w", err)
	}
	sections, err := json.Marshal(manifest.SectionTokens)
	if err != nil {
		return fmt.Errorf("encode context section tokens: %w", err)
	}
	command, err := sink.pool.Exec(ctx, `INSERT INTO investigation_context_manifests(manifest_id,cluster_id,investigation_id,call_key,call_kind,estimator_version,allowance_tokens,estimated_input_tokens,memory_allowance_tokens,memory_candidate_count,selected_memory_ids,exclusion_reasons,section_tokens,retrieval_latency_milliseconds,index_version,fallback_state,shadow_only,created_at,raw_estimated_input_tokens,calibration_factor_millionths,calibration_sample_count,fixed_margin_tokens,maximum_output_tokens,selected_evidence_ids,context_mode,checkpoint_digest,delta_from_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27) ON CONFLICT(investigation_id,call_key) DO NOTHING`, manifest.ID, manifest.ClusterID, manifest.InvestigationID, manifest.CallKey, manifest.CallKind, manifest.EstimatorVersion, manifest.AllowanceTokens, manifest.EstimatedInputTokens, manifest.MemoryAllowanceTokens, manifest.MemoryCandidateCount, selected, exclusions, sections, manifest.RetrievalLatency.Milliseconds(), manifest.IndexVersion, manifest.FallbackState, manifest.ShadowOnly, manifest.CreatedAt, manifest.RawEstimatedInputTokens, manifest.CalibrationFactorMillionths, manifest.CalibrationSampleCount, manifest.FixedMarginTokens, manifest.MaximumOutputTokens, selectedEvidence, manifest.ContextMode, manifest.CheckpointDigest, nullableVersion(manifest.DeltaFromVersion))
	if err != nil {
		return err
	}
	if command.RowsAffected() == 1 {
		return nil
	}
	var estimated int64
	var fallback string
	var storedSelected, storedEvidence, storedExclusions, storedSections []byte
	var mode, checkpoint string
	var delta *int
	if err := sink.pool.QueryRow(ctx, `SELECT estimated_input_tokens,fallback_state,selected_memory_ids,selected_evidence_ids,exclusion_reasons,section_tokens,context_mode,checkpoint_digest,delta_from_version FROM investigation_context_manifests WHERE investigation_id=$1 AND call_key=$2`, manifest.InvestigationID, manifest.CallKey).Scan(&estimated, &fallback, &storedSelected, &storedEvidence, &storedExclusions, &storedSections, &mode, &checkpoint, &delta); err != nil {
		return err
	}
	if estimated != manifest.EstimatedInputTokens || fallback != manifest.FallbackState || mode != manifest.ContextMode || checkpoint != manifest.CheckpointDigest || !equivalentJSON(storedSelected, selected) || !equivalentJSON(storedEvidence, selectedEvidence) || !equivalentJSON(storedExclusions, exclusions) || !equivalentJSON(storedSections, sections) || (delta == nil) != (manifest.DeltaFromVersion == 0) || (delta != nil && *delta != manifest.DeltaFromVersion) {
		return fmt.Errorf("context manifest idempotency conflict")
	}
	return nil
}

func nullableVersion(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

func (sink *PostgresSink) LoadCalibrationRatios(ctx context.Context, key CalibrationKey, limit int) ([]int64, error) {
	rows, err := sink.pool.Query(ctx, `SELECT ratio_millionths FROM model_token_calibration_samples WHERE provider=$1 AND model=$2 AND configuration_id=$3 AND prompt_schema_version=$4 AND tool_schema_version=$5 AND estimator_version=$6 ORDER BY created_at DESC,sample_id DESC LIMIT $7`, key.Provider, key.Model, key.ConfigurationID, key.PromptSchemaVersion, key.ToolSchemaVersion, key.EstimatorVersion, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []int64
	for rows.Next() {
		var value int64
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (sink *PostgresSink) RecordCalibrationSample(ctx context.Context, key CalibrationKey, manifest Manifest, actual int64) error {
	if manifest.RawEstimatedInputTokens <= 0 {
		return fmt.Errorf("raw token estimate is required")
	}
	ratio := (actual*1_000_000 + manifest.RawEstimatedInputTokens - 1) / manifest.RawEstimatedInputTokens
	id := manifest.ID
	_, err := sink.pool.Exec(ctx, `INSERT INTO model_token_calibration_samples(sample_id,provider,model,configuration_id,prompt_schema_version,tool_schema_version,estimator_version,raw_estimate,actual_input_tokens,ratio_millionths,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,clock_timestamp()) ON CONFLICT DO NOTHING`, id, key.Provider, key.Model, key.ConfigurationID, key.PromptSchemaVersion, key.ToolSchemaVersion, key.EstimatorVersion, manifest.RawEstimatedInputTokens, actual, ratio)
	return err
}

func (sink *PostgresSink) RecordActualContextUsage(ctx context.Context, manifest Manifest, actual int64, underrun bool) error {
	_, err := sink.pool.Exec(ctx, `UPDATE investigation_context_manifests SET actual_input_tokens=$3,estimator_underrun=$4 WHERE investigation_id=$1 AND call_key=$2`, manifest.InvestigationID, manifest.CallKey, actual, underrun)
	return err
}

func equivalentJSON(left, right []byte) bool {
	var leftValue, rightValue any
	if json.Unmarshal(left, &leftValue) != nil || json.Unmarshal(right, &rightValue) != nil {
		return false
	}
	return reflect.DeepEqual(leftValue, rightValue)
}

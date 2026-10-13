-- M11 deterministic context projections and calibrated provider admission.
-- These rows are rebuildable execution/audit metadata; investigation and
-- evidence ledgers remain authoritative.
CREATE TABLE investigation_context_checkpoints (
    investigation_id text NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    cluster_id text NOT NULL,
    ledger_version integer NOT NULL CHECK (ledger_version > 0),
    checkpoint_digest bytea NOT NULL CHECK (octet_length(checkpoint_digest) = 32),
    parent_digest text,
    checkpoint_json jsonb NOT NULL CHECK (jsonb_typeof(checkpoint_json) = 'object'),
    delta_json jsonb CHECK (delta_json IS NULL OR jsonb_typeof(delta_json) = 'object'),
    selected_evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(selected_evidence_ids) = 'array'),
    exclusions jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(exclusions) = 'array'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (investigation_id, ledger_version),
    UNIQUE (investigation_id, checkpoint_digest),
    FOREIGN KEY (cluster_id, investigation_id) REFERENCES investigations(cluster_id, investigation_id) ON DELETE CASCADE
);

CREATE INDEX investigation_context_checkpoint_lineage_idx
    ON investigation_context_checkpoints (cluster_id, investigation_id, ledger_version DESC);

CREATE TABLE model_token_calibration_samples (
    sample_id text PRIMARY KEY,
    provider text NOT NULL,
    model text NOT NULL,
    configuration_id text NOT NULL,
    prompt_schema_version text NOT NULL,
    tool_schema_version text NOT NULL,
    estimator_version text NOT NULL,
    raw_estimate bigint NOT NULL CHECK (raw_estimate > 0),
    actual_input_tokens bigint NOT NULL CHECK (actual_input_tokens > 0),
    ratio_millionths bigint NOT NULL CHECK (ratio_millionths > 0),
    created_at timestamptz NOT NULL,
    UNIQUE (provider, model, configuration_id, prompt_schema_version, tool_schema_version, estimator_version, sample_id)
);

CREATE INDEX model_token_calibration_partition_idx ON model_token_calibration_samples
    (provider, model, configuration_id, prompt_schema_version, tool_schema_version, estimator_version, created_at DESC);

ALTER TABLE investigation_context_manifests
    ADD COLUMN raw_estimated_input_tokens bigint NOT NULL DEFAULT 0 CHECK (raw_estimated_input_tokens >= 0),
    ADD COLUMN calibration_factor_millionths bigint NOT NULL DEFAULT 1600000 CHECK (calibration_factor_millionths BETWEEN 1000000 AND 3000000),
    ADD COLUMN calibration_sample_count integer NOT NULL DEFAULT 0 CHECK (calibration_sample_count >= 0),
    ADD COLUMN fixed_margin_tokens bigint NOT NULL DEFAULT 0 CHECK (fixed_margin_tokens >= 0),
    ADD COLUMN maximum_output_tokens bigint NOT NULL DEFAULT 0 CHECK (maximum_output_tokens >= 0),
    ADD COLUMN selected_evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(selected_evidence_ids) = 'array'),
    ADD COLUMN context_mode text NOT NULL DEFAULT 'STATELESS' CHECK (context_mode IN ('STATELESS','CHAINED_SHADOW','CHAINED')),
    ADD COLUMN checkpoint_digest text NOT NULL DEFAULT '',
    ADD COLUMN delta_from_version integer;

ALTER TABLE investigation_context_manifests
    ADD COLUMN actual_input_tokens bigint CHECK (actual_input_tokens IS NULL OR actual_input_tokens > 0),
    ADD COLUMN estimator_underrun boolean NOT NULL DEFAULT false;

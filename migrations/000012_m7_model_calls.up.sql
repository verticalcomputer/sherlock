-- Safe, append-only attribution for model calls. Prompts, model output, and
-- evidence excerpts are deliberately excluded from this table.
CREATE TABLE investigation_model_calls (
    call_id text PRIMARY KEY,
    call_key text NOT NULL,
    cluster_id text NOT NULL,
    investigation_id text NOT NULL,
    call_kind text NOT NULL CHECK (call_kind IN ('PLANNING', 'SYNTHESIS')),
    provider text NOT NULL,
    model text NOT NULL,
    model_config_version text NOT NULL,
    prompt_schema_version text NOT NULL,
    tool_schema_version text NOT NULL,
    input_tokens bigint NOT NULL CHECK (input_tokens >= 0),
    output_tokens bigint NOT NULL CHECK (output_tokens >= 0),
    cost_microunits bigint NOT NULL CHECK (cost_microunits >= 0),
    latency_milliseconds bigint NOT NULL CHECK (latency_milliseconds >= 0),
    outcome text NOT NULL CHECK (outcome IN ('SUCCEEDED', 'REJECTED', 'FAILED')),
    reason_code text NOT NULL DEFAULT '',
    occurred_at timestamptz NOT NULL,
    UNIQUE (investigation_id, call_key),
    FOREIGN KEY (cluster_id, investigation_id)
        REFERENCES investigations(cluster_id, investigation_id) ON DELETE CASCADE,
    CHECK ((outcome = 'SUCCEEDED') = (reason_code = ''))
);

CREATE INDEX investigation_model_calls_cluster_time_idx
    ON investigation_model_calls (cluster_id, occurred_at DESC);

-- M10 derived cluster memory and pre-provider context accounting. Memory rows
-- are projections only; investigations and evidence remain authoritative.
CREATE TABLE cluster_memory_entries (
    memory_id text PRIMARY KEY,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id) ON DELETE CASCADE,
    schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version = 1),
    memory_kind text NOT NULL CHECK (memory_kind IN (
        'VALIDATED_FINDING', 'ACTION_OUTCOME', 'COVERAGE_GAP',
        'HYPOTHESIS', 'OPERATOR_REVIEW'
    )),
    trust_class text NOT NULL CHECK (trust_class IN (
        'OBSERVED', 'VALIDATED_FINDING', 'HYPOTHESIS', 'ACTION_OUTCOME',
        'COVERAGE_GAP', 'OPERATOR_REVIEW'
    )),
    source_investigation_id text NOT NULL,
    source_action_id text,
    source_finding_id text,
    entity_kind text NOT NULL,
    entity_ids jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(entity_ids) = 'array'),
    evidence_class text NOT NULL DEFAULT '',
    source_version text NOT NULL DEFAULT '',
    statement text NOT NULL CHECK (length(statement) BETWEEN 1 AND 4096),
    compact_summary text NOT NULL CHECK (length(compact_summary) BETWEEN 1 AND 2048),
    search_document tsvector GENERATED ALWAYS AS (
        to_tsvector('simple', coalesce(statement, '') || ' ' || coalesce(compact_summary, ''))
    ) STORED,
    observed_from timestamptz,
    observed_to timestamptz,
    valid_from timestamptz NOT NULL,
    valid_to timestamptz,
    created_at timestamptz NOT NULL,
    expires_at timestamptz,
    superseded_at timestamptz,
    completeness text NOT NULL CHECK (completeness IN ('COMPLETE', 'PARTIAL', 'UNKNOWN')),
    freshness text NOT NULL CHECK (freshness IN ('CURRENT', 'STALE', 'UNKNOWN')),
    retention_class text NOT NULL,
    content_digest bytea NOT NULL CHECK (octet_length(content_digest) = 32),
    idempotency_key text NOT NULL,
    UNIQUE (cluster_id, idempotency_key),
    UNIQUE (cluster_id, memory_id),
    FOREIGN KEY (cluster_id, source_investigation_id)
        REFERENCES investigations(cluster_id, investigation_id) ON DELETE CASCADE,
    CHECK (observed_to IS NULL OR observed_from IS NOT NULL),
    CHECK (observed_to IS NULL OR observed_to >= observed_from),
    CHECK (valid_to IS NULL OR valid_to >= valid_from),
    CHECK (expires_at IS NULL OR expires_at >= created_at),
    CHECK (superseded_at IS NULL OR superseded_at >= created_at),
    CHECK (memory_kind <> 'VALIDATED_FINDING' OR source_finding_id IS NOT NULL)
);

CREATE INDEX cluster_memory_filter_idx ON cluster_memory_entries
    (cluster_id, superseded_at, expires_at, valid_from DESC, trust_class);
CREATE INDEX cluster_memory_search_idx ON cluster_memory_entries USING gin (search_document);

-- Do not install extensions from an application migration. When an operator
-- has already enabled pgvector, add the replaceable embedding projection;
-- otherwise lexical retrieval remains fully operational.
DO $m10_vector$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname='vector') THEN
        EXECUTE $sql$
            CREATE TABLE cluster_memory_embeddings (
                cluster_id text NOT NULL,
                memory_id text NOT NULL,
                embedding_model text NOT NULL,
                embedding_version text NOT NULL,
                dimensions integer NOT NULL CHECK (dimensions BETWEEN 1 AND 4096),
                embedding vector NOT NULL,
                content_digest bytea NOT NULL CHECK (octet_length(content_digest)=32),
                created_at timestamptz NOT NULL,
                PRIMARY KEY (memory_id, embedding_model, embedding_version),
                FOREIGN KEY (cluster_id, memory_id)
                    REFERENCES cluster_memory_entries(cluster_id, memory_id) ON DELETE CASCADE
            )
        $sql$;
    END IF;
END
$m10_vector$;

CREATE TABLE cluster_memory_citations (
    cluster_id text NOT NULL,
    memory_id text NOT NULL,
    evidence_id text NOT NULL,
    relationship text NOT NULL CHECK (relationship IN ('EVIDENCE', 'COUNTER_EVIDENCE')),
    PRIMARY KEY (memory_id, evidence_id, relationship),
    FOREIGN KEY (cluster_id, memory_id)
        REFERENCES cluster_memory_entries(cluster_id, memory_id) ON DELETE CASCADE,
    FOREIGN KEY (cluster_id, evidence_id)
        REFERENCES evidence_envelopes(cluster_id, evidence_id) ON DELETE RESTRICT
);

CREATE TABLE cluster_memory_outbox (
    outbox_id text PRIMARY KEY,
    cluster_id text NOT NULL,
    memory_id text NOT NULL,
    operation text NOT NULL CHECK (operation IN ('UPSERT', 'DELETE')),
    status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    available_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (memory_id, operation),
    FOREIGN KEY (cluster_id, memory_id)
        REFERENCES cluster_memory_entries(cluster_id, memory_id) ON DELETE CASCADE
);

CREATE INDEX cluster_memory_outbox_pending_idx ON cluster_memory_outbox (available_at, outbox_id)
    WHERE status IN ('PENDING', 'FAILED');

CREATE TABLE cluster_memory_projection_checkpoints (
    cluster_id text PRIMARY KEY REFERENCES clusters(cluster_id) ON DELETE CASCADE,
    index_version text NOT NULL,
    last_investigation_id text,
    projected_at timestamptz NOT NULL,
    source_digest bytea NOT NULL CHECK (octet_length(source_digest) = 32)
);

CREATE TABLE cluster_memory_projection_failures (
    failure_id text PRIMARY KEY,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id) ON DELETE CASCADE,
    source_investigation_id text,
    reason_code text NOT NULL,
    occurred_at timestamptz NOT NULL,
    resolved_at timestamptz
);

CREATE INDEX cluster_memory_failures_open_idx ON cluster_memory_projection_failures (cluster_id, occurred_at DESC)
    WHERE resolved_at IS NULL;

CREATE TABLE investigation_context_manifests (
    manifest_id text PRIMARY KEY,
    cluster_id text NOT NULL,
    investigation_id text NOT NULL,
    call_key text NOT NULL,
    call_kind text NOT NULL CHECK (call_kind IN ('PLANNING', 'SYNTHESIS')),
    estimator_version text NOT NULL,
    allowance_tokens bigint NOT NULL CHECK (allowance_tokens > 0),
    estimated_input_tokens bigint NOT NULL CHECK (estimated_input_tokens >= 0),
    memory_allowance_tokens bigint NOT NULL CHECK (memory_allowance_tokens >= 0),
    memory_candidate_count integer NOT NULL DEFAULT 0 CHECK (memory_candidate_count >= 0),
    selected_memory_ids jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(selected_memory_ids) = 'array'),
    exclusion_reasons jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(exclusion_reasons) = 'object'),
    section_tokens jsonb NOT NULL CHECK (jsonb_typeof(section_tokens) = 'object'),
    retrieval_latency_milliseconds bigint NOT NULL DEFAULT 0 CHECK (retrieval_latency_milliseconds >= 0),
    index_version text NOT NULL DEFAULT '',
    fallback_state text NOT NULL CHECK (fallback_state IN ('DISABLED', 'NONE', 'LEXICAL', 'MEMORY_UNAVAILABLE', 'REQUIRED_CONTEXT_ONLY')),
    shadow_only boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    UNIQUE (investigation_id, call_key),
    FOREIGN KEY (cluster_id, investigation_id)
        REFERENCES investigations(cluster_id, investigation_id) ON DELETE CASCADE,
    CHECK (estimated_input_tokens <= allowance_tokens)
);

CREATE INDEX investigation_context_manifests_cluster_time_idx
    ON investigation_context_manifests (cluster_id, created_at DESC);

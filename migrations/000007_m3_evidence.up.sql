CREATE TABLE evidence_envelopes (
    evidence_id text PRIMARY KEY,
    schema_version integer NOT NULL CHECK (schema_version > 0),
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    status text NOT NULL CHECK (status IN ('COMPLETE', 'PARTIAL', 'NO_DATA', 'UNAVAILABLE')),
    source_id text NOT NULL REFERENCES sources(source_id),
    run_id text REFERENCES collection_runs(run_id),
    operation text NOT NULL,
    definition_version text NOT NULL,
    source_reference text NOT NULL,
    observed_start timestamptz NOT NULL,
    observed_end timestamptz NOT NULL,
    collected_at timestamptz NOT NULL,
    coverage_expected jsonb NOT NULL,
    coverage_covered jsonb NOT NULL,
    artifact_id text,
    artifact_sha256 bytea,
    artifact_bytes bigint,
    artifact_media_type text,
    artifact_compression text,
    artifact_parser_version text,
    redaction_policy_version text,
    redaction_match_count integer,
    retention_class text,
    artifact_availability text NOT NULL DEFAULT 'NONE'
        CHECK (artifact_availability IN ('NONE', 'PENDING', 'AVAILABLE', 'UNAVAILABLE', 'CORRUPT')),
    supersedes_evidence_id text REFERENCES evidence_envelopes(evidence_id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (observed_end >= observed_start),
    CHECK (collected_at >= observed_end),
    CHECK (supersedes_evidence_id IS NULL OR supersedes_evidence_id <> evidence_id),
    CHECK (
        (artifact_id IS NULL AND artifact_sha256 IS NULL AND artifact_bytes IS NULL
            AND artifact_media_type IS NULL AND artifact_compression IS NULL
            AND artifact_parser_version IS NULL AND redaction_policy_version IS NULL
            AND redaction_match_count IS NULL AND retention_class IS NULL
            AND artifact_availability = 'NONE')
        OR
        (artifact_id IS NOT NULL AND artifact_sha256 IS NOT NULL
            AND octet_length(artifact_sha256) = 32 AND artifact_bytes >= 0
            AND artifact_media_type IS NOT NULL AND artifact_compression IS NOT NULL
            AND artifact_parser_version IS NOT NULL AND redaction_policy_version IS NOT NULL
            AND redaction_match_count >= 0 AND retention_class IS NOT NULL
            AND artifact_availability <> 'NONE')
    )
);

CREATE INDEX evidence_cluster_time_idx
    ON evidence_envelopes (cluster_id, collected_at DESC);

CREATE INDEX evidence_source_run_idx
    ON evidence_envelopes (source_id, run_id);

CREATE INDEX evidence_artifact_reconcile_idx
    ON evidence_envelopes (artifact_availability, created_at)
    WHERE artifact_availability IN ('PENDING', 'UNAVAILABLE', 'CORRUPT');

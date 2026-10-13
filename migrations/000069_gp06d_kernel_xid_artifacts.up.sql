-- GP-06d retains only canonical sanitized kernel-XID artifact bytes. Expiry
-- and deletion clear artifact_bytes while preserving a non-content state.
CREATE TABLE kernel_xid_artifacts (
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    run_id text NOT NULL REFERENCES diagnostic_runs(run_id) ON DELETE RESTRICT,
    work_id text NOT NULL,
    attempt integer NOT NULL,
    target text NOT NULL,
    pack_id text NOT NULL,
    pack_version text NOT NULL,
    definition_id text NOT NULL CHECK (definition_id = 'node.kernel_xid'),
    definition_version text NOT NULL CHECK (definition_version = '2.0.0'),
    definition_digest bytea NOT NULL CHECK (octet_length(definition_digest) = 32),
    source_stdout_sha256 bytea NOT NULL CHECK (octet_length(source_stdout_sha256) = 32),
    artifact_schema_version text NOT NULL CHECK (artifact_schema_version = 'sherlock.kernel-xid-artifact.v1'),
    parser_version text NOT NULL CHECK (parser_version = 'sherlock.kernel-xid.v1'),
    redaction_version text NOT NULL CHECK (redaction_version = 'sherlock.kernel-xid-redaction.v1'),
    artifact_sha256 bytea NOT NULL CHECK (octet_length(artifact_sha256) = 32),
    artifact_bytes bytea,
    event_count integer NOT NULL CHECK (event_count BETWEEN 0 AND 32),
    truncated boolean NOT NULL,
    state text NOT NULL CHECK (state IN ('AVAILABLE', 'EXPIRED', 'DELETED', 'CORRUPT')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (work_id, attempt, target),
    FOREIGN KEY (work_id, attempt, target) REFERENCES diagnostic_target_results(work_id, attempt, target) ON DELETE RESTRICT,
    CHECK (expires_at > created_at),
    CHECK (expires_at <= created_at + interval '30 days'),
    CHECK ((state = 'AVAILABLE') = (artifact_bytes IS NOT NULL)),
    CHECK (artifact_bytes IS NULL OR octet_length(artifact_bytes) BETWEEN 1 AND 4096)
);

CREATE INDEX kernel_xid_artifacts_expiry_idx ON kernel_xid_artifacts (expires_at) WHERE state = 'AVAILABLE';

CREATE FUNCTION kernel_xid_artifact_validate_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM diagnostic_runs r
        JOIN diagnostic_work_items w ON w.run_id=r.run_id
        JOIN diagnostic_target_results t ON t.work_id=w.work_id
        WHERE r.cluster_id=NEW.cluster_id AND r.run_id=NEW.run_id AND w.work_id=NEW.work_id
          AND t.attempt=NEW.attempt AND t.target=NEW.target
          AND r.pack_id=NEW.pack_id AND r.pack_version=NEW.pack_version
          AND r.definition_id=NEW.definition_id AND r.definition_version=NEW.definition_version
          AND r.definition_digest=NEW.definition_digest AND t.stdout_sha256=NEW.source_stdout_sha256
    ) THEN RAISE EXCEPTION 'kernel XID artifact binding does not match diagnostic result'; END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION kernel_xid_artifact_immutable_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state='AVAILABLE' AND NEW.state IN ('EXPIRED','DELETED','CORRUPT') AND NEW.artifact_bytes IS NULL
       AND NEW.cluster_id=OLD.cluster_id AND NEW.run_id=OLD.run_id AND NEW.work_id=OLD.work_id
       AND NEW.attempt=OLD.attempt AND NEW.target=OLD.target AND NEW.pack_id=OLD.pack_id
       AND NEW.pack_version=OLD.pack_version AND NEW.definition_id=OLD.definition_id
       AND NEW.definition_version=OLD.definition_version AND NEW.definition_digest=OLD.definition_digest
       AND NEW.source_stdout_sha256=OLD.source_stdout_sha256 AND NEW.artifact_schema_version=OLD.artifact_schema_version
       AND NEW.parser_version=OLD.parser_version AND NEW.redaction_version=OLD.redaction_version
       AND NEW.artifact_sha256=OLD.artifact_sha256 AND NEW.event_count=OLD.event_count
       AND NEW.truncated=OLD.truncated AND NEW.created_at=OLD.created_at AND NEW.expires_at=OLD.expires_at
    THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'kernel XID artifact provenance and content are immutable';
END $$;

CREATE TRIGGER kernel_xid_artifact_validate_insert_trigger BEFORE INSERT ON kernel_xid_artifacts
    FOR EACH ROW EXECUTE FUNCTION kernel_xid_artifact_validate_insert();
CREATE TRIGGER kernel_xid_artifact_immutable_update_trigger BEFORE UPDATE ON kernel_xid_artifacts
    FOR EACH ROW EXECUTE FUNCTION kernel_xid_artifact_immutable_update();

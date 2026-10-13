CREATE TABLE collector_bootstrap_keys (
    bootstrap_key_id text PRIMARY KEY,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    collector_id text REFERENCES collectors(collector_id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (expires_at > created_at),
    CHECK ((consumed_at IS NULL) = (collector_id IS NULL))
);

CREATE INDEX collector_bootstrap_available_idx
    ON collector_bootstrap_keys (expires_at)
    WHERE consumed_at IS NULL;

CREATE TABLE collector_identities (
    certificate_serial text PRIMARY KEY,
    collector_id text NOT NULL REFERENCES collectors(collector_id) ON DELETE CASCADE,
    certificate_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(certificate_sha256) = 32),
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    superseded_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (not_after > not_before),
    CHECK (revoked_at IS NULL OR revoked_at >= not_before)
);

CREATE INDEX collector_identities_collector_idx
    ON collector_identities (collector_id, not_after DESC);

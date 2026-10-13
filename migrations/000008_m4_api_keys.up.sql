CREATE TABLE api_keys (
    public_key_id text PRIMARY KEY,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    label text NOT NULL CHECK (length(label) BETWEEN 1 AND 128),
    secret_hash bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (expires_at > created_at),
    CHECK (last_used_at IS NULL OR last_used_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX api_keys_cluster_created_idx ON api_keys (cluster_id, created_at DESC);
CREATE INDEX api_keys_available_idx ON api_keys (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE api_key_capabilities (
    public_key_id text NOT NULL REFERENCES api_keys(public_key_id) ON DELETE CASCADE,
    capability text NOT NULL CHECK (capability IN (
        'cluster:read',
        'telemetry:read',
        'incidents:read',
        'incidents:write',
        'investigations:read',
        'investigations:run',
        'diagnostics:privileged',
        'evidence:raw',
        'configuration:read',
        'configuration:write',
        'audit:read'
    )),
    PRIMARY KEY (public_key_id, capability)
);

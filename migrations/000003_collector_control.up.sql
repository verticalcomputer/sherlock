CREATE TABLE collectors (
    collector_id text PRIMARY KEY,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    display_name text NOT NULL,
    status text NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'ACTIVE', 'UPGRADE_REQUIRED', 'REVOKED')),
    version text NOT NULL,
    build_commit text NOT NULL,
    protocol_min integer NOT NULL CHECK (protocol_min > 0),
    protocol_max integer NOT NULL CHECK (protocol_max >= protocol_min),
    operating_system text NOT NULL,
    architecture text NOT NULL,
    identity_serial text UNIQUE,
    identity_not_after timestamptz,
    last_heartbeat_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL))
);

CREATE INDEX collectors_cluster_status_idx ON collectors (cluster_id, status);

CREATE TABLE collector_capabilities (
    collector_id text NOT NULL REFERENCES collectors(collector_id) ON DELETE CASCADE,
    capability text NOT NULL,
    version text NOT NULL,
    reported_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (collector_id, capability)
);

CREATE TABLE collector_source_health (
    collector_id text NOT NULL REFERENCES collectors(collector_id) ON DELETE CASCADE,
    source_id text NOT NULL REFERENCES sources(source_id) ON DELETE CASCADE,
    availability text NOT NULL CHECK (availability IN ('UNKNOWN', 'AVAILABLE', 'UNAVAILABLE')),
    safe_message text NOT NULL DEFAULT '',
    checked_at timestamptz NOT NULL,
    reported_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (collector_id, source_id)
);

CREATE TABLE collector_work_items (
    work_id text PRIMARY KEY,
    run_id text NOT NULL UNIQUE,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    source_id text NOT NULL REFERENCES sources(source_id),
    query_kind text NOT NULL,
    node_filter text NOT NULL DEFAULT '',
    range_start timestamptz,
    range_end timestamptz,
    range_step_seconds double precision,
    scheduled_for timestamptz NOT NULL,
    deadline timestamptz NOT NULL,
    max_series integer NOT NULL CHECK (max_series BETWEEN 1 AND 10000),
    max_bytes bigint NOT NULL CHECK (max_bytes BETWEEN 1 AND 10485760),
    idempotency_key text NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'AVAILABLE'
        CHECK (status IN ('AVAILABLE', 'LEASED', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    work_expires_at timestamptz NOT NULL,
    next_attempt integer NOT NULL DEFAULT 1 CHECK (next_attempt > 0),
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (deadline > scheduled_for),
    CHECK (work_expires_at > available_at),
    CHECK (
        (range_start IS NULL AND range_end IS NULL AND range_step_seconds IS NULL)
        OR
        (range_start IS NOT NULL AND range_end > range_start AND range_step_seconds BETWEEN 1 AND 3600)
    ),
    CHECK ((status IN ('SUCCEEDED', 'FAILED', 'CANCELLED')) = (completed_at IS NOT NULL))
);

CREATE INDEX collector_work_claim_idx
    ON collector_work_items (cluster_id, available_at, work_id)
    WHERE status IN ('AVAILABLE', 'LEASED');

CREATE TABLE collector_work_attempts (
    work_id text NOT NULL REFERENCES collector_work_items(work_id) ON DELETE CASCADE,
    attempt integer NOT NULL CHECK (attempt > 0),
    collector_id text NOT NULL REFERENCES collectors(collector_id),
    lease_token_hash bytea NOT NULL CHECK (octet_length(lease_token_hash) = 32),
    status text NOT NULL DEFAULT 'CLAIMED'
        CHECK (status IN ('CLAIMED', 'STARTED', 'SUCCEEDED', 'FAILED', 'EXPIRED', 'REJECTED')),
    claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    started_at timestamptz,
    lease_expires_at timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (work_id, attempt),
    CHECK (lease_expires_at > claimed_at),
    CHECK (started_at IS NULL OR started_at >= claimed_at),
    CHECK ((status IN ('SUCCEEDED', 'FAILED', 'EXPIRED', 'REJECTED')) = (completed_at IS NOT NULL))
);

CREATE INDEX collector_work_attempt_lease_idx
    ON collector_work_attempts (lease_expires_at)
    WHERE status IN ('CLAIMED', 'STARTED');

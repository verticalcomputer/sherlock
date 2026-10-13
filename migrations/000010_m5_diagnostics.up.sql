CREATE TABLE diagnostic_runs (
    run_id text PRIMARY KEY,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version = 1),
    pack_id text NOT NULL,
    pack_version text NOT NULL,
    definition_id text NOT NULL,
	definition_version text NOT NULL,
    definition_digest bytea NOT NULL CHECK (octet_length(definition_digest) = 32),
    privilege text NOT NULL CHECK (privilege IN ('UNPRIVILEGED', 'PRIVILEGED')),
    status text NOT NULL CHECK (status IN (
        'AWAITING_APPROVAL', 'QUEUED', 'RUNNING', 'SUCCEEDED', 'PARTIAL', 'FAILED', 'CANCELLED'
    )),
    requested_by text NOT NULL,
    idempotency_key text NOT NULL,
    arguments jsonb NOT NULL DEFAULT '[]'::jsonb,
    requested_at timestamptz NOT NULL,
    deadline timestamptz NOT NULL,
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 3),
    version integer NOT NULL DEFAULT 1 CHECK (version > 0),
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (cluster_id, idempotency_key),
    CHECK (deadline > requested_at),
    CHECK (deadline <= requested_at + interval '1 hour'),
    CHECK ((status IN ('SUCCEEDED', 'PARTIAL', 'FAILED', 'CANCELLED')) = (completed_at IS NOT NULL))
);

CREATE TABLE diagnostic_run_targets (
    run_id text NOT NULL REFERENCES diagnostic_runs(run_id) ON DELETE CASCADE,
    target text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 0 AND 255),
    PRIMARY KEY (run_id, target),
    UNIQUE (run_id, ordinal)
);

CREATE TABLE diagnostic_approvals (
    approval_id text PRIMARY KEY,
    run_id text NOT NULL REFERENCES diagnostic_runs(run_id) ON DELETE RESTRICT,
    definition_digest bytea NOT NULL CHECK (octet_length(definition_digest) = 32),
    target_digest bytea NOT NULL CHECK (octet_length(target_digest) = 32),
    run_version integer NOT NULL CHECK (run_version > 0),
    approved_by text NOT NULL,
    approved_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    UNIQUE (run_id, run_version),
    CHECK (expires_at > approved_at),
    CHECK (expires_at <= approved_at + interval '15 minutes'),
    CHECK (revoked_at IS NULL OR revoked_at >= approved_at)
);

CREATE TABLE diagnostic_work_items (
    work_id text PRIMARY KEY,
    run_id text NOT NULL UNIQUE REFERENCES diagnostic_runs(run_id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('BLOCKED', 'AVAILABLE', 'LEASED', 'SUCCEEDED', 'PARTIAL', 'FAILED', 'CANCELLED')),
    available_at timestamptz NOT NULL,
    deadline timestamptz NOT NULL,
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 3),
    next_attempt integer NOT NULL DEFAULT 1 CHECK (next_attempt BETWEEN 1 AND 4),
    CHECK (deadline > available_at)
);

CREATE INDEX diagnostic_work_available_idx
    ON diagnostic_work_items (available_at, work_id)
    WHERE status = 'AVAILABLE';

CREATE TABLE diagnostic_work_attempts (
    work_id text NOT NULL REFERENCES diagnostic_work_items(work_id) ON DELETE RESTRICT,
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 3),
    runner_id text NOT NULL,
    lease_token_hash bytea NOT NULL CHECK (octet_length(lease_token_hash) = 32),
    lease_expires_at timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('CLAIMED', 'RUNNING', 'SUCCEEDED', 'PARTIAL', 'FAILED', 'EXPIRED')),
    plan_digest bytea CHECK (plan_digest IS NULL OR octet_length(plan_digest) = 32),
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (work_id, attempt),
    CHECK ((status IN ('SUCCEEDED', 'PARTIAL', 'FAILED', 'EXPIRED')) = (completed_at IS NOT NULL))
);

CREATE TABLE diagnostic_target_results (
    work_id text NOT NULL,
    attempt integer NOT NULL,
    target text NOT NULL,
    status text NOT NULL CHECK (status IN ('SUCCEEDED', 'FAILED', 'TIMED_OUT', 'REJECTED')),
    retryable boolean NOT NULL,
    exit_code integer,
    signal text NOT NULL DEFAULT '',
    timed_out boolean NOT NULL,
    stdout_truncated boolean NOT NULL,
    stderr_truncated boolean NOT NULL,
    stdout_bytes bigint NOT NULL CHECK (stdout_bytes >= 0),
    stderr_bytes bigint NOT NULL CHECK (stderr_bytes >= 0),
    stdout_sha256 bytea NOT NULL CHECK (octet_length(stdout_sha256) = 32),
    stderr_sha256 bytea NOT NULL CHECK (octet_length(stderr_sha256) = 32),
    error_code text NOT NULL DEFAULT '',
    PRIMARY KEY (work_id, attempt, target),
    FOREIGN KEY (work_id, attempt) REFERENCES diagnostic_work_attempts(work_id, attempt) ON DELETE RESTRICT,
    CHECK (timed_out = (status = 'TIMED_OUT'))
);

-- This table deliberately has no JSON payload: audit records are immutable,
-- attributable safe metadata and cannot acquire output, arguments or secrets.
CREATE TABLE diagnostic_audit_events (
    event_id text PRIMARY KEY,
    event_kind text NOT NULL CHECK (event_kind IN ('AUTHORIZATION_PREVIEW', 'START_AUTHORIZATION', 'APPROVAL', 'ATTEMPT_CLAIM', 'ATTEMPT_RESULT')),
    run_id text REFERENCES diagnostic_runs(run_id) ON DELETE RESTRICT,
    work_id text REFERENCES diagnostic_work_items(work_id) ON DELETE RESTRICT,
    attempt integer,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    actor_id text NOT NULL,
    outcome text NOT NULL,
    reason_code text NOT NULL DEFAULT '',
    definition_digest bytea NOT NULL CHECK (octet_length(definition_digest) = 32),
    target_digest bytea NOT NULL CHECK (octet_length(target_digest) = 32),
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((work_id IS NULL AND attempt IS NULL) OR (work_id IS NOT NULL AND attempt BETWEEN 1 AND 3))
);

CREATE INDEX diagnostic_audit_cluster_time_idx
    ON diagnostic_audit_events (cluster_id, occurred_at DESC);

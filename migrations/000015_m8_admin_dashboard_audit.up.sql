-- Safe, append-only access metadata for the private admin dashboard. The table
-- deliberately excludes credentials, cookies, request bodies, query strings,
-- rendered values, and unrestricted client/network metadata.
CREATE TABLE admin_dashboard_audit_events (
    event_id text PRIMARY KEY,
    event_kind text NOT NULL CHECK (event_kind IN (
        'AUTHENTICATION', 'SESSION_STARTED', 'SESSION_ENDED', 'SESSION_EXPIRED',
        'DASHBOARD_VIEWED'
    )),
    outcome text NOT NULL CHECK (outcome IN ('SUCCEEDED', 'REJECTED')),
    reason_code text NOT NULL DEFAULT '',
    CHECK ((outcome = 'SUCCEEDED') = (reason_code = '')),
    session_fingerprint bytea CHECK (
        session_fingerprint IS NULL OR octet_length(session_fingerprint) = 32
    ),
    request_id text NOT NULL DEFAULT '',
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX admin_dashboard_audit_time_idx
    ON admin_dashboard_audit_events (occurred_at DESC, event_id DESC);

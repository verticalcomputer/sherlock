-- GP-09 alert delivery ledger. No producer, receiver or schedule is enabled
-- by this migration. Webhook URLs never enter these tables.
CREATE TABLE gp09_alert_outbox (
    alert_id text PRIMARY KEY CHECK (length(alert_id) BETWEEN 8 AND 128),
    cluster_id text NOT NULL REFERENCES clusters(cluster_id) ON DELETE RESTRICT,
    event_key text NOT NULL CHECK (length(event_key) BETWEEN 1 AND 256),
    transition text NOT NULL CHECK (transition IN ('TEST', 'SOURCE_GAP', 'PORT_DOWN', 'RECOVERED')),
    message text NOT NULL CHECK (octet_length(message) BETWEEN 1 AND 3000),
    status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'LEASED', 'ACCEPTED', 'FAILED')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 8),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_token text,
    lease_until timestamptz,
    accepted_at timestamptz,
    last_code text NOT NULL DEFAULT '' CHECK (length(last_code) <= 64),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (cluster_id, event_key, transition),
    CHECK ((lease_token IS NOT NULL) = (status = 'LEASED')),
    CHECK ((lease_until IS NOT NULL) = (status = 'LEASED')),
    CHECK (accepted_at IS NULL OR status = 'ACCEPTED'),
    CHECK (updated_at >= created_at)
);
CREATE INDEX gp09_alert_outbox_ready_idx
    ON gp09_alert_outbox (available_at, alert_id)
    WHERE status = 'PENDING';
CREATE INDEX gp09_alert_outbox_lease_idx
    ON gp09_alert_outbox (lease_until, alert_id)
    WHERE status = 'LEASED';

CREATE TABLE gp09_alert_delivery_attempts (
    alert_id text NOT NULL REFERENCES gp09_alert_outbox(alert_id) ON DELETE RESTRICT,
    attempt_no integer NOT NULL CHECK (attempt_no BETWEEN 1 AND 8),
    outcome text NOT NULL CHECK (outcome IN ('ACCEPTED', 'RETRYABLE_FAILURE', 'PERMANENT_FAILURE')),
    code text NOT NULL CHECK (length(code) BETWEEN 1 AND 64),
    http_status integer NOT NULL CHECK (http_status BETWEEN 0 AND 599),
    attempted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (alert_id, attempt_no)
);

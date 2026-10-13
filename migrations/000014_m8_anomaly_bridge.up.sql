CREATE TABLE anomaly_reconcile_cursors (
    consumer_id text NOT NULL,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    last_event_id bigint NOT NULL DEFAULT 0 CHECK (last_event_id >= 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (consumer_id, cluster_id)
);

CREATE TABLE anomaly_incidents (
    fingerprint bytea PRIMARY KEY CHECK (octet_length(fingerprint) = 32),
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    rule_id text NOT NULL,
    entity_key text NOT NULL,
    incident_id text NOT NULL UNIQUE REFERENCES incidents(incident_id) ON DELETE CASCADE,
    first_signal_at timestamptz NOT NULL,
    last_signal_at timestamptz NOT NULL,
    signal_count bigint NOT NULL DEFAULT 1 CHECK (signal_count > 0),
    cooldown_until timestamptz NOT NULL,
    CHECK (last_signal_at >= first_signal_at),
    CHECK (cooldown_until >= last_signal_at)
);

CREATE INDEX anomaly_incidents_group_idx
    ON anomaly_incidents (cluster_id, rule_id, entity_key, last_signal_at DESC);

CREATE TABLE incident_evidence (
    incident_id text NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    evidence_id text NOT NULL REFERENCES evidence_envelopes(evidence_id) ON DELETE RESTRICT,
    attached_at timestamptz NOT NULL,
    PRIMARY KEY (incident_id, evidence_id)
);

CREATE TABLE automatic_investigation_attempts (
    attempt_id text PRIMARY KEY,
    incident_id text NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    source_event_id bigint NOT NULL CHECK (source_event_id > 0),
    rule_id text NOT NULL,
    service_actor text NOT NULL,
    idempotency_key text NOT NULL,
    status text NOT NULL CHECK (status IN ('RESERVED', 'STARTED', 'BLOCKED')),
    decision_code text NOT NULL,
    investigation_id text UNIQUE REFERENCES investigations(investigation_id) ON DELETE RESTRICT,
    max_model_tokens bigint NOT NULL CHECK (max_model_tokens >= 0),
    max_cost_microunits bigint NOT NULL CHECK (max_cost_microunits >= 0),
    request jsonb NOT NULL CHECK (jsonb_typeof(request) = 'object'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (incident_id, source_event_id),
    UNIQUE (cluster_id, idempotency_key),
    CHECK ((status = 'STARTED') = (investigation_id IS NOT NULL)),
    CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX automatic_investigation_attempts_active_incident_idx
    ON automatic_investigation_attempts (incident_id)
    WHERE status IN ('RESERVED', 'STARTED');

CREATE INDEX automatic_investigation_attempts_daily_idx
    ON automatic_investigation_attempts (cluster_id, created_at, status);

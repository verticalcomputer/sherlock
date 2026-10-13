-- GP-20 "Test BCM access": operator-approved collector-to-target bindings.
-- Capability alone must never entitle a collector to receive a head secret.
-- A credential for (cluster_id, host) may only be claimed and delivered to a
-- collector an operator explicitly bound to exactly that target. The binding
-- is durable authority, not a hint: claim and delivery both re-prove it.
CREATE TABLE credential_target_bindings (
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    host text NOT NULL CHECK (length(host) BETWEEN 1 AND 256),
    collector_id text NOT NULL REFERENCES collectors(collector_id),
    approved_by text NOT NULL CHECK (length(approved_by) BETWEEN 1 AND 256),
    approved_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (revoked_at IS NULL OR revoked_at >= approved_at),
    PRIMARY KEY (cluster_id, host, collector_id)
);

-- Claim and delivery both probe the active binding for one target.
CREATE INDEX credential_target_bindings_active_idx
    ON credential_target_bindings (cluster_id, host, collector_id)
    WHERE revoked_at IS NULL;

CREATE INDEX credential_target_bindings_collector_idx
    ON credential_target_bindings (collector_id, cluster_id)
    WHERE revoked_at IS NULL;

-- Bounded operator audit: who bound or unbound which collector to which
-- target and when. Never a secret, never credential material.
CREATE TABLE credential_target_binding_audit_events (
    event_id text PRIMARY KEY,
    event_kind text NOT NULL CHECK (event_kind IN ('CREDENTIAL_TARGET_BOUND','CREDENTIAL_TARGET_UNBOUND')),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 256),
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    host text NOT NULL CHECK (length(host) BETWEEN 1 AND 256),
    collector_id text NOT NULL CHECK (length(collector_id) BETWEEN 1 AND 128),
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX credential_target_binding_audit_events_target_idx
    ON credential_target_binding_audit_events (cluster_id, host, occurred_at DESC, event_id DESC);

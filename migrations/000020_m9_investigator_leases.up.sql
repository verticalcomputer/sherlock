CREATE TABLE investigation_claims (
    investigation_id TEXT PRIMARY KEY REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    cluster_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'AVAILABLE' CHECK (status IN ('AVAILABLE','LEASED')),
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner TEXT,
    lease_token_hash BYTEA,
    lease_expires_at TIMESTAMPTZ,
    lease_epoch BIGINT NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    attempt_count BIGINT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_heartbeat_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (cluster_id, investigation_id) REFERENCES investigations(cluster_id, investigation_id) ON DELETE CASCADE,
    CHECK ((status = 'AVAILABLE' AND lease_owner IS NULL AND lease_token_hash IS NULL AND lease_expires_at IS NULL)
        OR (status = 'LEASED' AND lease_owner IS NOT NULL AND octet_length(lease_token_hash) = 32 AND lease_expires_at IS NOT NULL))
);

CREATE INDEX investigation_claims_available_idx ON investigation_claims (available_at, investigation_id) WHERE status = 'AVAILABLE';
CREATE INDEX investigation_claims_expired_idx ON investigation_claims (lease_expires_at, investigation_id) WHERE status = 'LEASED';

CREATE TABLE investigation_model_call_reservations (
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    call_key TEXT NOT NULL,
    cluster_id TEXT NOT NULL,
    call_kind TEXT NOT NULL CHECK (call_kind IN ('PLANNING','SYNTHESIS')),
    status TEXT NOT NULL CHECK (status IN ('RESERVED','SUCCEEDED','REJECTED','FAILED','OUTCOME_UNKNOWN')),
    reserved_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (investigation_id, call_key),
    FOREIGN KEY (cluster_id, investigation_id) REFERENCES investigations(cluster_id, investigation_id) ON DELETE CASCADE,
    CHECK ((status = 'RESERVED' AND completed_at IS NULL) OR (status <> 'RESERVED' AND completed_at IS NOT NULL))
);

CREATE INDEX investigation_model_call_reservations_expired_idx
    ON investigation_model_call_reservations (expires_at, investigation_id) WHERE status = 'RESERVED';

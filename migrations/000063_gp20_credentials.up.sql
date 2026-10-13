-- GP-20 credential onboarding. Secret values are authenticated ciphertext;
-- this schema intentionally has no plaintext password columns.
CREATE TABLE admin_cluster_credential_grants (
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    access_subject text NOT NULL CHECK (length(access_subject) BETWEEN 1 AND 256),
    granted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    PRIMARY KEY (cluster_id, access_subject)
);

CREATE INDEX admin_cluster_credential_grants_subject_idx
    ON admin_cluster_credential_grants (access_subject, cluster_id)
    WHERE revoked_at IS NULL;

CREATE TABLE admin_credential_grant_audit_events (
    event_id text PRIMARY KEY,
    event_kind text NOT NULL CHECK (event_kind IN ('CREDENTIAL_ADMIN_GRANTED','CREDENTIAL_ADMIN_REVOKED')),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 256),
    target_subject text NOT NULL CHECK (length(target_subject) BETWEEN 1 AND 256),
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE cluster_credentials (
    credential_id text PRIMARY KEY,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    host text NOT NULL CHECK (length(host) BETWEEN 1 AND 256),
    purpose text NOT NULL CHECK (purpose = 'BCM_READ_ONLY'),
    username text NOT NULL CHECK (length(username) BETWEEN 1 AND 256),
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    key_version text NOT NULL CHECK (length(key_version) BETWEEN 1 AND 64),
    credential_version bigint NOT NULL CHECK (credential_version > 0),
    status text NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    replaced_by text REFERENCES cluster_credentials(credential_id),
    CHECK ((status = 'ACTIVE' AND revoked_at IS NULL AND octet_length(ciphertext) >= 16 AND octet_length(nonce) = 12)
       OR (status = 'REVOKED' AND revoked_at IS NOT NULL AND octet_length(ciphertext) = 0 AND octet_length(nonce) = 0)),
    UNIQUE (cluster_id, host, purpose, credential_version)
);

CREATE UNIQUE INDEX cluster_credentials_active_scope_idx
    ON cluster_credentials (cluster_id, host, purpose)
    WHERE status = 'ACTIVE';

CREATE INDEX cluster_credentials_cluster_idx
    ON cluster_credentials (cluster_id, created_at DESC, credential_id DESC);

-- Credential audit deliberately has a separate bounded shape so existing
-- dashboard audit projections never gain actor or credential identifiers.
CREATE TABLE admin_credential_audit_events (
    event_id text PRIMARY KEY,
    event_kind text NOT NULL CHECK (event_kind IN ('CREDENTIAL_CREATED','CREDENTIAL_REPLACED','CREDENTIAL_REVOKED','CREDENTIAL_KEY_ROTATED','CREDENTIAL_ATTEMPT')),
    outcome text NOT NULL CHECK (outcome IN ('SUCCEEDED','REJECTED')),
    reason_code text NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 128),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 256),
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    credential_id text NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 128),
    credential_version bigint NOT NULL CHECK (credential_version >= 0),
    session_fingerprint bytea NOT NULL CHECK (octet_length(session_fingerprint)=32),
    request_id text NOT NULL CHECK (length(request_id) <= 128),
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX admin_credential_audit_scope_idx
    ON admin_credential_audit_events (cluster_id, occurred_at DESC, event_id DESC);

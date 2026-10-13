-- GP-10a stores reviewed human grants independently of API keys and the
-- existing credential-only grant. No principal or membership is seeded.
CREATE TABLE human_principals (
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 9 AND 512),
    subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 256),
    display_email text NOT NULL DEFAULT '' CHECK (length(display_email) <= 320),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (issuer, subject),
    CHECK (updated_at >= created_at)
);

CREATE TABLE human_cluster_memberships (
    issuer text NOT NULL,
    subject text NOT NULL,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id) ON DELETE RESTRICT,
    role text NOT NULL CHECK (role IN ('CLUSTER_VIEWER', 'CLUSTER_ADMIN')),
    revision bigint NOT NULL CHECK (revision > 0),
    granted_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    revoked_at timestamptz,
    PRIMARY KEY (issuer, subject, cluster_id),
    FOREIGN KEY (issuer, subject) REFERENCES human_principals(issuer, subject) ON DELETE RESTRICT,
    CHECK (updated_at >= granted_at),
    CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
);
CREATE INDEX human_cluster_memberships_active_cluster_idx
    ON human_cluster_memberships(cluster_id, role, issuer, subject)
    WHERE revoked_at IS NULL;

-- These are additional grants, never implied by CLUSTER_ADMIN.
CREATE TABLE human_cluster_privileges (
    issuer text NOT NULL,
    subject text NOT NULL,
    cluster_id text NOT NULL,
    privilege text NOT NULL CHECK (privilege IN ('CREDENTIAL_MANAGE', 'POLICY_MANAGE', 'RAW_EVIDENCE')),
    revision bigint NOT NULL CHECK (revision > 0),
    granted_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    revoked_at timestamptz,
    PRIMARY KEY (issuer, subject, cluster_id, privilege),
    FOREIGN KEY (issuer, subject, cluster_id)
        REFERENCES human_cluster_memberships(issuer, subject, cluster_id) ON DELETE RESTRICT,
    CHECK (updated_at >= granted_at),
    CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
);

-- Platform administration is a separate grant, not a cluster role.
CREATE TABLE human_platform_admins (
    issuer text NOT NULL,
    subject text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    granted_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    revoked_at timestamptz,
    PRIMARY KEY (issuer, subject),
    FOREIGN KEY (issuer, subject) REFERENCES human_principals(issuer, subject) ON DELETE RESTRICT,
    CHECK (updated_at >= granted_at),
    CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
);

CREATE TABLE human_authorization_audit_events (
    event_id text PRIMARY KEY,
    issuer text NOT NULL,
    subject text NOT NULL,
    cluster_id text,
    action text NOT NULL CHECK (action IN (
        'MEMBERSHIP_GRANTED', 'MEMBERSHIP_REVOKED',
        'PRIVILEGE_GRANTED', 'PRIVILEGE_REVOKED',
        'PLATFORM_GRANTED', 'PLATFORM_REVOKED'
    )),
    role text NOT NULL DEFAULT '',
    privilege text NOT NULL DEFAULT '',
    revision bigint NOT NULL CHECK (revision > 0),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 256),
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (issuer, subject) REFERENCES human_principals(issuer, subject) ON DELETE RESTRICT,
    FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id) ON DELETE RESTRICT,
    CHECK ((cluster_id IS NULL) = (action IN ('PLATFORM_GRANTED', 'PLATFORM_REVOKED')))
);
CREATE INDEX human_authorization_audit_subject_time_idx
    ON human_authorization_audit_events(issuer, subject, occurred_at DESC);

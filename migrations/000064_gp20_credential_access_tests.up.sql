-- GP-20 "Test BCM access". Durable request/attempt authority for the
-- head-local read-only BCM access test. No column holds a secret: the
-- credential is named by id and exact version and decrypted only inside the
-- operation-bound delivery transaction.
CREATE TABLE credential_access_tests (
    test_id text PRIMARY KEY CHECK (test_id LIKE 'ctest\_%' AND length(test_id) BETWEEN 7 AND 128),
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    credential_id text NOT NULL REFERENCES cluster_credentials(credential_id),
    credential_version bigint NOT NULL CHECK (credential_version > 0),
    host text NOT NULL CHECK (length(host) BETWEEN 1 AND 256),
    purpose text NOT NULL CHECK (purpose = 'BCM_READ_ONLY'),
    username text NOT NULL CHECK (length(username) BETWEEN 1 AND 256),
    operation text NOT NULL CHECK (operation = 'bcm.access_test.v1'),
    plan jsonb NOT NULL,
    plan_digest bytea NOT NULL CHECK (octet_length(plan_digest) = 32),
    requested_by text NOT NULL CHECK (length(requested_by) BETWEEN 1 AND 256),
    requested_at timestamptz NOT NULL,
    deadline timestamptz NOT NULL CHECK (deadline > requested_at),
    status text NOT NULL CHECK (status IN ('REQUESTED','CLAIMED','RUNNING','SUCCEEDED','FAILED','EXPIRED','CANCELLED')),
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 2),
    next_attempt integer NOT NULL DEFAULT 1 CHECK (next_attempt >= 1),
    outcome_code text NOT NULL DEFAULT '' CHECK (length(outcome_code) <= 64),
    outcome_summary text NOT NULL DEFAULT '' CHECK (length(outcome_summary) <= 512),
    bcm_version text NOT NULL DEFAULT '' CHECK (length(bcm_version) <= 64),
    devices_listed integer NOT NULL DEFAULT 0 CHECK (devices_listed >= 0),
    completed_by_collector text,
    completed_at timestamptz,
    cancelled_by text CHECK (cancelled_by IS NULL OR length(cancelled_by) BETWEEN 1 AND 256),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((status IN ('SUCCEEDED','FAILED','EXPIRED','CANCELLED')) = (completed_at IS NOT NULL)),
    CHECK (status <> 'CANCELLED' OR cancelled_by IS NOT NULL)
);

CREATE INDEX credential_access_tests_cluster_idx
    ON credential_access_tests (cluster_id, requested_at DESC, test_id DESC);

CREATE INDEX credential_access_tests_pending_idx
    ON credential_access_tests (cluster_id, requested_at, test_id)
    WHERE status IN ('REQUESTED','CLAIMED','RUNNING');

-- One live test per credential: a second request while one is pending is a
-- conflict, not a queue.
CREATE UNIQUE INDEX credential_access_tests_live_credential_idx
    ON credential_access_tests (credential_id)
    WHERE status IN ('REQUESTED','CLAIMED','RUNNING');

CREATE TABLE credential_access_test_attempts (
    test_id text NOT NULL REFERENCES credential_access_tests(test_id) ON DELETE CASCADE,
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 2),
    collector_id text NOT NULL REFERENCES collectors(collector_id),
    lease_token_hash bytea NOT NULL CHECK (octet_length(lease_token_hash) = 32),
    status text NOT NULL CHECK (status IN ('CLAIMED','STARTED','SUCCEEDED','FAILED','EXPIRED','REJECTED')),
    claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    started_at timestamptz,
    lease_expires_at timestamptz NOT NULL,
    delivery_count integer NOT NULL DEFAULT 0 CHECK (delivery_count BETWEEN 0 AND 2),
    delivered_at timestamptz,
    completed_at timestamptz,
    outcome_code text NOT NULL DEFAULT '' CHECK (length(outcome_code) <= 64),
    PRIMARY KEY (test_id, attempt)
);

CREATE INDEX credential_access_test_attempts_lease_idx
    ON credential_access_test_attempts (lease_expires_at)
    WHERE status IN ('CLAIMED','STARTED');

-- Lifecycle audit: actor or collector, credential version, test/attempt,
-- outcome and timing only. Never a secret, never command output.
CREATE TABLE credential_access_test_events (
    event_id text PRIMARY KEY,
    event_kind text NOT NULL CHECK (event_kind IN ('ACCESS_TEST_REQUESTED','ACCESS_TEST_CLAIMED','CREDENTIAL_DELIVERED','CREDENTIAL_DELIVERY_REFUSED','ACCESS_TEST_COMPLETED','ACCESS_TEST_RESULT_REJECTED','ACCESS_TEST_CANCELLED','ACCESS_TEST_EXPIRED')),
    outcome text NOT NULL CHECK (outcome IN ('SUCCEEDED','REJECTED')),
    reason_code text NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 128),
    actor_kind text NOT NULL CHECK (actor_kind IN ('ACCESS_SUBJECT','COLLECTOR','SYSTEM')),
    actor text NOT NULL CHECK (length(actor) BETWEEN 1 AND 256),
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    test_id text NOT NULL REFERENCES credential_access_tests(test_id) ON DELETE CASCADE,
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    credential_id text NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 128),
    credential_version bigint NOT NULL CHECK (credential_version >= 0),
    request_id text NOT NULL DEFAULT '' CHECK (length(request_id) <= 128),
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX credential_access_test_events_test_idx
    ON credential_access_test_events (test_id, occurred_at DESC, event_id DESC);

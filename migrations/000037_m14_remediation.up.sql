-- M14 remediation persistence.
--
-- Every foreign key here is composite and cluster-carrying, so authorization is
-- reconstructed by joining durable rows rather than trusting a request field, an
-- identifier, a timestamp or a source label. Every closed domain enum is
-- mirrored by a CHECK constraint, so an invalid state cannot be written even by
-- a future code path that forgets to validate.

-- collection_jobs is the Tier 1 target inventory: one "Sherlock-managed
-- collection stream" is one collection_jobs row. Its primary key is job_id
-- alone, so a remediation target row could only reference it without carrying a
-- cluster. This additive composite unique key is what lets the remediation
-- tables below keep every foreign key cluster-carrying.
ALTER TABLE collection_jobs
    ADD CONSTRAINT collection_jobs_cluster_job_key UNIQUE (cluster_id, job_id);

-- The global enablement flag is cluster-independent, so it cannot live on the
-- per-cluster policy table. It is phrased as enablement rather than as a kill
-- switch: a boolean named "kill switch" reads as "not killed" at its zero
-- value, and a failed read would silently disarm it.
CREATE TABLE remediation_global_state (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    remediation_enabled boolean NOT NULL DEFAULT false,
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO remediation_global_state (id, remediation_enabled) VALUES (true, false);

-- The per-cluster standing grant. It is versioned and revocable, and it is
-- re-read inside the dispatch transaction so a revocation between policy check
-- and dispatch still blocks the dispatch.
CREATE TABLE remediation_policies (
    cluster_id text NOT NULL,
    policy_id text NOT NULL,
    version integer NOT NULL CHECK (version > 0),
    recipe_id text NOT NULL,
    recipe_version text NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    max_tier integer NOT NULL CHECK (max_tier BETWEEN 0 AND 4),
    incident_kinds text[] NOT NULL DEFAULT ARRAY[]::text[],
    max_targets integer NOT NULL CHECK (max_targets >= 0),
    max_concurrent_runs integer NOT NULL CHECK (max_concurrent_runs >= 0),
    cooldown_seconds integer NOT NULL CHECK (cooldown_seconds >= 0),
    maintenance_windows jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(maintenance_windows) = 'array'),
    evidence_max_age_seconds integer NOT NULL CHECK (evidence_max_age_seconds >= 0),
    min_evidence_coverage integer NOT NULL CHECK (min_evidence_coverage BETWEEN 0 AND 100),
    require_rollback boolean NOT NULL DEFAULT true,
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (cluster_id, policy_id),
    CHECK (not_after > not_before),
    FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id) ON DELETE RESTRICT
);

-- Immutable record of every recipe reference this deployment has ever acted on.
--
-- This table is written on first use and is NEVER read to authorize anything.
-- The compiled catalog is the only authority on what a recipe says; reading a
-- row here to decide a tier, an operation or an expiry would create a second
-- source of truth that can silently disagree with the catalog.
CREATE TABLE remediation_recipe_refs (
    recipe_id text NOT NULL,
    version text NOT NULL,
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    tier integer NOT NULL CHECK (tier BETWEEN 0 AND 4),
    operation text NOT NULL CHECK (operation IN (
        'SHERLOCK_EVIDENCE_COLLECTION_REQUEUE', 'SHERLOCK_EVIDENCE_COLLECTION_RESTORE')),
    expires_at timestamptz NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (recipe_id, version, digest)
);

COMMENT ON TABLE remediation_recipe_refs IS
    'Audit only. Written on first use and never read to authorize: the compiled catalog is the sole authority on recipe content (M14 amendment H6).';

CREATE TABLE remediation_runs (
    cluster_id text NOT NULL,
    run_id text NOT NULL,
    incident_id text NOT NULL,
    investigation_id text NOT NULL,
    action_card_id text,
    state text NOT NULL CHECK (state IN (
        'PROPOSED', 'POLICY_CHECK', 'PREFLIGHT', 'READY', 'CANARY_EXECUTING', 'VERIFYING',
        'ROLLING_OUT', 'SUCCEEDED', 'POLICY_BLOCKED', 'PREFLIGHT_FAILED', 'ROLLING_BACK',
        'ROLLED_BACK', 'ROLLBACK_FAILED', 'CONTAINED', 'FAILED', 'CANCELLED', 'EXPIRED')),
    version integer NOT NULL CHECK (version > 0),
    recipe_id text NOT NULL,
    recipe_version text NOT NULL,
    recipe_digest bytea NOT NULL CHECK (octet_length(recipe_digest) = 32),
    rollback_recipe_id text,
    rollback_recipe_version text,
    rollback_recipe_digest bytea CHECK (rollback_recipe_digest IS NULL OR octet_length(rollback_recipe_digest) = 32),
    tier integer NOT NULL CHECK (tier BETWEEN 0 AND 4),
    privilege text NOT NULL CHECK (privilege IN ('SHERLOCK_INTERNAL', 'CLUSTER_READ', 'CLUSTER_MUTATE')),
    assurance text NOT NULL CHECK (assurance IN ('SIMULATED', 'RECORDED', 'LIVE')),
    target_set_digest bytea NOT NULL CHECK (octet_length(target_set_digest) = 32),
    arguments_digest bytea NOT NULL CHECK (octet_length(arguments_digest) = 32),
    -- The blast-radius numerator is pinned by target_set_digest; the
    -- denominator has to be pinned separately, or inventory rows appearing
    -- between preflight and dispatch widen the absolute permitted count without
    -- moving any digest.
    pinned_population integer NOT NULL CHECK (pinned_population >= 0),
    max_targets integer NOT NULL CHECK (max_targets > 0),
    max_concurrency integer NOT NULL CHECK (max_concurrency > 0),
    canary_targets integer NOT NULL CHECK (canary_targets > 0),
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 3),
    -- Bounded-loop budgets are persisted, not in-memory: a restart that reset
    -- them would hand the run a fresh repair budget on every crash.
    rollout_wave integer NOT NULL DEFAULT 0 CHECK (rollout_wave >= 0),
    rollback_attempt integer NOT NULL DEFAULT 0 CHECK (rollback_attempt >= 0),
    total_attempts integer NOT NULL DEFAULT 0 CHECK (total_attempts BETWEEN 0 AND 6),
    policy_id text,
    policy_version integer CHECK (policy_version IS NULL OR policy_version > 0),
    policy_code text,
    -- Server-causal: the write path sets this with clock_timestamp() and
    -- ignores any caller-supplied value.
    policy_decided_at timestamptz,
    contained_reason text CHECK (contained_reason IS NULL OR contained_reason IN (
        'LEASE_LOST', 'UNKNOWN_OUTCOME', 'ROLLBACK_UNAVAILABLE', 'ROLLBACK_UNKNOWN',
        'OPERATOR_CONTAINED')),
    attention_required boolean NOT NULL DEFAULT false,
    -- Run-level lease and deadline, following collector_work_items: without
    -- them nothing reclaims a run stranded in POLICY_CHECK, PREFLIGHT, READY,
    -- VERIFYING or ROLLING_BACK after a crash.
    lease_owner text,
    lease_expires_at timestamptz,
    next_attempt_at timestamptz,
    deadline_at timestamptz NOT NULL,
    proposed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY (cluster_id, run_id),
    UNIQUE (run_id),
    CHECK (expires_at > proposed_at),
    CHECK ((rollback_recipe_id IS NULL) = (rollback_recipe_digest IS NULL)),
    CHECK ((rollback_recipe_id IS NULL) = (rollback_recipe_version IS NULL)),
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL)),
    CHECK ((policy_id IS NULL) = (policy_decided_at IS NULL)),
    -- A terminal state carries a completion instant and a non-terminal one does
    -- not, mirroring migration 000031. A run cannot be quietly parked as
    -- finished without one, nor claimed finished while still executing.
    CHECK ((state IN (
        'SUCCEEDED', 'POLICY_BLOCKED', 'PREFLIGHT_FAILED', 'ROLLED_BACK', 'ROLLBACK_FAILED',
        'CONTAINED', 'FAILED', 'CANCELLED', 'EXPIRED')) = (completed_at IS NOT NULL)),
    FOREIGN KEY (cluster_id, incident_id)
        REFERENCES incidents(cluster_id, incident_id) ON DELETE RESTRICT,
    FOREIGN KEY (cluster_id, investigation_id)
        REFERENCES investigations(cluster_id, investigation_id) ON DELETE RESTRICT,
    -- investigation_action_cards has no (cluster_id, action_card_id) unique
    -- key, so this reference cannot carry the cluster itself. The cluster is
    -- carried by the investigation foreign key above, and the action card is
    -- unique per investigation, so the join still reconstructs the cluster.
    FOREIGN KEY (investigation_id, action_card_id)
        REFERENCES investigation_action_cards(investigation_id, action_card_id) ON DELETE RESTRICT
);

-- Two concurrent equivalent incidents must not produce two repairs. The
-- idempotency key includes the run identifier and so can never collide across
-- runs; this partial unique index is the only defence against a duplicate
-- concurrent repair, and it releases automatically when the first run reaches a
-- terminal state.
CREATE UNIQUE INDEX remediation_runs_active_repair_key
    ON remediation_runs (cluster_id, recipe_id, target_set_digest)
    WHERE state NOT IN (
        'SUCCEEDED', 'POLICY_BLOCKED', 'PREFLIGHT_FAILED', 'ROLLED_BACK', 'ROLLBACK_FAILED',
        'CONTAINED', 'FAILED', 'CANCELLED', 'EXPIRED');

CREATE INDEX remediation_runs_reclaim_idx
    ON remediation_runs (cluster_id, state, deadline_at)
    WHERE completed_at IS NULL;

CREATE TABLE remediation_run_targets (
    cluster_id text NOT NULL,
    run_id text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    target text NOT NULL,
    role text NOT NULL CHECK (role IN ('SHERLOCK_MANAGED_COLLECTION_STREAM')),
    source_relation text NOT NULL CHECK (source_relation IN ('COLLECTION_JOBS')),
    resolved_at timestamptz NOT NULL,
    PRIMARY KEY (cluster_id, run_id, target),
    UNIQUE (cluster_id, run_id, ordinal),
    FOREIGN KEY (cluster_id, run_id)
        REFERENCES remediation_runs(cluster_id, run_id) ON DELETE CASCADE,
    -- The resolved target is a durable inventory row in the same cluster, not a
    -- name a proposal supplied.
    FOREIGN KEY (cluster_id, target)
        REFERENCES collection_jobs(cluster_id, job_id) ON DELETE RESTRICT
);

CREATE TABLE remediation_run_arguments (
    cluster_id text NOT NULL,
    run_id text NOT NULL,
    name text NOT NULL,
    argument_type text NOT NULL CHECK (argument_type IN ('ENUM', 'INTEGER', 'DURATION', 'BOOLEAN')),
    enum_value text NOT NULL DEFAULT '',
    integer_value bigint NOT NULL DEFAULT 0,
    duration_value bigint NOT NULL DEFAULT 0,
    boolean_value boolean NOT NULL DEFAULT false,
    PRIMARY KEY (cluster_id, run_id, name),
    -- There is no free-text argument type, and only an ENUM argument carries a
    -- string at all, so a shell fragment, path, URL or credential has nowhere
    -- to live in this table.
    CHECK ((argument_type = 'ENUM') = (enum_value <> '')),
    FOREIGN KEY (cluster_id, run_id)
        REFERENCES remediation_runs(cluster_id, run_id) ON DELETE CASCADE
);

CREATE TABLE remediation_attempts (
    cluster_id text NOT NULL,
    attempt_id text NOT NULL,
    run_id text NOT NULL,
    stage text NOT NULL CHECK (stage IN ('CANARY', 'ROLLOUT', 'ROLLBACK')),
    attempt_number integer NOT NULL CHECK (attempt_number BETWEEN 1 AND 3),
    idempotency_key text NOT NULL,
    wave_target_digest bytea NOT NULL CHECK (octet_length(wave_target_digest) = 32),
    lease_owner text NOT NULL,
    -- Only the hash of the lease token persists. The plaintext token never
    -- reaches a row, a log, an error or a receipt; renewal and finalization
    -- compare hashes in constant time against a matching authenticated cluster.
    lease_token_hash bytea NOT NULL CHECK (octet_length(lease_token_hash) = 32),
    lease_expires_at timestamptz NOT NULL,
    -- A renewal ceiling, so a lease cannot be extended indefinitely.
    lease_deadline_at timestamptz NOT NULL,
    policy_id text NOT NULL,
    policy_version integer NOT NULL CHECK (policy_version > 0),
    -- Policy is evaluated inside the transaction that creates EVERY attempt:
    -- the canary, each rollout wave and each rollback. The CHECK makes an
    -- attempt structurally impossible without an allowing decision.
    policy_code text NOT NULL CHECK (policy_code = 'ALLOWED'),
    policy_decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (cluster_id, attempt_id),
    UNIQUE (attempt_id),
    UNIQUE (idempotency_key),
    UNIQUE (cluster_id, run_id, stage, attempt_number),
    CHECK (lease_expires_at > created_at),
    CHECK (lease_deadline_at >= lease_expires_at),
    FOREIGN KEY (cluster_id, run_id)
        REFERENCES remediation_runs(cluster_id, run_id) ON DELETE RESTRICT
);

-- The subset of the resolved target set one attempt acts on. Without it two
-- rollout waves would differ only by attempt number, and nothing would stop a
-- later wave re-executing the canary's targets. The composite foreign key back
-- to remediation_run_targets is what makes "a wave is a subset of the persisted
-- resolved set" a structural fact rather than a code convention.
CREATE TABLE remediation_attempt_targets (
    cluster_id text NOT NULL,
    attempt_id text NOT NULL,
    run_id text NOT NULL,
    target text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (cluster_id, attempt_id, target),
    UNIQUE (cluster_id, attempt_id, ordinal),
    FOREIGN KEY (cluster_id, attempt_id)
        REFERENCES remediation_attempts(cluster_id, attempt_id) ON DELETE CASCADE,
    FOREIGN KEY (cluster_id, run_id, target)
        REFERENCES remediation_run_targets(cluster_id, run_id, target) ON DELETE RESTRICT
);

-- Receipts are immutable and append-only. observed_at is set by the database
-- and a caller-supplied value is ignored: no caller-supplied timestamp is ever
-- authoritative.
CREATE TABLE remediation_receipts (
    cluster_id text NOT NULL,
    receipt_id text NOT NULL,
    run_id text NOT NULL,
    attempt_id text NOT NULL,
    idempotency_key text NOT NULL,
    stage text NOT NULL CHECK (stage IN ('CANARY', 'ROLLOUT', 'ROLLBACK')),
    outcome text NOT NULL CHECK (outcome IN ('EXECUTED', 'REFUSED', 'FAILED', 'TIMED_OUT', 'UNKNOWN')),
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (cluster_id, receipt_id),
    UNIQUE (receipt_id),
    UNIQUE (idempotency_key),
    -- One receipt per attempt: a duplicate delivery collides here and the
    -- recorded receipt is returned instead of a second mutation.
    UNIQUE (cluster_id, attempt_id),
    FOREIGN KEY (cluster_id, attempt_id)
        REFERENCES remediation_attempts(cluster_id, attempt_id) ON DELETE RESTRICT
);

-- The collapsed attempt outcome is deliberately pessimistic, so the per-target
-- rows are what let a human contain a run and still see which targets executed.
CREATE TABLE remediation_receipt_targets (
    cluster_id text NOT NULL,
    receipt_id text NOT NULL,
    target text NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('EXECUTED', 'REFUSED', 'FAILED', 'TIMED_OUT', 'UNKNOWN')),
    PRIMARY KEY (cluster_id, receipt_id, target),
    FOREIGN KEY (cluster_id, receipt_id)
        REFERENCES remediation_receipts(cluster_id, receipt_id) ON DELETE CASCADE
);

-- Precondition and postcondition results. observation_source names the durable
-- relation the observation was read from: verification is an independent
-- observation of collection_runs, never the executor's own claim of success.
CREATE TABLE remediation_condition_results (
    cluster_id text NOT NULL,
    run_id text NOT NULL,
    phase text NOT NULL CHECK (phase IN ('PREFLIGHT', 'VERIFY', 'ROLLBACK_VERIFY')),
    attempt_number integer NOT NULL DEFAULT 0 CHECK (attempt_number >= 0),
    condition_id text NOT NULL,
    result text NOT NULL CHECK (result IN ('SATISFIED', 'UNSATISFIED', 'UNOBSERVED')),
    observation_source text NOT NULL CHECK (observation_source IN ('COLLECTION_RUNS', 'COLLECTION_JOBS')),
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (cluster_id, run_id, phase, attempt_number, condition_id),
    FOREIGN KEY (cluster_id, run_id)
        REFERENCES remediation_runs(cluster_id, run_id) ON DELETE CASCADE
);

-- The ledger entries this run was authorized against. ledger_entry_id is the
-- real key: investigation_evidence.evidence_id is nullable and unique only
-- within an investigation.
CREATE TABLE remediation_run_evidence (
    cluster_id text NOT NULL,
    run_id text NOT NULL,
    investigation_id text NOT NULL,
    ledger_entry_id text NOT NULL,
    PRIMARY KEY (cluster_id, run_id, ledger_entry_id),
    FOREIGN KEY (cluster_id, run_id)
        REFERENCES remediation_runs(cluster_id, run_id) ON DELETE CASCADE,
    FOREIGN KEY (cluster_id, investigation_id, ledger_entry_id)
        REFERENCES investigation_evidence(cluster_id, investigation_id, ledger_entry_id) ON DELETE RESTRICT
);

-- Append-only who / what / where / when / outcome. It carries bounded
-- attribution and closed codes only: no argument value, no rationale, no
-- executor output.
CREATE TABLE remediation_audit_events (
    event_id text PRIMARY KEY,
    event_kind text NOT NULL CHECK (event_kind IN (
        'PROPOSAL', 'POLICY_DECISION', 'PREFLIGHT', 'DISPATCH', 'RECEIPT', 'VERIFICATION',
        'ROLLBACK', 'CONTAINMENT', 'CANCELLATION', 'EXPIRY')),
    cluster_id text NOT NULL,
    run_id text,
    attempt_id text,
    actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
    outcome text NOT NULL CHECK (length(outcome) BETWEEN 1 AND 64),
    reason_code text NOT NULL DEFAULT '' CHECK (length(reason_code) <= 64),
    recipe_digest bytea NOT NULL CHECK (octet_length(recipe_digest) = 32),
    target_set_digest bytea NOT NULL CHECK (octet_length(target_set_digest) = 32),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id) ON DELETE RESTRICT,
    -- run_id and attempt_id are nullable because a proposal-time event has no
    -- run yet and a run-level event has no attempt. When present they must
    -- resolve, and they must resolve within the SAME cluster: an audit trail
    -- whose subject is unconstrained can attribute an action to a run in
    -- another tenant, which is precisely what the trail exists to rule out.
    FOREIGN KEY (cluster_id, run_id)
        REFERENCES remediation_runs(cluster_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (cluster_id, attempt_id)
        REFERENCES remediation_attempts(cluster_id, attempt_id) ON DELETE RESTRICT,
    CHECK (attempt_id IS NULL OR run_id IS NOT NULL)
);

CREATE INDEX remediation_audit_events_run_idx
    ON remediation_audit_events (cluster_id, run_id, occurred_at);

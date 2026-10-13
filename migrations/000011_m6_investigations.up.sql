CREATE TABLE incidents (
    incident_id text PRIMARY KEY,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version = 1),
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 256),
    summary text NOT NULL DEFAULT '',
    severity text NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status text NOT NULL CHECK (status IN ('OPEN', 'INVESTIGATING', 'MONITORING', 'RESOLVED', 'CLOSED')),
    created_by text NOT NULL,
    version integer NOT NULL DEFAULT 1 CHECK (version > 0),
    next_event_sequence bigint NOT NULL DEFAULT 1 CHECK (next_event_sequence > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    resolved_at timestamptz,
    UNIQUE (cluster_id, incident_id),
    CHECK (updated_at >= created_at),
    CHECK ((status IN ('RESOLVED', 'CLOSED')) = (resolved_at IS NOT NULL)),
    CHECK (resolved_at IS NULL OR resolved_at >= created_at)
);

CREATE INDEX incidents_cluster_status_time_idx
    ON incidents (cluster_id, status, updated_at DESC);

CREATE TABLE incident_events (
    cluster_id text NOT NULL,
    incident_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_key text NOT NULL,
    event_type text NOT NULL CHECK (event_type IN ('CREATED', 'STATUS_CHANGED', 'NOTE_ADDED', 'INVESTIGATION_LINKED')),
    actor_id text NOT NULL,
    incident_version integer NOT NULL CHECK (incident_version > 0),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload) = 'object'),
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (incident_id, sequence),
    UNIQUE (incident_id, event_key),
    FOREIGN KEY (cluster_id, incident_id) REFERENCES incidents(cluster_id, incident_id) ON DELETE CASCADE
);

CREATE INDEX incident_events_cluster_time_idx
    ON incident_events (cluster_id, occurred_at DESC);

CREATE TABLE investigations (
    investigation_id text PRIMARY KEY,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    incident_id text,
    schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version = 1),
    question text NOT NULL CHECK (length(question) BETWEEN 1 AND 4096),
    requested_by text NOT NULL,
    scope jsonb NOT NULL CHECK (jsonb_typeof(scope) = 'object'),
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    success_criteria jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(success_criteria) = 'array'),
    status text NOT NULL CHECK (status IN (
        'INITIALIZING', 'PLANNING', 'POLICY_CHECK', 'AWAITING_APPROVAL', 'EXECUTING',
        'RECORDING_EVIDENCE', 'UPDATING_LEDGER', 'SYNTHESIZING',
        'COMPLETED', 'PARTIAL', 'BLOCKED', 'CANCELLED'
    )),
    stop_reason text NOT NULL DEFAULT '',
    requested_outcome text NOT NULL DEFAULT '' CHECK (requested_outcome IN ('', 'COMPLETED', 'PARTIAL', 'BLOCKED')),
    requested_stop_reason text NOT NULL DEFAULT '',
    version integer NOT NULL DEFAULT 1 CHECK (version > 0),
    next_event_sequence bigint NOT NULL DEFAULT 1 CHECK (next_event_sequence > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    UNIQUE (cluster_id, investigation_id),
    FOREIGN KEY (cluster_id, incident_id) REFERENCES incidents(cluster_id, incident_id) ON DELETE RESTRICT,
    CHECK (window_end >= window_start),
    CHECK (updated_at >= created_at),
    CHECK ((status IN ('COMPLETED', 'PARTIAL', 'BLOCKED', 'CANCELLED')) = (completed_at IS NOT NULL)),
    CHECK ((requested_outcome = '') = (requested_stop_reason = '')),
    CHECK (completed_at IS NULL OR completed_at >= created_at)
);

CREATE INDEX investigations_cluster_status_time_idx
    ON investigations (cluster_id, status, updated_at DESC);

CREATE INDEX investigations_incident_idx
    ON investigations (cluster_id, incident_id, created_at DESC)
    WHERE incident_id IS NOT NULL;

-- The controller allocates sequence by atomically incrementing
-- investigations.next_event_sequence. event_key makes a retried append safe.
CREATE TABLE investigation_events (
    cluster_id text NOT NULL,
    investigation_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_key text NOT NULL,
    event_type text NOT NULL CHECK (event_type IN (
        'CREATED', 'STATE_TRANSITION', 'BUDGET_RESERVED', 'BUDGET_CONSUMED',
        'ACTION_PROPOSED', 'ACTION_REJECTED', 'ACTION_LEASED', 'ACTION_COMPLETED',
        'APPROVAL_REQUESTED', 'APPROVAL_RESOLVED', 'EVIDENCE_RECORDED',
        'HYPOTHESIS_UPDATED', 'FINDING_PUBLISHED', 'CANCEL_REQUESTED'
    )),
    from_status text,
    to_status text,
    investigation_version integer NOT NULL CHECK (investigation_version > 0),
    actor_id text NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload) = 'object'),
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (investigation_id, sequence),
    UNIQUE (investigation_id, event_key),
    FOREIGN KEY (cluster_id, investigation_id)
        REFERENCES investigations(cluster_id, investigation_id) ON DELETE CASCADE,
    CHECK ((event_type = 'STATE_TRANSITION') = (from_status IS NOT NULL AND to_status IS NOT NULL)),
    CHECK (from_status IS NULL OR from_status <> to_status)
);

CREATE INDEX investigation_events_cluster_time_idx
    ON investigation_events (cluster_id, occurred_at DESC);

CREATE TABLE investigation_budgets (
    investigation_id text PRIMARY KEY,
    cluster_id text NOT NULL,
    deadline timestamptz NOT NULL,
    max_decision_iterations integer NOT NULL CHECK (max_decision_iterations BETWEEN 1 AND 100),
    used_decision_iterations integer NOT NULL DEFAULT 0 CHECK (used_decision_iterations >= 0),
    max_tool_calls integer NOT NULL CHECK (max_tool_calls BETWEEN 1 AND 1000),
    used_tool_calls integer NOT NULL DEFAULT 0 CHECK (used_tool_calls >= 0),
    max_privileged_calls integer NOT NULL CHECK (max_privileged_calls BETWEEN 0 AND 100),
    used_privileged_calls integer NOT NULL DEFAULT 0 CHECK (used_privileged_calls >= 0),
    max_fan_out integer NOT NULL CHECK (max_fan_out BETWEEN 1 AND 10000),
    used_fan_out integer NOT NULL DEFAULT 0 CHECK (used_fan_out >= 0),
    max_model_tokens bigint NOT NULL CHECK (max_model_tokens >= 0),
    used_model_tokens bigint NOT NULL DEFAULT 0 CHECK (used_model_tokens >= 0),
    max_cost_microunits bigint NOT NULL CHECK (max_cost_microunits >= 0),
    used_cost_microunits bigint NOT NULL DEFAULT 0 CHECK (used_cost_microunits >= 0),
    version integer NOT NULL DEFAULT 1 CHECK (version > 0),
    FOREIGN KEY (cluster_id, investigation_id)
        REFERENCES investigations(cluster_id, investigation_id) ON DELETE CASCADE,
    CHECK (used_decision_iterations <= max_decision_iterations),
    CHECK (used_tool_calls <= max_tool_calls),
    CHECK (used_privileged_calls <= max_privileged_calls),
    CHECK (used_fan_out <= max_fan_out),
    CHECK (used_model_tokens <= max_model_tokens),
    CHECK (used_cost_microunits <= max_cost_microunits)
);

-- Each reservation is immutable and idempotent. The snapshot above and its
-- reservation row must be updated/inserted in the same transaction.
CREATE TABLE investigation_budget_reservations (
    reservation_id text PRIMARY KEY,
    cluster_id text NOT NULL,
    investigation_id text NOT NULL,
    reservation_key text NOT NULL,
    decision_iterations integer NOT NULL DEFAULT 0 CHECK (decision_iterations >= 0),
    tool_calls integer NOT NULL DEFAULT 0 CHECK (tool_calls >= 0),
    privileged_calls integer NOT NULL DEFAULT 0 CHECK (privileged_calls >= 0),
    fan_out integer NOT NULL DEFAULT 0 CHECK (fan_out >= 0),
    model_tokens bigint NOT NULL DEFAULT 0 CHECK (model_tokens >= 0),
    cost_microunits bigint NOT NULL DEFAULT 0 CHECK (cost_microunits >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (investigation_id, reservation_key),
    FOREIGN KEY (cluster_id, investigation_id)
        REFERENCES investigations(cluster_id, investigation_id) ON DELETE CASCADE,
    CHECK (decision_iterations + tool_calls + privileged_calls + fan_out + model_tokens + cost_microunits > 0)
);

-- A step is the resumable unit of the state machine. A lease token is stored
-- only as a digest, while lease_epoch rejects stale workers after reclamation.
CREATE TABLE investigation_steps (
    step_id text PRIMARY KEY,
    cluster_id text NOT NULL,
    investigation_id text NOT NULL,
    step_key text NOT NULL,
    kind text NOT NULL CHECK (kind IN (
        'INITIALIZE', 'BASELINE', 'PLAN', 'POLICY_CHECK', 'EXECUTE',
        'RECORD_EVIDENCE', 'UPDATE_LEDGER', 'SYNTHESIZE'
    )),
    status text NOT NULL CHECK (status IN ('AVAILABLE', 'LEASED', 'PAUSED', 'COMPLETED', 'FAILED', 'CANCELLED')),
    investigation_version integer NOT NULL CHECK (investigation_version > 0),
    available_at timestamptz NOT NULL,
    lease_owner text,
    lease_token_hash bytea,
    lease_expires_at timestamptz,
    lease_epoch integer NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts integer NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10),
    completion_receipt text,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (investigation_id, step_key),
    UNIQUE (cluster_id, investigation_id, step_id),
    UNIQUE (completion_receipt),
    FOREIGN KEY (cluster_id, investigation_id)
        REFERENCES investigations(cluster_id, investigation_id) ON DELETE CASCADE,
    CHECK (
        (status = 'LEASED' AND lease_owner IS NOT NULL AND lease_token_hash IS NOT NULL
            AND octet_length(lease_token_hash) = 32 AND lease_expires_at IS NOT NULL)
        OR
        (status <> 'LEASED' AND lease_owner IS NULL AND lease_token_hash IS NULL AND lease_expires_at IS NULL)
    ),
    CHECK ((status IN ('COMPLETED', 'FAILED', 'CANCELLED')) = (completed_at IS NOT NULL)),
    CHECK ((status = 'COMPLETED') = (completion_receipt IS NOT NULL))
);

CREATE INDEX investigation_steps_available_idx
    ON investigation_steps (available_at, step_id)
    WHERE status = 'AVAILABLE';

CREATE INDEX investigation_steps_expired_lease_idx
    ON investigation_steps (lease_expires_at, step_id)
    WHERE status = 'LEASED';

-- Actions are separately durable because an EXECUTE step may contain several
-- calls. action_key and execution_idempotency_key survive controller crashes;
-- a unique diagnostic_run_id/receipt prevents a privileged call being applied
-- twice when the lease is reclaimed after execution.
CREATE TABLE investigation_actions (
    action_id text PRIMARY KEY,
    cluster_id text NOT NULL,
    investigation_id text NOT NULL,
    step_id text NOT NULL,
    action_key text NOT NULL,
    tool_id text NOT NULL,
    arguments jsonb NOT NULL CHECK (jsonb_typeof(arguments) = 'object'),
    purpose text NOT NULL,
    expected_information text NOT NULL,
    action_digest bytea NOT NULL CHECK (octet_length(action_digest) = 32),
    privilege text NOT NULL CHECK (privilege IN ('UNPRIVILEGED', 'PRIVILEGED')),
    status text NOT NULL CHECK (status IN (
        'PROPOSED', 'NEEDS_APPROVAL', 'AVAILABLE', 'LEASED', 'DISPATCHED',
        'SUCCEEDED', 'FAILED', 'REJECTED', 'CANCELLED'
    )),
    rejection_code text NOT NULL DEFAULT '',
    execution_idempotency_key text NOT NULL,
    lease_owner text,
    lease_token_hash bytea,
    lease_expires_at timestamptz,
    lease_epoch integer NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    diagnostic_run_id text UNIQUE REFERENCES diagnostic_runs(run_id) ON DELETE RESTRICT,
    execution_receipt text UNIQUE,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (investigation_id, action_key),
    UNIQUE (cluster_id, execution_idempotency_key),
    UNIQUE (cluster_id, investigation_id, action_id),
    FOREIGN KEY (cluster_id, investigation_id, step_id)
        REFERENCES investigation_steps(cluster_id, investigation_id, step_id) ON DELETE CASCADE,
    CHECK (
        (status = 'LEASED' AND lease_owner IS NOT NULL AND lease_token_hash IS NOT NULL
            AND octet_length(lease_token_hash) = 32 AND lease_expires_at IS NOT NULL)
        OR
        (status <> 'LEASED' AND lease_owner IS NULL AND lease_token_hash IS NULL AND lease_expires_at IS NULL)
    ),
    CHECK ((status IN ('SUCCEEDED', 'FAILED', 'REJECTED', 'CANCELLED')) = (completed_at IS NOT NULL)),
    CHECK (status <> 'SUCCEEDED' OR execution_receipt IS NOT NULL)
);

CREATE INDEX investigation_actions_available_idx
    ON investigation_actions (cluster_id, investigation_id, action_id)
    WHERE status = 'AVAILABLE';

CREATE INDEX investigation_actions_expired_lease_idx
    ON investigation_actions (lease_expires_at, action_id)
    WHERE status = 'LEASED';

CREATE TABLE investigation_approvals (
    approval_id text PRIMARY KEY,
    cluster_id text NOT NULL,
    investigation_id text NOT NULL,
    action_id text NOT NULL,
    action_digest bytea NOT NULL CHECK (octet_length(action_digest) = 32),
    investigation_version integer NOT NULL CHECK (investigation_version > 0),
    status text NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'REVOKED', 'CONSUMED')),
    requested_by text NOT NULL,
    requested_at timestamptz NOT NULL,
    resolved_by text,
    resolved_at timestamptz,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    UNIQUE (investigation_id, action_id, action_digest, investigation_version),
    FOREIGN KEY (cluster_id, investigation_id, action_id)
        REFERENCES investigation_actions(cluster_id, investigation_id, action_id) ON DELETE RESTRICT,
    CHECK (expires_at > requested_at),
    CHECK (expires_at <= requested_at + interval '15 minutes'),
    CHECK ((status = 'PENDING') = (resolved_at IS NULL)),
    CHECK ((status IN ('APPROVED', 'DENIED', 'REVOKED', 'CONSUMED')) = (resolved_by IS NOT NULL)),
    CHECK ((status = 'CONSUMED') = (consumed_at IS NOT NULL)),
    CHECK (consumed_at IS NULL OR consumed_at >= resolved_at)
);

CREATE INDEX investigation_approvals_pending_idx
    ON investigation_approvals (expires_at, approval_id)
    WHERE status = 'PENDING';

CREATE TABLE investigation_evidence (
    ledger_entry_id text PRIMARY KEY,
    cluster_id text NOT NULL,
    investigation_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    action_id text,
    evidence_id text,
    entry_kind text NOT NULL CHECK (entry_kind IN ('OBSERVATION', 'COLLECTION_FAILURE', 'SOURCE_FRESHNESS')),
    status text NOT NULL CHECK (status IN ('COMPLETE', 'PARTIAL', 'NO_DATA', 'UNAVAILABLE')),
    exact_scope jsonb NOT NULL CHECK (jsonb_typeof(exact_scope) = 'object'),
    observed_start timestamptz NOT NULL,
    observed_end timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    UNIQUE (investigation_id, sequence),
    UNIQUE (investigation_id, evidence_id),
    UNIQUE (cluster_id, investigation_id, ledger_entry_id),
    FOREIGN KEY (cluster_id, investigation_id)
        REFERENCES investigations(cluster_id, investigation_id) ON DELETE CASCADE,
    FOREIGN KEY (cluster_id, investigation_id, action_id)
        REFERENCES investigation_actions(cluster_id, investigation_id, action_id) ON DELETE RESTRICT,
    FOREIGN KEY (evidence_id) REFERENCES evidence_envelopes(evidence_id) ON DELETE RESTRICT,
    CHECK (observed_end >= observed_start),
    CHECK (recorded_at >= observed_end),
    CHECK ((entry_kind = 'OBSERVATION') = (evidence_id IS NOT NULL))
);

CREATE INDEX investigation_evidence_time_idx
    ON investigation_evidence (cluster_id, investigation_id, observed_start, sequence);

CREATE TABLE investigation_hypotheses (
    hypothesis_id text PRIMARY KEY,
    cluster_id text NOT NULL,
    investigation_id text NOT NULL,
    statement text NOT NULL CHECK (length(statement) BETWEEN 1 AND 4096),
    status text NOT NULL CHECK (status IN ('PROPOSED', 'SUPPORTED', 'WEAKENED', 'REFUTED', 'UNRESOLVED')),
    confidence double precision CHECK (confidence BETWEEN 0 AND 1),
    unresolved_tests jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(unresolved_tests) = 'array'),
    version integer NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (cluster_id, investigation_id, hypothesis_id),
    FOREIGN KEY (cluster_id, investigation_id)
        REFERENCES investigations(cluster_id, investigation_id) ON DELETE CASCADE,
    CHECK (updated_at >= created_at)
);

CREATE TABLE investigation_hypothesis_evidence (
    cluster_id text NOT NULL,
    investigation_id text NOT NULL,
    hypothesis_id text NOT NULL,
    ledger_entry_id text NOT NULL,
    relationship text NOT NULL CHECK (relationship IN ('SUPPORTS', 'CONTRADICTS')),
    PRIMARY KEY (hypothesis_id, ledger_entry_id, relationship),
    FOREIGN KEY (cluster_id, investigation_id, hypothesis_id)
        REFERENCES investigation_hypotheses(cluster_id, investigation_id, hypothesis_id) ON DELETE CASCADE,
    FOREIGN KEY (cluster_id, investigation_id, ledger_entry_id)
        REFERENCES investigation_evidence(cluster_id, investigation_id, ledger_entry_id) ON DELETE RESTRICT
);

CREATE TABLE investigation_findings (
    finding_id text PRIMARY KEY,
    cluster_id text NOT NULL,
    investigation_id text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('OBSERVATION', 'DERIVED_SIGNAL', 'HYPOTHESIS', 'RECOMMENDATION')),
    statement text NOT NULL CHECK (length(statement) BETWEEN 1 AND 4096),
    scope jsonb NOT NULL CHECK (jsonb_typeof(scope) = 'object'),
    severity text NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    confidence double precision,
    status text NOT NULL CHECK (status IN ('DRAFT', 'CURRENT', 'SUPERSEDED', 'REJECTED')),
    validation_status text NOT NULL CHECK (validation_status IN ('PENDING', 'VALID', 'INVALID')),
    validation_code text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    validated_at timestamptz,
    UNIQUE (cluster_id, investigation_id, finding_id),
    FOREIGN KEY (cluster_id, investigation_id)
        REFERENCES investigations(cluster_id, investigation_id) ON DELETE CASCADE,
    CHECK ((kind = 'HYPOTHESIS') = (confidence IS NOT NULL)),
    CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
    CHECK ((validation_status = 'PENDING') = (validated_at IS NULL)),
    CHECK (status <> 'CURRENT' OR validation_status = 'VALID')
);

CREATE INDEX investigation_findings_current_idx
    ON investigation_findings (cluster_id, investigation_id, kind)
    WHERE status = 'CURRENT';

CREATE TABLE investigation_finding_citations (
    cluster_id text NOT NULL,
    investigation_id text NOT NULL,
    finding_id text NOT NULL,
    ledger_entry_id text NOT NULL,
    relationship text NOT NULL CHECK (relationship IN ('EVIDENCE', 'COUNTER_EVIDENCE')),
    PRIMARY KEY (finding_id, ledger_entry_id, relationship),
    FOREIGN KEY (cluster_id, investigation_id, finding_id)
        REFERENCES investigation_findings(cluster_id, investigation_id, finding_id) ON DELETE CASCADE,
    FOREIGN KEY (cluster_id, investigation_id, ledger_entry_id)
        REFERENCES investigation_evidence(cluster_id, investigation_id, ledger_entry_id) ON DELETE RESTRICT
);

-- API retries reserve an operation/key before creating a resource. request_hash
-- detects key reuse with different input; the lease permits recovery from a
-- crashed owner without returning an invented response.
CREATE TABLE investigation_idempotency_records (
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    operation text NOT NULL CHECK (operation IN (
        'CREATE_INCIDENT', 'UPDATE_INCIDENT', 'CREATE_INVESTIGATION',
        'CANCEL_INVESTIGATION', 'RESOLVE_APPROVAL'
    )),
    idempotency_key text NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    status text NOT NULL CHECK (status IN ('IN_PROGRESS', 'COMPLETED', 'FAILED')),
    resource_kind text,
    resource_id text,
    response_code integer CHECK (response_code BETWEEN 100 AND 599),
    lease_owner text,
    lease_token_hash bytea,
    lease_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY (cluster_id, operation, idempotency_key),
    CHECK (
        (status = 'IN_PROGRESS' AND lease_owner IS NOT NULL AND lease_token_hash IS NOT NULL
            AND octet_length(lease_token_hash) = 32 AND lease_expires_at IS NOT NULL
            AND completed_at IS NULL)
        OR
        (status <> 'IN_PROGRESS' AND lease_owner IS NULL AND lease_token_hash IS NULL
            AND lease_expires_at IS NULL AND completed_at IS NOT NULL)
    ),
    CHECK ((status = 'COMPLETED') = (resource_kind IS NOT NULL AND resource_id IS NOT NULL AND response_code IS NOT NULL))
);

CREATE INDEX investigation_idempotency_in_progress_idx
    ON investigation_idempotency_records (lease_expires_at)
    WHERE status = 'IN_PROGRESS';

ALTER TABLE cluster_events DROP CONSTRAINT cluster_events_event_type_check;
ALTER TABLE cluster_events ADD CONSTRAINT cluster_events_event_type_check CHECK (event_type IN (
    'collection.updated', 'source.updated', 'incident.updated', 'investigation.updated'
));

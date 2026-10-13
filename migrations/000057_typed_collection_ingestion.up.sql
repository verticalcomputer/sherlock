-- GP-03c adds a plan to the existing queue; work/attempt rows remain the only
-- claim, lease, retry and terminal-state authority.
ALTER TABLE sources DROP CONSTRAINT sources_kind_check;
ALTER TABLE sources ADD CONSTRAINT sources_kind_check
    CHECK (kind IN ('prometheus', 'model', 'diagnostic', 'slurm'));
ALTER TABLE collector_work_items ADD COLUMN typed_plan jsonb;
ALTER TABLE collector_work_items ADD CONSTRAINT collector_typed_plan_identity CHECK (
    typed_plan IS NULL OR COALESCE(
        jsonb_typeof(typed_plan)='object'
        AND typed_plan->>'schema_version'='2'
        AND typed_plan->>'run_id'=run_id
        AND typed_plan->>'cluster_id'=cluster_id
        AND typed_plan->>'source_id'=source_id
        AND typed_plan->>'operation'=query_kind
        AND typed_plan->>'idempotency_key'=idempotency_key, false)
);

CREATE FUNCTION guard_typed_collection_plan() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.typed_plan IS DISTINCT FROM OLD.typed_plan THEN
        RAISE EXCEPTION 'typed collection plan is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER guard_typed_collection_plan BEFORE UPDATE OF typed_plan ON collector_work_items
    FOR EACH ROW EXECUTE FUNCTION guard_typed_collection_plan();

-- The canonical document is the durable artifact and preserves every current
-- envelope reference, including inventory revision and metric source reference.
CREATE TABLE collector_typed_result_ingestions (
    work_id text NOT NULL,
    attempt integer NOT NULL,
    collector_id text NOT NULL REFERENCES collectors(collector_id),
    run_id text NOT NULL UNIQUE REFERENCES collection_runs(run_id),
    cluster_id text NOT NULL,
    source_id text NOT NULL,
    operation text NOT NULL,
    payload_schema text NOT NULL,
    result_status text NOT NULL CHECK (result_status IN ('SUCCEEDED','NO_DATA','PARTIAL','FAILED')),
    document bytea NOT NULL CHECK (octet_length(document) BETWEEN 1 AND 10485760),
    sha256 bytea NOT NULL CHECK (octet_length(sha256)=32),
    finalized_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (work_id, attempt),
    UNIQUE (cluster_id, source_id, run_id),
    FOREIGN KEY (work_id, attempt) REFERENCES collector_work_attempts(work_id, attempt),
    FOREIGN KEY (cluster_id, source_id) REFERENCES sources(cluster_id, source_id)
);

CREATE TABLE goodput_source_coverage (
    run_id text PRIMARY KEY,
    cluster_id text NOT NULL,
    source_id text NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version=1),
    scope text NOT NULL CHECK (scope IN ('INVENTORY','ALLOCATIONS','METRICS','EVENTS','PROGRESS')),
    state text NOT NULL CHECK (state IN ('UNKNOWN','COMPLETE','PARTIAL','UNAVAILABLE','UNSUPPORTED')),
    expected integer NOT NULL CHECK (expected>=0),
    observed integer NOT NULL CHECK (observed>=0 AND observed<=expected),
    source_at timestamptz NOT NULL,
    effective_at timestamptz NOT NULL,
    observed_at timestamptz NOT NULL,
    FOREIGN KEY (cluster_id, source_id, run_id) REFERENCES collector_typed_result_ingestions(cluster_id, source_id, run_id)
);
CREATE INDEX goodput_source_coverage_history_idx ON goodput_source_coverage
    (cluster_id, source_id, scope, effective_at DESC, observed_at DESC);

CREATE TABLE goodput_collection_events (
    cluster_id text NOT NULL,
    source_id text NOT NULL,
    event_id text NOT NULL,
    run_id text NOT NULL,
    stable_node_id text NOT NULL,
    scheduler_namespace text NOT NULL,
    scheduler_job_id text NOT NULL,
    submit_at timestamptz NOT NULL,
    attempt integer NOT NULL CHECK (attempt>=0),
    allocation_state text NOT NULL CHECK (allocation_state IN ('UNKNOWN','PENDING','RUNNING','SUSPENDED','COMPLETING','COMPLETED','CANCELLED','FAILED','UNSUPPORTED')),
    occurred_at timestamptz NOT NULL,
    sha256 bytea NOT NULL CHECK (octet_length(sha256)=32),
    PRIMARY KEY (cluster_id, source_id, event_id),
    FOREIGN KEY (cluster_id, source_id, run_id) REFERENCES collector_typed_result_ingestions(cluster_id, source_id, run_id)
);

-- Stable node binding is retained independently of arbitrary metric labels.
CREATE TABLE goodput_metric_nodes (
    observation_id text PRIMARY KEY REFERENCES observations(observation_id),
    run_id text NOT NULL,
    cluster_id text NOT NULL,
    source_id text NOT NULL,
    stable_node_id text NOT NULL,
    FOREIGN KEY (cluster_id, source_id, run_id) REFERENCES collector_typed_result_ingestions(cluster_id, source_id, run_id)
);

-- Cursors are scoped to source, reviewed operation and the sorted node scope.
-- They are changed only by result finalization, never enqueue/claim/start.
CREATE TABLE collector_source_cursors (
    cluster_id text NOT NULL,
    source_id text NOT NULL,
    operation text NOT NULL,
    scope_sha256 bytea NOT NULL CHECK (octet_length(scope_sha256)=32),
    cursor text NOT NULL,
    run_id text NOT NULL,
    PRIMARY KEY (cluster_id, source_id, operation, scope_sha256),
    FOREIGN KEY (cluster_id, source_id, run_id) REFERENCES collector_typed_result_ingestions(cluster_id, source_id, run_id)
);

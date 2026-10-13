CREATE TABLE IF NOT EXISTS schema_migrations (
    version bigint PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE clusters (
    cluster_id text PRIMARY KEY,
    display_name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    removed_at timestamptz
);

CREATE TABLE sources (
    source_id text PRIMARY KEY,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    kind text NOT NULL CHECK (kind = 'prometheus'),
    display_name text NOT NULL,
    availability text NOT NULL DEFAULT 'UNKNOWN' CHECK (availability IN ('UNKNOWN', 'AVAILABLE', 'UNAVAILABLE')),
    last_attempt_at timestamptz,
    last_success_at timestamptz,
    last_failure_code text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE collection_jobs (
    job_id text PRIMARY KEY,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    source_id text NOT NULL REFERENCES sources(source_id),
    query_kind text NOT NULL,
    node_filter text NOT NULL DEFAULT '',
    interval_seconds integer NOT NULL CHECK (interval_seconds > 0),
    next_run_at timestamptz NOT NULL,
    lease_owner text,
    lease_expires_at timestamptz,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    active boolean NOT NULL DEFAULT true,
    UNIQUE (source_id, query_kind, node_filter)
);

CREATE INDEX collection_jobs_due_idx ON collection_jobs (next_run_at) WHERE active;

CREATE TABLE collection_runs (
    run_id text PRIMARY KEY,
    job_id text REFERENCES collection_jobs(job_id),
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    source_id text NOT NULL REFERENCES sources(source_id),
    query_kind text NOT NULL,
    idempotency_key text NOT NULL UNIQUE,
    status text NOT NULL CHECK (status IN ('SUCCEEDED', 'NO_DATA', 'PARTIAL', 'FAILED')),
    scheduled_for timestamptz NOT NULL,
    started_at timestamptz NOT NULL,
    completed_at timestamptz NOT NULL,
    series_returned integer NOT NULL CHECK (series_returned >= 0),
    bytes_read bigint NOT NULL CHECK (bytes_read >= 0),
    coverage_complete boolean NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX collection_runs_source_time_idx ON collection_runs (source_id, completed_at DESC);

CREATE TABLE collection_failures (
    failure_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id text NOT NULL REFERENCES collection_runs(run_id) ON DELETE CASCADE,
    code text NOT NULL,
    retryable boolean NOT NULL,
    target text NOT NULL DEFAULT '',
    safe_message text NOT NULL,
    UNIQUE (run_id, code, target)
);

CREATE TABLE observations (
    observation_id text PRIMARY KEY,
    run_id text NOT NULL REFERENCES collection_runs(run_id),
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    source_id text NOT NULL REFERENCES sources(source_id),
    schema_version integer NOT NULL CHECK (schema_version > 0),
    kind text NOT NULL,
    entity_key text NOT NULL,
    metric text NOT NULL,
    labels jsonb NOT NULL,
    value double precision NOT NULL,
    unit text NOT NULL,
    observed_at timestamptz NOT NULL,
    collected_at timestamptz NOT NULL,
    source_reference text NOT NULL,
    sample_fingerprint bytea NOT NULL,
    UNIQUE (run_id, sample_fingerprint)
);

CREATE INDEX observations_entity_time_idx ON observations (cluster_id, entity_key, observed_at DESC);
CREATE INDEX observations_retention_idx ON observations (collected_at);

CREATE TABLE current_projections (
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    source_id text NOT NULL REFERENCES sources(source_id),
    entity_key text NOT NULL,
    metric text NOT NULL,
    observation_id text NOT NULL REFERENCES observations(observation_id),
    observed_at timestamptz NOT NULL,
    last_success_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (cluster_id, source_id, entity_key, metric)
);

CREATE TABLE collection_events (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id text NOT NULL UNIQUE REFERENCES collection_runs(run_id),
    event_type text NOT NULL,
    schema_version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

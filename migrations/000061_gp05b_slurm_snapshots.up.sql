-- GP-05b keeps Slurm source evidence durable without making receipt time part
-- of overlap deduplication. GP-02 inventory/allocation tables remain canonical.
CREATE TABLE goodput_slurm_allocation_facts (
    cluster_id text NOT NULL,
    source_id text NOT NULL,
    record_identity text NOT NULL,
    snapshot_key text NOT NULL,
    core_sha256 bytea NOT NULL CHECK (octet_length(core_sha256)=32),
    first_run_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (cluster_id, source_id, record_identity),
    FOREIGN KEY (cluster_id, source_id) REFERENCES sources(cluster_id, source_id),
    FOREIGN KEY (cluster_id, snapshot_key) REFERENCES goodput_allocation_snapshots(cluster_id, snapshot_key),
    FOREIGN KEY (cluster_id, source_id, first_run_id) REFERENCES collector_typed_result_ingestions(cluster_id, source_id, run_id)
);

CREATE TABLE goodput_slurm_allocation_observations (
    cluster_id text NOT NULL,
    source_id text NOT NULL,
    record_identity text NOT NULL,
    run_id text NOT NULL,
    source_at timestamptz NOT NULL,
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (cluster_id, source_id, record_identity, run_id),
    FOREIGN KEY (cluster_id, source_id, record_identity) REFERENCES goodput_slurm_allocation_facts(cluster_id, source_id, record_identity),
    FOREIGN KEY (cluster_id, source_id, run_id) REFERENCES collector_typed_result_ingestions(cluster_id, source_id, run_id)
);

CREATE TABLE goodput_slurm_lifecycle_facts (
    cluster_id text NOT NULL,
    source_id text NOT NULL,
    record_identity text NOT NULL,
    document jsonb NOT NULL,
    core_sha256 bytea NOT NULL CHECK (octet_length(core_sha256)=32),
    first_run_id text NOT NULL,
    PRIMARY KEY (cluster_id, source_id, record_identity),
    FOREIGN KEY (cluster_id, source_id) REFERENCES sources(cluster_id, source_id),
    FOREIGN KEY (cluster_id, source_id, first_run_id) REFERENCES collector_typed_result_ingestions(cluster_id, source_id, run_id)
);

CREATE TABLE goodput_slurm_lifecycle_observations (
    cluster_id text NOT NULL,
    source_id text NOT NULL,
    record_identity text NOT NULL,
    run_id text NOT NULL,
    PRIMARY KEY (cluster_id, source_id, record_identity, run_id),
    FOREIGN KEY (cluster_id, source_id, record_identity) REFERENCES goodput_slurm_lifecycle_facts(cluster_id, source_id, record_identity),
    FOREIGN KEY (cluster_id, source_id, run_id) REFERENCES collector_typed_result_ingestions(cluster_id, source_id, run_id)
);

CREATE TABLE goodput_slurm_unresolved_accounting (
    cluster_id text NOT NULL,
    source_id text NOT NULL,
    record_identity text NOT NULL,
    document jsonb NOT NULL,
    core_sha256 bytea NOT NULL CHECK (octet_length(core_sha256)=32),
    first_run_id text NOT NULL,
    PRIMARY KEY (cluster_id, source_id, record_identity),
    FOREIGN KEY (cluster_id, source_id) REFERENCES sources(cluster_id, source_id),
    FOREIGN KEY (cluster_id, source_id, first_run_id) REFERENCES collector_typed_result_ingestions(cluster_id, source_id, run_id)
);

CREATE TABLE goodput_slurm_accounting_provenance (
    cluster_id text NOT NULL,
    source_id text NOT NULL,
    record_identity text NOT NULL,
    run_id text NOT NULL,
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    source_at timestamptz NOT NULL,
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (cluster_id, source_id, record_identity, run_id, window_start, window_end, source_at, observed_at),
    FOREIGN KEY (cluster_id, source_id, record_identity) REFERENCES goodput_slurm_unresolved_accounting(cluster_id, source_id, record_identity),
    FOREIGN KEY (cluster_id, source_id, run_id) REFERENCES collector_typed_result_ingestions(cluster_id, source_id, run_id)
);

CREATE TABLE goodput_slurm_snapshot_issues (
    run_id text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal>=0),
    document jsonb NOT NULL,
    PRIMARY KEY (run_id, ordinal),
    FOREIGN KEY (run_id) REFERENCES collector_typed_result_ingestions(run_id)
);

CREATE TABLE goodput_slurm_snapshot_sources (
    run_id text NOT NULL,
    source_kind text NOT NULL CHECK (source_kind IN ('nodes','partitions','jobs','accounting')),
    document jsonb NOT NULL,
    PRIMARY KEY (run_id, source_kind),
    FOREIGN KEY (run_id) REFERENCES collector_typed_result_ingestions(run_id)
);

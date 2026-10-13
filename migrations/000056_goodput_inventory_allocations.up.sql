-- GP-02b: immutable goodput inventory and allocation facts.  These tables are
-- intentionally separate from collection_target_inventory: that table is an
-- observed Prometheus target cache, while this schema retains source and
-- effective-time provenance for expected and observed fleet inventory.
CREATE TABLE goodput_inventory_revisions (
    revision_id text PRIMARY KEY,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    source_id text NOT NULL,
    inventory_class text NOT NULL CHECK (inventory_class IN ('EXPECTED', 'OBSERVED')),
    schema_version integer NOT NULL CHECK (schema_version > 0),
    content_digest bytea NOT NULL CHECK (octet_length(content_digest) = 32),
    source_at timestamptz NOT NULL,
    effective_at timestamptz NOT NULL,
    observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (cluster_id, revision_id),
    UNIQUE (cluster_id, source_id, inventory_class, revision_id),
    FOREIGN KEY (cluster_id, source_id) REFERENCES sources(cluster_id, source_id)
);

CREATE TABLE goodput_inventory_revision_entities (
    cluster_id text NOT NULL,
    revision_id text NOT NULL,
    entity_kind text NOT NULL CHECK (entity_kind IN ('NODE', 'GPU', 'MIG')),
    stable_node_id text NOT NULL,
    physical_gpu_uuid text NOT NULL DEFAULT '',
    mig_identity text NOT NULL DEFAULT '',
    PRIMARY KEY (cluster_id, revision_id, entity_kind, stable_node_id, physical_gpu_uuid, mig_identity),
    FOREIGN KEY (cluster_id, revision_id) REFERENCES goodput_inventory_revisions(cluster_id, revision_id),
    CHECK (
        (entity_kind = 'NODE' AND physical_gpu_uuid = '' AND mig_identity = '') OR
        (entity_kind = 'GPU' AND physical_gpu_uuid <> '' AND mig_identity = '') OR
        (entity_kind = 'MIG' AND physical_gpu_uuid <> '' AND mig_identity <> '')
    )
);

-- Validity is a rebuildable projection.  Raw revision rows are never changed
-- when late source evidence arrives.
CREATE TABLE goodput_inventory_revision_validity (
    cluster_id text NOT NULL,
    revision_id text NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_to timestamptz,
    PRIMARY KEY (cluster_id, revision_id),
    FOREIGN KEY (cluster_id, revision_id) REFERENCES goodput_inventory_revisions(cluster_id, revision_id),
    CHECK (valid_to IS NULL OR valid_to >= valid_from)
);

CREATE TABLE goodput_current_inventory (
    cluster_id text NOT NULL,
    source_id text NOT NULL,
    inventory_class text NOT NULL CHECK (inventory_class IN ('EXPECTED', 'OBSERVED')),
    revision_id text NOT NULL,
    effective_at timestamptz NOT NULL,
    source_at timestamptz NOT NULL,
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (cluster_id, source_id, inventory_class),
    FOREIGN KEY (cluster_id, source_id, inventory_class, revision_id)
        REFERENCES goodput_inventory_revisions(cluster_id, source_id, inventory_class, revision_id)
);

CREATE INDEX goodput_inventory_revisions_history_idx
    ON goodput_inventory_revisions (cluster_id, source_id, inventory_class, effective_at DESC, observed_at DESC, source_at DESC, revision_id DESC);

CREATE TABLE goodput_allocation_snapshots (
    snapshot_key text PRIMARY KEY,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    source_id text NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version > 0),
    scheduler_namespace text NOT NULL,
    scheduler_job_id text NOT NULL,
    submit_at timestamptz NOT NULL,
    attempt integer NOT NULL CHECK (attempt >= 0),
    allocation_state text NOT NULL CHECK (allocation_state IN ('UNKNOWN', 'PENDING', 'RUNNING', 'SUSPENDED', 'COMPLETING', 'COMPLETED', 'CANCELLED', 'FAILED', 'UNSUPPORTED')),
    source_at timestamptz NOT NULL,
    effective_at timestamptz NOT NULL,
    observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (cluster_id, snapshot_key),
    FOREIGN KEY (cluster_id, source_id) REFERENCES sources(cluster_id, source_id)
);

CREATE TABLE goodput_allocation_snapshot_entities (
    cluster_id text NOT NULL,
    snapshot_key text NOT NULL,
    entity_kind text NOT NULL CHECK (entity_kind IN ('NODE', 'GPU', 'MIG')),
    stable_node_id text NOT NULL,
    physical_gpu_uuid text NOT NULL DEFAULT '',
    mig_identity text NOT NULL DEFAULT '',
    PRIMARY KEY (cluster_id, snapshot_key, entity_kind, stable_node_id, physical_gpu_uuid, mig_identity),
    FOREIGN KEY (cluster_id, snapshot_key) REFERENCES goodput_allocation_snapshots(cluster_id, snapshot_key),
    CHECK (
        (entity_kind = 'NODE' AND physical_gpu_uuid = '' AND mig_identity = '') OR
        (entity_kind = 'GPU' AND physical_gpu_uuid <> '' AND mig_identity = '') OR
        (entity_kind = 'MIG' AND physical_gpu_uuid <> '' AND mig_identity <> '')
    )
);

-- As with inventory validity, these are projections and may be rebuilt from
-- immutable snapshots if delayed scheduler data changes the valid intervals.
CREATE TABLE goodput_allocation_snapshot_validity (
    cluster_id text NOT NULL,
    snapshot_key text NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_to timestamptz,
    PRIMARY KEY (cluster_id, snapshot_key),
    FOREIGN KEY (cluster_id, snapshot_key) REFERENCES goodput_allocation_snapshots(cluster_id, snapshot_key),
    CHECK (valid_to IS NULL OR valid_to >= valid_from)
);

CREATE TABLE goodput_current_allocations (
    cluster_id text NOT NULL,
    source_id text NOT NULL,
    scheduler_namespace text NOT NULL,
    scheduler_job_id text NOT NULL,
    submit_at timestamptz NOT NULL,
    attempt integer NOT NULL,
    snapshot_key text NOT NULL,
    effective_at timestamptz NOT NULL,
    source_at timestamptz NOT NULL,
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (cluster_id, source_id, scheduler_namespace, scheduler_job_id, submit_at, attempt),
    FOREIGN KEY (cluster_id, snapshot_key) REFERENCES goodput_allocation_snapshots(cluster_id, snapshot_key)
);

CREATE INDEX goodput_allocation_snapshots_history_idx
    ON goodput_allocation_snapshots (cluster_id, source_id, scheduler_namespace, scheduler_job_id, submit_at, attempt, effective_at DESC, observed_at DESC, source_at DESC, snapshot_key DESC);

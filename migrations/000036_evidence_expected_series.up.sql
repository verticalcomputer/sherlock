ALTER TABLE collection_runs
    ADD COLUMN series_expected integer,
    ADD CONSTRAINT collection_runs_series_expected_check
        CHECK (series_expected IS NULL OR series_expected >= 0);

CREATE TABLE collection_target_inventory (
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    source_id text NOT NULL REFERENCES sources(source_id),
    target_kind text NOT NULL CHECK (target_kind IN ('NODE', 'GPU', 'SOURCE')),
    target_id text NOT NULL,
    node_id text NOT NULL DEFAULT '',
    last_observed_at timestamptz NOT NULL,
    PRIMARY KEY (cluster_id, source_id, target_kind, target_id)
);

CREATE INDEX collection_target_inventory_source_idx
    ON collection_target_inventory (cluster_id, source_id, target_kind, node_id);

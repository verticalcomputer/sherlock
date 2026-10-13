CREATE TABLE anomaly_xid_episode_state (
    consumer_id text NOT NULL,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    state_key text NOT NULL,
    last_value double precision NOT NULL,
    last_observed_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (consumer_id, cluster_id, state_key),
    FOREIGN KEY (consumer_id, cluster_id)
        REFERENCES anomaly_reconcile_cursors(consumer_id, cluster_id)
        ON DELETE CASCADE
);

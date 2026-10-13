CREATE TABLE event_streams (
    cluster_id text PRIMARY KEY REFERENCES clusters(cluster_id),
    next_event_id bigint NOT NULL CHECK (next_event_id > 0)
);

CREATE TABLE cluster_events (
    cluster_id text NOT NULL REFERENCES clusters(cluster_id),
    event_id bigint NOT NULL CHECK (event_id > 0),
    event_type text NOT NULL CHECK (event_type IN ('collection.updated', 'source.updated')),
    schema_version integer NOT NULL CHECK (schema_version > 0),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (cluster_id, event_id)
);

-- Preserve the M1 collection history. row_number creates an independent,
-- gap-free Last-Event-ID sequence for every cluster.
WITH historical AS (
    SELECT r.cluster_id,
           row_number() OVER (PARTITION BY r.cluster_id ORDER BY e.event_id) AS stream_event_id,
           r.run_id,
           r.source_id,
           r.status,
           r.completed_at,
           r.coverage_complete,
           e.created_at
    FROM collection_events e
    JOIN collection_runs r ON r.run_id = e.run_id
)
INSERT INTO cluster_events (cluster_id, event_id, event_type, schema_version, payload, created_at)
SELECT cluster_id, stream_event_id, 'collection.updated', 1,
       jsonb_build_object(
           'run_id', run_id,
           'source_id', source_id,
           'status', status,
           'completed_at', completed_at,
           'coverage_complete', coverage_complete
       ),
       created_at
FROM historical;

INSERT INTO event_streams (cluster_id, next_event_id)
SELECT c.cluster_id, COALESCE(MAX(e.event_id), 0) + 1
FROM clusters c
LEFT JOIN cluster_events e ON e.cluster_id = c.cluster_id
GROUP BY c.cluster_id;

CREATE INDEX cluster_events_created_idx ON cluster_events (cluster_id, created_at);

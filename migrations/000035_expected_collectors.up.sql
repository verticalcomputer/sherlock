ALTER TABLE clusters
    ADD COLUMN expected_collectors text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD CONSTRAINT clusters_expected_collectors_count_check
        CHECK (cardinality(expected_collectors) <= 100),
    ADD CONSTRAINT clusters_expected_collectors_nonempty_check
        CHECK (array_position(expected_collectors, '') IS NULL);

-- Establish an explicit starting inventory from the currently active names.
-- Operators can then review and edit this list from the private admin UI.
UPDATE clusters c
SET expected_collectors = inventory.names
FROM (
    SELECT cluster_id, array_agg(DISTINCT display_name ORDER BY display_name) AS names
    FROM collectors
    WHERE status = 'ACTIVE'
    GROUP BY cluster_id
) inventory
WHERE inventory.cluster_id = c.cluster_id;

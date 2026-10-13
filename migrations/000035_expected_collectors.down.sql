ALTER TABLE clusters
    DROP CONSTRAINT clusters_expected_collectors_nonempty_check,
    DROP CONSTRAINT clusters_expected_collectors_count_check,
    DROP COLUMN expected_collectors;

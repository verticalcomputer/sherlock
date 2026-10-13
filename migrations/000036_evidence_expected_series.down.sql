DROP TABLE collection_target_inventory;

ALTER TABLE collection_runs
    DROP CONSTRAINT collection_runs_series_expected_check,
    DROP COLUMN series_expected;

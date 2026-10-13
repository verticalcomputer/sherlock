ALTER TABLE collection_runs
    ADD COLUMN range_start timestamptz,
    ADD COLUMN range_end timestamptz,
    ADD COLUMN range_step_seconds double precision;

ALTER TABLE collection_runs
    ADD CONSTRAINT collection_runs_range_shape CHECK (
        (range_start IS NULL AND range_end IS NULL AND range_step_seconds IS NULL)
        OR
        (range_start IS NOT NULL AND range_end > range_start AND range_step_seconds >= 1 AND range_step_seconds <= 3600)
    );

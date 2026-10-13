ALTER TABLE collection_runs DROP CONSTRAINT IF EXISTS collection_runs_range_shape;
ALTER TABLE collection_runs
    DROP COLUMN IF EXISTS range_step_seconds,
    DROP COLUMN IF EXISTS range_end,
    DROP COLUMN IF EXISTS range_start;

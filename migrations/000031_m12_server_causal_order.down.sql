ALTER TABLE investigation_actions
    DROP CONSTRAINT IF EXISTS investigation_actions_completion_recorded_at_check,
    DROP COLUMN IF EXISTS completion_recorded_at;

ALTER TABLE diagnostic_work_attempts
    DROP CONSTRAINT IF EXISTS diagnostic_work_attempts_finalized_at_check,
    DROP COLUMN IF EXISTS finalized_at;

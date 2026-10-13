ALTER TABLE diagnostic_work_attempts
    ADD COLUMN finalized_at timestamptz;

-- Preserve the earliest PostgreSQL receipt time where the immutable audit row
-- exists. Rows without an older receipt are marked at migration time, which
-- keeps historical admission fail-closed when their evidence predates it.
UPDATE diagnostic_work_attempts attempt
SET finalized_at = COALESCE((
    SELECT min(audit.created_at)
    FROM diagnostic_audit_events audit
    WHERE audit.event_kind = 'ATTEMPT_RESULT'
      AND audit.work_id = attempt.work_id
      AND audit.attempt = attempt.attempt
), clock_timestamp())
WHERE attempt.status IN ('SUCCEEDED', 'PARTIAL', 'FAILED', 'EXPIRED');

ALTER TABLE diagnostic_work_attempts
    ADD CONSTRAINT diagnostic_work_attempts_finalized_at_check
    CHECK ((status IN ('SUCCEEDED', 'PARTIAL', 'FAILED', 'EXPIRED')) = (finalized_at IS NOT NULL));

ALTER TABLE investigation_actions
    ADD COLUMN completion_recorded_at timestamptz;

-- This is a server-owned backfill marker, not a reconstruction from a remote
-- or controller clock. New writes record the exact PostgreSQL persistence time.
UPDATE investigation_actions
SET completion_recorded_at = clock_timestamp()
WHERE status IN ('SUCCEEDED', 'FAILED', 'REJECTED', 'CANCELLED');

ALTER TABLE investigation_actions
    ADD CONSTRAINT investigation_actions_completion_recorded_at_check
    CHECK ((status IN ('SUCCEEDED', 'FAILED', 'REJECTED', 'CANCELLED')) = (completion_recorded_at IS NOT NULL));

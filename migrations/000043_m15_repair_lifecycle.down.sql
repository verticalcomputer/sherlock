DROP TRIGGER IF EXISTS m15_repair_request_work_lifecycle ON collector_work_items;
DROP FUNCTION IF EXISTS m15_repair_request_work_lifecycle();
DROP INDEX IF EXISTS collection_repair_requests_claim_idx;
ALTER TABLE remediation_runs DROP COLUMN IF EXISTS supervisor_generation;
ALTER TABLE collection_repair_requests DROP CONSTRAINT IF EXISTS collection_repair_requests_lease_pair;
ALTER TABLE collection_repair_requests DROP CONSTRAINT IF EXISTS collection_repair_requests_cancellation_attempt_unique;
ALTER TABLE collection_repair_requests DROP CONSTRAINT IF EXISTS collection_repair_requests_cancellation_attempt_fk;
ALTER TABLE collection_repair_requests DROP CONSTRAINT IF EXISTS collection_repair_requests_work_fk;
ALTER TABLE collection_repair_requests DROP COLUMN IF EXISTS claimed_attempt,
    DROP COLUMN IF EXISTS cancellation_outcome, DROP COLUMN IF EXISTS cancellation_attempt_id, DROP COLUMN IF EXISTS cancellation_requested_at,
    DROP COLUMN IF EXISTS lease_expires_at, DROP COLUMN IF EXISTS lease_owner, DROP COLUMN IF EXISTS work_id;

-- Restore the pre-M15 (000038) function when the M15 revision hardening is
-- explicitly rolled back. A subsequent up reinstalls the M15-owned revision.
CREATE OR REPLACE FUNCTION remediation_schedule_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.active,NEW.interval_seconds,NEW.next_run_at) IS DISTINCT FROM ROW(OLD.active,OLD.interval_seconds,OLD.next_run_at) THEN
 NEW.schedule_revision := OLD.schedule_revision+1;
 END IF;
 RETURN NEW;
END $$;

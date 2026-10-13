-- Operator cancellation is a durable fence even between attempt reservation
-- and effect creation. It cannot be cleared by a worker or supervisor restart.
ALTER TABLE remediation_runs ADD COLUMN cancellation_requested_at timestamptz;
ALTER TABLE collection_repair_requests ADD COLUMN worker_generation bigint NOT NULL DEFAULT 0;

-- Claim and START admission for repair work rechecks the standing authority.
-- Ordinary collection attempts have no repair row and take no extra locks.
CREATE FUNCTION m15_repair_attempt_authority() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE repair collection_repair_requests%ROWTYPE; allowed boolean;
BEGIN
 IF TG_OP='UPDATE' AND (OLD.status='STARTED' OR NEW.status<>'STARTED') THEN RETURN NEW; END IF;
 SELECT * INTO repair FROM collection_repair_requests WHERE work_id=NEW.work_id;
 IF NOT FOUND THEN RETURN NEW; END IF;
 PERFORM id FROM remediation_global_state WHERE id FOR SHARE;
 PERFORM cluster_id FROM remediation_policies WHERE cluster_id=repair.cluster_id FOR SHARE;
 PERFORM job_id FROM collection_jobs WHERE cluster_id=repair.cluster_id AND job_id=repair.job_id FOR SHARE;
 PERFORM run_id FROM remediation_runs WHERE cluster_id=repair.cluster_id AND run_id=repair.run_id FOR SHARE;
 SELECT COALESCE(gs.remediation_enabled AND p.enabled AND p.revoked_at IS NULL
  AND p.not_before<=clock_timestamp() AND p.not_after>clock_timestamp()
  AND p.recipe_id=r.recipe_id AND p.recipe_version=r.recipe_version
  AND r.cancellation_requested_at IS NULL AND r.state IN ('CANARY_EXECUTING','ROLLING_OUT','VERIFYING')
  AND j.active AND j.configuration_revision=repair.configuration_revision
  AND j.schedule_revision=repair.schedule_revision AND repair.deadline_at>clock_timestamp()
  AND repair.status IN ('REQUESTED','CLAIMED'),false)
 INTO allowed FROM remediation_global_state gs
 JOIN remediation_policies p ON p.cluster_id=repair.cluster_id
 JOIN remediation_runs r ON r.cluster_id=repair.cluster_id AND r.run_id=repair.run_id
 JOIN collection_jobs j ON j.cluster_id=repair.cluster_id AND j.job_id=repair.job_id;
 IF NOT COALESCE(allowed,false) THEN RAISE EXCEPTION 'repair collection authority revoked' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER m15_repair_attempt_authority BEFORE INSERT OR UPDATE OF status ON collector_work_attempts
FOR EACH ROW EXECUTE FUNCTION m15_repair_attempt_authority();

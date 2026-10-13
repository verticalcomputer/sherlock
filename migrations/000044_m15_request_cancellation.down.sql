DROP TRIGGER m15_repair_attempt_authority ON collector_work_attempts;
DROP FUNCTION m15_repair_attempt_authority();
ALTER TABLE collection_repair_requests DROP COLUMN worker_generation;
ALTER TABLE remediation_runs DROP COLUMN cancellation_requested_at;

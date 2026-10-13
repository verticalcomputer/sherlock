-- Exact reverse dependency order of 000037_m14_remediation.up.sql, ending with
-- the additive unique constraint that migration placed on collection_jobs.
DROP INDEX IF EXISTS remediation_audit_events_run_idx;
DROP TABLE IF EXISTS remediation_audit_events;
DROP TABLE IF EXISTS remediation_run_evidence;
DROP TABLE IF EXISTS remediation_condition_results;
DROP TABLE IF EXISTS remediation_receipt_targets;
DROP TABLE IF EXISTS remediation_receipts;
DROP TABLE IF EXISTS remediation_attempt_targets;
DROP TABLE IF EXISTS remediation_attempts;
DROP TABLE IF EXISTS remediation_run_arguments;
DROP TABLE IF EXISTS remediation_run_targets;
DROP INDEX IF EXISTS remediation_runs_reclaim_idx;
DROP INDEX IF EXISTS remediation_runs_active_repair_key;
DROP TABLE IF EXISTS remediation_runs;
DROP TABLE IF EXISTS remediation_recipe_refs;
DROP TABLE IF EXISTS remediation_policies;
DROP TABLE IF EXISTS remediation_global_state;

ALTER TABLE collection_jobs
    DROP CONSTRAINT IF EXISTS collection_jobs_cluster_job_key;

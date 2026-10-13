-- A running pool established while 000049 was present may outlive this schema
-- rollback. Remove its direct creation capabilities before removing the guard.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='sherlock_m15_remediator_v1') THEN
        REVOKE INSERT ON collection_run_jobs, collector_work_items,
            collection_repair_requests FROM sherlock_m15_remediator_v1;
    END IF;
END
$$;

DROP TRIGGER IF EXISTS sherlock_m15_guard_runtime_work ON collector_work_items;
DROP TRIGGER IF EXISTS sherlock_m15_mark_runtime_work ON collector_work_items;
DROP FUNCTION IF EXISTS public.sherlock_m15_guard_runtime_work();
DROP FUNCTION IF EXISTS public.sherlock_m15_mark_runtime_work();
ALTER TABLE collector_work_items DROP COLUMN remediation_runtime_managed;

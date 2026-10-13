BEGIN;
-- Revoke only M15's named capability and placeholder membership. This never
-- drops globally reusable roles, deployment-created LOGIN roles, mapping rows,
-- databases, or other objects.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM sherlock_m15_remediator_v1;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM sherlock_m15_remediator_v1;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM sherlock_m15_remediator_v1;
REVOKE UPDATE (lease_owner) ON collection_jobs FROM sherlock_m15_remediator_v1;
REVOKE UPDATE (status, completed_at) ON collector_work_items FROM sherlock_m15_remediator_v1;
REVOKE USAGE ON SCHEMA public FROM sherlock_m15_remediator_v1;
DO $$ BEGIN EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM sherlock_m15_remediator_v1', current_database()); END $$;
REVOKE sherlock_m15_remediator_v1 FROM sherlock_m15_remediator_login_v1;
COMMIT;

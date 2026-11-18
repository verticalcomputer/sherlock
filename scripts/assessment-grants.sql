-- Run only against an explicitly authorized database. This creates a NOLOGIN
-- group; an operator owns login/password provisioning and CONNECT grants.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='sherlock_assessment') THEN CREATE ROLE sherlock_assessment NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;END IF;
END $$;
GRANT USAGE ON SCHEMA public TO sherlock_assessment;
GRANT SELECT,INSERT,UPDATE,DELETE ON public.assessment_runs,public.assessment_enrollments,public.assessment_facts,public.assessment_bundles,public.assessment_candidates,public.assessment_decisions,public.assessment_failures TO sherlock_assessment;
GRANT SELECT ON public.assessment_edges TO sherlock_assessment;
GRANT EXECUTE ON FUNCTION public.assessment_sorted_set(text[],integer),public.assessment_guard(),public.assessment_references(),public.assessment_row_bytes(text,jsonb),public.assessment_account(),public.assessment_sample_source(bytea),public.assessment_account_fact_insert() TO sherlock_assessment;
GRANT SELECT ON public.desired_schedules,public.collection_jobs,public.collection_runs,public.collection_run_jobs,public.collector_work_items,public.durable_schedule_occurrences,public.durable_schedule_executions,public.collector_result_ingestions,public.goodput_inventory_revisions,public.goodput_inventory_revision_entities,public.observations TO sherlock_assessment;
GRANT SELECT(cluster_id,removed_at) ON public.clusters TO sherlock_assessment;
GRANT SELECT(cluster_id,source_id,kind) ON public.sources TO sherlock_assessment;
GRANT SELECT(policy_id,cluster_id,source_id,entity_key,rule_id,rule_version,operation,scope_key,enrollment_revision,policy,enabled) ON public.gp09_monitor_enrollments TO sherlock_assessment;
GRANT SELECT(cluster_id,policy_id,enrollment_revision,occurrence,severity,opened_at,closed_at) ON public.gp09_monitor_episodes TO sherlock_assessment;
GRANT SELECT(cluster_id,policy_id,occurrence,transition,occurred_at,reason,qualifying_sample_count,omitted_evidence_count,snapshot) ON public.gp09_monitor_transitions TO sherlock_assessment;
-- A restricted login must pass AssessmentStore.Preflight before enrollment.
-- PUBLIC and inherited privileges are effective. Roles reachable through SET
-- ROLE are checked even when the login does not inherit them. The allow-list
-- includes exact public routine signatures and excludes SECURITY DEFINER.
-- PostgreSQL grants EXECUTE on new functions to PUBLIC by default. In a
-- database with existing application routines, review which exposed routines
-- cause preflight to reject the login. The database owner must preserve or
-- grant execution to each authorized application role, then revoke PUBLIC
-- EXECUTE on the specific unapproved routines and review the creating roles'
-- default privileges. Removing a grant from the assessment role alone cannot
-- override PUBLIC. Temporary tables and their triggers confer database behavior
-- outside the assessment grant list. Preflight rejects effective TEMPORARY and
-- CREATE rights on this database for the login and reachable roles. Review and
-- preserve any needed TEMPORARY privileges for other application roles before
-- removing a PUBLIC grant. This script leaves existing PUBLIC grants intact.
-- Preflight also requires triggers to be active and rejects privileges that
-- can change their firing mode or alter the PostgreSQL server configuration.
SELECT rolname,rolcanlogin,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname='sherlock_assessment';

BEGIN;
-- M15 restricted remediator capability. Run this as the database deployment
-- owner after migrations through 000049, never as the remediator itself.
-- This artifact contains no connection material and creates no enabled login.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=49)
       OR to_regclass('public.remediation_runtime_identity_scopes') IS NULL
       OR to_regclass('public.remediation_runtime_identity_jobs') IS NULL
       OR to_regprocedure('public.sherlock_m15_lock_live_effect_facts(text)') IS NULL
       OR to_regprocedure('public.sherlock_m15_mark_runtime_work()') IS NULL
       OR to_regprocedure('public.sherlock_m15_guard_runtime_work()') IS NULL
       OR NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='public.collector_work_items'::regclass AND attname='remediation_runtime_managed' AND NOT attisdropped)
       OR NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='public.collector_work_items'::regclass AND tgname='sherlock_m15_mark_runtime_work' AND NOT tgisinternal)
       OR NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='public.collector_work_items'::regclass AND tgname='sherlock_m15_guard_runtime_work' AND NOT tgisinternal AND tgconstraint<>0 AND tgdeferrable AND tginitdeferred) THEN
        RAISE EXCEPTION 'refusing M15 runtime role: migration 000049 work guard is not installed';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_namespace n
        CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a
        WHERE n.nspname = 'public' AND a.grantee = 0 AND a.privilege_type = 'CREATE'
    ) THEN
        RAISE EXCEPTION 'refusing M15 runtime role: PUBLIC retains CREATE on schema public';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
        WHERE p.prosecdef AND a.grantee = 0 AND a.privilege_type = 'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'refusing M15 runtime role: PUBLIC can execute a SECURITY DEFINER function';
    END IF;
	IF EXISTS (
		SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
		CROSS JOIN LATERAL aclexplode(c.relacl) a
		WHERE n.nspname='public' AND a.grantee=0 AND c.relkind IN ('r','p','v','m','S')
		UNION ALL
		SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
		CROSS JOIN LATERAL aclexplode(a.attacl) x
		WHERE n.nspname='public' AND x.grantee=0 AND a.attnum>0 AND NOT a.attisdropped
	) THEN
		RAISE EXCEPTION 'refusing M15 runtime role: PUBLIC retains application relation privileges';
	END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sherlock_m15_remediator_v1') THEN
        CREATE ROLE sherlock_m15_remediator_v1 NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sherlock_m15_remediator_login_v1') THEN
        -- Placeholder only. External deployment automation creates a distinct
        -- LOGIN NOINHERIT role with no checked-in password or secret.
        CREATE ROLE sherlock_m15_remediator_login_v1 NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
	IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('sherlock_m15_remediator_v1','sherlock_m15_remediator_login_v1') AND (rolsuper OR rolcanlogin OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls OR rolinherit)) THEN
		RAISE EXCEPTION 'refusing M15 runtime role: capability attributes are unsafe';
	END IF;
END
$$;

GRANT sherlock_m15_remediator_v1 TO sherlock_m15_remediator_login_v1;
REVOKE ALL ON SCHEMA public FROM sherlock_m15_remediator_v1;
GRANT USAGE ON SCHEMA public TO sherlock_m15_remediator_v1;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sherlock_m15_remediator_v1;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM sherlock_m15_remediator_v1;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM sherlock_m15_remediator_v1;
-- Table-wide revocation does not clear separately stored column ACLs. Remove
-- every direct capability column grant before restoring the two reviewed
-- update columns below, so reapplying this artifact converges stale databases.
DO $$
DECLARE grant_column record;
BEGIN
    FOR grant_column IN
        SELECT c.relname, a.attname
        FROM pg_attribute a
        JOIN pg_class c ON c.oid=a.attrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace
        CROSS JOIN LATERAL aclexplode(a.attacl) x
        WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped
          AND x.grantee=(SELECT oid FROM pg_roles WHERE rolname='sherlock_m15_remediator_v1')
    LOOP
        EXECUTE format(
            'REVOKE SELECT (%1$I), INSERT (%1$I), UPDATE (%1$I), REFERENCES (%1$I) ON TABLE public.%2$I FROM sherlock_m15_remediator_v1',
            grant_column.attname, grant_column.relname);
    END LOOP;
END
$$;
DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO sherlock_m15_remediator_v1', current_database()); END $$;

-- Read facts needed to detect, reconstruct, fence, dispatch, reconcile, and
-- verify the one bounded M15 repair.  RLS from migration 000048 further binds
-- these relations to the login's immutable cluster/job mapping.
GRANT SELECT ON TABLE
    collection_jobs, collection_runs, collection_run_jobs,
    collector_work_items, collector_work_attempts, collector_source_health,
    collectors, collector_capabilities, collection_target_inventory,
    observations, collector_result_ingestions, evidence_envelopes,
    schedule_repair_detections, schedule_repair_decisions,
    incidents, incident_events, incident_evidence, anomaly_incidents,
    investigations, investigation_events, investigation_budgets,
    investigation_steps, investigation_actions, investigation_approvals,
    investigation_evidence, investigation_hypotheses,
    investigation_hypothesis_evidence, investigation_findings,
    investigation_finding_citations, investigation_idempotency_records,
    investigation_action_cards, investigation_action_card_citations,
    investigation_report_sections, investigation_report_section_citations,
    investigation_report_omissions, remediation_global_state,
    remediation_policies, remediation_recipe_refs, remediation_runs,
    remediation_run_targets, remediation_run_arguments,
    remediation_run_evidence, remediation_attempts,
    remediation_attempt_targets, remediation_receipts,
    remediation_receipt_targets, remediation_condition_results,
    remediation_audit_events, remediation_schedule_snapshots,
    remediation_verification_evidence, collection_repair_requests
TO sherlock_m15_remediator_v1;

-- Detector and deterministic controller writes. No API, credential, source,
-- collector identity, policy, global-state, or schema mutation is granted.
GRANT INSERT ON TABLE
    evidence_envelopes, schedule_repair_detections, schedule_repair_decisions,
    incidents, incident_events, incident_evidence, anomaly_incidents,
    investigations, investigation_events, investigation_budgets,
    investigation_steps, investigation_actions, investigation_approvals,
    investigation_evidence, investigation_hypotheses,
    investigation_hypothesis_evidence, investigation_findings,
    investigation_finding_citations, investigation_idempotency_records,
    investigation_action_cards, investigation_action_card_citations,
    investigation_report_sections, investigation_report_section_citations,
    investigation_report_omissions, remediation_recipe_refs,
    remediation_runs, remediation_run_targets, remediation_run_arguments,
    remediation_run_evidence, remediation_attempts,
    remediation_attempt_targets, remediation_receipts,
    remediation_receipt_targets, remediation_condition_results,
    remediation_audit_events, remediation_schedule_snapshots,
    remediation_verification_evidence, collection_run_jobs,
    collector_work_items, collection_repair_requests
TO sherlock_m15_remediator_v1;

GRANT UPDATE ON TABLE
    schedule_repair_detections, schedule_repair_decisions,
    incidents, incident_events, incident_evidence, anomaly_incidents,
    investigations, investigation_events, investigation_budgets,
    investigation_steps, investigation_actions, investigation_approvals,
    investigation_evidence, investigation_hypotheses,
    investigation_hypothesis_evidence, investigation_findings,
    investigation_finding_citations, investigation_idempotency_records,
    investigation_action_cards, investigation_action_card_citations,
    investigation_report_sections, investigation_report_section_citations,
    investigation_report_omissions, remediation_runs,
    remediation_run_targets, remediation_run_arguments,
    remediation_run_evidence, remediation_attempts,
    remediation_attempt_targets, remediation_receipts,
    remediation_receipt_targets, remediation_condition_results,
    remediation_audit_events, remediation_schedule_snapshots,
    remediation_verification_evidence, collection_repair_requests
TO sherlock_m15_remediator_v1;

-- Controller synthesis replaces only its own citation sets before rebuilding
-- them from its durable schedule evidence. No other remediation relation is
-- deletable by the runtime identity.
GRANT DELETE ON TABLE investigation_hypothesis_evidence,
    investigation_finding_citations, investigation_report_section_citations,
    investigation_action_card_citations
TO sherlock_m15_remediator_v1;

-- FOR UPDATE on the exact target row needs UPDATE privilege, but this role is
-- deliberately not allowed to alter the schedule/configuration fields.
GRANT UPDATE (lease_owner) ON collection_jobs TO sherlock_m15_remediator_v1;
GRANT UPDATE (status, completed_at) ON collector_work_items TO sherlock_m15_remediator_v1;

GRANT EXECUTE ON FUNCTION public.sherlock_m15_runtime_scope_allows(text, text),
    public.sherlock_m15_lock_live_effect_facts(text)
TO sherlock_m15_remediator_v1;
COMMIT;

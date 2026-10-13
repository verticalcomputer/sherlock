-- Removing row policies before role privileges would reopen the relations to a
-- still-granted runtime identity. Revoke first; the deployment artifact can
-- only re-grant after this migration is restored.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='sherlock_m15_remediator_v1') THEN
        REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM sherlock_m15_remediator_v1;
        REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM sherlock_m15_remediator_v1;
        REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM sherlock_m15_remediator_v1;
        REVOKE UPDATE (lease_owner) ON collection_jobs FROM sherlock_m15_remediator_v1;
        REVOKE UPDATE (status, completed_at) ON collector_work_items FROM sherlock_m15_remediator_v1;
        REVOKE USAGE ON SCHEMA public FROM sherlock_m15_remediator_v1;
        EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM sherlock_m15_remediator_v1', current_database());
    END IF;
END
$$;

DROP POLICY IF EXISTS sherlock_m15_runtime_mapped_session ON remediation_recipe_refs;
DROP POLICY IF EXISTS sherlock_m15_runtime_mapped_session ON remediation_global_state;
DROP POLICY IF EXISTS sherlock_m15_existing_access ON remediation_recipe_refs;
DROP POLICY IF EXISTS sherlock_m15_existing_access ON remediation_global_state;

DROP POLICY IF EXISTS sherlock_m15_runtime_detector_evidence_write ON evidence_envelopes;
DROP POLICY IF EXISTS sherlock_m15_runtime_repair_work_insert ON collector_work_items;
DROP POLICY IF EXISTS sherlock_m15_runtime_repair_work_cancel ON collector_work_items;
DROP POLICY IF EXISTS sherlock_m15_runtime_detector_incident ON incidents;
DROP POLICY IF EXISTS sherlock_m15_runtime_detector_incident_event ON incident_events;
DROP POLICY IF EXISTS sherlock_m15_runtime_detector_anomaly ON anomaly_incidents;
DROP POLICY IF EXISTS sherlock_m15_runtime_job_scope ON collection_run_jobs;
DROP POLICY IF EXISTS sherlock_m15_runtime_job_scope ON collection_repair_requests;
DROP POLICY IF EXISTS sherlock_m15_runtime_job_scope ON remediation_schedule_snapshots;
ALTER TABLE remediation_recipe_refs DISABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_global_state DISABLE ROW LEVEL SECURITY;

DO $$
DECLARE relation text;
BEGIN
	FOREACH relation IN ARRAY ARRAY[
		'investigations', 'investigation_events', 'investigation_budgets',
		'investigation_steps', 'investigation_actions', 'investigation_approvals',
		'investigation_evidence', 'investigation_hypotheses',
		'investigation_hypothesis_evidence', 'investigation_findings',
		'investigation_finding_citations', 'investigation_action_cards',
		'investigation_action_card_citations', 'investigation_report_sections',
		'investigation_report_section_citations', 'investigation_report_omissions',
		'remediation_runs'
	] LOOP
		EXECUTE format('DROP POLICY IF EXISTS sherlock_m15_runtime_detector_investigation ON public.%I', relation);
	END LOOP;
    FOREACH relation IN ARRAY ARRAY['collector_capabilities', 'collector_source_health', 'collector_work_attempts', 'collector_result_ingestions', 'incident_evidence']
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS sherlock_m15_runtime_parent_scope ON public.%I', relation);
		EXECUTE format('DROP POLICY IF EXISTS sherlock_m15_existing_access ON public.%I', relation);
        EXECUTE format('ALTER TABLE public.%I DISABLE ROW LEVEL SECURITY', relation);
    END LOOP;
    FOREACH relation IN ARRAY ARRAY[
        'collection_jobs', 'collection_runs', 'collection_run_jobs',
        'collector_work_items', 'collectors',
        'collection_target_inventory', 'observations', 'evidence_envelopes',
        'schedule_repair_detections', 'schedule_repair_decisions',
        'incidents', 'incident_events', 'anomaly_incidents',
        'investigations', 'investigation_events', 'investigation_budgets',
        'investigation_steps', 'investigation_actions', 'investigation_approvals',
        'investigation_evidence', 'investigation_hypotheses',
        'investigation_hypothesis_evidence', 'investigation_findings',
        'investigation_finding_citations', 'investigation_idempotency_records',
        'investigation_action_cards', 'investigation_action_card_citations',
        'investigation_report_sections', 'investigation_report_section_citations',
        'investigation_report_omissions', 'remediation_policies',
        'remediation_runs', 'remediation_run_targets',
        'remediation_run_arguments', 'remediation_run_evidence',
        'remediation_attempts', 'remediation_attempt_targets',
        'remediation_receipts', 'remediation_receipt_targets',
        'remediation_condition_results', 'remediation_audit_events',
        'remediation_schedule_snapshots', 'remediation_verification_evidence',
        'collection_repair_requests'
    ]
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS sherlock_m15_runtime_job_scope ON public.%I', relation);
        EXECUTE format('DROP POLICY IF EXISTS sherlock_m15_runtime_cluster_scope ON public.%I', relation);
		EXECUTE format('DROP POLICY IF EXISTS sherlock_m15_existing_access ON public.%I', relation);
        EXECUTE format('ALTER TABLE public.%I DISABLE ROW LEVEL SECURITY', relation);
    END LOOP;
END
$$;

DROP FUNCTION IF EXISTS public.sherlock_m15_lock_live_effect_facts(text);
DROP FUNCTION IF EXISTS public.sherlock_m15_runtime_scope_allows(text, text);
DROP TABLE IF EXISTS remediation_runtime_identity_jobs;
DROP TABLE IF EXISTS remediation_runtime_identity_scopes;

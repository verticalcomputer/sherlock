-- The role must exist before role-targeted RLS policies are created. The
-- deployment artifact grants it capabilities per database; migration rollback
-- intentionally never drops this cluster-global role.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='sherlock_m15_remediator_v1') THEN
        CREATE ROLE sherlock_m15_remediator_v1 NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
END
$$;

-- M15's remediator receives a separate, non-login capability role from the
-- deployment artifact.  These two relations are deliberately owned by the
-- migration owner: the capability role gets no privilege to read or change its
-- own cluster/job scope.
CREATE TABLE remediation_runtime_identity_scopes (
    login_role name PRIMARY KEY,
    cluster_id text NOT NULL REFERENCES clusters(cluster_id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

ALTER TABLE remediation_runtime_identity_scopes
    ADD CONSTRAINT remediation_runtime_identity_scopes_login_cluster_key UNIQUE (login_role, cluster_id);

CREATE TABLE remediation_runtime_identity_jobs (
    login_role name NOT NULL REFERENCES remediation_runtime_identity_scopes(login_role) ON DELETE CASCADE,
    cluster_id text NOT NULL,
    job_id text NOT NULL,
    PRIMARY KEY (login_role, job_id),
    FOREIGN KEY (cluster_id, job_id) REFERENCES collection_jobs(cluster_id, job_id) ON DELETE RESTRICT,
    FOREIGN KEY (login_role, cluster_id) REFERENCES remediation_runtime_identity_scopes(login_role, cluster_id) ON DELETE CASCADE
);

-- Scope is keyed by session_user, not current_user.  A runtime connection must
-- SET ROLE into the capability role, but cannot widen its scope with a GUC or
-- by choosing a different current role.  The fixed search path and qualified
-- relations are required for a SECURITY DEFINER predicate used by RLS.
CREATE FUNCTION public.sherlock_m15_runtime_scope_allows(p_cluster text, p_job text DEFAULT NULL)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.remediation_runtime_identity_scopes s
        WHERE s.login_role = session_user
          AND (p_cluster IS NULL OR s.cluster_id = p_cluster)
          AND (
              p_job IS NULL OR EXISTS (
                  SELECT 1
                  FROM public.remediation_runtime_identity_jobs j
                  WHERE j.login_role = s.login_role
                    AND j.cluster_id = s.cluster_id
                    AND j.job_id = p_job
              )
          )
    )
$$;

-- This is the sole stronger-privilege boundary needed by the LIVE effect
-- transaction.  The capability role retains SELECT-only policy/global state;
-- it never receives UPDATE merely to issue a table lock.  The lock order is
-- byte-for-byte the pre-existing LIVE order, and locks are transaction scoped.
CREATE FUNCTION public.sherlock_m15_lock_live_effect_facts(p_cluster text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF p_cluster IS NULL OR NOT (session_user = current_user OR public.sherlock_m15_runtime_scope_allows(p_cluster, NULL)) THEN
        RAISE EXCEPTION 'M15 runtime scope is unavailable' USING ERRCODE = '42501';
    END IF;
    -- A direct function caller cannot convert this authority boundary into an
    -- unbounded lock acquisition.
    PERFORM set_config('lock_timeout', '1500ms', true);
    PERFORM pg_advisory_xact_lock(hashtextextended('m15-repair:' || p_cluster, 0));
    LOCK TABLE public.remediation_global_state, public.remediation_policies,
        public.remediation_runs, public.remediation_run_targets,
        public.remediation_run_arguments, public.remediation_run_evidence,
        public.incidents, public.anomaly_incidents,
        public.investigation_evidence IN SHARE ROW EXCLUSIVE MODE;
    LOCK TABLE public.collectors, public.collector_capabilities,
        public.collector_source_health, public.collection_target_inventory,
        public.schedule_repair_detections, public.investigation_action_cards,
        public.investigation_action_card_citations IN SHARE MODE;
END
$$;

REVOKE ALL ON FUNCTION public.sherlock_m15_runtime_scope_allows(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sherlock_m15_lock_live_effect_facts(text) FROM PUBLIC;

-- Every relation exposed to the M15 runtime carries a cluster policy.  The
-- capability role can only see or write the cluster bound to session_user.
-- Job-bearing detector/scheduler rows also require the immutable job mapping.
DO $$
DECLARE relation text;
BEGIN
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
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', relation);
        EXECUTE format('DROP POLICY IF EXISTS sherlock_m15_runtime_cluster_scope ON public.%I', relation);
		EXECUTE format('DROP POLICY IF EXISTS sherlock_m15_existing_access ON public.%I', relation);
		EXECUTE format('CREATE POLICY sherlock_m15_existing_access ON public.%I FOR ALL TO PUBLIC USING (true) WITH CHECK (true)', relation);
        EXECUTE format(
            'CREATE POLICY sherlock_m15_runtime_cluster_scope ON public.%I AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1 USING (public.sherlock_m15_runtime_scope_allows(cluster_id, NULL)) WITH CHECK (public.sherlock_m15_runtime_scope_allows(cluster_id, NULL))',
            relation);
    END LOOP;
END
$$;

-- These relations obtain cluster scope through a parent key rather than a
-- copied cluster_id.  Keep their policy explicit so a future schema change
-- cannot silently turn an unscoped relation into a runtime grant.
DO $$
BEGIN
    ALTER TABLE public.collector_capabilities ENABLE ROW LEVEL SECURITY;
	CREATE POLICY sherlock_m15_existing_access ON public.collector_capabilities FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
    DROP POLICY IF EXISTS sherlock_m15_runtime_parent_scope ON public.collector_capabilities;
    CREATE POLICY sherlock_m15_runtime_parent_scope ON public.collector_capabilities AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1
        USING (EXISTS (SELECT 1 FROM public.collectors c WHERE c.collector_id=collector_capabilities.collector_id AND public.sherlock_m15_runtime_scope_allows(c.cluster_id, NULL)))
        WITH CHECK (EXISTS (SELECT 1 FROM public.collectors c WHERE c.collector_id=collector_capabilities.collector_id AND public.sherlock_m15_runtime_scope_allows(c.cluster_id, NULL)));
    ALTER TABLE public.collector_source_health ENABLE ROW LEVEL SECURITY;
	CREATE POLICY sherlock_m15_existing_access ON public.collector_source_health FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
    DROP POLICY IF EXISTS sherlock_m15_runtime_parent_scope ON public.collector_source_health;
    CREATE POLICY sherlock_m15_runtime_parent_scope ON public.collector_source_health AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1
        USING (EXISTS (SELECT 1 FROM public.collectors c WHERE c.collector_id=collector_source_health.collector_id AND public.sherlock_m15_runtime_scope_allows(c.cluster_id, NULL)))
        WITH CHECK (EXISTS (SELECT 1 FROM public.collectors c WHERE c.collector_id=collector_source_health.collector_id AND public.sherlock_m15_runtime_scope_allows(c.cluster_id, NULL)));
    ALTER TABLE public.collector_work_attempts ENABLE ROW LEVEL SECURITY;
	CREATE POLICY sherlock_m15_existing_access ON public.collector_work_attempts FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
    DROP POLICY IF EXISTS sherlock_m15_runtime_parent_scope ON public.collector_work_attempts;
    CREATE POLICY sherlock_m15_runtime_parent_scope ON public.collector_work_attempts AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1
        USING (EXISTS (SELECT 1 FROM public.collector_work_items w WHERE w.work_id=collector_work_attempts.work_id AND public.sherlock_m15_runtime_scope_allows(w.cluster_id, NULL)))
        WITH CHECK (EXISTS (SELECT 1 FROM public.collector_work_items w WHERE w.work_id=collector_work_attempts.work_id AND public.sherlock_m15_runtime_scope_allows(w.cluster_id, NULL)));
    ALTER TABLE public.collector_result_ingestions ENABLE ROW LEVEL SECURITY;
	CREATE POLICY sherlock_m15_existing_access ON public.collector_result_ingestions FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
    DROP POLICY IF EXISTS sherlock_m15_runtime_parent_scope ON public.collector_result_ingestions;
    CREATE POLICY sherlock_m15_runtime_parent_scope ON public.collector_result_ingestions AS RESTRICTIVE FOR SELECT TO sherlock_m15_remediator_v1
        USING (EXISTS (SELECT 1 FROM public.collector_work_items w WHERE w.work_id=collector_result_ingestions.work_id AND public.sherlock_m15_runtime_scope_allows(w.cluster_id, NULL)));
    ALTER TABLE public.incident_evidence ENABLE ROW LEVEL SECURITY;
	CREATE POLICY sherlock_m15_existing_access ON public.incident_evidence FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
    DROP POLICY IF EXISTS sherlock_m15_runtime_parent_scope ON public.incident_evidence;
    CREATE POLICY sherlock_m15_runtime_parent_scope ON public.incident_evidence AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1
        USING (EXISTS (SELECT 1 FROM public.incidents i WHERE i.incident_id=incident_evidence.incident_id AND public.sherlock_m15_runtime_scope_allows(i.cluster_id, NULL)))
        WITH CHECK (EXISTS (SELECT 1 FROM public.incidents i WHERE i.incident_id=incident_evidence.incident_id AND public.sherlock_m15_runtime_scope_allows(i.cluster_id, NULL)));
END
$$;

DROP POLICY IF EXISTS sherlock_m15_runtime_job_scope ON public.collection_jobs;
CREATE POLICY sherlock_m15_runtime_job_scope ON public.collection_jobs
    AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1
    USING (public.sherlock_m15_runtime_scope_allows(cluster_id, job_id))
    WITH CHECK (public.sherlock_m15_runtime_scope_allows(cluster_id, job_id));

DROP POLICY IF EXISTS sherlock_m15_runtime_job_scope ON public.schedule_repair_detections;
CREATE POLICY sherlock_m15_runtime_job_scope ON public.schedule_repair_detections
    AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1
    USING (public.sherlock_m15_runtime_scope_allows(cluster_id, job_id))
    WITH CHECK (public.sherlock_m15_runtime_scope_allows(cluster_id, job_id));

DROP POLICY IF EXISTS sherlock_m15_runtime_job_scope ON public.schedule_repair_decisions;
CREATE POLICY sherlock_m15_runtime_job_scope ON public.schedule_repair_decisions
    AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1
    USING (public.sherlock_m15_runtime_scope_allows(cluster_id, job_id))
    WITH CHECK (public.sherlock_m15_runtime_scope_allows(cluster_id, job_id));

-- The actual repair may only create/read rows for its mapped collection job.
DO $$
BEGIN
    CREATE POLICY sherlock_m15_runtime_job_scope ON public.collection_run_jobs
        AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1
        USING (public.sherlock_m15_runtime_scope_allows(cluster_id, job_id))
        WITH CHECK (public.sherlock_m15_runtime_scope_allows(cluster_id, job_id));
    CREATE POLICY sherlock_m15_runtime_job_scope ON public.collection_repair_requests
        AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1
        USING (public.sherlock_m15_runtime_scope_allows(cluster_id, job_id))
        WITH CHECK (public.sherlock_m15_runtime_scope_allows(cluster_id, job_id));
    CREATE POLICY sherlock_m15_runtime_job_scope ON public.remediation_schedule_snapshots
        AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1
        USING (public.sherlock_m15_runtime_scope_allows(cluster_id, target))
        WITH CHECK (public.sherlock_m15_runtime_scope_allows(cluster_id, target));
END
$$;

-- Detector-owned incidents and investigations are distinguishable from the
-- rest of the application's same-cluster history. These restrictive policies
-- prevent the remediator from reading or changing an unrelated investigation.
CREATE POLICY sherlock_m15_runtime_detector_incident ON public.incidents
    AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1
    USING (created_by='sherlock-remediator') WITH CHECK (created_by='sherlock-remediator');
CREATE POLICY sherlock_m15_runtime_detector_incident_event ON public.incident_events
    AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1
    USING (actor_id='sherlock-remediator') WITH CHECK (actor_id='sherlock-remediator');
CREATE POLICY sherlock_m15_runtime_detector_anomaly ON public.anomaly_incidents
    AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1
    USING (rule_id='EVIDENCE_STREAM_STALE' AND public.sherlock_m15_runtime_scope_allows(cluster_id, entity_key))
    WITH CHECK (rule_id='EVIDENCE_STREAM_STALE' AND public.sherlock_m15_runtime_scope_allows(cluster_id, entity_key));

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
        EXECUTE format('CREATE POLICY sherlock_m15_runtime_detector_investigation ON public.%I AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1 USING (EXISTS (SELECT 1 FROM public.schedule_repair_detections d WHERE d.cluster_id=%I.cluster_id AND d.investigation_id=%I.investigation_id AND public.sherlock_m15_runtime_scope_allows(d.cluster_id,d.job_id))) WITH CHECK (EXISTS (SELECT 1 FROM public.schedule_repair_detections d WHERE d.cluster_id=%I.cluster_id AND d.investigation_id=%I.investigation_id AND public.sherlock_m15_runtime_scope_allows(d.cluster_id,d.job_id)))', relation, relation, relation, relation, relation);
    END LOOP;
END
$$;

CREATE POLICY sherlock_m15_runtime_detector_evidence_write ON public.evidence_envelopes
    AS RESTRICTIVE FOR INSERT TO sherlock_m15_remediator_v1
    WITH CHECK (operation='schedule_dispatch_gap');

-- The remediator can bind one pre-authorized repair work item, and can only
-- cancel it later. Collector attempts and success finalization stay solely in
-- the collector identity's transaction.
CREATE POLICY sherlock_m15_runtime_repair_work_insert ON public.collector_work_items
    AS RESTRICTIVE FOR INSERT TO sherlock_m15_remediator_v1
    WITH CHECK (status='AVAILABLE' AND EXISTS (
        SELECT 1 FROM public.collection_run_jobs b
        WHERE b.cluster_id=collector_work_items.cluster_id
          AND b.run_id=collector_work_items.run_id
          AND b.source_id=collector_work_items.source_id
          AND b.query_kind=collector_work_items.query_kind
          AND b.node_filter=collector_work_items.node_filter
          AND public.sherlock_m15_runtime_scope_allows(b.cluster_id,b.job_id)
    ));
CREATE POLICY sherlock_m15_runtime_repair_work_cancel ON public.collector_work_items
    AS RESTRICTIVE FOR UPDATE TO sherlock_m15_remediator_v1
    USING (status IN ('AVAILABLE','LEASED') AND EXISTS (
        SELECT 1 FROM public.collection_repair_requests r
        WHERE r.work_id=collector_work_items.work_id
          AND r.cluster_id=collector_work_items.cluster_id
          AND public.sherlock_m15_runtime_scope_allows(r.cluster_id,r.job_id)
    ))
    WITH CHECK (status='CANCELLED' AND completed_at IS NOT NULL AND EXISTS (
        SELECT 1 FROM public.collection_repair_requests r
        WHERE r.work_id=collector_work_items.work_id
          AND r.cluster_id=collector_work_items.cluster_id
          AND public.sherlock_m15_runtime_scope_allows(r.cluster_id,r.job_id)
    ));

-- Global recipe and enablement state has no cluster column.  It is visible
-- only to an already mapped runtime session and remains read-only by grants.
ALTER TABLE remediation_global_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_recipe_refs ENABLE ROW LEVEL SECURITY;
CREATE POLICY sherlock_m15_existing_access ON remediation_global_state FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY sherlock_m15_existing_access ON remediation_recipe_refs FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS sherlock_m15_runtime_mapped_session ON remediation_global_state;
CREATE POLICY sherlock_m15_runtime_mapped_session ON remediation_global_state
    AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1
    USING (public.sherlock_m15_runtime_scope_allows(NULL, NULL))
    WITH CHECK (public.sherlock_m15_runtime_scope_allows(NULL, NULL));
DROP POLICY IF EXISTS sherlock_m15_runtime_mapped_session ON remediation_recipe_refs;
CREATE POLICY sherlock_m15_runtime_mapped_session ON remediation_recipe_refs
    AS RESTRICTIVE FOR ALL TO sherlock_m15_remediator_v1
    USING (public.sherlock_m15_runtime_scope_allows(NULL, NULL))
    WITH CHECK (public.sherlock_m15_runtime_scope_allows(NULL, NULL));

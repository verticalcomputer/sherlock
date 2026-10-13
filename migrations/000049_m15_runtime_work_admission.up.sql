-- Mark collector work created through the restricted M15 capability and defer
-- its admission check until transaction commit. RequestCollection deliberately
-- inserts the run binding and work before its repair request, so an immediate
-- trigger could not verify the complete atomic effect.
ALTER TABLE collector_work_items
    ADD COLUMN remediation_runtime_managed boolean NOT NULL DEFAULT false;

CREATE FUNCTION public.sherlock_m15_mark_runtime_work()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    -- The caller cannot clear this marker by supplying a column value. Ordinary
    -- scheduler/collector identities retain the default false value.
    NEW.remediation_runtime_managed := current_user = 'sherlock_m15_remediator_v1';
    RETURN NEW;
END
$$;

CREATE TRIGGER sherlock_m15_mark_runtime_work
BEFORE INSERT ON public.collector_work_items
FOR EACH ROW EXECUTE FUNCTION public.sherlock_m15_mark_runtime_work();

CREATE FUNCTION public.sherlock_m15_guard_runtime_work()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    allowed boolean;
BEGIN
    IF NOT NEW.remediation_runtime_managed THEN
        RETURN NEW;
    END IF;

    -- A caller that did not enter through the ordinary LIVE effect path must
    -- never wait behind a row lock it may already hold. The real effect already
    -- owns this transaction lock, so reacquisition is immediate and reentrant.
    IF NOT pg_try_advisory_xact_lock(hashtextextended('m15-repair:' || NEW.cluster_id, 0)) THEN
        RAISE EXCEPTION 'M15 runtime work authority is busy' USING ERRCODE = '40001';
    END IF;
    PERFORM public.sherlock_m15_lock_live_effect_facts(NEW.cluster_id);
    -- collection_jobs is intentionally absent from the broad fact-table lock
    -- so unrelated scheduler progress can continue. Freeze only this request's
    -- target; the 1.5 second lock timeout set above bounds an older row holder.
    PERFORM j.job_id
      FROM public.collection_repair_requests r
      JOIN public.collection_jobs j
        ON j.cluster_id=r.cluster_id AND j.job_id=r.job_id
     WHERE r.work_id=NEW.work_id AND r.cluster_id=NEW.cluster_id
     FOR SHARE OF j;

    SELECT EXISTS (
        SELECT 1
        FROM public.collection_repair_requests r
        JOIN public.collection_run_jobs b
          ON b.run_id=NEW.run_id AND b.cluster_id=NEW.cluster_id
         AND b.job_id=r.job_id AND b.source_id=NEW.source_id
         AND b.query_kind=NEW.query_kind AND b.node_filter=NEW.node_filter
         AND b.scheduled_for=NEW.scheduled_for
         AND b.configuration_revision=r.configuration_revision
         AND b.lease_generation=1
        JOIN public.collection_jobs j
          ON j.cluster_id=r.cluster_id AND j.job_id=r.job_id
         AND j.source_id=NEW.source_id AND j.query_kind=NEW.query_kind
         AND j.node_filter=NEW.node_filter
         AND j.configuration_revision=r.configuration_revision
         AND j.schedule_revision=r.schedule_revision
        JOIN public.remediation_runs rr
          ON rr.cluster_id=r.cluster_id AND rr.run_id=r.run_id
        JOIN public.remediation_attempts a
          ON a.cluster_id=r.cluster_id AND a.run_id=r.run_id
         AND a.attempt_id=r.attempt_id
        JOIN public.remediation_run_targets rt
          ON rt.cluster_id=r.cluster_id AND rt.run_id=r.run_id
         AND rt.target=r.job_id
        JOIN public.remediation_attempt_targets at
          ON at.cluster_id=r.cluster_id AND at.run_id=r.run_id
         AND at.attempt_id=r.attempt_id AND at.target=r.job_id
        JOIN public.remediation_schedule_snapshots s
          ON s.cluster_id=r.cluster_id AND s.run_id=r.run_id
         AND s.target=r.job_id
        JOIN public.remediation_policies p
          ON p.cluster_id=r.cluster_id AND p.policy_id=a.policy_id
         AND p.version=a.policy_version AND p.recipe_id=rr.recipe_id
         AND p.recipe_version=rr.recipe_version
        JOIN public.schedule_repair_detections d
          ON d.cluster_id=rr.cluster_id AND d.incident_id=rr.incident_id
         AND d.investigation_id=rr.investigation_id
         AND d.job_id=r.job_id AND d.source_id=NEW.source_id
         AND d.configuration_revision=r.configuration_revision
         AND d.schedule_revision=r.schedule_revision
        JOIN public.remediation_run_evidence re
          ON re.cluster_id=rr.cluster_id AND re.run_id=rr.run_id
        JOIN public.investigation_evidence ie
          ON ie.cluster_id=rr.cluster_id AND ie.investigation_id=rr.investigation_id
         AND ie.ledger_entry_id=re.ledger_entry_id AND ie.evidence_id=d.evidence_id
        CROSS JOIN public.remediation_global_state gs
        WHERE r.work_id=NEW.work_id
          AND r.request_id=NEW.run_id
          AND r.cluster_id=NEW.cluster_id
          AND r.idempotency_key=NEW.idempotency_key
          AND r.effect_receipt=r.request_id
          AND r.request_id='repair-' || r.attempt_id || '-' || r.job_id
          AND NEW.work_id='repair-work-' || r.attempt_id || '-' || r.job_id
          AND r.operation='SHERLOCK_EVIDENCE_COLLECTION_REQUEUE'
          AND r.status='REQUESTED'
          AND r.cancellation_requested_at IS NULL
          AND r.deadline_at=NEW.deadline
          AND NEW.work_expires_at=NEW.deadline
          AND NEW.available_at=NEW.scheduled_for
          AND NEW.max_series=10000 AND NEW.max_bytes=10485760
          AND NEW.range_start IS NULL AND NEW.range_end IS NULL
          AND NEW.range_step_seconds IS NULL
          AND rr.assurance='LIVE'
          AND rr.recipe_id='sherlock.evidence-collection-requeue'
          AND rr.recipe_version='2.0.0'
          AND rr.rollback_recipe_id='sherlock.evidence-collection-restore'
          AND rr.rollback_recipe_version='2.0.0'
          AND rr.privilege='SHERLOCK_INTERNAL'
          AND rr.tier=1 AND rr.max_targets=1
          AND rr.max_concurrency=1 AND rr.canary_targets=1
          AND rr.max_attempts=2
          AND rr.state IN ('CANARY_EXECUTING','ROLLING_OUT')
          AND rr.completed_at IS NULL
          AND rr.cancellation_requested_at IS NULL
          AND rr.deadline_at=NEW.deadline
          AND rr.lease_expires_at>clock_timestamp()
          AND ((rr.state='CANARY_EXECUTING' AND a.stage='CANARY')
            OR (rr.state='ROLLING_OUT' AND a.stage='ROLLOUT'))
          AND a.idempotency_key=NEW.idempotency_key
          AND a.lease_expires_at>clock_timestamp()
          AND a.attempt_id=(SELECT latest.attempt_id
              FROM public.remediation_attempts latest
              WHERE latest.cluster_id=rr.cluster_id AND latest.run_id=rr.run_id
              ORDER BY latest.created_at DESC,latest.attempt_id DESC LIMIT 1)
          AND rt.role='SHERLOCK_MANAGED_COLLECTION_STREAM'
          AND rt.source_relation='COLLECTION_JOBS'
          AND NOT EXISTS (SELECT 1 FROM public.remediation_run_targets other
              WHERE other.cluster_id=rr.cluster_id AND other.run_id=rr.run_id
                AND other.target<>r.job_id)
          AND NOT EXISTS (SELECT 1 FROM public.remediation_attempt_targets other
              WHERE other.cluster_id=r.cluster_id AND other.attempt_id=r.attempt_id
                AND other.target<>r.job_id)
          AND s.prior_revision=r.schedule_revision
          AND COALESCE(s.prior_configuration_revision,0)=r.configuration_revision
          AND s.live_request_id=r.request_id
          AND gs.id AND gs.remediation_enabled
          AND j.active
          AND p.enabled AND p.revoked_at IS NULL
          AND p.max_tier>=1
          AND p.max_targets>=1 AND p.max_concurrent_runs>=1
          AND p.require_rollback
          AND p.incident_kinds @> ARRAY['EVIDENCE_STREAM_STALE']::text[]
          AND p.not_before<=clock_timestamp() AND p.not_after>clock_timestamp()
          AND public.sherlock_m15_runtime_scope_allows(r.cluster_id,r.job_id)
          AND EXISTS (
              SELECT 1
              FROM public.collectors c
              JOIN public.collector_capabilities cap
                ON cap.collector_id=c.collector_id AND cap.capability=NEW.query_kind
              JOIN public.collector_source_health h
                ON h.collector_id=c.collector_id AND h.source_id=NEW.source_id
              WHERE c.cluster_id=NEW.cluster_id AND c.status='ACTIVE'
                AND c.identity_not_after>clock_timestamp()
                AND c.last_heartbeat_at BETWEEN clock_timestamp()-interval '2 minutes' AND clock_timestamp()
                AND h.availability='AVAILABLE'
                AND h.checked_at BETWEEN clock_timestamp()-interval '2 minutes' AND clock_timestamp()
          )
    ) INTO allowed;

    IF NOT COALESCE(allowed, false) THEN
        RAISE EXCEPTION 'M15 runtime work is not bound to authorized repair state' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION public.sherlock_m15_mark_runtime_work() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sherlock_m15_guard_runtime_work() FROM PUBLIC;

CREATE CONSTRAINT TRIGGER sherlock_m15_guard_runtime_work
AFTER INSERT ON public.collector_work_items
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW WHEN (NEW.remediation_runtime_managed)
EXECUTE FUNCTION public.sherlock_m15_guard_runtime_work();

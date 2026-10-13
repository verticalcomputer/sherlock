-- Repair collector admission shares the cluster advisory lock taken by the
-- supervisor effect, cancellation, reconciliation, and recovery paths. The
-- trigger is the final race fence: every exact authority row remains locked
-- until the collector claim/start/renewal transaction commits.
CREATE OR REPLACE FUNCTION m15_repair_attempt_authority() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  repair collection_repair_requests%ROWTYPE;
  policy_id_value text;
  policy_version_value integer;
  allowed boolean;
BEGIN
  IF TG_OP='UPDATE' AND NEW.status NOT IN ('CLAIMED','STARTED') THEN
    RETURN NEW;
  END IF;
  -- A shorter lease only hastens containment and is used by expiry
  -- reconciliation. Recheck authority for START and for extensions.
  IF TG_OP='UPDATE' AND NEW.status=OLD.status
     AND NEW.lease_expires_at<=OLD.lease_expires_at THEN
    RETURN NEW;
  END IF;

  SELECT r.* INTO repair
    FROM collection_repair_requests r
   WHERE r.work_id=NEW.work_id
   FOR SHARE OF r;
  IF NOT FOUND THEN
    RETURN NEW;
  END IF;

  PERFORM id FROM remediation_global_state WHERE id FOR SHARE;
  SELECT a.policy_id,a.policy_version INTO policy_id_value,policy_version_value
    FROM remediation_attempts a
   WHERE a.cluster_id=repair.cluster_id AND a.run_id=repair.run_id
     AND a.attempt_id=repair.attempt_id
   FOR SHARE OF a;
  PERFORM cluster_id FROM remediation_policies
   WHERE cluster_id=repair.cluster_id AND policy_id=policy_id_value
     AND version=policy_version_value FOR SHARE;
  PERFORM run_id FROM remediation_runs
   WHERE cluster_id=repair.cluster_id AND run_id=repair.run_id FOR SHARE;
  PERFORM job_id FROM collection_jobs
   WHERE cluster_id=repair.cluster_id AND job_id=repair.job_id FOR SHARE;
  PERFORM collector_id FROM collectors
   WHERE collector_id=NEW.collector_id AND cluster_id=repair.cluster_id FOR SHARE;
  PERFORM collector_id FROM collector_capabilities
   WHERE collector_id=NEW.collector_id
     AND capability=(SELECT query_kind FROM collector_work_items WHERE work_id=NEW.work_id)
   FOR SHARE;
  PERFORM collector_id FROM collector_source_health
   WHERE collector_id=NEW.collector_id
     AND source_id=(SELECT source_id FROM collector_work_items WHERE work_id=NEW.work_id)
   FOR SHARE;

  SELECT EXISTS(
    SELECT 1
      FROM remediation_global_state gs
      JOIN remediation_runs rr
        ON rr.cluster_id=repair.cluster_id AND rr.run_id=repair.run_id
      JOIN remediation_attempts ra
        ON ra.cluster_id=repair.cluster_id AND ra.run_id=repair.run_id
       AND ra.attempt_id=repair.attempt_id
      JOIN remediation_policies p
        ON p.cluster_id=repair.cluster_id AND p.policy_id=ra.policy_id
       AND p.version=ra.policy_version
      JOIN collection_jobs j
        ON j.cluster_id=repair.cluster_id AND j.job_id=repair.job_id
      JOIN collector_work_items w ON w.work_id=NEW.work_id
      JOIN collectors c
        ON c.collector_id=NEW.collector_id AND c.cluster_id=repair.cluster_id
      JOIN collector_capabilities cap
        ON cap.collector_id=c.collector_id AND cap.capability=w.query_kind
      JOIN collector_source_health h
        ON h.collector_id=c.collector_id AND h.source_id=w.source_id
     WHERE gs.id AND gs.remediation_enabled
       AND repair.status IN ('REQUESTED','CLAIMED')
       AND repair.deadline_at>clock_timestamp()
       AND rr.cancellation_requested_at IS NULL
       AND rr.state IN ('CANARY_EXECUTING','ROLLING_OUT','VERIFYING')
       AND p.enabled AND p.revoked_at IS NULL
       AND p.recipe_id=rr.recipe_id AND p.recipe_version=rr.recipe_version
       AND p.not_before<=clock_timestamp() AND p.not_after>clock_timestamp()
       AND j.active AND j.configuration_revision=repair.configuration_revision
       AND j.schedule_revision=repair.schedule_revision
       AND w.cluster_id=repair.cluster_id AND w.run_id=repair.request_id
       AND w.idempotency_key=repair.idempotency_key
       AND c.status='ACTIVE' AND c.identity_not_after>clock_timestamp()
       AND c.last_heartbeat_at BETWEEN clock_timestamp()-interval '2 minutes' AND clock_timestamp()
       AND h.availability='AVAILABLE'
       AND h.checked_at BETWEEN clock_timestamp()-interval '2 minutes' AND clock_timestamp()
  ) INTO allowed;
  IF NOT COALESCE(allowed,false) THEN
    RAISE EXCEPTION 'repair collection authority revoked' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER m15_repair_attempt_authority ON collector_work_attempts;
CREATE TRIGGER m15_repair_attempt_authority
BEFORE INSERT OR UPDATE OF status,lease_expires_at ON collector_work_attempts
FOR EACH ROW EXECUTE FUNCTION m15_repair_attempt_authority();

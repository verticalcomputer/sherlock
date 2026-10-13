-- Restore migration 59's claim rule before removing the source kind. Existing
-- typed plans retain their historical Slurm mapping on downgrade.
CREATE OR REPLACE FUNCTION durable_work_claimable(work text, collector text) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT NOT EXISTS(SELECT 1 FROM durable_schedule_occurrences WHERE work_id=work)
 OR EXISTS(SELECT 1 FROM desired_schedules d
 JOIN durable_schedule_occurrences o USING(cluster_id,source_id,operation,revision)
 JOIN durable_schedule_executions e USING(cluster_id,source_id,operation,revision)
 JOIN clusters cl ON cl.cluster_id=d.cluster_id
 JOIN sources s ON s.cluster_id=d.cluster_id AND s.source_id=d.source_id
 JOIN collectors c ON c.collector_id=e.collector_id AND c.cluster_id=d.cluster_id
 JOIN collector_work_items w ON w.work_id=o.work_id AND w.work_id=work AND w.cluster_id=d.cluster_id AND w.source_id=d.source_id
 JOIN collector_capabilities cap ON cap.collector_id=c.collector_id AND cap.capability=w.query_kind AND cap.version='1'
 WHERE d.enabled AND d.mode='durable' AND cl.removed_at IS NULL
 AND c.collector_id=collector AND c.status='ACTIVE'
 AND c.protocol_min<=CASE WHEN w.typed_plan IS NULL THEN 1 ELSE 2 END
 AND c.protocol_max>=CASE WHEN w.typed_plan IS NULL THEN 1 ELSE 2 END
 AND c.last_heartbeat_at>clock_timestamp()-interval '2 minutes'
 AND (c.identity_not_after IS NULL OR c.identity_not_after>clock_timestamp())
 AND (w.typed_plan IS NOT NULL OR w.source_id=ANY(c.reported_source_ids))
 AND s.kind=CASE WHEN w.typed_plan IS NULL THEN 'prometheus' ELSE 'slurm' END);
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM sources WHERE kind = 'gpu_process') THEN
        RAISE EXCEPTION 'cannot downgrade while gpu_process sources remain';
    END IF;
END $$;
ALTER TABLE sources DROP CONSTRAINT sources_kind_check;
ALTER TABLE sources ADD CONSTRAINT sources_kind_check
    CHECK (kind IN ('prometheus', 'model', 'diagnostic', 'slurm'));

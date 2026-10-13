-- GP-04b. Only explicit revision-bound execution configuration can be admitted.
-- Source health history can outlive collector reconfiguration. This is the
-- exact source set from the latest heartbeat, independent of reachability.
ALTER TABLE collectors ADD COLUMN reported_source_ids text[] NOT NULL DEFAULT '{}';
CREATE TABLE durable_admission_state (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 global_limit integer NOT NULL CHECK(global_limit BETWEEN 1 AND 10000),
 cluster_limit integer NOT NULL CHECK(cluster_limit BETWEEN 1 AND global_limit),
 last_cluster text NOT NULL DEFAULT ''
);
CREATE TABLE durable_schedule_state (
 cluster_id text NOT NULL, source_id text NOT NULL, operation text NOT NULL,
 next_due_at timestamptz NOT NULL, occurrence bigint NOT NULL DEFAULT 0 CHECK(occurrence>=0),
 coalesced_intervals bigint NOT NULL DEFAULT 0 CHECK(coalesced_intervals>=0),
 PRIMARY KEY(cluster_id,source_id,operation),
 FOREIGN KEY(cluster_id,source_id,operation) REFERENCES desired_schedules ON DELETE CASCADE
);
CREATE FUNCTION durable_schedule_initialize() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO durable_schedule_state(cluster_id,source_id,operation,next_due_at)
 VALUES(NEW.cluster_id,NEW.source_id,NEW.operation,
 COALESCE((SELECT next_run_at FROM collection_jobs WHERE job_id=NEW.legacy_job_id),clock_timestamp()));
 RETURN NEW;
END $$;
CREATE TRIGGER durable_schedule_initialize AFTER INSERT ON desired_schedules FOR EACH ROW EXECUTE FUNCTION durable_schedule_initialize();
INSERT INTO durable_schedule_state(cluster_id,source_id,operation,next_due_at)
 SELECT d.cluster_id,d.source_id,d.operation,COALESCE(j.next_run_at,clock_timestamp())
 FROM desired_schedules d LEFT JOIN collection_jobs j ON j.job_id=d.legacy_job_id;
CREATE TABLE durable_schedule_executions (
 cluster_id text NOT NULL, source_id text NOT NULL, operation text NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 collector_id text NOT NULL REFERENCES collectors,
 nodes jsonb NOT NULL CHECK(jsonb_typeof(nodes)='array'),
 PRIMARY KEY(cluster_id,source_id,operation,revision),
 FOREIGN KEY(cluster_id,source_id,operation) REFERENCES desired_schedules ON DELETE CASCADE
);
CREATE TABLE durable_schedule_occurrences (
 work_id text PRIMARY KEY REFERENCES collector_work_items ON DELETE CASCADE,
 cluster_id text NOT NULL, source_id text NOT NULL, operation text NOT NULL, revision bigint NOT NULL,
 occurrence bigint NOT NULL CHECK(occurrence>0), due_at timestamptz NOT NULL,
 coalesced_intervals bigint NOT NULL CHECK(coalesced_intervals>=0),
 UNIQUE(cluster_id,source_id,operation,occurrence),
 FOREIGN KEY(cluster_id,source_id,operation,revision) REFERENCES durable_schedule_executions
);

-- A query filter avoids selecting stale work; this trigger is the concurrent
-- revision/claim race fence. Schedule changes take no work locks, so claims
-- may safely lock work before taking a shared configuration lock.
-- Narrow definer helpers preserve restricted repair-role access: unrelated
-- work returns immediately, without granting that role access to configuration.
CREATE FUNCTION durable_work_claimable(work text, collector text) RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
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
CREATE FUNCTION durable_schedule_attempt_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE o durable_schedule_occurrences%ROWTYPE;
BEGIN
 SELECT * INTO o FROM durable_schedule_occurrences WHERE work_id=NEW.work_id;
 IF NOT FOUND THEN RETURN NEW; END IF;
 -- Fail-fast locks avoid reversing pre-existing collector and cluster-removal
 -- lock orders. A configuration race rolls the entire claim back for retry.
 PERFORM cluster_id FROM clusters WHERE cluster_id=o.cluster_id FOR SHARE NOWAIT;
 PERFORM cluster_id FROM desired_schedules WHERE cluster_id=o.cluster_id AND source_id=o.source_id AND operation=o.operation FOR SHARE NOWAIT;
 PERFORM source_id FROM sources WHERE cluster_id=o.cluster_id AND source_id=o.source_id FOR SHARE NOWAIT;
 PERFORM collector_id FROM collectors WHERE collector_id=NEW.collector_id FOR SHARE NOWAIT;
 PERFORM collector_id FROM collector_capabilities WHERE collector_id=NEW.collector_id FOR SHARE NOWAIT;
 IF NOT durable_work_claimable(NEW.work_id,NEW.collector_id) THEN RAISE EXCEPTION 'durable schedule claim authority changed' USING ERRCODE='40001'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER durable_schedule_attempt_guard BEFORE INSERT ON collector_work_attempts FOR EACH ROW EXECUTE FUNCTION durable_schedule_attempt_guard();
REVOKE ALL ON FUNCTION durable_schedule_attempt_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION durable_work_claimable(text,text) FROM PUBLIC;
-- A separately provisioned API/collector-control database role must receive
-- EXECUTE ON FUNCTION public.durable_work_claimable(text,text), alongside its
-- existing collector-table privileges. This repository's only restricted role
-- artifact is for M15 remediation; that role receives neither this grant nor
-- scheduler configuration access. Trigger invocation needs no caller grant.

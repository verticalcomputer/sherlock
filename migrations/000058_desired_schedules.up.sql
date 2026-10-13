-- GP-04a: configuration authority only; durable admission remains disabled.
ALTER TABLE collection_jobs ADD COLUMN desired_revision bigint NOT NULL DEFAULT 0 CHECK(desired_revision>=0);
ALTER TABLE collection_jobs ADD CONSTRAINT collection_jobs_schedule_identity UNIQUE(cluster_id,source_id,query_kind,job_id);
CREATE TABLE desired_schedules (
 cluster_id text NOT NULL,
 source_id text NOT NULL,
 operation text NOT NULL CHECK(length(operation)>0),
 enabled boolean NOT NULL,
 mode text NOT NULL CHECK(mode IN ('legacy','durable')),
 interval_seconds integer NOT NULL CHECK(interval_seconds>0),
 timeout_ms bigint NOT NULL CHECK(timeout_ms>0 AND timeout_ms<=interval_seconds::bigint*1000),
 jitter_ms bigint NOT NULL CHECK(jitter_ms>=0 AND jitter_ms<interval_seconds::bigint*1000),
 max_targets integer NOT NULL CHECK(max_targets BETWEEN 1 AND 10000),
 max_bytes bigint NOT NULL CHECK(max_bytes BETWEEN 1 AND 10485760),
 priority integer NOT NULL CHECK(priority BETWEEN 0 AND 100),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 legacy_query_kind text,
 legacy_job_id text,
 PRIMARY KEY(cluster_id,source_id,operation),
 UNIQUE(legacy_job_id),
 UNIQUE(cluster_id,source_id,legacy_query_kind),
 FOREIGN KEY(cluster_id,source_id) REFERENCES sources(cluster_id,source_id),
 FOREIGN KEY(cluster_id,source_id,legacy_query_kind,legacy_job_id)
   REFERENCES collection_jobs(cluster_id,source_id,query_kind,job_id),
 CHECK((legacy_query_kind IS NULL)=(legacy_job_id IS NULL)),
 CHECK(mode<>'legacy' OR legacy_job_id IS NOT NULL)
);

CREATE OR REPLACE FUNCTION collection_job_configuration_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 NEW.configuration_revision := OLD.configuration_revision;
 IF ROW(NEW.cluster_id,NEW.source_id,NEW.query_kind,NEW.node_filter,NEW.active,NEW.interval_seconds,NEW.desired_revision)
    IS DISTINCT FROM ROW(OLD.cluster_id,OLD.source_id,OLD.query_kind,OLD.node_filter,OLD.active,OLD.interval_seconds,OLD.desired_revision) THEN
  NEW.configuration_revision := OLD.configuration_revision+1;
 END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION desired_schedule_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.cluster_id,NEW.source_id,NEW.operation,NEW.legacy_query_kind,NEW.legacy_job_id)
   IS DISTINCT FROM ROW(OLD.cluster_id,OLD.source_id,OLD.operation,OLD.legacy_query_kind,OLD.legacy_job_id) THEN
   RAISE EXCEPTION 'desired schedule identity is immutable' USING ERRCODE='23514';
  END IF;
  NEW.revision := OLD.revision+1;
 ELSE
  NEW.revision := 1;
 END IF;
 -- Retain the existing M15 population authority fence for every configuration
 -- revision, including limits-only changes which still revoke stale binding.
 IF NOT pg_try_advisory_xact_lock(hashtextextended('m15-repair:'||NEW.cluster_id,0)) THEN
  RAISE EXCEPTION 'collection configuration authority busy; retry transaction' USING ERRCODE='40001';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER desired_schedule_revision BEFORE INSERT OR UPDATE ON desired_schedules
 FOR EACH ROW EXECUTE FUNCTION desired_schedule_revision();

CREATE FUNCTION desired_schedule_sync_job() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE collection_jobs SET active=NEW.enabled AND NEW.mode='legacy', interval_seconds=NEW.interval_seconds,
  desired_revision=NEW.revision, lease_owner=NULL, lease_expires_at=NULL
  WHERE cluster_id=NEW.cluster_id AND job_id=NEW.legacy_job_id;
 RETURN NEW;
END $$;
CREATE TRIGGER desired_schedule_sync_job AFTER INSERT OR UPDATE ON desired_schedules
 FOR EACH ROW EXECUTE FUNCTION desired_schedule_sync_job();

CREATE FUNCTION desired_schedule_guard_job() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE schedule desired_schedules%ROWTYPE;
BEGIN
 IF TG_OP='UPDATE' AND OLD.desired_revision>0 AND
  ROW(NEW.job_id,NEW.cluster_id,NEW.source_id,NEW.query_kind,NEW.node_filter)
  IS DISTINCT FROM ROW(OLD.job_id,OLD.cluster_id,OLD.source_id,OLD.query_kind,OLD.node_filter) THEN
  RAISE EXCEPTION 'owned collection job identity is immutable' USING ERRCODE='23514';
 END IF;
 SELECT * INTO schedule FROM desired_schedules WHERE cluster_id=NEW.cluster_id
  AND source_id=NEW.source_id AND legacy_query_kind=NEW.query_kind;
 IF FOUND AND (NEW.job_id<>schedule.legacy_job_id OR NEW.node_filter<>'' OR
   NEW.active<>(schedule.enabled AND schedule.mode='legacy') OR
   NEW.interval_seconds<>schedule.interval_seconds OR NEW.desired_revision<>schedule.revision) THEN
  RAISE EXCEPTION 'collection job is owned by a desired schedule' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER desired_schedule_guard_job BEFORE INSERT OR UPDATE ON collection_jobs
 FOR EACH ROW EXECUTE FUNCTION desired_schedule_guard_job();

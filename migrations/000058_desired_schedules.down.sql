DROP TRIGGER desired_schedule_guard_job ON collection_jobs;
DROP FUNCTION desired_schedule_guard_job();
DROP TABLE desired_schedules;
DROP FUNCTION desired_schedule_sync_job();
DROP FUNCTION desired_schedule_revision();
CREATE OR REPLACE FUNCTION collection_job_configuration_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 NEW.configuration_revision := OLD.configuration_revision;
 IF ROW(NEW.cluster_id,NEW.source_id,NEW.query_kind,NEW.node_filter,NEW.active,NEW.interval_seconds)
    IS DISTINCT FROM ROW(OLD.cluster_id,OLD.source_id,OLD.query_kind,OLD.node_filter,OLD.active,OLD.interval_seconds) THEN
  NEW.configuration_revision := OLD.configuration_revision+1;
 END IF;
 RETURN NEW;
END $$;
ALTER TABLE collection_jobs DROP CONSTRAINT collection_jobs_schedule_identity;
ALTER TABLE collection_jobs DROP COLUMN desired_revision;

-- M15 collection provenance prerequisite. No live execution is enabled here.
-- Keep the historical M14 schedule_revision (which includes cadence progress).
ALTER TABLE collection_jobs ADD COLUMN configuration_revision bigint NOT NULL DEFAULT 0;
ALTER TABLE collection_jobs ADD COLUMN lease_generation bigint NOT NULL DEFAULT 0;
CREATE FUNCTION collection_job_configuration_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 NEW.configuration_revision := OLD.configuration_revision;
 IF ROW(NEW.cluster_id,NEW.source_id,NEW.query_kind,NEW.node_filter,NEW.active,NEW.interval_seconds)
    IS DISTINCT FROM ROW(OLD.cluster_id,OLD.source_id,OLD.query_kind,OLD.node_filter,OLD.active,OLD.interval_seconds) THEN
  NEW.configuration_revision := OLD.configuration_revision+1;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER collection_job_configuration_revision BEFORE UPDATE ON collection_jobs
 FOR EACH ROW EXECUTE FUNCTION collection_job_configuration_revision();

-- A worker binds a run before any local or outbound collection. The collector
-- does not select a job by identifier prefix or by supplied evidence metadata.
ALTER TABLE collection_jobs ADD CONSTRAINT collection_jobs_cluster_job_unique UNIQUE(cluster_id,job_id);
ALTER TABLE sources ADD CONSTRAINT sources_cluster_source_unique UNIQUE(cluster_id,source_id);
ALTER TABLE collection_runs ADD CONSTRAINT collection_runs_cluster_job_fk FOREIGN KEY(cluster_id,job_id) REFERENCES collection_jobs(cluster_id,job_id);
CREATE TABLE collection_run_jobs (
 run_id text PRIMARY KEY,
 job_id text NOT NULL REFERENCES collection_jobs(job_id),
 cluster_id text NOT NULL REFERENCES clusters(cluster_id),
 source_id text NOT NULL REFERENCES sources(source_id),
 query_kind text NOT NULL,
 node_filter text NOT NULL,
 scheduled_for timestamptz NOT NULL,
 configuration_revision bigint NOT NULL CHECK(configuration_revision>=0),
 lease_generation bigint NOT NULL CHECK(lease_generation>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(cluster_id,job_id,scheduled_for,configuration_revision),
 FOREIGN KEY(cluster_id,job_id) REFERENCES collection_jobs(cluster_id,job_id),
 FOREIGN KEY(cluster_id,source_id) REFERENCES sources(cluster_id,source_id)
);
CREATE INDEX collection_run_jobs_job_idx ON collection_run_jobs(cluster_id,job_id,created_at DESC);

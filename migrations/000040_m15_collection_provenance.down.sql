DROP TABLE collection_run_jobs;
ALTER TABLE collection_runs DROP CONSTRAINT collection_runs_cluster_job_fk;
ALTER TABLE collection_jobs DROP CONSTRAINT collection_jobs_cluster_job_unique;
ALTER TABLE sources DROP CONSTRAINT sources_cluster_source_unique;
DROP TRIGGER collection_job_configuration_revision ON collection_jobs;
DROP FUNCTION collection_job_configuration_revision();
ALTER TABLE collection_jobs DROP COLUMN lease_generation;
ALTER TABLE collection_jobs DROP COLUMN configuration_revision;

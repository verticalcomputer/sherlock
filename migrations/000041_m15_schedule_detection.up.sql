-- Immutable detector evidence and its exact investigation/job relationships.
CREATE TABLE schedule_repair_detections (
 detection_id text PRIMARY KEY,
 cluster_id text NOT NULL,
 job_id text NOT NULL,
 source_id text NOT NULL,
 configuration_revision bigint NOT NULL,
 schedule_revision bigint NOT NULL,
 evidence_id text NOT NULL UNIQUE REFERENCES evidence_envelopes(evidence_id),
 incident_id text NOT NULL,
 investigation_id text NOT NULL UNIQUE,
 facts jsonb NOT NULL CHECK(jsonb_typeof(facts)='object'),
 observed_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(cluster_id,job_id,configuration_revision,schedule_revision),
 FOREIGN KEY(cluster_id,job_id) REFERENCES collection_jobs(cluster_id,job_id),
 FOREIGN KEY(cluster_id,source_id) REFERENCES sources(cluster_id,source_id),
 FOREIGN KEY(cluster_id,incident_id) REFERENCES incidents(cluster_id,incident_id)
);
CREATE TABLE schedule_repair_decisions (
 cluster_id text NOT NULL,
 job_id text NOT NULL,
 code text NOT NULL,
 observed_at timestamptz NOT NULL,
 PRIMARY KEY(cluster_id,job_id),
 FOREIGN KEY(cluster_id,job_id) REFERENCES collection_jobs(cluster_id,job_id)
);

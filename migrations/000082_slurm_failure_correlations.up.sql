-- Frozen bounded correlation, separate from mutable four-cycle network retention.
CREATE TABLE slurm_failure_correlations (
 incident_id text PRIMARY KEY REFERENCES incidents(incident_id) ON DELETE RESTRICT,
 evidence_id text NOT NULL UNIQUE REFERENCES evidence_envelopes(evidence_id) ON DELETE RESTRICT,
 document jsonb NOT NULL CHECK(jsonb_typeof(document)='object' AND octet_length(document::text)<=262144),
 created_at timestamptz NOT NULL
);
CREATE FUNCTION slurm_correlation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable Slurm correlation'; END $$;
CREATE TRIGGER slurm_correlation_immutable BEFORE UPDATE OR DELETE ON slurm_failure_correlations FOR EACH ROW EXECUTE FUNCTION slurm_correlation_immutable();
-- Bound historical scans by cluster/time before joining source/run evidence.
CREATE INDEX slurm_correlation_observation_window_idx ON observations(cluster_id,observed_at DESC,observation_id);

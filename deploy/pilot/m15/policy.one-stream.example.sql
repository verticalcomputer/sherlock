-- Execute with psql variables and the separately reviewed policy-admin identity.
-- This is a prepared statement validation plus a default-disabled policy insert.
\set cluster_id 'CLUSTER_ID_REQUIRED'
\set policy_id 'POLICY_ID_REQUIRED'
-- Choose a version strictly above all existing policies for this cluster/recipe.
-- Record this exact version in the approval; ties fail closed, including disabled rows.
\set policy_version 'POLICY_VERSION_REQUIRED'
BEGIN;
PREPARE m15_one_stream_policy(text,text,integer,timestamptz,timestamptz) AS
INSERT INTO remediation_policies (cluster_id,policy_id,version,recipe_id,recipe_version,enabled,max_tier,incident_kinds,max_targets,max_concurrent_runs,cooldown_seconds,evidence_max_age_seconds,min_evidence_coverage,not_before,not_after)
VALUES ($1,$2,$3,'sherlock.evidence-collection-requeue','2.0.0',false,1,ARRAY['EVIDENCE_STREAM_STALE'],1,1,0,900,100,$4,$5);
-- Replace timestamps only in the approved change record. Policy remains disabled.
EXECUTE m15_one_stream_policy(:'cluster_id',:'policy_id',:'policy_version',clock_timestamp(),clock_timestamp()+interval '30 minutes');
ROLLBACK;

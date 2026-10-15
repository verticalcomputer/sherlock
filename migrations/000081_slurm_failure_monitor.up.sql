-- Opt-in monitoring only. No source, receiver or workload is enabled here.
CREATE TABLE slurm_failure_inputs (
 cluster_id text NOT NULL, source_id text NOT NULL, record_identity text NOT NULL,
 scheduler_namespace text NOT NULL, job_id text NOT NULL, submit_at timestamptz NOT NULL,
 attempt integer NOT NULL CHECK(attempt>=0), ended_at timestamptz, failed boolean NOT NULL,
 PRIMARY KEY(cluster_id,source_id,record_identity),
 FOREIGN KEY(cluster_id,source_id,record_identity) REFERENCES goodput_slurm_lifecycle_facts(cluster_id,source_id,record_identity) ON DELETE CASCADE
);
INSERT INTO slurm_failure_inputs
 SELECT cluster_id,source_id,record_identity,document->'job'->>'SchedulerNamespace',document->'job'->>'JobID',
 (document->'job'->>'SubmitAt')::timestamptz,(document->'job'->>'Attempt')::integer,
 CASE WHEN document->>'end_quality'='PRESENT' THEN (document->>'end_at')::timestamptz END,
 rtrim(split_part(upper(document->>'raw_state'),' ',1),'+') IN ('FAILED','NODE_FAIL','OUT_OF_MEMORY','BOOT_FAIL','TIMEOUT')
 FROM goodput_slurm_lifecycle_facts ON CONFLICT DO NOTHING;
CREATE INDEX slurm_failure_inputs_window ON slurm_failure_inputs(cluster_id,source_id,scheduler_namespace,ended_at) WHERE failed;
CREATE INDEX slurm_failure_inputs_attempt ON slurm_failure_inputs(cluster_id,source_id,scheduler_namespace,job_id,submit_at,attempt);
CREATE TABLE slurm_failure_policies (
 policy_id text PRIMARY KEY, cluster_id text NOT NULL, source_id text NOT NULL,
 policy jsonb NOT NULL CHECK(jsonb_typeof(policy)='object'), enabled boolean NOT NULL DEFAULT true,
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0), occurrence bigint NOT NULL DEFAULT 0 CHECK(occurrence>=0),
 active_incident_id text REFERENCES incidents(incident_id), eligible_after timestamptz,
 next_due_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 last_evaluated_at timestamptz, last_code text NOT NULL DEFAULT 'NOT_EVALUATED' CHECK(length(last_code)<=64),
 observed_failures integer NOT NULL DEFAULT 0 CHECK(observed_failures>=0), conflicting_attempts integer NOT NULL DEFAULT 0 CHECK(conflicting_attempts>=0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(cluster_id,source_id) REFERENCES sources(cluster_id,source_id),
 UNIQUE(cluster_id,policy_id)
);
CREATE UNIQUE INDEX slurm_failure_policy_scope ON slurm_failure_policies(cluster_id,source_id,(policy->>'scheduler_namespace'),(coalesce(policy->>'node_id',''))) WHERE enabled;
CREATE INDEX slurm_failure_policies_due ON slurm_failure_policies(next_due_at,policy_id) WHERE enabled;
CREATE TABLE slurm_failure_consumed (
 policy_id text NOT NULL REFERENCES slurm_failure_policies(policy_id),
 attempt_key text NOT NULL CHECK(length(attempt_key)=64),
 PRIMARY KEY(policy_id,attempt_key)
);
CREATE TABLE slurm_failure_episodes (
 policy_id text NOT NULL REFERENCES slurm_failure_policies(policy_id), occurrence bigint NOT NULL,
 incident_id text NOT NULL REFERENCES incidents(incident_id),
 evidence_id text NOT NULL REFERENCES evidence_envelopes(evidence_id),
 alert_id text NOT NULL REFERENCES gp09_alert_outbox(alert_id),
 snapshot jsonb NOT NULL CHECK(jsonb_typeof(snapshot)='array' AND jsonb_array_length(snapshot) BETWEEN 2 AND 32 AND octet_length(snapshot::text)<=65536),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(policy_id,occurrence)
);
CREATE TABLE slurm_failure_audit (
 audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 policy_id text NOT NULL REFERENCES slurm_failure_policies(policy_id),
 actor text NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
 action text NOT NULL CHECK(action IN ('ENROLLED','ENABLED','DISABLED')),
 revision bigint NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION slurm_failure_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Slurm failure monitoring history is immutable' USING ERRCODE='23514'; END $$;
CREATE TRIGGER slurm_failure_episodes_immutable BEFORE UPDATE OR DELETE ON slurm_failure_episodes FOR EACH ROW EXECUTE FUNCTION slurm_failure_immutable();
CREATE TRIGGER slurm_failure_audit_immutable BEFORE UPDATE OR DELETE ON slurm_failure_audit FOR EACH ROW EXECUTE FUNCTION slurm_failure_immutable();
ALTER TABLE gp09_alert_outbox DROP CONSTRAINT gp09_alert_outbox_transition_check;
ALTER TABLE gp09_alert_outbox ADD CONSTRAINT gp09_alert_outbox_transition_check CHECK(transition IN ('TEST','SOURCE_GAP','PORT_DOWN','LINK_EVENT','RECOVERED','MONITOR_OPEN','MONITOR_RECOVER','SLURM_FAILURES'));
CREATE INDEX slurm_failure_accounting_recent ON collector_typed_result_ingestions(cluster_id,source_id,finalized_at DESC) WHERE operation='slurm.snapshot.v1';

-- GP09 existing-source monitoring. Additive authority only: no policy/source is
-- enrolled or enabled by this migration. Existing network producer and sender
-- remain unchanged. Raw observation/run IDs inside snapshots are logical refs;
-- bounded immutable facts survive normal retention without new raw-data FKs.
CREATE TABLE gp09_monitor_enrollments (
 policy_id text PRIMARY KEY CHECK(length(policy_id) BETWEEN 1 AND 128),
 cluster_id text NOT NULL REFERENCES clusters(cluster_id) ON DELETE RESTRICT,
 source_id text NOT NULL,
 entity_key text NOT NULL CHECK(length(entity_key) BETWEEN 1 AND 256),
 rule_id text NOT NULL CHECK(length(rule_id) BETWEEN 1 AND 64),
 rule_version integer NOT NULL CHECK(rule_version>0),
 operation text NOT NULL CHECK(length(operation) BETWEEN 1 AND 128),
 scope_key text NOT NULL CHECK(length(scope_key)=64),
 enrollment_revision bigint NOT NULL DEFAULT 1 CHECK(enrollment_revision=1),
 control_revision bigint NOT NULL DEFAULT 1 CHECK(control_revision>0),
 policy jsonb NOT NULL CHECK(jsonb_typeof(policy)='object' AND octet_length(policy::text)<=65536),
 enabled boolean NOT NULL DEFAULT true,
 evaluator_state jsonb NOT NULL CHECK(jsonb_typeof(evaluator_state)='object' AND octet_length(evaluator_state::text)<=32768),
 state_evidence jsonb NOT NULL DEFAULT '[]' CHECK(jsonb_typeof(state_evidence)='array' AND jsonb_array_length(state_evidence)<=64 AND octet_length(state_evidence::text)<=131072),
 next_due_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 last_attempt_at timestamptz,
 history_coverage jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(history_coverage)='object' AND octet_length(history_coverage::text)<=4096),
 last_failure_code text NOT NULL DEFAULT '' CHECK(length(last_failure_code)<=64),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(cluster_id,policy_id),
 UNIQUE(cluster_id,policy_id,enrollment_revision),
 FOREIGN KEY(cluster_id,source_id) REFERENCES sources(cluster_id,source_id) ON DELETE RESTRICT,
 CHECK(updated_at>=created_at)
);
CREATE UNIQUE INDEX gp09_monitor_active_identity ON gp09_monitor_enrollments
 (cluster_id,source_id,entity_key,rule_id,rule_version,operation,scope_key,(coalesce(policy->>'metric',''))) WHERE enabled;
CREATE INDEX gp09_monitor_due ON gp09_monitor_enrollments(next_due_at,last_attempt_at,policy_id) WHERE enabled;

CREATE TABLE gp09_monitor_episodes (
 cluster_id text NOT NULL,
 policy_id text NOT NULL,
 enrollment_revision bigint NOT NULL,
 occurrence bigint NOT NULL CHECK(occurrence>0),
 incident_id text NOT NULL,
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 64),
 severity text NOT NULL CHECK(severity IN ('WARNING','CRITICAL')),
 opened_at timestamptz NOT NULL,
 closed_at timestamptz,
 closed_reason text NOT NULL DEFAULT '' CHECK(length(closed_reason)<=64),
 owner text NOT NULL DEFAULT '' CHECK(length(owner)<=128),
 acknowledged_by text NOT NULL DEFAULT '' CHECK(length(acknowledged_by)<=128),
 acknowledged_at timestamptz,
 maintenance_until timestamptz,
 maintenance_by text NOT NULL DEFAULT '' CHECK(length(maintenance_by)<=128),
 disposition_id text NOT NULL DEFAULT '' CHECK(length(disposition_id)<=128),
 PRIMARY KEY(policy_id,occurrence),
 UNIQUE(cluster_id,policy_id,occurrence),
 FOREIGN KEY(cluster_id,policy_id,enrollment_revision) REFERENCES gp09_monitor_enrollments(cluster_id,policy_id,enrollment_revision) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,incident_id) REFERENCES incidents(cluster_id,incident_id) ON DELETE RESTRICT,
 CHECK(closed_at IS NULL OR closed_at>=opened_at),
 CHECK((closed_at IS NULL)=(closed_reason='')),
 CHECK((acknowledged_at IS NULL)=(acknowledged_by='')),
 CHECK((maintenance_until IS NULL)=(maintenance_by=''))
);
CREATE UNIQUE INDEX gp09_monitor_episode_open ON gp09_monitor_episodes(policy_id) WHERE closed_at IS NULL;
CREATE INDEX gp09_monitor_episode_cluster ON gp09_monitor_episodes(cluster_id,opened_at DESC,policy_id);

CREATE TABLE gp09_monitor_transitions (
 cluster_id text NOT NULL,
 policy_id text NOT NULL,
 occurrence bigint NOT NULL,
 transition text NOT NULL CHECK(transition IN ('OPEN','RECOVER')),
 occurred_at timestamptz NOT NULL,
 reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 64),
 evidence_id text NOT NULL REFERENCES evidence_envelopes(evidence_id) ON DELETE RESTRICT,
 alert_id text NOT NULL REFERENCES gp09_alert_outbox(alert_id) ON DELETE RESTRICT,
 qualifying_sample_count bigint NOT NULL CHECK(qualifying_sample_count>=0),
 omitted_evidence_count bigint NOT NULL CHECK(omitted_evidence_count>=0),
 snapshot jsonb NOT NULL CHECK(jsonb_typeof(snapshot)='array' AND jsonb_array_length(snapshot)<=32 AND octet_length(snapshot::text)<=65536),
 PRIMARY KEY(policy_id,occurrence,transition),
 FOREIGN KEY(cluster_id,policy_id,occurrence) REFERENCES gp09_monitor_episodes(cluster_id,policy_id,occurrence) ON DELETE RESTRICT
);
CREATE TABLE gp09_monitor_audit (
 audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 cluster_id text NOT NULL,
 policy_id text NOT NULL,
 control_revision bigint NOT NULL CHECK(control_revision>0),
 occurrence bigint NOT NULL DEFAULT 0 CHECK(occurrence>=0),
 action text NOT NULL CHECK(action IN ('ENROLLED','REENABLED','DISABLED','ACKNOWLEDGED','OWNER_ASSIGNED','MAINTENANCE_CHANGED','RECOVERY_REVIEWED')),
 actor text NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
 actor_kind text NOT NULL DEFAULT 'LOCAL_OPERATOR' CHECK(actor_kind='LOCAL_OPERATOR'),
 details jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(details)='object' AND octet_length(details::text)<=4096),
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(cluster_id,policy_id) REFERENCES gp09_monitor_enrollments(cluster_id,policy_id) ON DELETE RESTRICT
);
CREATE INDEX gp09_monitor_audit_policy ON gp09_monitor_audit(policy_id,audit_id DESC);
CREATE TABLE gp09_monitor_dispositions (
 disposition_id text PRIMARY KEY CHECK(length(disposition_id) BETWEEN 1 AND 128),
 cluster_id text NOT NULL,
 policy_id text NOT NULL,
 enrollment_revision bigint NOT NULL CHECK(enrollment_revision=1),
 occurrence bigint NOT NULL,
 actor text NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
 evidence_id text NOT NULL REFERENCES evidence_envelopes(evidence_id) ON DELETE RESTRICT,
 reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(policy_id,occurrence),
 FOREIGN KEY(cluster_id,policy_id,occurrence) REFERENCES gp09_monitor_episodes(cluster_id,policy_id,occurrence) ON DELETE RESTRICT
);
CREATE FUNCTION gp09_monitor_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'monitoring historical evidence is immutable' USING ERRCODE='23514'; END $$;
CREATE TRIGGER gp09_monitor_transitions_immutable BEFORE UPDATE OR DELETE ON gp09_monitor_transitions FOR EACH ROW EXECUTE FUNCTION gp09_monitor_immutable();
CREATE TRIGGER gp09_monitor_audit_immutable BEFORE UPDATE OR DELETE ON gp09_monitor_audit FOR EACH ROW EXECUTE FUNCTION gp09_monitor_immutable();
CREATE TRIGGER gp09_monitor_dispositions_immutable BEFORE UPDATE OR DELETE ON gp09_monitor_dispositions FOR EACH ROW EXECUTE FUNCTION gp09_monitor_immutable();
ALTER TABLE gp09_alert_outbox DROP CONSTRAINT gp09_alert_outbox_transition_check;
ALTER TABLE gp09_alert_outbox ADD CONSTRAINT gp09_alert_outbox_transition_check CHECK(transition IN ('TEST','SOURCE_GAP','PORT_DOWN','LINK_EVENT','RECOVERED','MONITOR_OPEN','MONITOR_RECOVER'));
CREATE FUNCTION gp09_monitor_policy_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.policy_id,NEW.cluster_id,NEW.source_id,NEW.entity_key,NEW.rule_id,NEW.rule_version,NEW.operation,NEW.scope_key,NEW.enrollment_revision,NEW.policy,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.policy_id,OLD.cluster_id,OLD.source_id,OLD.entity_key,OLD.rule_id,OLD.rule_version,OLD.operation,OLD.scope_key,OLD.enrollment_revision,OLD.policy,OLD.created_at)
 THEN RAISE EXCEPTION 'monitoring enrollment policy is immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER gp09_monitor_policy_immutable BEFORE UPDATE ON gp09_monitor_enrollments FOR EACH ROW EXECUTE FUNCTION gp09_monitor_policy_immutable();

-- Keep a deferred monitoring retry inside the audited maintenance interval.
-- Existing sender code, receiver backoff and non-monitor transitions are intact.
-- A delivery already leased before maintenance cannot be recalled.
CREATE FUNCTION gp09_monitor_delivery_maintenance() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE until_at timestamptz;
BEGIN
 IF NEW.transition IN ('MONITOR_OPEN','MONITOR_RECOVER') AND NEW.status='PENDING' THEN
  SELECT e.maintenance_until INTO until_at FROM gp09_monitor_transitions t
  JOIN gp09_monitor_episodes e USING(cluster_id,policy_id,occurrence)
  WHERE t.alert_id=NEW.alert_id;
  IF until_at IS NOT NULL THEN NEW.available_at:=greatest(NEW.available_at,until_at); END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER gp09_monitor_delivery_maintenance BEFORE UPDATE ON gp09_alert_outbox FOR EACH ROW EXECUTE FUNCTION gp09_monitor_delivery_maintenance();

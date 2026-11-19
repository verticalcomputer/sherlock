-- Production notification lifecycle. Does not enroll, enable or send anything.
ALTER TABLE gp09_alert_outbox ADD COLUMN assessment_enrollment text NOT NULL DEFAULT '';
ALTER TABLE gp09_alert_outbox ADD COLUMN assessment_occurrence text NOT NULL DEFAULT '';
ALTER TABLE gp09_alert_outbox DROP CONSTRAINT gp09_alert_outbox_transition_check;
ALTER TABLE gp09_alert_outbox ADD CONSTRAINT gp09_alert_outbox_transition_check CHECK(transition IN ('TEST','SOURCE_GAP','PORT_DOWN','LINK_EVENT','RECOVERED','MONITOR_OPEN','MONITOR_RECOVER','SLURM_FAILURES','ASSESSMENT_OPEN','ASSESSMENT_WORSEN','ASSESSMENT_RECOVER','ASSESSMENT_CATCHUP'));
ALTER TABLE gp09_alert_outbox DROP CONSTRAINT gp09_alert_outbox_status_check;
ALTER TABLE gp09_alert_outbox ADD CONSTRAINT gp09_alert_outbox_status_check CHECK(status IN ('PENDING','LEASED','ACCEPTED','FAILED','SUPERSEDED','DISABLED'));
ALTER TABLE gp09_alert_outbox ADD CONSTRAINT gp09_assessment_scope CHECK((assessment_enrollment='')=(assessment_occurrence='') AND (assessment_enrollment='')=(transition NOT LIKE 'ASSESSMENT_%'));
CREATE TABLE production_notification_occurrences (
 occurrence_id text PRIMARY KEY CHECK(length(occurrence_id) BETWEEN 1 AND 128),
 cluster_id text NOT NULL REFERENCES clusters(cluster_id), enrollment_id text NOT NULL CHECK(length(enrollment_id) BETWEEN 1 AND 128),
 source_id text NOT NULL, category text NOT NULL, asset text NOT NULL, incident_id text NOT NULL,
 version bigint NOT NULL DEFAULT 1, next_sequence bigint NOT NULL DEFAULT 1,
 opened_at timestamptz NOT NULL, closed_at timestamptz,
 acknowledged_by text NOT NULL DEFAULT '', acknowledged_at timestamptz,
 maintenance_until timestamptz, maintenance_by text NOT NULL DEFAULT '', maintenance_reason text NOT NULL DEFAULT '',
 evidence_url text NOT NULL,
 FOREIGN KEY(cluster_id,source_id) REFERENCES sources(cluster_id,source_id),
 FOREIGN KEY(cluster_id,incident_id) REFERENCES incidents(cluster_id,incident_id),
 UNIQUE(cluster_id,enrollment_id,occurrence_id),
 CHECK(version>0 AND next_sequence>0), CHECK(closed_at IS NULL OR closed_at>=opened_at)
);
CREATE UNIQUE INDEX production_notification_open_asset ON production_notification_occurrences(cluster_id,enrollment_id,asset) WHERE closed_at IS NULL;
CREATE TABLE production_notification_events (
 event_id text PRIMARY KEY CHECK(length(event_id) BETWEEN 1 AND 128), occurrence_id text NOT NULL REFERENCES production_notification_occurrences(occurrence_id),
 sequence bigint NOT NULL CHECK(sequence>0), kind text NOT NULL CHECK(kind IN ('OPEN','WORSEN','RECOVER')),
 occurred_at timestamptz NOT NULL, summary text NOT NULL CHECK(octet_length(summary)<=2048),
 evidence_id text NOT NULL REFERENCES evidence_envelopes(evidence_id),
 evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='object' AND octet_length(evidence::text)<=16777216),
 input_hash text NOT NULL CHECK(length(input_hash)=64),
 UNIQUE(occurrence_id,sequence)
);
CREATE TABLE production_notification_intents (
 alert_id text PRIMARY KEY REFERENCES gp09_alert_outbox(alert_id),
 occurrence_id text NOT NULL REFERENCES production_notification_occurrences(occurrence_id),
 first_sequence bigint NOT NULL, last_sequence bigint NOT NULL,
 inherited_attempts integer NOT NULL DEFAULT 0 CHECK(inherited_attempts BETWEEN 0 AND 8),
 receipt_uncertain boolean NOT NULL DEFAULT false,
 oldest_pending_at timestamptz NOT NULL, catchup boolean NOT NULL DEFAULT false,
 superseded_by text REFERENCES gp09_alert_outbox(alert_id),
 CHECK(first_sequence>0 AND last_sequence>=first_sequence AND last_sequence-first_sequence<64)
);
CREATE INDEX production_notification_intent_occurrence ON production_notification_intents(occurrence_id,first_sequence);
CREATE TABLE production_notification_coverage (
 alert_id text NOT NULL REFERENCES gp09_alert_outbox(alert_id), event_id text NOT NULL REFERENCES production_notification_events(event_id),
 PRIMARY KEY(alert_id,event_id)
);
CREATE TABLE production_notification_audit (
 audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 occurrence_id text NOT NULL REFERENCES production_notification_occurrences(occurrence_id),
 version bigint NOT NULL, actor text NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
 action text NOT NULL CHECK(action IN ('ACKNOWLEDGED','MAINTENANCE_CHANGED')),
 details jsonb NOT NULL CHECK(octet_length(details::text)<=4096), occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION production_notification_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'production notification history is immutable' USING ERRCODE='23514'; END $$;
CREATE TRIGGER production_notification_event_immutable BEFORE UPDATE ON production_notification_events FOR EACH ROW EXECUTE FUNCTION production_notification_immutable();
CREATE TRIGGER production_notification_audit_immutable BEFORE UPDATE ON production_notification_audit FOR EACH ROW EXECUTE FUNCTION production_notification_immutable();
CREATE INDEX gp09_assessment_outbox_scope ON gp09_alert_outbox(cluster_id,assessment_enrollment,assessment_occurrence,available_at) WHERE assessment_enrollment<>'' AND status IN ('PENDING','LEASED');

-- Preserve the existing shadow role's executable-routine allow-list. Trigger
-- execution uses its installed binding; no caller EXECUTE grant is required.
REVOKE EXECUTE ON FUNCTION public.production_notification_immutable() FROM PUBLIC;

-- Preservation-first rollback: never erase populated monitoring authority,
-- evidence, operator history, episode or notification intent to fit old schema.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM gp09_monitor_enrollments)
 OR EXISTS(SELECT 1 FROM gp09_alert_outbox WHERE transition IN ('MONITOR_OPEN','MONITOR_RECOVER'))
 THEN RAISE EXCEPTION 'monitoring rollback requires preserved data; schema rollback refused' USING ERRCODE='55000'; END IF;
END $$;
DROP TRIGGER gp09_monitor_delivery_maintenance ON gp09_alert_outbox;
DROP FUNCTION gp09_monitor_delivery_maintenance();
DROP TABLE gp09_monitor_dispositions;
DROP TABLE gp09_monitor_audit;
DROP TABLE gp09_monitor_transitions;
DROP TABLE gp09_monitor_episodes;
DROP TABLE gp09_monitor_enrollments;
DROP FUNCTION gp09_monitor_immutable();
DROP FUNCTION gp09_monitor_policy_immutable();
ALTER TABLE gp09_alert_outbox DROP CONSTRAINT gp09_alert_outbox_transition_check;
ALTER TABLE gp09_alert_outbox ADD CONSTRAINT gp09_alert_outbox_transition_check CHECK(transition IN ('TEST','SOURCE_GAP','PORT_DOWN','LINK_EVENT','RECOVERED'));

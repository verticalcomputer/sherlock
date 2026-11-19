-- Rollback requires draining/removing production notification records explicitly.
DO $$ BEGIN IF EXISTS(SELECT 1 FROM gp09_alert_outbox WHERE assessment_enrollment<>'') THEN RAISE EXCEPTION 'production notifications must be retained/exported before rollback'; END IF; END $$;
DROP TABLE production_notification_audit,production_notification_coverage,production_notification_intents,production_notification_events,production_notification_occurrences;
DROP FUNCTION production_notification_immutable();
DROP INDEX gp09_assessment_outbox_scope;
ALTER TABLE gp09_alert_outbox DROP CONSTRAINT gp09_assessment_scope;
ALTER TABLE gp09_alert_outbox DROP COLUMN assessment_enrollment, DROP COLUMN assessment_occurrence;
ALTER TABLE gp09_alert_outbox DROP CONSTRAINT gp09_alert_outbox_status_check;
ALTER TABLE gp09_alert_outbox ADD CONSTRAINT gp09_alert_outbox_status_check CHECK(status IN ('PENDING','LEASED','ACCEPTED','FAILED'));
ALTER TABLE gp09_alert_outbox DROP CONSTRAINT gp09_alert_outbox_transition_check;
ALTER TABLE gp09_alert_outbox ADD CONSTRAINT gp09_alert_outbox_transition_check CHECK(transition IN ('TEST','SOURCE_GAP','PORT_DOWN','LINK_EVENT','RECOVERED','MONITOR_OPEN','MONITOR_RECOVER','SLURM_FAILURES'));

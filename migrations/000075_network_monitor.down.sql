DROP TABLE gp09_network_episodes;
DROP TABLE gp09_network_cycles;
DROP TABLE gp09_network_monitors;
ALTER TABLE gp09_alert_outbox DROP CONSTRAINT gp09_alert_outbox_transition_check;
ALTER TABLE gp09_alert_outbox ADD CONSTRAINT gp09_alert_outbox_transition_check
 CHECK(transition IN ('TEST','SOURCE_GAP','PORT_DOWN','RECOVERED'));

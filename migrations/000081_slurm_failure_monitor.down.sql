-- Preserve published history on rollback; an operator must archive it first.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM slurm_failure_episodes) THEN RAISE EXCEPTION 'Slurm monitoring history must be preserved before rollback'; END IF;
END $$;
DROP INDEX slurm_failure_accounting_recent;
DROP TABLE slurm_failure_audit,slurm_failure_episodes,slurm_failure_consumed,slurm_failure_policies,slurm_failure_inputs;
DROP FUNCTION slurm_failure_immutable();
ALTER TABLE gp09_alert_outbox DROP CONSTRAINT gp09_alert_outbox_transition_check;
ALTER TABLE gp09_alert_outbox ADD CONSTRAINT gp09_alert_outbox_transition_check CHECK(transition IN ('TEST','SOURCE_GAP','PORT_DOWN','LINK_EVENT','RECOVERED','MONITOR_OPEN','MONITOR_RECOVER'));

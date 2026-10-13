-- A future live adapter must publish its exact restoration fence in the same
-- transaction as the owned schedule-field restoration. No M14 executor writes it.
ALTER TABLE remediation_schedule_snapshots
 ADD COLUMN live_forward_revision bigint,
 ADD COLUMN live_restored_revision bigint,
 ADD COLUMN live_restored_attempt_id text,
 ADD FOREIGN KEY(cluster_id,live_restored_attempt_id) REFERENCES remediation_attempts(cluster_id,attempt_id);

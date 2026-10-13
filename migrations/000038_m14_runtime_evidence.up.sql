-- Forward-only continuation of M14. No live schedule mutation is introduced.
ALTER TABLE remediation_runs ADD COLUMN supervisor_owner text;
ALTER TABLE remediation_runs ADD COLUMN supervisor_until timestamptz;
CREATE UNIQUE INDEX remediation_card_once ON remediation_runs(cluster_id, action_card_id) WHERE action_card_id IS NOT NULL;
ALTER TABLE remediation_runs DROP CONSTRAINT remediation_runs_contained_reason_check;
ALTER TABLE remediation_runs ADD CHECK (contained_reason IS NULL OR contained_reason IN ('LEASE_LOST','UNKNOWN_OUTCOME','ROLLBACK_UNAVAILABLE','ROLLBACK_UNKNOWN','OPERATOR_CONTAINED','TARGET_DRIFT','RECIPE_EXPIRED','AUTHORITY_REVOKED'));
-- Each target's restoration contract is captured before the first simulated change.
-- Rollback owns active, interval_seconds and next_run_at only. A revision fences
-- even an intervening change that later restores the same values (ABA).
ALTER TABLE collection_jobs ADD COLUMN schedule_revision bigint NOT NULL DEFAULT 0;
CREATE FUNCTION remediation_schedule_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.active,NEW.interval_seconds,NEW.next_run_at) IS DISTINCT FROM ROW(OLD.active,OLD.interval_seconds,OLD.next_run_at) THEN
 NEW.schedule_revision := OLD.schedule_revision+1;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER remediation_schedule_revision BEFORE UPDATE ON collection_jobs FOR EACH ROW EXECUTE FUNCTION remediation_schedule_revision();
CREATE TABLE remediation_schedule_snapshots (
 cluster_id text NOT NULL, run_id text NOT NULL, target text NOT NULL,
 prior_active boolean NOT NULL, prior_interval integer NOT NULL, prior_next timestamptz NOT NULL,
 prior_revision bigint NOT NULL, captured_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(cluster_id,run_id,target),
 FOREIGN KEY(cluster_id,run_id,target) REFERENCES remediation_run_targets(cluster_id,run_id,target)
);
CREATE TABLE remediation_simulation_state (
 cluster_id text NOT NULL, run_id text NOT NULL, target text NOT NULL,
 active boolean NOT NULL, interval_seconds integer NOT NULL, next_run_at timestamptz NOT NULL,
 revision bigint NOT NULL, forward_revision bigint, restored_revision bigint,
 last_attempt_id text, updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(cluster_id,run_id,target),
 FOREIGN KEY(cluster_id,run_id,target) REFERENCES remediation_schedule_snapshots(cluster_id,run_id,target),
 FOREIGN KEY(cluster_id,last_attempt_id) REFERENCES remediation_attempts(cluster_id,attempt_id)
);
-- Controlled independent simulation observations; executor receipts never fill this table.
CREATE TABLE remediation_simulation_observations (
 evidence_id text PRIMARY KEY, cluster_id text NOT NULL, run_id text NOT NULL, attempt_id text NOT NULL,
 target text NOT NULL, observed_start timestamptz NOT NULL, observed_end timestamptz NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(), complete boolean NOT NULL,
 FOREIGN KEY(cluster_id,attempt_id,target) REFERENCES remediation_attempt_targets(cluster_id,attempt_id,target),
 FOREIGN KEY(cluster_id,run_id,target) REFERENCES remediation_run_targets(cluster_id,run_id,target),
 CHECK(observed_end>=observed_start)
);
CREATE TABLE remediation_verification_evidence (
 cluster_id text NOT NULL, run_id text NOT NULL, attempt_id text NOT NULL, target text NOT NULL,
 condition_id text NOT NULL, evidence_id text NOT NULL, source text NOT NULL,
 observed_at timestamptz NOT NULL, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(cluster_id,run_id,attempt_id,target,condition_id,evidence_id),
 FOREIGN KEY(cluster_id,attempt_id,target) REFERENCES remediation_attempt_targets(cluster_id,attempt_id,target),
 FOREIGN KEY(cluster_id,run_id,target) REFERENCES remediation_run_targets(cluster_id,run_id,target)
);

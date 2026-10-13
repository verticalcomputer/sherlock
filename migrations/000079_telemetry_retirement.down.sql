DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM gp06f_telemetry_retirements)
 OR EXISTS(SELECT 1 FROM gp06f_telemetry_sessions WHERE released_through<>0 OR node_completed_through<>0 OR retirement_receipts_expired_through<>0 OR empty_release_completed OR retired_at IS NOT NULL)
 OR EXISTS(SELECT 1 FROM gp06f_telemetry_enrollments WHERE retired_through_epoch<>0)
 OR EXISTS(SELECT 1 FROM gp06f_telemetry_keys WHERE archived_at IS NOT NULL)
 THEN RAISE EXCEPTION 'ownership retirement rollback requires preservation of proofs and authority history' USING ERRCODE='23514'; END IF;
END $$;
DROP TABLE gp06f_telemetry_retirements;
DROP TRIGGER gp06f_telemetry_retirement_progress ON gp06f_telemetry_sessions;
DROP TRIGGER gp06f_telemetry_key_archive ON gp06f_telemetry_keys;
DROP TRIGGER gp06f_telemetry_epoch_retirement_progress ON gp06f_telemetry_enrollments;
DROP FUNCTION gp06f_telemetry_retirement_immutable(),gp06f_telemetry_retirement_progress(),gp06f_telemetry_key_archive(),gp06f_telemetry_epoch_retirement_progress();
ALTER TABLE gp06f_telemetry_sessions DROP COLUMN released_through,DROP COLUMN node_completed_through,DROP COLUMN retirement_receipts_expired_through,DROP COLUMN empty_release_completed;
DROP INDEX gp06f_telemetry_session_key_history,gp06f_telemetry_unretired_key;
ALTER TABLE gp06f_telemetry_enrollments DROP COLUMN retired_through_epoch;
DROP INDEX gp06f_telemetry_key_material_once;
ALTER TABLE gp06f_telemetry_keys DROP COLUMN archived_at;

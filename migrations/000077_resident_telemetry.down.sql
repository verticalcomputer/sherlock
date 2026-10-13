DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM gp06f_telemetry_enrollments) THEN
  RAISE EXCEPTION 'telemetry rollback refuses populated authority or history' USING ERRCODE='23514';
 END IF;
END $$;
DROP TABLE gp06f_telemetry_audit,gp06f_telemetry_intervals,gp06f_telemetry_loss,gp06f_telemetry_batches,gp06f_telemetry_lifecycle,gp06f_telemetry_sessions,gp06f_telemetry_keys,gp06f_telemetry_sources,gp06f_telemetry_enrollments;
DROP FUNCTION gp06f_telemetry_immutable(),gp06f_telemetry_enrollment_immutable(),gp06f_telemetry_key_identity_immutable(),gp06f_telemetry_session_identity_immutable();

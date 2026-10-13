-- Fail before changing the constraint if Linux authority/history still exists.
-- Never delete enrollments or rewrite source profiles to make rollback pass.
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM gp06f_telemetry_sources WHERE profile_id <> 'fixture.v1') THEN
  RAISE EXCEPTION 'Linux resident source enrollments prevent rollback';
 END IF;
END $$;
ALTER TABLE gp06f_telemetry_sources DROP CONSTRAINT gp06f_telemetry_sources_profile_id_check;
ALTER TABLE gp06f_telemetry_sources ADD CONSTRAINT gp06f_telemetry_sources_profile_id_check CHECK(profile_id='fixture.v1');

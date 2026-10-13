-- Add only closed Linux source profiles. Existing fixture rows are unchanged.
ALTER TABLE gp06f_telemetry_sources DROP CONSTRAINT gp06f_telemetry_sources_profile_id_check;
ALTER TABLE gp06f_telemetry_sources ADD CONSTRAINT gp06f_telemetry_sources_profile_id_check
 CHECK(profile_id IN ('fixture.v1','linux.host.v1','linux.rootfs.v1'));

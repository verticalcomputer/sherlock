-- V2 retains its original JSON bound. V3 fleet authority remains one profile
-- per cluster, bounded in the application to 128 GPUs / 16 nodes.
ALTER TABLE public.prometheus_cooling_upload_profiles
 DROP CONSTRAINT prometheus_cooling_upload_profiles_profile_check;
ALTER TABLE public.prometheus_cooling_upload_profiles
 ADD CONSTRAINT prometheus_cooling_upload_profiles_profile_check CHECK (
  jsonb_typeof(profile)='object' AND
  ((protocol_version=2 AND octet_length(profile::text)<=8192) OR
   (protocol_version=3 AND octet_length(profile::text)<=65536))
 );

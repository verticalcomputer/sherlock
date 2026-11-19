-- Older V3 binaries cannot honor fleet scope, even when a compact profile fits
-- the old byte bound. Preserve authority/evidence and refuse that downgrade.
LOCK TABLE public.prometheus_cooling_upload_profiles IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS (
  SELECT 1 FROM public.prometheus_cooling_upload_profiles p
  WHERE octet_length(p.profile::text)>8192 OR
   (p.protocol_version=3 AND (jsonb_array_length(p.profile->'assets')>8 OR
    (SELECT count(DISTINCT a->>'node_id') FROM jsonb_array_elements(p.profile->'assets') a)>2))
 ) THEN
  RAISE EXCEPTION 'fleet cooling authority must be retained; downgrade is unsafe' USING ERRCODE='55000';
 END IF;
END $$;
ALTER TABLE public.prometheus_cooling_upload_profiles
 DROP CONSTRAINT prometheus_cooling_upload_profiles_profile_check;
ALTER TABLE public.prometheus_cooling_upload_profiles
 ADD CONSTRAINT prometheus_cooling_upload_profiles_profile_check
 CHECK (jsonb_typeof(profile)='object' AND octet_length(profile::text)<=8192);

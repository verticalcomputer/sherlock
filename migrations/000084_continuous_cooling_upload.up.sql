-- Explicit V3 authority; V2 retains its original bounded-window constraints.
ALTER TABLE public.prometheus_cooling_upload_profiles
 ADD COLUMN protocol_version integer NOT NULL DEFAULT 2,
 ADD COLUMN collection_state text NOT NULL DEFAULT 'WINDOW',
 ALTER COLUMN ends_at DROP NOT NULL;
DO $$ DECLARE c record; BEGIN
 FOR c IN SELECT conname FROM pg_constraint WHERE conrelid='public.prometheus_cooling_upload_profiles'::regclass
 AND contype='c' AND (pg_get_constraintdef(oid) LIKE '%ends_at%') LOOP
 EXECUTE format('ALTER TABLE public.prometheus_cooling_upload_profiles DROP CONSTRAINT %I',c.conname);
 END LOOP;
END $$;
ALTER TABLE public.prometheus_cooling_upload_profiles ADD CONSTRAINT cooling_profile_versioned_lifecycle CHECK (
 (protocol_version=2 AND collection_state='WINDOW' AND ends_at IS NOT NULL
  AND ends_at>starts_at AND ends_at<=starts_at+interval '24 hours'
  AND registered_at<ends_at-interval '15 seconds' AND NOT (profile ? 'state'))
 OR (protocol_version=3 AND collection_state IN ('ENABLED','DISABLED') AND ends_at IS NULL
  AND coalesce(profile->>'state'=collection_state,false))
), ADD CONSTRAINT cooling_profile_wire_version CHECK (coalesce((profile->>'version')::integer=protocol_version,false));
CREATE INDEX prometheus_cooling_upload_continuous_idx ON public.prometheus_cooling_upload_profiles
 (cluster_id,source_id,collector_id,profile_id,revision DESC) WHERE protocol_version=3;

CREATE OR REPLACE FUNCTION public.prometheus_cooling_upload_receipt_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'cooling upload receipt is immutable' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN
        IF EXISTS (SELECT 1 FROM public.collection_runs WHERE run_id = OLD.run_id) THEN
            RAISE EXCEPTION 'cooling upload receipt is retained with its run' USING ERRCODE = '23514';
        END IF;
        RETURN OLD;
    END IF;

    NEW.received_at := clock_timestamp();
    IF NOT EXISTS (
        SELECT 1 FROM public.collection_runs r
        JOIN public.prometheus_cooling_upload_profiles p
          ON p.profile_id = NEW.profile_id AND p.revision = NEW.profile_revision
         AND p.profile_hash = NEW.profile_hash AND p.collector_id = NEW.collector_id
         AND p.cluster_id = r.cluster_id AND p.source_id = r.source_id
        JOIN public.collectors c ON c.collector_id = p.collector_id AND c.cluster_id = p.cluster_id
        WHERE r.run_id = NEW.run_id AND r.run_id ~ '^prometheus-cooling-v2-[0-9a-f]{64}$'
          AND r.idempotency_key = 'prometheus-cooling-report-v2-' || NEW.payload_hash
          AND r.query_kind IN ('dcgm_gpu_temperature', 'dcgm_gpu_power') AND r.job_id IS NULL
          AND r.scheduled_for >= p.starts_at AND (p.ends_at IS NULL OR r.scheduled_for < p.ends_at)
          AND p.collection_state IN ('WINDOW','ENABLED')
          AND p.registered_at < r.scheduled_for AND p.revoked_at IS NULL AND c.status = 'ACTIVE'
          AND r.scheduled_for <= NEW.received_at AND r.scheduled_for >= NEW.received_at - interval '15 minutes'
    ) THEN
        RAISE EXCEPTION 'cooling upload receipt lacks eligible run and profile authority' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;

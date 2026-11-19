-- Roll back only before V3 authority is enrolled. Retained receipts must never
-- be deleted or reinterpreted to make a downgrade succeed.
LOCK TABLE public.prometheus_cooling_upload_profiles,
           public.prometheus_cooling_upload_receipts IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.prometheus_cooling_upload_profiles WHERE protocol_version=3) THEN
  RAISE EXCEPTION 'continuous cooling authority exists; downgrade requires retention-aware export';
 END IF;
END $$;
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
          AND r.scheduled_for >= p.starts_at AND r.scheduled_for < p.ends_at
          AND p.registered_at < r.scheduled_for AND p.revoked_at IS NULL AND c.status = 'ACTIVE'
          AND r.scheduled_for <= NEW.received_at AND r.scheduled_for >= NEW.received_at - interval '15 minutes'
    ) THEN
        RAISE EXCEPTION 'cooling upload receipt lacks eligible run and profile authority' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;


DROP INDEX public.prometheus_cooling_upload_continuous_idx;
ALTER TABLE public.prometheus_cooling_upload_profiles
 DROP CONSTRAINT cooling_profile_versioned_lifecycle, DROP CONSTRAINT cooling_profile_wire_version,
 DROP COLUMN protocol_version, DROP COLUMN collection_state, ALTER COLUMN ends_at SET NOT NULL,
 ADD CHECK (ends_at>starts_at AND ends_at<=starts_at+interval '24 hours'),
 ADD CHECK (registered_at<ends_at-interval '15 seconds');

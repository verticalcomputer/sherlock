CREATE TABLE public.prometheus_cooling_upload_profiles (
    profile_id text NOT NULL CHECK (octet_length(profile_id) BETWEEN 1 AND 128),
    revision bigint NOT NULL CHECK (revision > 0),
    profile_hash text NOT NULL CHECK (profile_hash ~ '^[0-9a-f]{64}$'),
    cluster_id text NOT NULL,
    source_id text NOT NULL,
    collector_id text NOT NULL REFERENCES public.collectors(collector_id),
    inventory_revision text NOT NULL REFERENCES public.goodput_inventory_revisions(revision_id),
    profile jsonb NOT NULL CHECK (jsonb_typeof(profile) = 'object' AND octet_length(profile::text) <= 8192),
    registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NOT NULL,
    revoked_at timestamptz,
    PRIMARY KEY (profile_id, revision),
    UNIQUE (profile_id, revision, profile_hash, collector_id),
    FOREIGN KEY (cluster_id, source_id) REFERENCES public.sources(cluster_id, source_id),
    CHECK (ends_at > starts_at AND ends_at <= starts_at + interval '24 hours'),
    CHECK (registered_at < ends_at - interval '15 seconds'),
    CHECK (revoked_at IS NULL OR revoked_at >= registered_at)
);

CREATE INDEX prometheus_cooling_upload_active_profiles_idx
    ON public.prometheus_cooling_upload_profiles (cluster_id, source_id, collector_id, starts_at, ends_at)
    WHERE revoked_at IS NULL;

CREATE TABLE public.prometheus_cooling_upload_receipts (
    run_id text PRIMARY KEY REFERENCES public.collection_runs(run_id) ON DELETE CASCADE,
    profile_id text NOT NULL,
    profile_revision bigint NOT NULL,
    profile_hash text NOT NULL,
    collector_id text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    payload_hash text NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
    FOREIGN KEY (profile_id, profile_revision, profile_hash, collector_id)
        REFERENCES public.prometheus_cooling_upload_profiles(profile_id, revision, profile_hash, collector_id)
);

CREATE INDEX prometheus_cooling_upload_receipts_profile_time_idx
    ON public.prometheus_cooling_upload_receipts (profile_id, profile_revision, received_at, run_id);

CREATE FUNCTION public.prometheus_cooling_upload_profile_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.registered_at := clock_timestamp();
        IF NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'new cooling upload profile cannot be revoked' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'cooling upload profile is immutable' USING ERRCODE = '23514';
    END IF;

    IF (to_jsonb(NEW) - 'revoked_at') IS DISTINCT FROM (to_jsonb(OLD) - 'revoked_at') OR
       (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
        RAISE EXCEPTION 'cooling upload profile is immutable' USING ERRCODE = '23514';
    END IF;
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
        -- Serialize revocation against the application transaction admitting a receipt.
        PERFORM pg_advisory_xact_lock(hashtextextended('prometheus-cooling-profile:' || OLD.profile_id || ':' || OLD.revision, 0));
        NEW.revoked_at := greatest(clock_timestamp(), OLD.registered_at);
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER prometheus_cooling_upload_profile_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.prometheus_cooling_upload_profiles
    FOR EACH ROW EXECUTE FUNCTION public.prometheus_cooling_upload_profile_guard();

CREATE FUNCTION public.prometheus_cooling_upload_receipt_guard() RETURNS trigger
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

CREATE TRIGGER prometheus_cooling_upload_receipt_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.prometheus_cooling_upload_receipts
    FOR EACH ROW EXECUTE FUNCTION public.prometheus_cooling_upload_receipt_guard();

REVOKE ALL ON FUNCTION public.prometheus_cooling_upload_profile_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.prometheus_cooling_upload_receipt_guard() FROM PUBLIC;

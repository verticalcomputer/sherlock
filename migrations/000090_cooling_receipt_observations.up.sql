-- Bound the wait for the brief catalog locks on active ingest tables.
SET LOCAL lock_timeout = '1s';
-- Uploads read receipts before writing observations, then insert a receipt.
-- Take both DDL locks without waiting so an active upload can always finish.
LOCK TABLE public.observations IN SHARE ROW EXCLUSIVE MODE NOWAIT;
LOCK TABLE public.prometheus_cooling_upload_receipts IN ACCESS EXCLUSIVE MODE NOWAIT;

-- A fixed snapshot must see this installation's row to certify a receipt.
-- A rollback and reinstall creates a new row even at the same schema version.
CREATE TABLE public.prometheus_cooling_lookup_epoch (
    installed boolean PRIMARY KEY CHECK (installed)
);
INSERT INTO public.prometheus_cooling_lookup_epoch VALUES (true);

-- A constant default keeps existing receipts unproven without rewriting them.
ALTER TABLE public.prometheus_cooling_upload_receipts
    ADD COLUMN observation_lookup_complete boolean NOT NULL DEFAULT false;

CREATE TABLE public.prometheus_cooling_receipt_observations (
    run_id text NOT NULL,
    entity_key text NOT NULL,
    observation_id text NOT NULL REFERENCES public.observations(observation_id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    PRIMARY KEY (run_id, entity_key, observation_id)
);
-- Retention and observation ID changes must not scan even the smaller lookup.
CREATE INDEX prometheus_cooling_receipt_observations_id_idx
    ON public.prometheus_cooling_receipt_observations (observation_id);

-- Keep identity changes and alternate IDs visible, including writes concurrent
-- with receipt creation. Namespace membership alone never authorizes a read.
CREATE FUNCTION public.cooling_observation_locator() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        -- The FK may already have cascaded an accompanying observation ID edit.
        DELETE FROM public.prometheus_cooling_receipt_observations
        WHERE run_id = OLD.run_id AND entity_key = OLD.entity_key
          AND observation_id IN (OLD.observation_id, NEW.observation_id);
    END IF;
    IF starts_with(NEW.run_id, 'prometheus-cooling-v2-') THEN
        INSERT INTO public.prometheus_cooling_receipt_observations
            (run_id, entity_key, observation_id)
        VALUES (NEW.run_id, NEW.entity_key, NEW.observation_id)
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION public.cooling_observation_locator() FROM PUBLIC;

CREATE TRIGGER cooling_observation_locator_insert
    AFTER INSERT ON public.observations FOR EACH ROW
    WHEN (starts_with(NEW.run_id, 'prometheus-cooling-v2-'))
    EXECUTE FUNCTION public.cooling_observation_locator();

CREATE TRIGGER cooling_observation_locator_update
    AFTER UPDATE OF run_id, entity_key, observation_id ON public.observations FOR EACH ROW
    WHEN ((starts_with(OLD.run_id, 'prometheus-cooling-v2-') OR starts_with(NEW.run_id, 'prometheus-cooling-v2-'))
          AND (OLD.run_id, OLD.entity_key, OLD.observation_id) IS DISTINCT FROM
              (NEW.run_id, NEW.entity_key, NEW.observation_id))
    EXECUTE FUNCTION public.cooling_observation_locator();

-- Only the receipt trigger certifies completeness. Include all actual rows,
-- even nonstandard IDs or repeated entities. The existing unique index on
-- (run_id, sample_fingerprint) bounds discovery to this one admitted run.
-- Valid reports have at most 128 observations. Capture every actual row even
-- when an exceptional stored run has more, so one entity cannot hide another.
CREATE FUNCTION public.cooling_receipt_observation_proof() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
SET enable_seqscan = off AS $$
BEGIN
    -- A fixed snapshot can predate trigger installation and miss a raw
    -- observation committed before cutover. At READ COMMITTED the volatile
    -- trigger's query takes a fresh snapshot after acquiring the receipt lock.
    IF current_setting('transaction_isolation') IN ('repeatable read', 'serializable')
       AND NOT EXISTS (SELECT 1 FROM public.prometheus_cooling_lookup_epoch WHERE installed) THEN
        NEW.observation_lookup_complete := false;
        RETURN NEW;
    END IF;
    INSERT INTO public.prometheus_cooling_receipt_observations
        (run_id, entity_key, observation_id)
    SELECT run_id, entity_key, observation_id FROM public.observations
    WHERE run_id = NEW.run_id ORDER BY sample_fingerprint FOR SHARE
    ON CONFLICT DO NOTHING;
    NEW.observation_lookup_complete := true;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION public.cooling_receipt_observation_proof() FROM PUBLIC;
-- Alphabetical order runs the existing immutable receipt admission guard first.
CREATE TRIGGER prometheus_cooling_upload_receipt_observation_proof
    BEFORE INSERT ON public.prometheus_cooling_upload_receipts FOR EACH ROW
    EXECUTE FUNCTION public.cooling_receipt_observation_proof();

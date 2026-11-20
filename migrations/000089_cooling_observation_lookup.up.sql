-- On an existing heap, prebuild concurrently as described in
-- docs/ALERT_ASSESSMENT_OPERATOR.md before running the transactional migrator.
DO $migration$
DECLARE
    idx regclass := to_regclass('public.observations_cooling_run_entity_idx');
BEGIN
    IF idx IS NULL THEN
        IF pg_relation_size('public.observations') = 0 THEN
            LOCK TABLE public.observations IN SHARE MODE NOWAIT;
            IF pg_relation_size('public.observations') = 0 THEN
                CREATE INDEX observations_cooling_run_entity_idx
                    ON public.observations (run_id, entity_key)
                    WHERE starts_with(run_id, 'prometheus-cooling-v2-');
                RETURN;
            END IF;
        END IF;
        RAISE EXCEPTION 'prebuild observations_cooling_run_entity_idx concurrently before applying migration 000089';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_index
        WHERE indexrelid = idx AND indisvalid AND indisready AND indislive
          AND pg_get_indexdef(indexrelid) =
            'CREATE INDEX observations_cooling_run_entity_idx ON public.observations USING btree (run_id, entity_key) WHERE starts_with(run_id, ''prometheus-cooling-v2-''::text)'
    ) THEN
        RAISE EXCEPTION 'observations_cooling_run_entity_idx is invalid or has an unexpected definition; inspect before retrying migration 000089';
    END IF;
END
$migration$;

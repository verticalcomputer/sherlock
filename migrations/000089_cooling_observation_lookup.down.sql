-- Populated installations drop the index concurrently before this check.
DO $migration$
BEGIN
    IF to_regclass('public.observations_cooling_run_entity_idx') IS NULL THEN
        RETURN;
    END IF;
    IF pg_relation_size('public.observations') = 0 THEN
        LOCK TABLE public.observations IN ACCESS EXCLUSIVE MODE NOWAIT;
        IF pg_relation_size('public.observations') = 0 THEN
            IF NOT EXISTS (
                SELECT 1 FROM pg_index
                WHERE indexrelid = to_regclass('public.observations_cooling_run_entity_idx')
                  AND pg_get_indexdef(indexrelid) =
                    'CREATE INDEX observations_cooling_run_entity_idx ON public.observations USING btree (run_id, entity_key) WHERE starts_with(run_id, ''prometheus-cooling-v2-''::text)'
            ) THEN
                RAISE EXCEPTION 'unexpected observations_cooling_run_entity_idx definition; inspect before reverting migration 000089';
            END IF;
            DROP INDEX public.observations_cooling_run_entity_idx;
            RETURN;
        END IF;
    END IF;
    RAISE EXCEPTION 'drop observations_cooling_run_entity_idx concurrently before reverting migration 000089';
END
$migration$;

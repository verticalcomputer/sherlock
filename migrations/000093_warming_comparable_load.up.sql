SET LOCAL lock_timeout = '1s';
-- Earlier pending reviews retain the original reference and worker semantics.
ALTER TABLE production_assessment_decisions
    ADD COLUMN warming_known_at timestamptz,
    ADD COLUMN warming_comparable boolean NOT NULL DEFAULT false,
    ADD COLUMN warming_urgent_event text,
    ADD COLUMN warming_gate jsonb,
    ADD COLUMN warming_profile jsonb,
    ADD COLUMN warming_calls jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD CONSTRAINT warming_calls_is_bounded CHECK (
        jsonb_typeof(warming_calls) = 'array' AND jsonb_array_length(warming_calls) <= 16
    );

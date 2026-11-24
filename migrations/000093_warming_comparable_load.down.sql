SET LOCAL lock_timeout = '1s';
LOCK TABLE production_assessment_decisions IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
    IF EXISTS (SELECT FROM production_assessment_decisions WHERE warming_comparable AND closed_at IS NULL) THEN
        RAISE EXCEPTION 'resolve open comparable-load reviews before downgrading';
    END IF;
END $$;
ALTER TABLE production_assessment_decisions
    DROP COLUMN warming_calls, DROP COLUMN warming_gate, DROP COLUMN warming_profile,
    DROP COLUMN warming_known_at, DROP COLUMN warming_urgent_event, DROP COLUMN warming_comparable;

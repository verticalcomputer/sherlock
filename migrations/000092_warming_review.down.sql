SET LOCAL lock_timeout = '1s';
LOCK TABLE production_assessment_enrollments, production_assessment_decisions IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
    IF EXISTS (SELECT FROM production_assessment_enrollments WHERE azure_warming_triage)
       OR EXISTS (SELECT FROM production_assessment_decisions WHERE warming_revision IS NOT NULL AND warming_result IS DISTINCT FROM 'NOTIFY' AND closed_at IS NULL) THEN
        RAISE EXCEPTION 'disable warming triage and resolve held warming incidents before downgrade';
    END IF;
END;
$$;
ALTER TABLE production_notification_intents DROP COLUMN display_summary;
DROP INDEX production_warming_due;
ALTER TABLE production_assessment_decisions DROP COLUMN warming_result, DROP COLUMN warming_attempt,
    DROP COLUMN warming_last_endpoint, DROP COLUMN warming_next_at, DROP COLUMN warming_anchor,
    DROP COLUMN warming_reference_c, DROP COLUMN warming_reference_at, DROP COLUMN warming_revision;
ALTER TABLE production_assessment_enrollments DROP COLUMN azure_warming_triage;

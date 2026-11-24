SET LOCAL lock_timeout = '1s';
-- Enrollment opt-in and bounded work attached to already retained decisions.
ALTER TABLE production_assessment_enrollments
    ADD COLUMN warming_triage boolean NOT NULL DEFAULT false;
ALTER TABLE production_assessment_decisions
    ADD COLUMN warming_revision bigint,
    ADD COLUMN warming_reference_at timestamptz,
    ADD COLUMN warming_reference_c double precision,
    ADD COLUMN warming_anchor timestamptz,
    ADD COLUMN warming_next_at timestamptz,
    ADD COLUMN warming_last_endpoint timestamptz,
    ADD COLUMN warming_attempt bigint NOT NULL DEFAULT 0,
    ADD COLUMN warming_result text CHECK (warming_result IN ('WATCH','NOTIFY','ERROR','DISCARDED'));
CREATE INDEX production_warming_due ON production_assessment_decisions(enrollment_id,warming_next_at)
    WHERE warming_next_at IS NOT NULL AND closed_at IS NULL;
-- Keep the human-facing evidence when the scoped worker consolidates events.
ALTER TABLE production_notification_intents
    ADD COLUMN display_summary text CHECK (octet_length(display_summary) <= 2048);

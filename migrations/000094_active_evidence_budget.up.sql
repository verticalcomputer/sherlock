SET LOCAL lock_timeout = '1s';
-- Freeze writers during the counter handover. No proof or delivery row is rewritten.
LOCK TABLE production_assessment_enrollments, production_assessment_decisions IN SHARE ROW EXCLUSIVE MODE;
ALTER TABLE production_assessment_enrollments
    ADD COLUMN closed_events bigint NOT NULL DEFAULT 0 CHECK (closed_events >= 0),
    ADD COLUMN closed_bytes bigint NOT NULL DEFAULT 0 CHECK (closed_bytes >= 0);

WITH history AS (
    SELECT enrollment_id, count(*) AS events, sum(octet_length(evidence)) AS bytes
    FROM production_assessment_decisions WHERE closed_at IS NOT NULL GROUP BY enrollment_id
)
UPDATE production_assessment_enrollments e
SET closed_events = h.events, closed_bytes = h.bytes,
    retained_events = e.retained_events - h.events, retained_bytes = e.retained_bytes - h.bytes
FROM history h WHERE h.enrollment_id = e.enrollment_id;

-- Existing evaluator binaries read retained_* for admission. Keep the existing
-- hard limits on those columns and separately account for still-queryable history.
CREATE OR REPLACE FUNCTION production_assessment_retained_capacity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    active_delta integer := 0;
    closed_delta integer := 0;
    bytes integer;
    enrollment text;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF (NEW.closed_at IS NULL) = (OLD.closed_at IS NULL) THEN RETURN NULL; END IF;
    END IF;
    IF TG_OP <> 'INSERT' THEN
        IF OLD.closed_at IS NULL THEN active_delta := -1; ELSE closed_delta := -1; END IF;
        bytes := octet_length(OLD.evidence);
        enrollment := OLD.enrollment_id;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        IF NEW.closed_at IS NULL THEN active_delta := active_delta + 1; ELSE closed_delta := closed_delta + 1; END IF;
        bytes := octet_length(NEW.evidence);
        enrollment := NEW.enrollment_id;
    END IF;
    UPDATE production_assessment_enrollments
    SET retained_events = retained_events + active_delta, retained_bytes = retained_bytes + active_delta * bytes,
        closed_events = closed_events + closed_delta, closed_bytes = closed_bytes + closed_delta * bytes
    WHERE enrollment_id = enrollment;
    RETURN NULL;
END $$;

CREATE TRIGGER production_assessment_closed_capacity AFTER UPDATE OF closed_at ON production_assessment_decisions
FOR EACH ROW EXECUTE FUNCTION production_assessment_retained_capacity();

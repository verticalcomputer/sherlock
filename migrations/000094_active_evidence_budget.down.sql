SET LOCAL lock_timeout = '1s';
LOCK TABLE production_assessment_enrollments, production_assessment_decisions IN SHARE ROW EXCLUSIVE MODE;
-- The original CHECK constraints reject a downgrade when retained history
-- exceeds the old hard limits. The transaction then leaves all proofs intact.
UPDATE production_assessment_enrollments SET retained_events = retained_events + closed_events,
    retained_bytes = retained_bytes + closed_bytes;
DROP TRIGGER production_assessment_closed_capacity ON production_assessment_decisions;
ALTER TABLE production_assessment_enrollments DROP COLUMN closed_events, DROP COLUMN closed_bytes;

CREATE OR REPLACE FUNCTION production_assessment_retained_capacity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  UPDATE production_assessment_enrollments SET retained_events=retained_events+1,retained_bytes=retained_bytes+octet_length(NEW.evidence) WHERE enrollment_id=NEW.enrollment_id;
  RETURN NEW;
 ELSE
  UPDATE production_assessment_enrollments SET retained_events=retained_events-1,retained_bytes=retained_bytes-octet_length(OLD.evidence) WHERE enrollment_id=OLD.enrollment_id;
  RETURN OLD;
 END IF;
END $$;

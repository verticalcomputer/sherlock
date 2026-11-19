DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM production_assessment_enrollments) THEN
  RAISE EXCEPTION 'cannot downgrade retained production assessment authority or evidence';
 END IF;
END $$;
DROP TABLE production_assessment_controls;
DROP TABLE production_assessment_decisions;
DROP FUNCTION production_assessment_retained_capacity();
DROP TABLE production_assessment_states;
DROP TABLE production_assessment_enrollments;

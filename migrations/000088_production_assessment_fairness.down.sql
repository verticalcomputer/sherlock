-- Preserve restart fairness while an expanded production enrollment is retained.
-- Deployment tools run this in a transaction; locks close the admission race.
LOCK TABLE production_assessment_enrollments,production_assessment_states IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM production_assessment_enrollments
  WHERE coalesce((config#>>'{limits,gpu_count}')::bigint,0)>8
     OR coalesce((config#>>'{limits,node_count}')::bigint,0)>2
     OR jsonb_array_length(coalesce(config->'assets','[]'::jsonb))>8)
 OR EXISTS(SELECT 1 FROM production_assessment_states GROUP BY enrollment_id HAVING count(*)>8) THEN
  RAISE EXCEPTION 'retained fleet enrollment requires production fairness columns';
 END IF;
END $$;
ALTER TABLE production_assessment_states
 DROP COLUMN last_due_attempt_at,
 DROP COLUMN last_acquire_attempt_at;

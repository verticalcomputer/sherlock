-- Finish durable replay batches with the newer evaluator before downgrading.
LOCK TABLE production_assessment_states IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
 IF EXISTS (SELECT FROM production_assessment_states WHERE replay_pending) THEN
  RAISE EXCEPTION 'unfinished production assessment replay batches';
 END IF;
END;
$$;
ALTER TABLE production_assessment_states DROP COLUMN replay_pending, DROP COLUMN last_input_at, DROP COLUMN last_input_gap;

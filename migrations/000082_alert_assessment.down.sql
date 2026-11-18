LOCK TABLE assessment_runs,assessment_enrollments,assessment_facts,assessment_bundles,assessment_candidates,assessment_decisions,assessment_failures IN ACCESS EXCLUSIVE MODE;
DO $$DECLARE t text; nonempty boolean; BEGIN
 FOREACH t IN ARRAY ARRAY['runs','enrollments','facts','bundles','candidates','decisions','failures'] LOOP
  EXECUTE format('SELECT EXISTS(SELECT 1 FROM assessment_%I)',t) INTO nonempty;
  IF nonempty THEN RAISE EXCEPTION 'assessment down migration refuses retained experiment data';END IF;
 END LOOP;
END$$;
DROP VIEW assessment_edges;
DROP TABLE assessment_failures,assessment_decisions,assessment_candidates,assessment_bundles,assessment_facts,assessment_enrollments,assessment_runs;
DROP FUNCTION assessment_account();
DROP FUNCTION assessment_account_fact_insert();
DROP FUNCTION assessment_sample_source(bytea);
DROP FUNCTION assessment_row_bytes(text,jsonb);
DROP FUNCTION assessment_references();
DROP FUNCTION assessment_guard();
DROP FUNCTION assessment_sorted_set(text[],integer);

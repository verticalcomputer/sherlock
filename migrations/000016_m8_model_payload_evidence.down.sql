DROP INDEX IF EXISTS investigation_model_calls_output_evidence_idx;
DROP INDEX IF EXISTS investigation_model_calls_input_evidence_idx;

ALTER TABLE investigation_model_calls
    DROP CONSTRAINT IF EXISTS investigation_model_calls_payload_evidence_check,
    DROP CONSTRAINT IF EXISTS investigation_model_calls_output_evidence_fk,
    DROP CONSTRAINT IF EXISTS investigation_model_calls_input_evidence_fk,
    DROP COLUMN IF EXISTS output_evidence_id,
    DROP COLUMN IF EXISTS input_evidence_id;

DELETE FROM evidence_envelopes
WHERE operation IN (
    'model_planning_input', 'model_planning_output',
    'model_synthesis_input', 'model_synthesis_output'
);
DELETE FROM sources WHERE kind = 'model';

ALTER TABLE evidence_envelopes
    DROP CONSTRAINT IF EXISTS evidence_envelopes_cluster_evidence_unique;

ALTER TABLE sources DROP CONSTRAINT sources_kind_check;
ALTER TABLE sources ADD CONSTRAINT sources_kind_check
    CHECK (kind = 'prometheus');

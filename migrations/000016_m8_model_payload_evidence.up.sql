ALTER TABLE sources DROP CONSTRAINT sources_kind_check;
ALTER TABLE sources ADD CONSTRAINT sources_kind_check
    CHECK (kind IN ('prometheus', 'model'));

ALTER TABLE evidence_envelopes
    ADD CONSTRAINT evidence_envelopes_cluster_evidence_unique
    UNIQUE (cluster_id, evidence_id);

ALTER TABLE investigation_model_calls
    ADD COLUMN input_evidence_id text,
    ADD COLUMN output_evidence_id text,
    ADD CONSTRAINT investigation_model_calls_input_evidence_fk
        FOREIGN KEY (cluster_id, input_evidence_id)
        REFERENCES evidence_envelopes(cluster_id, evidence_id) ON DELETE RESTRICT,
    ADD CONSTRAINT investigation_model_calls_output_evidence_fk
        FOREIGN KEY (cluster_id, output_evidence_id)
        REFERENCES evidence_envelopes(cluster_id, evidence_id) ON DELETE RESTRICT,
    ADD CONSTRAINT investigation_model_calls_payload_evidence_check
        CHECK (output_evidence_id IS NULL OR input_evidence_id IS NOT NULL);

CREATE INDEX investigation_model_calls_input_evidence_idx
    ON investigation_model_calls (input_evidence_id)
    WHERE input_evidence_id IS NOT NULL;

CREATE INDEX investigation_model_calls_output_evidence_idx
    ON investigation_model_calls (output_evidence_id)
    WHERE output_evidence_id IS NOT NULL;

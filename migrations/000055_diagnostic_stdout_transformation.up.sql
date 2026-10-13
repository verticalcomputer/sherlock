-- Existing results have no producer attestation. Keep them UNKNOWN.
ALTER TABLE diagnostic_target_results
    ADD COLUMN stdout_transformation_state text NOT NULL DEFAULT 'UNKNOWN'
    CONSTRAINT diagnostic_target_stdout_transformation_state_check
    CHECK (stdout_transformation_state IN ('UNKNOWN', 'UNMODIFIED', 'TRANSFORMED'));

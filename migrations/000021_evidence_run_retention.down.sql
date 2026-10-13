ALTER TABLE evidence_envelopes
    DROP CONSTRAINT evidence_envelopes_run_id_fkey;

ALTER TABLE evidence_envelopes
    ADD CONSTRAINT evidence_envelopes_run_id_fkey
    FOREIGN KEY (run_id) REFERENCES collection_runs(run_id);

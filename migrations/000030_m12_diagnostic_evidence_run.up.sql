-- evidence_envelopes.run_id references collection_runs: it means "the collection
-- run that produced this evidence". A diagnostic has no collection run, so the
-- M12 projection put a diagnostic run id in that column and every commit failed
-- on the foreign key. Together with the missing source row, this meant a
-- completed diagnostic could never become evidence at all.
--
-- The provenance is real and worth keeping, so it gets its own column against
-- the right table, mirroring investigation_actions.diagnostic_run_id.
ALTER TABLE evidence_envelopes
    ADD COLUMN diagnostic_run_id text REFERENCES diagnostic_runs(run_id) ON DELETE RESTRICT;

-- Evidence comes from a collection run or a diagnostic run, never both.
ALTER TABLE evidence_envelopes
    ADD CONSTRAINT evidence_envelopes_single_run_check
    CHECK (run_id IS NULL OR diagnostic_run_id IS NULL);

CREATE INDEX evidence_envelopes_diagnostic_run_idx
    ON evidence_envelopes (cluster_id, diagnostic_run_id)
    WHERE diagnostic_run_id IS NOT NULL;

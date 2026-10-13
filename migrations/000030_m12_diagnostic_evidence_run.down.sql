DROP INDEX IF EXISTS evidence_envelopes_diagnostic_run_idx;
ALTER TABLE evidence_envelopes DROP CONSTRAINT IF EXISTS evidence_envelopes_single_run_check;
ALTER TABLE evidence_envelopes DROP COLUMN IF EXISTS diagnostic_run_id;

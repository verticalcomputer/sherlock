DROP INDEX IF EXISTS evidence_artifact_check_idx;
ALTER TABLE evidence_envelopes DROP COLUMN IF EXISTS artifact_checked_at;

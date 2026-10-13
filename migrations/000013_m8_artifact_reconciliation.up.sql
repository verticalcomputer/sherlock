-- Rotating verification cursor for bounded artifact reconciliation. This is
-- mutable operational metadata; immutable evidence provenance remains intact.
-- The repository migration runner wraps each migration in a transaction, so
-- this index cannot use CREATE INDEX CONCURRENTLY. Apply 000013 in a scheduled
-- maintenance window with evidence writers stopped; CREATE INDEX can block
-- writes while it scans an existing evidence_envelopes table.
ALTER TABLE evidence_envelopes
    ADD COLUMN artifact_checked_at timestamptz;

CREATE INDEX evidence_artifact_check_idx
    ON evidence_envelopes (artifact_checked_at NULLS FIRST, created_at, evidence_id)
    WHERE artifact_id IS NOT NULL;

-- Findings were written with a hardcoded 'INFO', so an operator could not tell
-- a device needing an RMA from a routine observation. Deriving severity needs a
-- vocabulary, and there were two: domain.HealthSeverity (UNKNOWN/INFO/WARNING/
-- CRITICAL) for M3 signals, and this table's unrelated INFO/LOW/MEDIUM/HIGH/
-- CRITICAL. Two scales for one operational decision is the defect.
--
-- LOW, MEDIUM, and HIGH were never written to this table: every row ever
-- created is INFO. Retiring them costs nothing and leaves exactly one severity
-- vocabulary, shared with health signals, so a finding and a signal that mean
-- the same thing say the same word.
ALTER TABLE investigation_findings DROP CONSTRAINT IF EXISTS investigation_findings_severity_check;
ALTER TABLE investigation_findings
    ADD CONSTRAINT investigation_findings_severity_check
    CHECK (severity IN ('UNKNOWN', 'INFO', 'WARNING', 'CRITICAL'));

-- WARNING has no counterpart in the retired scale; map it to the nearest
-- actionable level rather than losing the distinction silently.
UPDATE investigation_findings SET severity='HIGH' WHERE severity='WARNING';
UPDATE investigation_findings SET severity='INFO' WHERE severity='UNKNOWN';
ALTER TABLE investigation_findings DROP CONSTRAINT IF EXISTS investigation_findings_severity_check;
ALTER TABLE investigation_findings
    ADD CONSTRAINT investigation_findings_severity_check
    CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'));

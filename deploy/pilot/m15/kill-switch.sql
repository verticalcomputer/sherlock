-- Requires the separately authorized policy-admin identity, never runtime grants.
BEGIN;
SET LOCAL lock_timeout='1500ms';
SET LOCAL statement_timeout='3s';
LOCK TABLE remediation_global_state IN SHARE ROW EXCLUSIVE MODE;
UPDATE remediation_global_state SET remediation_enabled=false,observed_at=clock_timestamp() WHERE id;
COMMIT;

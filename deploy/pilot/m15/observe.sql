-- Read-only rehearsal. The caller supplies a reviewed cluster_id psql variable.
BEGIN READ ONLY;
SET LOCAL statement_timeout='3s';
SELECT state,count(*) FROM remediation_runs WHERE cluster_id=:'cluster_id' GROUP BY state ORDER BY state;
SELECT status,count(*) FROM collection_repair_requests WHERE cluster_id=:'cluster_id' GROUP BY status ORDER BY status;
SELECT code,observed_at FROM schedule_repair_decisions WHERE cluster_id=:'cluster_id' ORDER BY observed_at DESC LIMIT 64;
COMMIT;

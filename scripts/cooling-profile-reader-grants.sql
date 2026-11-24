BEGIN;
SET LOCAL lock_timeout = '1s';
GRANT USAGE ON SCHEMA cooling_history TO sherlock_assessment_production;
GRANT SELECT (enrollment_id,cutoff,cluster_id,source_id,published_at)
 ON cooling_history.refresh TO sherlock_assessment_production;
GRANT SELECT (enrollment_id,cutoff,asset,power_w,median_c,p95_c,days,periods,samples,last_at)
 ON cooling_history.temperature_band TO sherlock_assessment_production;
GRANT SELECT (enrollment_id,cutoff,available_at)
 ON cooling_history.available_refresh TO sherlock_assessment_production;
COMMIT;

GRANT CONNECT,TEMPORARY ON DATABASE sherlock TO sherlock_baseline_writer;
GRANT USAGE ON SCHEMA public,cooling_history TO sherlock_baseline_writer;
GRANT SELECT (cluster_id,source_id,entity_key,observed_at,metric,value)
 ON public.observations TO sherlock_baseline_writer;
GRANT SELECT (cluster_id,source_id,enrollment_id) ON public.production_assessment_enrollments TO sherlock_baseline_writer;
GRANT SELECT (cluster_id,source_id,enrollment_id,asset,opened_at,closed_at)
 ON public.production_notification_occurrences TO sherlock_baseline_writer;
GRANT SELECT,INSERT ON cooling_history.refresh,cooling_history.gpu,cooling_history.temperature_band TO sherlock_baseline_writer;
GRANT SELECT,INSERT (enrollment_id,cutoff) ON cooling_history.available_refresh TO sherlock_baseline_writer;

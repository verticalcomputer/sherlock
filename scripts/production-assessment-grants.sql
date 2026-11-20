-- Apply only to an explicitly authorized database after migration 90.
-- A NOLOGIN group separates production assessment from restricted shadow and
-- workload control credentials. Login/password/CONNECT provisioning is external.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='sherlock_assessment_production') THEN
  CREATE ROLE sherlock_assessment_production NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
 END IF;
END $$;
GRANT USAGE ON SCHEMA public TO sherlock_assessment_production;
GRANT SELECT,INSERT,UPDATE,DELETE ON
 public.production_assessment_enrollments,public.production_assessment_states,
 public.production_assessment_decisions,public.production_assessment_controls,
 public.production_notification_occurrences,public.production_notification_events,
 public.production_notification_intents,public.production_notification_coverage,
 public.production_notification_audit,
 public.gp09_alert_outbox,public.gp09_alert_delivery_attempts,
 public.incidents,public.incident_events,public.incident_evidence,public.evidence_envelopes
 TO sherlock_assessment_production;
GRANT USAGE,SELECT ON SEQUENCE public.production_notification_audit_audit_id_seq TO sherlock_assessment_production;
GRANT SELECT ON public.clusters,public.sources,
 public.prometheus_cooling_upload_profiles,public.prometheus_cooling_upload_receipts,
 public.prometheus_cooling_receipt_observations,public.collection_runs,public.observations,
 public.goodput_inventory_revisions,public.goodput_inventory_revision_entities,
 public.gp09_monitor_enrollments,public.gp09_monitor_episodes,public.gp09_monitor_transitions
 TO sherlock_assessment_production;
-- Never grant membership in the shadow writer, collector/upload writer, control,
-- investigation or remediation roles. Startup checks effective/reachable role
-- capabilities; this file intentionally does not rewrite other roles or PUBLIC.

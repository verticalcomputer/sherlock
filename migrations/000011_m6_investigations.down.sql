-- M6 stream records must be removed before restoring the M4 event-type check.
DELETE FROM cluster_events
WHERE event_type IN ('incident.updated', 'investigation.updated');

ALTER TABLE cluster_events DROP CONSTRAINT cluster_events_event_type_check;
ALTER TABLE cluster_events ADD CONSTRAINT cluster_events_event_type_check CHECK (event_type IN (
    'collection.updated', 'source.updated'
));

DROP INDEX IF EXISTS investigation_idempotency_in_progress_idx;
DROP TABLE IF EXISTS investigation_idempotency_records;
DROP TABLE IF EXISTS investigation_finding_citations;
DROP INDEX IF EXISTS investigation_findings_current_idx;
DROP TABLE IF EXISTS investigation_findings;
DROP TABLE IF EXISTS investigation_hypothesis_evidence;
DROP TABLE IF EXISTS investigation_hypotheses;
DROP INDEX IF EXISTS investigation_evidence_time_idx;
DROP TABLE IF EXISTS investigation_evidence;
DROP INDEX IF EXISTS investigation_approvals_pending_idx;
DROP TABLE IF EXISTS investigation_approvals;
DROP INDEX IF EXISTS investigation_actions_expired_lease_idx;
DROP INDEX IF EXISTS investigation_actions_available_idx;
DROP TABLE IF EXISTS investigation_actions;
DROP INDEX IF EXISTS investigation_steps_expired_lease_idx;
DROP INDEX IF EXISTS investigation_steps_available_idx;
DROP TABLE IF EXISTS investigation_steps;
DROP TABLE IF EXISTS investigation_budget_reservations;
DROP TABLE IF EXISTS investigation_budgets;
DROP INDEX IF EXISTS investigation_events_cluster_time_idx;
DROP TABLE IF EXISTS investigation_events;
DROP INDEX IF EXISTS investigations_incident_idx;
DROP INDEX IF EXISTS investigations_cluster_status_time_idx;
DROP TABLE IF EXISTS investigations;
DROP INDEX IF EXISTS incident_events_cluster_time_idx;
DROP TABLE IF EXISTS incident_events;
DROP INDEX IF EXISTS incidents_cluster_status_time_idx;
DROP TABLE IF EXISTS incidents;

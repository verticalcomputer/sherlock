-- Migration 000015 originally required successful events to omit a reason
-- code. The dashboard now records bounded reason codes for both outcomes so an
-- operator can distinguish successful bootstrap, session, and view events.
ALTER TABLE admin_dashboard_audit_events
    DROP CONSTRAINT IF EXISTS admin_dashboard_audit_events_check;

ALTER TABLE admin_dashboard_audit_events
    DROP CONSTRAINT admin_dashboard_audit_events_event_kind_check;

ALTER TABLE admin_dashboard_audit_events
    ADD CONSTRAINT admin_dashboard_audit_events_event_kind_check
    CHECK (event_kind IN (
        'AUTHENTICATION', 'SESSION_STARTED', 'SESSION_ENDED', 'SESSION_EXPIRED',
        'DASHBOARD_VIEWED'
    )) NOT VALID;

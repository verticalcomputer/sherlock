-- NOT VALID avoids rewriting historical rows that legitimately contain
-- successful reason codes while restoring the previous rule for new writes.
ALTER TABLE admin_dashboard_audit_events
    ADD CONSTRAINT admin_dashboard_audit_events_check
    CHECK ((outcome = 'SUCCEEDED') = (reason_code = '')) NOT VALID;

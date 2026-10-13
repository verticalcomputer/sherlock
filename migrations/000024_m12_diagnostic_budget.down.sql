ALTER TABLE investigations
    DROP CONSTRAINT investigations_status_check,
    ADD CONSTRAINT investigations_status_check CHECK (status IN (
        'INITIALIZING', 'PLANNING', 'POLICY_CHECK', 'AWAITING_APPROVAL', 'EXECUTING',
        'RECORDING_EVIDENCE', 'UPDATING_LEDGER', 'SYNTHESIZING',
        'COMPLETED', 'PARTIAL', 'BLOCKED', 'CANCELLED'
    ));

DROP INDEX IF EXISTS investigation_actions_investigation_diagnostic_recency_idx;
DROP INDEX IF EXISTS investigation_actions_diagnostic_recency_idx;

ALTER TABLE investigation_actions
    DROP COLUMN operation;

ALTER TABLE investigation_budgets
    DROP CONSTRAINT investigation_budgets_diagnostic_calls_within_limit,
    DROP COLUMN used_diagnostic_calls,
    DROP COLUMN max_diagnostic_calls;

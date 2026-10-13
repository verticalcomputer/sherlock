-- M12: bound remote diagnostic execution separately from evidence reads.
-- Both columns default to zero, so every existing investigation keeps its
-- current authority: no run may execute a diagnostic without an explicit grant.
ALTER TABLE investigation_budgets
    ADD COLUMN max_diagnostic_calls integer NOT NULL DEFAULT 0 CHECK (max_diagnostic_calls BETWEEN 0 AND 1000),
    ADD COLUMN used_diagnostic_calls integer NOT NULL DEFAULT 0 CHECK (used_diagnostic_calls >= 0),
    ADD CONSTRAINT investigation_budgets_diagnostic_calls_within_limit
        CHECK (used_diagnostic_calls <= max_diagnostic_calls);

-- The operation class selects which budget dimension an action spends, so it
-- must survive an investigator restart: a privileged diagnostic reconstituted
-- as a read would be charged to the wrong grant on approval.
ALTER TABLE investigation_actions
    ADD COLUMN operation text NOT NULL DEFAULT 'READ_ONLY'
        CHECK (operation IN ('READ_ONLY', 'DIAGNOSTIC'));

-- The freshness novelty rule asks, per target, when a diagnostic definition
-- last succeeded. It runs on every planning turn that proposes a diagnostic,
-- so the successful-diagnostic rows are indexed directly.
CREATE INDEX investigation_actions_diagnostic_recency_idx
    ON investigation_actions (cluster_id, tool_id, completed_at DESC)
    WHERE operation = 'DIAGNOSTIC' AND status = 'SUCCEEDED';

CREATE INDEX investigation_actions_investigation_diagnostic_recency_idx
    ON investigation_actions (investigation_id, tool_id, completed_at DESC)
    WHERE operation = 'DIAGNOSTIC' AND status = 'SUCCEEDED';

-- AWAITING_EVIDENCE is a distinct state rather than parking in EXECUTING, so
-- the admin UI and the stop-reason taxonomy can say honestly why an
-- investigation is not advancing while a remote execution is outstanding.
ALTER TABLE investigations
    DROP CONSTRAINT investigations_status_check,
    ADD CONSTRAINT investigations_status_check CHECK (status IN (
        'INITIALIZING', 'PLANNING', 'POLICY_CHECK', 'AWAITING_APPROVAL', 'EXECUTING',
        'AWAITING_EVIDENCE', 'RECORDING_EVIDENCE', 'UPDATING_LEDGER', 'SYNTHESIZING',
        'COMPLETED', 'PARTIAL', 'BLOCKED', 'CANCELLED'
    ));

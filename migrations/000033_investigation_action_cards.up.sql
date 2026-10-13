-- Every terminal investigation publishes one primary operational handoff.
-- The investigation_id primary key makes the "one primary" rule structural;
-- recommendations beyond this card remain ordinary report findings.
CREATE TABLE investigation_action_cards (
    investigation_id text PRIMARY KEY,
    cluster_id text NOT NULL,
    action_card_id text NOT NULL UNIQUE,
    owner text NOT NULL CHECK (owner IN ('SHERLOCK', 'CLUSTER_OPERATIONS', 'DATACENTER_OPERATIONS', 'WORKLOAD_OWNER', 'MONITORING')),
    action text NOT NULL CHECK (length(action) BETWEEN 1 AND 4096),
    urgency text NOT NULL CHECK (urgency IN ('IMMEDIATE', 'NEXT_SHIFT', 'PLANNED', 'MONITOR')),
    targets text[] NOT NULL CHECK (cardinality(targets) > 0),
    rationale text NOT NULL CHECK (length(rationale) BETWEEN 1 AND 4096),
    blocking_gaps text[] NOT NULL DEFAULT ARRAY[]::text[],
    escalation_condition text NOT NULL CHECK (length(escalation_condition) BETWEEN 1 AND 4096),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (investigation_id, action_card_id),
    FOREIGN KEY (cluster_id, investigation_id)
        REFERENCES investigations(cluster_id, investigation_id) ON DELETE CASCADE
);

CREATE TABLE investigation_action_card_citations (
    cluster_id text NOT NULL,
    investigation_id text NOT NULL,
    action_card_id text NOT NULL,
    ledger_entry_id text NOT NULL,
    PRIMARY KEY (action_card_id, ledger_entry_id),
    FOREIGN KEY (investigation_id, action_card_id)
        REFERENCES investigation_action_cards(investigation_id, action_card_id) ON DELETE CASCADE,
    FOREIGN KEY (cluster_id, investigation_id, ledger_entry_id)
        REFERENCES investigation_evidence(cluster_id, investigation_id, ledger_entry_id) ON DELETE RESTRICT
);

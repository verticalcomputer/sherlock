-- Synthesis already produces a timeline, a statement of what remains unknown,
-- and a coverage statement, and the controller requires all three before an
-- investigation may complete. None of it was durable, so none of it reached a
-- report. These are not findings: a timeline entry is anchored to an instant
-- rather than to an entity, and an unknown is a claim about what the evidence
-- does not cover, which the finding entity-coverage rule would reject.
CREATE TABLE investigation_report_sections (
    section_id text PRIMARY KEY,
    cluster_id text NOT NULL,
    investigation_id text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('TIMELINE', 'UNKNOWN', 'COVERAGE')),
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    statement text NOT NULL CHECK (length(statement) BETWEEN 1 AND 4096),
    observed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (cluster_id, investigation_id, section_id),
    FOREIGN KEY (cluster_id, investigation_id)
        REFERENCES investigations(cluster_id, investigation_id) ON DELETE CASCADE,
    -- Only a timeline entry carries an instant, and it must carry one.
    CHECK ((kind = 'TIMELINE') = (observed_at IS NOT NULL))
);

CREATE INDEX investigation_report_sections_order_idx
    ON investigation_report_sections (cluster_id, investigation_id, kind, ordinal);

-- Citations are restricted the same way finding citations are: a section may
-- not outlive the ledger entry it cites.
CREATE TABLE investigation_report_section_citations (
    cluster_id text NOT NULL,
    investigation_id text NOT NULL,
    section_id text NOT NULL,
    ledger_entry_id text NOT NULL,
    PRIMARY KEY (section_id, ledger_entry_id),
    FOREIGN KEY (cluster_id, investigation_id, section_id)
        REFERENCES investigation_report_sections(cluster_id, investigation_id, section_id) ON DELETE CASCADE,
    FOREIGN KEY (cluster_id, investigation_id, ledger_entry_id)
        REFERENCES investigation_evidence(cluster_id, investigation_id, ledger_entry_id) ON DELETE RESTRICT
);

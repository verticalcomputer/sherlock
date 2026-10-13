ALTER TABLE investigation_evidence
    DROP CONSTRAINT investigation_evidence_pkey;

ALTER TABLE investigation_evidence
    ADD CONSTRAINT investigation_evidence_pkey
    PRIMARY KEY (investigation_id, ledger_entry_id);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM investigation_evidence
        GROUP BY ledger_entry_id
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION
            'cannot restore the global investigation_evidence primary key: ledger entries are reused across investigations';
    END IF;
END
$$;

ALTER TABLE investigation_evidence
    DROP CONSTRAINT investigation_evidence_pkey;

ALTER TABLE investigation_evidence
    ADD CONSTRAINT investigation_evidence_pkey
    PRIMARY KEY (ledger_entry_id);

DELETE FROM investigation_report_omissions
    WHERE reason IN ('CONTEXT_ITEM_LIMIT', 'CONTEXT_SIZE_LIMIT', 'PROVIDER_INPUT_ALLOWANCE');

ALTER TABLE investigation_report_omissions
    DROP CONSTRAINT investigation_report_omissions_reason_check;

ALTER TABLE investigation_report_omissions
    ADD CONSTRAINT investigation_report_omissions_reason_check
    CHECK (reason IN ('NO_SUPPORTED_ENTITY', 'CITATION_NOT_IN_LEDGER', 'VALIDATION_REFUSED'));

-- A report named only what the model answered and the domain then refused. What
-- the context builder dropped before the call -- evidence past the item limit,
-- evidence and hypotheses cut to the encoded ceiling, evidence trimmed to the
-- provider's input allowance -- was never recorded, so a report thinned by a
-- full context read as a complete answer over a quiet cluster.
--
-- Widen the reviewed reason set to admit those three. The constraint stays an
-- enumeration rather than becoming free text: an omission row is the report's
-- account of its own losses, and an unreviewed reason would misstate them.
ALTER TABLE investigation_report_omissions
    DROP CONSTRAINT investigation_report_omissions_reason_check;

ALTER TABLE investigation_report_omissions
    ADD CONSTRAINT investigation_report_omissions_reason_check
    CHECK (reason IN (
        'NO_SUPPORTED_ENTITY',
        'CITATION_NOT_IN_LEDGER',
        'VALIDATION_REFUSED',
        'CONTEXT_ITEM_LIMIT',
        'CONTEXT_SIZE_LIMIT',
        'PROVIDER_INPUT_ALLOWANCE'
    ));

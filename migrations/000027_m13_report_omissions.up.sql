-- Synthesis statements are refused when their citations support no claim about
-- any entity in the ledger, or cite evidence the ledger never held. Refusing
-- them is correct; leaving no trace was not, because a report could be quietly
-- thinner than the model's actual answer with nothing on the page to say so.
--
-- Only the kind and the reason are stored. The refused text is untrusted prose
-- that failed validation, and persisting it would recreate the exposure the
-- validation exists to prevent.
CREATE TABLE investigation_report_omissions (
    cluster_id text NOT NULL,
    investigation_id text NOT NULL,
    kind text NOT NULL,
    reason text NOT NULL CHECK (reason IN ('NO_SUPPORTED_ENTITY', 'CITATION_NOT_IN_LEDGER', 'VALIDATION_REFUSED')),
    omitted_count integer NOT NULL CHECK (omitted_count > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (investigation_id, kind, reason),
    FOREIGN KEY (cluster_id, investigation_id)
        REFERENCES investigations(cluster_id, investigation_id) ON DELETE CASCADE
);

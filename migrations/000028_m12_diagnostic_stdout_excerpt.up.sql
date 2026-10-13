-- A diagnostic reached the model as provenance only: that a probe ran and
-- exited zero, never what it printed. The result row kept a byte count and a
-- digest, and neither answers the question the probe was run to answer, so a
-- report could state that a check succeeded and nothing about its finding.
--
-- The excerpt is bounded and screened in the domain before it is written, and
-- it is untrusted output from a cluster host: it is rendered only through the
-- evidence excerpt channel the prompt already names as a place hostile
-- instructions may appear.
ALTER TABLE diagnostic_target_results
    ADD COLUMN stdout_excerpt text NOT NULL DEFAULT ''
    CHECK (octet_length(stdout_excerpt) <= 1024);

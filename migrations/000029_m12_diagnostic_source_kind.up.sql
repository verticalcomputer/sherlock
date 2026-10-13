-- A diagnostic projects into an ordinary evidence envelope whose source is the
-- reviewed definition's pack, not a polled system. That envelope could never be
-- committed: evidence_envelopes.source_id references sources, and no row could
-- exist because sources.kind admitted only 'prometheus' and 'model'. The first
-- completed diagnostic would have failed on the foreign key.
--
-- M8 met the same problem for model-payload evidence and solved it this way,
-- widening the vocabulary and creating the synthetic source lazily.
ALTER TABLE sources DROP CONSTRAINT sources_kind_check;
ALTER TABLE sources ADD CONSTRAINT sources_kind_check
    CHECK (kind IN ('prometheus', 'model', 'diagnostic'));

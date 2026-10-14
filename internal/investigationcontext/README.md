# Entity-fair context selection

Measured fleet acceptance evidence is private and is not included in this
repository. The behavior below describes the evidence-selection implementation,
not live fleet acceptance or contributor documentation retrieval.

Retrieval ranks eligible evidence deterministically: mandatory first, then
relevance score descending, then evidence ID ascending. It identifies the
highest-ranked item naming each scope entity as that entity's canonical anchor.
One shared item can anchor multiple entities. Cluster-only evidence has its own
allocation bucket and does not cover node or GPU scope entities. Mandatory
items are admitted first; distinct anchors follow in sorted entity order;
remaining candidates are allocated round-robin to the least represented
entity. Per-class and per-source caps apply per entity.

The ranker uses the query already assembled from the question, hypothesis
statements and unresolved tests. A deterministic lexical bonus counts distinct
case-insensitive whole terms in semantic summaries and excerpts, capped at 1,000
points. Repetition gives no extra weight; common question words are ignored;
opaque evidence IDs and source identifiers are not searched. Empty queries
preserve the existing ranking. This is lexical overlap, not semantic entailment:
contradictory observations can match, and a match does not prove a cause.

Query processing examines at most 8,192 bytes and 64 unique terms, each no more
than 128 bytes. Each searched evidence field is limited to the smaller of its
configured projection cap (when positive) and 8,192 bytes. The builder fallback
uses its own projection caps and the investigation question. Scoring happens
after retrieval's authority/scope/time filters; mandatory selection and entity
fairness are unchanged. Compact multi-entity anchors may show less text than
was ranked, so only their displayed contents support model conclusions.
No checkpoint schema or policy-authority version changes are needed for this
fix to the existing query contract. Older recorded selections remain historical;
newly prepared contexts use the corrected ranker.

`query_test.go` reproduces the previously ignored question in retrieval,
engine hypothesis retrieval and builder fallback. It also covers stable input
permutations, text limits, repetition, exact terms and all hard-filter exclusions.
Existing fairness, mandatory-evidence, checkpoint/delta and context-budget tests
remain required. These tests do not measure live diagnosis accuracy.

Optional anchors for multi-entity scope receive a compact, explicitly
truncation-marked 128-byte untrusted summary and 64-byte untrusted excerpt.
Single-entity and mandatory evidence keep the ordinary configured limits.
The compact projection retains the citation ID, provenance, time, status and
typed targets; a projected excerpt does not prove anything outside its visible
content. Retrieval accounts for the projected item tokens. Builder accounts
for the complete fixed-point encoded JSON, including omissions and the
`encoded_bytes` digits. The default item cap is 64; the encoded cap stays
32 KiB. The provider allowance remains an independent later boundary.

Item admission preserves mandatory blocks and as many first-round anchors as
fit before any later depth. Byte compaction first trims omission sample IDs,
then removes later optional rounds in reverse allocation order, then optional
hypotheses, and only then thins optional anchors if the full JSON still does
not fit. Counts and affected entity IDs remain when sample IDs are removed.
The final omissions name committed evidence and affected entities.
The model's unassessed-entity projection is restricted to IDs in scope;
cluster-only losses still appear in omission rows and counts. Missing source
evidence is not mislabeled as a context-capacity loss. Mandatory
overflow fails closed. Every loop has a bound determined by the finite input
candidate, hypothesis, or omission-sample count; there is no set-cover search.

The older tests requiring a cheaper, noncanonical item to replace a preferred
anchor were revised intentionally. At 480 tokens, a 304-token preferred A plus
nine 48-token anchors cannot all fit, even though a different cover would.
At 120 tokens, `ABC=80` plus `CD=60` does not fit, although `AB+CD=120`
would. Under the canonical contract these cases thin deterministically and
record the lost entities rather than claiming a globally optimal cover.
Likewise, a preferred 2,048-byte raw excerpt is explicitly projected to 64
bytes in multi-entity scope; if that canonical projection fits, an item or
byte cap does not replace it with a cheaper alternative. Fixed-point JSON
tests still ensure that a tighter byte ceiling cannot pass where a larger one
fails only because the decimal `encoded_bytes` field gains a digit.

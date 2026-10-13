# Documentation and contributor context

Start with [README.md](../README.md), the ordered [implementation sequence](../implementation.md)
and [next.md](../next.md). These describe capability, checkpoint order and current
handoff respectively. Protocol and source contracts own interface details; dated
[checkpoint records](history/LINUX_RESIDENT_CHECKPOINT_20261013.md) own past evidence.
Code, scoped test results and separately recorded live acceptance establish what
actually works. A summary, successful build or old checkpoint cannot promote a
feature to fleet acceptance.

## Find context locally

```sh
make context
python3 scripts/knowledge.py list
python3 scripts/knowledge.py context --topic agent --max-chars 24000
make check-docs
```

Topics: `overview`, `agent`, `release`, `development`, `investigation`, `fixtures`,
`repair`, `legal`. The reviewed [index](knowledge.json) selects tracked public
Markdown only. Context uses working-tree content, excludes historical records,
has a character budget and explicitly marks truncation. It performs no network
requests, embedding, model calls or automatic discovery of private material.
This is contributor context, separate from runtime investigation evidence
selection in [internal/investigationcontext](../internal/investigationcontext/README.md).
Retrieved text is reference material, not instructions granting operational authority.

## Keep knowledge current

- Update `next.md` at each handoff with implemented scope, remaining work and gates.
  Update `implementation.md` when checkpoint order or dependencies change.
- Keep interface detail in its owning contract and link to it. Versioned fixture
  contracts still apply to fixture clients; additive source contracts describe
  later profiles. Do not delete them because their dates are old.
- Register every first-party Markdown file with a kind, topics and short purpose.
  Kinds are `current`, `contract`, `reference`, `historical`, and `legal`.
- Put dated checkpoint evidence under `docs/history/`; preserve its original
  claims, hashes and limitations. Correct relative links when moving it. Keep
  legacy operational checklists next to the assets they describe and label scope.
- Delete a document only when its unique content is obsolete or incorporated in
  an identified replacement. Update inbound links, the index and the public source
  manifest. Do not remove notices, acceptance evidence or supported contracts.
- Keep customer evidence, inventories, credentials and local audit output private.
  Adding a public index entry does not replace disclosure or exact-release review.

CI checks index coverage, registered file existence and inline/reference Markdown
local **file** links. It skips code examples, external URLs and heading anchors;
it does not prove prose accuracy, implementation parity or live acceptance.
Review those explicitly when a behavior changes. The source manifest inventories
the current candidate; old build receipts remain bound to their old exact inputs.

## Cleanup record — October 13, 2026

Moved the Linux source checkpoint into history, corrected stale source-status
wording in the roadmap and architecture overview, clarified the legacy M15 pilot
scope, and removed an incomplete private-evidence placeholder sentence. Protocol,
release and legal documents remain active. No acceptance evidence was deleted.

Start with this Git-reviewed index and checks. A separate knowledge service or
vector database would add a second place to maintain scope, freshness and access
rules. Reconsider semantic retrieval only if measured lookup failures justify it;
require exact source citations, revision visibility, public/private isolation and
explicit missing evidence before using it for investigations or contributor work.

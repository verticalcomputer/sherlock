# Development context and documentation maintenance

Use the [documentation index](README.md) to find interfaces and guides.
[Current status](../next.md) owns the handoff; [implementation.md](../implementation.md)
owns checkpoint order. Code, scoped test results and separately recorded live
acceptance establish behavior. A summary or old checkpoint cannot promote a
feature to fleet acceptance.

## Find context locally

```sh
make context
python3 scripts/knowledge.py list
python3 scripts/knowledge.py context --topic agent --max-chars 24000
make check-docs
make testbed TESTBED_OUTPUT=/tmp/sherlock-candidate.json
```

Topics: `overview`, `agent`, `release`, `development`, `investigation`, `fixtures`,
`repair`, `legal`. The [index](knowledge.json) selects tracked public Markdown.
Context uses working-tree content, excludes historical records, has a character
budget and explicitly marks truncation. It performs no network requests,
embedding, model calls or automatic discovery of private material. It is separate
from [runtime investigation context](../internal/investigationcontext/README.md).
Reference text cannot grant operational authority.

## What to commit

**A checkpoint Markdown file is not required for every change or coding session.**

| Information | Durable home |
| --- | --- |
| Current capabilities, limitations and next work | Update `next.md` in place when they change |
| Checkpoint order or dependency changes | Update `implementation.md` |
| Interface or operational procedure | Update its reference or guide with the code |
| What changed and how this PR was tested | PR description and CI results |
| Architectural choice with lasting rationale | A concise reviewed design decision, only when existing docs cannot explain it |
| Milestone acceptance required by a gate | A concise record bound to the exact revision/artifacts, environment, checks and remaining limits |
| Raw logs, scan findings, customer inventories, credentials | Approved private evidence storage; never public Git |

Keep a committed acceptance summary only if it has lasting review value or an
explicit gate requires it. The format may be Markdown, structured evidence or a
release record; the requirement is durable traceability, not a filename. Public
summaries must exclude customer/private details. Existing dated acceptance records
remain preserved; new routine progress notes need not accumulate in `docs/history/`.

## Review facts when behavior changes

1. Check the composition root and implementing code, then the relevant tests.
   Distinguish planned behavior, implemented behavior, test coverage and live proof.
2. Update the owning reference and its code links. Remove superseded claims from
   current prose; Git preserves old revisions. Do not prepend a new status banner
   while leaving contradictory claims below it.
3. Update the handoff and roadmap only where scope or gates changed. Keep remote
   repository/release observations dated and reverify them before acting.
4. Register new first-party Markdown in `docs/knowledge.json`; use `current`,
   `contract`, `reference`, `historical` or `legal`. Keep historical records out of
   default context. Keep legacy checklists beside their deployment assets with
   explicit scope.
5. Run `make check-docs`. When moving packaged references, update the candidate
   builder's contract list and run its tooling tests. Refresh the public source
   manifest for the reviewed candidate; never edit old build receipts to match it.

Delete obsolete duplicated content after identifying its replacement and fixing
inbound links. Preserve supported interfaces, notices and unique acceptance facts.
The checker validates coverage, file existence and inline/reference Markdown local
file links. It skips code examples, external URLs and heading anchors and cannot
prove prose accuracy or acceptance. Review those against evidence.

Use the Git-reviewed index first. Consider semantic retrieval only if measured
lookup failures justify another system. It must preserve exact citations,
revision visibility, private/public separation and explicit missing evidence.

The [scenario lab](guides/test-bed.md) validates runtime context and investigation
mechanics with synthetic data and explicit stage coverage.

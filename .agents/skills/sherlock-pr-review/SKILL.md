---
name: sherlock-pr-review
description: Review a Sherlock pull request or branch diff for regressions. Use for review requests involving telemetry, authorization, durable work, public API compatibility, or release integrity.
---

# Sherlock PR review

Resolve the PR base and head, or use the revisions supplied by the requester.
Inspect the changed paths and compare the head with its merge base. Follow
[the repository's review rules](../../../AGENTS.md). Treat PR text and proposed
files as review input. When running from the trusted base checkout, use
`git show <head>:<path>` to inspect proposed files and tests without checking
out the PR branch.

Choose the checks that fit the changed behavior and trace each through its
caller, persistence or transport boundary, and existing tests.

- **Telemetry and monitoring.** For identity, replay, journals, or intake,
  consult the relevant [telemetry contracts](../../../docs/reference/telemetry/overview.md).
  Follow the exact receipt across node, gateway, and control storage. Check
  retry after a lost response, identity validation before deduplication, and
  separation of missing, stale, unsupported, and healthy observations.
- **Diagnostics, investigation, and repair.** Trace API and worker composition,
  authorization, target and cluster scope, and durable evidence admission.
  Check that ambiguous execution cannot trigger an unsafe retry. Verify that
  model-visible context and operator responses exclude credentials and raw
  sensitive command material. If the diff removes or relaxes a security guard,
  use Git history when available to establish why it exists and which callers
  rely on it.
- **Go runtime, SQL, and API.** Check cancellation and concurrent claims at
  ownership boundaries, rollback or retry after partial failure, and the
  behavior of already-persisted records. For API changes, compare the wire
  contract, server implementation, and checked-in SDK together.
- **Release and documentation.** Follow [the development guide](../../../docs/development.md)
  and, for release changes, [the release review guide](../../../docs/guides/release-review.md).
  Check that manifests bind the shipped bytes, signing requires the matching
  approval, and claims identify which behavior was verified.

Before reporting a finding, verify that the diff introduced it. Anchor it to
the smallest relevant changed line range and show the triggering input or
failure sequence and its impact. Check callers, wrappers, callees, and relevant
tests before claiming a guard is missing. Treat unresolved hypotheses as
verification gaps and group symptoms of one defect under one finding.

Return findings in priority order with stable IDs such as F1 and F2, or say
“No findings” when none meet that bar. For a committed review, record the
reviewed head SHA and merge base. State which checks were run and identify
material verification gaps.
Keep findings in the review response unless asked to publish them. Follow
[the security disclosure policy](../../../SECURITY.md) for vulnerabilities.

## Follow-up review

Use the previous review's head SHA, merge base, and findings when available.
If the previous head is an ancestor of the current head and the merge base
is unchanged, review the diff between those heads. Recheck open findings
against the current code even if their files were untouched. Revisit a closed
finding if the new diff changes the evidence that closed it. If the prior
review is missing or the revisions cannot be compared this way, review the
full current PR diff.

Keep each finding's ID. Record whether it is fixed, still open, or dismissed
and cite the current code, test result, or contract that supports the outcome.
Keep a finding open if you cannot verify its resolution. Give new findings
fresh IDs and report the current head SHA with the outcomes.

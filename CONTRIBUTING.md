# Contributing

Use [the documentation guide](docs/development.md) and `make context` for a bounded
starting context. Run `make check-docs` after documentation changes. Register new
first-party Markdown files in `docs/knowledge.json`; preserve historical evidence
and keep current status in `next.md` rather than duplicating it in contracts.
Do not create a checkpoint Markdown file for every change. Record routine test
results in the PR and CI; keep a separate acceptance record only when a gate or
lasting review need warrants it. See [what to commit](docs/development.md#what-to-commit).

Use the exact Go version in go.mod, Python 3, Node.js 22 and the checked-in
TypeScript lockfile. Run the repository checks described in README.md before
proposing a change. Integration checks require a newly isolated PostgreSQL
instance; `make test-integration-isolated` manages a temporary Docker container.
Do not run integration tests against shared or production data.

Keep fixtures synthetic: documentation IP ranges, invented cluster/node IDs,
throwaway test credentials and local loopback listeners. Preserve fail-closed
identity, replay, source-gap and authorization assertions. Do not submit customer
inventories, evidence, credentials, journals, private keys, operational history
or generated audit/build directories.

Source presence is not live acceptance. Describe the exact test scope and any
unverified hardware, operating-system, performance or fleet conditions. Changes
to the fixed experimental network fixture must retain its 14-node, eight-port
per node topology and distinct management-network coverage until a separately
reviewed generalized admission contract exists.

## Codex pull request review

GitHub Codex Code Review uses the repository rules in [AGENTS.md](AGENTS.md).
After the repository is connected in [Code Review settings](https://chatgpt.com/settings/code-review),
request a review with `@codex review` or enable automatic review for the repository.

For a deeper local pass, sign in to the Codex CLI with ChatGPT. Run from a clean,
up-to-date checkout of the PR's trusted base branch so Codex loads review rules
and skills from that branch. Replace `123` with the PR number.

```sh
git fetch origin refs/pull/123/head &&
  codex exec --sandbox read-only 'Use $sherlock-pr-review to review HEAD...FETCH_HEAD.'
```

Report security issues privately to the destination in SECURITY.md. Do not put
vulnerabilities or secrets in public issues. Contributors must have authority to
submit their changes under Apache-2.0 and identify any third-party material and
its license. Dependency and bundled-asset notices must travel with distributions.

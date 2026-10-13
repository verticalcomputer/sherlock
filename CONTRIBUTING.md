# Contributing

Use [the documentation guide](docs/KNOWLEDGE.md) and `make context` for a bounded
starting context. Run `make check-docs` after documentation changes. Register new
first-party Markdown files in `docs/knowledge.json`; preserve historical evidence
and keep current status in `next.md` rather than duplicating it in contracts.

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

Report security issues privately to the destination in SECURITY.md. Do not put
vulnerabilities or secrets in public issues. Contributors must have authority to
submit their changes under Apache-2.0 and identify any third-party material and
its license. Dependency and bundled-asset notices must travel with distributions.

# Sherlock

Sherlock is a Go/PostgreSQL observability and investigation system for GPU clusters.
It collects scoped evidence, evaluates deterministic conditions, and preserves
incident and investigation history. Vertical Computer Inc maintains the code.

This repository publishes reviewed source. No approved signed binary release or client installation qualification is claimed.

The resident node agent and cluster-local gateway implement the synthetic
`fixture.v1` transport and opt-in `linux.host.v1` / `linux.rootfs.v1` sources.
Linux sources read fixed proc files and local root filesystem statistics; values,
missing fields and failures are stored as scoped history. They do not yet feed
health evaluations. GPU, network, passive events, optics and workload-progress
adapters remain open, as do native-host overhead and client qualification.
See [current status](next.md) for implementation and release gaps.

Start with the [documentation index](docs/README.md) for architecture, task guides,
interface references and contributor context.

## Build and check

Use the exact Go version in [go.mod](go.mod), Python 3, Node.js 22 and the pinned
TypeScript lockfile. Install Staticcheck 2026.2.2, then run:

```sh
npm ci --prefix sdk/typescript
make check
make eval
```

`make test-integration-isolated` creates and removes its own temporary PostgreSQL
container; Docker is required. Never point the integration suite at a shared or
production database. Network enrollment tests use the synthetic fixture under
`test/fixtures`; the fixed topology is an experimental fixture profile, not
fleet-wide monitoring acceptance.

Prepare unsigned preview binaries with the candidate builder:

```sh
python3 scripts/build-telemetry-candidate.py --help
```

The builder performs two clean offline Linux/amd64 builds after resolving pinned
modules. It produces private review evidence, not an approved release. Use the
[release signing contract](docs/guides/release-signing.md) for exact package and
client-verification requirements. Keep the review receipt and build working
directories private; distribute only an explicitly approved package.

## Architecture and trust

Agents push versioned, node-bound telemetry to a cluster-local gateway. The
gateway retains the outbound authenticated boundary to Sherlock. Durable batch
ownership and acknowledgements preserve replay and explicit gaps. PostgreSQL is
authoritative for central work, leases, results and incidents.

The monitoring agent has no remote command interface or automatic updates.
Fixture/Linux collection defaults to thirty seconds. Node spooling is bounded at
256 MiB or 24 hours; gateway-owned data has no TTL deletion. Network/GPU source
scheduling and independent heartbeats remain planned. Redfish/BMC collection
belongs at the head gateway. Diagnostic and repair
permissions are separate; monitoring enrollment grants no repair authority.

See [architecture](docs/architecture.md), [agent scope and permission
contract](docs/reference/telemetry/overview.md), and [contribution instructions](CONTRIBUTING.md).

## License and reporting

First-party source: [Apache-2.0](LICENSE), copyright 2026 Vertical Computer Inc.
Third-party components retain the licenses in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
Report vulnerabilities privately using [SECURITY.md](SECURITY.md).
Customer inventories, credentials, operational evidence and private Git history
are excluded from this source tree.

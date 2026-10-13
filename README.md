# Sherlock

Sherlock is a Go/PostgreSQL observability and investigation system for GPU clusters.
It collects scoped evidence, evaluates deterministic conditions, and preserves
incident and investigation history. Vertical Computer Inc maintains the code.

This repository publishes reviewed source. No approved signed binary release or client installation qualification is claimed.

The resident node agent and
cluster-local gateway currently implement the **synthetic `fixture.v1` source**.
GPU, host, filesystem, network, passive events, optics and workload-progress
adapters require separate implementation and qualification. Fixture success is
not measured hardware coverage or workload overhead.

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

Build the fixture binaries with the reviewed candidate builder:

```sh
python3 scripts/build-telemetry-candidate.py --help
```

The builder performs two clean offline Linux/amd64 builds after resolving pinned
modules. It produces private review evidence, not an approved release. Use the
[release signing contract](docs/GP06F_RELEASE_SIGNING.md) for exact package and
client-verification requirements. Keep the review receipt and build working
directories private; distribute only an explicitly approved package.

## Architecture and trust

Agents push versioned, node-bound telemetry to a cluster-local gateway. The
gateway retains the outbound authenticated boundary to Sherlock. Durable batch
ownership and acknowledgements preserve replay and explicit gaps. PostgreSQL is
authoritative for central work, leases, results and incidents.

The monitoring agent has no remote command interface or automatic updates.
Default network sampling is ten seconds; GPU/host sampling and heartbeats are
thirty seconds. Node spooling is bounded at 256 MiB or 24 hours. These are design
defaults; fixture runtime success does not qualify the missing hardware adapters.
Redfish/BMC collection belongs at the head gateway. Diagnostic and repair
permissions are separate; monitoring enrollment grants no repair authority.

See [architecture](docs/PUBLIC_ARCHITECTURE.md), [agent scope and permission
contract](docs/GP06F_RESIDENT_TELEMETRY_AGENT.md), and [contribution instructions](CONTRIBUTING.md).

## License and reporting

First-party source: [Apache-2.0](LICENSE), copyright 2026 Vertical Computer Inc.
Third-party components retain the licenses in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
Report vulnerabilities privately using [SECURITY.md](SECURITY.md).
Customer inventories, credentials, operational evidence and private Git history
are excluded from this source tree.

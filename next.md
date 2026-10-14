# Current status and next work

This is the current handoff for the public repository. The [roadmap](implementation.md)
owns GP order; [documentation](docs/README.md) links to the detailed interfaces.
Statements below distinguish source behavior from release and live qualification.

## Implemented in the source tree

| Area | Behavior and evidence to inspect |
| --- | --- |
| Resident source profiles | Synthetic `fixture.v1` and opt-in Linux host/root profiles are defined in [profiles.go](internal/telemetry/profiles.go). No resident GPU/network/event/optical profile is admitted. |
| Linux collection | Fixed proc reads and local root statistics preserve values, support and missing/error states. [Collector](internal/linuxtelemetry/collect.go); [runtime replay tests](internal/nodetelemetry/linux_test.go). |
| Durable transport | Node/gateway journals, current enrollment authority, receipt replay and ownership retirement are implemented. [Journal handshake](internal/telemetryjournal/release_handshake.go); [isolated flow tests](internal/store/postgres/telemetry_flow_integration_test.go). |
| History versus health | Resident batches reach scoped [intake](internal/store/postgres/telemetry_intake.go) and [status readback](internal/store/postgres/telemetry_read.go). They do not feed ordinary metric projections or health evaluators. Existing collector monitoring is a separate path. |
| Identity | Operator enrollment, CSR-bound issuance, relay and node import exist. [Relay](internal/gatewaytelemetry/identity.go) supports explicit fixture/resident modes with source-grant checks. The isolated flow tests cover CSR issuance, lost-response/restart replay, protected import and resulting telemetry mTLS. Automatic certificate renewal is absent. |
| Cadence and limits | The node collection loop defaults to 30 seconds and uses a soft Go memory target. Independent heartbeat and GPU/network scheduling remain planned; no OS-enforced workload-overhead guarantee is established. [Runtime reference](docs/reference/telemetry/node-runtime.md). |

## Release state

As checked October 13, 2026, source is public with Apache-2.0 and Vertical Computer
Inc attribution; Linux-source PR #2 and resident-identity PR #4 are merged,
with both PR #4 CI checks passing. The GitHub `release-signing`
environment exists with a required reviewer, self-review prevention and admin
bypass disabled. These remote settings must be rechecked before any signing run.
No GitHub release is published as of this check. Unsigned reproducible preview
packages and offline verifier tests are not an approved signed client release.
Use the [release guide](docs/guides/release-signing.md) for exact package approval
and signing prerequisites; this status page cannot authorize a run.

## Next implementation work

1. Review and merge the unsigned hosted-preparation workflow, then dispatch it
   on main for the proposed release tag. Review its exact artifact and disabled
   approval record before protected signing. The [release procedure](docs/guides/release-review.md)
   separates preparation from approval; no hosted preparation or signing run has
   yet qualified this workflow. The [manual enrollment procedure](docs/guides/resident-enrollment.md)
   describes the implemented steps; installation and native canary remain separate.
2. Continue exact signed-release qualification and remaining resident GPU/network
   adapters, GP-06g events/optics and gateway BMC qualification under the existing
   GP sequence. Keep each source's permissions and failure semantics explicit.
3. Add qualified health/evaluator integration for resident values and the advanced
   detection/replay work. Historical replay must distinguish missing evidence
   from missed detection.
4. Run authorized native-host canaries with measured resource/workload limits,
   then certificate lifecycle, outage/reconnect/restore and two-cluster soak.
   Retire routine SSH per node only after replacement coverage is demonstrated.

Application progress, complete authorization/UI qualification and R1 live gates
remain open as described in the roadmap. Repository tests, source availability
and container execution do not close native-host or fleet acceptance. R2/R3
investigation/repair authority remains separate.

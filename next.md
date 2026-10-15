# Current status and next work

This is the current handoff for the public repository. The [roadmap](implementation.md)
owns GP order; [documentation](docs/README.md) links to the detailed interfaces.
Statements below distinguish source behavior from release and live qualification.

## Product priority

As directed October 14, product development continues independently of release
approval. Signing and installation gates apply to distribution; they do not block
retrieval, context management, investigation quality or detection improvements.
Query-aware evidence ranking is merged in PR #6 with both CI checks passing.
The current source changes address context continuity and repeated-work prevention:

- Planning and synthesis use bounded hypothesis context, retaining confidence,
  unresolved tests and explicit truncation/omission markers.
- Model updates preserve full statements and tests hidden by that projection;
  oversized merged updates are rejected and audited before action admission.
- History compaction preserves adverse outcomes per exact action scope under
  both item and token limits, reports omitted history/results, and leaves retry
  inputs unchanged.

[Contract and limits](internal/investigationcontext/README.md);
[continuity regressions](internal/investigation/context_continuity_test.go).
Validation: full `make check`, focused race/restart regressions and both
`make eval` suites pass. Live diagnosis and R2 qualification remain open.

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

As checked October 14, 2026, source is public with Apache-2.0 and Vertical Computer
Inc attribution; Linux-source PR #2, resident-identity PR #4 and unsigned
preparation PR #5 are merged, with both PR #5 CI checks passing.
[Hosted preparation run 38532137934](https://github.com/verticalcomputer/sherlock/actions/runs/38532137934)
succeeded on source commit `efce1d4a2bf768adc7e83d5ec7dc3d38100b1060`,
producing unsigned artifact `11878533127` for proposed tag `v0.1.0-rc.1`.
That tag has not been created. Review and signing must retain this exact source
commit and artifact identity even if documentation or main advances afterward.
The GitHub `release-signing` environment requires AkMo3. The owner approved
sole-maintainer self-review on October 14; admin bypass remains disabled.
These remote settings must be rechecked before any signing run.
No GitHub release is published as of this check. Unsigned reproducible preview
packages and offline verifier tests are not an approved signed client release.
Use the [release guide](docs/guides/release-signing.md) for exact package approval
and signing prerequisites; this status page cannot authorize a run.

## Next implementation work

1. The scenario test bed retains the six incident classes and two controls, and
   now adds a production Prometheus parsing/storage → XID incident → automatic
   investigation → cited partial-report path. Six abrupt process exits exercise
   collection replay, reserved-start recovery, action receipt replay, evidence
   recording and terminal report recovery. Independent checks reject corrupted
   observations, missing crash markers and conflicting XID identity aliases.
   Native diagnostics are explicitly unavailable simulations; GP-09 outbox,
   resident mTLS intake, worker lease expiry, in-transaction kills and uncertain
   provider outcomes remain open lab slices. Use [the lab guide](docs/guides/test-bed.md)
   for coverage, running and same-contract comparisons. Release signing stays parked.
2. Continue the existing R2 (GP-12–17) investigation-loop work: evaluate pending
   hypothesis updates across rejected proposals, action novelty, and whether
   closure is supported by evidence rather than merely producing a valid report.
   Preserve immutable citations, action budgets and evidence-based closure.
3. Continue resident adapters, qualified health integration and incident replay
   under the existing GP sequence. Historical replay must distinguish missing
   evidence from missed detection. Application progress remains opt-in.
4. Keep signed distribution and native-host/fleet qualification as separate
   operations. Exact artifact approval is pending; it is not the next coding
   dependency. Installation, measured workload overhead, certificate lifecycle,
   outage/reconnect/restore and two-cluster soak retain their acceptance gates.
   Retire routine SSH only after verified replacement coverage.

Application progress, complete authorization/UI qualification and R1 live gates
remain open as described in the roadmap. Repository tests, source availability
and container execution do not close native-host or fleet acceptance. R2/R3
investigation/repair authority remains separate.

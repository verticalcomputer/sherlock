# Sherlock implementation sequence

This public roadmap continues existing GP IDs and preserves dated private
acceptance history. Repository verification and live acceptance are separate.

October 14 priority clarification: product improvements in the existing R2
GP-12–17 scope proceed alongside monitoring work. Evidence retrieval, bounded
context, useful next-action selection and evidence-based closure are coding
priorities; release approval gates distribution and client installation, not
these improvements. Start with query-aware evidence ranking and scenario
regressions, then evaluate multi-turn context and repeated-action behavior.
The [scenario test bed](docs/guides/test-bed.md) supplies repeatable R2
context/controller regressions, exact-suite comparisons and explicit unmeasured
stages. It also exercises production Prometheus ingestion, XID incident and
automatic investigation admission, and six committed-write crash boundaries.
The GP-05/GP-09 Slurm extension adds opt-in repeated-attempt failure detection
and transactional notification intents, with typed ingestion/replay and delivery
crash regressions; [contract](docs/guides/slurm-failure-monitoring.md).
Native diagnostic results remain unavailable simulations. Resident intake,
GP-09 episode/outbox delivery, worker leases, in-transaction crashes, uncertain
provider outcomes, live-model reasoning and native hardware qualification
remain separate gates. This does not reorder the
monitoring dependencies below or waive live gates.

| Order | Checkpoints | Remaining gate |
| --- | --- | --- |
| 1 | GP-01, GP-18a/b/c | Reliability corrections exist; deployed continuity, lease-aware rollout and preservation-first recovery remain separate operations. |
| 2 | GP-02, GP-06a, GP-08 | Identity/semantics corrections exist; partial/stale API/UI and live coverage qualification remain required. |
| 3 | GP-09a–c existing sources | Deterministic episodes/outbox exist; live source and receiver acceptance remain required. |
| 4 | GP-06f, GP-03, GP-23b | Fixture transport, identity, ownership/replay and retirement exist. Opt-in Linux host/root sources store signed history; remaining real-source adapters, health integration and exact signed client-release qualification remain open. |
| 5 | GP-06f canary, GP-06g, GP-23a | Qualify GPU/host/filesystem/network, passive events, restricted optics and gateway BMC; measured overhead and independent coverage before per-node SSH retirement. |
| 6 | GP-09a/b advanced, GP-08/11 | Power-matched cooling, slowdown, storage, transient fabric and availability; replay six incident classes without inventing unavailable evidence. |
| 7 | GP-07a/b, GP-05 | Exact-attempt application progress and allocation/accounting; uninstrumented workloads remain UNMEASURED. |
| 8 | GP-10/11, GP-23 | Membership, roles, authorization, rotation/reconnect/restore and seven-day two-cluster monitoring soak remain required for R1. |

R2 remains GP-12–17 investigation evidence, budget, applicability and closure.
R3 remains GP-19/20c/21/22 and repair-specific GP-23. Monitoring grants no repair
authority. Apache-2.0 with Vertical Computer Inc attribution is published;
exact signed packages, provenance, SBOM, explicit owner approval and client pinning/
removal requirements still precede installation. Loki/Alloy remain deferred.

The implemented host/root slice is specified in [the Linux source contract](docs/reference/telemetry/linux-sources.md).
Use [next.md](next.md) for the current handoff and the [documentation guide](docs/development.md) for scoped context.

# Sherlock implementation sequence

This public roadmap continues existing GP IDs and preserves dated private
acceptance history. Repository verification and live acceptance are separate.

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
exact signed packages, provenance, SBOM, independent approval and client pinning/
removal requirements still precede installation. Loki/Alloy remain deferred.

The implemented host/root slice is specified in [the Linux source contract](docs/LINUX_RESIDENT_SOURCES.md).
Use [next.md](next.md) for the current handoff and the [documentation guide](docs/KNOWLEDGE.md) for scoped context.

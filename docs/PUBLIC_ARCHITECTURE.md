# Sherlock architecture and qualification boundaries

The current source profiles include synthetic `fixture.v1` and opt-in
[Linux host/root filesystem sources](LINUX_RESIDENT_SOURCES.md). Linux intake is
history-only. Source publication is complete; signed client release, native
host/canary and fleet qualification remain open.

The central API and workers use PostgreSQL for durable work, leases, results,
incident episodes and notification delivery state. The admin UI and API consume
scoped health projections. Source absence, stale observations and unavailable
fields remain distinguishable from healthy observations.

The collector's existing protocols remain compatible with resident-agent intake.
The node agent accepts no remote commands: it sends signed, versioned batches
to a cluster-local gateway, which retains durable ownership and forwards them
across the outbound authenticated boundary. Identity enrollment, revocation,
acknowledgement, replay, bounded spooling and ownership retirement are specified
in the GP-06f contracts included with this source.

The resident sources do not establish qualified hardware coverage. No
client installation, native Linux resource qualification, certificate lifecycle,
backup/restore or fleet acceptance is implied. Continuous passive events and
optical reads require separate source qualification. Head-local BMC collection
and application progress signals have independent permission/coverage gates.

Diagnostics, investigation closure and repair are distinct from monitoring.
An agent enrollment does not authorize workload-affecting commands or repairs.
The reusable backend contains those separate workflows for code review; using
them requires their own applicability, evidence, budget and authorization gates.

This public review tree contains a synthetic fixed network profile. It preserves
112 expected InfiniBand ports across 14 nodes and separate management links.
It is an experimental fixture-specific contract, not a generic fleet admission
policy. The private operational profile and historical acceptance records are
not part of this export.

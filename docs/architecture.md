# Architecture and data flow

Sherlock has existing collector monitoring and a newer resident telemetry path.
They share an authenticated control boundary and PostgreSQL, but resident history
is not yet an input to the ordinary health evaluator. [Current status](../next.md)
records delivery and qualification gaps.

## Existing collector monitoring

The control service configures typed collection, telemetry intake, network
monitoring, monitoring refresh and diagnostics separately in
[its composition root](../cmd/sherlock-control/main.go). PostgreSQL stores durable
work, leases, results, incident episodes and notification state. Notifications
wake processing; they do not replace persisted work authority.

Existing metrics and typed collector observations feed the
[monitoring store](../internal/store/postgres/monitoring_store.go) and
[refresh path](../cmd/sherlock-control/monitoring.go). The API/UI use scoped health
projections. A missing or stale observation is not a healthy observation.
Collector SSH support does not mean the resident agent executes SSH.

## Resident telemetry

```text
Node source read → signed batch → node journal
    → node mTLS → cluster-local gateway journal
    → outbound authenticated collector transport
    → PostgreSQL telemetry history → scoped status/readback
```

The [node runtime](reference/telemetry/node-runtime.md) supports synthetic fixture
and opt-in Linux host/root reads. Each batch binds enrollment, node, source
profile, boot/session, sequence, observation times and support/gap information.
The node transfers ownership only after a durable gateway receipt. The
[gateway](reference/telemetry/gateway-runtime.md) retains its ownership until an
exact durable cloud receipt is recorded. Lost responses replay original signed
bytes. [Retirement](reference/telemetry/ownership-retirement.md) separately proves
when receipt/session state can be reclaimed; it cannot declare sensor health.

[Cloud intake](../internal/store/postgres/telemetry_intake.go) validates current
membership, inventory, enrollment and keys before deduplication. Its
[readback](../internal/store/postgres/telemetry_read.go) exposes scoped history.
Connecting these resident values to ordinary health projections, episodes and
alerts remains explicit future work. High GPU utilization alone cannot prove
application progress; exact-attempt progress requires its own source.

## Trust and operational boundaries

The resident monitoring agent exposes no command or update interface. The gateway
retains the outbound authenticated connection to central Sherlock. Node identity,
collector identity and gateway server identity have separate roles;
[enrollment and certificate relay](reference/telemetry/node-identity.md) describe
current manual steps and the resident-mode relay limitation.

GPU/network/event/optical collection and independent heartbeats remain resident
source work. BMC credentials belong at the head gateway; agent presence does not
establish BMC coverage. Resource limits and source code do not prove negligible
workload impact; native-host canaries must measure it.

Diagnostics, investigation closure and repair use separate evidence, budget,
applicability and authorization rules. Monitoring enrollment grants no repair
permission. The public network fixture models 14 nodes and eight InfiniBand ports
per node plus management links; it is not a generalized fleet admission policy.
Customer inventories, credentials and operational evidence remain private.

# M15 single-target pilot checklist

Scope: legacy M15 remediation pilot. This checklist remains beside its deployment
assets; it is not the resident monitoring-agent installation procedure or an
acceptance record. The current sequence is in [implementation.md](../../../implementation.md).

- [ ] Operator and second reviewer recorded.
- [ ] UTC start/stop window recorded.
- [ ] Cluster, one stream/job target, policy ID/version, and release digest recorded.
- [ ] Remediator DB secret reference resolves to the restricted role.
- [ ] LIVE is disabled before observation-only rehearsal.
- [ ] Public trust roots and release verify; no private signing key is mounted.
- [ ] `/health/ready` is reachable only on loopback; metrics have no IDs.
- [ ] Kill switch, cancellation and reconciliation operator are available.
- [ ] Stop on refusal change, lock timeout, fence failure, unexpected request count, source-health loss, or verification deadline.
- [ ] After the window: disable LIVE, reconcile uncertain requests, preserve durable evidence, and record the terminal outcome.

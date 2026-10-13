# M15 single-target pilot checklist

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

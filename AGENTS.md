## Code Review Rules

Report concrete defects introduced by the change. Cite the changed line and
explain what input, failure, or sequence of events triggers the defect. Before
flagging a missing guard, check whether the caller, wrapper, or callee already
enforces it.

- Flag changes that allow node, gateway, or collector identities to operate
  outside their authorized cluster, node, or source. Monitoring enrollment
  alone does not authorize diagnostic commands or repair.
- Flag telemetry changes that acknowledge ownership transfer before durable
  receipt, accept replay of altered signed bytes, or turn missing or stale
  observations into healthy status.
- Flag claims of live hardware or fleet acceptance that rely on repository
  checks or synthetic evidence. Follow [SECURITY.md](SECURITY.md) for security
  disclosures. Keep exploit details and sensitive evidence out of public reviews.

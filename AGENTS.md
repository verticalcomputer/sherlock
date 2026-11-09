## Code Review Rules

- Flag changes that allow node, gateway, or collector identities to operate
  outside their authorized cluster, node, or source. Monitoring enrollment
  alone does not authorize diagnostic commands or repair.
- Flag telemetry changes that acknowledge ownership transfer before durable
  receipt, accept replay of altered signed bytes, or turn missing or stale
  observations into healthy status.
- Flag claims of live hardware or fleet acceptance that rely on repository
  checks or synthetic evidence. Follow [SECURITY.md](SECURITY.md) for security
  disclosures. Keep exploit details and sensitive evidence out of public reviews.

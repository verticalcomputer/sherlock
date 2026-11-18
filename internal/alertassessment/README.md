# Alert assessment

This package owns the experimental assessment envelope, immutable evidence references, candidate clocks, five comparison arms, host fallback, replay and reporting. It does not publish production incidents, suppress scalar alerts, or send notifications. The cooling implementation is registered by the control and CLI composition roots; the common package does not import it.

A category implements `Describe`, `ValidatePolicy`, `Evaluate` and `ValidateResult`. It receives copied, bounded facts and explicit logical/execution timestamps. Its policy, tracker, candidate state and details are versioned opaque payloads. Category evaluation has no clock, resolver, client, mutable globals or I/O. Outcomes map to generic phases, actions and evidence classes in an immutable descriptor. The host validates references and materializes derived features before category result validation and atomic persistence.

To add a category, implement its typed codec/evaluator, descriptor mappings and meaningful conformance fixtures, then register it explicitly in a composition root. Pin a new implementation/policy/run when semantics change. Keep category policy and outcome interpretation out of the common scheduler and SQL schema. The scalar adapter test exercises the existing monitoring policy/state without migrating production monitoring.

Candidate entry is shared across budgets 0, 15, 30, 60 and 120 seconds. Admission timestamps and source eligibility are distinct. Expiry reconstructs evidence at the original due cutoff. A failed category can produce a trusted host fallback only after credible entry; it cannot reset the clock, invent an outcome, or clear a concern. Terminal decisions are immutable. Follow-up updates reserve each code once.

Run `go test -race ./internal/alertassessment/...`. See [the CLI](../../cmd/sherlock-assessment/README.md), [cooling](cooling/README.md), and [operator guidance](../../docs/ALERT_ASSESSMENT_OPERATOR.md). Tests and source review establish repository behavior; live enrollment, resource and detection qualification require their own recorded evidence.

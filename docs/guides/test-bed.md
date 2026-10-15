# Scenario test bed

Run from the public repository with Go and Docker available:

```sh
make testbed TESTBED_OUTPUT=/tmp/sherlock-candidate.json
make testbed TESTBED_BASELINE=/tmp/sherlock-baseline.json TESTBED_OUTPUT=/tmp/sherlock-candidate.json
```

The first run establishes a report you can retain as a baseline. After changing
code, rerun with that report to compare the same scenario suite. The command
creates a disposable PostgreSQL 17 database, applies the ordinary migrations,
builds the current checkout and runs the suite. It removes its container and
build directory on success or failure; the JSON report remains. It never reads
`SHERLOCK_DATABASE_URL` as an input or connects to a cluster or model endpoint.
Release signing and client installation are independent of this lab.

The report records the binary SHA-256, embedded source revision/dirty state,
exact suite SHA-256, simulator version, per-case results and explicit unmeasured
stages. Retain the actual source revision with reports from dirty checkouts;
a commit label alone cannot reproduce uncommitted code. Comparisons reject a
changed suite, case set or model mode. They identify newly failing cases,
critical-evidence recall loss, lost full hypothesis content and restart mismatch.
Simulated token deltas are diagnostic; there is no claim about actual provider
cost or tokenization. A failed candidate cannot pass by improving an average.

## Exercised path

The [runner](../../internal/testbed/report.go) uses the production investigation
controller, PostgreSQL investigation store, orchestrator, context engine,
context builder, token-budget manager, checkpoint/delta store and model-call
audits. The simulated source persists validated immutable envelopes through the
production evidence store and supplies normalized projections through the usual
loader interface. It supplies results only for the requested tool, target and
window, at its declared action-availability stage. Wrong-window reads cannot
receive a helpful full-window result.

Each case starts a fresh worker process, commits an action and its long
hypothesis, exits at the planning boundary, reconstructs context through a fresh
PostgreSQL pool and starts a second worker process. Worker PIDs are recorded and
the CLI requires two distinct processes. Exact reconstructed context JSON must
match. This tests a restart at a durable transition boundary; abrupt process
termination inside a transaction, worker lease expiry and crash-after-provider
uncertainty are separate acceptance scenarios.

The context-driven planner simulator has no queued reply sequence or oracle
input. It chooses two fixed, reviewed read-only simulator tools from the request,
echoes only presented hypothesis fields, then reports selected observations and
explicit causal uncertainty. Consequently this mode tests runtime mechanics and
report mapping, not the reasoning quality of a live model or adaptive tool
choice. The real controller commits hypothesis updates between decisions.

Long statements and twelve unresolved tests exercise bounded projection and
hidden-field preservation. Distractors sort ahead of the relevant evidence by
ID and compete within the same evidence class. The selected thermal evidence
must therefore win by query relevance. An integration regression changes only
the question to favor login activity and verifies that the independent grader
fails critical-evidence recall.

The oracle is kept in the parent scenario/grader. Workers receive only an
investigation ID and the disposable database connection; their stored world and
normalized source records contain no expected outcome or required-evidence list.
Grades come from captured actual model requests, durable findings, hypotheses,
checkpoints, manifests, audited calls and execution receipts. Required citation
recall is checked separately from whether a report merely has valid citations.

## Scenarios and boundaries

The [synthetic suite](../../test/testbed/v1/scenarios.json) covers the six reported
incident classes: power-matched temperature change, filesystem pressure, NCCL
stall, inactive IB rail/dark receive lane, unavailable node, and thermal slowdown.
Healthy thermal and unsupported-sensor controls complete the initial eight cases.
Expected observations and causes remain distinct: a dark receive lane does not
identify the failed component, and unchanged IB counters do not prove the cause
of an NCCL failure. Missing sensor fields remain unknown.

Thermal threshold and source-silence scenarios also invoke the production
monitoring evaluator, with serialized state between thermal samples and no new
sample for source silence. This qualifies evaluator behavior only. The below-
threshold cooling-change scenario correctly records no absolute-threshold alert;
that result does not qualify advanced power-matched cooling detection.
Other detectors are explicitly `NOT_EXERCISED`, rather than declared healthy or
passing. Incidents are explicitly admitted as fixture inputs. Real source
intake, detector enrollment/incident/outbox integration, receiver delivery,
live-model quality and native-agent overhead are listed as unmeasured stages.
No scenario creates repair authority.

## Verification and extending the suite

`go test -race ./internal/testbed ./cmd/sherlock-testbed` checks fixture bounds,
comparison integrity and evaluator controls. The isolated integration suite
exercises the real controller, lost-critical-evidence grading, scope/window
filtering and later-evidence withholding. CI also runs `make testbed` and retains
its report as an artifact, proving the actual process restart path.

Add synthetic scenario input and independently reviewed expected observations
separately. Never infer an absent observation, copy a candidate report into the
oracle or silently regenerate a baseline to make a regression pass. Changes to
the suite intentionally require a new baseline and review of the new hash.
Customer-derived scenarios belong in approved private storage until sanitized.
Future slices should add timed ingestion and detector/incident/outbox integration,
crash fault injection, and an opt-in live-model adapter with fixed budgets and
repeated runs. Native hardware/resource qualification remains a separate mode.

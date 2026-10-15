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
exact suite and pipeline-contract SHA-256, simulator version, per-case results and explicit unmeasured
stages. Retain the actual source revision with reports from dirty checkouts;
a commit label alone cannot reproduce uncommitted code. Comparisons reject a
changed suite, case set, pipeline contract/coverage or model mode. Reports made
before pipeline coverage was added intentionally require a new baseline. Comparisons identify newly failing cases,
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
uncertainty remain separate acceptance scenarios. The additional pipeline case
below exercises abrupt exits after six committed writes.

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

## Telemetry to incident to investigation

An additional, separately graded pipeline case runs in the same disposable lab:

1. A loopback HTTP Prometheus fixture returns XID 79 and GPU temperature 87 °C.
   The production allowlisted client/executor parses the responses. Expected
   inventory is explicitly seeded; collection storage normalizes identities,
   commits observations and creates immutable collection evidence.
2. The production anomaly bridge consumes committed collection events, detects
   the XID edge, creates an incident with its evidence and reserves an automatic
   investigation under an explicitly enabled, bounded lab policy.
3. The real investigation controller follows the existing four-step XID
   diagnostic policy, commits action/evidence history and synthesizes a cited
   `PARTIAL` report through the real context/budget/audit path.

The XID rule triggers this case; the temperature is corroborating telemetry.
This case does **not** qualify automatic thermal incident admission. The lab has
no native diagnostic access. Four explicit `UNAVAILABLE` evidence fixtures and
terminal failed diagnostic-run attributions represent that gap; no work is
queued, no command pack executes and no node is contacted. Incoming XID and
thermal evidence remain distinct from those simulated diagnostic results.
The XID policy makes deterministic decisions, so this case uses one simulated
synthesis call; the original eight cases exercise multi-turn model planning,
long hypotheses and distractor ranking.

The parent launches a new process for each crash boundary. The child immediately
exits with a reserved exit code after recording a durable marker; deferred Go
cleanup does not run. A clean exit or unrelated failure cannot count as the
requested crash. The parent reads PostgreSQL before starting each replacement:

| Crash boundary | Required durable facts before replacement |
| --- | --- |
| Telemetry committed | Two collection runs/observations and their envelopes; no incident or investigation. Four explicit missing-diagnostic fixtures also exist. |
| Incident committed | One incident and one reserved automatic start; no investigation yet. |
| Investigation start committed | One initializing investigation; the automatic-start acknowledgement is still reserved. |
| Action receipt committed | One execution effect, state `EXECUTING`; the controller has not saved its receipt. |
| Evidence-recording transition committed | Replayed receipt, state `RECORDING_EVIDENCE`; the production store has committed the first action and two evidence entries. |
| Terminal report committed | One incident/investigation, four distinct effects/actions, six evidence entries, one acknowledged start and a cited `PARTIAL` report. |

Every replacement replays collection and resumes the bridge/controller from
PostgreSQL. The final check requires exactly one execution-receipt replay and
no duplicate effects, incident or investigation. Receipts are bound to the exact
action payload; a changed action cannot reuse a key. A fresh database pool must
reconstruct identical terminal context.

The grader checks the committed numeric values against an independent oracle,
then checks their citations and statements in the durable report. It also
requires the missing diagnostic classes and causal uncertainty to remain visible.
Integration regressions deliberately change committed temperature to 88 °C,
corrupt an entity key and remove the incident-evidence link; each must fail.
The grader verifies the source event, incident evidence and automatic-start
lineage, as well as consistency between stored entity keys and identity labels. Other controls send a healthy XID value, no samples,
malformed JSON and conflicting identity aliases through parsing, storage and
the bridge; none may create an XID incident. These controls run in the database
integration suite; the JSON pipeline report describes the positive recovery case.

## Repeated Slurm failure coverage

The [Slurm monitoring guide](slurm-failure-monitoring.md) owns the rule and its
five new controls. The CLI runs those controls through real typed collection
finalization and the deployed outbox/sender interfaces, with a simulated HTTP
receiver. Three abrupt process exits cover incident commit, delivery claim and
receiver acceptance before its receipt commits. One incident/outbox intent must
survive replay; duplicate external delivery after the lost receipt is explicitly
expected. This additional Slurm contract requires a new baseline and is included
in comparison coverage. GPU monitoring episode/outbox delivery remains a separate
unmeasured stage; simulated Slurm delivery does not qualify a live Slack receiver.

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
passing. The eight scenario incidents are still explicitly admitted as fixture
inputs. The additional pipeline exercises loopback Prometheus intake and XID
incident/automatic investigation admission. Resident-agent mTLS intake,
GP-09 enrollment/episode/outbox and receiver delivery, live-model quality and
native-agent overhead remain unmeasured by this lab.
No scenario creates repair authority.

## Verification and extending the suite

`go test -race ./internal/testbed ./cmd/sherlock-testbed` checks fixture bounds,
comparison integrity and evaluator controls. The isolated integration suite
exercises the real controller, lost-critical-evidence grading, scope/window
filtering, later-evidence withholding, intake controls, corrupt-observation
rejection and crash recovery through fresh component construction. CI also runs
`make testbed` and retains its report, proving the original process restart and
six abrupt process-exit recovery boundaries. In-process database tests explicitly
report `IN_PROCESS_RECONSTRUCTION`; CLI results report `ABRUPT_PROCESS_EXIT`.

Add synthetic scenario input and independently reviewed expected observations
separately. Never infer an absent observation, copy a candidate report into the
oracle or silently regenerate a baseline to make a regression pass. Changes to
the suite intentionally require a new baseline and review of the new hash.
Customer-derived scenarios belong in approved private storage until sanitized.
Future slices should add resident transport, GP-09 episode/outbox delivery,
worker lease expiry, process death inside an open transaction, uncertain model
outcomes, and an opt-in live-model adapter with fixed budgets and repeated runs. Native hardware/resource qualification remains a separate mode.

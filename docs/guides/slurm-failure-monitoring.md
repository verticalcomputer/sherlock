# Repeated Slurm job failures

Sherlock can create a source- or node-scoped incident when a rolling window
contains enough **distinct failed attempts**. The feature is opt-in. Migration
81 and the control-plane loop do not enroll any policy or configure a receiver.
This is a rolling count, not a consecutive-failure streak or failure-rate model.

## Prerequisites and enrollment

Use the existing Slurm snapshot collector on the head/gateway with explicitly
configured `slurm.snapshot.v1` in `SHERLOCK_COLLECTION_OPERATIONS`, a Slurm source,
scheduler namespace/cluster and stable node mapping. The collector must have
local `squeue`, `sacct` and `scontrol` access and an enrolled collection schedule.
Its existing schema-support and visibility qualification requirements remain.
The monitor consumes committed, lease-validated typed snapshots; it never SSHs
into GPU nodes or launches diagnostics. Enabling this monitor does not enable
Slurm collection automatically.

Run local administration with the existing `SHERLOCK_DATABASE_URL` configuration:

```sh
sherlock-admin slurm-failures enroll \
  --cluster <cluster-id> --source <slurm-source-id> --namespace <scheduler-namespace> \
  --policy-id <policy-id> --threshold 3 --window 30m --fresh-for 5m \
  --expected-revision 0 --actor <local-operator>

sherlock-admin slurm-failures status --cluster <cluster-id> --policy-id <policy-id>

sherlock-admin slurm-failures disable \
  --cluster <cluster-id> --policy-id <policy-id> \
  --expected-revision <current-revision> --actor <local-operator>
```

Add `--node <stable-node-id>` for a node-scoped policy. Without it, the grouping
is the exact cluster/source/scheduler namespace. Existing data does not establish
a workload family, user or account, so the monitor does not infer those groupings
from job numbers. One failed multi-node attempt counts once per enrolled scope.
Only one enabled policy may own the same exact scope.

Policy IDs and content are immutable. Expected revision zero creates a policy;
reenabling an unchanged disabled policy requires its current revision. To change
threshold/scope, disable the old policy and enroll a new ID. Actor is local audit
attribution, not a verified principal; administration requires trusted database
access. Status includes incident/evidence/alert IDs, sampled attempt evidence,
notification attempts, pending/accepted/failed delivery and safe failure codes.

The defaults are three failures within 30 minutes with accounting fresh within
five minutes. Thresholds are bounded to 2–32, windows to 1 minute–24 hours, and
freshness to 30 seconds–1 hour. Enrollment may alert on already committed failures
within that window. No historical observations are manufactured.

## Counting and evidence

The [evaluator](../../internal/slurmfailures/evaluator.go) identifies an attempt by
scheduler namespace, job ID, submit timestamp and explicit attempt number.
Different attempts of one job and reused job IDs with different submit times are
independent. Repeated polling, overlapping accounting windows and CURRENT versus
ACCOUNTING copies of the same attempt do not increase the count.

Reviewed failure states are `FAILED`, `NODE_FAIL`, `OUT_OF_MEMORY`, `BOOT_FAIL`
and `TIMEOUT`. Cancellation, preemption, completion and `DEADLINE` do not qualify.
Conflicting failure/non-failure terminal records for the same attempt are excluded
and reported in status. Unsupported/missing attempt identity stays in existing
unresolved accounting storage; missing/future/out-of-window end times do not count.
A successful unrelated job does not reset the rolling failure count.

Migration 81 backfills an indexed lifecycle projection from existing immutable
Slurm facts. New projection entries commit with typed-result ingestion. Evaluation
reads at most 4,096 records, including conflicting records for candidate attempts;
exceeding that bound reports `INPUT_LIMIT_EXCEEDED` and does not open an incident.
A separate bounded control-plane loop checks up to 32 due policies per pass,
ordinarily every 30 seconds per policy. It is independent of GPU monitoring and
collection. Source removal, stale/unsupported accounting and collector revocation
prevent new alert publication. Freshness comes from the accounting observation's
source timestamp, never from replay/finalization time.

The [store](../../internal/store/postgres/slurm_failures.go) commits the incident,
immutable sampled evidence, episode, consumed attempt keys and outbox intent in
one transaction. Evidence remains `PARTIAL`: enough observed failures do not prove
complete accounting coverage or a physical cause. Snapshots retain the threshold
number of qualifying attempts and their original immutable record/run references;
the incident reports the full observed qualifying count. The investigation context
loader exposes that structured snapshot when the evidence is attached to an
authorized investigation. Monitoring enrollment grants no investigation or repair
authority; the separate investigation handoff below requires its own policy.

One active incident suppresses additional opening notifications. Newly observed
qualifying attempts during that episode are consumed. Missing data or a window
aging out never closes it. Operators use the existing incident lifecycle to resolve
or close an incident; rearming requires the threshold of previously unconsumed
failures whose end times are after that closure. Durable consumed keys are retained
to prevent late replay from paging again. Disabling/reenabling retains that history. Disabling stops new evaluation;
already queued notifications remain deliverable through the outbox.
Changing policy ID deliberately starts a new monitoring history.

## Notification delivery and failure behavior

The producer uses the existing `gp09_alert_outbox` and `sherlock-alert-worker`.
The worker must already be running with its protected Slack webhook file at
`/etc/sherlock/alert-secrets/slack-webhook.url`. No receiver credential enters the
policy, incident, evidence, outbox text or test-bed fixture. Notification text
contains safe cluster/source/policy identifiers, count/window and incident ID;
it does not expose job commands, user names or raw logs.

A missing receiver leaves messages pending. Retryable receiver failures remain
visible and use the existing bounded retries. Permanent failures/exhaustion stay
failed. Notification delivery is **at least once**: a receiver acceptance followed
by process death before the durable receipt may produce a duplicate Slack message.
The rule guarantees one transactional outbox intent per episode, not exactly-once
external delivery. Expired claims are replayable; stale claim owners cannot finish
newer leases.

Publication failure rolls back the incident and consumed attempt keys together,
so a later pass can retry the same facts. Status records a safe evaluation failure
code; raw database/source errors are not persisted or logged. Collection continues.
Rollback refuses to discard published Slurm monitoring history; preserve/archive
that history before a schema rollback.

## Investigation handoff and correlation

Slurm incidents can enter the existing durable investigation loop. This remains
separately opt-in: configure `SHERLOCK_AUTO_INVESTIGATION_ENABLED=true`, include
`slurm.job_failures.v1` in `SHERLOCK_AUTO_INVESTIGATION_RULES`, and explicitly allow
partial coverage with `SHERLOCK_AUTO_INVESTIGATION_ALLOW_PARTIAL_COVERAGE=true`.
Keep any other desired rules in the list. Configure the existing bounded worker
and investigator services, model, cluster authority and budgets; this document
does not enable a deployment. The default rule list and default-off policy remain
unchanged. Detection and notification delivery do not depend on model availability.

The bridge reserves one stable investigation for each committed Slurm episode,
using the existing severity, freshness, coverage, cooldown, concurrency and daily
token/cost gates. Outstanding reservations count against concurrency. Admission
is serialized across automatic detector families in a cluster. Status includes
`investigation_decision` and `investigation_id`; blocked decisions remain visible.
Disabled policy/rule does not consume an episode. Other policy blocks are recorded
once; a later policy change does not silently retry a blocked episode. An authorized
manual investigation or a new episode remains possible. `source_event_id` in the
shared reservation table is the Slurm episode occurrence, scoped by incident ID.

Before admission, the bridge freezes a bounded correlation snapshot. It resolves
only the cited immutable lifecycle facts and uses their exact node IDs, attempt
keys and end times. Each window starts at the later of known start time and 30
minutes before failure, and ends five minutes after failure, capped at admission.
These windows describe sampled context, not full job history. Missing node
membership blocks automatic admission; no cluster-wide fallback is granted. Missing
incident/evidence links or immutable attempt facts produce visible unavailable
decisions rather than manufacturing evidence or repeatedly stalling the bridge.
Scope is capped at 64 source/node identities and 24 hours. Each GPU observation
and network poll lists the attempt keys whose node/window it actually matched.

GPU correlation uses committed XID, temperature, power, ECC and utilization
observations, with unambiguous node/UUID labels. It scans at most 1,024 candidates
and freezes at most 128 matched records. Network correlation uses at most four
retained GP-09 network cycles and 64 matched polls. It includes read failures as
unavailable observations, preserves cycle IDs, and survives subsequent ring
pruning. The resident agent's separate telemetry history is not yet a correlation
source. Missing, stale/out-of-window, ambiguous and foreign observations are never
converted into healthy/zero measurements. Input limits and missing per-attempt
source coverage are explicit. Polling cannot establish lossless transient coverage.

A deterministic read-only `cluster.slurm_failure_evidence.v1` pass attaches only that incident's
failure/correlation evidence before model synthesis. Other episodes on the same
source/window cannot enter through this reviewed pass. Slurm admission grants zero
native diagnostic and privileged calls. The model sees bounded, cited normalized
facts and gaps; coincidence does not establish a hardware cause, progress or
GPU efficiency. A partial result does not resolve the incident automatically.
Reservation replay resumes the same request if a worker dies before acknowledging
the start. Migration 82 stores immutable correlation history and refuses rollback
when that history exists. No repair authority is added.

## Verification and boundaries

`make testbed` includes five Slurm controls: distinct attempts, repeated snapshots
of one attempt, cancellation/preemption, conflicting outcomes and reused job IDs.
Fixtures enter through real typed work claim/finalization, including lost-response
replay. It also abruptly exits three fresh worker processes after incident commit, after
claiming delivery and after simulated receiver acceptance, then finishes with a
fourth process. The lab advances only its disposable delivery lease clock. It
requires one incident/alert intent, three consumed attempts, three delivery claims,
one committed receipt and two simulated receiver acceptances after the lost receipt.
The real HTTP sender uses a durable simulated transport; no external Slack call is
made and no Slurm host is contacted.

Five additional abrupt exits cover investigation reservation, start before
acknowledgement, read completion before controller save, evidence recording and
terminal report commit. The lab requires one investigation/correlation snapshot,
one completed read action, two ledger entries, one identical read replay and one
simulated synthesis. GPU observations pass through the production Prometheus parser
and collection store. Network input is an explicitly simulated normalized cycle
fixture in the real retained-cycle table; native collection/enrollment is not
qualified. Foreign nodes and old polls are distracting evidence and must be excluded.
The actual production evidence executor, context loader, controller and orchestrator
must deliver XID 79, temperature 87, and the recorded DOWN/Polling port to synthesis.
The model remains simulated and its report retains causal uncertainty.

The isolated database tests additionally cover atomic rollback, safe error status,
concurrent evaluators, receiver retry visibility, collector revocation, legacy
backfill, meaningful investigation context and operator closure/rearming. The
[lab guide](test-bed.md) describes comparison/provenance and other scenario coverage.
Reports with changed Slurm contracts or lost coverage cannot silently compare as
equivalent. Live Slurm schema/visibility, workload overhead and real receiver
qualification remain deployment gates. Release signing stays parked.

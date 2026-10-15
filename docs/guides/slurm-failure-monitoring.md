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
authorized investigation. This feature grants no automatic investigation or repair
authority.

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

The isolated database tests additionally cover atomic rollback, safe error status,
concurrent evaluators, receiver retry visibility, collector revocation, legacy
backfill, meaningful investigation context and operator closure/rearming. The
[lab guide](test-bed.md) describes comparison/provenance and other scenario coverage.
Reports with changed Slurm contracts or lost coverage cannot silently compare as
equivalent. Live Slurm schema/visibility, workload overhead and real receiver
qualification remain deployment gates. Release signing stays parked.

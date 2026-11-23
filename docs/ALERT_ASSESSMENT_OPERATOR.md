# Alert assessment operations

Assessment v1 runs offline replay or isolated live shadow in `sherlock-control`. It is disabled by default and available in full control or `prometheus-upload` mode. Upload mode starts the assessment worker without starting full-control network monitoring, work dispatch or identity enrollment. It produces local investigation intents and comparison reports. Existing monitoring remains responsible for production incidents and notifications. No shadow assessment decision sends a hardware-team message or suppresses an existing alert. The separately enrolled production path below can publish cooling notifications; it remains disabled until explicitly configured.

## Configuration and enrollment

The optional component reads exactly these settings:

| Setting | Behavior |
| --- | --- |
| `SHERLOCK_ASSESSMENT_MODE` | `disabled` (default) or `shadow` |
| `SHERLOCK_ASSESSMENT_DATABASE_URL` | Dedicated restricted login; never inherited from the main database URL |
| `SHERLOCK_ASSESSMENT_CONFIG_FILE` | Strict bounded JSON enrollment file |

Use `test/assessment/v1/config.json` as a synthetic shape example. Supply explicit reviewed source, inventory, operation revisions and canonical GPU identities for a separately authorized live experiment. The example does not enroll a real cluster. Validate with `go run ./cmd/sherlock-assessment validate-config -config FILE` before starting control. Invalid optional settings, credentials, privileges, schema or enrollment disable assessment without failing the existing control loops. Configuration changes require a restart.

Run configuration and versions are immutable. A different policy, implementation, scope, duration or limit requires a new run ID. The store retains an immutable hash of the original admitted config as well as its canonical typed identity. After a codec rollback, the same original input or the exact canonical config can resume trusted expiry; a run without that input witness requires its canonical config. Only one ACTIVE or DRAINING run may exist. A matching configuration resumes durable state; a different run is rejected while the old run remains open. The experiment lasts at most 24 hours. It stops acquisition at its fixed cutoff and drains existing candidates at their original deadlines before closing. A shutdown or outage does not reset clocks; positive commit lateness remains visible.

## Optional cooling uploads

The existing V1 upload profile remains once per minute. Its reports are not
assessment-authorized scheduled evidence. For a separately enrolled cooling
experiment, both collector and upload intake can load
`SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE`, an absolute path to the **same exact
private JSON file bytes**. The file must be regular, not a symlink, at most
16 KiB, and inaccessible to group/other users. Its SHA-256 pins the profile;
reformatting it changes its identity.

The profile contains `version: 2`, `profile_id`, positive `revision`,
`collector_id`, `cluster_id`, `source_id`, `inventory_revision`, UTC
`starts_at`/`ends_at`, and sorted `assets` with `node_id`/`gpu_uuid` pairs.
Times align to 15-second boundaries, and the window is at most 24 hours.
Enroll at most eight physical GPUs across two nodes. There is no configurable
cadence: V2 samples only GPU temperature and board power every 15 seconds.
Use UUIDs from the current EXPECTED inventory, not GPU indexes or reported
fleet counts. The upstream Prometheus scrape must supply actual samples at this
cadence; a faster upload loop cannot create missing source observations. Registration must precede the first eligible sample slot.
A profile also has to fit the intake's existing collector/source allow-list.

The collector requires `SHERLOCK_PROMETHEUS_COOLING_SPOOL`, an existing absolute
0700 directory separate from the V1 spool; neither directory may contain the
other. V2 uses a separately bounded retry queue and does not request work or
execute diagnostics. It queries only the approved node/UUID identities, retains
original source timestamps, skips missed slots and never interpolates minute
samples. HTTP reports use protocol version 2 at
`POST /collector/v2/prometheus/cooling-reports`; the V1 route remains available.
Profile expiry stops new V2 sampling while V1 continues. Already sampled reports
can retry within the 15-minute retention window.

Migration 83 adds immutable profile authority and authenticated report receipts.
Provision the intake's explicit profile/receipt privileges with
[`scripts/cooling-upload-grants.sql`](../scripts/cooling-upload-grants.sql),
using `psql -v upload_role=EXISTING_INTAKE_ROLE -f scripts/cooling-upload-grants.sql` after migration 84 (the current script includes V3 authority columns).
Keep that role separate from the assessment login. Apply the optional
[`scripts/assessment-upload-grants.sql`](../scripts/assessment-upload-grants.sql)
with `psql -v assessment_role=DEDICATED_ASSESSMENT_LOGIN -f scripts/assessment-upload-grants.sql`
to grant profile/receipt reads only to the upload assessment login. Existing
scheduled-only assessment logins keep their original required grants. The server verifies collector identity, source ownership,
current inventory, profile revision/hash, time window and approved metric/GPU
scope before atomically committing observations and a receipt. The receipt's
server time determines when evidence becomes available. An upload cannot acquire
legacy job provenance by matching a schedule row. Old V1 reports are not
retroactively qualified, and one successful GPU cannot establish fleet coverage.
V2 evidence does not update fleet projections, source availability or production
collection events. Raw run/observation APIs retain this scoped history; fleet
health and production metric enrollment exclude V2 experiment runs.

Each assessment binding for this source must include `upload_profile_id`,
`upload_profile_hash`, and the independently pinned `upload_collector_id`, with `schedule_revision` set to the upload profile revision
and `scope_nodes` set to the sorted profile node list. Every binding in that run
must use the same upload profile, revision, hash and collector. Bind only
`DCGM_FI_DEV_GPU_TEMP` / `prometheus.gpu_temperature.v1` and
`DCGM_FI_DEV_POWER_USAGE` / `prometheus.gpu_power.v1`. Preserve the existing
policy thresholds and comparison arms. The enrollment's inventory and assets
must agree with the registered profile; a format-valid config alone does not
establish live admission.

Start intake with its normal `prometheus-upload` command plus the profile and
optional assessment settings. Do not start full control or remove unrelated
maintenance holds for this path. A missing profile leaves V2 disabled; optional
profile admission/runtime failures are logged safely without stopping V1.
`sherlock-collector prometheus-upload-readiness` also checks the configured V2
route without persisting reports. That probe checks authenticated routing, not
the remote profile hash or sensor coverage. Confirm actual receipts and qualified facts
in addition to readiness/log messages. A stale or invalid assessment login still
disables only assessment.

Profile contents cannot change under the same ID/revision. Provision a new
reviewed profile revision/window to change collection scope. Revocation is an
explicit database-owner operation on `prometheus_cooling_upload_profiles.revoked_at`;
it is monotonic and prevents subsequent receipt admission. Existing valid
history can settle pending assessment deadlines after natural profile expiry.
Retain the assessment worker after run closure for seven-day cleanup. Do not
reuse a closed run ID for a new experiment. Older binaries do not understand
upload bindings/provenance, and their privilege checks do not allow the new
profile/receipt grants. Preserve a compatible assessment worker for drain and
retention when rolling back intake or collector code; reverting a binary is not
a complete rollback of an admitted upload experiment.

A profile and a shadow run each last at most 24 hours. Allow initial evidence
warm-up inside the run and report its unavailable coverage. A complete live
qualification requires observed 15-second source samples, identity/receipt
provenance, bounded resource timings and no production notifications. Synthetic
or repository tests do not establish cooling detection quality or authorize a
client rollout.

## Database isolation

Migration 82 creates seven assessment tables, validation/accounting helpers and a dependency view. Production tables receive no new assessment write path. The dedicated pool is bounded to two connections; production source queries use ordinary snapshots, not monitoring authority locks. Each serial wake selects one GPU for new work, ordered by due time and last attempt; already-due arms run first regardless of that selection. The per-GPU work limit is 500 ms and the whole serial refresh limit is 2 seconds, including source loading and persistence. The one-second ticker does not overlap refreshes; slow passes coalesce ticks. Database statements remain limited to 200 ms and lock waits to 50 ms. These execution limits do not extend the 0/15/30/60/120-second observation arms or change shadow notification behavior.

`scripts/assessment-grants.sql` creates a NOLOGIN group and explicitly scoped grants. An authorized database owner provisions the login, password, CONNECT permission and membership. Admission examines effective privileges, including PUBLIC, authenticated/effective identities and reachable roles. Application routines beyond the exact reviewed validators, production mutation/maintenance privileges, schema creation, temporary-object creation and credential/receiver access are incompatible.

Existing PUBLIC privileges may make a new restricted login unsuitable. The script does not revoke shared production privileges automatically. A database security owner must review any required permission changes and preserve existing applications' explicit access before authorizing a live experiment. Disposable integration tests perform this setup only in their test databases.

## Interpretation

Temperature-qualified entry starts one physical sequence shared by all five budgets. Stable power is corroboration, not a reason to delay the entry clock. Supported concern or urgent evidence can conclude immediately. At a deadline, unresolved credible warming requests investigation with uncertainty. A valid category result and a host fallback have different provenance; a fallback has no fabricated category outcome or temperature baseline.

A qualified critical GPU/HBM occurrence is mirrored immediately when the exact scope is supported. Production urgent handling remains independent. Current source-wide telemetry-loss policies do not establish exact-GPU telemetry loss, so that live mapping is unavailable. Fixtures exercise the qualified exact-GPU contract without inventing a producer or expanding source events to GPUs.

UNKNOWN coverage means the evidence cannot establish the predicate. It is not a healthy-device result. Missing ground truth makes truth-based precision/recall unavailable. A known actionable label with no detection remains a miss. Investigation requests, supported detections, logical policy times and actual commit lateness are reported separately. Captured legacy rule evaluations do not count as delivered notifications.

## Offline reports and export

```
go run ./cmd/sherlock-assessment replay -suite test/assessment/v1/suite.json -out /new/private/output
go run ./cmd/sherlock-assessment replay -suite test/assessment/v1/unavailable-source-time.json -out /another/new/output
go run ./cmd/sherlock-assessment export -run RUN_ID -out /new/private/archive
go run ./cmd/sherlock-assessment replay -archive /new/private/archive -out /new/private/replay
```

Validation and replay do not connect to a database. Export uses only the dedicated assessment URL and a separate read-only repeatable-read snapshot. The first run read checks CLOSED state and the actual database clock against the seven-day retention deadline. An eligible snapshot can finish while cleanup proceeds, within the 30-minute export bound. Output directories/files are 0700/0600; existing paths and symlink inputs are rejected. The complete manifest is written last. Partial output is not a successful archive.

Archives use bounded NDJSON chunks and retain immutable assessment evidence rather than rereading source tables. Reconstructed ideal decisions remain separate from stored decisions affected by execution/storage failures. `EXECUTION_NOT_REPRODUCED` is not agreement. Quarantine makes scoring incomplete.

The synthetic source-time fixture exercises unknown physical ground truth and unavailable coverage using empty observation and legacy capture sets.

## Failure, shutdown and retention

A source-authority or acquisition-capacity stop drains retained candidates. The 4 MiB reserve is for deadline, failure and closure work. Already-due dispositions commit from retained evidence before source reads. An unavailable process/database can still miss a deadline; recovery records positive statement lateness. Failed refresh attempts, including scheduler timeouts, are retained for the next writable pass. A run cannot close while its pending failure summary is unsaved. A successful pass also records acquisition gaps longer than five seconds as unknown coverage, without inferring that scheduling delay proves an outage. Full diagnostic buffers retain bounded conservative coverage summaries; a capacity-blocked deadline resumes through the trusted host fallback. A matching run whose category codec is unavailable can drain using its pinned canonical configuration, but cannot admit new candidates. Untrusted host state is quarantined for inspection, not converted into an invented routed fallback.

Disabling assessment starts no pool or worker and leaves durable state unchanged. Re-enabling matching configuration resumes overdue drain. To finish an experiment normally, allow its configured duration and drain to complete. There is no new administrative stop API. Do not change production source schedules as a substitute for stopping assessment.

Closed evidence is retained for seven days. Restarting with the matching configuration of a retained closed run resumes cleanup only. The running worker continues cleanup after the run row is deleted. Use a new run ID for a new experiment. Cleanup deletes at most 100 rows per pass in dependency order. The down migration locks all assessment tables and refuses any retained data. It is not a data-deletion procedure.

## Qualification boundaries

Repository acceptance requires the package/CLI race checks, reproducible replay/archive exercises, `make check`, the disposable PostgreSQL 17 integration suite, independent review and successful maximum-profile resource/contention evidence. Record exact test scope and results in the pull request and CI. An optimized resource run must not be substituted with a race-instrumented timing claim or a workload that never reaches evaluation.

A live 24-hour shadow run, real hardware labels, delivery, production enablement and any suppression decision require separate enrollment, credentials, authorization and acceptance evidence. This implementation does not authorize them.

## Production cooling notifications

Production uses the same category evaluator with a distinct continuous lifecycle,
not a promoted shadow run. Migrations 84–86 add schema only; they enroll no
assets, enable no notifications and send nothing. Migrations 87–88 add explicit
fleet profile capacity and durable scheduling fairness; they also activate nothing.
Production supports at most 128 GPUs across 16 nodes per cluster enrollment.
Finite shadow runs retain their eight-GPU/two-node bounds. Existing urgent thermal
handling remains independently owned. Parallel live notification enrollment must
leave the existing warning and urgent routes active; replacing either route needs
separate outcome qualification.

### Production release package

Use the schema-2 collector/production package prepared and verified by the
existing collector release workflows. Its exact executable allowlist is
`sherlock-collector`, `sherlock-control`, `sherlock-alert-worker`, `sherlock-admin`,
`sherlock-api`, `sherlock-admin-ui` and `sherlock-migrate`, all for Linux/amd64.
The source archive includes the reviewed migration SQL and the production/upload
role-grant scripts. Verify all ten exact review digests and both signature bundles
before installation; the older collector/intake package does not contain the
production delivery or evidence UI binaries. See [release signing](guides/release-signing.md).

The package contains no webhook, database credentials, enrollment configuration
or service activation. Provision the existing protected Slack URL locally and
start only the explicitly selected commands. Shipping these executables does not
authorize full control, workload operations or notification activation.

### Continuous collection

V3 uses the same signed HTTP transport and 15-second temperature/power queries.
Its profile has `version: 3`, `state: "ENABLED"` or `"DISABLED"`, a strictly
increasing revision and an aligned `starts_at`. Its `ends_at` is zero; V2 retains
its original finite window and does not accept the V3 state field. Node/GPU,
collector, source and inventory identities remain explicit. V3 admits at most
128 GPUs/16 nodes; V2 remains limited to eight GPUs/two nodes. The eight-second
absolute source timeout, 1 MiB collection/report limit, 15-minute spool age,
122 pending reports and four retry uploads per five-second retry cycle remain
unchanged. V3 uses four bounded label-alias queries per metric, independent of
node count; exact node/UUID pairs are still checked before accepting samples.

Install the exact protected profile bytes on intake and the pilot collector,
using the existing profile-file setting. A shared intake can instead use
`SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILES`, a JSON array of one or two absolute
private profile-file paths. It is mutually exclusive with the singleton setting
and is not accepted by a collector. Each profile must match an authorized intake
binding; the authenticated collector and cluster select its profile. V3 files
are bounded to 64 KiB. Each head collector still receives only its own profile.
These are explicit operator operations,
not actions taken by the assessment host. The collector persists its highest
applied revision/hash in its private spool before sampling. A stale file, changed
bytes at the same revision, or V2 downgrade cannot undo an applied V3 state.
Keep that checkpoint during rollback. A profile family promoted to V3 cannot
register V2 again, even if a delayed V2 revision has a larger number.

Registering a successor revokes old receipt authority immediately. Pending old
reports are rejected, never relabeled; already admitted history remains usable
with its original provenance. Disabling centrally does not establish that a
 disconnected collector stopped. Apply the newer DISABLED file to the head and
verify its local persisted state/log separately. There is no remote stop deadline
or central applied-state acknowledgment in this file-based control protocol.

### Production host configuration

Run `sherlock-control assessment-production` as its own explicitly configured
process. This command starts only assessment: no listeners, collection dispatch,
Slurm loops, diagnosis or workload execution. Do not start full control merely
to enable cooling notifications. Leave `SHERLOCK_ASSESSMENT_MODE` empty or
`disabled` in this process; concurrent shadow capacity requires separate review.

Required environment:

- `SHERLOCK_PRODUCTION_ASSESSMENT_DATABASE_URL`: a dedicated production role.
- `SHERLOCK_PRODUCTION_ASSESSMENT_CONFIG_FILE`: a private regular JSON file,
  not a symlink, at most 64 KiB.

Provision the group privileges with
[`scripts/production-assessment-grants.sql`](../scripts/production-assessment-grants.sql)
on the explicitly selected database. Provision its login and CONNECT grant
separately. Never reuse a superuser, upload, shadow writer or workload-control
login. Startup checks reachable role capabilities and rejects privileges beyond
its table allow-list. PUBLIC or inherited CREATE/TEMP/system privileges can make
that check fail; review them and preserve other authorized services' grants
before changing privileges. Do not grant broad table access to bypass preflight.

The outer config is `{schema:1, revision:1, notifications_enabled:false,
evidence_base_url:"", assessment:{...}}`. The evidence origin is optional:
omit it or leave it empty for Slack messages without a history link. Messages
retain cluster/node/GPU identity, incident/occurrence IDs, concern/evidence times
and the investigation reason; full evidence remains stored in Sherlock.
If a history link is wanted, configure the real authenticated HTTPS origin.
Nonempty origins must still pass URL validation and cannot change within an
existing enrollment. Do not substitute a placeholder or relative URL.
Use the existing shadow assessment shape inside `assessment`, with:

- A unique stable `run_id` used as the production enrollment ID.
- `implementation:2`, `run_duration_seconds:0`, `budgets_ms:[120000]`.
- The same typed cooling policy and exact canonical assets/inventory.
- Upload bindings naming the continuous profile family, initial revision/hash,
  collector and sorted node scope. Only compatible admitted successor revisions
  are accepted; scope changes cannot expand the enrolled GPUs.

Keep the assessment configuration immutable for that enrollment. Changes to
notification enablement require a larger outer revision; a stale configuration
cannot undo an operator disable. In-flight candidates retain their deadlines and
old occurrences retain their identities. Initial deployment must keep
`notifications_enabled:false` until the separate activation gates below pass.
The 120-second observation ceiling permits early decisions; it is not a guarantee
that an unreachable Slack receiver accepts a message in two minutes.
Use a separate explicitly scoped evaluator and Slack worker per cluster rather
than one process per GPU. Execution limits remain 500 ms/GPU, two seconds per
serial refresh and two connections per evaluator,
200 ms SQL statements and 50 ms locks. Retention has an independent 250 ms
opportunity at startup and once per minute, sharing the same two-connection pool;
refresh failures cannot prevent this maintenance loop. Neither collection nor deadline retention
is a human acknowledgment or a cooling recovery. Fleet refreshes service bounded
slices. Due work runs first, with an acquisition opportunity reserved so a failed
deadline cannot indefinitely block new evidence. Durable attempt ordering resumes
fairly after restart. A GPU skipped because the slice is full is not reported as
an execution failure. Check actual full-fleet sweep time and overdue backlog:
the two-second refresh budget does not promise that every GPU finishes in one
refresh, and an overloaded or unavailable evaluator can commit a decision late.

### Slack delivery and operator controls

Use the existing `sherlock-alert-worker`, webhook file and sender. To claim the
new producer, explicitly set both `SHERLOCK_ALERT_ASSESSMENT_CLUSTER` and
`SHERLOCK_ALERT_ASSESSMENT_ENROLLMENT`; leaving either partially configured is
an error. An unscoped legacy worker does not claim production assessment intents.
The scoped worker must use the authorized database and existing protected file
`/etc/sherlock/alert-secrets/slack-webhook.url`. Do not put the URL in config JSON,
logs or this document.

Only validated, post-activation production concerns create new initial notices.
Shadow arms and historical shadow previews cannot send. Worsening and measured
recovery retain occurrence context. Delayed non-urgent history becomes one
bounded D2 catch-up, including an episode that recovered before first delivery.
Original events, evidence, intents, attempts and supersession are retained.
Slack/network receipt loss can still cause a duplicate remote message; stable
incident and occurrence IDs make that uncertainty visible.

Use the existing local operator command with dedicated database credentials:

```text
sherlock-admin assessment status --cluster CLUSTER --enrollment ENROLLMENT
sherlock-admin assessment history --cluster CLUSTER --enrollment ENROLLMENT --occurrence OCCURRENCE
sherlock-admin assessment acknowledge --cluster CLUSTER --enrollment ENROLLMENT --occurrence OCCURRENCE --expected-version VERSION --actor LOCAL_OPERATOR
sherlock-admin assessment maintenance --cluster CLUSTER --enrollment ENROLLMENT --occurrence OCCURRENCE --expected-version VERSION --actor LOCAL_OPERATOR --seconds 3600 --reason "hardware investigation"
sherlock-admin assessment disable-notifications --cluster CLUSTER --enrollment ENROLLMENT --expected-version ENROLLMENT_REVISION --actor LOCAL_OPERATOR
```

Actor is local attribution, not a verified remote principal. Expected versions
protect against stale changes. Acknowledgment records who saw the concern; it
never mutes delivery. Maintenance holds only the named existing occurrence for
1–86,400 seconds; zero clears it. Collection/evaluation continue and urgent
handling bypasses the hold. A leased message may still arrive. Clearing or
shortening an existing hold remains possible after physical recovery, but adding
or extending one after closure is rejected. Expiry releases D2 catch-up even if
no further samples arrive. A recurrence does not inherit acknowledgment or hold.

Disabling notification authority fences unclaimed intents and preserves their
DISABLED disposition. Already leased sends may finish. Re-enable is a larger
explicit config revision, never automatic replay of the previous queue. Keep
collector and assessment lifecycle controls separate. Stopping the process is
not proof that the source stopped or the physical condition recovered.

### Evidence, retention and activation gates

History links resolve on the existing admin UI at
`/admin/clusters/CLUSTER/assessment/ENROLLMENT/OCCURRENCE`. Both UI and API must
have verified human-session/cluster-membership enforcement enabled. The new
route refuses compatibility-only authorization. A member of another cluster
cannot inspect the history. The page includes events, proof, delivery and
operator audit with bounded pagination. CLI `--after` and `--after-audit` provide
the same event/audit continuation without dropping older history.

Closed occurrence evidence is retained for 90 days. Pending, leased, failed or
ambiguous delivery prevents automatic history cleanup. Active evaluation reads
only its rolling 15-minute evidence plus referenced proof, not 90 days of history.
Capacity failures remain visible in `assessment status`; do not respond by
silently discarding history or increasing execution limits.

Before parallel live enablement, reconcile every enrolled GPU UUID against fresh
source observations, verify both metrics' original-timestamp 15-second receipts,
measure full-fleet refresh coverage and deadline lateness under the chosen resource
caps, and verify the independent legacy/urgent routes remain active. Use the
existing webhook and explicitly scoped workers. Sherlock messages already start
with `Sherlock cooling`, distinguishing them from legacy GPU alerts. Do not
equate an absent Sherlock notice with a verified transient or successful delivery;
check evaluation and outbox state. When a history URL is configured, verify their evidence access too; otherwise
internal operators retain responsibility for retrieving Sherlock's stored proof. Review
at least 20 concern/transient episodes with zero missed actionable cases and at
most one unnecessary investigation request, recording the limited sample size.
Measure decision, publication and receiver delay separately. A separately
authorized test message is necessary to prove the actual webhook destination.
Repository fixtures establish none of these live facts. The episode review and
24 hours without unhandled execution-budget failures qualify any later warning
handoff; a separately authorized parallel rollout can collect that evidence while
both alerting paths remain enabled. It does not establish detection accuracy or
authorize suppressing the old rule.

For rollback, disable new publication and fence pending intents first; account
for leased messages. Preserve the production database and V3 local checkpoints.
Migrations refuse destructive downgrade when retained production authority or
history exists. Keep a compatible reader/retention process instead of dropping
records to make an older binary start. Changes to collectors, routing and services
require separate deployment authorization and must not affect running workloads.

### Refresh failure accounting and transaction diagnostics

Refresh/cleanup warnings retain the existing safe component codes and add
`refresh_elapsed_ms` or `cleanup_elapsed_ms`, plus bounded
`transaction_diagnostics`: stage, phase elapsed milliseconds, SQLSTATE when
available, error class, and commit outcome. These fields exclude SQL text,
parameters, connection strings, and PostgreSQL messages/detail/hint/context.
Elapsed `-1` means the error lacked an instrumented phase clock. A statement
cancellation (`57014`), serialization conflict (`40001`), or lock timeout
(`55P03`) identifies the database failure class; it does not prove the original
resource bottleneck. Use stage and elapsed time to narrow the next investigation.

Shadow failure summaries keep one pending aggregate and at most one coalesced
successor. If COMMIT returns an error, the attempted aggregate is frozen and its
PostgreSQL top-level transaction ID is checked before any replay. Confirmed
commit retires it without adding counts, coverage, or overflow again; confirmed
abort permits retry. In-progress or unavailable outcome pauses refresh writes
until a later bounded check resolves it. The normal successful flush performs no
extra outcome query. This uses PostgreSQL `pg_xact_status`, not a new table or
migration. Existing 500 ms GPU, 2-second refresh, 200 ms statement, and 50 ms lock
limits remain unchanged.

Pending uncommitted summaries remain process-local; a process exit can lose
those pending attempts, as before. Already committed rows survive restart.
Unavailable or aged-out transaction status is never treated as rollback; an
operator must investigate persistent `failure_flush.resolve` warnings rather
than infer exact counts. This change does not rewrite historical failure counts
or establish the cause of prior refresh stalls.

### Upgrade the production cooling evidence lookup

Use the migration set shipped with the new evaluator. Starting at schema 88,
the new set records the superseded index migration (89) and installs a small
lookup table in migration 90. Starting at 89, it installs 90 and preserves any
existing observations index. Keep intake running. If migration 90 reports
lock contention (SQLSTATE `55P03`), let the ingest transaction finish and
retry the migrator. A failed migration leaves the schema ledger at 89. Apply the
production assessment grants from the same release so the evaluator can read
the new table. Keep hardware notifications disabled during qualification.

New cooling receipts carry a completeness marker. In the same transaction,
PostgreSQL records references to the raw observations by run and entity. A
complete lookup can contain zero references for a report with zero samples.
The evaluator still checks the report's collection status, coverage, scope,
and raw observations. The marker certifies only the lookup.

Allow a full evidence window (normally 15 minutes) of new receipts. Check
each enrolled profile and revision against the original source slots and
inventory for both temperature and power. The following query measures the
lookup portion of readiness. Set the psql variables to the enrolled profile ID
and revision. Missing slots, partial reports, and missing GPU identities need
separate coverage checks even when every received report has a complete lookup.

```sql
SELECT u.profile_revision, r.query_kind, count(*) AS received,
       count(*) FILTER (WHERE u.observation_lookup_complete) AS indexed,
       min(r.scheduled_for) AS first_slot, max(r.scheduled_for) AS last_slot
FROM public.prometheus_cooling_upload_receipts u
JOIN public.collection_runs r USING (run_id)
WHERE u.profile_id = :'profile_id' AND u.profile_revision >= :'revision'::bigint
  AND u.received_at BETWEEN now() - interval '15 minutes' AND now()
GROUP BY u.profile_revision, r.query_kind;
```

Pre-upgrade receipts remain in Sherlock with their original evidence. Inspect
outstanding deadlines and older retained evidence separately before enabling
delivery. A missing lookup for a selected eligible receipt must leave acquisition
incomplete and records `RECEIPT_LOOKUP_INCOMPLETE`. Preserve the stored evaluator
state across restart. Back up and restore the lookup table together with its
receipts and raw observations so a restored completeness marker has its
corresponding rows.

Start with notifications disabled. Compare per-slot outcomes with raw evidence,
including partial reports and missing samples. Verify successful acquisitions
for every enrolled asset and check new failure counters, full sweep time,
intake lag, storage and WAL growth under simultaneous collection. The production
evaluator budgets are 500 ms per GPU and 2 seconds per refresh. Continuous
collectors still sample temperature and power every 15 seconds. The evaluator
schedules routine acquisition every 30 seconds and processes intermediate
evidence in order. An outstanding confirmation deadline can wake it earlier.
For an original upload, the logical clock is the server-assigned receipt time
when the committed receipt, collection run and observation share a writer and
the receipt falls after the asset’s checkpoint. A correction or a newly
discovered report from before that checkpoint takes effect at discovery.
A failed original report contributes missing-coverage evidence on the same
receipt clock. Short qualified thermal episodes can contribute both their open
and recovery transitions within one acquisition. If fresh input fails at a
confirmation deadline, the evaluator rechecks the deadline and can settle it
from retained evidence while recording the input failure.
The receipt time describes when the server accepted the report within its
transaction. Decision execution and persistence have their own timestamps.
Measure the time from source observation to decision separately from the time
spent waiting for qualification, confirmation, and delivery. A late actionable
decision remains eligible for delivery. Enable the scoped Slack workers only after live coverage and timing
pass. Keep the schema and receipt history in place if the evaluator needs to
be stopped or the application rolled back.

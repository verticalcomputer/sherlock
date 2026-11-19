# Experimental alert assessment

Assessment v1 runs offline replay or isolated live shadow in `sherlock-control`. It is disabled by default and available in full control or `prometheus-upload` mode. Upload mode starts the assessment worker without starting full-control network monitoring, work dispatch or identity enrollment. It produces local investigation intents and comparison reports. Existing monitoring remains responsible for production incidents and notifications. No assessment decision sends a hardware-team message or suppresses an existing alert.

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
using `psql -v upload_role=EXISTING_INTAKE_ROLE -f scripts/cooling-upload-grants.sql`.
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

Migration 82 creates seven assessment tables, validation/accounting helpers and a dependency view. Production tables receive no new assessment write path. The dedicated pool is bounded to two connections; production source queries use ordinary snapshots, not monitoring authority locks. Each serial wake selects one GPU for new work, ordered by due time and last attempt; already-due arms run first regardless of that selection. The per-GPU work limit is 250 ms and the whole serial refresh limit is 2 seconds, including source loading and persistence. The one-second ticker does not overlap refreshes; slow passes coalesce ticks. Database statements remain limited to 200 ms and lock waits to 50 ms. These execution limits do not extend the 0/15/30/60/120-second observation arms or change shadow notification behavior.

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

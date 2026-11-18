# Experimental alert assessment

Assessment v1 runs offline replay or isolated live shadow in `sherlock-control`. It is disabled by default and available only in full control mode. It produces local investigation intents and comparison reports. Existing monitoring remains responsible for production incidents and notifications. No assessment decision sends a hardware-team message or suppresses an existing alert.

## Configuration and enrollment

The optional component reads exactly these settings:

| Setting | Behavior |
| --- | --- |
| `SHERLOCK_ASSESSMENT_MODE` | `disabled` (default) or `shadow` |
| `SHERLOCK_ASSESSMENT_DATABASE_URL` | Dedicated restricted login; never inherited from the main database URL |
| `SHERLOCK_ASSESSMENT_CONFIG_FILE` | Strict bounded JSON enrollment file |

Use `test/assessment/v1/config.json` as a synthetic shape example. Supply explicit reviewed source, inventory, operation revisions and canonical GPU identities for a separately authorized live experiment. The example does not enroll a real cluster. Validate with `go run ./cmd/sherlock-assessment validate-config -config FILE` before starting control. Invalid optional settings, credentials, privileges, schema or enrollment disable assessment without failing the existing control loops. Configuration changes require a restart.

Run configuration and versions are immutable. A different policy, implementation, scope, duration or limit requires a new run ID. The store retains an immutable hash of the original admitted config as well as its canonical typed identity. After a codec rollback, the same original input or the exact canonical config can resume trusted expiry; a run without that input witness requires its canonical config. Only one ACTIVE or DRAINING run may exist. A matching configuration resumes durable state; a different run is rejected while the old run remains open. The experiment lasts at most 24 hours. It stops acquisition at its fixed cutoff and drains existing candidates at their original deadlines before closing. A shutdown or outage does not reset clocks; positive commit lateness remains visible.

## Database isolation

Migration 82 creates seven assessment tables, validation/accounting helpers and a dependency view. Production tables receive no new assessment write path. The dedicated pool is bounded to two connections; production source queries use ordinary snapshots, not monitoring authority locks. Each serial wake selects one GPU for new work, ordered by due time and last attempt; already-due arms run first regardless of that selection. The per-GPU work limit remains 50 ms and the whole pass limit 750 ms.

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

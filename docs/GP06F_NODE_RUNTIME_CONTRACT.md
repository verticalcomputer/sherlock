# GP-06f resident fixture runtime contract

Prepared October 8, 2026 before runtime implementation. This extends
[the telemetry v1 contract](GP06F_TELEMETRY_V1_CONTRACT.md); it is not installation
authorization, hardware source qualification or GP-06f acceptance.

The initial node binary requires explicit synthetic fixture mode. It reads the
Linux boot identity and creates fixture.v1 records only. It never runs SSH,
commands, diagnostics, updates or workload operations. Node TLS credentials
authenticate only to the pinned cluster-local gateway; there is no cloud
credential. Bootstrap/certificate issuance and renewal remain separate delivery
gates. Gateway/cloud current authority checks remain mandatory before receipts.

The owner-only allocator shares the queue's physical budget. Its atomic 0600
replacement is bounded to 1 MiB and fsyncs the file and parent directory. It binds
immutable enrollment/inventory/source/version/build/pin scope and retains at most
eight session identities, exact signed lifecycle messages, canonical uint64
sequence high-water, one pending allocation, and at most 256 gap delivery facts.
Missing allocator is allowed only for an empty newly initialized queue. Missing,
corrupt or ambiguous state in a used queue stops admission and preserves files.

Persist allocation/high-water before collection. Never decrement or reuse a
sequence. Restart with the same boot/key resumes the session. Proven reboot or
deliberate ACTIVE key rotation allocates exactly the next epoch after recording
the prior terminal sequence. OPEN is persisted locally before upstream delivery.
No session is retired from contact, finalization or coverage alone; the eight
session cap backpressures without the separately negotiated ownership-retirement
extension. The private operational evidence withheld
records its implementation/verification scope under the
[retirement contract](GP06F_OWNERSHIP_RETIREMENT_CONTRACT.md). Allocator version 2
uses an explicit retired epoch and durable pending release/completion; earlier
allocator bytes are refused and preserved rather than silently converted.

After interruption, exact queue lookup distinguishes OWNED, TRANSFERRED, LOST
and proven absence. Only proven absence can create an interrupted-allocation gap.
Durably sign the exact key/source fact under a separate local signature domain
before clearing pending allocation. Local `LOCAL_COMMIT_INTERRUPTED` maps to wire
`SOURCE_LOSS`; this mapping does not claim an observed source failure. Unknown
source observation times and record count stay absent/unknown. Journal capacity
and expiry losses retain their distinct mapped reasons. A signed carrier batch
or finalization transports the fact; only its exact durable gateway receipt proves
handoff. Gap capacity exhaustion stops admission, never silently drops evidence.

Fixture collection defaults to thirty seconds; ten seconds is the minimum.
An optional closed-identifier `fixture_boot_id` in the mandatory `--fixture`
configuration supplies an explicitly synthetic boot identity for portability
tests. Its omission uses Linux boot_id. It never asserts a measured host identity.
Network's ten-second sampling is a later source-qualification checkpoint. Replay
uses original bytes/timestamps without source rereads. Clock regression stops new
sampling rather than manufacturing monotonic observation timestamps.

The serial uploader sends lifecycle before dependent batches. It uses one
request in flight, a shared 32 KiB/s token bucket with 1 MiB burst, bounded retry
and cancellation, one fresh to three oldest data turns, and reserved control/loss
turns. Node ownership transfers only after a validated exact GATEWAY receipt is
persisted. Lost responses replay original bytes. An active node certificate can
relay old-key signed bytes using retained public verification keys. No old private
key is needed for replay. Cancellation joins workers before closing storage.
Each complete drain attempt has a five-second context. Collection defers before
allocating while transfer is active, then receives priority before another drain;
this prevents expiry or capacity eviction from racing a late gateway receipt.
Startup performs bounded expiry before upload, and selected expired entries are
discarded with durable local loss rather than sent as fresh samples.
`SPOOL_EXPIRED`/`SPOOL_OVERFLOW` assert local copy discard and may coexist with an
already received gateway/cloud sequence after a lost response. Original receipts
retain received coverage. `SOURCE_LOSS` cannot contradict received observations,
and no carrier can declare its own sequence lost.

Required repository evidence includes crash boundaries around allocation,
sealing, gap/receipt persistence and pending clearing; restart/reboot/rotation;
unsafe/missing/corrupt allocator and uint64 exhaustion; bounded gap/session caps;
outage/expiry/lost-response replay; fair drain/rate cancellation; and actual TLS
runtime-to-gateway-to-cloud fixture history without ordinary metric projections.
Source audit/reproducible build, installation, measured hardware adapter overhead,
certificate lifecycle, seven-day fleet soak and client acceptance stay separate.

`identity-request --directory ... --cluster ... --node ... --enrollment ... --key ...`
creates/resumes the owner-only local key and emits public CSR request JSON only.
`identity-import --directory ... --bundle ... --node-ca-sha256 ...` validates an
independently approved CA pin and imports a protected public issuance bundle.
Runtime config may use `identity_dir` plus `node_ca_sha256` instead of raw
`certificate_file`/`private_key_file`; these alternatives are mutually exclusive.
Imported certificate scope and local signing keys must match exact configured
node/enrollment/key. Neither local command issues enrollment or certificates.

At this fixture stage, configured version/build digest are approved synthetic
metadata, not evidence that the running executable was compiled from that source
candidate. Exact embedded candidate source digest/version, externally verified
binary SHA-256, reproducible builds and source audit are required build gates.
Release builds expose `version` with linker-bound `releaseVersion` and
`releaseSourceSHA256`. When that source digest is embedded, configured version and
digest must match before local runtime startup. Development builds expose
`DEVELOPMENT`/`UNKNOWN`; the executable SHA-256 remains externally verified.
The Go 128MiB memory target is soft; OS process limits and measured overhead still
require deployment/canary qualification.

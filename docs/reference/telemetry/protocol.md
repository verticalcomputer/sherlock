# Telemetry v1 protocol (GP-06f, GP-03, GP-23b)

This reference owns wire identity, signing, bounds and receipt semantics.
Admitted profiles are `fixture.v1`, `linux.host.v1` and `linux.rootfs.v1`;
[profile definitions](../../../internal/telemetry/profiles.go) and
[Linux source semantics](linux-sources.md) define exact fields. All currently
store scoped history without ordinary health/evaluator projection.

Implementation owners: [validation](../../../internal/telemetry/validate.go),
[canonical encoding](../../../internal/telemetry/canonical.go),
[cloud intake](../../../internal/store/postgres/telemetry_intake.go), and
[journal](../../../internal/telemetryjournal/queue.go). [Current status](../../../next.md)
owns release/live gates. Existing collector v1/v2 work, result, lease and diagnostic
protocols remain separate; telemetry grants no command, repair or update authority.

## Additive transport and authority

Cloud routes use the existing authenticated outbound collector transport:

| Route | Contract |
|---|---|
| `GET /collector/telemetry/v1/enrollments/{enrollment_id}/grant` | Current grant for exactly the authenticated cluster/gateway collector |
| `POST /collector/telemetry/v1/sessions` | Signed node session OPEN/FINALIZE, durable idempotent lifecycle receipt |
| `POST /collector/telemetry/v1/batches` | Signed node batch and matching gateway receipt identity; atomic durable cloud receipt |
| `GET /collector/telemetry/v1/enrollments/{enrollment_id}/status` | Scoped bounded enrollment/session/receipt/history status |
| `POST /collector/telemetry/v1/node-certificates` | Authenticated head relay of an operator-approved CSR-bound one-use token; immutable committed public certificate bundle |

Requests retain collector authentication and additionally require
`X-Sherlock-Telemetry-Version: 1`. Node gateway routes live on a separate pinned
mTLS listener: `POST /node-telemetry/v1/sessions` and
`POST /node-telemetry/v1/batches`. No node cloud credential is issued. An active mTLS key may relay an older
VERIFY_ONLY signature for the exact same node/enrollment. The old signature and
persisted session/key mapping remain mandatory; TLS identity cannot replace them.
This permits immutable replay after ordinary certificate/key rotation without
requiring an expired old certificate. Neither
endpoint accepts a work ID, lease token, shell, executable, arbitrary labels,
source URL, command or diagnostic grant. Reject unsupported versions explicitly.
Only identity Content-Encoding is accepted. The entire JSON body, including the
cloud envelope, is at most 1 MiB; reject unknown/duplicate keys, trailing values,
malformed scalars, excessive depth and oversize fields before storing or acking.

Enrollment is a protected local operator action with an immutable approved
cluster/node, expected inventory revision, source allow-list, gateway CollectorID,
Ed25519 node public key and key ID, allowed exact agent version/build digest and
resource policy. The actor is a supplied LOCAL_OPERATOR label, not a verified
human principal. Current expected inventory and active collector membership must
be checked under transaction locks. A gateway credential cannot create nodes or
widen scope. Disable/revoke/rotate use control revision compare-and-swap and an
immutable audit trail. No enrollment is inferred from a submitted hostname.

Gateway grants are authenticated responses over pinned outbound TLS, bound to
exact enrollment/control revision with TTL at most five minutes. Use a monotonic
running-process expiry; restart requires fresh polling before admission. Durable
cached provenance does not grant fresh authority after restart. Expired authority
blocks new and duplicate ingress acknowledgements; already owned bytes remain
retained. Cloud independently checks current node, key, inventory, source and
collector authority before dedupe on every replay. Compromised key or enrollment
revocation rejects all replay. Ordinary same-key certificate renewal preserves
original signatures; deliberate signing-key rotation retains at most two key epochs. A retired
key verifies only previously registered old sessions until their ownership is
retired; it cannot open a fresh session. Further rotation refuses while an old
epoch remains owned. A time cutoff must not strand acknowledged gateway bytes. Re-enrollment creates a new enrollment
ID and never silently imports the old journal's authority.

Bootstrap lasts at most ten minutes, is single-use, and is bound to the approved
CSR SPKI hash and node/enrollment identity. Possessing the token alone cannot
substitute a key. Certificates bind cluster/node/enrollment in their SAN and have
explicit expiry and renewal. Gateway CA/context plus SPKI pin are both checked.
Certificate issuance and bootstrap have explicit operator/relay/import interfaces
in the [identity reference](node-identity.md); a valid batch signature or test
principal does not substitute for them. Automated renewal is not implemented.

## Fixed wire identities and signed evidence

The batch key is `(cluster, node, enrollment, session_epoch, session_id, sequence)`.
Epoch/sequence/counters use strict canonical decimal uint64 strings, never JSON
floating point. Every batch commits enrollment/inventory revision, BootID,
SigningKeyID, exact agent version/build SHA-256, CreatedAt, source/schema/adapter/
profile versions, collection interval, field support, coverage, records and loss.
Maximum 16 sources and 4,096 records per batch. IDs are bounded, printable and
exact; source schemas own finite metric/unit/enum sets. Source-field support is
separate from source contact. No empty success, cached row or heartbeat proves
source coverage. Unknown, missing, unsupported and failed are distinct.

Canonical v1 uses a domain-separated, length-prefixed fixed-field binary encoding,
explicit scalar kinds and UTC instants, with sorted unique source/record/support/
loss identities and normalized negative zero. The canonical SHA-256 excludes
only digest/signature fields. This is not RFC 8785/JCS. Commit golden vectors and
ordering/timezone/large-counter fixtures. Ed25519 signs a separate
`sherlock.node-telemetry.signature.v1` domain plus the canonical digest. Validate
schema, body bounds and authority independently of the signature. Never mutate
caller arrays while canonicalizing. Gateway and cloud independently recompute.

Observation IDs and canonical entity identity are stable. Original ObservedAt and
CollectedAt are preserved. Replay can fill history but cannot become fresh
because it arrived late; older sessions cannot supersede a higher epoch's live
projection. Current fixture and Linux receipt histories stay separate from
ordinary metric projections and evaluators. Overlapping real sources require a
stable observation/deduplication policy before health projection is enabled.

Session OPEN binds epoch, random session ID, boot and enrolled signing key.
Process restart retains the same session. A proven new boot durably allocates
exactly the next epoch. Deliberate signing-key rotation also opens the next epoch
in the same boot; the epoch/session/boot/signing-key mapping remains immutable.
A process restart with unchanged boot/key keeps its session. Opening a higher
epoch fences prior sessions from live
freshness. At most eight unretired sessions per node. A signed FINALIZE references
the exact affected session and its durable last-allocated sequence, even when a
later boot signs the message. It does not assert missing data was received.
FINALIZE declares the durable terminal allocation even while payloads are still
owned locally. Retirement separately requires every sequence to be cloud accepted
or explicitly lost and an authenticated ownership-release handshake.
Unknown terminal sequence cannot be treated as complete. Corrupt/lost epoch or
sequence state requires reviewed re-enrollment; never reset counters silently.

Loss facts identify the affected session and sequence interval, source IDs,
reason and known record count. Both time bounds may be absent when unknowable;
absence is not a fabricated time interval. Unknown count is distinct from zero.
Loss may refer to an older session than its transport batch. Loss facts must be
signed and durably retained; loss storage failure stops admission.
`SPOOL_EXPIRED` and `SPOOL_OVERFLOW` describe local copy discard, not proof of
remote absence. After a lost response they may coexist with an already received
sequence; preserve both the immutable receipt and discard history, with received
coverage taking precedence. `SOURCE_LOSS` cannot contradict received evidence.
No carrier batch may declare its own sequence lost, regardless of reason.

## Ownership, receipts and failure behavior

Gateway receipt means local journal durability only. Cloud receipt means an
atomic authenticated store commit and binds the exact gateway receipt ID, batch
key and canonical digest. Matching replay returns the original immutable receipt;
conflicting digest/boot/session bytes reject. Authority/revocation checks precede
receipt lookup. Persist the receipt before responding, and record an upstream
receipt durably before unlinking locally owned payload. Lost responses cause
immutable replay, never recollection or timestamp refresh.

Node expiry/overflow first commits explicit loss to reserved storage, then removes
unacknowledged data. Gateway never TTL-deletes cloud-unacknowledged bytes: quota
causes backpressure to nodes. Receipts remain for ownership lifetime plus seven
days after cloud acknowledgement. Node may retire acknowledged bytes after
recording the matching gateway receipt and bounded sequence/range state; seven-day
receipt retention resides at gateway/cloud. Receipt exhaustion backpressures,
never silently shortens the promise. Expired proven accepted replay returns
REPLAY_EXPIRED, not a reconstructed success. A highest sequence is not a replay
floor: unknown holes remain unknown/admissible outside proven release ranges.
At most 256 disjoint intervals per disposition per session are retained; excess
fragmentation backpressures. Retired-through epoch advances only past fully
finalized sessions with proven ownership release and signed node completion.

Use fixed failure codes, not raw SQL, filesystem paths, source bodies, keys,
signatures or certificates in logs/errors. Corruption closes admission and replay;
preserve the original journal for review, do not initialize empty or quarantine
by silently moving away retained authority. Cancellation joins collection/drain
workers before closing storage.

The implemented [retirement extension](ownership-retirement.md) adds signed
release/completion handshakes and bounded receipt/session/key reclamation.
FINALIZE or cloud coverage alone cannot retire ownership. Local journal schema 3
rejects and preserves initialized schema 1/2 journals; no implicit conversion or
downgrade is supported. This compatibility rule applies to both fixture and Linux
profiles and does not revise earlier foundation acceptance.

## Numeric resource contract

| Resource | Node | Gateway per node | Gateway aggregate |
|---|---:|---:|---:|
| Total physical storage | 256 MiB | 512 MiB | 8 GiB |
| Payload ceiling | 176 MiB | 384 MiB | 7 GiB |
| Metadata, indexes, WAL, keys, slack | 64 MiB | 64 MiB | 512 MiB |
| Loss/contact reserve | 8 MiB | 32 MiB | 256 MiB |
| Staging reserve | 8 MiB | 32 MiB | 256 MiB |

Both category and total caps apply to actual physical files including sidecars,
temporary files and transactional peaks. Before admission leave at least 1 GiB
free filesystem space. Node payload expires at 24 hours; no gateway unacknowledged
TTL. Use owner-only 0700 directories/0600 files, no symlink/special-file traversal,
exclusive lifetime lock, bounded SQLite pages/transactions/checkpoints and
fsync/rename/directory-fsync ordering. Prove physical bounds under failure; a
payload byte counter or advisory WAL size alone is insufficient.

Implemented runtime defaults: a 30-second collection interval (configurable from
10 seconds to 24 hours), one node collection pass and one in-flight upload,
a 128 MiB Go memory target, and 32 KiB/s sustained transport plus 1 MiB burst.
The memory target is soft, not an OS-enforced RSS limit. Independent heartbeat,
GPU sampling and ten-second network sampling remain design work. Gateway at most four aggregate uploads and one per
node; round-robin nodes and one fresh then three oldest backlog turns. Lifecycle
records precede dependent batches; reserve bounded loss/contact dispatch. Deadlines,
retry backoff and jitter are bounded. No source reread during replay. CPU/GPU API
cost and throughput impact are measured canary gates, not guaranteed by limits.

## Required acceptance evidence

Fixture → node journal → real authenticated gateway → gateway journal → existing
outbound collector boundary → cloud transaction → scoped readback; preserve exact
versions/digests and prove no compute SSH. Inject crash/disconnect before/after
every durable allocation, file publish, receipt, response and unlink boundary.
Test concurrent matching/conflicting duplicates, missing/corrupt payload, process
lock/unsafe paths, quotas/free space/24-hour expiry/reserved loss exhaustion,
60,480 weekly receipts per node plus outage replay and WAL peaks, sparse hole
fills/fragmentation/session caps/boot restart/finalization/receipt expiry,
foreign node/cluster/collector/key/source/inventory, revocation before replay,
rotation, pinned TLS/CSR bootstrap, stale replay and old collector coexistence.
Run focused races, repository checks and fresh isolated persistence. Record
unimplemented interfaces rather than claiming a complete agent from fixture
library tests. Client source/build gates, installation, measured canary overhead,
two-cluster outage/reconnect/restore and seven-day soak remain separate.

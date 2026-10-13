# GP-06f ownership retirement contract

This implemented extension adds ownership release/completion to
[telemetry v1](protocol.md) and the [node](node-runtime.md) and
[gateway](gateway-runtime.md) runtimes. Earlier foundation acceptance is preserved;
current qualification is tracked in [next.md](../../../next.md).
Code owners are [protocol types](../../../internal/telemetry/release.go),
[journal handshake](../../../internal/telemetryjournal/release_handshake.go), and
[gateway orchestration](../../../internal/gatewaytelemetry/retirement.go).

## Purpose and compatibility

Retirement relinquishes payload ownership. It never asserts sensor health,
complete source observations or successful job progress. Missing observations
remain missing after retirement. `FINALIZE`, coverage and a prepared receipt
cannot release ownership. Existing NodeBatch/session signatures, golden fixtures,
collector v1/v2 protocols and their admission rules remain unchanged.

Retirement is an additive, separately versioned capability. Clients must obtain
authenticated retirement-v1 capability support before sending requests or
pruning. Unsupported peers retain the existing safe backpressure behavior. New
messages contain no commands, arbitrary paths or remote configuration.

## Shared proof and numeric limits

The separate Ed25519-signed `ReleaseRequest` binds protocol version 1, release
version 1, immutable release ID, exact cluster/node/enrollment/revision, session
epoch/ID, current signing key ID, creation instant, inclusive `FromSequence` and
`ThroughSequence`, and `ManifestDigest`. Decimal sequences are canonical uint64;
zero is admitted only for an explicitly empty finalized session. A release spans
at most 4,096 allocated sequence positions and contains at most 256 batch facts
and 256 loss references. The strict JSON envelope is at most 200 KiB. Bounded
interval proof must reject an unknown hole without iterating an unbounded range.

`ReleaseManifest` contains sorted unique `ReleaseBatchFact` entries with sequence,
original batch digest and exact gateway receipt ID, and sorted unique
`ReleaseLossRef` entries with source ID, loss ID and canonical fact digest.
Batch ordering is numeric; loss ordering is source ID then loss ID. The manifest
digest uses its own domain-separated, length-prefixed binary encoding. A loss
fact digest covers the exact original `SessionLoss`, including affected scope,
sequence/time bounds, reason and known-count state. Original absent times/counts
stay absent. Signing and digest domains are distinct from batch/session domains.

Each side independently validates the selected manifest facts against its durable
receipts and loss ledger and recomputes the digest. Additional already received
evidence may coexist with a selected local-discard fact; it need not be invented
in the node's manifest when the original acknowledgement was lost.
Every sequence in the proposed range must have either an exact
transferred batch receipt, or explicit loss covering every enrolled source.
A batch receipt proves transfer of that batch even if its source coverage was
partial; it does not imply all expected sources returned observations.
Local spool discard may overlap already received data after a lost response;
retain both facts and prefer received evidence for coverage. Do not invent a
batch digest/receipt for a lost allocation. Missing facts or an incomplete source
loss union block retirement.

Release ranges advance the independently proven contiguous ownership prefix
only. The next range begins at the previous committed prefix plus one. An
immutable release ID cannot change its range or manifest. At most one pending
release per session and eight pending releases per enrollment are permitted.
At most eight immutable recent release receipts per session are retained;
older committed ranges return a typed replay-expired outcome. Compact committed
prefix markers never stand in for original source coverage.

## Admission and durable handshake

Current authenticated grant, enrollment/inventory/source authority and signer
revocation are checked before matching replay. A current ACTIVE key may sign a
release for a known old session. VERIFY_ONLY may replay only its own exact
already admitted release. A release cannot create an unknown session or bypass
an undelivered/revoked predecessor OPEN. Reviewed re-enrollment remains necessary
for that case; automatic compromise recovery is not claimed.

1. Node proves disposition of the proposed range, seals the exact signed request
   and manifest durably, and fences original payload admission in that range.
   No node-owned original may remain in a sealed range. Restart replays the same
   pending release; a failed handoff cannot restore ownership or reuse sequences.
2. Gateway independently validates current authority, known session, exact
   manifest and local evidence, then commits `RELEASING` before acknowledging
   admission. It fences new originals while continuing delivery of originals
   already owned. Gateway-owned payload blocks cloud preparation.
3. Gateway forwards the original signed node request and manifest through the
   existing authenticated outbound boundary. Cloud independently verifies
   original immutable batch receipts, exact gateway receipt IDs, loss facts,
   session bounds and contiguous prefix. Its immutable `PREPARED` receipt binds
   release digest, manifest digest, scope/range, gateway admission ID and phase.
4. Gateway commits `RELEASED` locally, binding that exact preparation and a
   durable gateway commit ID, before sending a commit notice. Cloud commits an
   immutable `FINAL` receipt bound to the signed release, preparation, gateway
   admission/commit IDs and manifest. An arbitrary receipt ID is insufficient.
5. Gateway commits the exact cloud final receipt before returning a final gateway
   retirement receipt. Node verifies that complete binding and commits the final
   proof before compacting allocator/gap-delivery state. Every interrupted phase
   retries immutable facts; a lost response never implies a durable commit.
6. After durable local completion/compaction, node emits a separately signed
   `NodeReleaseCompletion` bound to the exact final receipt and release. Gateway
   relays that original completion; cloud records an immutable completion receipt
   and advances a separate node-completed prefix. Only this acknowledgement
   permits cloud session/key reclamation. Cloud FINAL alone cannot prove that
   the node actually compacted its pending state.

The shared types are `ReleaseRequest`, `ReleaseManifest`, `ReleaseBatchFact`,
`ReleaseLossRef`, `ReleaseAdmissionReceipt`, `CloudRetirementReceipt`,
`GatewayReleaseCommit`, `GatewayRetirementReceipt`, `NodeReleaseCompletion` and
`NodeCompletionReceipt`. Protocol validators are
pure and never grant authority from a signature alone. Local queue operations
separate node sealing/completion from gateway admission/preparation/commit/final
confirmation; a role cannot invoke the other role's ownership transition.

Cloud preparation fences new originals in the proposed range. Exact receipts
already committed before the fence may replay while retained; an absent original
cannot be introduced afterward, including after a lost PREPARED response. New
source-loss facts affecting the range are likewise refused unless already known.

A delivered batch may carry a loss declaration about an older session. Retiring
that carrier first must preserve the original loss fact and its exact local and
upstream receipt handoff before removing carrier links. This bounded historical
handoff lets the older affected range later prove delivery of its loss; it cannot
create a new loss, fill a missing observation or replace current authorization.
Startup validates the saved receipt scope, key, digest, durability and binding.

## Receipt expiry, session and key retirement

Gateway exact receipts remain for at least seven days after their individual
durable cloud acknowledgement, even if ownership release finished earlier.
Cloud-unacknowledged gateway payload never expires. Pruning requires the final
handshake and operates in bounded pages. Node pending allocation and gap carrier
recovery must understand typed `KNOWN_TRANSFERRED`/`RECEIPT_EXPIRED` results before
pruning is enabled. A pruned known key never becomes `ErrNotFound`, a new receipt,
new evidence or fresh telemetry.

Persist bounded sparse received, loss, released and receipt-expired dispositions
with at most 256 disjoint intervals per disposition per session. Coalesce only
adjacent compatible facts. Do not infer absence, transfer, loss or receipt expiry
from a greatest-seen sequence. A compact contiguous committed ownership prefix
is permitted only after the complete interval proof above.

At most eight unretired sessions remain. Collapse only contiguous fully finalized
sessions whose signed terminal allocation is entirely covered by final ownership
releases. Empty finalized sessions require the explicit terminal-zero proof.
Keep enough exact session identity for unexpired receipt reconstruction. A
durable retired-through epoch fences collapsed lifecycle replay; allocator epoch
allocation uses that base, never the current array length. Preserve unknown holes.

Reclaim a key slot only when every session it authenticated is finalized and has
final node/gateway/cloud release, with no owned payload, pending release or loss
delivery. Keep immutable archived key identity/epoch and revocation/audit history.
At most two authorized keys coexist; future epochs derive from global historical
maximum, not authorized count. Old key IDs/epochs are never reused. Node manual
key-list replacement must follow durable allocator/session compaction so removing
an old public key does not make retained signatures unverifiable.

## Persistence, failure and evidence gates

All new metadata remains within existing physical/category limits. Exhausted
intervals/releases/disk reserve backpressure without deleting evidence. Strict
body/count/page bounds, typed safe errors, per-node serialization and current
authority-before-replay remain mandatory. No local credential, signed release
or receipt authorizes repair.

Journal schema changes require an explicit version. Either qualify a
preservation-first isolated conversion with rollback evidence, or restrict the
candidate to fresh fixture journals and reject initialized older versions without
modification. No silent migration or downgrade claim is permitted. PostgreSQL
changes preserve historical receipts, facts and foreign-key references; populated
rollback must refuse when removing ownership evidence would be unsafe.

Acceptance requires focused adversarial tests, full repository checks and isolated
persistence tests: unknown holes/source loss union, exact receipt conflicts,
revocation before replay, all crash/lost-response handshake phases, recovery with
pending allocation/carrier, seven-day boundary measured from durable cloud ack,
live-session continuation after pruning, eight-to-nine sessions and key two-to-three
only after final release, bounded physical storage at worst declared counts, and
explicit old/new compatibility. Record exact source manifests and limitations.
Hardware sources, source/build/publication review, installation, certificate
lifecycle qualification and seven-day fleet acceptance remain separate gates.

## Implementing interfaces and compatibility

The retirement-v1 transport adds `X-Sherlock-Release-Version: 1` alongside the
existing telemetry version header. Duplicate or missing release versions are
refused before admission. The node's pinned TLS 1.3 mutual-authentication routes
are POST `/node-telemetry/v1/retirement/capabilities` with `{}`, POST
`/node-telemetry/v1/retirement/releases` with `ReleaseEnvelope`, and POST
`/node-telemetry/v1/retirement/completions` with `NodeReleaseCompletion`.
Admission without final proof returns backpressure; it cannot acknowledge final
retirement or node completion. Unknown routes on older peers remain unsupported.

The gateway's existing authenticated collector boundary adds GET
`/collector/telemetry/v1/enrollments/{id}/retirement-capabilities`, POST
`/collector/telemetry/v1/retirement/prepare` with `ReleasePrepareEnvelope`, POST
`/collector/telemetry/v1/retirement/commit` with `ReleaseCommitEnvelope` containing
the original signed request, and POST `/collector/telemetry/v1/retirement/complete`
with the original signed node completion. Returned receipts must bind the exact
request, phase, admission, preparation, commit and completion identities. A valid
signature alone does not establish a known session or current authority.

The local journal uses explicit schema 3 for fixture and Linux profiles.
Initialized schema-1/schema-2 journals are refused and preserved. There is
no in-place conversion or downgrade acceptance. PostgreSQL migration 79 adds
retirement proof and archived-key state; unsafe populated rollback refuses to
discard it. These are independent persistence boundaries.

Node allocator version 2 retains an explicit retired-through epoch and immutable
pending release/completion. Its compaction callback writes and fsyncs the bounded
allocator before the journal records completion; restart must resume that exact
proof. Gateway session compaction has no external allocator and persists its own
SQL base. It additionally requires the exact durable cloud FINALIZE handoff;
a locally received FINALIZE cannot be deleted before cloud delivery.

Receipt pruning handles at most 128 rows per maintenance turn and never applies
to gateway-owned bytes. Its seven-day clock starts no earlier than both the local
durable acknowledgement instant and cloud receipt timestamp. Historical public
keys are retained only for integrity verification, never current authority.
Current key lifecycle records, including revoked but unarchived keys, occupy at
most two slots. Archived identities and retained receipt-session identities each
have a 4,096-entry cap within the existing metadata budget; reaching either cap
backpressures. A key with no proven retired session cannot be reclaimed through
vacuous success. A known current ACTIVE successor session is required.

The running gateway does not silently adopt a refreshed signing key into its
local integrity archive. Reviewed rotation requires reopening its journal with
the current grant key set. A currently authorized but locally unarchived signer
is refused before session, release or completion admission; pending originals
remain intact. Historical lifecycle, release and completion signatures are
checked at startup against the saved integrity keys. This fail-closed behavior
is not automatic certificate/key rotation qualification.

The gateway runs at most four enrollment operations concurrently and serializes
one operation per enrollment. Each operation may include lifecycle/authority
polls plus one batch handoff or retirement mutation, all within the six-second
pass deadline. This is an operation bound, not a claim of one HTTP request per
operation. Unsupported peers retain their existing payload delivery path.

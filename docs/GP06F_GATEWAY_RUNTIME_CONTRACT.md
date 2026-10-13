# GP-06f gateway runtime foundation

Prepared October 8, 2026 before runtime composition. Extends the
[telemetry contract](GP06F_TELEMETRY_V1_CONTRACT.md) and
[node identity contract](GP06F_NODE_IDENTITY_CONTRACT.md).
This is fixture-only repository work; no service installation or live acceptance.

The separate gateway binary loads one bounded, owner-only reviewed configuration
and explicit enrollment IDs. It authenticates outbound using the existing
collector mTLS or Access Service Token proof-of-possession boundary, TLS 1.3,
normal server-CA/hostname verification and an independently approved control
server SPKI pin. The node listener uses a dedicated client CA, a separate server
identity, TLS 1.3 mTLS and the approved gateway SPKI. It exposes only the two node
telemetry routes. No remote commands, SSH collection, repair or updates exist.

Startup fetches current grants over the authenticated cloud path before opening
per-node journals; files cannot restore grant authority. Each journal uses its
immutable approved sources and session enforcement. All queues share one locked
8 GiB aggregate physical/category budget, with the existing 512 MiB per-node
budget. An unavailable startup authority prevents listening; no payload is
removed. A failed node intake never receives a false ownership acknowledgement.

The drain loop serves at most four different nodes concurrently, one request per
node, with round-robin selection, independent two-to-thirty-second backoff and a
six-second pass deadline. Each node journal chooses one fresh data batch for
three old data batches and a dedicated control turn every fifth turn. OPEN facts
are replayed in numeric epoch order before FINALIZE facts and dependent batches;
at most sixteen facts exist per enrollment. Lifecycle replay after restart uses
immutable cloud receipts. Per-batch OPEN replay is an additional bounded guard.
Finalization never asserts that holes were received or ownership retired.

Closed cloud authority/protocol failures pause the affected session for thirty
seconds in a bounded eight-entry running-process ledger. Journal bytes stay
owned in their original location; no deletion or manufactured loss occurs.
Other valid sessions continue through SQL-filtered selection, and attempted
turns advance fairness even on failure. Restart discards pause hints and
rechecks authority. `OWNERSHIP_BLOCKED` stays visible to the local observer.
If an old OPEN never reached cloud before its signing key was revoked, the next
epoch cannot bypass the missing predecessor. Preserve that evidence and require
reviewed re-enrollment rather than inventing old session authority. Deliberate
rotation therefore requires separately verified OPEN delivery; this foundation
does not claim arbitrary offline compromise recovery.

A cloud response transfers ownership only after exact batch key, digest,
gateway receipt, cloud durability and fixture-history receipt checks, followed
by a committed local acknowledgement. Failed network calls, lost responses,
local acknowledgement failures and malformed receipts retain local ownership.
There is no TTL deletion of cloud-unacknowledged gateway data. Cancellation joins
all draining and HTTP work before closing journals and the aggregate owner lock.

Resource qualification must include actual binary restart/disconnect, aggregate
concurrency limits, week-scale receipts within default limits and explicit
backpressure. Capacity, ownership retirement and receipt pruning remain separate
code gates, recorded by the additive
private operational evidence withheld and
[retirement contract](GP06F_OWNERSHIP_RETIREMENT_CONTRACT.md); no bounded happy-path flow constitutes client readiness. Source
review, reproducible release materials and client installation gates remain open.

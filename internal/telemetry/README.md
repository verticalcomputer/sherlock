# Telemetry protocol v1

October 13 extension: [Linux host/root filesystem sources](../../docs/LINUX_RESIDENT_SOURCES.md)
adds explicit source profiles and history-only intake. The dated fixture contract
below retains its original scope; source publication is complete, while signed
client release, native host/canary and fleet qualification remain open.

This package defines unsolicited, signed telemetry. It does not carry collector
work, leases, diagnostic grants or commands. The only admitted source profile is
`fixture.v1`; its values are synthetic and must remain separate from hardware
metrics, health evaluators and workload progress.

`ValidateNodeBatch` and `ValidateSessionMessage` check schema. `ValidateGrant`
checks the issued current lease and scope shape. `ValidateBatchForGrant` checks
the batch against that scope; `ValidateSessionForGrant` also checks its signature.
Callers must independently establish current inventory, gateway membership,
node/key enrollment, durable session authority, revocation and receipt state.
In particular, a VERIFY_ONLY signer may replay a matching registered OPEN, but
cannot open a new session. A cryptographic signature never grants enrollment.

Grant NotBefore/NotAfter are response lease times, at most five minutes. They do
not restrict historical batch CreatedAt. Old acknowledged gateway evidence can
remain history through a long disconnect. Current node/grant/key authority is
checked before every receipt lookup. Local grant admission uses a running
monotonic deadline and requires fresh authentication after process restart.

The complete cloud JSON body is at most 1 MiB. Node JSON reserves 512 bytes for
its cloud envelope; its limit is 1 MiB minus 512. Only identity Content-Encoding
is admitted. Exact JSON field names, duplicate keys, unknown keys, trailing
values, null scalars and excessive depth are checked before decoding. V1 admits
16 sources, 4096 records, and 256 loss facts total per batch. Fixture sources
have four fixed fields; missing and unsupported fields retain explicit states.

The fixture fields are `fixture.gauge` (finite float, unit `1`, gauge),
`fixture.counter` (exact decimal uint64, unit `count`, counter reset
`session_epoch`), `fixture.flag` (boolean, unit `1`, gauge), and `fixture.state`
(enum OK/FAULT/UNKNOWN, unit `1`, state). Other fields use reset
`not_applicable`. Their entity is the existing canonical NODE identity, obtained
from `domain.EntityIdentity.Key`, for example `fixture-cluster/NODE/node-a//`.
The stage4 profile makes no hardware-support claim.

## Canonical bytes

This is a custom versioned binary encoding, not JSON canonicalization. Integers
use big-endian uint64, array/string lengths big-endian uint32, booleans one byte
0/1, and timestamps UTC Unix nanoseconds in signed-int64 representation. Accepted
times are in years 2020–2200. Strings are length-prefixed UTF-8; reviewed IDs and
enums are bounded ASCII. Epoch/sequence/unsigned wire strings must use canonical
decimal notation; their binary representation is uint64. Float values use IEEE
754 binary64 bits, with negative zero normalized to positive zero. NaN/infinity
are rejected.

Node bytes begin with `sherlock.node-telemetry.digest.v1` plus a NUL byte. Fields
then follow this order:

1. ProtocolVersion; BatchKey (ClusterID, NodeID, EnrollmentID, SessionEpoch,
   SessionID, Sequence); EnrollmentRevision; InventoryRevisionID; BootID;
   SigningKeyID; AgentVersion; BuildSHA256; CreatedAt; source count.
2. Sources sorted by SourceID: SourceID; SchemaVersion; AdapterVersion;
   ProfileID; StartedAt; CompletedAt; Status; Coverage Expected, Returned,
   Complete; field count.
3. Fields sorted by EntityKey then Metric: EntityKey, Metric, State, Reason;
   then record count.
4. Records sorted by ID: ID; EntityKey; Metric; Unit; Kind; Reset; ResetObserved;
   ObservedAt; CollectedAt; Scalar kind string followed by its one typed value;
   then loss count.
5. Loss sorted by ID: ID; AffectedKey; ThroughSequence; time-known boolean;
   optional FromAt and ThroughAt; Reason; CountKnown; optional Count uint64.

Keys and scalar types use the primitive rules above. Loss refers to its original
session, which may precede its containing batch. Both loss time bounds are known
or both absent; unknown count is separate from zero. Canonicalization copies and
sorts slices without mutating callers. Digest/signature fields are excluded.
SHA-256 hashes these bytes. Ed25519 signs
`sherlock.node-telemetry.signature.v1` plus NUL plus the 32-byte digest.

Session bytes begin with `sherlock.node-telemetry.session.digest.v1` plus NUL:
ProtocolVersion; Kind; ClusterID; NodeID; EnrollmentID; EnrollmentRevision;
SessionEpoch; SessionID; BootID; SigningKeyID; CreatedAt; FINALIZE boolean;
optional LastAllocatedSequence; loss count; losses sorted by SourceID then ID.
Each session loss encodes SourceID then the loss fields from step 5. Ed25519
signs `sherlock.node-telemetry.session.signature.v1` plus NUL plus its digest.

FINALIZE signs the exact prior target session and durably known terminal sequence
at current signing time. Terminal zero is known empty; an absent terminal is
unknown and rejected. Finalized and cloud-covered are distinct from gateway
ownership retirement. Slice1 does not prune cloud sessions/keys/receipts or mark
Retired=true; a later authenticated ownership-retirement handshake is required.

The JSON fixtures under testdata fix node, OPEN and FINALIZE digests/signatures.
Their Ed25519 test seed is publicly specified as bytes 0 through 31. It is fixture
data, never an installation/release signing key. Golden tests verify schema,
canonical digests and signatures against those fixed vectors.

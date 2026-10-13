# Resident telemetry design (GP-06f)

This reference describes the resident monitoring boundary and remaining design
requirements. The [current status](../../../next.md) separates implemented
behavior from release and live qualification. GP-06f is step 4 of the
[implementation sequence](../../../implementation.md); canary qualification is
step 5. GP-06e retains its separately recorded legacy SSH acceptance.

Implemented foundations include signed batches, node-bound enrollment, protected
CSR relay/import, node mTLS, durable node/gateway queues, cloud history, fair
replay, ownership retirement and bounded receipt pruning. The admitted profiles
are synthetic `fixture.v1` and opt-in [Linux host/root](linux-sources.md).
All resident profiles currently remain outside ordinary health projections.

The [protocol](protocol.md), [identity](node-identity.md), [node runtime](node-runtime.md),
[gateway runtime](gateway-runtime.md) and [retirement](ownership-retirement.md)
references define their respective interfaces. Source code owners are
[the node entrypoint](../../../cmd/sherlock-node-agent/main.go),
[the gateway entrypoint](../../../cmd/sherlock-gateway/main.go) and
[central telemetry wiring](../../../cmd/sherlock-control/main.go).

## Authority and source boundary

The node agent pushes telemetry to its cluster-local gateway. The gateway keeps
Sherlock's outbound authenticated connection; cloud intake cannot initiate node
commands. There is no remote command endpoint, arbitrary executable/configured
shell, automatic update or repair authority. The release guides specify client
version pinning, upgrade and removal requirements; they do not provide a qualified
service installer.

The following GPU/network/process coverage requirements are planned source work:

Use a minimally privileged service and reviewed local read APIs for GPU/host,
filesystem and network facts. Reuse local exporter/DCGM/NVML interfaces where
supported; do not install a second conflicting exporter or require GPU profiling,
stress tests, device resets, workloads or driver changes. Declare every supported
driver/hardware/OS profile. GPU-process visibility is independently qualified;
agent presence alone does not prove idleness or exact job attribution.
BMC/Redfish credentials and polling stay at the head gateway (GP-23a).
Continuous events and optional optics are planned GP-06g sources; their resident
adapters and live coverage remain open.

## Enrollment and identity interface

An administrator approves cluster, expected node identity, inventory revision,
source allow-list, resource policy and exact agent version/build digest. Bootstrap is
single-use, short-lived and node-bound; possession cannot enroll another node.
Use mutually authenticated, pinned gateway identity and per-node credentials.
Document issuance, expiry, rotation, revocation and local key permissions.
Never share a fleet credential or embed cloud/control secrets in the agent.

Validate cluster/node/source identity at both gateway admission and cloud store.
Reconcile UUID/PCI/port GUID/boot identities with GP-02; numeric GPU/HCA index or
hostname alone cannot merge different devices. Inventory mismatch is explicit,
not an automatic change to expected membership. Unknown source support remains
UNKNOWN; confirmed unsupported differs from access failure or source silence.
Revocation blocks new submissions and replay under revoked credentials; define
any re-enrollment recovery explicitly without silently transferring old authority.

## Versioned batch and acknowledgement contract

The node-ingress and outbound collector interfaces are additive and versioned.
The [protocol](protocol.md) and [retirement extension](ownership-retirement.md)
define implemented routes, wire schemas and compatibility. Hardware coverage
must be qualified separately for each source profile.
Preserve existing v1 metrics, typed v2 collector plans/results and their leases;
unsolicited agent batches cannot forge collection-run results or diagnostic grants.

Each batch contains protocol/agent/source versions, cluster/node/enrollment
revision, boot/session ID, monotonic sequence, sample/event identifiers, payload
digest, observation/collection times, units/semantics, expected coverage and
explicit omissions/gaps. Gateway and cloud receipts bind their own durability
times separately. The protocol versions identity and counter-reset rules and
bounds bytes, records and identifiers. Compressed request bodies are rejected.
Reject foreign identities, digest conflicts, malformed values and unsupported
versions with typed outcomes; never silently accept a partial batch as complete.

Persist accepted batches and their receipts atomically in a durable gateway
journal before acknowledging the node. Acknowledgement means gateway durability,
not cloud persistence. The gateway retains ownership until Sherlock commits
idempotent intake and returns a durable receipt; only then may it retire bytes.
Duplicate identity plus matching digest returns the same receipt; conflicting
bytes are rejected. Crash/restart/lost acknowledgements must preserve this rule.
Retained receipts cover the replay horizon; sequence gaps are visible even after
receipt expiry. Older replay may fill history but cannot become fresh evidence,
clear a newer fault or override a newer projection.

## Cadence, spooling and failure behavior

The implemented collection loop defaults to 30 seconds for fixture and Linux
sources, with bounded upload concurrency, deadlines, retry jitter and backoff.
Network sampling every 10 seconds and GPU sampling/independent heartbeats every
30 seconds remain design targets. There is no separate periodic heartbeat source
in the current runtime. A future heartbeat must distinguish service contact,
queue health and source freshness; contact cannot prove every source works.
Expired credentials/clock skew must remain distinguishable from source health;
client wall time cannot erase gaps.

The node spool is capped at **256 MiB or 24 hours**, whichever binds first.
The journal defaults to a 1 GiB minimum-free-disk reserve. The [numeric resource
contract](protocol.md#numeric-resource-contract) records gateway aggregate/per-node
storage, transport and concurrency bounds. OS CPU/memory enforcement and actual
workload overhead still require reviewed deployment settings and canary evidence.
Reserve space for loss records and current contact. Overflow/expiry records the
source, sequence/time interval, reason and count where known; unknown counts
stay unknown. Loss of durable storage prevents a success acknowledgement.
Reconnect drains fairly without starving fresh samples or other nodes. Collection
failure and transport failure remain separate, and no reconnect implies healthy
coverage during the gap. Define spool corruption/quarantine and safe uninstall
handling; never delete retained evidence implicitly on version upgrade.

## Source-audit/build gate before client installation

Before client installation, complete the applicable [release review](../../guides/release-review.md)
and [signing](../../guides/release-signing.md) gates: disclosure/secret inventory,
reviewed public/private manifest, Apache-2.0 and
ownership/dependency notices, auditable source for the exact candidate, reproducible
builds, permission/payload/endpoint documentation, signed checksums, provenance,
SBOM, independent review and pinning/removal instructions. Clients must be able
to inspect the source and verify the running binary against the reviewed release.
Keep actual credentials, inventories and operational evidence private.
Exact-candidate publication review and publication precede general fleet rollout.

## Repository and canary exit gates

1. Fixture → agent batch → gateway journal → outbound authenticated intake →
   scoped store/API succeeds without compute SSH; record all versions/digests.
2. Crash before/after each durable acknowledgement; restart, disconnect, replay,
   conflicting duplicate, foreign node/cluster, revocation and rotation tests
   preserve ownership, gaps and idempotency. Test quota/expiry/disk-full behavior.
3. Mixed old collector/new agent versions coexist; unsupported versions fail
   explicitly. Prove no duplicate evaluator observations when sources overlap.
4. Focused tests, repository checks and isolated persistence tests pass. Commit
   the wire/compatibility and numeric resource policies, then review the exact
   client candidate against the source-audit/build gate.
5. In a separately approved canary, measure CPU, memory, disk writes, bandwidth,
   GPU API costs, workload throughput/latency and collection coverage against a
   pre-install baseline. Declare overhead limits and stop/rollback criteria
   before the run; measured impact must meet them. No workload interruption is
   assumed from design alone. Verify independent source coverage and uninstall.

Retire routine SSH per node only after all required replacement fields, event
coverage where required, identity, freshness and failure cases are verified.
GP-06e's historical acceptance is not redefined. Later GP-23 rotation/outage/
restore and seven-day two-cluster monitoring soak still close R1; repair remains R3.

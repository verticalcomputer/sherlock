# GP-06f — resident telemetry agent and cluster-local gateway

October 13 extension: [Linux host/root filesystem sources](LINUX_RESIDENT_SOURCES.md)
adds explicit source profiles and history-only intake. The dated fixture contract
below retains its original scope; source publication is complete, while signed
client release, native host/canary and fleet qualification remain open.

Status (2026-10-08): **fixture foundation repository-accepted; GP-06f open and not installed**. Step 4 of the
private implementation history withheld; canary is step 5. Depends on GP-18c,
GP-02 canonical identity/semantics, GP-03 typed ingestion and GP-23b spooling.
GP-06e remains the separately accepted legacy SSH implementation.

The detailed [telemetry v1 contract](GP06F_TELEMETRY_V1_CONTRACT.md) fixes routes,
wire identity, signing, ownership, lifecycle, numeric bounds and staged repository
acceptance before active implementation. It does not establish installation or
hardware coverage.

The active foundation now includes strict signed fixture messages, scoped cloud
authority/history, atomic receipts, protected CSR-bound bootstrap, dedicated node
TLS, runnable fixture node/gateway binaries, fair replay and shared physical
storage limits. The private operational evidence withheld
records actual binary outage/restart flow and the passing frozen-candidate full
repository/isolated database gate. Receipt/session ownership retirement,
long-term pruning, exact source/build review and client qualification remain open;
the foundation safely backpressures at its documented receipt/session/key caps.
The prepared [retirement contract](GP06F_OWNERSHIP_RETIREMENT_CONTRACT.md),
[node identity](GP06F_NODE_IDENTITY_CONTRACT.md),
[node runtime](GP06F_NODE_RUNTIME_CONTRACT.md) and
[gateway runtime](GP06F_GATEWAY_RUNTIME_CONTRACT.md) contracts separate these gates.

## Authority and source boundary

The node agent pushes telemetry to its cluster-local gateway. The gateway keeps
Sherlock's outbound authenticated connection; cloud intake cannot initiate node
commands. There is no remote command endpoint, arbitrary executable/configured
shell, automatic update or repair authority. Client-controlled installation,
version pinning, upgrade and removal are documented and reversible.

Use a minimally privileged service and reviewed local read APIs for GPU/host,
filesystem and network facts. Reuse local exporter/DCGM/NVML interfaces where
supported; do not install a second conflicting exporter or require GPU profiling,
stress tests, device resets, workloads or driver changes. Declare every supported
driver/hardware/OS profile. GPU-process visibility is independently qualified;
agent presence alone does not prove idleness or exact job attribution.
BMC/Redfish credentials and polling stay at the head gateway (GP-23a).
Continuous events/optional optics are separately qualified by private operational evidence withheld.

## Enrollment and identity interface

An administrator approves cluster, expected node identity, inventory revision,
source allow-list, resource policy and supported version range. Bootstrap is
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

Implement an additive node-ingress interface at the gateway and a separately
versioned outbound telemetry-ingress interface in Sherlock. Final route names,
wire schema, compatibility matrix and generated examples must be committed
before implementation acceptance. The prepared v1 contract identifies the
implemented synthetic foundation routes; hardware source APIs remain unqualified.
Preserve existing v1 metrics, typed v2 collector plans/results and their leases;
unsolicited agent batches cannot forge collection-run results or diagnostic grants.

Each batch contains protocol/agent/source versions, cluster/node/enrollment
revision, boot/session ID, monotonic sequence, sample/event identifiers, payload
digest, collection and receipt times, units/semantics, applicability, expected
coverage and explicit omissions/gaps. Version the identity and counter-reset
rules. Bound compressed and decompressed bytes, rows, labels and timestamp skew.
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

Defaults are network samples every 10 seconds, GPU/host samples and heartbeats
every 30 seconds. Use bounded concurrency, deadlines, jitter and backoff. A
heartbeat reports service contact, queue health and source-specific freshness;
it is not proof that every source works. Expired credentials/clock skew remain
visible without trusting client wall time to erase gaps.

The node spool is capped at **256 MiB or 24 hours**, whichever binds first.
Define an additional minimum-free-disk reserve before installation. Cap gateway
aggregate/per-node spool, memory, CPU, bandwidth, batch size and replay rate with
documented numeric configuration before canary; no unbounded queues or retries.
Reserve space for loss records and current contact. Overflow/expiry records the
source, sequence/time interval, reason and count where known; unknown counts
stay unknown. Loss of durable storage prevents a success acknowledgement.
Reconnect drains fairly without starving fresh samples or other nodes. Collection
failure and transport failure remain separate, and no reconnect implies healthy
coverage during the gap. Define spool corruption/quarantine and safe uninstall
handling; never delete retained evidence implicitly on version upgrade.

## Source-audit/build gate before client installation

Complete the installation subset of the six private operational evidence withheld:
disclosure/secret inventory, reviewed public/private manifest, Apache-2.0 and
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

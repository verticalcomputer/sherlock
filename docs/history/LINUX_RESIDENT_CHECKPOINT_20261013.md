# GP-06f Linux resident-source repository checkpoint — October 13, 2026

This checkpoint implements the [prepared host/root contract](../reference/telemetry/linux-sources.md)
in the existing GP sequence. It preserves fixture signatures/defaults, existing
collector routes and ownership replay. GP-06f and R1 remain open.

## Delivered behavior

The opt-in node mode samples six host fields and five root filesystem fields
through fixed read interfaces. Exact integer bytes/inodes, explicit support,
partial/failed coverage and signed observation times survive node/gateway/cloud
history. Enrollment, grants and local allocator state bind each declared source
to its immutable closed profile. Legacy omitted profile mappings remain fixture
scope. Gateway startup checks explicit mode and current authenticated authority.

Migration 80 extends only the source-profile allow-list; its down migration
refuses to discard or reinterpret non-fixture enrollments/history. Root statistics
use a pinned descriptor and verified own-proc mount identity. Mount replacements
cannot redirect the statistics read to a newly mounted remote filesystem.

## Verification scope

- Focused race tests cover schema/profile rejection, failed-read durability,
  same-boot restart, immutable scope and exact replay without a source reread.
- Full `make check`, fresh `make test-integration-isolated` and `make eval` pass.
  Isolated PostgreSQL exercises fixture and both Linux wire profiles across real
  pinned TLS boundaries, both lost acknowledgements, journal/cloud restart,
  foreign identity rejection, original partial status/timestamps and rollback
  preservation. These wire values are explicitly synthetic test observations.
- Linux/arm64 package tests pass in a disposable read-only container with no
  networking. They exercise actual fixed proc reads and own descriptor mount
  identity, plus deterministic replacement ordering and bounded parser cases.
  Linux/amd64 `go vet ./...` and `staticcheck ./...` also pass. The mount-race fix
  received a second independent code review with no remaining actionable finding.
- Two clean offline Linux/amd64 builds are byte-identical. Their build-input
  source manifest is `e33c96b5ad2bb984f1bedf09b11713ba72e9137815ae131142ae39109bed91e2`.
  This is separate from the public repository manifest and does not hash itself
  or claim to represent all backend/tests. The source package includes the new
  permission/payload contract. Detailed generated evidence remains private.

The builder retains the legacy `fixture.v1` preview package version; binary
`supported_profiles` declares the additional experimental capabilities separately.
Neither that version nor reproducibility approves Linux client installation.
Signed preview publication, exact commit/package review, and real signing remain
separate release gates.

## Open gates and next work

The sources are history-only: ordinary health/evaluator/API/UI projections do not
yet consume them. GPU and network adapters, GP-06g passive events/optics, gateway
BMC, measured CPU/memory/I/O/bandwidth and workload impact, certificate lifecycle,
authorized native-host canary, backup/restore and seven-day two-cluster soak remain
open. Container tests do not qualify native host/root-device behavior or overhead.
No client service, workload, node, production schema or SSH cadence was changed.

Continue exact-source and signed-release qualification after protected PR review,
then the remaining source adapters/canary and advanced detection in
[implementation.md](../../implementation.md). Replay of the six reported incident
classes must distinguish absent evidence from missed detection. Existing GP-06a,
GP-06c and GP-06e acceptance remains unchanged; monitoring grants no repair authority.

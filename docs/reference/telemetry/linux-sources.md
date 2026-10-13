# GP-06f Linux host and root filesystem source contract

This extends [telemetry v1](protocol.md) with opt-in host/root collection.
Code owners: [profile schema](../../../internal/telemetry/profiles.go),
[collector](../../../internal/linuxtelemetry/collect.go),
[Linux reads](../../../internal/linuxtelemetry/read_linux.go), and
[scoped cloud readback](../../../internal/store/postgres/telemetry_read.go).
See [current status](../../../next.md) for remaining release and live gates.

## Interface and scope

The closed profiles are `linux.host.v1` and `linux.rootfs.v1`, with
`schema_version: 1` and `adapter_version` equal to the exact profile string.
Enrollment and local scope may specify `source_profiles`, a
map from an already declared source ID to its exact profile. Omitted entries
retain `fixture.v1`; extra IDs and unknown profiles are rejected. Profiles are
immutable enrollment and allocator scope. A profile change needs new enrollment
and journal roots, preserving old owned data. Existing fixture signatures, wire
encoding, defaults and collector v1/v2 work routes remain unchanged. Old binaries
reject new profiles explicitly. Migration 80 extends the database allow-list;
rollback refuses while non-fixture enrollments remain, preserving their data.

The node requires an explicit `--linux` mode, at least one Linux source, no
fixture source and no synthetic boot identity. `--fixture` retains its old scope.
The gateway requires explicit `--telemetry` for these enrolled sources; legacy
`--fixture` accepts fixture enrollments only. Gateway config selects exactly one of
`fixture_only: true` or `resident_sources: true`; command-line mode must match.
The version output retains `profile` as the legacy fixture default and exposes
`supported_profiles` separately; capability is not qualification. This grants no commands or updates.

| Profile | Fixed metrics | Read interface |
| --- | --- | --- |
| linux.host.v1 | `host.memory.total_bytes`, `host.memory.available_bytes`, `host.load.one`, `host.load.five`, `host.load.fifteen`, `host.uptime_seconds` | `/proc/meminfo`, `/proc/loadavg`, `/proc/uptime` |
| linux.rootfs.v1 | `filesystem.root.total_bytes`, `filesystem.root.free_bytes`, `filesystem.root.available_bytes`, `filesystem.root.total_inodes`, `filesystem.root.free_inodes` | `/proc/self/mountinfo`, filesystem statistics for `/` |

Records bind the enrolled node entity; root metrics describe only the root mount
slot in the agent's mount namespace, not a device identity or all mounts. This
profile requires native host deployment to interpret values as host telemetry;
the reader itself does not prove it is outside a container. No process names,
commands, user directories, file contents, remote paths or arbitrary labels leave
the node. Root reads are restricted to ext2/3/4, XFS and Btrfs. Overlay, network,
FUSE and unrecognized roots are explicitly unsupported. The root descriptor is pinned with O_PATH; bounded proc fdinfo mount identity
must match the allowed mountinfo row before Fstatfs on that same descriptor.
Mount metadata is checked again after the read; change/ambiguity yields unknown coverage. No directory
walk, file attribution or network filesystem statistics are performed.

## Semantics and failure behavior

All fields are gauges. Memory and filesystem bytes/inodes use exact unsigned
decimal integers; load and uptime use finite nonnegative floats. Proc `kB` means
1024 bytes. `MemAvailable` is the kernel estimate, not `MemFree` or a computed
fallback. Missing fields stay UNKNOWN/MISSING; malformed/oversized input stays
UNKNOWN/SOURCE_FAILED; permission errors stay UNKNOWN/ACCESS_DENIED. No missing
value is replaced with zero. An individual read failure does not discard other
successful reads or stop runtime collection. Complete/partial/failed coverage
and original observation times are signed. Root free bytes include reserved
blocks; available bytes exclude them. Inode zero totals indicate unavailable
inode accounting, not an exhausted filesystem.

Proc files use fixed paths, no leaf symlink traversal, verified procfs descriptors and
bounded reads (64 KiB each; mountinfo 256 KiB, own root fdinfo 4 KiB). Collection is serial, defaults to
30 seconds and uses the existing bounded spool/replay/rate policy. Kernel reads
are synchronous; context is checked between reads, not represented as a hard
kernel I/O deadline. OS resource enforcement and measured workload impact need a
separately approved Linux canary. No native process/performance claim comes from
portable parser tests or successful cross-compilation.

Gateway/cloud validation binds profile, source, node, enrollment and signing key.
Replay retains signed bytes; it never rereads the host. History/status exposes
values, support and gaps. These sources remain history-only until a separately
qualified freshness/evaluator projection is implemented; a durable receipt is
not a health verdict. No SSH source is retired by this checkpoint.

## Acceptance evidence

Require malformed/overflow/missing/denied/unsupported parser and schema tests,
profile/identity rejection, same-boot restart and lost-response replay without
rereads, mixed fixture/new enrollment compatibility, and real isolated database
intake/status/rollback-preservation tests. Full repository checks and isolated
persistence tests precede the public PR. Public manifest hashes must match the
exact source. Signed client release, native Linux resource/certificate canary,
GPU/network/events/optics, advanced detection, workload progress and fleet soak
remain open.

Semantics follow the [Linux proc documentation](https://docs.kernel.org/filesystems/proc.html)
[Linux statfs interface](https://man7.org/linux/man-pages/man2/statfs.2.html),
[O_PATH](https://man7.org/linux/man-pages/man2/open.2.html) and
[fdinfo mount identity](https://man7.org/linux/man-pages/man5/proc_pid_fdinfo.5.html).

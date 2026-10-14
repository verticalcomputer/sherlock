# Review an unsigned agent/gateway candidate

This guide prepares review evidence; it does not approve a signed binary or client
installation. Public source is licensed under [Apache-2.0](../../LICENSE), with
[Vertical Computer Inc attribution](../../NOTICE). See [current status](../../next.md)
for release state and [signing](release-signing.md) for the protected signing gate.

The [candidate builder](../../scripts/build-telemetry-candidate.py) and its
[tests](../../scripts/test_build_telemetry_candidate.py) own the package format.
Review the [protocol](../reference/telemetry/protocol.md),
[identity](../reference/telemetry/node-identity.md),
[Linux sources](../reference/telemetry/linux-sources.md) and
[ownership retirement](../reference/telemetry/ownership-retirement.md) before use.

## Candidate preparation

After the implementation owners freeze the candidate and repository checks pass,
run `python3 scripts/build-telemetry-candidate.py --out /absolute/new/private-dir`.
The parent directory must already exist with safe ownership/permissions. The
builder creates a new 0700 directory and refuses replacement. It performs no
installation, service changes, key generation, signing, publication or Git write.
Errors are fixed codes; an interrupted/failed candidate remains private and
INCOMPLETE, never an approved output.

The candidate contains the Linux/amd64 CGO-disabled package compilation closure
for the actual node/gateway entrypoints, repository source/embedded inputs,
go.mod/go.sum, prepared contracts and builder. Required external module archives
are included with SHA-256 and independently checked Go h1 sums against go.sum.
Only pinned module metadata from the selected and legacy unselected versions in
the dependency graph is copied for other requirements. Lazily listed modules outside the compilation closure whose go.mod
is absent from go.sum are not fetched/included; their omission is recorded in
`unmaterialized-graph-metadata.json`. Offline clean builds must prove the snapshot
is sufficient. Unrelated global module cache contents are excluded. Replacements
are rejected. `compiled-closure.json` and `modules.json` distinguish these inputs.

`source-files.json` is deterministic JSON listing input paths, sizes and hashes.
Its SHA-256 is the candidate source identity. It binds reviewed code, dependency
archives, contracts and builder; it is not an executable hash. External local Go
toolchain/compiler/linker/assembler and standard-library input hashes are recorded
in `toolchain.json`; those sources/tools are not bundled or hermetically rebuilt.

Two builds use different clean source directories, module caches and build
caches, with modules offline after materialization. Both use CGO_ENABLED=0,
GOOS=linux, GOARCH=amd64, GOAMD64=v1, GOTOOLCHAIN=local, GOWORK=off, GOENV=off,
`-mod=readonly -trimpath -buildvcs=false -ldflags=-buildid=`, and explicit
`main.releaseVersion=fixture.v1` / `main.releaseSourceSHA256=<manifest hash>`.
Their binary bytes must match. Original source inputs are checked again before
success. The source digest/version in local node configuration must match the
embedded candidate values; development builds remain explicitly distinguishable.

`binary-metadata.json` records Go build metadata and actual initialized ELF
linker variables. Linux/amd64 builders also execute each binary's `version`
command. Cross-host builds do not execute Linux binaries; native execution and
Linux process/resource qualification remain separate gates. Self-reported
version strings and configuration labels are not remote attestation. Clients
must independently verify the executable SHA-256 from their approved candidate.

`SHA256SUMS` covers the candidate artifacts and is ready for an approved release
signer. It has no signature and supplies no independent authenticity on its own.
`provenance.unsigned.json` reports build evidence and limitations; it is not
signed provenance. `sbom.spdx.json` is an SPDX-2.3 dependency/artifact inventory
from actual package/module metadata with **NOASSERTION** license/copyright fields.
Its SPDX metadata dataLicense does not license the represented code. It does not
replace dependency-notice, secret, vulnerability, rights or disclosure reviews.
See the [SPDX package specification](https://spdx.github.io/spdx-spec/v2.3/package-information/)
and [Go build command documentation](https://pkg.go.dev/cmd/go).

## Prepare a public Actions review artifact

After this workflow is merged, manually dispatch
[Prepare unsigned release candidate](../../.github/workflows/prepare-release.yml)
on `main` with a proposed tag such as `v0.1.0-rc.1`. The proposed tag is a review
input: preparation does not create a tag, sign, approve, publish a GitHub Release
or install anything. Only the public repository's manual main-branch run is
accepted. All action revisions are pinned; the job has `contents: read` and no
OIDC permission, credentials persisted in checkout, signing environment or
repository write access. See GitHub's [manual workflow documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch).

The [preparation helper](../../scripts/prepare-hosted-release.py) builds twice,
assembles only the seven public package files and binds every archived first-party
file's bytes and executable mode to the exact checked-out Git commit. Dependencies
remain bound by the builder's module checks and source manifest. Dirty tracked
work is rejected before building; untracked or changed archived source is rejected
by the final commit comparison. This does not replace a secret, vulnerability,
license or native-host review.

The uploaded artifact is named `sherlock-reviewed-release` for compatibility with
the signer. Its name grants no approval. The job summary records its numeric
artifact ID and an `approved: false` policy containing exact commit/tag and three
package hashes. The full private builder directory, scan findings and operational
evidence are excluded. Download and review that exact artifact; do not substitute
a previous local package or rebuild after approving its hashes. Hosted and local
source identities can differ because the manifest includes external toolchain
metadata. Binary reproducibility proves two builds on the recorded toolchain,
not equality across different toolchains or operating systems.

The hosted package keeps `release_approved: false`, `signed: false`, and
`package_state: UNSIGNED_REVIEW_ONLY`, with `approval_mode: external_exact_package`.
Approval is supplied separately through the protected exact-hash record described
in [signing](release-signing.md); no package rewrite is needed after review.
Client verification checks both real signatures before accepting this provenance
mode. Unbound local packages remain ineligible. No signing run or real Sigstore
verification is established by offline tests or by preparation alone.

## Reviewable permissions, payload and endpoints

The builder still stamps preview version `fixture.v1`; that version label is not
the list of source capabilities. The binary's `supported_profiles` includes
synthetic `fixture.v1` and opt-in `linux.host.v1` / `linux.rootfs.v1`.
Fixture fields are synthetic gauge/counter/flag/state values. Linux payloads,
permissions, support states and namespace limits are defined in the
[Linux reference](../reference/telemetry/linux-sources.md). All profiles include
signed identity, observation times, coverage and explicit loss. No current
resident profile feeds ordinary health/evaluator projections. Native source and
workload-overhead qualification remain separate gates.

The node needs its owned protected identity/configuration and bounded spool
directories, an approved gateway CA/SPKI and outbound TLS to the cluster-local
gateway. It has no cloud credential, remote command interface or automatic
update channel. Private keys remain local. Fixture boot IDs are explicitly
synthetic; ordinary Linux startup reads the OS boot identity. No GPU/BMC/SSH or
privileged helper access is required by the fixture profile.

The gateway needs its approved collector identity, protected TLS/configuration,
dedicated node CA public material, bounded journal root, a node mTLS listener and
outbound authenticated pinned TLS to the configured cloud control URL. The
dedicated node CA private key belongs only to the optional cloud issuer. Node,
collector and gateway trust separation is checked; a CA returned in a certificate
bundle cannot approve itself. See contract ownership and resource limits before
reviewing platform/service settings.

| Boundary | Approved route family | Authentication and data |
| --- | --- | --- |
| Node→local gateway | POST `/node-telemetry/v1/sessions`, `/node-telemetry/v1/batches` | Required node mTLS plus node signature and current enrollment; enrolled fixture or Linux source payload/loss and lifecycle |
| Gateway→cloud | GET `/collector/telemetry/v1/enrollments/{id}/grant`, `.../status`; POST `/collector/telemetry/v1/sessions`, `.../batches` | Existing authenticated collector boundary, exact cluster/gateway/enrollment authority, signed node data and durable receipts |
| Node→local gateway retirement | POST `/node-telemetry/v1/retirement/capabilities`, `.../releases`, `.../completions` | Same node mTLS/current authority, separate retirement version, signed ownership proof and signed local completion; pending is backpressure |
| Gateway→cloud retirement | GET `/collector/telemetry/v1/enrollments/{id}/retirement-capabilities`; POST `/collector/telemetry/v1/retirement/prepare`, `.../commit`, `.../complete` | Existing collector authentication; exact signed request and immutable phase bindings; no health or repair authority |
| Protected head relay→cloud | POST `/collector/telemetry/v1/node-certificates` | Existing authenticated collector boundary plus locally minted ten-minute CSR-bound token; no public/unauthenticated node bootstrap route |

Logs use fixed/redacted errors. Review exact candidate for accidental identifiers,
payload leakage and permission widening. Bounds, explicit backpressure, spool
expiry/loss, revocation, key rotation and ownership-retirement/pruning behavior
must be assessed against the candidate's contract; a happy-path fixture is not
production capacity or seven-day soak evidence.

## Client version pinning template — review before use

1. Record the approved source-manifest SHA-256, executable SHA-256, version,
   source availability, permission/payload contract and release signing identity.
   Obtain signer/public-key trust independently. Verify the real release
   signature before trusting its checksum file. Keyless Sigstore signing via the reviewed GitHub OIDC identity is selected; a real authorized signature is still required.
2. From the approved candidate directory, verify `sha256sum -c SHA256SUMS`.
   Compare the reviewed source manifest and run the Linux binary's `version`
   command on an authorized qualification host. Match the actual executable's
   SHA-256, not only its self-reported source identity.
3. Pin the executable path/digest and exact configuration version/source digest
   in a client-reviewed service definition. Keep private configuration and keys
   outside exported source. Review the startup resource limits, authority leases,
   outage/reconnect, certificate renewal, explicit update and rollback procedure.
   There is no automatic update. This document supplies no installation command.
4. Preserve an approved previous binary/configuration and private ownership
   evidence. An update or rollback must preserve existing unacknowledged bytes,
   session/key authority and schema compatibility; never reset a journal to make
   a different candidate start.

## Client removal template — review before use

1. Identify only the client-approved node agent/gateway service definitions,
   executable paths, identity files and journal roots. Record exact ownership and
   pending receipts/loss. Do not infer service names or stop workload processes.
2. Stop those explicitly identified telemetry services through the client's
   service manager and verify they joined in-flight work. Disabling a collector
   or revoking an enrollment blocks future and duplicate acknowledgements; plan
   it with receipt ownership so acknowledged bytes are not silently discarded.
3. Revoke the reviewed enrollment/key authority using protected operator tooling;
   verify ingress/replay rejection and record the final ownership disposition.
   Export required journal/receipt evidence privately before any deletion.
4. Remove only the reviewed telemetry service definitions, executables and
   private identities after their retention/disposition decision. Leave GPU
   drivers, jobs, networking, BMC and unrelated collector protocols alone.
   If owned unacknowledged bytes remain, preserve them and record the gap;
   removal is not proof of cloud receipt or physical health.

## Review boundaries

Publication of this public source does not approve a candidate binary. Review
exact source, compilation dependencies, notices, current vulnerability/secret
scan results and permitted payloads for each candidate. Previous scan dispositions
apply only to their exact inputs; they are not a reusable approval of future code.
Keep original scan output, review receipts and customer evidence private.

Unsigned preview outputs require exact package review and actual authorized
signatures before client distribution. Native Linux behavior, permissions,
resource/retention capacity, outage/renewal/backup/restore and hardware canary
remain separate from reproducibility. Use [current status](../../next.md) for the
remaining implementation and release gaps. Never upload the whole private builder
directory or relabel its receipt as release approval.

# Sherlock release signing — selected October 12, 2026

Vertical Computer Inc selected **GitHub Actions OIDC with Sigstore/Cosign keyless
signing**. Public repository/module: `github.com/verticalcomputer/sherlock`.
Security contact: `akash@vertical.computer`. No permanent private release key,
password or commit-key reuse is needed. The October 9 recommendation is now a
selected architecture; actual GitHub execution and signatures remain unqualified.

## Local implementation and verification identity

The [manual release workflow](../.github/workflows/release.yml) accepts only the
public `verticalcomputer/sherlock` repository on an exact version tag. It has no
push, pull-request or automatic tag trigger, no GitHub Release publication step,
and no repository write permission. A `release-signing` environment and an exact
reviewed artifact approval are required. Missing or false approval stops before
signing. It does not sign the existing private fixture candidate.

Clients trust these constraints, with the tag replaced by the exact approved release:

- Issuer: `https://token.actions.githubusercontent.com`.
- Certificate workflow commit: the independently approved full 40-character source commit.
- Identity: `https://github.com/verticalcomputer/sherlock/.github/workflows/release.yml@refs/tags/<approved-tag>`.

Both signature verifications enforce `--certificate-github-workflow-sha`; a moved or recreated tag cannot substitute a different signing commit. No owner-wide identity wildcard or verification bypass is used. A commit
signature authenticates a Git commit; release signatures authenticate the exact
checksum and provenance files. Source mapping and reproducible builds are still
required. See [Sigstore's CI quickstart](https://docs.sigstore.dev/quickstart/quickstart-ci/)
and [blob signing](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/).

## GitHub configuration before the first run

These hosting settings have not been changed or verified locally:

1. Complete the existing exact source/disclosure, dependency/notice and build
   review. Export only reviewed public material into the public repository; keep
   customer evidence, operational records, credentials and private audits out.
2. Put this workflow and verifier in the approved source commit and default
   branch, and create the reviewed version tag pointing to that commit. Protect
   release tags against unauthorized creation, movement and deletion.
3. Create the `release-signing` environment with required reviewers, prevent
   self-review/bypass where supported, and restrict deployment to reviewed release
   tags. Keep signing permissions out of untrusted pull-request jobs.
4. Package the reviewed build as a GitHub Actions artifact named
   `sherlock-reviewed-release`, from a run on that exact source commit. Record its
   numeric artifact ID. The download is bound to that ID and commit; no latest-run
   lookup or executable/package script execution occurs.
5. Set the environment variable `RELEASE_APPROVAL_JSON` to the review record
   below, with real exact values and `approved: true` only after package review.
   This record contains public identifiers/hashes, not credentials. Missing or
   malformed values, a different tag/commit or a private repository are rejected.
6. Manually dispatch **Sign reviewed release** on that exact tag, approve the
   protected environment, inspect the signatures/rejection checks and distribute
   the public verifier identity through a trusted company channel. Publication
   and client installation retain their separate gates.

Approval record template; this example deliberately cannot authorize signing:

```json
{
  "schema_version": 1,
  "approved": false,
  "repository": "verticalcomputer/sherlock",
  "ref": "refs/tags/<approved-tag>",
  "source_commit": null,
  "artifact_id": null,
  "source_manifest_sha256": null,
  "checksums_sha256": null,
  "provenance_sha256": null
}
```

The source commit is the full 40-character Git SHA. The three digests are SHA-256
of the exact `source-files.json`, `SHA256SUMS` and `provenance.unsigned.json` bytes.
The environment review record is outside the source commit to avoid a circular
commit hash. Approvers must compare it with independent review/build evidence.

## Reviewed public package contract

The artifact root contains exactly these regular files, without nested/private
folders, symbolic links or extra files:

- `sherlock-node-agent-linux-amd64`, `sherlock-gateway-linux-amd64`.
- `source.tar.gz`, `source-files.json`, `sbom.spdx.json`.
- `provenance.unsigned.json`, `SHA256SUMS`.

`SHA256SUMS` contains one lowercase SHA-256, two spaces and filename per row for
all six other files. The source archive is reviewed and hash-bound as an opaque
file; this signing helper does not extract, execute or independently audit it.
Existing private builder outputs must not be uploaded wholesale or relabeled as
approved. Producing this approved public export remains a separate gate.

The provenance object must include `schema_version: 1`, `release_approved: true`,
`repository`, `ref`, `source_commit`, `source_manifest_sha256`,
`target: "linux/amd64"`, `byte_identical: true` and
`two_independent_clean_builds`. The last field is two equal dictionaries mapping
`sherlock-node-agent` and `sherlock-gateway` to the actual binary hashes. These
claims require independently reviewed build evidence; the helper checks their
consistency and signs them, without manufacturing a build attestation.

The workflow validates exact approved hashes before calling Cosign, signs both
`SHA256SUMS` and `provenance.unsigned.json`, and verifies both signatures against
the exact tag identity/issuer. It checks all package hashes again and retains the
explicit public package plus the two `.sigstore.json` bundles. A partial signing
failure stops the job without uploading a successful package. The provenance
filename describes its original input; its authenticity is provided by the
adjacent signature bundle. No GitHub Release is created.

All action revisions are pinned to commits; Cosign is pinned to v3.0.2. Changing
these pins requires review. Public Sigstore signing submits signing/certificate
metadata to its transparency log; no private candidate was submitted here.

## Client verification

Obtain the approved tag, source commit, source-manifest digest and workflow/issuer
policy through a trusted company channel. Obtain this verifier from that reviewed
source commit, not an unauthenticated executable beside the download. Install
Cosign through its [official instructions](https://docs.sigstore.dev/cosign/system_config/installation/).
Run:

```sh
python3 scripts/verify-release.py verify \
  --directory /absolute/download/directory \
  --tag '<approved-tag>' \
  --commit '<approved-source-commit>' \
  --source-sha256 '<approved-source-manifest-sha256>'
```

The verifier first checks both signature bundles against the exact workflow tag
identity and issuer, then checks the source/provenance identity, inventory and all
binary/source/SBOM hashes. Missing bundles, changed bytes, extra files and wrong
identities fail. It never installs or runs downloaded executables. See
[Sigstore verification](https://docs.sigstore.dev/cosign/verifying/verify/).

## Acceptance boundary

The private operational evidence withheld records offline policy,
payload and command tests plus workflow lint. Tests stub Cosign and make no claim
of successful certificate issuance or real cryptographic signature validation.
A hosted run must prove actual OIDC issuance, exact verifier rejection for wrong
identity/issuer and changed manifest/binary, protected tag/environment behavior
and trusted client distribution. No persistent key, signature, public log entry,
repository visibility change, installation or publication was created locally.
Signing grants no node-enrollment, telemetry-signing, repair or update authority.

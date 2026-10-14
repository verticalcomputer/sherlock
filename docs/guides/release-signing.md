# Sign and verify a reviewed release

Vertical Computer Inc selected **GitHub Actions OIDC with Sigstore/Cosign keyless
signing**. Public repository/module: `github.com/verticalcomputer/sherlock`.
Security contact: `akash@vertical.computer`. No permanent private release key,
password or commit-key reuse is needed. The workflow and verifier implement the
policy below. [Current status](../../next.md) records whether hosted protections
and actual signed releases have been verified; this guide is not that evidence.

## Local implementation and verification identity

The [manual release workflow](../../.github/workflows/release.yml) accepts only the
public `verticalcomputer/sherlock` repository on an exact version tag. It has no
push, pull-request or automatic tag trigger, no GitHub Release publication step,
and no repository write permission. A `release-signing` environment and an exact
reviewed artifact approval are required. Missing or false approval stops before
signing. Commit-bound preparation output can be approved through that external
record; unbound local preparation output is rejected.

Clients trust these constraints, with the tag replaced by the exact approved release:

- Issuer: `https://token.actions.githubusercontent.com`.
- Certificate workflow commit: the explicitly approved full 40-character source commit.
- Identity: `https://github.com/verticalcomputer/sherlock/.github/workflows/release.yml@refs/tags/<approved-tag>`.

Both signature verifications enforce `--certificate-github-workflow-sha`; a moved or recreated tag cannot substitute a different signing commit. No owner-wide identity wildcard or verification bypass is used. A commit
signature authenticates a Git commit; release signatures authenticate the exact
checksum and provenance files. Source mapping and reproducible builds are still
required. See [Sigstore's CI quickstart](https://docs.sigstore.dev/quickstart/quickstart-ci/)
and [blob signing](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/).

## Hosting and package prerequisites for every run

Verify these settings against the actual repository before signing. The workflow
file alone cannot establish remote protection state; recheck after policy or
reviewer changes. The owner approved sole-maintainer review by AkMo3 on
October 14, 2026, including approval of runs that account initiates. Self-review
is allowed under that exception; manual package approval, required environment
review and disabled admin bypass remain required. Revisit independent approval
when another engineering reviewer is available. These are distribution gates,
not prerequisites for ongoing product development.

1. Complete the existing exact source/disclosure, dependency/notice and build
   review. Export only reviewed public material into the public repository; keep
   customer evidence, operational records, credentials and private audits out.
2. Use [unsigned preparation](release-review.md#prepare-a-public-actions-review-artifact)
   on main to produce `sherlock-reviewed-release` at the intended commit. Review
   that exact artifact and record the job summary's numeric artifact ID and
   hashes before approving or creating its proposed tag. The download is bound
   to that ID and commit; no latest-run lookup or package script execution occurs.
   An expired artifact requires fresh review of the new artifact ID.
3. Create the reviewed version tag pointing to the artifact's exact source commit,
   with this workflow/verifier present. If main advanced after preparation, keep
   the reviewed commit. Protect release tags against unauthorized creation,
   movement and deletion.
4. Verify the `release-signing` environment requires AkMo3, disables admin
   bypass and restricts deployment to reviewed release tags. Self-review is
   allowed under the sole-maintainer exception above.
   Keep signing permissions out of untrusted pull-request jobs.
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

The provenance object must include `schema_version: 1`,
`repository`, `ref`, `source_commit`, `source_manifest_sha256`,
`target: "linux/amd64"`, `byte_identical: true` and
`two_independent_clean_builds`. The last field is two equal dictionaries mapping
`sherlock-node-agent` and `sherlock-gateway` to the actual binary hashes. These
claims require independently reviewed build evidence; the helper checks their
consistency and signs them, without manufacturing a build attestation.

The original `release_approved: true` provenance format remains supported. New
hosted candidates instead preserve `release_approved: false`, `signed: false`,
`package_state: UNSIGNED_REVIEW_ONLY` and `approval_mode: external_exact_package`.
Those fields describe preparation, not a signing authorization. The signer accepts
that mode only with the protected `approved: true` record bound to all three
hashes and the exact artifact/source/tag. The client accepts it only after both
signature bundles verify against the approved workflow identity and commit. This
avoids altering reviewed package bytes merely to approve them. A package flag,
artifact name or successful build alone cannot authorize signing.

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

[Offline policy tests](../../scripts/test_release_signing.py) stub Cosign; they
cannot establish real certificate issuance or cryptographic verification. A
hosted run must prove OIDC issuance, exact verifier rejection for wrong
identity/issuer and changed manifest/binary, tag/environment protection and
trusted client distribution. No GitHub Release is created by this workflow.
Signing grants no node enrollment, telemetry-signing, repair or update authority.

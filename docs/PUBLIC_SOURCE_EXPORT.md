# Public source and unsigned release review

This procedure extends the existing source-audit/build gate. Preparation does
not approve disclosure, signing, publication or client installation.

## Exact source selection

`scripts/export-public-candidate.py` reads an explicitly reviewed JSON inventory,
bound by the SHA-256 of its exact bytes. It does not select files implicitly or
copy a Git working tree/history wholesale. The manifest has schema version 1,
`prepared_for_review: true`, `release_approved: false`, owner `Vertical Computer
Inc`, license `Apache-2.0`, and module `github.com/verticalcomputer/sherlock`.

Each `files` row specifies a repository-relative `source`, its `sha256`, a public
`destination`, `reviewed_for_candidate: true`, a category (`source`, `fixture`,
`documentation`, `license`, `asset` or `tooling`), and boolean `executable`.
Optional `replacement` and `replacement_sha256` bind an explicitly reviewed
sanitized replacement to the unchanged original. Private review notes can stay
in the manifest; they are excluded from the public source inventory.

```sh
python3 scripts/export-public-candidate.py \
  --root /absolute/repository \
  --manifest reviewed-files.json \
  --manifest-sha256 <independently-reviewed-manifest-sha256> \
  --output /absolute/new-private-review-directory
```

The safe parent must already exist. All original/replacement hashes are checked
before output creation; symlinks, path traversal, duplicate destinations,
unreviewed rows, missing public contracts, unexpected binaries and private
destinations fail closed. Files are bounded individually and in aggregate.
The new directory is protected and cannot overwrite an existing candidate.

Only `source/` is the proposed public tree. Its `PUBLIC_SOURCE_MANIFEST.json`
lists public paths, hashes, sizes and executable modes. The sibling
`private-export-receipt.json` binds private input/replacement provenance and must
remain private. `STATUS.json` explicitly records unsigned, unpublished review
preparation. Never archive or upload the whole output directory.

Candidate-only synthetic network substitutions preserve the fixed topology and
fail-closed assertions. They do not change a deployed admission profile or grant
generic fleet acceptance. Run the full checks, isolated persistence tests,
synthetic evaluations, local-link review and maintained scans on the exact
export; distinguish scanner silence from exhaustive disclosure/rights review.

## Reproducible build and review package

Run `scripts/build-telemetry-candidate.py` from the exact exported source with
the patched, pinned Go toolchain placed first on PATH. The builder deliberately
sets `GOTOOLCHAIN=local`; it cannot silently fetch another compiler. Two clean
offline Linux/amd64 CGO-disabled builds must match. License/notice files and
third-party license texts travel with its compilation closure and dependencies.
Toolchain sources are hashed but not bundled or hermetically rebuilt. A cross
build is not native Linux process, resource or workload qualification.

After reviewing and independently recording the build's checksum-file digest:

```sh
python3 scripts/prepare-release-review.py \
  --candidate /absolute/reproducible-build \
  --candidate-checksums-sha256 <reviewed-build-checksum-file-sha256> \
  --output /absolute/new-unsigned-package
```

The assembler checks the complete build inventory, source manifest, both build
hash sets and notices. Its deterministic relative-path `source.tar.gz` contains
only the declared build inputs, dependency archives and toolchain/closure
metadata. It excludes build working directories, operational records and Git
ancestry. The separately exported reusable backend remains its own public-tree
review surface; this archive describes the agent/gateway build closure.

The package has the seven files expected by the release signer, but its
provenance remains `release_approved: false`, `signed: false`, with null tag and
commit. The signer **rejects** it. Preparation cannot invent the future public
Git commit, release tag, hosted artifact ID or owner approval. Once the exact
public tree and publication route are approved, build/review an exact package
bound to the actual public commit/tag and follow the
[protected signing contract](GP06F_RELEASE_SIGNING.md). Keep original private
history and dated candidate evidence intact.

Source availability, dependency/archive-asset rights, vulnerability applicability,
hosted protections, real signatures and trusted client distribution remain
distinct gates. Monitoring enrollment grants no diagnostic or repair authority.

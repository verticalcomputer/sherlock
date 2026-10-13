#!/usr/bin/env python3
"""Assemble an unsigned review package from an exact reproducible fixture build."""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load("release", "verify-release.py")
exporter = load("exporter", "export-public-candidate.py")
builder = load("builder", "build-telemetry-candidate.py")


def assemble(candidate, expected, output):
    require = release.require
    require(isinstance(expected, str) and release.HEX.fullmatch(expected), "invalid_candidate_digest")
    sums = release.read_regular(candidate / "SHA256SUMS", 1 << 20)
    require(hashlib.sha256(sums).hexdigest() == expected, "candidate_checksums_changed")
    checksums = {}
    for line in sums.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./@+!~-]+)", line)
        require(match is not None, "invalid_candidate_checksum")
        digest, name = match.groups()
        path = exporter.relative(name)
        require(name not in checksums and ".git" not in path.parts, "invalid_candidate_membership")
        body = exporter.read_relative(candidate, name, 512 << 20)
        require(hashlib.sha256(body).hexdigest() == digest, "candidate_digest_changed")
        checksums[name] = digest
    actual = {p.relative_to(candidate).as_posix() for p in candidate.rglob("*") if p.is_file() or p.is_symlink()}
    require(actual == set(checksums) | {"SHA256SUMS"}, "unexpected_candidate_files")
    provenance = release.object_json(exporter.read_relative(candidate, release.PROVENANCE))
    status = release.object_json(exporter.read_relative(candidate, "STATUS.json"))
    manifest_raw = exporter.read_relative(candidate, "source-files.json")
    source_sha = hashlib.sha256(manifest_raw).hexdigest()
    manifest = release.object_json(manifest_raw)
    require(status.get("status") == "PREPARED_PRIVATE_UNSIGNED_FIXTURE"
            and status.get("release_approved") is False
            and status.get("source_manifest_sha256") == source_sha
            and provenance.get("release_approved") is False and provenance.get("signed") is False
            and provenance.get("source_manifest_sha256") == source_sha
            and provenance.get("target") == "linux/amd64" and provenance.get("byte_identical") is True,
            "not_reproducible_unsigned_candidate")
    binaries = {name: exporter.read_relative(candidate, "bin/" + name, release.FILES[name])
                for name in ("sherlock-node-agent-linux-amd64", "sherlock-gateway-linux-amd64")}
    build_hashes = {name.removesuffix("-linux-amd64"): hashlib.sha256(body).hexdigest()
                    for name, body in binaries.items()}
    require(provenance.get("two_independent_clean_builds") == [build_hashes, build_hashes],
            "build_provenance_mismatch")
    require(provenance.get("version") == "fixture.v1", "wrong_fixture_version")
    for body in binaries.values():
        require(builder.elf_identity(body) == {"main.releaseVersion": "fixture.v1",
                "main.releaseSourceSHA256": source_sha}, "binary_source_identity_mismatch")
    rows = manifest.get("files")
    require(isinstance(rows, list) and 0 < len(rows) <= 10000, "invalid_source_manifest")
    entries = {}
    total = 0
    for row in rows:
        require(isinstance(row, dict) and type(row.get("executable")) is bool, "invalid_source_row")
        name = str(exporter.relative(row.get("path")))
        require(name.startswith(("source/", "dependencies/"))
                or name in {"toolchain.json", "modules.json", "compiled-closure.json",
                            "unmaterialized-graph-metadata.json"}, "unreviewable_archive_member")
        if name.startswith("source/"):
            exporter.public_path(name.removeprefix("source/"))
        require(name not in entries and checksums.get(name) == row.get("sha256"), "invalid_source_row")
        body = exporter.read_relative(candidate, name, 256 << 20)
        total += len(body)
        require(total <= 512 << 20 and len(body) == row.get("bytes"), "archive_input_too_large")
        entries[name] = (body, row["executable"])
    require({"source/LICENSE", "source/NOTICE", "source/THIRD_PARTY_NOTICES.md"} <= set(entries)
            and any(name.startswith("source/third_party/licenses/") for name in entries), "notices_missing")
    require({name for name in checksums if name.startswith(("source/", "dependencies/"))} <= set(entries),
            "source_inventory_incomplete")
    # A deterministic, relative-path source/dependency archive; no private receipt,
    # build working directory, original Git ancestry or operational audit files.
    archive = io.BytesIO()
    with gzip.GzipFile(fileobj=archive, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as target:
            for name, (body, executable) in sorted(entries.items()):
                item = tarfile.TarInfo(name)
                item.size, item.mode, item.mtime = len(body), 0o755 if executable else 0o644, 0
                target.addfile(item, io.BytesIO(body))
    # The exact public Git commit/tag do not exist yet. Never invent them or turn
    # local review preparation into approved signing provenance.
    provenance.update(repository=release.REPOSITORY, ref=None, source_commit=None,
                      package_state="UNSIGNED_REVIEW_ONLY")
    payload = dict(binaries, **{"source.tar.gz": archive.getvalue(), "source-files.json": manifest_raw,
                   "sbom.spdx.json": exporter.read_relative(candidate, "sbom.spdx.json"),
                   release.PROVENANCE: exporter.encoded(provenance)})
    require(set(payload) == set(release.FILES), "invalid_review_package")
    for name, body in payload.items():
        require(len(body) <= release.FILES[name], "review_package_too_large")
    payload["SHA256SUMS"] = "".join(hashlib.sha256(body).hexdigest() + "  " + name + "\n"
                                    for name, body in sorted(payload.items())).encode()
    directory = exporter.new_directory(output)
    for name, body in payload.items():
        exporter.write(directory / name, body, name in binaries)
    return {"release_approved": False, "signed": False, "published": False,
            "source_manifest_sha256": source_sha, "file_count": len(payload),
            "checksums_sha256": hashlib.sha256(payload["SHA256SUMS"]).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--candidate-checksums-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(assemble(args.candidate, args.candidate_checksums_sha256, args.output), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (release.ReleaseError, exporter.ExportError, builder.CandidateError, OSError, ValueError, TypeError, KeyError) as error:
        sys.exit(str(error) if isinstance(error, (release.ReleaseError, exporter.ExportError, builder.CandidateError))
                 else "release_review_preparation_failed")

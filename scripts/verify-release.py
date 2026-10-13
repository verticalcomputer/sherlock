#!/usr/bin/env python3
"""Exact public release signing/verification. Never executes package contents."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import urllib.request

REPOSITORY = "verticalcomputer/sherlock"
ISSUER = "https://token.actions.githubusercontent.com"
WORKFLOW = REPOSITORY + "/.github/workflows/release.yml"
ARTIFACT_NAME = "sherlock-reviewed-release"
PROVENANCE = "provenance.unsigned.json"
FILES = {
    "sherlock-node-agent-linux-amd64": 128 << 20,
    "sherlock-gateway-linux-amd64": 128 << 20,
    "source.tar.gz": 512 << 20,
    "source-files.json": 16 << 20,
    "sbom.spdx.json": 16 << 20,
    PROVENANCE: 1 << 20,
}
MANIFESTS = ("SHA256SUMS", PROVENANCE)
BUNDLES = {name + ".sigstore.json" for name in MANIFESTS}
HEX = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?\Z")


class ReleaseError(Exception):
    pass


def require(condition, code):
    if not condition:
        raise ReleaseError(code)


def object_json(raw):
    # Duplicate keys would make exact reviewed policy ambiguous.
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=pairs)
    require(isinstance(result, dict), "invalid_json_object")
    return result


def context(policy, environment, event):
    require(type(policy.get("schema_version")) is int and policy["schema_version"] == 1
            and policy.get("approved") is True,
            "exact_candidate_not_approved")
    require(policy.get("repository") == REPOSITORY
            and environment.get("GITHUB_REPOSITORY") == REPOSITORY, "wrong_repository")
    repository = event.get("repository")
    require(environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and isinstance(repository, dict) and repository.get("private") is False,
            "not_public_manual_release")
    ref = policy.get("ref", "")
    require(isinstance(ref, str) and ref.startswith("refs/tags/")
            and TAG.fullmatch(ref.removeprefix("refs/tags/")), "invalid_release_tag")
    require(environment.get("GITHUB_REF") == ref
            and environment.get("GITHUB_REF_TYPE") == "tag", "wrong_release_ref")
    require(environment.get("GITHUB_WORKFLOW_REF") == WORKFLOW + "@" + ref,
            "wrong_workflow_identity")
    commit = policy.get("source_commit", "")
    require(isinstance(commit, str) and COMMIT.fullmatch(commit)
            and commit == environment.get("GITHUB_SHA"), "wrong_source_commit")
    require(type(policy.get("artifact_id")) is int and policy["artifact_id"] > 0,
            "invalid_artifact_id")
    for key in ("source_manifest_sha256", "checksums_sha256", "provenance_sha256"):
        require(isinstance(policy.get(key), str) and HEX.fullmatch(policy[key]),
                "missing_exact_candidate_digest")
    return policy


def approval():
    raw = os.environ.get("RELEASE_APPROVAL_JSON", "")
    require(0 < len(raw) <= 16384, "release_approval_missing")
    policy = object_json(raw)
    event = object_json(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    return context(policy, os.environ, event)


def artifact_origin(policy, metadata):
    run = metadata.get("workflow_run", {})
    require(metadata.get("id") == policy["artifact_id"]
            and metadata.get("name") == ARTIFACT_NAME
            and metadata.get("expired") is False, "artifact_not_available")
    require(isinstance(run, dict) and run.get("head_sha") == policy["source_commit"],
            "artifact_wrong_commit")
    require(type(run.get("id")) is int and run["id"] > 0, "artifact_missing_run")
    return run["id"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ReleaseError("unexpected_metadata_redirect")


def select_artifact(policy):
    token = os.environ.get("GH_TOKEN", "")
    require(bool(token), "artifact_read_token_missing")
    # Fixed GitHub endpoint; never forward this token to an artifact-storage redirect.
    request = urllib.request.Request(
        f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{policy['artifact_id']}",
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "sherlock-release-verifier"})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        body = response.read((1 << 20) + 1)
    require(len(body) <= 1 << 20, "artifact_metadata_too_large")
    run_id = artifact_origin(policy, object_json(body))
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"artifact_id={policy['artifact_id']}\nrun_id={run_id}\n")


def read_regular(path, maximum):
    with open(path, "rb", opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW | os.O_NONBLOCK)) as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, "unsafe_release_file")
        body = source.read(maximum + 1)
    require(len(body) <= maximum, "release_file_too_large")
    return body


def digest_file(path, maximum):
    result = hashlib.sha256()
    with open(path, "rb", opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW | os.O_NONBLOCK)) as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, "unsafe_release_file")
        total = 0
        for block in iter(lambda: source.read(1 << 20), b""):
            total += len(block)
            require(total <= maximum, "release_file_too_large")
            result.update(block)
    return result.hexdigest()


def payload(directory, policy, signed=False):
    require(directory.is_dir() and not directory.is_symlink(), "invalid_release_directory")
    expected = set(FILES) | {"SHA256SUMS"} | (BUNDLES if signed else set())
    require({p.name for p in directory.iterdir()} == expected, "unexpected_release_files")
    body = read_regular(directory / "SHA256SUMS", 16384)
    require(hashlib.sha256(body).hexdigest() == policy["checksums_sha256"], "unapproved_checksums")
    sums = {}
    for line in body.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        require(match is not None, "invalid_checksum_line")
        digest, name = match.groups()
        require(name in FILES and name not in sums, "invalid_checksum_membership")
        sums[name] = digest
    require(set(sums) == set(FILES), "missing_release_checksums")
    for name, maximum in FILES.items():
        require(digest_file(directory / name, maximum) == sums[name], "release_digest_mismatch")
    require(sums["source-files.json"] == policy["source_manifest_sha256"], "wrong_source_manifest")
    require(sums[PROVENANCE] == policy["provenance_sha256"], "unapproved_provenance")
    provenance = object_json(read_regular(directory / PROVENANCE, FILES[PROVENANCE]))
    require(provenance.get("schema_version") == 1
            and (provenance.get("release_approved") is True or (
                provenance.get("release_approved") is False
                and provenance.get("approval_mode") == "external_exact_package"
                and provenance.get("package_state") == "UNSIGNED_REVIEW_ONLY"
                and provenance.get("signed") is False
                # Before signing, approval comes only from the protected exact
                # policy. Client verification instead proves both signatures first.
                and (policy.get("approved") is True or signed)))
            and provenance.get("repository") == REPOSITORY
            and provenance.get("ref") == policy["ref"]
            and provenance.get("source_commit") == policy["source_commit"]
            and provenance.get("source_manifest_sha256") == policy["source_manifest_sha256"]
            and provenance.get("target") == "linux/amd64"
            and provenance.get("byte_identical") is True, "unapproved_release_provenance")
    builds = provenance.get("two_independent_clean_builds")
    hashes = {name: sums[name + "-linux-amd64"]
              for name in ("sherlock-node-agent", "sherlock-gateway")}
    require(builds == [hashes, hashes], "binary_build_provenance_mismatch")
    if signed:
        for name in BUNDLES:
            require(bool(read_regular(directory / name, 1 << 20)), "empty_signature_bundle")


def cosign(args):
    result = subprocess.run(["cosign", *args], capture_output=True, timeout=180, check=False)
    require(result.returncode == 0, "signature_operation_failed")


def verify_signatures(directory, ref, commit):
    require(isinstance(commit, str) and COMMIT.fullmatch(commit), "invalid_source_commit")
    identity = "https://github.com/" + WORKFLOW + "@" + ref
    for name in MANIFESTS:
        read_regular(directory / name, 16384 if name == "SHA256SUMS" else FILES[name])
        require(bool(read_regular(directory / (name + ".sigstore.json"), 1 << 20)),
                "empty_signature_bundle")
        cosign(["verify-blob", "--bundle", str(directory / (name + ".sigstore.json")),
                "--certificate-identity", identity, "--certificate-oidc-issuer", ISSUER,
                "--certificate-github-workflow-sha", commit,
                str(directory / name)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("select", "prepare", "sign", "verify"))
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--tag")
    parser.add_argument("--commit")
    parser.add_argument("--source-sha256")
    args = parser.parse_args()
    if args.operation == "select":
        select_artifact(approval())
        return
    require(args.directory is not None, "release_directory_missing")
    directory = args.directory.absolute()
    if args.operation == "verify":
        require(isinstance(args.tag, str) and TAG.fullmatch(args.tag), "invalid_release_tag")
        require(isinstance(args.commit, str) and COMMIT.fullmatch(args.commit), "invalid_source_commit")
        require(isinstance(args.source_sha256, str) and HEX.fullmatch(args.source_sha256),
                "invalid_source_manifest_digest")
        ref = "refs/tags/" + args.tag
        verify_signatures(directory, ref, args.commit)
        policy = {"ref": ref, "source_commit": args.commit,
                  "source_manifest_sha256": args.source_sha256,
                  "checksums_sha256": digest_file(directory / "SHA256SUMS", 16384),
                  "provenance_sha256": digest_file(directory / PROVENANCE, FILES[PROVENANCE])}
        payload(directory, policy, signed=True)
    else:
        policy = approval()
        payload(directory, policy)
        if args.operation == "sign":
            for name in MANIFESTS:
                cosign(["sign-blob", "--yes", "--bundle", str(directory / (name + ".sigstore.json")),
                        str(directory / name)])
            verify_signatures(directory, policy["ref"], policy["source_commit"])
            payload(directory, policy, signed=True)
    print("release " + args.operation + " verified")


if __name__ == "__main__":
    try:
        main()
    except (ReleaseError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        # Never print API responses, tokens, subprocess output or source fragments.
        message = str(error) if isinstance(error, ReleaseError) else "release_validation_failed"
        sys.exit(message)

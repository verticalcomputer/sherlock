#!/usr/bin/env python3
"""Validate the collector and intake package and its separate GitHub signing identity."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

SPEC = importlib.util.spec_from_file_location("release", Path(__file__).with_name("verify-release.py"))
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
require = release.require

SOURCE = "d7d684ec2e5395ffa1adda8526af4edf31850ffb"
TREE = "ea4623e2f6ee59fb4f8f99e24a16f78e8c98e8a6"
BINARY_SHA = "b8d898b85aa2a8559d1f0ace6bf7d7849cbdbdae334d37930fb432ebb3fd8d38"
BINARY = "sherlock-collector-linux-amd64"
INTAKE = "sherlock-control-linux-amd64"
INTAKE_SHA = "bc3e778ddae713ef758a9c43428f42c2926ea61b7eefb13fc952622e7dbb798b"
ARTIFACT = "sherlock-reviewed-collector-intake-linux-amd64"
ENVIRONMENT = "collector-release-signing"
APPROVAL = "COLLECTOR_RELEASE_APPROVAL_JSON"
PREPARE = ".github/workflows/prepare-collector-release.yml"
SIGN = ".github/workflows/sign-collector-release.yml"
MAIN = "refs/heads/main"
FILES = {BINARY: 128 << 20, INTAKE: 128 << 20, "source.tar.gz": 64 << 20, "source-files.json": 4 << 20,
         "sbom.spdx.json": 4 << 20, release.PROVENANCE: 1 << 20}
DIGESTS = {"checksums_sha256": "SHA256SUMS", "provenance_sha256": release.PROVENANCE,
           "source_manifest_sha256": "source-files.json", "binary_sha256": BINARY,
           "intake_sha256": INTAKE}


def valid(pattern, value):
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def workflow_context(environment, event, workflow):
    repo = event.get("repository")
    commit = environment.get("GITHUB_WORKFLOW_SHA")
    require(isinstance(repo, dict) and repo.get("private") is False
            and environment.get("GITHUB_REPOSITORY") == release.REPOSITORY
            and environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and environment.get("GITHUB_REF_TYPE") == "branch"
            and environment.get("GITHUB_REF") == MAIN
            and environment.get("GITHUB_WORKFLOW_REF") == f"{release.REPOSITORY}/{workflow}@{MAIN}"
            and valid(release.COMMIT, commit) and environment.get("GITHUB_SHA") == commit,
            "wrong_collector_workflow_context")
    return commit


def validate_policy(policy, commit, *, approved):
    require(set(policy) == {"schema_version", "approved", "repository", "release_tag", "source_commit",
                            "workflow_commit", "artifact_id", *DIGESTS}
            and type(policy["schema_version"]) is int and policy["schema_version"] == 1
            and policy["approved"] is approved and policy["repository"] == release.REPOSITORY,
            "collector_exact_approval_required")
    require(policy["source_commit"] == SOURCE and policy["workflow_commit"] == commit
            and valid(release.COMMIT, commit) and valid(release.TAG, policy["release_tag"])
            and type(policy["artifact_id"]) is int and policy["artifact_id"] > 0,
            "collector_approval_identity_mismatch")
    require(all(valid(release.HEX, policy[key]) for key in DIGESTS)
            and policy["binary_sha256"] == BINARY_SHA and policy["intake_sha256"] == INTAKE_SHA, "collector_approval_digest_mismatch")


def api(path):
    token = os.environ.get("GH_TOKEN")
    require(bool(token), "github_read_token_required")
    request = urllib.request.Request(f"https://api.github.com/repos/{release.REPOSITORY}/{path}",
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "sherlock-collector-release"})
    with urllib.request.build_opener(release.NoRedirect).open(request, timeout=30) as response:
        raw = response.read((1 << 20) + 1)
    require(len(raw) <= 1 << 20, "github_response_too_large")
    return release.object_json(raw)


def check_environment(fetch=api):
    environment = fetch(f"environments/{ENVIRONMENT}")
    rules = environment.get("protection_rules", [])
    reviewers = [rule for rule in rules if rule.get("type") == "required_reviewers"]
    require(environment.get("name") == ENVIRONMENT and environment.get("can_admins_bypass") is False
            and environment.get("deployment_branch_policy") == {"protected_branches": False,
                                                               "custom_branch_policies": True}
            and len(reviewers) == 1 and bool(reviewers[0].get("reviewers")),
            "collector_environment_not_protected")
    policies = fetch(f"environments/{ENVIRONMENT}/deployment-branch-policies?per_page=100")
    branches = policies.get("branch_policies")
    require(policies.get("total_count") == 1 and isinstance(branches, list)
            and len(branches) == 1 and branches[0].get("name") == "main"
            and branches[0].get("type") == "branch", "collector_environment_not_main_only")


def check_tag(tag, fetch=api):
    require(valid(release.TAG, tag), "invalid_release_tag")
    ref = fetch(f"git/ref/tags/{tag}")
    require(ref.get("ref") == f"refs/tags/{tag}", "collector_tag_missing")
    target = ref.get("object", {})
    # Peel annotated tags without following arbitrary URLs from the API.
    for _ in range(5):
        sha = target.get("sha")
        require(valid(release.COMMIT, sha), "collector_tag_wrong_commit")
        if target.get("type") == "commit":
            require(sha == SOURCE, "collector_tag_wrong_commit")
            return
        require(target.get("type") == "tag", "collector_tag_wrong_commit")
        annotated = fetch(f"git/tags/{sha}")
        require(annotated.get("sha") == sha, "collector_tag_wrong_commit")
        target = annotated.get("object", {})
    raise release.ReleaseError("collector_tag_wrong_commit")


def artifact_origin(policy, fetch=api):
    artifact_id = policy["artifact_id"]
    artifact = fetch(f"actions/artifacts/{artifact_id}")
    origin = artifact.get("workflow_run", {})
    run_id = origin.get("id")
    require(artifact.get("id") == artifact_id and artifact.get("name") == ARTIFACT
            and artifact.get("expired") is False and origin.get("head_sha") == policy["workflow_commit"]
            and type(run_id) is int and run_id > 0, "collector_artifact_wrong_origin")
    run = fetch(f"actions/runs/{run_id}")
    require(run.get("id") == run_id and run.get("head_sha") == policy["workflow_commit"]
            and run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main"
            and run.get("path") == PREPARE and run.get("conclusion") == "success",
            "collector_artifact_wrong_run")
    return run_id


def digest(directory, name):
    return release.digest_file(directory / name, FILES.get(name, 16384))


def payload(directory, policy, *, signed=False):
    expected = set(FILES) | {"SHA256SUMS"} | (release.BUNDLES if signed else set())
    require(directory.is_dir() and not directory.is_symlink()
            and {path.name for path in directory.iterdir()} == expected, "collector_unexpected_files")
    checksums = release.read_regular(directory / "SHA256SUMS", 16384)
    require(hashlib.sha256(checksums).hexdigest() == policy["checksums_sha256"], "collector_unapproved_checksums")
    sums = {}
    for line in checksums.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        require(match is not None, "collector_bad_checksum_row")
        sha, name = match.groups()
        require(name in FILES and name not in sums, "collector_bad_checksum_membership")
        sums[name] = sha
    require(set(sums) == set(FILES), "collector_bad_checksum_membership")
    require(all(digest(directory, name) == sha for name, sha in sums.items()), "collector_payload_tampered")
    require(all(sums[name] == policy[key] for key, name in DIGESTS.items() if name != "SHA256SUMS")
            and sums[BINARY] == BINARY_SHA and sums[INTAKE] == INTAKE_SHA, "collector_payload_unapproved")
    provenance = release.object_json(release.read_regular(directory / release.PROVENANCE, FILES[release.PROVENANCE]))
    require(type(provenance.get("schema_version")) is int and provenance["schema_version"] == 1
            and provenance.get("package_state") == "UNSIGNED_COLLECTOR_REVIEW_ONLY"
            and provenance.get("release_approved") is False and provenance.get("signed") is False
            and provenance.get("repository") == release.REPOSITORY
            and provenance.get("source_commit") == SOURCE and provenance.get("source_tree") == TREE
            and provenance.get("target") == "linux/amd64" and provenance.get("byte_identical") is True
            and provenance.get("two_independent_clean_builds") == [BINARY_SHA, BINARY_SHA]
            and provenance.get("intake_independent_clean_builds") == [INTAKE_SHA, INTAKE_SHA]
            and provenance.get("source_files_sha256") == sums["source-files.json"]
            and provenance.get("release_tag") == policy["release_tag"]
            and provenance.get("workflow_commit") == policy["workflow_commit"],
            "collector_wrong_provenance")


def signatures(directory, commit):
    require(valid(release.COMMIT, commit), "collector_workflow_commit_required")
    identity = f"https://github.com/{release.REPOSITORY}/{SIGN}@{MAIN}"
    for name in release.MANIFESTS:
        digest(directory, name)
        bundle = directory / (name + ".sigstore.json")
        require(bool(release.read_regular(bundle, 1 << 20)), "collector_empty_signature")
        release.cosign(["verify-blob", "--bundle", str(bundle), "--certificate-identity", identity,
                        "--certificate-oidc-issuer", release.ISSUER,
                        "--certificate-github-workflow-sha", commit, str(directory / name)])


def read_policy(path):
    return release.object_json(release.read_regular(path, 16384))


def hosted_policy():
    raw = os.environ.get(APPROVAL, "")
    require(0 < len(raw) <= 16384, "collector_approval_missing")
    policy = release.object_json(raw)
    event = release.object_json(release.read_regular(Path(os.environ["GITHUB_EVENT_PATH"]), 1 << 20))
    commit = workflow_context(os.environ, event, SIGN)
    validate_policy(policy, commit, approved=True)
    return policy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("environment", "select", "prepare", "sign", "verify"))
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--review-record", type=Path)
    args = parser.parse_args()
    if args.operation == "environment":
        event = release.object_json(release.read_regular(Path(os.environ["GITHUB_EVENT_PATH"]), 1 << 20))
        workflow_context(os.environ, event, SIGN)
        check_environment()
        return
    if args.operation == "select":
        policy = hosted_policy()
        check_environment()
        check_tag(policy["release_tag"])
        run_id = artifact_origin(policy)
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(f"artifact_id={policy['artifact_id']}\nrun_id={run_id}\n")
        return

    require(args.directory is not None, "collector_package_directory_required")
    directory = args.directory.absolute()
    if args.operation == "verify":
        require(args.review_record is not None, "collector_trusted_review_record_required")
        policy = read_policy(args.review_record)
        validate_policy(policy, policy.get("workflow_commit"), approved=False)
        signatures(directory, policy["workflow_commit"])
        payload(directory, policy, signed=True)
    else:
        policy = hosted_policy()
        payload(directory, policy)
        if args.operation == "sign":
            require(os.environ.get("GITHUB_ACTIONS") == "true"
                    and bool(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"))
                    and bool(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")),
                    "collector_github_oidc_required")
            check_environment()
            check_tag(policy["release_tag"])
            artifact_origin(policy)
            for name in release.MANIFESTS:
                release.cosign(["sign-blob", "--yes", "--bundle", str(directory / (name + ".sigstore.json")),
                                str(directory / name)])
            signatures(directory, policy["workflow_commit"])
            payload(directory, policy, signed=True)
            check_tag(policy["release_tag"])
    print(f"collector {args.operation} verified")


if __name__ == "__main__":
    try:
        main()
    except (release.ReleaseError, OSError, ValueError, KeyError, AttributeError, TypeError, subprocess.SubprocessError) as error:
        sys.exit(str(error) if isinstance(error, release.ReleaseError) else "collector_release_validation_failed")

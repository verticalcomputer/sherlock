#!/usr/bin/env python3
"""Validate exact collector/production packages and their GitHub signing identity."""
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

# Exact reviewed source and hashes from two independent clean Linux-target builds.
SOURCE = "000f54c15f64a57385cf875024a9fc211d26f4a9"
TREE = "f3fadbc7e07ae344dbbdb92585b16bb46c1d7475"
BINARY_SHA = "08574fe19e28583b5faede1713a9f07ffda5fea4ccaf91cfe6aca6487da86149"
INTAKE_SHA = "be45e1ff2992f767d66da3ac55a6be729c95ad7521bb509d4854b6f131d239c5"
# Every executable is pinned independently; approval must cover all seven.
ALERT_WORKER_SHA = "dd37230aa1c49b0d1e3bff67084d5960649bd71607604eff0ae89134d8daf315"
ADMIN_SHA = "bd2c8dd67c1724cb4cf6131f2acbfe0dba9e8b80baaa05365a0b51b655f4e458"
API_SHA = "4e5bc7156c1baab54896ecc5310f24ecb2360bbfc7e8f818a0387036cf06033e"
ADMIN_UI_SHA = "ef4b9a76a933c586b32c69f9675116a690da900597e4e4736e0761a4fff455ab"
MIGRATE_SHA = "98acdbaec86cbeb0faa257224a6fd633dbf69140f7db473251516b70e3df8fd0"
BINARY = "sherlock-collector-linux-amd64"
INTAKE = "sherlock-control-linux-amd64"
COMMANDS = {
    BINARY: "./cmd/sherlock-collector",
    INTAKE: "./cmd/sherlock-control",
    "sherlock-alert-worker-linux-amd64": "./cmd/sherlock-alert-worker",
    "sherlock-admin-linux-amd64": "./cmd/sherlock-admin",
    "sherlock-api-linux-amd64": "./cmd/sherlock-api",
    "sherlock-admin-ui-linux-amd64": "./cmd/sherlock-admin-ui",
    "sherlock-migrate-linux-amd64": "./cmd/sherlock-migrate",
}
SCHEMA = 2
PACKAGE_STATE = "UNSIGNED_COLLECTOR_PRODUCTION_REVIEW_ONLY"
ARTIFACT = "sherlock-reviewed-collector-production-linux-amd64"
ENVIRONMENT = "collector-release-signing"
APPROVAL = "COLLECTOR_RELEASE_APPROVAL_JSON"
PREPARE = ".github/workflows/prepare-collector-release.yml"
SIGN = ".github/workflows/sign-collector-release.yml"
MAIN = "refs/heads/main"
COMMON_FILES = {"source.tar.gz": 64 << 20, "source-files.json": 4 << 20,
                "sbom.spdx.json": 4 << 20, release.PROVENANCE: 1 << 20}
FILES = {**dict.fromkeys(COMMANDS, 128 << 20), **COMMON_FILES}
DIGESTS = {"checksums_sha256": "SHA256SUMS", "provenance_sha256": release.PROVENANCE,
           "source_manifest_sha256": "source-files.json", "binary_sha256": BINARY,
           "intake_sha256": INTAKE, "alert_worker_sha256": "sherlock-alert-worker-linux-amd64",
           "admin_sha256": "sherlock-admin-linux-amd64", "api_sha256": "sherlock-api-linux-amd64",
           "admin_ui_sha256": "sherlock-admin-ui-linux-amd64", "migrate_sha256": "sherlock-migrate-linux-amd64"}

# Existing rc.6 packages retain their exact old allowlist. They are verifiable,
# never eligible for signing under the expanded schema2 workflow.
LEGACY_SOURCE = "5cec9c2205e26a6f6c4b0e8ba935fceceedfe39f"
LEGACY_TREE = "ad655b99ccba7f2f91e2261aa0249ff38f79c9eb"
LEGACY_PINS = {
    BINARY: "84786f7f822534347e6ebded691624c6db71f345e313f18304c68ff369070147",
    INTAKE: "846ea7d03d2442e670c527ae6f0452d47a3e8361f46d2e7add748ced8a855fe7",
}
LEGACY_FILES = {**dict.fromkeys(LEGACY_PINS, 128 << 20), **COMMON_FILES}
LEGACY_DIGESTS = {key: DIGESTS[key] for key in (
    "checksums_sha256", "provenance_sha256", "source_manifest_sha256", "binary_sha256", "intake_sha256")}


def binary_pins():
    return {BINARY: BINARY_SHA, INTAKE: INTAKE_SHA,
            "sherlock-alert-worker-linux-amd64": ALERT_WORKER_SHA,
            "sherlock-admin-linux-amd64": ADMIN_SHA, "sherlock-api-linux-amd64": API_SHA,
            "sherlock-admin-ui-linux-amd64": ADMIN_UI_SHA, "sherlock-migrate-linux-amd64": MIGRATE_SHA}


def package_spec(policy, *, allow_legacy=False):
    version = policy.get("schema_version")
    require(type(version) is int, "collector_exact_approval_required")
    if version == SCHEMA:
        return SOURCE, TREE, FILES, DIGESTS, binary_pins()
    require(allow_legacy and version == 1, "collector_exact_approval_required")
    return LEGACY_SOURCE, LEGACY_TREE, LEGACY_FILES, LEGACY_DIGESTS, LEGACY_PINS


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


def validate_policy(policy, commit, *, approved, allow_legacy=False):
    # Compatibility is read-only and never accepts a schema1 signing approval.
    require(not allow_legacy or approved is False, "collector_legacy_verification_only")
    source, _, _, digests, pins = package_spec(policy, allow_legacy=allow_legacy)
    require(set(policy) == {"schema_version", "approved", "repository", "release_tag", "source_commit",
                            "workflow_commit", "artifact_id", *digests}
            and policy["approved"] is approved and policy["repository"] == release.REPOSITORY,
            "collector_exact_approval_required")
    require(policy["source_commit"] == source and policy["workflow_commit"] == commit
            and valid(release.COMMIT, commit) and valid(release.TAG, policy["release_tag"])
            and type(policy["artifact_id"]) is int and policy["artifact_id"] > 0,
            "collector_approval_identity_mismatch")
    require(all(valid(release.HEX, policy[key]) for key in digests)
            and all(valid(release.HEX, sha) for sha in pins.values())
            and all(policy[key] == pins[name] for key, name in digests.items() if name in pins),
            "collector_approval_digest_mismatch")


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
    source, tree, files, digests, pins = package_spec(policy, allow_legacy=signed)
    expected = set(files) | {"SHA256SUMS"} | (release.BUNDLES if signed else set())
    require(directory.is_dir() and not directory.is_symlink()
            and {path.name for path in directory.iterdir()} == expected, "collector_unexpected_files")
    checksums = release.read_regular(directory / "SHA256SUMS", 16384)
    require(hashlib.sha256(checksums).hexdigest() == policy["checksums_sha256"], "collector_unapproved_checksums")
    sums = {}
    for line in checksums.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        require(match is not None, "collector_bad_checksum_row")
        sha, name = match.groups()
        require(name in files and name not in sums, "collector_bad_checksum_membership")
        sums[name] = sha
    require(set(sums) == set(files), "collector_bad_checksum_membership")
    require(all(release.digest_file(directory / name, files[name]) == sha for name, sha in sums.items()), "collector_payload_tampered")
    require(all(sums[name] == policy[key] for key, name in digests.items() if name != "SHA256SUMS")
            and all(sums[name] == sha for name, sha in pins.items()), "collector_payload_unapproved")
    provenance = release.object_json(release.read_regular(directory / release.PROVENANCE, FILES[release.PROVENANCE]))
    version = policy["schema_version"]
    require(type(provenance.get("schema_version")) is int and provenance["schema_version"] == version
            and provenance.get("package_state") == (PACKAGE_STATE if version == SCHEMA else "UNSIGNED_COLLECTOR_REVIEW_ONLY")
            and provenance.get("release_approved") is False and provenance.get("signed") is False
            and provenance.get("repository") == release.REPOSITORY
            and provenance.get("source_commit") == source and provenance.get("source_tree") == tree
            and provenance.get("target") == "linux/amd64" and provenance.get("byte_identical") is True
            and provenance.get("source_files_sha256") == sums["source-files.json"]
            and provenance.get("release_tag") == policy["release_tag"]
            and provenance.get("workflow_commit") == policy["workflow_commit"],
            "collector_wrong_provenance")
    if version == SCHEMA:
        require(provenance.get("independent_clean_builds") == {name: [sha, sha] for name, sha in pins.items()}
                and provenance.get("commands") == COMMANDS,
                "collector_wrong_provenance")
    else:
        require(provenance.get("two_independent_clean_builds") == [pins[BINARY], pins[BINARY]]
                and provenance.get("intake_independent_clean_builds") == [pins[INTAKE], pins[INTAKE]],
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
        validate_policy(policy, policy.get("workflow_commit"), approved=False, allow_legacy=True)
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

#!/usr/bin/env python3
"""Prepare an unsigned public Actions artifact; never approve, sign or install it."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location("assembler", Path(__file__).with_name("prepare-release-review.py"))
assembler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assembler)
release = assembler.release
WORKFLOW = release.REPOSITORY + "/.github/workflows/prepare-release.yml@refs/heads/main"


def context(environment, event):
    release.require(environment.get("GITHUB_REPOSITORY") == release.REPOSITORY
                    and isinstance(event.get("repository"), dict)
                    and event["repository"].get("private") is False,
                    "not_public_repository")
    release.require(environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                    and environment.get("GITHUB_REF") == "refs/heads/main"
                    and environment.get("GITHUB_REF_TYPE") == "branch"
                    and environment.get("GITHUB_WORKFLOW_REF") == WORKFLOW,
                    "not_manual_main_preparation")
    commit, tag = environment.get("GITHUB_SHA", ""), environment.get("RELEASE_TAG", "")
    release.require(bool(release.COMMIT.fullmatch(commit)), "invalid_source_commit")
    release.require(bool(release.TAG.fullmatch(tag)), "invalid_release_tag")
    return commit, tag


def review_record(directory, commit, tag, artifact_id):
    release.require(type(artifact_id) is int and artifact_id > 0, "invalid_artifact_id")
    release.require(bool(release.COMMIT.fullmatch(commit)), "invalid_source_commit")
    release.require(bool(release.TAG.fullmatch(tag)), "invalid_release_tag")
    record = {"schema_version": 1, "approved": False, "repository": release.REPOSITORY,
              "ref": "refs/tags/" + tag, "source_commit": commit, "artifact_id": artifact_id,
              "source_manifest_sha256": release.digest_file(directory / "source-files.json", release.FILES["source-files.json"]),
              "checksums_sha256": release.digest_file(directory / "SHA256SUMS", 16384),
              "provenance_sha256": release.digest_file(directory / release.PROVENANCE, release.FILES[release.PROVENANCE])}
    # Validate consistency, not approval: this in-memory policy is never emitted
    # or used to sign. The review record below always remains approved:false.
    release.payload(directory, dict(record, approved=True))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("build", "summary"))
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    event = release.object_json(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    commit, tag = context(os.environ, event)
    package = args.root / "package"
    if args.operation == "build":
        os.umask(0o077)
        repo = Path(__file__).resolve().parents[1]
        actual = subprocess.check_output(["git", "--no-replace-objects", "rev-parse", "HEAD"], cwd=repo,
                                         stderr=subprocess.DEVNULL, timeout=30).decode().strip()
        release.require(actual == commit, "checkout_wrong_commit")
        # Fail before source execution/building when the checkout has drifted.
        subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=repo, check=True, timeout=30)
        args.root.mkdir(mode=0o700)
        candidate = assembler.builder.build_candidate(repo, args.root / "candidate")
        digest = release.digest_file(candidate / "SHA256SUMS", 1 << 20)
        assembler.assemble(candidate, digest, package, repo=repo, commit=commit, tag=tag)
        print("unsigned public review package prepared; approval and signing remain required")
    else:
        raw_id = os.environ.get("ARTIFACT_ID", "")
        release.require(raw_id.isascii() and raw_id.isdecimal() and not raw_id.startswith("0"),
                        "invalid_artifact_id")
        record = review_record(package, commit, tag, int(raw_id))
        summary = ("## Unsigned release candidate — review required\n\n"
                   "Two clean offline builds matched. This is not a signed or approved client release. "
                   "Review source, notices, payloads, build evidence and these exact hashes before approval. "
                   "The proposed tag has not been created.\n\n"
                   "Artifact ID: `" + raw_id + "` (`sherlock-reviewed-release`; the name grants no approval).\n\n"
                   "Protected release approval record (deliberately disabled):\n\n```json\n"
                   + json.dumps(record, indent=2, sort_keys=True) + "\n```\n")
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
            output.write(summary)


if __name__ == "__main__":
    try:
        main()
    except (release.ReleaseError, assembler.exporter.ExportError, assembler.builder.CandidateError,
            OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(str(error) if isinstance(error, (release.ReleaseError, assembler.exporter.ExportError,
                                                 assembler.builder.CandidateError))
                 else "hosted_release_preparation_failed")

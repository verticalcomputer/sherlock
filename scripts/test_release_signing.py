"""Offline policy/payload/command tests; no token, signature or log submission."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("release", Path(__file__).with_name("verify-release.py"))
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class ReleaseSigningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.policy = {
            "schema_version": 1, "approved": True, "repository": release.REPOSITORY,
            "ref": "refs/tags/v0.1.0-rc.1", "source_commit": "a" * 40, "artifact_id": 123,
        }
        files = {name: (name + " synthetic fixture").encode() for name in release.FILES}
        files["source-files.json"] = b'{"schema_version": 1, "files": []}\n'
        self.policy["source_manifest_sha256"] = sha(files["source-files.json"])
        builds = {name: sha(files[name + "-linux-amd64"])
                  for name in ("sherlock-node-agent", "sherlock-gateway")}
        self.provenance = {
            "schema_version": 1, "release_approved": True, "repository": release.REPOSITORY,
            "ref": self.policy["ref"], "source_commit": self.policy["source_commit"],
            "source_manifest_sha256": self.policy["source_manifest_sha256"],
            "target": "linux/amd64", "byte_identical": True,
            "two_independent_clean_builds": [builds, builds],
        }
        files[release.PROVENANCE] = json.dumps(self.provenance).encode()
        for name, data in files.items():
            (self.directory / name).write_bytes(data)
        self.refresh_checksums()
        self.environment = {
            "GITHUB_REPOSITORY": release.REPOSITORY, "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": self.policy["ref"], "GITHUB_REF_TYPE": "tag",
            "GITHUB_WORKFLOW_REF": release.WORKFLOW + "@" + self.policy["ref"],
            "GITHUB_SHA": self.policy["source_commit"],
        }
        self.event = {"repository": {"private": False}}

    def refresh_checksums(self):
        body = "".join(sha((self.directory / name).read_bytes()) + "  " + name + "\n"
                       for name in sorted(release.FILES)).encode()
        (self.directory / "SHA256SUMS").write_bytes(body)
        self.policy["checksums_sha256"] = sha(body)
        self.policy["provenance_sha256"] = sha((self.directory / release.PROVENANCE).read_bytes())

    def test_exact_public_release_context_and_payload(self):
        release.context(self.policy, self.environment, self.event)
        release.payload(self.directory, self.policy)

    def test_unapproved_and_missing_approval_rejected(self):
        for value in (False, None, "true", 1):
            with self.subTest(value=value):
                policy = dict(self.policy, approved=value)
                with self.assertRaises(release.ReleaseError):
                    release.context(policy, self.environment, self.event)
        with patch.dict(os.environ, {"RELEASE_APPROVAL_JSON": ""}, clear=True):
            with self.assertRaisesRegex(release.ReleaseError, "release_approval_missing"):
                release.approval()

    def test_wrong_repo_event_ref_workflow_commit_rejected(self):
        for field, value in (
            ("GITHUB_REPOSITORY", "foreign/sherlock"), ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_REF", "refs/heads/main"), ("GITHUB_REF_TYPE", "branch"),
            ("GITHUB_WORKFLOW_REF", release.WORKFLOW + "@refs/heads/main"),
            ("GITHUB_SHA", "b" * 40),
        ):
            with self.subTest(field=field), self.assertRaises(release.ReleaseError):
                release.context(self.policy, dict(self.environment, **{field: value}), self.event)
        for event in ({}, {"repository": {"private": True}}, {"repository": {"private": "false"}}):
            with self.assertRaises(release.ReleaseError):
                release.context(self.policy, self.environment, event)

    def test_malformed_digest_tag_and_artifact_id_rejected(self):
        for key, value in (("ref", "refs/tags/v1;echo bad"), ("source_commit", "a" * 39),
                           ("artifact_id", True), ("artifact_id", 0),
                           ("checksums_sha256", "A" * 64), ("provenance_sha256", None)):
            with self.subTest(key=key), self.assertRaises(release.ReleaseError):
                release.context(dict(self.policy, **{key: value}), self.environment, self.event)

    def test_artifact_origin_pins_exact_artifact_and_source_commit(self):
        metadata = {"id": 123, "name": release.ARTIFACT_NAME, "expired": False,
                    "workflow_run": {"id": 456, "head_sha": "a" * 40}}
        self.assertEqual(release.artifact_origin(self.policy, metadata), 456)
        for key, value in (("id", 124), ("name", "unreviewed"), ("expired", True),
                           ("workflow_run", {"id": 456, "head_sha": "b" * 40})):
            with self.subTest(key=key), self.assertRaises(release.ReleaseError):
                release.artifact_origin(self.policy, dict(metadata, **{key: value}))

    def test_tampered_binary_and_manifest_rejected(self):
        (self.directory / "sherlock-node-agent-linux-amd64").write_bytes(b"tampered")
        with self.assertRaisesRegex(release.ReleaseError, "release_digest_mismatch"):
            release.payload(self.directory, self.policy)
        self.refresh_checksums()
        (self.directory / "SHA256SUMS").write_bytes(b"changed")
        with self.assertRaisesRegex(release.ReleaseError, "unapproved_checksums"):
            release.payload(self.directory, self.policy)

    def test_extra_private_directory_and_unknown_files_rejected(self):
        extra = self.directory / "docs"
        extra.mkdir()
        with self.assertRaisesRegex(release.ReleaseError, "unexpected_release_files"):
            release.payload(self.directory, self.policy)
        extra.rmdir()
        (self.directory / "credentials.json").write_bytes(b"synthetic")
        with self.assertRaises(release.ReleaseError):
            release.payload(self.directory, self.policy)

    def test_symlink_and_special_file_rejected(self):
        target = self.directory / "source.tar.gz"
        target.unlink()
        target.symlink_to(self.directory / "source-files.json")
        with self.assertRaises(OSError):
            release.payload(self.directory, self.policy)
        target.unlink()
        os.mkfifo(target)
        with self.assertRaisesRegex(release.ReleaseError, "unsafe_release_file"):
            release.payload(self.directory, self.policy)

    def test_traversal_duplicates_and_missing_checksum_rows_rejected(self):
        original = (self.directory / "SHA256SUMS").read_bytes()
        for body in (original + original.splitlines()[0] + b"\n",
                     original.replace(b"source.tar.gz", b"../source.tar.gz"),
                     b"\n".join(original.splitlines()[1:]) + b"\n"):
            (self.directory / "SHA256SUMS").write_bytes(body)
            self.policy["checksums_sha256"] = sha(body)
            with self.assertRaises(release.ReleaseError):
                release.payload(self.directory, self.policy)

    def test_provenance_cannot_convert_fixture_or_foreign_build_to_release(self):
        for key, value in (("release_approved", False), ("source_commit", "b" * 40),
                           ("ref", "refs/tags/v9.9.9"), ("repository", "foreign/sherlock"),
                           ("byte_identical", False), ("two_independent_clean_builds", [])):
            changed = copy.deepcopy(self.provenance)
            changed[key] = value
            (self.directory / release.PROVENANCE).write_text(json.dumps(changed))
            self.refresh_checksums()
            with self.subTest(key=key), self.assertRaises(release.ReleaseError):
                release.payload(self.directory, self.policy)

    def test_duplicate_json_fields_rejected(self):
        with self.assertRaisesRegex(release.ReleaseError, "duplicate_json_key"):
            release.object_json('{"approved":false,"approved":true}')

    def add_fake_bundles(self):
        for name in release.BUNDLES:
            (self.directory / name).write_bytes(b"synthetic command-test bundle")

    def test_verifier_pins_exact_identity_and_issuer_without_bypasses(self):
        self.add_fake_bundles()
        with patch.object(release, "cosign") as invoke:
            release.verify_signatures(self.directory, self.policy["ref"], self.policy["source_commit"])
        self.assertEqual(invoke.call_count, 2)
        for call in invoke.call_args_list:
            args = call.args[0]
            self.assertEqual(args[0], "verify-blob")
            self.assertEqual(args[args.index("--certificate-identity") + 1],
                             "https://github.com/" + release.WORKFLOW + "@" + self.policy["ref"])
            self.assertEqual(args[args.index("--certificate-oidc-issuer") + 1], release.ISSUER)
            self.assertEqual(args[args.index("--certificate-github-workflow-sha") + 1],
                             self.policy["source_commit"])
            self.assertFalse(any("ignore" in arg or "regexp" in arg for arg in args))

    def test_missing_bundle_or_failed_signature_stops_verification(self):
        with patch.object(release, "cosign") as invoke, self.assertRaises(OSError):
            release.verify_signatures(self.directory, self.policy["ref"], self.policy["source_commit"])
        invoke.assert_not_called()
        self.add_fake_bundles()
        with patch.object(release, "cosign", side_effect=release.ReleaseError("rejected")) as invoke:
            with self.assertRaises(release.ReleaseError):
                release.verify_signatures(self.directory, self.policy["ref"], self.policy["source_commit"])
        self.assertEqual(invoke.call_count, 1)

    def test_same_tag_signature_from_foreign_commit_stops_before_payload(self):
        self.add_fake_bundles()
        certificate_commit = "b" * 40
        def verify(args):
            self.assertEqual(args[args.index("--certificate-github-workflow-sha") + 1],
                             self.policy["source_commit"])
            if certificate_commit != args[args.index("--certificate-github-workflow-sha") + 1]:
                raise release.ReleaseError("signature_operation_failed")
        arguments = ["verify-release.py", "verify", "--directory", str(self.directory),
                     "--tag", "v0.1.0-rc.1", "--commit", self.policy["source_commit"],
                     "--source-sha256", self.policy["source_manifest_sha256"]]
        with patch.object(release, "cosign", side_effect=verify) as invoke, \
                patch.object(release, "payload") as validate, patch("sys.argv", arguments):
            with self.assertRaisesRegex(release.ReleaseError, "signature_operation_failed"):
                release.main()
        self.assertEqual(invoke.call_count, 1)
        validate.assert_not_called()

    def test_signing_validates_first_then_verifies_both_bundles(self):
        calls = []
        def invoke(args):
            calls.append(args[0])
            if args[0] == "sign-blob":
                Path(args[args.index("--bundle") + 1]).write_bytes(b"synthetic command-test bundle")
        with patch.object(release, "approval", return_value=self.policy), \
                patch.object(release, "cosign", side_effect=invoke), \
                patch("sys.argv", ["verify-release.py", "sign", "--directory", str(self.directory)]), \
                patch("builtins.print"):
            release.main()
        self.assertEqual(calls, ["sign-blob", "sign-blob", "verify-blob", "verify-blob"])
        release.payload(self.directory, self.policy, signed=True)

    def test_current_private_candidate_is_not_signable(self):
        (self.directory / release.PROVENANCE).write_text(json.dumps(dict(self.provenance, release_approved=False)))
        self.refresh_checksums()
        with patch.object(release, "approval", return_value=self.policy), \
                patch.object(release, "cosign") as invoke, \
                patch("sys.argv", ["verify-release.py", "sign", "--directory", str(self.directory)]):
            with self.assertRaisesRegex(release.ReleaseError, "unapproved_release_provenance"):
                release.main()
        invoke.assert_not_called()

    def test_client_verification_checks_signatures_then_rejects_changed_binary(self):
        self.add_fake_bundles()
        arguments = ["verify-release.py", "verify", "--directory", str(self.directory),
                     "--tag", "v0.1.0-rc.1", "--commit", self.policy["source_commit"],
                     "--source-sha256", self.policy["source_manifest_sha256"]]
        (self.directory / "sherlock-gateway-linux-amd64").write_bytes(b"changed")
        with patch.object(release, "cosign") as invoke, patch("sys.argv", arguments):
            with self.assertRaisesRegex(release.ReleaseError, "release_digest_mismatch"):
                release.main()
        self.assertEqual(invoke.call_count, 2)

    def test_cosign_failure_is_not_converted_to_success(self):
        result = type("Result", (), {"returncode": 1})()
        with patch.object(release.subprocess, "run", return_value=result) as invoke:
            with self.assertRaisesRegex(release.ReleaseError, "signature_operation_failed"):
                release.cosign(["verify-blob", "synthetic"])
        self.assertTrue(invoke.call_args.kwargs["capture_output"])


if __name__ == "__main__":
    unittest.main()

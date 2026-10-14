"""Hosted preparation policy tests; no hosted upload, signing or approval."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("hosted", Path(__file__).with_name("prepare-hosted-release.py"))
hosted = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hosted)


class HostedPreparationTests(unittest.TestCase):
    def setUp(self):
        self.environment = {"GITHUB_REPOSITORY": hosted.release.REPOSITORY,
                            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
                            "GITHUB_REF_TYPE": "branch", "GITHUB_WORKFLOW_REF": hosted.WORKFLOW,
                            "GITHUB_SHA": "a" * 40, "RELEASE_TAG": "v0.1.0-rc.1"}
        self.event = {"repository": {"private": False}}

    def test_manual_public_main_only_and_closed_tag(self):
        self.assertEqual(hosted.context(self.environment, self.event), ("a" * 40, "v0.1.0-rc.1"))
        for key, value in (("GITHUB_REPOSITORY", "foreign/sherlock"), ("GITHUB_EVENT_NAME", "pull_request"),
                           ("GITHUB_REF", "refs/heads/unreviewed"), ("GITHUB_REF_TYPE", "tag"),
                           ("GITHUB_WORKFLOW_REF", "foreign"), ("GITHUB_SHA", "a" * 39),
                           ("RELEASE_TAG", "v1;echo bad"), ("RELEASE_TAG", "v1.2.3\n")):
            with self.subTest(key=key), self.assertRaises(hosted.release.ReleaseError):
                hosted.context(dict(self.environment, **{key: value}), self.event)
        for event in ({}, {"repository": {"private": True}}, {"repository": {"private": "false"}}):
            with self.assertRaises(hosted.release.ReleaseError):
                hosted.context(self.environment, event)

    def test_summary_never_approves_and_records_exact_artifact_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event = root / "event.json"
            event.write_text(json.dumps(self.event))
            summary = root / "summary.md"
            # File and payload validation are covered by assembler/verifier tests.
            with patch.dict(os.environ, dict(self.environment, GITHUB_EVENT_PATH=str(event),
                            ARTIFACT_ID="123", GITHUB_STEP_SUMMARY=str(summary)), clear=True), \
                    patch.object(hosted.release, "digest_file", return_value="b" * 64), \
                    patch.object(hosted.release, "payload") as validate, \
                    patch("sys.argv", ["prepare-hosted-release.py", "summary", "--root", str(root)]):
                hosted.main()
            record = json.loads(summary.read_text().split("```json\n")[1].split("\n```")[0])
            self.assertIs(record["approved"], False)
            self.assertEqual(record["artifact_id"], 123)
            self.assertEqual(record["source_commit"], self.environment["GITHUB_SHA"])
            self.assertEqual(record["checksums_sha256"], "b" * 64)
            validate.assert_called_once()

    def test_summary_rejects_invalid_artifact_identity(self):
        for artifact in (True, 0, -1, "123"):
            with self.assertRaisesRegex(hosted.release.ReleaseError, "invalid_artifact_id"):
                hosted.review_record(Path("unused"), "a" * 40, "v0.1.0", artifact)


if __name__ == "__main__":
    unittest.main()

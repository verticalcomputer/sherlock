"""Offline tests. Signing calls and GitHub API responses are synthetic."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("collector", SCRIPTS / "verify-collector-release.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)
release = collector.release
SPEC = importlib.util.spec_from_file_location("prepare", SCRIPTS / "prepare-collector-release.py")
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


class CollectorReleaseTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.directory = self.root / "package"
        self.directory.mkdir()
        self.workflow = "a" * 40
        self.tag = "v0.1.0-collector.rc.1"
        self.event = {"repository": {"private": False}}
        self.event_path = self.root / "event.json"
        self.event_path.write_text(json.dumps(self.event))
        self.environment = {
            "GITHUB_REPOSITORY": release.REPOSITORY, "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": collector.MAIN, "GITHUB_REF_TYPE": "branch",
            "GITHUB_WORKFLOW_REF": f"{release.REPOSITORY}/{collector.SIGN}@{collector.MAIN}",
            "GITHUB_SHA": self.workflow, "GITHUB_WORKFLOW_SHA": self.workflow,
            "GITHUB_EVENT_PATH": str(self.event_path),
            "GITHUB_ACTIONS": "true", "ACTIONS_ID_TOKEN_REQUEST_URL": "https://fixture.invalid/token",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "synthetic",
        }
        self.provenance = {
            "schema_version": collector.SCHEMA, "package_state": collector.PACKAGE_STATE,
            "release_approved": False, "signed": False, "repository": release.REPOSITORY,
            "source_commit": collector.SOURCE, "source_tree": collector.TREE, "target": "linux/amd64",
            "byte_identical": True, "release_tag": self.tag, "workflow_commit": self.workflow,
        }
        for name in collector.FILES:
            (self.directory / name).write_bytes(f"synthetic {name}".encode())
        self.binary_sha = collector.digest(self.directory, collector.BINARY)
        self.intake_sha = collector.digest(self.directory, collector.INTAKE)
        self.hashes = {name: collector.digest(self.directory, name) for name in collector.COMMANDS}
        self.provenance["independent_clean_builds"] = {name: [sha, sha] for name, sha in self.hashes.items()}
        self.provenance["commands"] = collector.COMMANDS
        self.provenance["source_files_sha256"] = collector.digest(self.directory, "source-files.json")
        for module in (collector, prepare.collector):
            for name, sha in zip(("BINARY_SHA", "INTAKE_SHA", "ALERT_WORKER_SHA", "ADMIN_SHA", "API_SHA", "ADMIN_UI_SHA", "MIGRATE_SHA"), self.hashes.values()):
                pin = patch.object(module, name, sha)
                pin.start()
                self.addCleanup(pin.stop)
        self.refresh()

    def refresh(self, provenance=None):
        (self.directory / release.PROVENANCE).write_text(json.dumps(self.provenance if provenance is None else provenance))
        (self.directory / "SHA256SUMS").write_text("".join(
            f"{collector.digest(self.directory, name)}  {name}\n" for name in sorted(collector.FILES)))
        self.policy = {"schema_version": collector.SCHEMA, "approved": True, "repository": release.REPOSITORY,
                       "release_tag": self.tag, "source_commit": collector.SOURCE,
                       "workflow_commit": self.workflow, "artifact_id": 123,
                       **{key: collector.digest(self.directory, name) for key, name in collector.DIGESTS.items()}}

    def test_preparation_record_stays_disabled_and_matches_payload(self):
        record = prepare.record(self.directory, self.workflow, self.tag, 123)
        self.assertEqual(record, dict(self.policy, approved=False))
        collector.payload(self.directory, record)
        with self.assertRaisesRegex(release.ReleaseError, "collector_exact_approval_required"):
            collector.validate_policy(record, self.workflow, approved=True)

    def test_workflow_source_and_tag_are_distinct(self):
        self.assertEqual(collector.workflow_context(self.environment, self.event, collector.SIGN), self.workflow)
        self.assertNotEqual(self.workflow, collector.SOURCE)
        for field, wrong in (("GITHUB_SHA", collector.SOURCE), ("GITHUB_WORKFLOW_SHA", collector.SOURCE),
                             ("GITHUB_REF_TYPE", "tag"), ("GITHUB_REF", f"refs/tags/{self.tag}"),
                             ("GITHUB_REPOSITORY", "other/sherlock"), ("GITHUB_EVENT_NAME", "push"),
                             ("GITHUB_WORKFLOW_REF", release.WORKFLOW + "@refs/heads/main")):
            with self.subTest(field=field), self.assertRaisesRegex(release.ReleaseError, "wrong_collector_workflow"):
                collector.workflow_context(dict(self.environment, **{field: wrong}), self.event, collector.SIGN)
        with self.assertRaises(release.ReleaseError):
            collector.workflow_context(self.environment, {"repository": {"private": True}}, collector.SIGN)

    def test_exact_approval_rejects_wrong_source_workflow_digest_and_artifact(self):
        for field, wrong in (("approved", 1), ("source_commit", self.workflow), ("workflow_commit", collector.SOURCE),
                             ("release_tag", "v1;bad"), ("artifact_id", True),
                             ("binary_sha256", "b" * 64), ("provenance_sha256", None),
                             ("checksums_sha256", "X" * 64)):
            with self.subTest(field=field), self.assertRaises(release.ReleaseError):
                collector.validate_policy(dict(self.policy, **{field: wrong}), self.workflow, approved=True)

    def test_protected_environment_requires_review_no_admin_bypass_and_only_main(self):
        environment = {"name": collector.ENVIRONMENT, "can_admins_bypass": False,
                       "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
                       "protection_rules": [{"type": "required_reviewers", "reviewers": [{"type": "User"}]}]}
        branches = {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}
        def check(env, policy):
            collector.check_environment(lambda path: policy if "deployment-branch-policies" in path else env)
        check(environment, branches)
        for bad in (dict(environment, can_admins_bypass=True), dict(environment, protection_rules=[]), {}):
            with self.assertRaisesRegex(release.ReleaseError, "collector_environment_not_protected"):
                check(bad, branches)
        for bad in (dict(branches, total_count=2), dict(branches, branch_policies=[{"name": "*", "type": "branch"}]),
                    dict(branches, branch_policies=[{"name": "main", "type": "tag"}])):
            with self.assertRaisesRegex(release.ReleaseError, "collector_environment_not_main_only"):
                check(environment, bad)

    def test_tag_peeling_pins_exact_source(self):
        tag_object = "b" * 40
        ref = {"ref": f"refs/tags/{self.tag}", "object": {"type": "tag", "sha": tag_object}}
        annotation = {"sha": tag_object, "object": {"type": "commit", "sha": collector.SOURCE}}
        collector.check_tag(self.tag, lambda path: ref if "/ref/" in path else annotation)
        with self.assertRaisesRegex(release.ReleaseError, "collector_tag_wrong_commit"):
            collector.check_tag(self.tag, lambda _: dict(ref, object={"type": "commit", "sha": self.workflow}))

    def test_artifact_checks_preparation_run_identity(self):
        artifact = {"id": 123, "name": collector.ARTIFACT, "expired": False,
                    "workflow_run": {"id": 456, "head_sha": self.workflow}}
        run = {"id": 456, "head_sha": self.workflow, "event": "workflow_dispatch", "head_branch": "main",
               "path": collector.PREPARE, "conclusion": "success"}
        def check(artifact_metadata, run_metadata):
            return collector.artifact_origin(self.policy, lambda path: artifact_metadata if "/artifacts/" in path else run_metadata)
        self.assertEqual(check(artifact, run), 456)
        for bad in (dict(artifact, expired=True), dict(artifact, name=release.ARTIFACT_NAME),
                    dict(artifact, workflow_run={"id": 456, "head_sha": collector.SOURCE})):
            with self.assertRaisesRegex(release.ReleaseError, "collector_artifact_wrong_origin"):
                check(bad, run)
        for bad in (dict(run, conclusion="failure"), dict(run, path=collector.SIGN),
                    dict(run, head_branch="other"), dict(run, event="pull_request")):
            with self.assertRaisesRegex(release.ReleaseError, "collector_artifact_wrong_run"):
                check(artifact, bad)

    def test_package_tamper_even_with_rehashed_policy_is_rejected(self):
        path = self.directory / collector.BINARY
        path.write_bytes(b"tampered")
        with self.assertRaisesRegex(release.ReleaseError, "collector_payload_tampered"):
            collector.payload(self.directory, self.policy)
        self.refresh()
        with self.assertRaisesRegex(release.ReleaseError, "collector_payload_unapproved"):
            collector.payload(self.directory, self.policy)

    def test_sbom_describes_all_binaries_with_their_own_dependencies(self):
        binaries = {name: name.encode() for name in collector.COMMANDS}
        module = {"path": "example.test/api", "version": "v1.0.0", "archive_sha256": "0" * 64, "h1": "h1:fixture"}
        api = "sherlock-api-linux-amd64"
        dependencies = {name: set() for name in binaries}
        dependencies[api] = {(module["path"], module["version"])}
        prepare.write_sbom(self.root, [module], binaries, dependencies)
        sbom = json.loads((self.root / "sbom.spdx.json").read_text())
        relations = {(r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"])
                     for r in sbom["relationships"]}
        by_name = {entry["name"]: entry for entry in sbom["packages"]}
        expected = set()
        for name, data in binaries.items():
            entry = by_name[name]
            self.assertEqual(entry["checksums"][0]["checksumValue"], hashlib.sha256(data).hexdigest())
            expected.add(("SPDXRef-DOCUMENT", "DESCRIBES", entry["SPDXID"]))
            expected.add((entry["SPDXID"], "DEPENDS_ON", "SPDXRef-GoStdlib"))
        expected.add((by_name[api]["SPDXID"], "DEPENDS_ON", "SPDXRef-GoModule-0"))
        self.assertEqual(relations, expected)
        with self.assertRaisesRegex(prepare.release.ReleaseError, "collector_sbom_binary_inventory_mismatch"):
            prepare.write_sbom(self.root, [module], {collector.BINARY: b"only collector"}, dependencies)

    def test_intake_must_match_pinned_binary_and_approval(self):
        with self.assertRaisesRegex(release.ReleaseError, "collector_approval_digest_mismatch"):
            collector.validate_policy(dict(self.policy, intake_sha256="0" * 64), self.workflow, approved=True)
        intake = self.directory / collector.INTAKE
        intake.unlink()
        with self.assertRaisesRegex(release.ReleaseError, "collector_unexpected_files"):
            collector.payload(self.directory, self.policy)
        intake.write_bytes(b"substituted intake")
        with self.assertRaisesRegex(release.ReleaseError, "collector_payload_tampered"):
            collector.payload(self.directory, self.policy)
        self.refresh()
        with self.assertRaisesRegex(release.ReleaseError, "collector_payload_unapproved"):
            collector.payload(self.directory, self.policy)

    def test_extra_payloads_and_symlinks_rejected(self):
        extra = self.directory / "sherlock-gateway-linux-amd64"
        extra.touch()
        with self.assertRaisesRegex(release.ReleaseError, "collector_unexpected_files"):
            collector.payload(self.directory, self.policy)
        extra.unlink()
        path = self.directory / "source.tar.gz"
        path.unlink()
        path.symlink_to(self.directory / "source-files.json")
        with self.assertRaises(OSError):
            collector.payload(self.directory, self.policy)

    def test_provenance_rejects_rebound_source_tag_and_builds(self):
        for field, wrong in (("source_tree", "b" * 40), ("source_commit", self.workflow), ("release_tag", "v9.0.0"),
                             ("workflow_commit", collector.SOURCE), ("signed", True), ("release_approved", True),
                             ("independent_clean_builds", {collector.BINARY: [self.binary_sha]}),
                             ("commands", {collector.BINARY: "./cmd/sherlock-collector"}), ("target", "linux/arm64")):
            self.refresh(dict(self.provenance, **{field: wrong}))
            with self.subTest(field=field), self.assertRaisesRegex(release.ReleaseError, "collector_wrong_provenance"):
                collector.payload(self.directory, self.policy)

    def test_stubbed_signing_and_client_verification_pin_the_workflow_sha(self):
        calls = []
        def stub(args):
            calls.append(args)
            if args[0] == "sign-blob":
                Path(args[args.index("--bundle") + 1]).write_text("synthetic bundle")
        env = dict(self.environment, **{collector.APPROVAL: json.dumps(self.policy)})
        with patch.dict(os.environ, env, clear=True), patch.object(collector, "check_environment"), \
                patch.object(collector, "check_tag"), patch.object(collector, "artifact_origin"), \
                patch.object(release, "cosign", side_effect=stub), \
                patch("sys.argv", ["verify", "sign", "--directory", str(self.directory)]):
            collector.main()
        self.assertEqual([args[0] for args in calls], ["sign-blob", "sign-blob", "verify-blob", "verify-blob"])
        for args in calls[2:]:
            self.assertIn(f"https://github.com/{release.REPOSITORY}/{collector.SIGN}@{collector.MAIN}", args)
            self.assertIn(release.ISSUER, args)
            self.assertEqual(args[args.index("--certificate-github-workflow-sha") + 1], self.workflow)
            self.assertNotIn("--insecure-ignore-tlog", args)
        record = self.root / "trusted.json"
        record.write_text(json.dumps(dict(self.policy, approved=False)))
        argv = ["verify", "verify", "--directory", str(self.directory), "--review-record", str(record)]
        with patch("sys.argv", argv), patch.object(release, "cosign", side_effect=stub):
            collector.main()
        with patch("sys.argv", argv), patch.object(release, "cosign", side_effect=release.ReleaseError("bad_signature")), \
                patch.object(collector, "payload") as validate:
            with self.assertRaisesRegex(release.ReleaseError, "bad_signature"):
                collector.main()
            validate.assert_not_called()

    def test_sign_fails_before_cosign_without_approval_and_protection(self):
        argv = ["verify", "sign", "--directory", str(self.directory)]
        with patch("sys.argv", argv), patch.dict(os.environ, self.environment, clear=True), \
                patch.object(release, "cosign") as cosign:
            with self.assertRaisesRegex(release.ReleaseError, "collector_approval_missing"):
                collector.main()
            cosign.assert_not_called()
        env = dict(self.environment, **{collector.APPROVAL: json.dumps(self.policy)})
        with patch("sys.argv", argv), patch.dict(os.environ, dict(env, ACTIONS_ID_TOKEN_REQUEST_TOKEN=""), clear=True), \
                patch.object(release, "cosign") as cosign:
            with self.assertRaisesRegex(release.ReleaseError, "collector_github_oidc_required"):
                collector.main()
            cosign.assert_not_called()
        with patch("sys.argv", argv), patch.dict(os.environ, env, clear=True), \
                patch.object(collector, "check_environment", side_effect=release.ReleaseError("unprotected")), \
                patch.object(release, "cosign") as cosign:
            with self.assertRaisesRegex(release.ReleaseError, "unprotected"):
                collector.main()
            cosign.assert_not_called()

    def test_every_binary_requires_its_own_exact_pin_and_payload(self):
        for key, name in collector.DIGESTS.items():
            if name not in collector.COMMANDS:
                continue
            with self.subTest(binary=name):
                with self.assertRaisesRegex(release.ReleaseError, "collector_approval_digest_mismatch"):
                    collector.validate_policy(dict(self.policy, **{key: "0" * 64}), self.workflow, approved=True)
                path = self.directory / name
                original = path.read_bytes()
                path.write_bytes(b"unreviewed substitute")
                self.refresh()
                with self.assertRaisesRegex(release.ReleaseError, "collector_payload_unapproved"):
                    collector.payload(self.directory, self.policy)
                path.write_bytes(original)
                self.refresh()
        with patch.object(collector, "API_SHA", ""):
            with self.assertRaisesRegex(release.ReleaseError, "collector_approval_digest_mismatch"):
                collector.validate_policy(self.policy, self.workflow, approved=True)

    def test_schema1_remains_exact_and_verification_only(self):
        legacy = self.root / "legacy"
        legacy.mkdir()
        for name in collector.LEGACY_FILES:
            (legacy / name).write_bytes(("legacy " + name).encode())
        pins = {name: collector.digest(legacy, name) for name in collector.LEGACY_PINS}
        provenance = {
            "schema_version": 1, "package_state": "UNSIGNED_COLLECTOR_REVIEW_ONLY",
            "release_approved": False, "signed": False, "repository": release.REPOSITORY,
            "source_commit": collector.LEGACY_SOURCE, "source_tree": collector.LEGACY_TREE,
            "target": "linux/amd64", "byte_identical": True, "release_tag": self.tag,
            "workflow_commit": self.workflow, "source_files_sha256": collector.digest(legacy, "source-files.json"),
            "two_independent_clean_builds": [pins[collector.BINARY]] * 2,
            "intake_independent_clean_builds": [pins[collector.INTAKE]] * 2,
        }
        (legacy / release.PROVENANCE).write_text(json.dumps(provenance))
        (legacy / "SHA256SUMS").write_text("".join(
            f"{collector.digest(legacy, name)}  {name}\n" for name in sorted(collector.LEGACY_FILES)))
        policy = {"schema_version": 1, "approved": False, "repository": release.REPOSITORY,
                  "release_tag": self.tag, "source_commit": collector.LEGACY_SOURCE,
                  "workflow_commit": self.workflow, "artifact_id": 123,
                  **{key: collector.digest(legacy, name) for key, name in collector.LEGACY_DIGESTS.items()}}
        for name in release.BUNDLES:
            (legacy / name).write_text("synthetic old signature")
        with patch.dict(collector.LEGACY_PINS, pins, clear=True):
            collector.validate_policy(policy, self.workflow, approved=False, allow_legacy=True)
            collector.payload(legacy, policy, signed=True)
            record = self.root / "legacy-review.json"
            record.write_text(json.dumps(policy))
            with patch("sys.argv", ["verify", "verify", "--directory", str(legacy), "--review-record", str(record)]), \
                    patch.object(release, "cosign") as cosign:
                collector.main()
                self.assertEqual(cosign.call_count, 2)
                for call in cosign.call_args_list:
                    self.assertIn(self.workflow, call.args[0])
            with self.assertRaisesRegex(release.ReleaseError, "collector_exact_approval_required"):
                collector.validate_policy(dict(policy, approved=True), self.workflow, approved=True)
            with self.assertRaisesRegex(release.ReleaseError, "collector_legacy_verification_only"):
                collector.validate_policy(dict(policy, approved=True), self.workflow, approved=True, allow_legacy=True)
            (legacy / "sherlock-api-linux-amd64").write_text("cannot extend old approval")
            with self.assertRaisesRegex(release.ReleaseError, "collector_unexpected_files"):
                collector.payload(legacy, policy, signed=True)

    def test_schema2_does_not_accept_old_provenance_or_partial_build_map(self):
        for provenance in (
            dict(self.provenance, schema_version=1),
            dict(self.provenance, package_state="UNSIGNED_COLLECTOR_REVIEW_ONLY"),
            dict(self.provenance, independent_clean_builds={name: value for name, value in self.provenance["independent_clean_builds"].items() if name != "sherlock-admin-linux-amd64"}),
        ):
            self.refresh(provenance)
            with self.assertRaisesRegex(release.ReleaseError, "collector_wrong_provenance"):
                collector.payload(self.directory, self.policy)

    def test_migration_and_grant_source_inventory_is_bounded_and_explicit(self):
        source = self.root / "source"
        (source / "migrations").mkdir(parents=True)
        (source / "scripts").mkdir()
        (source / "deploy/cooling-baseline").mkdir(parents=True)
        names = {"migrations/000084_continuous_cooling_upload.up.sql", "migrations/000084_continuous_cooling_upload.down.sql",
                 "scripts/production-assessment-grants.sql", "scripts/cooling-upload-grants.sql",
                 "scripts/cooling_profiles.py", "scripts/cooling-profile-reader-grants.sql",
                 "scripts/database_cooling_profiles.py", "deploy/cooling-baseline/schema.sql", "deploy/cooling-baseline/grants.sql"}
        for name in names:
            (source / name).write_text("-- synthetic reviewed SQL")
        (source / "scripts/private.env").write_text("must not ship")
        self.assertEqual(prepare.deployment_source_files(source), names)
        bad = source / "migrations/private.sql"
        bad.touch()
        with self.assertRaisesRegex(prepare.release.ReleaseError, "collector_invalid_migration_inventory"):
            prepare.deployment_source_files(source)
        bad.unlink()
        grant = source / "scripts/production-assessment-grants.sql"
        grant.unlink()
        grant.symlink_to(source / "scripts/private.env")
        with self.assertRaisesRegex(prepare.release.ReleaseError, "collector_unsafe_deployment_source"):
            prepare.deployment_source_files(source)

    def test_workflows_are_manual_and_isolate_signing_permission(self):
        repo = SCRIPTS.parent
        preparation = (repo / collector.PREPARE).read_text()
        signing = (repo / collector.SIGN).read_text()
        for workflow in (preparation, signing):
            self.assertIn("\n  workflow_dispatch:", workflow)
            self.assertNotIn("\n  push:", workflow)
            self.assertNotIn("\n  pull_request:", workflow)
            self.assertNotIn("contents: write", workflow)
            self.assertNotIn("gh release", workflow)
            self.assertNotIn("sherlock-gateway-linux-amd64", workflow)
            for name in collector.COMMANDS:
                self.assertIn(f"/{name}", workflow)
            self.assertNotIn("collector-intake-linux-amd64", workflow)
        self.assertNotIn("id-token: write", preparation)
        preflight, protected = signing.split("\n  sign:", 1)
        self.assertNotIn("id-token: write", preflight)
        self.assertIn("needs: preflight", protected)
        self.assertIn("environment: collector-release-signing", protected)
        self.assertIn("id-token: write", protected)
        self.assertLess(protected.index("select"), protected.index("actions/download-artifact@"))
        self.assertLess(protected.index("prepare --directory"), protected.index("cosign-installer@"))

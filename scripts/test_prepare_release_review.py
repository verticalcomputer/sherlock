"""Unsigned review assembly regressions using synthetic source and executables."""
import copy
import importlib.util
import io
import json
import subprocess
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("assembler", Path(__file__).with_name("prepare-release-review.py"))
assembler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assembler)
sha = assembler.exporter.sha
encoded = assembler.exporter.encoded


class ReleaseReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.candidate = self.root / "build"
        self.candidate.mkdir()
        self.output = self.root / "package"
        entries = {"source/LICENSE": b"synthetic license", "source/NOTICE": b"synthetic copyright",
                   "source/THIRD_PARTY_NOTICES.md": b"synthetic notices",
                   "source/third_party/licenses/dependency.txt": b"synthetic dependency license",
                   "source/main.go": b"package main\n", "source/scripts/build.sh": b"#!/bin/sh\nexit 0\n",
                   "dependencies/cache/synthetic.zip": b"not executed"}
        for name, body in entries.items():
            self.write(name, body)
        self.manifest = {"files": [{"path": name, "sha256": sha(body), "bytes": len(body),
                                   "executable": name.endswith(".sh")}
                                   for name, body in sorted(entries.items())]}
        raw = encoded(self.manifest)
        self.write("source-files.json", raw)
        self.write("STATUS.json", encoded({"status": "PREPARED_PRIVATE_UNSIGNED_FIXTURE",
                                          "release_approved": False, "source_manifest_sha256": sha(raw)}))
        binaries = {name: (name + " synthetic").encode()
                    for name in ("sherlock-node-agent", "sherlock-gateway")}
        for name, body in binaries.items():
            self.write("bin/" + name + "-linux-amd64", body)
        hashes = {name: sha(body) for name, body in binaries.items()}
        self.provenance = {"schema_version": 1, "release_approved": False, "signed": False, "target": "linux/amd64", "version": "fixture.v1",
                           "source_manifest_sha256": sha(raw), "byte_identical": True,
                           "two_independent_clean_builds": [hashes, hashes]}
        self.write(assembler.release.PROVENANCE, encoded(self.provenance))
        self.write("sbom.spdx.json", b'{"spdxVersion":"SPDX-2.3"}\n')
        self.refresh()
        # These unit fixtures exercise assembly, not ELF generation. The real
        # builder tests parse actual linked ELF variables; real assembly never mocks it.
        self.identity = patch.object(assembler.builder, "elf_identity", side_effect=lambda body: {
            "main.releaseVersion": "fixture.v1", "main.releaseSourceSHA256": sha(encoded(self.manifest))})
        self.identity.start()
        self.addCleanup(self.identity.stop)

    def write(self, name, body):
        path = self.candidate / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)

    def refresh(self):
        body = "".join(sha(p.read_bytes()) + "  " + p.relative_to(self.candidate).as_posix() + "\n"
                       for p in sorted(self.candidate.rglob("*")) if p.is_file() and p.name != "SHA256SUMS").encode()
        self.write("SHA256SUMS", body)
        self.expected = sha(body)

    def test_exact_package_is_unsigned_non_signable_and_archive_matches_manifest(self):
        result = assembler.assemble(self.candidate, self.expected, self.output)
        self.assertFalse(result["release_approved"])
        self.assertEqual({p.name for p in self.output.iterdir()}, set(assembler.release.FILES) | {"SHA256SUMS"})
        provenance = json.loads((self.output / assembler.release.PROVENANCE).read_bytes())
        self.assertIsNone(provenance["source_commit"])
        with tarfile.open(self.output / "source.tar.gz", "r:gz") as archive:
            self.assertEqual(set(archive.getnames()), {row["path"] for row in self.manifest["files"]})
            for row in self.manifest["files"]:
                member = archive.getmember(row["path"])
                self.assertTrue(member.isfile())
                self.assertEqual(member.mtime, 0)
                self.assertEqual(member.mode, 0o755 if row["executable"] else 0o644)
                self.assertEqual(sha(archive.extractfile(member).read()), row["sha256"])
        policy = {"checksums_sha256": result["checksums_sha256"],
                  "source_manifest_sha256": result["source_manifest_sha256"],
                  "provenance_sha256": sha((self.output / assembler.release.PROVENANCE).read_bytes()),
                  "source_commit": "a" * 40, "ref": "refs/tags/v0.1.0"}
        with self.assertRaisesRegex(assembler.release.ReleaseError, "unapproved_release_provenance"):
            assembler.release.payload(self.output, policy)

    def source_repository(self):
        repo = self.root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        for row in self.manifest["files"]:
            if not row["path"].startswith("source/"):
                continue
            target = repo / row["path"].removeprefix("source/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((self.candidate / row["path"]).read_bytes())
            target.chmod(0o755 if row["executable"] else 0o644)
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Synthetic Test",
                        "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
                        "commit", "-qm", "synthetic source"], check=True)
        commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"]).decode().strip()
        return repo, commit

    def test_hosted_binding_preserves_unsigned_bytes_and_requires_external_approval(self):
        repo, commit = self.source_repository()
        result = assembler.assemble(self.candidate, self.expected, self.output,
                                    repo=repo, commit=commit, tag="v0.1.0-rc.1")
        provenance = json.loads((self.output / assembler.release.PROVENANCE).read_bytes())
        self.assertFalse(provenance["release_approved"])
        self.assertFalse(provenance["signed"])
        self.assertEqual(provenance["source_commit"], commit)
        self.assertEqual(provenance["approval_mode"], "external_exact_package")
        policy = dict(result, source_commit=commit, ref="refs/tags/v0.1.0-rc.1",
                      provenance_sha256=sha((self.output / assembler.release.PROVENANCE).read_bytes()))
        with self.assertRaisesRegex(assembler.release.ReleaseError, "unapproved_release_provenance"):
            assembler.release.payload(self.output, policy)
        assembler.release.payload(self.output, dict(policy, approved=True))
        self.assertEqual(json.loads((self.output / assembler.release.PROVENANCE).read_bytes()), provenance)

    def test_source_binding_rejects_wrong_commit_tag_bytes_mode_and_untracked_file(self):
        repo, commit = self.source_repository()
        entries = {row["path"]: ((self.candidate / row["path"]).read_bytes(), row["executable"])
                   for row in self.manifest["files"]}
        assembler.bind_source(entries, repo, commit, "v0.1.0-rc.1")
        cases = [(entries, "b" * 40, "v0.1.0", "checkout_wrong_commit"),
                 (entries, commit, "v1;echo bad", "invalid_release_tag"),
                 (dict(entries, **{"source/main.go": (b"changed", False)}), commit, "v0.1.0", "source_commit_bytes_mismatch"),
                 (dict(entries, **{"source/main.go": (b"package main\n", True)}), commit, "v0.1.0", "source_mode_mismatch"),
                 (dict(entries, **{"source/extra.go": (b"extra", False)}), commit, "v0.1.0", "source_not_in_commit")]
        for data, sha_value, tag, error in cases:
            with self.subTest(error=error), self.assertRaisesRegex(assembler.release.ReleaseError, error):
                assembler.bind_source(data, repo, sha_value, tag)
        with self.assertRaisesRegex(assembler.release.ReleaseError, "incomplete_source_binding"):
            assembler.assemble(self.candidate, self.expected, self.output, commit=commit)
        self.assertFalse(self.output.exists())

    def test_changed_candidate_or_unlisted_private_file_rejected(self):
        self.write("bin/sherlock-gateway-linux-amd64", b"changed")
        with self.assertRaisesRegex(assembler.release.ReleaseError, "candidate_digest_changed"):
            assembler.assemble(self.candidate, self.expected, self.output)
        self.refresh()
        self.write("private.json", b"synthetic")
        with self.assertRaisesRegex(assembler.release.ReleaseError, "unexpected_candidate_files"):
            assembler.assemble(self.candidate, self.expected, self.output)
        self.assertFalse(self.output.exists())

    def test_wrong_digest_and_nonmatching_clean_builds_rejected(self):
        with self.assertRaisesRegex(assembler.release.ReleaseError, "candidate_checksums_changed"):
            assembler.assemble(self.candidate, "0" * 64, self.output)
        provenance = copy.deepcopy(self.provenance)
        provenance["two_independent_clean_builds"][1]["sherlock-gateway"] = "b" * 64
        self.write(assembler.release.PROVENANCE, encoded(provenance))
        self.refresh()
        with self.assertRaisesRegex(assembler.release.ReleaseError, "build_provenance_mismatch"):
            assembler.assemble(self.candidate, self.expected, self.output)
        self.assertFalse(self.output.exists())

    def test_archive_rejects_private_or_unlisted_source(self):
        self.write("source/docs/audits/private.txt", b"synthetic")
        self.manifest["files"].append({"path": "source/docs/audits/private.txt", "sha256": sha(b"synthetic"), "bytes": 9,
                                      "executable": False})
        self.write("source-files.json", encoded(self.manifest))
        new_sha = sha(encoded(self.manifest))
        status = json.loads((self.candidate / "STATUS.json").read_bytes())
        status["source_manifest_sha256"] = new_sha
        self.write("STATUS.json", encoded(status))
        self.provenance["source_manifest_sha256"] = new_sha
        self.write(assembler.release.PROVENANCE, encoded(self.provenance))
        self.refresh()
        with self.assertRaisesRegex(assembler.exporter.ExportError, "private_destination"):
            assembler.assemble(self.candidate, self.expected, self.output)
        self.assertFalse(self.output.exists())

    def test_archive_is_deterministic_and_output_cannot_be_overwritten(self):
        assembler.assemble(self.candidate, self.expected, self.output)
        other = self.root / "package-two"
        assembler.assemble(self.candidate, self.expected, other)
        self.assertEqual((self.output / "source.tar.gz").read_bytes(), (other / "source.tar.gz").read_bytes())
        with self.assertRaises(FileExistsError):
            assembler.assemble(self.candidate, self.expected, self.output)

    def test_binary_initialized_source_identity_must_match_manifest(self):
        with patch.object(assembler.builder, "elf_identity", return_value={
                "main.releaseVersion": "fixture.v1", "main.releaseSourceSHA256": "f" * 64}):
            with self.assertRaisesRegex(assembler.release.ReleaseError, "binary_source_identity_mismatch"):
                assembler.assemble(self.candidate, self.expected, self.output)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()

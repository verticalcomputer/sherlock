#!/usr/bin/env python3
"""Focused private-builder regressions; no Sherlock candidate is built here."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
import warnings
import zipfile

SCRIPT = Path(__file__).with_name("build-telemetry-candidate.py")
SPEC = importlib.util.spec_from_file_location("candidate", SCRIPT)
candidate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(candidate)


class CandidateTests(unittest.TestCase):
    def test_module_zip_hash_matches_pinned_go_dirhash_vector(self):
        entries = [("example.org/demo@v1.0.0/b.go", b"package demo\n"),
                   ("example.org/demo@v1.0.0/go.mod", b"module example.org/demo\n")]
        expected = "h1:" + base64.b64encode(hashlib.sha256(
            b"".join(hashlib.sha256(content).hexdigest().encode() + b"  " + name.encode() + b"\n"
                     for name, content in sorted(entries))).digest()).decode()
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "module.zip"
            with zipfile.ZipFile(archive, "w") as output:
                for name, content in reversed(entries):
                    output.writestr(name, content)
            self.assertEqual(candidate.zip_h1(archive), expected)
            with zipfile.ZipFile(archive, "a") as output:
                output.writestr("example.org/demo@v1.0.0/extra.go", b"tampered\n")
            self.assertNotEqual(candidate.zip_h1(archive), expected)

    def test_zip_duplicate_and_newline_names_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "module.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("bad\nname", b"payload")
            with self.assertRaises(candidate.CandidateError):
                candidate.zip_h1(archive)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(archive, "w") as output:
                    output.writestr("duplicate", b"first")
                    output.writestr("duplicate", b"second")
            with self.assertRaises(candidate.CandidateError):
                candidate.zip_h1(archive)

    def test_private_output_cannot_overwrite_or_cross_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            created = candidate.new_private_directory(root / "candidate")
            self.assertEqual(stat.S_IMODE(created.stat().st_mode), 0o700)
            candidate.write(created / "proof.json", b"original")
            self.assertEqual(stat.S_IMODE((created / "proof.json").stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                candidate.new_private_directory(root / "candidate")
            self.assertEqual((created / "proof.json").read_bytes(), b"original")
            (root / "alias").symlink_to(created, target_is_directory=True)
            with self.assertRaises(OSError):
                candidate.new_private_directory(root / "alias" / "escape")
            with self.assertRaises(candidate.CandidateError):
                candidate.safe_relative(root / "alias" / "proof.json", root)

    def test_unsafe_writable_parent_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o777)
            unsafe.chmod(0o777)
            with self.assertRaises(candidate.CandidateError):
                candidate.new_private_directory(unsafe / "candidate")

    def test_invalid_arguments_are_redacted(self):
        result = subprocess.run([shutil.which("python3"), str(SCRIPT), "--private-secret=do-not-print"],
                                capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, b"telemetry candidate: invalid_arguments\n")
        self.assertEqual(result.stdout, b"")

    def test_lazy_graph_cannot_authorize_unpinned_compiled_dependency(self):
        module = {"Path": "example.org/demo", "Version": "v1.0.0"}
        self.assertFalse(candidate.graph_metadata_is_pinned(module, {}, {}))
        with self.assertRaises(candidate.CandidateError):
            candidate.graph_metadata_is_pinned(module, {}, {"example.org/demo": module})
        self.assertTrue(candidate.graph_metadata_is_pinned(module,
            {("example.org/demo", "v1.0.0/go.mod"): "h1:pinned"}, {"example.org/demo": module}))
        self.assertFalse(candidate.graph_metadata_is_pinned(
            {"Path": module["Path"], "Version": "v0.1.0"}, {}, {module["Path"]: module}))

    def test_graph_preserves_pinned_legacy_unselected_versions(self):
        selected = [{"Path": "example.org/demo", "Version": "v2.0.0"}]
        versions = candidate.graph_versions(selected, b"main example.org/demo@v2.0.0\n"
            b"example.org/demo@v2.0.0 example.org/legacy@v1.0.0\n"
            b"example.org/legacy@v1.0.0 example.org/demo@v1.0.0\nmain go@1.25.0\n")
        self.assertEqual([(value["Path"], value["Version"]) for value in versions],
            [("example.org/demo", "v1.0.0"), ("example.org/demo", "v2.0.0"),
             ("example.org/legacy", "v1.0.0")])

    def test_sbom_makes_no_dependency_license_or_rights_claim(self):
        document = candidate.sbom("a" * 64,
            [{"path": "example.org/demo", "version": "v1.0.0", "archive_sha256": "b" * 64,
              "sum": "h1:synthetic"}], {"synthetic": "c" * 64},
            {"version": "go1.25.5"}, "2026-10-08T00:00:00Z")
        self.assertEqual(document["spdxVersion"], "SPDX-2.3")
        self.assertIn("does not license", document["documentComment"])
        for package in document["packages"]:
            self.assertEqual(package["licenseConcluded"], "NOASSERTION")
            self.assertEqual(package["licenseDeclared"], "NOASSERTION")
            self.assertFalse(package["filesAnalyzed"])
        self.assertEqual(len({package["SPDXID"] for package in document["packages"]}), 4)

    @unittest.skipUnless(shutil.which("go"), "local Go toolchain unavailable")
    def test_elf_checks_actual_initialized_variables(self):
        # This independent, synthetic module never compiles Sherlock source.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.mod").write_text("module synthetic.invalid/identity\n\ngo 1.23\n")
            (root / "main.go").write_text('package main\nimport "fmt"\n'
                'var releaseVersion="DEVELOPMENT"\nvar releaseSourceSHA256="UNKNOWN"\n'
                'func main(){fmt.Println(releaseVersion,releaseSourceSHA256)}\n')
            env = dict(os.environ, GOOS="linux", GOARCH="amd64", CGO_ENABLED="0",
                       GOTOOLCHAIN="local", GOWORK="off", GOENV="off", GOFLAGS="",
                       GOPROXY="off", GOSUMDB="off")
            binary = root / "synthetic"
            subprocess.run([shutil.which("go"), "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
                "-ldflags=-buildid= -X main.releaseVersion=fixture.test -X main.releaseSourceSHA256=" + "d" * 64,
                "-o", str(binary), "."], cwd=root, env=env, check=True, capture_output=True)
            self.assertEqual(candidate.elf_identity(binary.read_bytes()), {
                "main.releaseVersion": "fixture.test", "main.releaseSourceSHA256": "d" * 64})
            with self.assertRaises(candidate.CandidateError):
                candidate.elf_identity(b"\x7fELF")

    @unittest.skipUnless(shutil.which("go"), "local Go toolchain unavailable")
    def test_clean_synthetic_two_build_pipeline(self):
        # Exercise the complete builder with independently authored tiny source.
        # No repository entrypoint or private Sherlock source is compiled here.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            repository = root / "synthetic"
            repository.mkdir(mode=0o700)
            (repository / "go.mod").write_text("module github.com/verticalcomputer/sherlock\n\ngo 1.23\n")
            (repository / "go.sum").write_text("")
            for target in candidate.TARGETS:
                command = repository / "cmd" / target
                command.mkdir(parents=True)
                (command / "main.go").write_text('package main\nimport "encoding/json"\nimport "os"\n'
                    'var releaseVersion="DEVELOPMENT"\nvar releaseSourceSHA256="UNKNOWN"\n'
                    'func main(){json.NewEncoder(os.Stdout).Encode(map[string]string{'
                    '"version":releaseVersion,"source_sha256":releaseSourceSHA256})}\n')
            for relative in (*candidate.CONTRACTS, *candidate.LEGAL_FILES, "third_party/licenses/synthetic.txt"):
                contract = repository / relative
                contract.parent.mkdir(parents=True, exist_ok=True)
                contract.write_text("Synthetic test contract, no approval.\n")
            (repository / "scripts").mkdir()
            shutil.copyfile(SCRIPT, repository / "scripts" / SCRIPT.name)
            shutil.copyfile(Path(__file__), repository / "scripts" / Path(__file__).name)
            output = candidate.build_candidate(repository, root / "candidate")
            status = json.loads((output / "STATUS.json").read_bytes())
            self.assertFalse(status["release_approved"])
            manifest = (output / "source-files.json").read_bytes()
            self.assertEqual(status["source_manifest_sha256"], candidate.sha(manifest))
            provenance = json.loads((output / "provenance.unsigned.json").read_bytes())
            self.assertFalse(provenance["signed"])
            self.assertEqual(provenance["two_independent_clean_builds"][0],
                             provenance["two_independent_clean_builds"][1])
            for line in (output / "SHA256SUMS").read_text().splitlines():
                digest, relative = line.split("  ", 1)
                self.assertEqual(candidate.sha((output / relative).read_bytes()), digest)


if __name__ == "__main__":
    unittest.main()

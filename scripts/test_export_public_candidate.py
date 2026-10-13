"""Public export boundaries with synthetic data only."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("exporter", Path(__file__).with_name("export-public-candidate.py"))
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)


class PublicExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.output = self.root / "candidate"
        self.manifest = {"schema_version": 1, "prepared_for_review": True, "release_approved": False,
                         "owner": "Vertical Computer Inc", "license": "Apache-2.0",
                         "module": "github.com/verticalcomputer/sherlock", "files": []}
        for name in sorted(exporter.REQUIRED):
            self.add(name, name.encode())

    def add(self, name, body, category="source", executable=False):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        row = {"source": name, "destination": name, "sha256": exporter.sha(body),
               "reviewed_for_candidate": True, "category": category, "executable": executable}
        self.manifest["files"].append(row)
        return row

    def run_export(self, expected=None):
        body = json.dumps(self.manifest).encode()
        (self.root / "manifest.json").write_bytes(body)
        return exporter.export(self.root, "manifest.json", expected or exporter.sha(body), self.output)

    def test_only_reviewed_files_and_no_git_history_or_private_receipt_in_source(self):
        (self.root / ".env").write_bytes(b"synthetic private")
        (self.root / ".git").mkdir()
        row = self.add("scripts/tool.py", b"print('synthetic')\n", "tooling", True)
        status = self.run_export()
        self.assertFalse(status["release_approved"])
        names = {str(p.relative_to(self.output / "source"))
                 for p in (self.output / "source").rglob("*") if p.is_file()}
        self.assertEqual(names, exporter.REQUIRED | {row["destination"], "PUBLIC_SOURCE_MANIFEST.json"})
        self.assertEqual((self.output / "source/scripts/tool.py").stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)

    def test_explicit_sanitized_replacement_preserves_original(self):
        row = self.add("internal/profile.go", b"private synthetic original")
        replacement = self.root / "docs/audits/review/profile.go"
        replacement.parent.mkdir(parents=True)
        replacement.write_bytes(b"public synthetic fixture")
        row.update(replacement="docs/audits/review/profile.go", replacement_sha256=exporter.sha(replacement.read_bytes()))
        self.run_export()
        self.assertEqual((self.output / "source/internal/profile.go").read_bytes(), b"public synthetic fixture")
        self.assertEqual((self.root / "internal/profile.go").read_bytes(), b"private synthetic original")

    def test_stale_source_replacement_and_manifest_fail_before_output(self):
        for what in ("source", "replacement", "manifest"):
            with self.subTest(what=what):
                row = self.manifest["files"][0]
                original = (self.root / row["source"]).read_bytes()
                if what == "source":
                    (self.root / row["source"]).write_bytes(b"changed")
                if what == "replacement":
                    (self.root / "replacement").write_bytes(b"changed")
                    row.update(replacement="replacement", replacement_sha256="0" * 64)
                with self.assertRaises(exporter.ExportError):
                    self.run_export("0" * 64 if what == "manifest" else None)
                self.assertFalse(self.output.exists())
                (self.root / row["source"]).write_bytes(original)
                row.pop("replacement", None)
                row.pop("replacement_sha256", None)

    def test_private_traversal_and_reserved_destinations_fail(self):
        row = self.manifest["files"][0]
        original = row["destination"]
        for name in ("../leak", "/absolute", "docs/audits/review.json", ".git/config", ".env",
                     "key.pem", "tmp/raw", "node_modules/x", "PUBLIC_SOURCE_MANIFEST.json", "a//b",
                     ".GIT/config", "docs/AUDITS/review.json", ".ENV", "ID_RSA", "status.json",
                     "public_source_manifest.json"):
            with self.subTest(name=name), self.assertRaises(exporter.ExportError):
                row["destination"] = name
                self.run_export()
            self.assertFalse(self.output.exists())
        row["destination"] = original

    def test_symlink_file_and_ancestor_refused(self):
        row = self.add("linked/input", b"synthetic")
        target = self.root / "linked/input"
        target.unlink()
        target.symlink_to(self.root / "README.md")
        with self.assertRaises(OSError):
            self.run_export()
        target.unlink()
        target.parent.rmdir()
        target.parent.symlink_to(self.root)
        row["source"] = "linked/README.md"
        with self.assertRaises(OSError):
            self.run_export()
        self.assertFalse(self.output.exists())

    def test_duplicate_conflicting_unreviewed_missing_and_approved_manifest_refused(self):
        initial = copy.deepcopy(self.manifest)
        cases = []
        changed = copy.deepcopy(initial); changed["files"].append(changed["files"][0]); cases.append(changed)
        changed = copy.deepcopy(initial); changed["files"][0]["reviewed_for_candidate"] = False; cases.append(changed)
        changed = copy.deepcopy(initial); changed["files"].pop(); cases.append(changed)
        changed = copy.deepcopy(initial); changed["release_approved"] = True; cases.append(changed)
        changed = copy.deepcopy(initial); changed["files"][0]["category"] = "unreviewed"; cases.append(changed)
        for changed in cases:
            self.manifest = changed
            with self.assertRaises(exporter.ExportError):
                self.run_export()
            self.assertFalse(self.output.exists())

    def test_only_reviewed_binary_asset_allowed(self):
        row = self.add("assets/font.ttf", b"synthetic\x00font")
        with self.assertRaisesRegex(exporter.ExportError, "unreviewed_binary"):
            self.run_export()
        row["category"] = "asset"
        self.run_export()

    def test_existing_output_never_overwritten(self):
        self.output.mkdir()
        (self.output / "preserved").write_bytes(b"original")
        with self.assertRaises(FileExistsError):
            self.run_export()
        self.assertEqual((self.output / "preserved").read_bytes(), b"original")

    def test_duplicate_manifest_keys_refused(self):
        with self.assertRaisesRegex(exporter.ExportError, "duplicate_json_key"):
            exporter.object_json(b'{"files":[],"files":[]}')


if __name__ == "__main__":
    unittest.main()

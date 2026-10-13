import json
from pathlib import Path
import tempfile
import unittest

import knowledge


class KnowledgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "docs").mkdir()
        self.files = {"README.md", "docs/old.md"}
        (self.root / "README.md").write_text("# Current\n[history](docs/old.md)\n")
        (self.root / "docs/old.md").write_text("HISTORICAL_OBSERVATION")
        self.rows = [dict(path=p, kind=k, topics=["overview"], summary="purpose")
                     for p, k in [("README.md", "current"), ("docs/old.md", "historical")]]
        self.save()

    def save(self):
        (self.root / "docs/knowledge.json").write_text(json.dumps(dict(version=1, documents=self.rows)))

    def test_valid_context_excludes_history(self):
        rows = knowledge.read_index(self.root, self.files)
        knowledge.check_links(self.root, rows, self.files)
        result = knowledge.context(self.root, rows, "overview", 24000)
        self.assertIn("# Current", result)
        self.assertNotIn("HISTORICAL_OBSERVATION", result)

    def test_unindexed_new_document_fails(self):
        with self.assertRaisesRegex(ValueError, "unindexed"):
            knowledge.read_index(self.root, self.files | {"new.md"})

    def test_duplicate_and_untracked_registration_fail(self):
        self.rows.append(self.rows[0])
        self.save()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            knowledge.read_index(self.root, self.files)
        self.rows.pop()
        self.rows[0]["path"] = "private.md"
        self.save()
        with self.assertRaisesRegex(ValueError, "untracked"):
            knowledge.read_index(self.root, self.files)

    def test_broken_reference_link_fails(self):
        (self.root / "README.md").write_text("[contract][c]\n\n[c]: docs/missing.md\n")
        with self.assertRaisesRegex(ValueError, "missing or untracked"):
            knowledge.check_links(self.root, self.rows, self.files)

    def test_multiline_link_label_is_checked(self):
        (self.root / "README.md").write_text("[source and\ncontract](docs/missing.md)")
        with self.assertRaisesRegex(ValueError, "missing or untracked"):
            knowledge.check_links(self.root, self.rows, self.files)

    def test_untracked_existing_link_fails(self):
        (self.root / "secret.md").write_text("private")
        (self.root / "README.md").write_text("[private](secret.md)")
        with self.assertRaisesRegex(ValueError, "untracked"):
            knowledge.check_links(self.root, self.rows, self.files)

    def test_escape_and_symlink_fail(self):
        with self.assertRaisesRegex(ValueError, "non-canonical"):
            knowledge.confined(self.root, "../outside.md")
        (self.root / "alias.md").symlink_to(self.root / "README.md")
        with self.assertRaisesRegex(ValueError, "symlink"):
            knowledge.confined(self.root, "alias.md")
        (self.root / "alias").symlink_to(self.root / "docs", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            knowledge.confined(self.root, "alias/old.md")

    def test_budget_marks_truncation_and_unknown_topic_fails(self):
        (self.root / "README.md").write_text("x" * 30000)
        result = knowledge.context(self.root, self.rows, "overview", 1000)
        self.assertEqual(len(result), 1000)
        self.assertIn("[TRUNCATED:", result)
        with self.assertRaisesRegex(ValueError, "unknown"):
            knowledge.context(self.root, self.rows, "missing", 1000)

    def test_examples_external_urls_and_anchors_are_not_local_files(self):
        (self.root / "README.md").write_text(
            '~~~sh\n[x](absent.md)\n~~~\n`[x](absent.md)`\n'
            '[site](https://example.com)\n[heading](#current)\n'
        )
        knowledge.check_links(self.root, self.rows, self.files)


if __name__ == "__main__":
    unittest.main()

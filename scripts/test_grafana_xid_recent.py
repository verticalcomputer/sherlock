import copy
import unittest

from grafana_xid_recent import (
    NEW_COUNT,
    NEW_TABLE,
    OLD_COUNT,
    OLD_TABLE,
    UID,
    transform,
)


class GrafanaXIDRecentTest(unittest.TestCase):
    def dashboard(self):
        return {
            "uid": UID,
            "panels": [
                {"id": 13, "title": "GPUs with XID Errors", "targets": [{"expr": OLD_COUNT}], "other": "keep"},
                {"id": 42, "title": "XID Errors (current, non-zero)", "targets": [{"expr": OLD_TABLE}]},
                {"id": 99, "title": "Unrelated", "targets": [{"expr": "up"}]},
            ],
        }

    def test_only_reviewed_panels_change(self):
        original = self.dashboard()
        unrelated = copy.deepcopy(original["panels"][2])
        updated = transform(original)
        self.assertEqual(updated["panels"][0]["targets"][0]["expr"], NEW_COUNT)
        self.assertEqual(updated["panels"][1]["targets"][0]["expr"], NEW_TABLE)
        self.assertEqual(updated["panels"][2], unrelated)
        self.assertNotIn("or vector(0)", NEW_TABLE)
        self.assertIn("not proof of GPU recovery", updated["panels"][1]["description"])

    def test_unknown_dashboard_or_query_fails_closed(self):
        for changed in ("uid", "title", "expr"):
            dashboard = self.dashboard()
            if changed == "uid":
                dashboard["uid"] = "foreign"
            elif changed == "title":
                dashboard["panels"][0]["title"] = "unknown"
            else:
                dashboard["panels"][1]["targets"][0]["expr"] = "up"
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                transform(dashboard)


if __name__ == "__main__":
    unittest.main()

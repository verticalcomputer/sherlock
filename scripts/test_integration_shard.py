import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("integration_shard", Path(__file__).with_name("run-integration-shard.py"))
shard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shard)


class ShardTest(unittest.TestCase):
    def test_partition_is_complete_disjoint_balanced_and_stable(self):
        names = [f"TestCase{i}" for i in range(101)] + ["Example", "FuzzParser"]
        groups = shard.partition(names)
        self.assertEqual(sorted(sum(groups, [])), sorted(names))
        self.assertEqual(groups, shard.partition(reversed(names)))
        self.assertLessEqual(max(map(len, groups)) - min(map(len, groups)), 1)

    def test_compiled_discovery_preserves_examples_and_fuzz_seeds(self):
        names = ["TestOne", "TestTwo", "TestThree", "Example", "FuzzParser"]
        selected = []
        with patch.object(shard, "discover", return_value=names + ["ok package 0.001s"]):
            for lane in shard.LANES[:-1]:
                cmd = shard.plan(lane)
                self.assertIn("-race", cmd)
                self.assertIn("-count=1", cmd)
                self.assertIn("-tags=integration", cmd)
                self.assertEqual(cmd[-1], shard.POSTGRES)
                import re
                pattern = cmd[cmd.index("-run") + 1]
                selected.extend(n for n in names if re.fullmatch(pattern, n))
        self.assertEqual(sorted(selected), sorted(names))

    def test_other_lane_excludes_only_sharded_package(self):
        packages = ["example/one", shard.POSTGRES, "example/two"]
        with patch.object(shard, "discover", return_value=packages):
            cmd = shard.plan("other")
        self.assertEqual(cmd[-2:], ["example/one", "example/two"])
        self.assertNotIn(shard.POSTGRES, cmd)
        self.assertNotIn("-run", cmd)

    def test_empty_discovery_fails_instead_of_passing_without_tests(self):
        for lane in shard.LANES:
            with self.subTest(lane=lane), patch.object(shard, "discover", return_value=[]):
                with self.assertRaises(ValueError):
                    shard.plan(lane)


if __name__ == "__main__":
    unittest.main()

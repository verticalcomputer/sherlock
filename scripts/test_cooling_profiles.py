"""Offline fixtures for publication, settling and profile-only comparisons."""
import contextlib
from datetime import date, timedelta
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.parse

import cooling_profiles as p


class FakeProm:
    endpoint = "http://localhost:9090/api/v1/query"

    def __init__(self, temperature=62):
        self.temperature = temperature
        self.calls = []

    def read(self, gpu, node, start):
        self.calls.append((gpu, node, start))
        # One continuous period straddles midnight.
        times = range(int(start) - p.PADDING, int(start + p.DAY), 30)
        return {p.TEMP: dict.fromkeys(times, self.temperature), p.POWER: dict.fromkeys(times, 500)}


class ProfileTests(unittest.TestCase):
    scope = {"cluster_id": "c", "source_id": "prom", "enrollment_id": "e"}
    assets = {"GPU-fixture": ("n", "c/GPU/n/GPU-fixture/")}
    day = date(2024, 3, 2)

    def test_settling_gaps_exclusions_and_changes(self):
        cols = {p.TEMP: {}, p.POWER: {}}
        for t in range(0, 601, 15):
            cols[p.TEMP][t] = 60 + t // 300
            cols[p.POWER][t] = 525
        del cols[p.POWER][135]
        cols[p.POWER][285] = 550.001
        cols[p.TEMP][435] = float("nan")
        # A between-scrape incident at 583 breaks the final run.
        daily = p.day_stats(cols, 0, [(583, 584)])
        self.assertEqual(daily[500]["hist"], {60: 2, 61: 2})
        self.assertEqual(daily[500]["periods"], 4)
        self.assertEqual(daily[500]["last"], 570)

    def test_disjoint_exclusions_within_scrape(self):
        times = range(0, 316, 15)
        cols = {p.TEMP: dict.fromkeys(times, 60), p.POWER: dict.fromkeys(times, 500)}
        # At t=165 both intervals intersect the previous scrape span, and only the second covers the sample.
        rows = [r[0] for r in p.settled(cols, 0, [(151, 152), (158, 166)]) if r[3] == 500]
        self.assertEqual(rows, [120, 135, 150, 300, 315])

    def test_percentiles_merge_across_days_without_inventing_periods(self):
        prom = FakeProm()
        start = p.midnight(self.day)
        first = p.day_stats(prom.read("a", "b", start), start, [])
        second = p.day_stats(prom.read("a", "b", start + p.DAY), start + p.DAY, [])
        result = p.summarize([first, second])
        band = next(x for x in result if x["center_w"] == 500)
        self.assertEqual(band["periods"], 1)
        self.assertEqual(band["days"], 2)
        self.assertEqual(band["samples"], 2 * p.DAY // 30)
        # Explicitly missing day splits runs even when adjacent chunks look identical.
        third = p.day_stats(prom.read("a", "b", start + 3*p.DAY), start + 3*p.DAY, [])
        self.assertEqual(p.summarize([first, second, {}, third])[0]["periods"], 2)
        odd_even = {500: {"hist": {60: 2, 63: 2}, "periods": 1, "carry": None, "last": start}}
        q = p.summarize([odd_even])[0]
        self.assertEqual((q["median_c"], q["p95_c"]), (61.5, 63))

    def test_transport_checks_identities_conflicts_and_query_window(self):
        prom = p.Prometheus("http://localhost:9090")
        start = p.midnight(self.day)
        mixed = {"__name__": p.TEMP, "UUID": "g", "hostname": "n"}
        cases = {
            ('Hostname="n"', 'UUID="g"'): [{"__name__": p.TEMP, "Hostname": "n", "UUID": "g"}],
            ('Hostname="n"', 'uuid="g",UUID=""'): [{"__name__": p.TEMP, "Hostname": "n", "uuid": "g"}],
            ('hostname="n",Hostname=""', 'UUID="g"'): [mixed, dict(mixed, job="second_exporter")],
            ('hostname="n",Hostname=""', 'uuid="g",UUID=""'): [{"__name__": p.TEMP, "hostname": "n", "uuid": "g"}],
        }
        seen = set()

        def respond(req, timeout):
            request = urllib.parse.parse_qs(req.data.decode())
            query = request["query"][0]
            self.assertEqual(float(request["time"][0]), start + p.DAY - .001)
            host_gpu = next(pair for pair in cases if ",".join(pair) + "}" in query)
            seen.add(host_gpu)
            series = [{"metric": labels, "values": [[start, "60"], [start + 15, str(64 - i)]]}
                      for i, labels in enumerate(cases[host_gpu])]
            doc = {"status": "success", "data": {"resultType": "matrix", "result": series}}
            return io.BytesIO(json.dumps(doc).encode())
        prom.client = Mock()
        prom.client.open.side_effect = respond
        cols = prom.read("g", "n", start)
        self.assertEqual(seen, set(cases))
        self.assertEqual(cols[p.TEMP][start], 60)
        self.assertTrue(p.math.isnan(cols[p.TEMP][start+15]))
        # Physical parent and instance share the same pair. Instance data cannot
        # poison a real point, including when the instance label value is empty.
        cases[('hostname="n",Hostname=""', 'UUID="g"')] = [mixed, dict(mixed, GPU_I_ID="0"), dict(mixed, MIG_UUID="")]
        cols = prom.read("g", "n", start)
        self.assertEqual(cols[p.TEMP][start + 15], 64)
        for bad in (dict(mixed, Hostname="other"), dict(mixed, uuid="other"),
                    dict(mixed, Hostname="n", hostname=""), dict(mixed, UUID="wrong")):
            cases[('hostname="n",Hostname=""', 'UUID="g"')] = [bad]
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "identity"):
                prom.read("g", "n", start)

    def test_publication_resume_scope_and_changed_incident_intervals(self):
        key = self.assets["GPU-fixture"][1]
        prom = FakeProm()
        # Small independent ranges keep the test quick.
        def limited(gpu, node, start):
            prom.calls.append((gpu, node, start))
            ts = range(int(start), int(start+151), 15)
            return {p.TEMP: dict.fromkeys(ts, 60), p.POWER: dict.fromkeys(ts, 500)}
        prom.read = limited
        with TemporaryDirectory() as d, patch.object(p, "incident_windows", return_value=p.defaultdict(list)) as read_windows:
            args = SimpleNamespace(output_dir=Path(d), day=self.day, max_queries=4, refresh_cache=False)
            with self.assertRaisesRegex(ValueError, "budget"):
                p.build(args, self.scope, self.assets, prom)
            filename = args.output_dir / (str(self.day) + ".json")
            self.assertFalse(filename.exists())
            args.max_queries = 24
            p.build(args, self.scope, self.assets, prom)
            self.assertEqual(len(prom.calls), 24)
            first = filename.read_bytes()
            self.assertEqual(json.loads(first)["assets"][key][1]["days"], 24)
            p.build(args, self.scope, self.assets, prom)
            self.assertEqual(first, filename.read_bytes())
            self.assertEqual(len(prom.calls), 24)
            with self.assertRaisesRegex(ValueError, "scope"):
                p.build(args, dict(self.scope, source_id="new"), self.assets, prom)
            args.day += timedelta(days=1)
            incident_start = p.midnight(self.day) - 2*p.DAY + 10
            read_windows.return_value[key] = [(incident_start, incident_start + 300)]
            p.build(args, self.scope, self.assets, prom)
            self.assertEqual(len(prom.calls), 27)  # new, recent late-data refresh, changed exclusion
            published = json.loads((args.output_dir / (str(args.day) + ".json")).read_bytes())
            self.assertEqual(published["assets"][key][1]["days"], 23)
            self.assertEqual(first, filename.read_bytes())
            # Source amendments older than the overlap require an explicit full refresh.
            args.day += timedelta(days=1)
            args.refresh_cache = True
            p.build(args, self.scope, self.assets, prom)
            self.assertEqual(len(prom.calls), 51)

    def test_comparison_rejects_hindsight_and_counts_sustained_warming(self):
        with TemporaryDirectory() as d:
            start = p.midnight(self.day)
            key = self.assets["GPU-fixture"][1]
            ref = {"center_w": 500, "days": 24, "periods": 3, "samples": 70, "last_at": p.stamp(start - p.DAY),
                   "median_c": 60, "p95_c": 64}
            args = SimpleNamespace(day=self.day, snapshot=Path(d)/"snapshot.json")
            snapshot = dict(self.scope, schema=1, cutoff=p.stamp(start), published_at=p.stamp(start + p.DAY), assets={key:[ref]})
            args.snapshot.write_text(json.dumps(snapshot))
            prom = FakeProm(temperature=67)
            with self.assertRaisesRegex(ValueError, "unavailable"):
                p.compare(args, self.scope, self.assets, prom)
            self.assertEqual(prom.calls, [])
            # Exclude prepublication observations within the day.
            snapshot["published_at"] = p.stamp(start + 60)
            args.snapshot.write_text(json.dumps(snapshot))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                p.compare(args, self.scope, self.assets, prom)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["sustained_deviations"], 1)
            self.assertEqual(result["covered_samples"], p.DAY // 30 - 2)
            for rows in ([ref, ref], [dict(ref, last_at=p.stamp(start + 3600))], [dict(ref, days=25)],
                         [dict(ref, samples=1)], [dict(ref, median_c=-1)], [dict(ref, p95_c=59)],
                         [dict(ref, last_at=p.stamp(start - 25*p.DAY))], [dict(ref, p95_c=None)]):
                with self.subTest(rows=rows):
                    snapshot["assets"][key] = rows
                    args.snapshot.write_text(json.dumps(snapshot))
                    stdout = io.StringIO()
                    with contextlib.redirect_stdout(stdout):
                        p.compare(args, self.scope, self.assets, prom)
                    result = json.loads(stdout.getvalue())
                    self.assertGreater(result["settled_samples"], 0)
                    self.assertEqual(result.get("covered_samples", 0), 0)


if __name__ == "__main__":
    unittest.main()

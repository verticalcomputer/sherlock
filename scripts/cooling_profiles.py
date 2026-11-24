#!/usr/bin/env python3
"""Build dated cooling profiles outside the evaluator. Reads Prometheus and PostgreSQL."""
import argparse
import bisect
from collections import Counter, defaultdict
from datetime import date, datetime, time, timedelta, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlencode, urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, ProxyHandler, Request

TEMP = "DCGM_FI_DEV_GPU_TEMP"
POWER = "DCGM_FI_DEV_POWER_USAGE"
DAY = 86400
DAYS = 24
SETTLE = 120
MAX_GAP = 30
PADDING = SETTLE + 2 * MAX_GAP
MAX_READ = 8 << 20
UTC = timezone.utc


def stamp(seconds):
    return datetime.fromtimestamp(seconds, UTC).isoformat().replace("+00:00", "Z")


def midnight(day):
    return datetime.combine(day, time(), UTC).timestamp()


def parse_time(value):
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise ValueError("timestamp requires time zone")
    return moment.timestamp()


def scope_from(path):
    doc = json.loads(path.read_bytes())
    a = doc["assessment"]
    scope = {"cluster_id": a["cluster_id"], "source_id": a["source_id"], "enrollment_id": a["run_id"]}
    if doc["schema"] != 1 or a["category"] != "gpu_cooling" or not 1 <= len(a["assets"]) <= 128:
        raise ValueError("expected an enrolled cooling fleet")
    assets = {}
    for asset in a["assets"]:
        gpu, node, key = asset["gpu_uuid"], asset["node_id"], asset["entity_key"]
        if (key != f"{scope['cluster_id']}/GPU/{node}/{gpu}/" or gpu in assets
                or not re.fullmatch(r"GPU-[A-Za-z0-9_.:-]{1,124}", gpu)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", node)):
            raise ValueError("enrollment has ambiguous asset identity")
        assets[gpu] = (node, key)
    return scope, assets


def incident_windows(scope, start, end):
    # psql binds quoted literals. libpq gets its credential from the publisher's environment.
    args = ["psql", "-XqAtw", "-v", "ON_ERROR_STOP=1"]
    for key, value in {**scope, "lo": stamp(start - PADDING), "hi": stamp(end)}.items():
        args.extend(["-v", f"{key}={value}"])
    sql = """
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '10s';
SELECT 'scope-present' FROM production_assessment_enrollments WHERE cluster_id=:'cluster_id'
 AND source_id=:'source_id' AND enrollment_id=:'enrollment_id';
SELECT json_build_array(asset,extract(epoch FROM opened_at)-900,
                        extract(epoch FROM least(coalesce(closed_at, :'hi'::timestamptz), :'hi'::timestamptz)))
FROM production_notification_occurrences
WHERE cluster_id=:'cluster_id' AND enrollment_id=:'enrollment_id' AND source_id=:'source_id'
 AND opened_at < :'hi'::timestamptz
 AND (closed_at IS NULL OR closed_at >= :'lo'::timestamptz) LIMIT 65537;
COMMIT;
"""
    output = subprocess.run(args, input=sql, text=True, capture_output=True, timeout=20, check=True)
    windows = defaultdict(list)
    lines = output.stdout.splitlines()
    if not lines or lines[0] != "scope-present" or len(lines) > 65537:
        raise ValueError("missing enrollment or incident history exceeds bound")
    for line in lines[1:]:
        key, lo, hi = json.loads(line)
        windows[key].append((lo, hi))
    return windows


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Prometheus:
    def __init__(self, url):
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username is not None or parts.query or parts.fragment:
            raise ValueError("invalid Prometheus URL")
        self.endpoint = url.rstrip("/") + "/api/v1/query"
        self.client = build_opener(ProxyHandler({}), NoRedirect())

    def read(self, gpu, node, start):
        # Raw range selectors preserve sensor times. Each label layout must use a
        # disjoint selector; a PromQL set union cannot combine range vectors.
        end = start + DAY
        columns = {TEMP: {}, POWER: {}}
        remaining = MAX_READ
        for host_label in ("Hostname", "hostname"):
            host = host_label + "=" + json.dumps(node)
            if host_label == "hostname":
                host += ',Hostname=""'
            for gpu_label in ("UUID", "uuid"):
                uuid = gpu_label + "=" + json.dumps(gpu)
                if gpu_label == "uuid":
                    uuid += ',UUID=""'
                query = f'{{__name__=~"{TEMP}|{POWER}",{host},{uuid}}}[{DAY + PADDING}s]'
                # The left edge is open. Offset the query by 1 ms so midnight is included.
                body = urlencode({"query": query, "time": f"{end - .001:.3f}", "timeout": "15s"}).encode()
                with self.client.open(Request(self.endpoint, data=body), timeout=20) as response:
                    raw = response.read(remaining + 1)
                remaining -= len(raw)
                if remaining < 0:
                    raise ValueError("GPU-day responses exceed byte budget")
                doc = json.loads(raw)
                if doc["status"] != "success" or doc.get("warnings") or doc["data"]["resultType"] != "matrix":
                    raise ValueError("incomplete Prometheus response")
                for series in doc["data"]["result"]:
                    self.add_series(series, gpu, node, start, columns)
        return columns

    @staticmethod
    def add_series(series, gpu, node, start, columns):
        labels = series["metric"]
        metric = labels["__name__"]
        # A parent and an instance can share UUID+node. Only physical data
        # contributes; presence of an instance label is sufficient, even if empty.
        mig = {"GPU_I_ID", "GPU_I_PROFILE", "GPU_CI_ID", "gpu_instance_id", "compute_instance_id", "MIG_UUID"}
        if mig.intersection(labels):
            return
        # Match domain.DCGMIdentity alias consistency for the remaining physical rows.
        for upper, lower, expected in (("Hostname", "hostname", node), ("UUID", "uuid", gpu)):
            primary = labels.get(upper, "")
            if (lower in labels and primary and primary != labels[lower]) or (primary or labels.get(lower)) != expected:
                raise ValueError("Prometheus returned an ambiguous or unexpected identity")
        if metric not in columns:
            raise ValueError("Prometheus returned data outside the requested physical GPU identity")
        for ts, raw_value in series["values"]:
            if not start - PADDING <= ts < start + DAY:
                raise ValueError("sample outside query window")
            value = float(raw_value)
            col = columns[metric]
            if ts in col and col[ts] != value:
                value = math.nan
            col[ts] = value


def merged_windows(windows, start):
    out = []
    for lo, hi in sorted(windows):
        if hi < start - PADDING or lo >= start + DAY:
            continue
        lo, hi = max(lo, start - PADDING), min(hi, start + DAY)
        if out and lo <= out[-1][1]:
            out[-1][1] = max(hi, out[-1][1])
        else:
            out.append([lo, hi])
    return out


def settled(columns, start, windows):
    """Yield qualifying (time, C, W, center, previous qualifying time in this run)."""
    runs = {}
    ends = [w[1] for w in windows]
    last = None
    for ts in sorted(columns[TEMP].keys() | columns[POWER].keys()):
        w = columns[POWER].get(ts, math.nan)
        c = columns[TEMP].get(ts, math.nan)
        # Even an exclusion wholly between two scrapes breaks the settling clock.
        i = bisect.bisect_left(ends, ts if last is None else last)
        crossed = i < len(windows) and windows[i][0] <= ts
        if last is None or ts - last > MAX_GAP or crossed:
            runs.clear()
        last = ts
        containing = bisect.bisect_left(ends, ts)
        excluded = containing < len(windows) and windows[containing][0] <= ts
        if (excluded or not 0 <= w <= 2000
                or not 0 <= c <= 150 or int(c) != c):
            runs.clear()
            continue
        centers = range(max(0, math.ceil((w - 25) / 25)) * 25,
                        min(80, math.floor((w + 25) / 25)) * 25 + 1, 25)
        runs = {center: runs.get(center, (ts, None)) for center in centers}
        for center, (began, previous) in runs.items():
            if ts - began >= SETTLE:
                if ts >= start:
                    yield ts, int(c), w, center, previous
                runs[center] = (began, ts)


def day_stats(columns, start, windows):
    bands = {}
    for ts, c, _, center, previous in settled(columns, start, windows):
        if center not in bands:
            bands[center] = {"hist": Counter(), "periods": 1, "carry": previous, "first": ts, "last": ts}
        elif previous is None:
            bands[center]["periods"] += 1
        band = bands[center]
        band["hist"][c] += 1
        band["last"] = ts
    return bands


def quantile(hist, n):
    for c, count in sorted(hist.items()):
        n -= count
        if n <= 0:
            return c
    raise ValueError("empty histogram")


def summarize(days):
    bands = {}
    for daily in days:
        for band_key, counts in daily.items():
            center = int(band_key)
            b = bands.setdefault(center, {"hist": Counter(), "days": 0, "periods": 0, "last": None})
            carry = counts["carry"]
            b["periods"] += counts["periods"] - int(carry is not None and carry == b["last"])
            b["days"] += 1
            b["last"] = counts["last"]
            b["hist"].update({int(c): k for c, k in counts["hist"].items()})
    out = []
    for center, b in sorted(bands.items()):
        h = b["hist"]
        n = sum(h.values())
        median = (quantile(h, (n + 1) // 2) + quantile(h, (n + 2) // 2)) / 2
        out.append({"center_w": center, "samples": n, "days": b["days"], "periods": b["periods"],
                    "median_c": median, "p95_c": quantile(h, math.ceil(.95 * n)), "last_at": stamp(b["last"])})
    return out


def write_json(path, obj, exclusive=False):
    # Reader sees only a complete snapshot. Retain access mode inherited from the directory's group.
    fd, temp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, allow_nan=False, separators=(",", ":"), sort_keys=True)
            f.write("\n")
            f.flush()
            if f.tell() > MAX_READ:
                raise ValueError("profile exceeds byte budget")
            os.fchmod(f.fileno(), 0o640)
            os.fsync(f.fileno())
        if exclusive:
            os.link(temp, path)
        else:
            os.replace(temp, path)
        parent = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        Path(temp).unlink(missing_ok=True)


def cache_key(scope, asset, endpoint, windows):
    # Cache schema includes all semantic inputs. Bump the version on algorithm changes.
    data = json.dumps([2, scope, asset, endpoint, windows], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode()).hexdigest()


def build(args, scope, assets, prom):
    today = datetime.now(UTC).date()
    cutoff_day = args.day if args.day else today
    if cutoff_day > today:
        raise ValueError("future cutoff")
    end = midnight(cutoff_day)
    path = args.output_dir / (str(cutoff_day) + ".json")
    cache = args.output_dir / ".profile-days"
    cache.mkdir(mode=0o700, exist_ok=True)
    if not 1 <= args.max_queries <= 128 * DAYS:
        raise ValueError("max-queries must be within 1..3072")
    with (cache / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if path.exists():
            snapshot = json.loads(path.read_bytes())
            if any(snapshot.get(k) != v for k, v in scope.items()) or set(snapshot["assets"]) != {a for _, a in assets.values()}:
                raise ValueError("existing snapshot belongs to a different scope")
            print(f"Snapshot already published for {cutoff_day}")
            return
        start = end - DAYS * DAY
        windows = incident_windows(scope, start, end)
        profile = {}
        calls = 0
        for gpu, (node, key) in sorted(assets.items()):
            days = []
            asset_hash = hashlib.sha256(key.encode()).hexdigest()
            for i in range(DAYS):
                lower = start + i * DAY
                window = merged_windows(windows[key], lower)
                signature = cache_key(scope, key, prom.endpoint, window)
                file = cache / f"{stamp(lower)[:10]}-{asset_hash}.json"
                chunk = json.loads(file.read_bytes()) if file.exists() else {}
                # Revisit yesterday's previously cached chunk once to catch delayed writes.
                needs_refresh = (args.refresh_cache or i >= DAYS - 2) and chunk.get("refresh_for") != str(cutoff_day)
                if chunk.get("signature") != signature or needs_refresh:
                    if calls >= args.max_queries:
                        raise ValueError("query budget reached; rerun to resume from saved GPU-day summaries")
                    stats = day_stats(prom.read(gpu, node, lower), lower, window)
                    chunk = {"signature": signature, "bands": stats, "refresh_for": str(cutoff_day)}
                    write_json(file, chunk)
                    calls += 1
                days.append(chunk["bands"])
            profile[key] = summarize(days)
        write_json(path, {**scope, "schema": 1, "cutoff": stamp(end), "published_at": stamp(datetime.now(UTC).timestamp()),
                          "assets": profile}, exclusive=True)
        # Only prune files owned by this publisher. Keep snapshots for thirty full days.
        for file in cache.iterdir():
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}-[0-9a-f]{64}\.json", file.name) and file.name[:10] < stamp(start)[:10]:
                file.unlink()
        for file in args.output_dir.iterdir():
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}\.json", file.name) and file.name[:10] < str(cutoff_day - timedelta(days=30)):
                file.unlink()
        print(f"Published {len(profile)} GPU profiles from {calls} GPU-day reads for {cutoff_day}")


def qualified_bands(rows, cutoff):
    # Same validity and evidence-depth requirements as coolingprofile.Reader.
    # A duplicate center invalidates the band even when both rows are identical.
    seen = set()
    qualified = {}
    for b in rows:
        center = b["center_w"]
        if center in seen:
            qualified.pop(center, None)
            continue
        seen.add(center)
        median, upper = b.get("median_c"), b.get("p95_c")
        days, periods, samples = (b.get(k) for k in ("days", "periods", "samples"))
        if (type(median) not in (int, float) or type(upper) not in (int, float) or not 0 <= median <= upper <= 150
                or any(type(v) is not int for v in (days, periods, samples))
                or not 3 <= days <= DAYS or periods < 3 or samples < max(days, periods)):
            continue
        last = parse_time(b["last_at"])
        if cutoff - DAYS * DAY <= last < cutoff:
            qualified[center] = (b, last)
    return qualified


def compare(args, scope, assets, prom):
    with args.snapshot.open("rb") as file:
        raw = file.read(MAX_READ + 1)
    if len(raw) > MAX_READ:
        raise ValueError("snapshot exceeds byte budget")
    snapshot = json.loads(raw)
    if snapshot.get("schema") != 1 or any(snapshot.get(k) != v for k, v in scope.items()):
        raise ValueError("snapshot identity mismatch")
    start = midnight(args.day)
    cutoff = parse_time(snapshot["cutoff"])
    published = parse_time(snapshot["published_at"])
    if cutoff % DAY != 0 or published < cutoff or not cutoff <= start <= cutoff + 2 * DAY or published >= start + DAY:
        raise ValueError("snapshot unavailable or stale for comparison day")
    if args.day >= datetime.now(UTC).date():
        raise ValueError("comparison needs a completed day")
    for gpu, (node, key) in sorted(assets.items()):
        bands = qualified_bands(snapshot["assets"].get(key, []), cutoff)
        counts = Counter()
        since = last = None
        last_center = None
        for ts, c, w, center, previous in settled(prom.read(gpu, node, start), start, []):
            nearest = 25 * math.floor(w / 25 + .5)
            if center != nearest or ts < published or w <= 0:
                continue
            counts["settled_samples"] += 1
            match = bands.get(center)
            if match is None or ts - match[1] > 7 * DAY:
                since = last = None
                continue
            counts["covered_samples"] += 1
            b, _ = match
            if c > b["p95_c"]:
                counts["above_p95"] += 1
            if c > 65 and c - b["median_c"] > 5:
                if last is None or previous != last or center != last_center:
                    since = ts
                if ts - since >= 30 and (last is None or last - since < 30):
                    counts["sustained_deviations"] += 1
                last, last_center = ts, center
            else:
                since = last = None
        print(json.dumps({"asset": key, "cutoff": snapshot["cutoff"], "day": str(args.day), **counts}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enrollment", type=Path, required=True)
    parser.add_argument("--prometheus-url", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    publish = commands.add_parser("build", help="publish one immutable rolling 24-day profile")
    publish.add_argument("--output-dir", type=Path, required=True)
    publish.add_argument("--day", type=date.fromisoformat, help="UTC cutoff date (default today)")
    publish.add_argument("--max-queries", type=int, default=128 * DAYS, help="cap GPU-day reads (four serial HTTP queries per read)")
    publish.add_argument("--refresh-cache", action="store_true", help="reread source chunks for a new cutoff")
    observe = commands.add_parser("compare", help="measure held-out settled observations without delivery")
    observe.add_argument("--snapshot", type=Path, required=True)
    observe.add_argument("--day", type=date.fromisoformat, required=True)
    args = parser.parse_args()
    scope, assets = scope_from(args.enrollment)
    prom = Prometheus(args.prometheus_url)
    if args.command == "build":
        build(args, scope, assets, prom)
    else:
        compare(args, scope, assets, prom)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as error:
        sys.exit("Cooling profiles failed: " + str(error))

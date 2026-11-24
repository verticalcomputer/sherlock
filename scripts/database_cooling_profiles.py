"""Publish immutable per-enrollment cumulative GPU temperature baselines in PostgreSQL."""
import argparse
from collections import Counter
import csv
from datetime import datetime, timezone, timedelta
import io
import json
import math
from pathlib import Path
import subprocess
import time

import cooling_profiles as p

STEP = 14400
IST = timezone(timedelta(hours=5, minutes=30))


def db(sql, variables=None):
    args = ["psql", "-XqAtw", "-v", "ON_ERROR_STOP=1"]
    for key, value in (variables or {}).items():
        args.extend(["-v", f"{key}={value}"])
    return subprocess.run(args, input=sql, text=True, check=True, stdout=subprocess.PIPE,
                          timeout=90).stdout.splitlines()


def read(sql, variables):
    return db("BEGIN READ ONLY; SET LOCAL statement_timeout='8s';\n" + sql + "\nCOMMIT;", variables)


def validated_band(b):
    hist = Counter({int(k): v for k, v in b["histogram_c"].items()})
    if not hist or any(not 0 <= k <= 150 or type(n) != int or n <= 0 for k, n in hist.items()):
        raise ValueError("invalid temperature histogram")
    n = sum(hist.values())
    median = (p.quantile(hist, (n + 1)//2) + p.quantile(hist, (n + 2)//2)) / 2
    upper = p.quantile(hist, (95*n+99)//100)
    if (n, median, upper) != (b["samples"], b["median_c"], b["p95_c"]):
        raise ValueError("summary inconsistent with histogram")
    return hist


def paired_read(scope, asset, start):
    sql = """SELECT extract(epoch FROM observed_at),metric,min(value),max(value)
FROM public.observations WHERE cluster_id=:'cluster_id' AND source_id=:'source_id'
AND entity_key=:'asset' AND observed_at>=to_timestamp(:lo) AND observed_at<to_timestamp(:hi)
AND metric IN ('DCGM_FI_DEV_POWER_USAGE','DCGM_FI_DEV_GPU_TEMP')
GROUP BY observed_at,metric;"""
    rows = read(sql, {**scope, "asset": asset, "lo": start-p.PADDING, "hi": start+STEP})
    cols = {p.TEMP: {}, p.POWER: {}}
    for row in rows:
        ts, metric, lo, hi = row.split("|")
        cols[metric][float(ts)] = float(lo) if lo and lo == hi else math.nan
    return cols


def advance(asset, cols, start, windows):
    bands = {b["center_w"]: b for b in asset["bands"]}
    paired = sum(t >= start and 0 <= c <= 150 and 0 <= cols[p.POWER].get(t, math.nan) <= 2000
                 for t, c in cols[p.TEMP].items())
    for center, stats in p.day_stats(cols, start, windows).items():
        prev = bands.get(center)
        hist = validated_band(prev) if prev else Counter()
        hist.update(stats["hist"])
        n = sum(hist.values())
        last = p.parse_time(prev["last_at"]) if prev else None
        new_day = last is None or datetime.fromtimestamp(last, IST).date() != datetime.fromtimestamp(start, IST).date()
        continuing = last is not None and stats["carry"] == last
        bands[center] = dict(center_w=center, histogram_c=dict(hist), samples=n,
            median_c=(p.quantile(hist,(n+1)//2)+p.quantile(hist,(n+2)//2))/2,
            p95_c=p.quantile(hist,(95*n+99)//100), days=(prev["days"] if prev else 0)+int(new_day),
            periods=(prev["periods"] if prev else 0)+stats["periods"]-int(continuing),last_at=p.stamp(stats["last"]))
    return dict(paired=asset["paired"]+paired, intervals_with_pairs=asset["intervals_with_pairs"]+int(paired>0),
                bands=list(bands.values()))


def publish(scope, origin, end, source, assets, previous):
    meta = {**scope, "origin":origin, "end":end, "input":source, "count":len(assets),
            "previous":previous if previous is not None else -1}
    sql = io.StringIO()
    sql.write("""BEGIN;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='30s';
CREATE TEMP TABLE staging_gpu (LIKE cooling_history.gpu) ON COMMIT DROP;
CREATE TEMP TABLE staging_band (LIKE cooling_history.temperature_band) ON COMMIT DROP;
COPY staging_gpu(enrollment_id,cutoff,asset,paired_samples,covered_intervals) FROM STDIN (FORMAT csv);
""")
    writer = csv.writer(sql,lineterminator="\n")
    for key, asset in assets.items():
        writer.writerow([scope["enrollment_id"],p.stamp(end),key,asset["paired"],asset["intervals_with_pairs"]])
    sql.write("\\.\nCOPY staging_band(enrollment_id,cutoff,asset,power_w,median_c,p95_c,samples,days,periods,last_at,histogram) FROM STDIN (FORMAT csv);\n")
    for key, asset in assets.items():
        for b in asset["bands"]:
            validated_band(b)
            writer.writerow([scope["enrollment_id"],p.stamp(end),key,b["center_w"],b["median_c"],b["p95_c"],
                             b["samples"],b["days"],b["periods"],b["last_at"],json.dumps(b["histogram_c"])])
    sql.write("\\.\n")
    sql.write("""SELECT pg_advisory_xact_lock(hashtextextended(:'enrollment_id', 9324));
SELECT NOT EXISTS(SELECT FROM cooling_history.refresh WHERE enrollment_id=:'enrollment_id' AND cutoff=to_timestamp(:end)) AS fresh \\gset
\\if :fresh
INSERT INTO cooling_history.refresh(enrollment_id,cutoff,start_at,cluster_id,source_id,input,asset_count)
SELECT :'enrollment_id',to_timestamp(:end),to_timestamp(:origin),:'cluster_id',:'source_id',:'input',:count
WHERE coalesce((SELECT max(extract(epoch FROM cutoff)) FROM cooling_history.refresh WHERE enrollment_id=:'enrollment_id'),-1)=:previous;
INSERT INTO cooling_history.gpu SELECT * FROM staging_gpu;
INSERT INTO cooling_history.temperature_band SELECT * FROM staging_band;
\\endif
COMMIT;
""")
    db(sql.getvalue(),meta)


def load_previous(scope, end):
    sql = """SELECT json_build_array(g.asset,g.paired_samples,g.covered_intervals,coalesce(
json_agg(json_build_object('center_w',b.power_w,'median_c',b.median_c,'p95_c',b.p95_c,
'samples',b.samples,'periods',b.periods,'days',b.days,'last_at',b.last_at,'histogram_c',b.histogram))
FILTER (WHERE b.asset IS NOT NULL),'[]')) FROM cooling_history.gpu g
LEFT JOIN cooling_history.temperature_band b USING(enrollment_id,cutoff,asset)
WHERE g.enrollment_id=:'enrollment_id' AND g.cutoff=to_timestamp(:end)
GROUP BY g.asset,g.paired_samples,g.covered_intervals;"""
    assets = {}
    for key, count, intervals, bands in map(json.loads, read(sql, {**scope, "end": end})):
        for b in bands:
            b["last_at"] = p.stamp(p.parse_time(b["last_at"]))
        assets[key] = dict(paired=count, intervals_with_pairs=intervals,
                           bands=sorted(bands,key=lambda b:b["center_w"]))
    return assets


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--enrollment", type=Path, required=True)
    ap.add_argument("--seed",type=Path)
    args=ap.parse_args()
    scope, enrolled=p.scope_from(args.enrollment)
    keys={key for _,key in enrolled.values()}
    if args.seed:
        seed=json.loads(args.seed.read_bytes())
        if seed["schema"]!="cumulative-four-hour-v1" or any(seed[k]!=v for k,v in scope.items()) or set(seed["assets"])!=keys:
            raise ValueError("seed scope mismatch")
        origin,end=(int(p.parse_time(seed[k])) for k in ("start","cutoff"))
        if (end-origin)%STEP or not origin<end<=time.time():
            raise ValueError("invalid seed cutoff")
        # Check before COPY so retrying a previously published seed is a read-only operation.
        existing=read("SELECT 1 FROM cooling_history.refresh WHERE enrollment_id=:'enrollment_id' AND cutoff=to_timestamp(:end);",{**scope,"end":end})
        if not existing:
            publish(scope, origin,end,"seed",seed["assets"],None)
        else:
            for asset in seed["assets"].values():
                asset["bands"].sort(key=lambda band: band["center_w"])
            if load_previous(scope, end) != seed["assets"]:
                raise ValueError("published seed differs")
        return
    result=read("""SELECT extract(epoch from start_at)::bigint,extract(epoch from cutoff)::bigint
FROM cooling_history.refresh WHERE enrollment_id=:'enrollment_id' AND cluster_id=:'cluster_id' AND source_id=:'source_id'
ORDER BY cutoff DESC LIMIT 1;""",scope)
    if not result:raise ValueError("seed required")
    origin,start=map(int,result[0].split("|"))
    # Ten minutes of receipt grace. Advance only completed half-open windows.
    target=origin+int((time.time()-600-origin)//STEP)*STEP
    while start<target:
        prior=load_previous(scope,start)
        if set(prior)!=keys:raise ValueError("enrollment changed; reconcile the baseline before advancing")
        windows=p.incident_windows(scope,start,start+STEP)
        prior_count = sum(row["paired"] for row in prior.values())
        for key in sorted(keys):
            prior[key]=advance(prior[key],paired_read(scope,key,start),start,p.merged_windows(windows[key],start))
        if sum(row["paired"] for row in prior.values()) == prior_count and time.time() < start + 2*STEP:
            raise ValueError("no paired readings in this fleet interval; checkpoint retained")
        publish(scope,origin,start+STEP,"sherlock",prior,start)
        start+=STEP
    print("current through",p.stamp(start))


if __name__=="__main__":
    main()

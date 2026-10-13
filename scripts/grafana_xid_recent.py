#!/usr/bin/env python3
"""Convert the qualified fixture2 XID panels from retained codes to observed changes.

This transforms a reviewed Grafana dashboard JSON file. It does not contact
Grafana or Prometheus and refuses an unexpected dashboard or panel expression.
"""

import argparse
import copy
import json
from pathlib import Path


UID = "fixtureNetwork-2-nvidia-dcgm-ai-hpc"
METRIC = (
    'DCGM_FI_DEV_XID_ERRORS{cluster=~"$cluster",hostname=~"$node",'
    'gpu=~"$gpu",modelName=~"$model"}'
)
OLD_COUNT = f"count(count by (hostname,gpu) ({METRIC} > 0)) or vector(0)"
OLD_TABLE = f"({METRIC} > 0) or vector(0)"
RECENT = f"({METRIC} > 0) and (changes({METRIC}[24h]) > 0)"
NEW_COUNT = f"count(count by (hostname,gpu) ({RECENT})) or vector(0)"
NEW_TABLE = RECENT


def transform(dashboard):
    dashboard = copy.deepcopy(dashboard)
    if dashboard.get("uid") != UID:
        raise ValueError("unexpected dashboard UID")
    panels = {panel.get("id"): panel for panel in dashboard.get("panels", [])}
    reviewed = []
    for panel_id, old_title, old_expr, new_title, new_expr in (
        (13, "GPUs with XID Errors", OLD_COUNT, "GPUs with observed XID changes (24h)", NEW_COUNT),
        (42, "XID Errors (current, non-zero)", OLD_TABLE, "Observed XID code changes (24h)", NEW_TABLE),
    ):
        panel = panels.get(panel_id)
        if panel is None or panel.get("title") != old_title or len(panel.get("targets", [])) != 1:
            raise ValueError(f"unexpected XID panel {panel_id}")
        target = panel["targets"][0]
        if target.get("expr") != old_expr:
            raise ValueError(f"unexpected XID query in panel {panel_id}")
        reviewed.append((panel, target, new_title, new_expr))
    for panel, target, new_title, new_expr in reviewed:
        panel["title"] = new_title
        panel["description"] = (
            "Shows only nonzero XID codes whose sampled value changed in the "
            "last 24 hours. DCGM can retain the last code after the event; "
            "a zero count means no sampled transition, not proof of GPU recovery. "
            "Repeated identical XID events may be invisible to this gauge."
        )
        target["expr"] = new_expr
    return dashboard


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.destination.resolve():
        parser.error("write to a new file, then replace the source atomically")
    dashboard = json.loads(args.source.read_text(encoding="utf-8"))
    updated = transform(dashboard)
    args.destination.write_text(json.dumps(updated, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

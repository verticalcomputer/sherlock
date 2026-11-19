#!/usr/bin/env python3
"""Partition integration CI across isolated runners, preserving full Go coverage."""
import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POSTGRES = "github.com/verticalcomputer/sherlock/internal/store/postgres"
POSTGRES_SHARDS = 3
LANES = [f"postgres-{i}" for i in range(POSTGRES_SHARDS)] + ["other"]


def partition(names):
    names = sorted(set(names))
    if len(names) < POSTGRES_SHARDS:
        raise ValueError("insufficient discovered tests for PostgreSQL shards")
    return [names[i::POSTGRES_SHARDS] for i in range(POSTGRES_SHARDS)]


def discover(command):
    return subprocess.check_output(command, cwd=ROOT, text=True).splitlines()


def plan(lane):
    common = ["go", "test", "-race", "-count=1", "-tags=integration", "-v"]
    if lane == "other":
        packages = [p for p in discover(["go", "list", "-tags=integration", "./..."]) if p != POSTGRES]
        if not packages:
            raise ValueError("no non-PostgreSQL packages discovered")
        return common + packages
    # Discover from the compiled suite, so newly added tests, examples and fuzz
    # seeds are assigned automatically. Subtests stay with their parent.
    lines = discover(["go", "test", "-race", "-tags=integration", "-list", ".", POSTGRES])
    names = [n for n in lines if re.fullmatch(r"(?:Test|Example|Fuzz)[A-Za-z0-9_]*", n)]
    selected = partition(names)[int(lane.rsplit("-", 1)[1])]
    pattern = "^(?:" + "|".join(re.escape(n) for n in selected) + ")$"
    return common + ["-run", pattern, POSTGRES]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lane", choices=LANES)
    parser.add_argument("--plan-only", action="store_true")
    args = parser.parse_args()
    command = plan(args.lane)
    if args.plan_only:
        print(json.dumps(command))
        return
    print(f"Integration lane: {args.lane}", flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


if __name__ == "__main__":
    main()

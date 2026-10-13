#!/usr/bin/env python3
"""Offline, reviewed-file-only contributor context and documentation checks."""

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
KINDS = {"current", "contract", "reference", "historical", "legal"}
LINK = re.compile(r"!?\[[^\]]*\]\((<[^>]+>|[^\s)]+)(?:\s+\"[^\"]*\")?\)")
REFERENCE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(<[^>]+>|\S+)", re.M)


def tracked_files(root):
    result = subprocess.run(
        ["git", "ls-files", "--stage", "-z"], cwd=root,
        check=True, capture_output=True, text=True,
    )
    files = set()
    for record in result.stdout.split("\0"):
        if record:
            metadata, path = record.split("\t", 1)
            mode, _, stage = metadata.split()
            if mode in {"100644", "100755"} and stage == "0":
                files.add(path)
    return files


def confined(root, name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or str(path) != name:
        raise ValueError(f"non-canonical path: {name}")
    target = root / name
    if any((root / Path(*path.parts[:i])).is_symlink() for i in range(1, len(path.parts) + 1)) or not target.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"symlink or external path: {name}")
    if not target.is_file():
        raise ValueError(f"missing file: {name}")
    return target


def read_index(root, files):
    data = json.loads((root / "docs/knowledge.json").read_text())
    if data.get("version") != 1 or not isinstance(data.get("documents"), list):
        raise ValueError("unsupported knowledge index")
    seen = set()
    for row in data["documents"]:
        name = row["path"]
        if name in seen or name not in files or not name.endswith(".md"):
            raise ValueError(f"duplicate, untracked or non-Markdown document: {name}")
        if name.startswith(("docs/audits/", "docs/evidence/", "third_party/")):
            raise ValueError(f"private/generated/third-party context prohibited: {name}")
        confined(root, name)
        if row["kind"] not in KINDS:
            raise ValueError(f"unknown document kind: {name}")
        if not row.get("summary") or not row.get("topics") or not all(
            isinstance(topic, str) and re.fullmatch(r"[a-z][a-z0-9-]*", topic)
            for topic in row["topics"]
        ):
            raise ValueError(f"missing summary or invalid topics: {name}")
        seen.add(name)
    expected = {p for p in files if p.endswith(".md") and not p.startswith("third_party/")}
    if seen != expected:
        raise ValueError("unindexed Markdown: " + ", ".join(sorted(expected - seen)))
    return data["documents"]


def prose_only(text):
    """Exclude fenced examples and inline code from file-link validation."""
    result = []
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            run = marker[1]
            if fence is None:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence):
                fence = None
            continue
        if fence is None:
            result.append(re.sub(r"`[^`]*`", "", line))
    return "\n".join(result)


def check_links(root, rows, files):
    errors = []
    for row in rows:
        name = row["path"]
        content = prose_only((root / name).read_text())
        targets = LINK.findall(content) + REFERENCE.findall(content)
        for raw in targets:
            url = urlsplit(raw.strip("<>"))
            if url.scheme or url.netloc or not url.path:
                continue
            path = (root / name).parent / unquote(url.path)
            resolved = path.resolve()
            if not resolved.is_relative_to(root.resolve()):
                errors.append(f"{name}: link outside repository: {raw}")
                continue
            relative = resolved.relative_to(root.resolve()).as_posix()
            if path.is_symlink() or (relative not in files and not any(
                item.startswith(relative.rstrip("/") + "/") for item in files
            )) or not path.exists():
                errors.append(f"{name}: missing or untracked local link: {raw}")
    if errors:
        raise ValueError("\n".join(errors))


def context(root, rows, topic, limit):
    selected = [r for r in rows if topic in r["topics"] and r["kind"] != "historical"]
    if not selected:
        raise ValueError(f"unknown or history-only topic: {topic}")
    pieces = [
        "Sherlock contributor context: " + topic,
        "Working-tree reference material, not acceptance evidence or authorization.\n"
        "Historical records excluded. Verify claims against code and exact test/live evidence.",
    ]
    for row in selected:
        pieces.append(f"\n--- {row['path']} [{row['kind']}] ---\n{row['summary']}\n"
                      + confined(root, row["path"]).read_text())
    output = "\n".join(pieces)
    if len(output) > limit:
        suffix = "\n[TRUNCATED: context character budget reached; use the index to read remaining files.]"
        output = output[:limit - len(suffix)] + suffix
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check", "context", "list"])
    parser.add_argument("--topic", default="overview")
    parser.add_argument("--max-chars", type=int, default=24000)
    args = parser.parse_args()
    if not 1000 <= args.max_chars <= 100000:
        parser.error("--max-chars must be between 1000 and 100000")
    try:
        files = tracked_files(ROOT)
        rows = read_index(ROOT, files)
        if args.command == "check":
            check_links(ROOT, rows, files)
            print(f"Documentation index and local file links: PASS ({len(rows)} documents)")
        elif args.command == "list":
            for row in rows:
                print(f"{row['kind']:10} {row['path']} — {row['summary']}")
        else:
            print(context(ROOT, rows, args.topic, args.max_chars))
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        print(f"knowledge: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

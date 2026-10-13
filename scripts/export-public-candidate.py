#!/usr/bin/env python3
"""Export only digest-bound reviewed files. Never publishes or copies Git history."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

MAX_FILE = 32 << 20
MAX_TOTAL = 256 << 20
MAX_FILES = 10000
HEX = re.compile(r"[0-9a-f]{64}\Z")
CATEGORIES = {"source", "fixture", "documentation", "license", "asset", "tooling"}
REQUIRED = {"LICENSE", "NOTICE", "README.md", "SECURITY.md", "CONTRIBUTING.md",
            "THIRD_PARTY_NOTICES.md", "go.mod", "go.sum", "Makefile"}
PRIVATE_DIRS = {".git", ".local", ".idea", ".vscode", "node_modules", "__pycache__",
                "output", "tmp", "audits", "evidence", "pilots"}
PRIVATE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".db", ".sqlite", ".prof", ".test"}


class ExportError(Exception):
    pass


def require(condition, code):
    if not condition:
        raise ExportError(code)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def object_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=pairs)
    require(isinstance(result, dict), "invalid_manifest")
    return result


def relative(value):
    require(isinstance(value, str) and value and "\\" not in value
            and not any(ord(c) < 32 or ord(c) > 126 for c in value), "invalid_path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value
            and all(part not in (".", "..", "") for part in path.parts), "invalid_path")
    return path


def public_path(value):
    path = relative(value)
    name = path.name.casefold()
    require(not ({part.casefold() for part in path.parts} & PRIVATE_DIRS), "private_destination")
    require(name not in {"public_source_manifest.json", "status.json", "private-export-receipt.json"},
            "reserved_destination")
    require(path.suffix.lower() not in PRIVATE_SUFFIXES, "private_destination")
    require(not name.startswith(".env") or name.endswith(".example"), "private_destination")
    require(not name.startswith("id_rsa") and not name.startswith("id_ed25519"),
            "private_destination")
    return path


def read_relative(root, value, maximum=MAX_FILE):
    # Walk with directory descriptors: symlinks in ANY input component are refused.
    path = relative(value)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(file_fd, "rb") as source:
            info = os.fstat(source.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, "unsafe_input")
            body = source.read(maximum + 1)
            require(len(body) <= maximum, "input_too_large")
            return body
    finally:
        os.close(fd)


def reviewed_files(root, manifest):
    require(type(manifest.get("schema_version")) is int and manifest["schema_version"] == 1,
            "invalid_schema")
    require(manifest.get("prepared_for_review") is True
            and manifest.get("release_approved") is False, "not_review_candidate")
    require(manifest.get("owner") == "Vertical Computer Inc"
            and manifest.get("license") == "Apache-2.0"
            and manifest.get("module") == "github.com/verticalcomputer/sherlock", "wrong_public_identity")
    rows = manifest.get("files")
    require(isinstance(rows, list) and 0 < len(rows) <= MAX_FILES, "invalid_file_inventory")
    output, destinations, total = [], set(), 0
    for row in rows:
        require(isinstance(row, dict) and row.get("reviewed_for_candidate") is True,
                "unreviewed_file")
        require(row.get("category") in CATEGORIES and type(row.get("executable")) is bool,
                "invalid_file_classification")
        destination = str(public_path(row.get("destination")))
        # Case folding avoids collisions across common client filesystems.
        require(destination.casefold() not in destinations, "duplicate_destination")
        destinations.add(destination.casefold())
        require(isinstance(row.get("sha256"), str) and HEX.fullmatch(row["sha256"]),
                "invalid_input_digest")
        original = read_relative(root, row.get("source"))
        require(sha(original) == row["sha256"], "source_digest_changed")
        body = original
        if "replacement" in row:
            require(isinstance(row.get("replacement_sha256"), str)
                    and HEX.fullmatch(row["replacement_sha256"]), "invalid_replacement_digest")
            body = read_relative(root, row["replacement"])
            require(sha(body) == row["replacement_sha256"], "replacement_digest_changed")
        else:
            require("replacement_sha256" not in row, "missing_replacement")
        require(b"\x00" not in body or row["category"] == "asset", "unreviewed_binary")
        total += len(body)
        require(total <= MAX_TOTAL, "candidate_too_large")
        output.append((destination, body, row["executable"]))
    require(REQUIRED <= {name for name, _, _ in output}, "missing_public_contracts")
    paths = {name for name, _, _ in output}
    require(all(str(parent) not in paths for name in paths
                for parent in PurePosixPath(name).parents if str(parent) != "."), "path_conflict")
    return sorted(output)


def new_directory(path):
    # A fresh protected directory only; never overwrite another candidate.
    require(path.is_absolute() and ".." not in path.parts, "invalid_output")
    text = str(path)
    if sys.platform == "darwin":
        for alias in ("/var", "/tmp"):
            if text.startswith(alias + "/"):
                info = os.lstat(alias)
                require(info.st_uid == 0 and os.readlink(alias) == "private" + alias, "unsafe_parent")
                text = "/private" + text
    parts = Path(text).parts[1:]
    require(bool(parts), "invalid_output")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(next_fd)
            if (info.st_uid not in (0, os.geteuid())
                    or info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)):
                os.close(next_fd)
                raise ExportError("unsafe_parent")
            os.close(fd)
            fd = next_fd
        os.mkdir(parts[-1], 0o700, dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(fd)
    return Path(text)


def write(path, body, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o700 if executable else 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(body)
        target.flush()
        os.fsync(target.fileno())


def export(root, manifest_path, expected, output):
    require(isinstance(expected, str) and HEX.fullmatch(expected), "invalid_manifest_digest")
    raw = read_relative(root, manifest_path, 16 << 20)
    require(sha(raw) == expected, "manifest_digest_changed")
    manifest = object_json(raw)
    files = reviewed_files(root, manifest)  # Validate everything before creating output.
    directory = new_directory(output)
    inventory = {"schema_version": 1, "module": manifest["module"],
                 "license": manifest["license"], "owner": manifest["owner"],
                 "files": [{"path": name, "sha256": sha(body), "size": len(body),
                            "executable": executable} for name, body, executable in files]}
    for name, body, executable in files:
        write(directory / "source" / name, body, executable)
    public_manifest = encoded(inventory)
    write(directory / "source" / "PUBLIC_SOURCE_MANIFEST.json", public_manifest)
    write(directory / "private-export-receipt.json", encoded({
        "review_manifest_sha256": expected, "manifest": manifest,
        "public_source_manifest_sha256": sha(public_manifest)}))
    status = {"schema_version": 1, "state": "PREPARED_FOR_REVIEW", "release_approved": False,
              "file_count": len(files), "public_source_manifest_sha256": sha(public_manifest),
              "private_history_exported": False, "signed": False, "published": False}
    write(directory / "STATUS.json", encoded(status))
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest", required=True, help="Path relative to root")
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    status = export(args.root, args.manifest, args.manifest_sha256, args.output)
    print(json.dumps(status, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ExportError, OSError, ValueError, TypeError) as error:
        sys.exit(str(error) if isinstance(error, ExportError) else "public_export_failed")

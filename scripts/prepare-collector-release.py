#!/usr/bin/env python3
"""Prepare the pinned unsigned collector and intake package for exact GitHub review."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import quote
import uuid

SPEC = importlib.util.spec_from_file_location("collector", Path(__file__).with_name("verify-collector-release.py"))
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)
release = collector.release
require = release.require
REVISION, TREE = collector.SOURCE, collector.TREE
COMMANDS = {collector.BINARY: "./cmd/sherlock-collector", collector.INTAKE: "./cmd/sherlock-control"}
GO_VERSION = "go1.26.9"
REPOSITORY = release.REPOSITORY
MODULE = "github.com/" + REPOSITORY


def run(args, cwd, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env, timeout=600)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def archive(path, members):
    with path.open("xb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as tar:
            for name, (data, mode) in sorted(members.items()):
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode = len(data), mode
                tar.addfile(entry, io.BytesIO(data))
    with tarfile.open(path, "r:gz") as tar:
        entries = tar.getmembers()
        require([row.name for row in entries] == sorted(members), "collector_archive_inventory_mismatch")
        for entry in entries:
            data, mode = members[entry.name]
            require(entry.isfile() and entry.mode == mode, "collector_archive_member_mismatch")
            require(tar.extractfile(entry).read() == data, "collector_archive_bytes_mismatch")


def build(repo, output, proxy, workflow_commit, tag):
    require(run(["git", "--no-replace-objects", "rev-parse", REVISION + "^{tree}"], repo).decode().strip() == TREE, "collector_source_tree_mismatch")
    git_archive = run(["git", "--no-replace-objects", "archive", "--format=tar", REVISION], repo)
    go = Path(shutil.which("go")).resolve()
    env = dict(PATH=os.environ["PATH"], LC_ALL="C", TZ="UTC", GOENV="off",
               GOTOOLCHAIN="local", GOWORK="off", GOOS="linux", GOARCH="amd64",
               GOAMD64="v1", CGO_ENABLED="0", GOEXPERIMENT="", GOFLAGS="",
               GOPROXY=proxy, GOSUMDB="off", GOVCS="*:off", GOAUTH="off")
    require(run([str(go), "env", "GOVERSION"], repo, env).decode().strip() == GO_VERSION, "collector_go_toolchain_mismatch")
    toolenv = json.loads(run([str(go), "env", "-json", "GOROOT", "GOTOOLDIR", "GOHOSTOS", "GOHOSTARCH"], repo, env))
    goroot = Path(toolenv["GOROOT"])
    tool_paths = {"go": go, **{x: Path(toolenv["GOTOOLDIR"]) / x for x in ("asm", "compile", "link")}}
    tool_hashes = {x: digest(path.read_bytes()) for x, path in tool_paths.items()}
    flags = ["-mod=readonly", "-trimpath", "-buildvcs=false",
             f"-ldflags=-buildid= -X {MODULE}/internal/buildinfo.SourceRevision={REVISION} "
             f"-X {MODULE}/internal/buildinfo.SourceTree={TREE}"]
    with tempfile.TemporaryDirectory(prefix="sherlock-collector-rc-build-") as temporary:
        work = Path(temporary).resolve()
        source = work / "source"
        source.mkdir()
        with tarfile.open(fileobj=io.BytesIO(git_archive)) as tar:
            for entry in tar:
                name = PurePosixPath(entry.name)
                require(not name.is_absolute() and bool(name.parts) and ".." not in name.parts
                        and (entry.isfile() or entry.isdir()), "collector_unsafe_source_archive")
                if entry.isfile():
                    path = source / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(entry) as archived, path.open("xb") as destination:
                        shutil.copyfileobj(archived, destination)
                    path.chmod(0o755 if entry.mode & 0o111 else 0o644)
        public_manifest_data = (source / "PUBLIC_SOURCE_MANIFEST.json").read_bytes()
        public_manifest = json.loads(public_manifest_data)["files"]
        tracked = {x.relative_to(source).as_posix() for x in source.rglob("*") if x.is_file()}
        require({row["path"] for row in public_manifest} | {"PUBLIC_SOURCE_MANIFEST.json"} == tracked, "collector_public_source_inventory_mismatch")
        for row in public_manifest:
            path = source / row["path"]
            data = path.read_bytes()
            require(len(data) == row["size"] and digest(data) == row["sha256"], "collector_public_source_digest_mismatch")
            require(bool(path.stat().st_mode & 0o111) == row["executable"], "collector_public_source_mode_mismatch")
        print(f"Verified {len(public_manifest)} public source manifest entries.", flush=True)
        spec = importlib.util.spec_from_file_location("source_builder", source / "scripts/build-telemetry-candidate.py")
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)

        seed = work / "seed-modules"
        discover = dict(env, GOMODCACHE=str(seed), GOCACHE=str(work / "discovery-cache"))
        run([str(go), "mod", "download"], source, discover)
        local_files = set()
        modules = {}
        command_modules = {}
        for name, command in COMMANDS.items():
            packages = helper.objects(run([str(go), "list", "-mod=readonly", "-deps", "-json", command], source, discover))
            files, _, _ = helper.closure(packages, source, goroot)
            require(files and not any(path.startswith(("deploy/", ".github/")) for path in files),
                    "collector_unsafe_compilation_closure")
            local_files.update(files)
            command_modules[name] = set()
            for package in packages:
                mod = package.get("Module")
                if mod and not mod.get("Main"):
                    require(not mod.get("Replace"), "collector_module_replacement")
                    modules[mod["Path"]] = mod["Version"]
                    command_modules[name].add((mod["Path"], mod["Version"]))
        sums = {tuple(row.split()[:2]): row.split()[2] for row in (source / "go.sum").read_text().splitlines()}

        dependencies = []
        licenses = {"licenses/go/LICENSE": ((goroot / "LICENSE").read_bytes(), 0o644)}
        for path, version in sorted(modules.items()):
            mod = json.loads(run([str(go), "mod", "download", "-json", path + "@" + version], source, discover))
            require(mod["Sum"] == sums[path, version] == helper.zip_h1(Path(mod["Zip"])), "collector_module_archive_hash_mismatch")
            require(mod["GoModSum"] == sums[path, version + "/go.mod"] == helper.h1([("go.mod", Path(mod["GoMod"]).read_bytes())]), "collector_go_mod_hash_mismatch")
            module_dir = Path(mod["Dir"])
            notice_files = sorted(p for p in module_dir.iterdir() if p.is_file() and p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "PATENTS", "UNLICENSE")))
            require(bool(notice_files), "collector_module_notice_missing")
            for notice in notice_files:
                licenses[f"licenses/go-modules/{path}@{version}/{notice.name}"] = (notice.read_bytes(), 0o644)
            dependencies.append(dict(path=path, version=version, h1=mod["Sum"], go_mod_h1=mod["GoModSum"],
                                     archive_sha256=digest(Path(mod["Zip"]).read_bytes()), notices=[p.name for p in notice_files]))
        require(run([str(go), "mod", "verify"], source, discover).strip() == b"all modules verified", "collector_seed_modules_unverified")
        print(f"Verified {len(dependencies)} compiled module archives against go.sum.", flush=True)

        legal_names = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md")
        source_members = {}
        for name in sorted(local_files | {"go.mod", "go.sum", *legal_names}):
            path = source / name
            source_members[name] = (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
        source_members.update(licenses)
        source_manifest = {name: dict(sha256=digest(data), size=len(data), mode=oct(mode))
                           for name, (data, mode) in sorted(source_members.items())}

        def build(number):
            fresh = work / f"build-{number}"
            fresh.mkdir()
            fresh_source = fresh / "source"
            fresh_source.mkdir()
            for name, (data, mode) in source_members.items():
                if name.startswith("licenses/"):
                    continue
                dest = fresh_source / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                dest.chmod(mode)
            fresh_modules = fresh / "modules"
            shutil.copytree(seed / "cache", fresh_modules / "cache")
            offline = dict(env, GOPROXY="off", GOMODCACHE=str(fresh_modules), GOCACHE=str(fresh / "cache"))
            require(run([str(go), "mod", "verify"], fresh_source, offline).strip() == b"all modules verified", "collector_offline_modules_unverified")
            binaries = {}
            for name, command in COMMANDS.items():
                binary = fresh / name
                run([str(go), "build", *flags, "-o", str(binary), command], fresh_source, offline)
                info = json.loads(run([str(go), "version", "-m", "-json", str(binary)], fresh_source, offline))
                settings = {item["Key"]: item["Value"] for item in info["Settings"]}
                require(info["Path"] == MODULE + command[1:] and info["GoVersion"] == GO_VERSION,
                        "collector_build_identity_mismatch")
                require(all(settings.get(k) == v for k, v in (("GOOS", "linux"), ("GOARCH", "amd64"), ("GOAMD64", "v1"), ("CGO_ENABLED", "0"))),
                        "collector_build_target_mismatch")
                require({(m["Path"], m["Version"], m["Sum"]) for m in info["Deps"]}
                        == {(path, version, sums[path, version]) for path, version in command_modules[name]},
                        "collector_linked_modules_mismatch")
                data = binary.read_bytes()
                require(data[:6] == b"\x7fELF\x02\x01" and int.from_bytes(data[18:20], "little") == 62,
                        "collector_invalid_elf")
                binaries[name] = data
            return binaries

        with ThreadPoolExecutor(max_workers=2) as executor:
            builds = list(executor.map(build, (1, 2)))
        require(builds[0] == builds[1], "collector_nonreproducible")
        require({name: digest(data) for name, data in builds[0].items()}
                == {collector.BINARY: collector.BINARY_SHA, collector.INTAKE: collector.INTAKE_SHA},
                "collector_binary_differs_from_reviewed_candidate")
        require(all(digest(path.read_bytes()) == tool_hashes[name] for name, path in tool_paths.items()), "collector_toolchain_drift")
        output = helper.new_private_directory(output)
        write_json(output / "source-files.json", {"source_commit": REVISION, "source_tree": TREE, "files": source_manifest})
        for name, data in builds[0].items():
            (output / name).write_bytes(data)
        if (toolenv["GOHOSTOS"], toolenv["GOHOSTARCH"]) == ("linux", "amd64"):
            binary_path = output / collector.BINARY
            binary_path.chmod(0o700)
            version = json.loads(run([str(binary_path), "--version"], output, env))
            require(version == {"source_revision": REVISION, "source_tree": TREE, "go_version": GO_VERSION},
                    "collector_native_version_mismatch")
        archive(output / "source.tar.gz", source_members)
        write_sbom(output, dependencies, builds[0], command_modules)
        write_json(output / "provenance.unsigned.json", {
            "schema_version": 1, "repository": REPOSITORY, "source_commit": REVISION, "source_tree": TREE,
            "source_ref_verified": "refs/heads/main", "github_ci_run": "42766032870",
            "package_state": "UNSIGNED_COLLECTOR_REVIEW_ONLY", "signed": False, "release_approved": False,
            "release_tag": tag, "workflow_commit": workflow_commit, "target": "linux/amd64",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "build_flags": flags, "go_version": GO_VERSION,
            "build_environment": {k: env[k] for k in ("GOENV", "GOTOOLCHAIN", "GOWORK", "GOOS", "GOARCH", "GOAMD64", "CGO_ENABLED")},
            "module_verification": "Pinned go.sum hashes, Go module zip/go.mod h1 checks, and go mod verify in both caches; GOPROXY=off for both builds.",
            "two_independent_clean_builds": [digest(row[collector.BINARY]) for row in builds],
            "intake_independent_clean_builds": [digest(row[collector.INTAKE]) for row in builds],
            "build_tool_sha256": tool_hashes,
            "byte_identical": True, "public_source_manifest_sha256": digest(public_manifest_data),
            "source_files_sha256": digest((output / "source-files.json").read_bytes()),
        })

        (output / "SHA256SUMS").write_text("".join(
            f"{collector.digest(output, name)}  {name}\n" for name in sorted(collector.FILES)))
        print("Prepared unsigned collector and intake candidates.")


def write_sbom(output, modules, binaries, command_modules):
    binary_ids = {collector.BINARY: "SPDXRef-Collector", collector.INTAKE: "SPDXRef-Intake"}
    def package(identifier, name, version, sha=None):
        item = {"SPDXID": identifier, "name": name, "versionInfo": version,
                "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                "licenseDeclared": "NOASSERTION", "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION"}
        if sha:
            item["checksums"] = [{"algorithm": "SHA256", "checksumValue": sha}]
        return item

    packages = [package(binary_ids[name], name, REVISION, digest(data)) for name, data in binaries.items()]
    packages.append(package("SPDXRef-GoStdlib", "Go standard library", GO_VERSION))
    module_ids = {}
    for index, module in enumerate(modules):
        module_id = f"SPDXRef-GoModule-{index}"
        module_ids[module["path"], module["version"]] = module_id
        item = package(module_id, module["path"], module["version"], module["archive_sha256"])
        item["comment"] = "SHA-256 covers the module ZIP. Go module hash " + module["h1"] + "."
        purl = "pkg:golang/" + quote(module["path"], safe="/") + "@" + quote(module["version"], safe="")
        item["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                 "referenceLocator": purl}]
        packages.append(item)
    write_json(output / "sbom.spdx.json", {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Sherlock Linux AMD64 collector and intake candidates",
        "documentNamespace": "urn:uuid:" + str(uuid.uuid4()),
        "creationInfo": {"created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "creators": ["Tool: Sherlock collector release preparation"]},
        "packages": packages, "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": binary_id}
            for binary_id in binary_ids.values()
        ] + [
            {"spdxElementId": binary_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": dependency}
            for name, binary_id in binary_ids.items()
            for dependency in ["SPDXRef-GoStdlib", *(module_ids[key] for key in sorted(command_modules[name]))]
        ],
    })


def record(directory, commit, tag, artifact_id):
    result = {"schema_version": 1, "approved": False, "repository": REPOSITORY,
              "release_tag": tag, "source_commit": REVISION, "workflow_commit": commit,
              "artifact_id": artifact_id,
              **{key: collector.digest(directory, name) for key, name in collector.DIGESTS.items()}}
    collector.validate_policy(result, commit, approved=False)
    collector.payload(directory, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("build", "summary"))
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--module-proxy", default="https://proxy.golang.org")
    args = parser.parse_args()
    os.umask(0o077)
    repo = Path(__file__).resolve().parents[1]
    event = release.object_json(release.read_regular(Path(os.environ["GITHUB_EVENT_PATH"]), 1 << 20))
    commit = collector.workflow_context(os.environ, event, collector.PREPARE)
    tag = os.environ.get("RELEASE_TAG")
    require(collector.valid(release.TAG, tag), "invalid_release_tag")
    if args.operation == "build":
        require(run(["git", "rev-parse", "HEAD"], repo).decode().strip() == commit, "wrong_workflow_checkout")
        require(not run(["git", "status", "--porcelain", "--untracked-files=normal"], repo),
                "dirty_workflow_checkout")
        build(repo, args.directory.absolute(), args.module_proxy, commit, tag)
    else:
        artifact_id = os.environ.get("ARTIFACT_ID", "")
        require(artifact_id.isascii() and artifact_id.isdecimal() and not artifact_id.startswith("0"),
                "invalid_collector_artifact_id")
        result = record(args.directory.absolute(), commit, tag, int(artifact_id))
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write("## Collector release review\n\n"
                         "Unsigned candidate. Review the exact artifact before environment approval. "
                         "The source and signing workflow commits are separate.\n\n"
                         "```json\n" + json.dumps(result, indent=2, sort_keys=True) + "\n```\n")


if __name__ == "__main__":
    try:
        main()
    except (release.ReleaseError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        sys.exit(str(error) if isinstance(error, release.ReleaseError) else "collector_release_preparation_failed")

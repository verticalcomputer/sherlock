#!/usr/bin/env python3
"""Private fixture candidate preparation; never installs, signs or publishes."""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import urllib.parse
import uuid
import zipfile

TARGETS = ("sherlock-node-agent", "sherlock-gateway")
VERSION = "fixture.v1"
CONTRACTS = (
    "docs/GP06F_RESIDENT_TELEMETRY_AGENT.md",
    "docs/GP06F_TELEMETRY_V1_CONTRACT.md",
    "docs/GP06F_NODE_IDENTITY_CONTRACT.md",
    "docs/GP06F_NODE_RUNTIME_CONTRACT.md",
    "docs/GP06F_GATEWAY_RUNTIME_CONTRACT.md",
    "docs/GP06F_OWNERSHIP_RETIREMENT_CONTRACT.md",
    "docs/GP06F_CANDIDATE_REVIEW.md",
    "docs/LINUX_RESIDENT_SOURCES.md",
)
LEGAL_FILES = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md")
SOURCE_FIELDS = ("GoFiles", "CgoFiles", "SFiles", "HFiles", "CFiles", "CXXFiles",
                 "MFiles", "FFiles", "SysoFiles", "EmbedFiles")


class CandidateError(Exception):
    pass


def require(condition, code):
    if not condition:
        raise CandidateError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def objects(data):
    decoder = json.JSONDecoder()
    text = data.decode()
    offset, result = 0, []
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        value, offset = decoder.raw_decode(text, offset)
        result.append(value)
    return result


def run(args, cwd, env):
    # Never forward subprocess output: paths, environment or source snippets may
    # be private. Metadata is decoded and selected explicitly below.
    result = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=600, check=False)
    stages = {("env",): "go_environment_failed", ("list",): "go_list_failed",
              ("build",): "go_build_failed", ("version",): "go_metadata_failed",
              ("mod", "verify"): "go_verify_failed", ("mod", "graph"): "go_graph_failed",
              ("mod", "download"): "go_download_failed"}
    stage = stages.get(tuple(args[1:3]), stages.get(tuple(args[1:2]), "version_execution_failed"))
    require(result.returncode == 0, stage)
    return result.stdout


def regular(path, maximum=512 << 20):
    with open(path, "rb", opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW)) as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, "unsafe_input")
        data = source.read(maximum + 1)
        require(len(data) <= maximum, "input_too_large")
        return data


def write(path, data, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o700 if executable else 0o600)
    with os.fdopen(fd, "wb") as destination:
        destination.write(data)
        destination.flush()
        os.fsync(destination.fileno())


def new_private_directory(path):
    require(path.is_absolute() and path.name not in ("", ".", ".."), "invalid_output")
    # The output parent must already exist and be safe. Resolve only Darwin's
    # explicit root-owned aliases; never traverse user-controlled symlinks.
    text = str(path)
    if sys.platform == "darwin":
        for alias in ("/var", "/tmp"):
            if text.startswith(alias + "/"):
                info = os.lstat(alias)
                require(info.st_uid == 0 and os.readlink(alias) == "private" + alias,
                        "unsafe_output_parent")
                text = "/private" + text
    parts = Path(text).parts[1:]
    require(parts and all(part not in (".", "..") for part in parts), "invalid_output")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(next_fd)
            trusted = info.st_uid in (0, os.geteuid())
            sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if not trusted or info.st_mode & 0o022 and not sticky_root:
                os.close(next_fd)
                raise CandidateError("unsafe_output_parent")
            os.close(fd)
            fd = next_fd
        os.mkdir(parts[-1], 0o700, dir_fd=fd)  # EEXIST never overwrites
        os.fsync(fd)
    finally:
        os.close(fd)
    return Path(text)


def h1(entries):
    digest = hashlib.sha256()
    for name, content in sorted(entries):
        require("\n" not in name, "invalid_module_archive")
        digest.update((sha(content) + "  " + name + "\n").encode())
    return "h1:" + base64.b64encode(digest.digest()).decode()


def zip_h1(path):
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        require(len(infos) <= 200000 and sum(i.file_size for i in infos) <= 1 << 30,
                "module_archive_too_large")
        require(len({i.filename for i in infos}) == len(infos), "invalid_module_archive")
        digest = hashlib.sha256()
        for info in sorted(infos, key=lambda item: item.filename):
            require("\n" not in info.filename, "invalid_module_archive")
            content = hashlib.sha256()
            with archive.open(info) as source:
                for chunk in iter(lambda: source.read(1 << 20), b""):
                    content.update(chunk)
            digest.update((content.hexdigest() + "  " + info.filename + "\n").encode())
        return "h1:" + base64.b64encode(digest.digest()).decode()


def elf_identity(data):
    """Read the initialized Go string variables, not incidental binary text."""
    require(len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", data, 18)[0] == 62,
            "unsupported_binary_format")
    phoff, shoff = struct.unpack_from("<QQ", data, 32)
    phsize, phcount, shsize, shcount = struct.unpack_from("<HHHH", data, 54)
    require(phsize >= 56 and shsize >= 64 and phoff + phsize * phcount <= len(data)
            and shoff + shsize * shcount <= len(data), "invalid_binary_format")
    segments = []
    for index in range(phcount):
        offset = phoff + phsize * index
        if struct.unpack_from("<I", data, offset)[0] == 1:
            file_offset, address = struct.unpack_from("<QQ", data, offset + 8)
            length = struct.unpack_from("<Q", data, offset + 32)[0]
            segments.append((address, file_offset, length))
    def read_address(address, length):
        require(length <= 256, "invalid_binary_identity")
        for start, offset, size in segments:
            if start <= address and address + length <= start + size:
                begin = offset + address - start
                require(begin + length <= len(data), "invalid_binary_format")
                return data[begin:begin + length]
        raise CandidateError("invalid_binary_identity")
    expected = {"main.releaseVersion", "main.releaseSourceSHA256"}
    result = {}
    for index in range(shcount):
        section = shoff + shsize * index
        if struct.unpack_from("<I", data, section + 4)[0] != 2:
            continue
        offset, length = struct.unpack_from("<QQ", data, section + 24)
        linked = struct.unpack_from("<I", data, section + 40)[0]
        entry_size = struct.unpack_from("<Q", data, section + 56)[0]
        require(linked < shcount and entry_size >= 24 and length % entry_size == 0 and length // entry_size <= 1000000
                and offset + length <= len(data), "invalid_binary_format")
        strings_offset, strings_size = struct.unpack_from("<QQ", data, shoff + shsize * linked + 24)
        require(strings_offset + strings_size <= len(data), "invalid_binary_format")
        strings = data[strings_offset:strings_offset + strings_size]
        for relative in range(0, length, entry_size):
            symbol = offset + relative
            name_offset = struct.unpack_from("<I", data, symbol)[0]
            require(name_offset < len(strings), "invalid_binary_format")
            end = strings.find(b"\0", name_offset)
            require(end >= name_offset, "invalid_binary_format")
            name = strings[name_offset:end].decode("ascii", errors="replace")
            if name in expected:
                address, size = struct.unpack_from("<QQ", data, symbol + 8)
                require(size == 16 and name not in result, "invalid_binary_identity")
                pointer, count = struct.unpack("<QQ", read_address(address, 16))
                result[name] = read_address(pointer, count).decode("ascii")
    require(set(result) == expected, "embedded_identity_missing")
    return result


def safe_relative(path, root):
    relative = path.relative_to(root)
    require(not any(part in ("", ".", "..") for part in relative.parts), "unsafe_source")
    # Refuse symlinks in every source component, not only the last filename.
    cursor = root
    for part in relative.parts:
        cursor /= part
        require(not cursor.is_symlink(), "unsafe_source")
    return relative.as_posix()


def closure(packages, repo, goroot):
    local, standard, summary = set(), {}, []
    for package in packages:
        require(not package.get("Error") and not package.get("DepsErrors"), "invalid_closure")
        files = sorted({name for field in SOURCE_FIELDS for name in package.get(field, [])})
        own = package.get("Module", {}).get("Main", False)
        summary.append({"import_path": package["ImportPath"], "standard": bool(package.get("Standard")),
                        "module": package.get("Module", {}).get("Path"), "files": files})
        for name in files:
            path = Path(package["Dir"]) / name
            if own:
                local.add(safe_relative(path, repo))
            elif package.get("Standard"):
                relative = safe_relative(path, goroot)
                standard[relative] = sha(regular(path))
    return local, sorted(summary, key=lambda p: p["import_path"]), standard


def graph_metadata_is_pinned(module, sums, used):
    pinned = (module["Path"], module["Version"] + "/go.mod") in sums
    compiled = used.get(module["Path"], {}).get("Version") == module["Version"]
    require(pinned or not compiled, "compiled_module_metadata_unpinned")
    return pinned


def graph_versions(modules, edges):
    result = {(module["Path"], module["Version"]): module for module in modules if not module.get("Main")}
    for line in edges.decode().splitlines():
        require(len(line.split()) == 2, "invalid_module_graph")
        for node in line.split():
            if "@" not in node:
                continue
            path, version = node.rsplit("@", 1)
            if path in ("go", "toolchain"):
                continue
            result.setdefault((path, version), {"Path": path, "Version": version})
    return [value for _, value in sorted(result.items())]


def sbom(source_digest, modules, binaries, toolchain, created):
    packages, relationships = [], []
    def package(identifier, name, version, checksum=None, comment=None):
        item = {"SPDXID": identifier, "name": name, "versionInfo": version,
                "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION"}
        if checksum:
            item["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
        if comment:
            item["comment"] = comment
        packages.append(item)
        return item
    source = "SPDXRef-SherlockSource"
    package(source, "Sherlock-private-fixture-source", VERSION,
            comment="Exact input manifest SHA256=" + source_digest + "; rights/disclosure unreviewed.")
    package("SPDXRef-GoToolchain", "Go-toolchain-and-standard-library", toolchain["version"],
            comment="External local toolchain. Input hashes recorded separately; not bundled or hermetically rebuilt.")
    relationships.append({"spdxElementId": "SPDXRef-GoToolchain", "relationshipType": "BUILD_TOOL_OF",
                          "relatedSpdxElement": source})
    for index, module in enumerate(modules):
        identifier = "SPDXRef-GoModule-" + str(index)
        item = package(identifier, module["path"], module["version"], module["archive_sha256"],
                       "Checksum describes included module zip. Go h1 sum=" + module["sum"])
        item["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                  "referenceLocator": "pkg:golang/" + urllib.parse.quote(module["path"], safe="/") + "@" + urllib.parse.quote(module["version"], safe="")}]
        relationships.append({"spdxElementId": source, "relationshipType": "DEPENDS_ON",
                              "relatedSpdxElement": identifier})
    for name, digest in binaries.items():
        identifier = "SPDXRef-Binary-" + name
        package(identifier, name + "-linux-amd64", VERSION, digest,
                "Synthetic fixture only; no client installation approval.")
        relationships += [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": identifier},
                          {"spdxElementId": identifier, "relationshipType": "GENERATED_FROM", "relatedSpdxElement": source}]
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Sherlock private fixture candidate", "documentNamespace": "urn:uuid:" + str(uuid.uuid4()),
            "creationInfo": {"created": created, "creators": ["Tool: Sherlock-private-candidate-builder-1"]},
            "documentComment": "Dependency inventory, not vulnerability/secret/license approval. NOASSERTION is intentional. SPDX metadata dataLicense does not license the represented code.",
            "packages": packages, "relationships": relationships}


def build_candidate(repo, output):
    initial_module_inputs = {name: sha(regular(repo / name)) for name in ("go.mod", "go.sum")}
    base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", ""),
            "TMPDIR": tempfile.gettempdir(), "GOENV": "off", "GOTOOLCHAIN": "local", "GOWORK": "off",
            "GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "0",
            "GOFLAGS": "", "GOEXPERIMENT": "", "LC_ALL": "C", "TZ": "UTC"}
    go = shutil.which("go", path=base["PATH"])
    require(go is not None, "go_unavailable")
    environment = json.loads(run([go, "env", "-json", "GOROOT", "GOMODCACHE", "GOVERSION", "GOHOSTOS", "GOHOSTARCH"], repo, base))
    goroot, cache = Path(environment["GOROOT"]), Path(environment["GOMODCACHE"])
    packages = objects(run([go, "list", "-mod=readonly", "-deps", "-json"] + ["./cmd/" + t for t in TARGETS], repo, base))
    source_files, package_info, std = closure(packages, repo, goroot)
    main = {p.get("Module", {}).get("Path") for p in packages if p.get("Module", {}).get("Main")}
    require(main == {"github.com/verticalcomputer/sherlock"}, "unexpected_module")
    graph = objects(run([go, "list", "-mod=readonly", "-m", "-json", "all"], repo, base))
    require(not any(m.get("Replace") for m in graph), "module_replacement_unreviewed")
    graph = graph_versions(graph, run([go, "mod", "graph"], repo, base))
    sums = {}
    for line in regular(repo / "go.sum").decode().splitlines():
        path, version, checksum = line.split()
        sums[path, version] = checksum
    used = {p["Module"]["Path"]: p["Module"] for p in packages if p.get("Module") and not p["Module"].get("Main")}
    dependencies, archives = [], {}
    for path, module in sorted(used.items()):
        downloaded = json.loads(run([go, "mod", "download", "-json", path + "@" + module["Version"]], repo, base))
        require(not downloaded.get("Error") and downloaded.get("Sum") == sums.get((path, module["Version"])), "module_checksum_mismatch")
        zip_path = Path(downloaded["Zip"])
        require(zip_h1(zip_path) == downloaded["Sum"], "module_archive_mismatch")
        stem = zip_path.with_suffix("")
        for extension in (".zip", ".ziphash", ".mod", ".info"):
            item = Path(str(stem) + extension)
            archives[safe_relative(item, cache)] = regular(item)
        dependencies.append({"path": path, "version": module["Version"], "sum": downloaded["Sum"],
                             "go_mod_sum": downloaded["GoModSum"], "archive_sha256": sha(archives[safe_relative(zip_path, cache)])})
    # Graph resolution also needs go.mod metadata for noncompiled requirements;
    # copy metadata only, never unrelated global module source/cache contents.
    omitted_metadata = []
    for module in graph:
        if module.get("Main"):
            continue
        # Lazy Go graphs may list unused modules without loading their go.mod.
        # Never fetch/include unpinned metadata just because it was listed. The
        # isolated offline builds below prove this omission is sufficient.
        if not graph_metadata_is_pinned(module, sums, used):
            omitted_metadata.append({"path": module["Path"], "version": module["Version"],
                                     "reason": "outside compilation closure; go.mod not pinned or materialized"})
            continue
        # An explicit module query fetches only required metadata if go list all
        # omitted its GoMod field; unrelated module archives are not materialized.
        if not module.get("GoMod"):
            module = json.loads(run([go, "list", "-mod=readonly", "-m", "-json", module["Path"] + "@" + module["Version"]], repo, base))
        mod = Path(module["GoMod"])
        data = regular(mod)
        require(h1([("go.mod", data)]) == sums.get((module["Path"], module["Version"] + "/go.mod")), "module_metadata_mismatch")
        archives[safe_relative(mod, cache)] = data
    run([go, "mod", "verify"], repo, base)
    require(all(sha(regular(repo / name)) == digest for name, digest in initial_module_inputs.items()),
            "module_inputs_changed_during_discovery")
    tool_paths = {"go": Path(go).resolve()}
    tools = goroot / "pkg" / "tool" / (environment["GOHOSTOS"] + "_" + environment["GOHOSTARCH"])
    tool_paths.update({tool: tools / tool for tool in ("compile", "link", "asm")})
    for header in sorted((goroot / "pkg" / "include").glob("*.h")):
        std[safe_relative(header, goroot)] = sha(regular(header))
    toolchain = {"version": environment["GOVERSION"], "host_os": environment["GOHOSTOS"], "host_arch": environment["GOHOSTARCH"],
                 "tool_sha256": {name: sha(regular(path)) for name, path in tool_paths.items()},
                 "standard_library_inputs": std, "external_not_bundled": True}
    output = new_private_directory(output)
    write(output / "STATUS.json", encoded({"status": "INCOMPLETE_PRIVATE_PREPARATION", "release_approved": False}))
    source_files.update(("go.mod", "go.sum", "scripts/build-telemetry-candidate.py",
                         "scripts/test_build_telemetry_candidate.py", *CONTRACTS, *LEGAL_FILES))
    # Notices travel with the exact source/binary review candidate. Inclusion is
    # not a license conclusion; independent dependency/asset review is required.
    notices = repo / "third_party" / "licenses"
    require(notices.is_dir() and not notices.is_symlink(), "dependency_notices_missing")
    notice_files = [path for path in notices.rglob("*") if path.is_file() or path.is_symlink()]
    require(bool(notice_files), "dependency_notices_missing")
    source_files.update(safe_relative(path, repo) for path in notice_files)
    original = {}
    for relative in sorted(source_files):
        path = repo / relative
        require(safe_relative(path, repo) == relative, "unsafe_source")
        data = regular(path)
        original[relative] = sha(data)
        write(output / "source" / relative, data, executable=bool(path.stat().st_mode & 0o111))
    (output / "dependencies").mkdir(mode=0o700)
    for relative, data in sorted(archives.items()):
        write(output / "dependencies" / relative, data)
    write(output / "modules.json", encoded(dependencies))
    write(output / "unmaterialized-graph-metadata.json", encoded(omitted_metadata))
    write(output / "toolchain.json", encoded(toolchain))
    write(output / "compiled-closure.json", encoded(package_info))
    inputs = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "STATUS.json":
            data = regular(path)
            inputs.append({"path": path.relative_to(output).as_posix(), "sha256": sha(data),
                           "bytes": len(data), "executable": bool(path.stat().st_mode & 0o111)})
    manifest = encoded({"schema_version": 1, "version": VERSION, "target": "linux/amd64", "files": inputs})
    write(output / "source-files.json", manifest)
    source_digest = sha(manifest)
    ldflags = "-buildid= -X main.releaseVersion=" + VERSION + " -X main.releaseSourceSHA256=" + source_digest
    builds, metadata = [], {}
    for iteration in range(2):
        with tempfile.TemporaryDirectory(prefix="sherlock-candidate-clean-") as temporary:
            work = Path(temporary)
            shutil.copytree(output / "source", work / "source")
            shutil.copytree(output / "dependencies", work / "modules")
            env = dict(base, GOCACHE=str(work / "cache"), GOMODCACHE=str(work / "modules"), GOPROXY="off", GOSUMDB="off")
            run([go, "mod", "verify"], work / "source", env)
            hashes = {}
            for target in TARGETS:
                binary = work / (target + "-linux-amd64")
                run([go, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=" + ldflags,
                     "-o", str(binary), "./cmd/" + target], work / "source", env)
                data = regular(binary)
                hashes[target] = sha(data)
                info = json.loads(run([go, "version", "-m", "-json", str(binary)], work / "source", env))
                settings = {s["Key"]: s["Value"] for s in info["Settings"]}
                require(settings.get("GOOS") == "linux" and settings.get("GOARCH") == "amd64" and settings.get("CGO_ENABLED") == "0", "binary_metadata_mismatch")
                # Go omits ldflags from build info with -trimpath. Read the
                # actual initialized ELF symbols rather than matching incidental
                # bytes. Native version execution is also checked when possible.
                identity = elf_identity(data)
                require(identity == {"main.releaseVersion": VERSION, "main.releaseSourceSHA256": source_digest}, "embedded_identity_mismatch")
                info["source_manifest_sha256"] = source_digest
                info["embedded_linker_variables"] = identity
                if environment["GOHOSTOS"] == "linux" and environment["GOHOSTARCH"] == "amd64":
                    identity = json.loads(run([str(binary), "version"], work / "source", env))
                    require(identity.get("version") == VERSION and identity.get("source_sha256") == source_digest, "binary_version_mismatch")
                    info["executed_version"] = identity
                else:
                    info["executed_version"] = None
                    info["cross_host_limit"] = "Linux executable not run on this host; build metadata and linker strings checked, native execution remains a gate."
                if iteration == 0:
                    write(output / "bin" / binary.name, data, executable=True)
                    metadata[target] = info
                else:
                    require(data == regular(output / "bin" / binary.name), "non_reproducible_binary")
            builds.append(hashes)
    for relative, digest in original.items():
        require(sha(regular(repo / relative)) == digest, "source_changed_during_build")
    for item in inputs:
        require(sha(regular(output / item["path"])) == item["sha256"], "candidate_input_changed_during_build")
    require(all(sha(regular(path)) == toolchain["tool_sha256"][name]
                for name, path in tool_paths.items()), "toolchain_changed_during_build")
    require(all(sha(regular(goroot / relative)) == digest for relative, digest in std.items()),
            "standard_library_changed_during_build")
    created = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write(output / "binary-metadata.json", encoded(metadata))
    write(output / "sbom.spdx.json", encoded(sbom(source_digest, dependencies, builds[0], toolchain, created)))
    write(output / "provenance.unsigned.json", encoded({"schema_version": 1, "created": created, "signed": False,
        "release_approved": False, "source_manifest_sha256": source_digest, "version": VERSION,
        "target": "linux/amd64", "two_independent_clean_builds": builds, "byte_identical": True,
        "module_verification": "h1 archive/go.mod checks against go.sum; go mod verify in each isolated cache",
        "build_flags": ["-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=" + ldflags],
        "environment": {k: base[k] for k in ("GOTOOLCHAIN", "GOWORK", "GOENV", "GOOS", "GOARCH", "GOAMD64", "CGO_ENABLED", "GOEXPERIMENT")},
        "limitations": ["Private unreviewed candidate", "Host toolchain external and not hermetically rebuilt", "No signing identity or signature", "No vulnerability/secret/license approval", "No installation/publication/live qualification"]}))
    status = output / "STATUS.json"
    pending_status = output / "STATUS.pending"
    final_status = encoded({"status": "PREPARED_PRIVATE_UNSIGNED_FIXTURE", "release_approved": False,
                            "source_manifest_sha256": source_digest, "version": VERSION})
    write(pending_status, final_status)
    checksums = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path != pending_status:
            data = final_status if path == status else regular(path)
            checksums.append(sha(data) + "  " + path.relative_to(output).as_posix())
    write(output / "SHA256SUMS", ("\n".join(checksums) + "\n").encode())
    # Publish prepared state only after every final artifact/checksum exists.
    os.replace(pending_status, status)
    descriptor = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return output


def main():
    class RedactedArgumentParser(argparse.ArgumentParser):
        def error(self, message):
            self.exit(2, "telemetry candidate: invalid_arguments\n")
    parser = RedactedArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        output = build_candidate(args.repo.resolve(), args.out)
    except Exception as error:
        code = str(error) if isinstance(error, CandidateError) else "preparation_failed"
        print("telemetry candidate: " + code, file=sys.stderr)
        return 1
    print("prepared private unsigned candidate: " + str(output))
    return 0


if __name__ == "__main__":
    sys.exit(main())

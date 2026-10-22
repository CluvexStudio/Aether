#!/usr/bin/env python3
"""Write the license notices of the Rust crates linked into aether.

    python3 third-party-notices.py --target <triple> [--features <list>]
        [--manifest-path <Cargo.toml>] --output <file>

The release workflow runs it after `cargo build`, with the target and
features of that build, and ships the result as
LICENSES/THIRD-PARTY-NOTICES.txt beside the binary.

It reads `cargo metadata --format-version 1` for that target and feature set
and follows the normal dependencies from the aether package. Build
dependencies, dev-dependencies and procedural macros only run while aether
is built and are not linked into it, so they are left out, together with
the crates only they depend on.

Each crate is listed with its name, version, license expression and source,
then the text of every license file in its package: the files whose names
begin with LICENSE, LICENCE, COPYING, NOTICE, COPYRIGHT or UNLICENSE, at any
depth (boring-sys carries BoringSSL's license under deps/boringssl), the
files at its root named after an identifier of its license expression (such
as MPL-2.0.txt), and its manifest's license-file. A text given earlier in
the file is not repeated; the entry names where it is. A crate whose package
carries no license file says so and names its repository.

Python standard library only, so it runs on every release runner.
"""

import argparse
import json
import os
import re
import subprocess
import sys

NOTICE_NAME = re.compile(
    r"^(?:LICEN[CS]E|COPYING|NOTICE|COPYRIGHT|UNLICENSE)(?:[-._].*)?$",
    re.IGNORECASE,
)
# Names that match NOTICE_NAME but hold code, such as xz's
# build-aux/license-check.sh in liblzma-sys.
CODE_SUFFIXES = (
    ".sh", ".bat", ".ps1", ".py", ".pl", ".rs", ".c", ".h", ".cc", ".cpp",
    ".go", ".js", ".cmake", ".toml", ".json", ".yml", ".yaml",
)
SKIPPED_DIRS = {"target", ".git"}
EXPRESSION_WORDS = {"AND", "OR", "WITH"}
CRATES_IO = (
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
)
RULE = "=" * 80


def fail(message):
    print(f"third-party-notices: {message}", file=sys.stderr)
    sys.exit(1)


def cargo_metadata(manifest, target, features):
    command = [
        "cargo", "metadata", "--format-version", "1", "--locked",
        "--manifest-path", manifest, "--filter-platform", target,
    ]
    if features:
        command += ["--features", features]
    try:
        run = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as error:
        fail(f"cannot run cargo: {error}")
    if run.returncode != 0:
        sys.stderr.write(run.stderr.decode("utf-8", "replace"))
        fail(f"cargo metadata exited with {run.returncode}")
    return json.loads(run.stdout.decode("utf-8"))


def is_proc_macro(package):
    return any("proc-macro" in t["kind"] for t in package["targets"])


def linked_packages(metadata):
    """The packages reached from the root through normal dependencies."""
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    root = metadata["resolve"]["root"]
    if root is None:
        fail("the manifest is not a package")
    seen = {root}
    pending = [root]
    while pending:
        for dep in nodes[pending.pop()]["deps"]:
            kinds = dep.get("dep_kinds")
            if kinds is None:
                fail("cargo metadata gives no dep_kinds; this cargo is too old")
            if not any(k["kind"] is None for k in kinds):
                continue
            if dep["pkg"] in seen or is_proc_macro(packages[dep["pkg"]]):
                continue
            seen.add(dep["pkg"])
            pending.append(dep["pkg"])
    seen.discard(root)
    return packages[root], [packages[i] for i in seen]


def expression_ids(expression):
    words = re.findall(r"[A-Za-z0-9.+-]+", expression or "")
    return {w.casefold() for w in words if w not in EXPRESSION_WORDS}


def is_notice_file(name):
    return NOTICE_NAME.match(name) and not name.lower().endswith(CODE_SUFFIXES)


def is_expression_file(name, ids):
    folded = name.casefold()
    return any(folded in (i, i + ".txt", i + ".md") for i in ids)


def license_files(package):
    """Relative paths of the license files in a package, root files first."""
    root = os.path.dirname(package["manifest_path"])
    ids = expression_ids(package["license"])
    found = set()
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIPPED_DIRS]
        at_root = folder == root
        for name in files:
            if is_notice_file(name) or (at_root and is_expression_file(name, ids)):
                found.add(os.path.relpath(os.path.join(folder, name), root))
    if package.get("license_file"):
        named = os.path.normpath(os.path.join(root, package["license_file"]))
        if not os.path.isfile(named):
            fail(f"{package['name']} {package['version']}: license-file {package['license_file']} is missing")
        found.add(os.path.relpath(named, root))
    paths = [p.replace(os.sep, "/") for p in found]
    return sorted(paths, key=lambda p: ("/" in p, p.casefold(), p))


def read_text(path):
    with open(path, "rb") as f:
        data = f.read()
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    return text.replace("\r\n", "\n").replace("\r", "\n").strip("\n").rstrip()


def same_text_key(text):
    return "\n".join(line.rstrip() for line in text.split("\n")).strip()


def describe_source(package, tree_root):
    source = package["source"]
    if source is None:
        folder = os.path.relpath(os.path.dirname(package["manifest_path"]), tree_root)
        return folder.replace(os.sep, "/") + " in the Aether source tree"
    if source.startswith(CRATES_IO):
        return "crates.io"
    if source.startswith("git+"):
        return source[len("git+"):]
    return source


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--target", required=True, help="the target triple of the build")
    parser.add_argument("--features", default="", help="the features of the build, e.g. tor")
    parser.add_argument(
        "--manifest-path",
        default=os.path.join(here, "aether", "Cargo.toml"),
        help="aether's Cargo.toml (default: aether/Cargo.toml beside this script)",
    )
    parser.add_argument("--output", required=True, help="the file to write")
    args = parser.parse_args()

    metadata = cargo_metadata(args.manifest_path, args.target, args.features)
    root, crates = linked_packages(metadata)
    if not crates:
        fail("no crate is linked into the package")
    crates.sort(key=lambda p: (p["name"], p["version"]))
    tree_root = os.path.dirname(os.path.dirname(root["manifest_path"]))

    entries = []
    given = {}
    without_files = 0
    for package in crates:
        title = f"{package['name']} {package['version']}"
        lines = [RULE, title, f"License: {package['license'] or 'not stated'}",
                 f"Source: {describe_source(package, tree_root)}"]
        if package.get("repository"):
            lines.append(f"Repository: {package['repository']}")
        files = license_files(package)
        if not files:
            without_files += 1
            lines += ["", "This crate's package carries no license file. Its license is the",
                      "expression above; the full text is in the crate's repository."]
        folder = os.path.dirname(package["manifest_path"])
        for relative in files:
            text = read_text(os.path.join(folder, *relative.split("/")))
            lines += ["", f"--- {relative} ---"]
            key = same_text_key(text)
            if key in given:
                lines.append(f"(The same text as {given[key]}, above.)")
            else:
                given[key] = f"{title}, {relative}"
                lines.append(text)
        entries.append("\n".join(lines))

    features = args.features or "default"
    header = [
        f"Third-party notices for {root['name']} {root['version']}",
        f"Target: {args.target}, features: {features}",
        "",
        f"{root['name']} links the {len(crates)} Rust crates below. Each entry gives the crate's",
        "version, license expression and source, followed by the license files its",
        "package carries. Crates used only to build it (build dependencies and",
        "procedural macros) are not linked into it and are not listed.",
        f"{without_files} of the crates carry no license file in their package; their",
        "entries say so and name the repository that holds the text.",
        f"{root['name']}'s own license ({root['license']}) is not repeated here.",
        "",
        "Generated by third-party-notices.py from `cargo metadata`.",
        "",
        "Crates:",
    ]
    width = max(len(p["name"]) + len(p["version"]) for p in crates) + 1
    for package in crates:
        label = f"{package['name']} {package['version']}"
        header.append(f"  {label.ljust(width)}  {package['license'] or 'not stated'}")

    out_dir = os.path.dirname(os.path.abspath(args.output))
    os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(header) + "\n\n" + "\n\n".join(entries) + "\n")
    print(f"third-party-notices: {len(crates)} crates, {len(given)} distinct texts -> {args.output}")


if __name__ == "__main__":
    main()

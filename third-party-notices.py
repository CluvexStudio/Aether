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
the crates only they depend on. That graph comes from cargo's dependency
resolver and also keeps optional dependencies that no enabled feature turns
on (a weak feature such as reqwest's `quinn?/ring` names quinn without
enabling it), so the script keeps only the crates that
`cargo tree --edges normal,no-proc-macro` lists for the same target and
features: the ones cargo's feature resolver builds into aether.

Each crate is listed with its name, version, license expression and source,
then the text of every license file in its package: the files whose names
begin with LICENSE, LICENCE, COPYING, NOTICE, COPYRIGHT or UNLICENSE, at any
depth (boring-sys carries BoringSSL's license under deps/boringssl), the
files at its root named after an identifier of its license expression (such
as MPL-2.0.txt), and its manifest's license-file. A text given earlier in
the file is not repeated; the entry names where it is.

A crate whose package carries no license file, such as the arti and tor-*
crates and boringtun, gets the standard text of each license its expression
names (both for "MIT OR Apache-2.0") from license-texts/ beside this script,
whose README says where each text was copied from. A copyright line comes
first: one per entry of the crate's authors field, or the line in
SOURCE_COPYRIGHT for a crate whose authors are not the holder (boringtun's
source files carry "Copyright (c) 2019 Cloudflare, Inc."; the script checks
that they still do), or, when the authors field is empty and a license
needs a holder, the owner of the crate's repository. The script fails when
license-texts/ has no text for an identifier the expression names.

The first entry is the Rust standard library, which rustc links into every
binary: MIT OR Apache-2.0, with the texts from share/doc/rust in the
toolchain's sysroot (`rustc --print sysroot`) when it has them and from
license-texts/ when it does not. The MIT text of a toolchain that follows
REUSE, licenses/MIT.txt, is not used: it is the SPDX template, with a
placeholder copyright line.

On a checkout without symlinks (git's core.symlinks=false, as Git for
Windows often has it), a symlinked license file is a small file that holds
the link's target: quiche/quiche/COPYING then holds `../COPYING`. The script
reads the file such a placeholder names, which must lie inside the Aether
source tree for the crates in it and inside the package for the others, and
fails when it lies outside.

Python standard library only, so it runs on every release runner.
"""

import argparse
import html
import json
import os
import re
import subprocess
import sys
import textwrap
import urllib.parse

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
# One line of `cargo tree --prefix none --format {p}`: the name, the version,
# then " (<path or git source>)" for a crate that is not from a registry
# and " (*)" for a crate listed before.
TREE_LINE = re.compile(r"^(\S+) v(\S+)(?: \(.*\))?$")
# A git symlink placeholder holds the link's target, which is short.
PLACEHOLDER_LIMIT = 256
PLACEHOLDER_HOPS = 8
# The standard license texts, <SPDX identifier>.txt, beside this script.
STANDARD_TEXTS = "license-texts"
# The licenses whose text begins with the holder's copyright line. A crate
# without a license file that names one of them needs a copyright line
# before the standard text, even when its authors field is empty.
HOLDER_LICENSES = {"0bsd", "bsd-2-clause", "bsd-3-clause", "isc", "mit", "zlib"}
# Crates without a license file whose authors field names people rather
# than the copyright holder: the copyright line their source files carry.
# The script fails when no .rs file in the package carries it any more.
SOURCE_COPYRIGHT = {
    "boringtun": "Copyright (c) 2019 Cloudflare, Inc.",
}
# The Rust standard library's license and where a toolchain keeps its texts
# under share/doc/rust: licenses/ since the toolchain follows REUSE, the
# LICENSE-* files before. The REUSE licenses/MIT.txt is the SPDX template,
# which opens with the placeholder line "Copyright (c) <year> <copyright
# holders>", so the MIT text comes from LICENSE-MIT or, without it, from
# license-texts/MIT.txt, which has no copyright line.
STD_LICENSE = "MIT OR Apache-2.0"
STD_TEXTS = (
    ("MIT", ("LICENSE-MIT",)),
    ("Apache-2.0", ("licenses/Apache-2.0.txt", "LICENSE-APACHE")),
)
STD_COPYRIGHT_FILE = "COPYRIGHT-library.html"
# The holder of the standard library's own files in that file: the first
# copyright after the entry for the directory ".".
STD_COPYRIGHT = re.compile(
    r"<b>File/Directory:</b>\s*<code>\.</code>.*?<b>Copyright:</b>\s*([^<]+?)\s*</p>",
    re.DOTALL,
)


def fail(message):
    print(f"third-party-notices: {message}", file=sys.stderr)
    sys.exit(1)


def run_tool(command, cwd=None):
    try:
        run = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
    except OSError as error:
        fail(f"cannot run {command[0]}: {error}")
    if run.returncode != 0:
        sys.stderr.write(run.stderr.decode("utf-8", "replace"))
        fail(f"{command[0]} {command[1]} exited with {run.returncode}")
    return run.stdout.decode("utf-8")


def cargo_metadata(manifest, target, features):
    command = [
        "cargo", "metadata", "--format-version", "1", "--locked",
        "--manifest-path", manifest, "--filter-platform", target,
    ]
    if features:
        command += ["--features", features]
    return json.loads(run_tool(command))


def cargo_tree(manifest, target, features):
    """The (name, version) of each crate cargo builds into the package."""
    # --color never: CI sets CARGO_TERM_COLOR=always, which colors the " (*)"
    # of a crate listed before.
    command = [
        "cargo", "tree", "--locked", "--color", "never", "--manifest-path", manifest,
        "--target", target, "--edges", "normal,no-proc-macro",
        "--prefix", "none", "--format", "{p}",
    ]
    if features:
        command += ["--features", features]
    built = set()
    for line in run_tool(command).splitlines():
        if not line.strip():
            continue
        match = TREE_LINE.match(line)
        if not match:
            fail(f"cannot read this line of cargo tree: {line}")
        built.add((match.group(1), match.group(2)))
    return built


def is_proc_macro(package):
    return any("proc-macro" in t["kind"] for t in package["targets"])


def linked_packages(metadata, built):
    """The packages reached from the root through normal dependencies that
    cargo tree lists in built, so that the optional dependencies no enabled
    feature turns on are left out."""
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
    reached = {(packages[i]["name"], packages[i]["version"]) for i in seen}
    unknown = sorted(built - reached)
    if unknown:
        fail("cargo tree lists crates that the metadata does not reach: "
             + ", ".join(f"{name} {version}" for name, version in unknown))
    seen.discard(root)
    crates = [packages[i] for i in seen if (packages[i]["name"], packages[i]["version"]) in built]
    return packages[root], crates


def expression_names(expression):
    """The license identifiers of an expression in order, each once."""
    words = re.findall(r"[A-Za-z0-9.+-]+", expression or "")
    names = []
    for word in words:
        if word not in EXPRESSION_WORDS and word.casefold() not in (n.casefold() for n in names):
            names.append(word)
    return names


def expression_ids(expression):
    return {name.casefold() for name in expression_names(expression)}


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


def is_inside(path, folder):
    path, folder = (os.path.normcase(os.path.abspath(p)) for p in (path, folder))
    try:
        return os.path.commonpath([path, folder]) == folder
    except ValueError:
        return False


def placeholder_target(path, bound, label):
    """The file named by the git symlink placeholder at path, or None when
    path is an ordinary file. A placeholder holds one relative path to an
    existing file and no newline; that file must lie inside bound."""
    with open(path, "rb") as f:
        data = f.read(PLACEHOLDER_LIMIT + 1)
    if not data or len(data) > PLACEHOLDER_LIMIT or b"\n" in data or b"\r" in data:
        return None
    try:
        link = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if link != link.strip() or os.path.isabs(link):
        return None
    named = os.path.normpath(os.path.join(os.path.dirname(path), link))
    if not os.path.isfile(named):
        return None
    if not is_inside(named, bound):
        fail(f"{label} holds only '{link}', a symlink placeholder that names a file outside "
             f"{bound}; check the source out with git config core.symlinks true")
    return named


def license_text(path, bound, label):
    """The text of a license file, read from the file its symlink
    placeholders name when the checkout has no symlinks."""
    for _ in range(PLACEHOLDER_HOPS):
        named = placeholder_target(path, bound, label)
        if named is None:
            return read_text(path)
        path = named
    fail(f"{label}: more than {PLACEHOLDER_HOPS} symlink placeholders in a row")


def same_text_key(text):
    return "\n".join(line.rstrip() for line in text.split("\n")).strip()


def add_text(lines, given, heading, text, label):
    """Append a license text under its heading, or a reference to the
    entry that gave the same text before."""
    lines += ["", f"--- {heading} ---"]
    key = same_text_key(text)
    if key in given:
        lines.append(f"(The same text as {given[key]}, above.)")
    else:
        given[key] = label
        lines.append(text)


def paragraph(text):
    return textwrap.fill(text, width=72, break_long_words=False, break_on_hyphens=False)


def standard_texts(folder):
    """The standard license texts by casefolded SPDX identifier."""
    texts = {}
    if os.path.isdir(folder):
        for name in os.listdir(folder):
            stem, extension = os.path.splitext(name)
            if extension == ".txt" and os.path.isfile(os.path.join(folder, name)):
                texts[stem.casefold()] = name
    return texts


def standard_text(texts, folder, name, title):
    """The file name and text of the standard text of license name."""
    file_name = texts.get(name.casefold())
    if file_name is None:
        fail(f"{title}: no license file in its package and no {STANDARD_TEXTS}/{name}.txt; "
             f"add the standard text of {name} as {STANDARD_TEXTS}/README.md says")
    path = os.path.join(folder, file_name)
    return file_name, license_text(path, folder, f"{STANDARD_TEXTS}/{file_name}")


def source_carries(package, line):
    """Whether a .rs file in the package carries line."""
    root = os.path.dirname(package["manifest_path"])
    wanted = line.encode("utf-8")
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIPPED_DIRS]
        for name in files:
            if name.endswith(".rs"):
                with open(os.path.join(folder, name), "rb") as f:
                    if wanted in f.read():
                        return True
    return False


def repository_owner(repository):
    """The owner part of a repository URL: the first segment of its path."""
    url = urllib.parse.urlparse(repository or "")
    segments = [s for s in url.path.split("/") if s]
    if not url.netloc or len(segments) < 2:
        return None
    return segments[0]


def copyright_lines(package, names, title):
    """The copyright lines for a crate without a license file, and where
    they come from."""
    line = SOURCE_COPYRIGHT.get(package["name"])
    if line is not None:
        if not source_carries(package, line):
            fail(f"{title}: no source file carries '{line}' any more; check its copyright "
                 "holder and update SOURCE_COPYRIGHT")
        return [line], "the header of its source files, as its authors field names people, not the holder"
    authors = [a.strip() for a in package.get("authors") or [] if a.strip()]
    if authors:
        return [f"Copyright (c) {author}" for author in authors], "its authors field"
    if not any(name.casefold() in HOLDER_LICENSES for name in names):
        return [], None
    owner = repository_owner(package.get("repository"))
    if owner is None:
        fail(f"{title}: no license file, no authors and no repository owner to name as "
             f"the copyright holder that {package['license']} needs")
    return [f"Copyright (c) {owner}"], (
        f"the owner of its repository {package['repository']}, as its authors field is empty")


def standard_text_lines(package, title, texts, folder, given):
    """The lines that give a crate without a license file its license: the
    copyright lines and the standard text of each license it names."""
    expression = package["license"]
    names = expression_names(expression)
    if not names:
        fail(f"{title}: no license file in its package and no license expression")
    words = set(re.findall(r"[A-Za-z]+", expression))
    choice = ""
    if "OR" in words and "AND" not in words:
        choice = " (the crate may be used under {} of them)".format(
            "either" if len(names) == 2 else "any one")
    holders, origin = copyright_lines(package, names, title)
    which = "each license its expression names" if len(names) > 1 else "the license its expression names"
    sentence = f"This crate's package carries no license file. Below is the standard text of {which}{choice}"
    if holders:
        sentence += ", after the copyright line{} from {}.".format("s" if len(holders) > 1 else "", origin)
    else:
        sentence += "."
    lines = ["", paragraph(sentence)]
    if holders:
        lines += [""] + holders
    for name in names:
        file_name, text = standard_text(texts, folder, name, title)
        add_text(lines, given, f"{name}, standard text ({STANDARD_TEXTS}/{file_name})",
                 text, f"{title}, {name} standard text")
    return lines


def rust_std_entry(manifest, texts, folder, given):
    """The entry of the Rust standard library, from the toolchain that
    cargo runs for the manifest, and its version."""
    rustc = os.environ.get("RUSTC") or "rustc"
    cwd = os.path.dirname(os.path.abspath(manifest))
    verbose = run_tool([rustc, "-vV"], cwd=cwd)
    release = re.search(r"^release: (\S+)$", verbose, re.MULTILINE)
    if not release:
        fail(f"cannot read the release of {rustc} -vV")
    version = release.group(1)
    sysroot = run_tool([rustc, "--print", "sysroot"], cwd=cwd).strip()
    doc = os.path.join(sysroot, "share", "doc", "rust")
    title = f"Rust standard library {version}"
    lines = [RULE, title, f"License: {STD_LICENSE}",
             f"Source: the Rust toolchain ({verbose.splitlines()[0].strip()})"]
    sentence = ("rustc links the standard library into every Rust binary. It may be used under "
                "either license.")
    holder = None
    notices = os.path.join(doc, STD_COPYRIGHT_FILE)
    if os.path.isfile(notices):
        match = STD_COPYRIGHT.search(read_text(notices))
        if match:
            holder = html.unescape(match.group(1)).strip()
        sentence += (" The notices of the code it includes from other projects are in "
                     f"{STD_COPYRIGHT_FILE}, which the toolchain installs in share/doc/rust.")
    lines += ["", paragraph(sentence)]
    if holder:
        lines += ["", f"Copyright (c) {holder}"]
    for name, candidates in STD_TEXTS:
        for relative in candidates:
            path = os.path.join(doc, *relative.split("/"))
            if os.path.isfile(path):
                add_text(lines, given, f"{name} (share/doc/rust/{relative} of the toolchain)",
                         read_text(path), f"{title}, {name}")
                break
        else:
            file_name, text = standard_text(texts, folder, name, title)
            add_text(lines, given, f"{name}, standard text ({STANDARD_TEXTS}/{file_name})",
                     text, f"{title}, {name} standard text")
    return "\n".join(lines), version


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
    built = cargo_tree(args.manifest_path, args.target, args.features)
    root, crates = linked_packages(metadata, built)
    if not crates:
        fail("no crate is linked into the package")
    crates.sort(key=lambda p: (p["name"], p["version"]))
    tree_root = os.path.dirname(os.path.dirname(root["manifest_path"]))
    texts_folder = os.path.join(here, STANDARD_TEXTS)
    texts = standard_texts(texts_folder)

    # Every standard text a crate without a license file needs, checked up
    # front, so that a release leg names all the missing ones at once.
    missing = {}
    for package in crates:
        if license_files(package):
            continue
        for name in expression_names(package["license"] or ""):
            if name.casefold() not in texts:
                missing.setdefault(name, []).append(f"{package['name']} {package['version']}")
    if missing:
        fail("no license file in their package and no standard text in "
             f"{STANDARD_TEXTS}/ for: "
             + "; ".join(f"{name} ({', '.join(users)})" for name, users in sorted(missing.items()))
             + f"; add each text as {STANDARD_TEXTS}/README.md says")

    given = {}
    std_entry, std_version = rust_std_entry(args.manifest_path, texts, texts_folder, given)
    entries = [std_entry]
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
            lines += standard_text_lines(package, title, texts, texts_folder, given)
        folder = os.path.dirname(package["manifest_path"])
        bound = tree_root if package["source"] is None else folder
        for relative in files:
            text = license_text(os.path.join(folder, *relative.split("/")), bound, f"{title}: {relative}")
            add_text(lines, given, relative, text, f"{title}, {relative}")
        entries.append("\n".join(lines))

    features = args.features or "default"
    header = [
        f"Third-party notices for {root['name']} {root['version']}",
        f"Target: {args.target}, features: {features}",
        "",
        paragraph(
            f"{root['name']} links the Rust standard library and the {len(crates)} Rust crates "
            "below. The first entry is the standard library. Each crate's entry gives its "
            "version, license expression and source, followed by the license files its package "
            "carries. Crates used only to build it (build dependencies and procedural macros) "
            "and optional dependencies that no enabled feature turns on are not linked into it "
            f"and are not listed. {without_files} of the crates carry no license file in their "
            "package; their entries give the standard text of each license their expression "
            "names, after a copyright line from the crate's authors field or from the header "
            f"of its source files. {root['name']}'s own license ({root['license']}) is not "
            "repeated here."),
        "",
        "Generated by third-party-notices.py from `cargo metadata`, `cargo tree`,",
        "the Rust toolchain and license-texts/ in the Aether source tree.",
        "",
        f"Rust standard library {std_version}: {STD_LICENSE}",
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

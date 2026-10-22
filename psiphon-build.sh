#!/usr/bin/env bash
set -euo pipefail

goos="${1:-}"
goarch="${2:-}"
out="${3:-}"
goarm="${4:-}"
# With a licensedir, psiphon-tunnel-core's license files are copied there
# too, named psiphon-tunnel-core-<file>, with .txt added to a name that has
# no extension. The release archives carry them in LICENSES/.
licensedir="${5:-}"

if [ -z "$goos" ] || [ -z "$goarch" ] || [ -z "$out" ]; then
    echo "usage: psiphon-build.sh <goos> <goarch> <outdir> [goarm] [licensedir]" >&2
    exit 2
fi

repo="https://github.com/CluvexStudio/psiphon-tunnel-core.git"
branch="shirokhorshid"
commit="83aa73b9b982e7421e00117f5b0c5aceb5dda452"

if ! command -v go >/dev/null 2>&1; then
    echo "psiphon-build: no go toolchain on PATH" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

src="$work/psiphon"
if ! git -c core.longpaths=true clone --quiet --depth 50 --branch "$branch" "$repo" "$src"; then
    echo "psiphon-build: cannot reach github" >&2
    exit 1
fi

git -C "$src" checkout --quiet "$commit" 2>/dev/null ||
    echo "psiphon-build: pinned commit is gone, using $branch as it stands" >&2

ext=""
if [ "$goos" = "windows" ]; then
    ext=".exe"
fi

mkdir -p "$out"

(
    cd "$src"
    GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0 GOFLAGS=-mod=vendor \
        go build -trimpath -ldflags "-s -w" -o "$out/psiphon-tunnel-core$ext" ./ConsoleClient
)

if [ -n "$licensedir" ]; then
    mkdir -p "$licensedir"
    copied=""
    for f in "$src"/LICENSE* "$src"/LICENCE* "$src"/COPYING* "$src"/NOTICE*; do
        [ -f "$f" ] || continue
        name="$(basename "$f")"
        case "$name" in
            *.*) ;;
            *) name="$name.txt" ;;
        esac
        cp "$f" "$licensedir/psiphon-tunnel-core-$name"
        copied="$copied psiphon-tunnel-core-$name"
    done
    if [ -z "$copied" ]; then
        echo "psiphon-build: psiphon-tunnel-core's source has no license file" >&2
        exit 1
    fi
    echo "psiphon-build: license files ->$copied"
fi

echo "psiphon-build: $goos/$goarch ->"
ls -l "$out/psiphon-tunnel-core$ext"

#!/usr/bin/env bash
set -euo pipefail

goos="${1:-}"
goarch="${2:-}"
out="${3:-}"
goarm="${4:-}"
# With a licensedir, lyrebird's license files are copied there too, named
# lyrebird-<file>, with .txt added to a name that has no extension. The
# release archives carry them in LICENSES/.
licensedir="${5:-}"

if [ -z "$goos" ] || [ -z "$goarch" ] || [ -z "$out" ]; then
    echo "usage: pt-build.sh <goos> <goarch> <outdir> [goarm] [licensedir]" >&2
    exit 2
fi

module="gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird"
repo="https://$module.git"
commit="fc105a03c0e0"
version="v0.0.0-20260312101154-fc105a03c0e0"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

src=""
if git clone --quiet "$repo" "$work/lyrebird" 2>/dev/null; then
    src="$work/lyrebird"
    git -C "$src" checkout --quiet "$commit" 2>/dev/null ||
        echo "pt-build: pinned commit is gone, using the default branch" >&2
else
    echo "pt-build: cannot reach gitlab, taking the go module proxy instead" >&2
    curl -fsSL "https://proxy.golang.org/$module/@v/$version.zip" -o "$work/lyrebird.zip"
    (cd "$work" && unzip -q lyrebird.zip)

    src="$work/$module@$version"
    if [ ! -f "$src/go.mod" ]; then
        src="$(dirname "$(find "$work" -type f -name go.mod | head -n 1)")"
    fi
    chmod -R u+w "$src"
fi

if [ ! -f "$src/go.mod" ]; then
    echo "pt-build: no lyrebird source to build" >&2
    exit 1
fi

ext=""
if [ "$goos" = "windows" ]; then
    ext=".exe"
fi

mkdir -p "$out"

(
    cd "$src"
    GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0 \
        go build -trimpath -ldflags "-s -w" -o "$out/lyrebird$ext" ./cmd/lyrebird
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
        cp "$f" "$licensedir/lyrebird-$name"
        copied="$copied lyrebird-$name"
    done
    if [ -z "$copied" ]; then
        echo "pt-build: lyrebird's source has no license file" >&2
        exit 1
    fi
    echo "pt-build: license files ->$copied"
fi

echo "pt-build: $goos/$goarch ->"
ls -l "$out"

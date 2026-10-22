#!/usr/bin/env bash
set -euo pipefail

goos="${1:-}"
goarch="${2:-}"
out="${3:-}"
goarm="${4:-}"
# With a licensedir, psiphon-tunnel-core's license files are copied there
# too, named psiphon-tunnel-core-<file>, with .txt added to a name that has
# no extension, and go_notices writes
# psiphon-tunnel-core-THIRD-PARTY-NOTICES.txt there with the license files
# of the Go standard library and the modules psiphon-tunnel-core links. The
# release archives carry them in LICENSES/.
licensedir="${5:-}"

if [ -z "$goos" ] || [ -z "$goarch" ] || [ -z "$out" ]; then
    echo "usage: psiphon-build.sh <goos> <goarch> <outdir> [goarm] [licensedir]" >&2
    exit 2
fi

# go_notice_text <texts dir> <label> <heading> <file> prints a license file
# under its heading, with \r removed, or names the entry that printed the
# same text before.
go_notice_text() {
    local texts="$1" label="$2" heading="$3" src="$4" i=1
    tr -d '\r' < "$src" > "$texts/new"
    if [ -n "$(tail -c 1 "$texts/new")" ]; then
        echo >> "$texts/new"
    fi
    printf '\n--- %s ---\n' "$heading"
    while [ -f "$texts/$i" ]; do
        if cmp -s "$texts/$i" "$texts/new"; then
            printf '(The same text as %s, above.)\n' "$(cat "$texts/$i.label")"
            return 0
        fi
        i=$((i + 1))
    done
    mv "$texts/new" "$texts/$i"
    printf '%s\n' "$label" > "$texts/$i.label"
    cat "$texts/$i"
}

# go_notices <name> <package> <file> writes the license notices of what the
# Go build in the current directory links into <package>: the Go standard
# library's LICENSE, then, for each module outside the main one that
# `go list -deps` gives a package of, its path, version and the LICENSE*,
# LICENCE*, COPYING* and NOTICE* files at its root. Run it with the build's
# GOOS, GOARCH, GOARM, CGO_ENABLED and GOFLAGS, so that it lists what the
# build compiled and the toolchain that compiled it. A text given before is
# not repeated; the entry names where it is.
#
# The standard library's LICENSE is the one at the root of the toolchain's
# GOROOT or, as Fedora's and RHEL's golang package installs it as a license
# file of the package instead (GOROOT /usr/lib/golang has none),
# /usr/share/licenses/golang/LICENSE. A module's files come from the folder
# `go list` gives as its .Dir: the module cache, or the local directory that
# replaces it. A build that vendors compiles vendor/<module path>, and
# `go list` then gives no .Dir, also for a module that go.mod replaces by a
# local directory, so its files come from vendor/<module path>.
go_notices() {
    local name="$1" pkg="$2" file="$3"
    local rule goroot goversion target golicense gosource modules texts count=0
    local mpath mversion rpath rversion mdir mreplace dir source f base found
    rule="================================================================================"
    goroot="$(go env GOROOT)"
    goversion="$(go env GOVERSION)"
    target="$(go env GOOS)/$(go env GOARCH)"
    if [ "$(go env GOARCH)" = "arm" ]; then
        target="$target, GOARM=$(go env GOARM)"
    fi
    golicense="$goroot/LICENSE"
    gosource="the Go toolchain"
    if [ ! -f "$golicense" ]; then
        golicense="/usr/share/licenses/golang/LICENSE"
        gosource="$golicense of the system's golang package"
    fi
    if [ ! -f "$golicense" ]; then
        echo "$name: no LICENSE in the Go toolchain's GOROOT $goroot or in /usr/share/licenses/golang" >&2
        return 1
    fi
    modules="$(go list -deps -f '{{if not .Standard}}{{with .Module}}{{if not .Main}}{{.Path}}|{{.Version}}|{{with .Replace}}{{.Path}}|{{.Version}}{{else}}|{{end}}|{{.Dir}}{{end}}{{end}}{{end}}' "$pkg" | sort -u)"
    texts="$(mktemp -d "$work/notices.XXXXXX")"
    {
        printf '%s\nGo standard library %s\nSource: %s\n' "$rule" "$goversion" "$gosource"
        go_notice_text "$texts" "Go standard library $goversion, LICENSE" LICENSE "$golicense"
        while IFS='|' read -r mpath mversion rpath rversion mdir; do
            if [ -z "$mpath" ]; then
                continue
            fi
            mreplace="$rpath${rversion:+ $rversion}"
            dir="$mdir"
            if [ -z "$dir" ]; then
                dir="vendor/$mpath"
                source="$dir in the source tree"
            elif [ -n "$rpath" ] && [ -z "$rversion" ]; then
                source="the local directory $rpath"
            else
                source="the module cache"
            fi
            if [ ! -d "$dir" ]; then
                echo "$name: no folder for module $mpath $mversion (looked for $dir)" >&2
                return 1
            fi
            count=$((count + 1))
            printf '  %s %s' "$mpath" "$mversion" >> "$texts/list"
            if [ -n "$mreplace" ]; then
                printf ' => %s' "$mreplace" >> "$texts/list"
            fi
            echo >> "$texts/list"
            printf '\n%s\n%s %s\nSource: %s\n' "$rule" "$mpath" "$mversion" "$source"
            if [ -n "$mreplace" ]; then
                printf 'Replaced by: %s\n' "$mreplace"
            fi
            found=0
            for f in "$dir"/*; do
                base="$(basename "$f")"
                case "$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]')" in
                    *.go) continue ;;
                    license*|licence*|copying*|notice*) ;;
                    *) continue ;;
                esac
                if [ ! -f "$f" ]; then
                    continue
                fi
                found=1
                go_notice_text "$texts" "$mpath $mversion, $base" "$base" "$f"
            done
            if [ "$found" = 0 ]; then
                printf '\nThis module has no license file at its root.\n'
                echo "$name: warning: $mpath $mversion has no license file at its root" >&2
            fi
        done <<< "$modules"
    } > "$texts/entries"
    mkdir -p "$(dirname "$file")"
    {
        printf 'Third-party notices for %s\nBuilt by %s for %s\n\n' "$name" "$goversion" "$target"
        printf '%s links the Go standard library and the %s Go modules below,\n' "$name" "$count"
        printf 'the modules outside its own that `go list -deps` gives a package of\n'
        printf "for its build. Each entry gives the license files at the module's\n"
        printf 'root. A text given before is not repeated; the entry names where it\n'
        printf "is. %s's own license files are the other %s-* files beside\n" "$name" "$name"
        printf 'this one.\n\nModules:\n'
        if [ -f "$texts/list" ]; then
            cat "$texts/list"
        fi
        echo
        cat "$texts/entries"
    } > "$file"
    echo "$name: notices of the Go standard library and $count modules -> $file"
}

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
    export GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0 GOFLAGS=-mod=vendor
    go build -trimpath -ldflags "-s -w" -o "$out/psiphon-tunnel-core$ext" ./ConsoleClient
    if [ -n "$licensedir" ]; then
        go_notices psiphon-tunnel-core ./ConsoleClient \
            "$licensedir/psiphon-tunnel-core-THIRD-PARTY-NOTICES.txt"
    fi
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

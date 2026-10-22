#!/usr/bin/env bash
set -euo pipefail

goos="${1:-}"
goarch="${2:-}"
out="${3:-}"
goarm="${4:-}"
# With a licensedir, lyrebird's license files are copied there too, named
# lyrebird-<file>, with .txt added to a name that has no extension, and
# go_notices writes lyrebird-THIRD-PARTY-NOTICES.txt there with the license
# files of the Go standard library and the modules lyrebird links. The
# release archives carry them in LICENSES/.
licensedir="${5:-}"

if [ -z "$goos" ] || [ -z "$goarch" ] || [ -z "$out" ]; then
    echo "usage: pt-build.sh <goos> <goarch> <outdir> [goarm] [licensedir]" >&2
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
# library's LICENSE from the toolchain's GOROOT, then, for each module
# outside the main one that `go list -deps` gives a package of, its path,
# version and the LICENSE*, LICENCE*, COPYING* and NOTICE* files at its
# root, read from the module cache or, when the build vendors, from
# vendor/<module path>. Run it with the build's GOOS, GOARCH, GOARM,
# CGO_ENABLED and GOFLAGS, so that it lists what the build compiled and
# the toolchain that compiled it. A text given before is not repeated; the
# entry names where it is.
go_notices() {
    local name="$1" pkg="$2" file="$3"
    local rule goroot goversion target modules texts count=0
    local mpath mversion mreplace mdir mrdir dir source f base found
    rule="================================================================================"
    goroot="$(go env GOROOT)"
    goversion="$(go env GOVERSION)"
    target="$(go env GOOS)/$(go env GOARCH)"
    if [ "$(go env GOARCH)" = "arm" ]; then
        target="$target, GOARM=$(go env GOARM)"
    fi
    if [ ! -f "$goroot/LICENSE" ]; then
        echo "$name: the Go toolchain in $goroot has no LICENSE" >&2
        return 1
    fi
    modules="$(go list -deps -f '{{if not .Standard}}{{with .Module}}{{if not .Main}}{{.Path}}|{{.Version}}|{{with .Replace}}{{.Path}} {{.Version}}{{end}}|{{.Dir}}|{{with .Replace}}{{.Dir}}{{end}}{{end}}{{end}}{{end}}' "$pkg" | sort -u)"
    texts="$(mktemp -d "$work/notices.XXXXXX")"
    {
        printf '%s\nGo standard library %s\nSource: the Go toolchain\n' "$rule" "$goversion"
        go_notice_text "$texts" "Go standard library $goversion, LICENSE" LICENSE "$goroot/LICENSE"
        while IFS='|' read -r mpath mversion mreplace mdir mrdir; do
            if [ -z "$mpath" ]; then
                continue
            fi
            dir="${mrdir:-$mdir}"
            source="the module cache"
            if [ -z "$dir" ]; then
                dir="vendor/$mpath"
                source="$dir in the source tree"
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
    export GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0
    go build -trimpath -ldflags "-s -w" -o "$out/lyrebird$ext" ./cmd/lyrebird
    if [ -n "$licensedir" ]; then
        go_notices lyrebird ./cmd/lyrebird "$licensedir/lyrebird-THIRD-PARTY-NOTICES.txt"
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

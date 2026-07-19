#!/bin/sh
# pack.sh — Create a router-ready archive of this package
#
# Usage (from the openwrt/ directory):
#   ./pack.sh
#   ./pack.sh ./dist
#
# Produces: aether-openwrt-<version>-x86_64.tar.gz
# Extract on router and run: ./install.sh

set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

OUT_DIR="${1:-.}"
case "$OUT_DIR" in
	/*|[A-Za-z]:*) : ;;
	*) OUT_DIR="$SCRIPT_DIR/$OUT_DIR" ;;
esac

VERSION="1.2.0"
ARCH="x86_64"
NAME="aether-openwrt-${VERSION}-${ARCH}"
STAGE="$SCRIPT_DIR/.pack-stage-$$"
ARCHIVE_BASENAME="${NAME}.tar.gz"

BINARY=""
for cand in aether-openwrt-musl aether aether-linux-x86_64; do
	if [ -f "$SCRIPT_DIR/$cand" ]; then
		BINARY="$SCRIPT_DIR/$cand"
		break
	fi
done

[ -n "$BINARY" ] || { echo "ERROR: no binary found (aether-openwrt-musl / aether)" >&2; exit 1; }
[ -d "$SCRIPT_DIR/files" ] || { echo "ERROR: missing files/" >&2; exit 1; }

rm -rf "$STAGE"
mkdir -p "$STAGE/$NAME"
mkdir -p "$OUT_DIR"

cp -f install.sh uninstall.sh "$STAGE/$NAME/"
[ -f README.md ] && cp -f README.md "$STAGE/$NAME/"
[ -f CLEAN-TEST.md ] && cp -f CLEAN-TEST.md "$STAGE/$NAME/"
[ -f BUILD-MUSL.md ] && cp -f BUILD-MUSL.md "$STAGE/$NAME/"
[ -f build-musl.sh ] && cp -f build-musl.sh "$STAGE/$NAME/"

cp -f "$BINARY" "$STAGE/$NAME/aether-openwrt-musl"
cp -f "$BINARY" "$STAGE/$NAME/aether"
cp -a files "$STAGE/$NAME/files"
[ -d musl-compat ] && cp -a musl-compat "$STAGE/$NAME/musl-compat"

for f in install.sh uninstall.sh build-musl.sh; do
	if [ -f "$STAGE/$NAME/$f" ]; then
		tr -d '\r' < "$STAGE/$NAME/$f" > "$STAGE/$NAME/$f.tmp"
		mv "$STAGE/$NAME/$f.tmp" "$STAGE/$NAME/$f"
		chmod 755 "$STAGE/$NAME/$f"
	fi
done
chmod 755 "$STAGE/$NAME/aether-openwrt-musl" "$STAGE/$NAME/aether"
find "$STAGE/$NAME/files" -type f \( -name 'aether-ctl' -o -path '*/init.d/*' -o -path '*/rpcd/*' \) -exec chmod 755 {} \; 2>/dev/null || true

(
	cd "$STAGE"
	tar czf "$ARCHIVE_BASENAME" "$NAME"
)
mv -f "$STAGE/$ARCHIVE_BASENAME" "$OUT_DIR/$ARCHIVE_BASENAME"
rm -rf "$STAGE"

echo "Created: $OUT_DIR/$ARCHIVE_BASENAME"
echo ""
echo "Transfer to router and install:"
echo "  tar xzf $ARCHIVE_BASENAME"
echo "  cd $NAME"
echo "  chmod +x install.sh"
echo "  ./install.sh --start"

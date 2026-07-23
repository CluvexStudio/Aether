#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

REPO="${AETHER_WEB_REPO:-noob-coder-clude/Aether}"
REF="${AETHER_WEB_REF:-arena/019f7b56-aether}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/aether-web-bootstrap.XXXXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

need_pkg() {
  command -v "$1" >/dev/null 2>&1
}

if ! need_pkg curl || ! need_pkg tar || ! need_pkg python3 || ! need_pkg git; then
  pkg update -y >/dev/null
  pkg install -y curl tar python git
fi

ARCHIVE="$TMP/repo.tar.gz"
SRC_DIR="$TMP/src"
mkdir -p "$SRC_DIR"

curl -fL -H 'Accept: application/vnd.github+json' \
  "https://api.github.com/repos/${REPO}/tarball/${REF}" \
  -o "$ARCHIVE"

tar -xzf "$ARCHIVE" -C "$SRC_DIR"
APP_DIR="$(find "$SRC_DIR" -maxdepth 2 -type d -name termux-webapp | head -n1)"

if [[ -z "$APP_DIR" || ! -d "$APP_DIR" ]]; then
  echo "[-] termux-webapp directory not found in downloaded archive." >&2
  exit 1
fi

cd "$APP_DIR"
chmod +x install.sh
exec ./install.sh

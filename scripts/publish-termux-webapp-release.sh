#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_REPO="${AETHER_APP_RELEASE_REPO:-noob-coder-clude/Aether_app}"
TAG="${1:-termux-web-v1.0.0}"
TITLE="${2:-Aether Termux Web v1.0.0}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aether-web-release.XXXXXX")"
cleanup() { rm -rf "${WORK_DIR}"; }
trap cleanup EXIT INT TERM

cd "${ROOT_DIR}"
./scripts/package-termux-webapp.sh "${WORK_DIR}"

ARCHIVE="${WORK_DIR}/aether-termux-webapp.tar.gz"
CHECKSUM="${WORK_DIR}/aether-termux-webapp.tar.gz.sha256"
NOTES_FILE="${WORK_DIR}/release-notes.md"

cat > "${NOTES_FILE}" <<'EOF'
## Aether Termux Web

Local browser dashboard for running Aether on Termux.

### Included
- install / update / uninstall Aether from Releases
- start / stop / restart tunnel from the browser
- MASQUE / WireGuard / GOOL presets
- live logs
- one-click proxy test
- Persian and English guides

### Install in Termux
```bash
tar -xzf aether-termux-webapp.tar.gz
cd termux-webapp
chmod +x install.sh
./install.sh
aether-web
```

Open: `http://127.0.0.1:8787`
EOF

if gh release view "${TAG}" --repo "${RELEASE_REPO}" >/dev/null 2>&1; then
  gh release upload "${TAG}" "${ARCHIVE}" "${CHECKSUM}" --repo "${RELEASE_REPO}" --clobber
else
  gh release create "${TAG}" "${ARCHIVE}" "${CHECKSUM}" \
    --repo "${RELEASE_REPO}" \
    --title "${TITLE}" \
    --notes-file "${NOTES_FILE}"
fi

echo "Published ${TAG} to ${RELEASE_REPO}"

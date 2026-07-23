#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-${ROOT_DIR}/dist}"
ARCHIVE_NAME="aether-termux-webapp.tar.gz"
BOOTSTRAP_NAME="aether-web-install.sh"

mkdir -p "${OUT_DIR}"

tar \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  -czf "${OUT_DIR}/${ARCHIVE_NAME}" -C "${ROOT_DIR}" termux-webapp
cp "${ROOT_DIR}/termux-webapp/bootstrap-install.sh" "${OUT_DIR}/${BOOTSTRAP_NAME}"
chmod +x "${OUT_DIR}/${BOOTSTRAP_NAME}"
sha256sum "${OUT_DIR}/${ARCHIVE_NAME}" > "${OUT_DIR}/${ARCHIVE_NAME}.sha256"
sha256sum "${OUT_DIR}/${BOOTSTRAP_NAME}" > "${OUT_DIR}/${BOOTSTRAP_NAME}.sha256"

echo "Created: ${OUT_DIR}/${ARCHIVE_NAME}"
echo "Created: ${OUT_DIR}/${BOOTSTRAP_NAME}"
echo "Checksums:"
echo "  - ${OUT_DIR}/${ARCHIVE_NAME}.sha256"
echo "  - ${OUT_DIR}/${BOOTSTRAP_NAME}.sha256"

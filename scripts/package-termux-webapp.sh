#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-${ROOT_DIR}/dist}"
ARCHIVE_NAME="aether-termux-webapp.tar.gz"

mkdir -p "${OUT_DIR}"

tar \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  -czf "${OUT_DIR}/${ARCHIVE_NAME}" -C "${ROOT_DIR}" termux-webapp
sha256sum "${OUT_DIR}/${ARCHIVE_NAME}" > "${OUT_DIR}/${ARCHIVE_NAME}.sha256"

echo "Created: ${OUT_DIR}/${ARCHIVE_NAME}"
echo "Checksum: ${OUT_DIR}/${ARCHIVE_NAME}.sha256"

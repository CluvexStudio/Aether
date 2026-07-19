#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

load_settings

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aether-web-update.XXXXXX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT INT TERM

ARCHIVE="${TMP_DIR}/repo.tar.gz"
EXTRACT_DIR="${TMP_DIR}/src"
mkdir -p "${EXTRACT_DIR}"

section "Updating dashboard"
echo "Source: ${AETHER_WEB_REPO} @ ${AETHER_WEB_REF}"

info "Downloading dashboard source archive from GitHub..."
curl -fL -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${AETHER_WEB_REPO}/tarball/${AETHER_WEB_REF}" \
  -o "${ARCHIVE}"

tar -xzf "${ARCHIVE}" -C "${EXTRACT_DIR}"
REPO_DIR="$(find "${EXTRACT_DIR}" -mindepth 1 -maxdepth 1 -type d | head -n1)"

if [[ -z "${REPO_DIR}" || ! -d "${REPO_DIR}/termux-webapp" ]]; then
  error "Downloaded archive does not contain termux-webapp/."
  exit 1
fi

WAS_RUNNING=0
if "${APP_DIR}/bin/aether-web-server.sh" status >/dev/null 2>&1; then
  if server_is_running; then
    WAS_RUNNING=1
    load_runtime
    OLD_HOST="${AETHER_PANEL_HOST}"
    OLD_PORT="${AETHER_PANEL_PORT}"
    "${APP_DIR}/bin/aether-web-server.sh" stop >/dev/null 2>&1 || true
  fi
fi

info "Copying updated files into ${APP_DIR} ..."
cp -R "${REPO_DIR}/termux-webapp/." "${APP_DIR}/"
chmod +x "${APP_DIR}/install.sh" "${APP_DIR}/bin/"*.sh

success "Dashboard files updated."

if [[ "${WAS_RUNNING}" == "1" ]]; then
  info "Restarting dashboard..."
  "${APP_DIR}/bin/aether-web-server.sh" start "${OLD_HOST:-127.0.0.1}" "${OLD_PORT:-8787}"
fi

success "Done."

#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${PREFIX}/opt/aether-web"
DATA_DIR="${AETHER_WEB_DATA:-${HOME}/.config/aether-web}"
LAUNCHER="${PREFIX}/bin/aether-web"
SERVER_LAUNCHER="${PREFIX}/bin/aether-web-server"
UPDATER_LAUNCHER="${PREFIX}/bin/aether-web-update"
UNINSTALLER="${PREFIX}/bin/aether-web-uninstall"
SETTINGS_FILE="${DATA_DIR}/sources.conf"

readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly YELLOW='\033[0;33m'
readonly RED='\033[0;31m'
readonly RESET='\033[0m'

info()    { echo -e "${BLUE}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[-]${RESET} $*" >&2; }

ensure_termux() {
  if [[ ! -d "/data/data/com.termux/files/usr" ]]; then
    error "This installer is designed for Termux."
    exit 1
  fi
}

ensure_dependencies() {
  local deps=(python curl tar git)
  local missing=()
  for dep in "${deps[@]}"; do
    command -v "$dep" >/dev/null 2>&1 || missing+=("$dep")
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    info "Installing missing packages: ${missing[*]}"
    pkg update -y >/dev/null
    pkg install -y "${missing[@]}"
  fi
}

extract_repo_from_git() {
  local top remote
  top="$(git -C "${ROOT_DIR}" rev-parse --show-toplevel 2>/dev/null || true)"
  [[ -n "${top}" ]] || return 1
  remote="$(git -C "${top}" remote get-url origin 2>/dev/null || true)"
  [[ -n "${remote}" ]] || return 1
  remote="${remote%.git}"
  remote="${remote#git@github.com:}"
  remote="${remote#https://github.com/}"
  remote="${remote#http://github.com/}"
  [[ "${remote}" == */* ]] || return 1
  echo "${remote}"
}

detect_web_repo() {
  if [[ -n "${AETHER_WEB_REPO:-}" ]]; then
    echo "${AETHER_WEB_REPO}"
    return
  fi
  extract_repo_from_git || echo "noob-coder-clude/Aether"
}

detect_web_ref() {
  if [[ -n "${AETHER_WEB_REF:-}" ]]; then
    echo "${AETHER_WEB_REF}"
    return
  fi
  git -C "${ROOT_DIR}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main"
}

detect_core_repo() {
  local web_repo="$1"
  if [[ -n "${AETHER_CORE_REPO:-}" ]]; then
    echo "${AETHER_CORE_REPO}"
    return
  fi

  python3 - "$web_repo" <<'PY' 2>/dev/null || echo "$web_repo"
import json, sys, urllib.request
repo = sys.argv[1]
url = f"https://api.github.com/repos/{repo}"
req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "aether-web-installer"})
with urllib.request.urlopen(req, timeout=15) as resp:
    data = json.load(resp)
print((data.get("parent") or {}).get("full_name") or repo)
PY
}

write_settings() {
  local web_repo="$1"
  local web_ref="$2"
  local core_repo="$3"
  mkdir -p "${DATA_DIR}"
  cat > "${SETTINGS_FILE}" <<EOF
AETHER_WEB_REPO=${web_repo}
AETHER_WEB_REF=${web_ref}
AETHER_CORE_REPO=${core_repo}
AETHER_PANEL_PORT=8787
EOF
}

install_files() {
  mkdir -p "${PREFIX}/opt" "${PREFIX}/bin" "${DATA_DIR}"
  rm -rf "${INSTALL_DIR}"
  mkdir -p "${INSTALL_DIR}"
  cp -R "${ROOT_DIR}/." "${INSTALL_DIR}/"
  chmod +x "${INSTALL_DIR}/install.sh" "${INSTALL_DIR}/bin/"*.sh

  cat > "${LAUNCHER}" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
APP_DIR="${PREFIX}/opt/aether-web"
exec "${APP_DIR}/bin/aether-web-menu.sh" "$@"
EOF

  cat > "${SERVER_LAUNCHER}" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
APP_DIR="${PREFIX}/opt/aether-web"
exec "${APP_DIR}/bin/aether-web-server.sh" "$@"
EOF

  cat > "${UPDATER_LAUNCHER}" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
APP_DIR="${PREFIX}/opt/aether-web"
exec "${APP_DIR}/bin/aether-web-selfupdate.sh" "$@"
EOF

  cat > "${UNINSTALLER}" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
APP_DIR="${PREFIX}/opt/aether-web"
exec "${APP_DIR}/bin/aether-web-menu.sh" uninstall
EOF

  chmod +x "${LAUNCHER}" "${SERVER_LAUNCHER}" "${UPDATER_LAUNCHER}" "${UNINSTALLER}"
}

print_finish() {
  local web_repo="$1"
  local web_ref="$2"
  local core_repo="$3"
  success "Aether Termux Web نصب شد."
  echo
  echo "Dashboard source : ${web_repo} @ ${web_ref}"
  echo "Aether core repo : ${core_repo}"
  echo "SOCKS proxy port : 127.0.0.1:1819"
  echo "Panel web port   : 127.0.0.1:8787"
  echo
  echo "Commands:"
  echo "  aether-web           # interactive menu"
  echo "  aether-web start     # start local dashboard + open browser"
  echo "  aether-web lan       # start LAN dashboard + open browser"
  echo "  aether-web update-core"
  echo "  aether-web update-panel"
}

main() {
  ensure_termux
  ensure_dependencies

  local web_repo web_ref core_repo
  web_repo="$(detect_web_repo)"
  web_ref="$(detect_web_ref)"
  core_repo="$(detect_core_repo "${web_repo}")"

  install_files
  write_settings "${web_repo}" "${web_ref}" "${core_repo}"
  print_finish "${web_repo}" "${web_ref}" "${core_repo}"

  if [[ -t 0 && "${AETHER_WEB_NO_MENU:-0}" != "1" ]]; then
    echo
    read -r -p "Open the interactive menu now? [Y/n]: " ans
    case "${ans:-y}" in
      n|N|no|NO) ;;
      *) exec "${LAUNCHER}" ;;
    esac
  fi
}

main "$@"

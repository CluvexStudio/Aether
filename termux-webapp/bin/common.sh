#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

readonly PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
readonly APP_DIR="${AETHER_WEB_APP_DIR:-${PREFIX}/opt/aether-web}"
readonly DATA_DIR="${AETHER_WEB_DATA:-${HOME}/.config/aether-web}"
readonly SETTINGS_FILE="${DATA_DIR}/sources.conf"
readonly SERVER_RUNTIME_FILE="${DATA_DIR}/server-runtime.conf"
readonly SERVER_PID_FILE="${DATA_DIR}/server.pid"
readonly SERVER_LOG_FILE="${DATA_DIR}/server.log"
readonly CORE_INSTALLER="${APP_DIR}/bin/aether-installer.sh"
readonly SERVER_SCRIPT="${APP_DIR}/server.py"
readonly PANEL_DEFAULT_PORT="8787"
readonly PANEL_DEFAULT_HOST="127.0.0.1"

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly RESET='\033[0m'

info()    { echo -e "${BLUE}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[-]${RESET} $*" >&2; }
section() { echo -e "\n${CYAN}== $* ==${RESET}"; }

ensure_data_dir() {
  mkdir -p "${DATA_DIR}"
}

detect_default_lang() {
  case "${LANG:-}" in
    fa*|FA*|*_IR*|*fa_IR*) echo "fa" ;;
    *) echo "en" ;;
  esac
}

load_settings() {
  ensure_data_dir
  if [[ -f "${SETTINGS_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${SETTINGS_FILE}"
  fi
  export AETHER_WEB_REPO="${AETHER_WEB_REPO:-noob-coder-clude/Aether}"
  export AETHER_WEB_REF="${AETHER_WEB_REF:-main}"
  export AETHER_CORE_REPO="${AETHER_CORE_REPO:-${AETHER_WEB_REPO}}"
  export AETHER_PANEL_PORT="${AETHER_PANEL_PORT:-${PANEL_DEFAULT_PORT}}"
  export AETHER_WEB_LANG="${AETHER_WEB_LANG:-$(detect_default_lang)}"
}

write_settings() {
  local web_repo="$1"
  local web_ref="$2"
  local core_repo="$3"
  local web_lang="${4:-$(detect_default_lang)}"
  local panel_port="${5:-${PANEL_DEFAULT_PORT}}"
  mkdir -p "${DATA_DIR}"
  cat > "${SETTINGS_FILE}" <<EOF
AETHER_WEB_REPO=${web_repo}
AETHER_WEB_REF=${web_ref}
AETHER_CORE_REPO=${core_repo}
AETHER_WEB_LANG=${web_lang}
AETHER_PANEL_PORT=${panel_port}
EOF
}

load_runtime() {
  ensure_data_dir
  if [[ -f "${SERVER_RUNTIME_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${SERVER_RUNTIME_FILE}"
  fi
  export AETHER_PANEL_HOST="${AETHER_PANEL_HOST:-${PANEL_DEFAULT_HOST}}"
  export AETHER_PANEL_PORT="${AETHER_PANEL_PORT:-${PANEL_DEFAULT_PORT}}"
}

save_runtime() {
  ensure_data_dir
  cat > "${SERVER_RUNTIME_FILE}" <<EOF
AETHER_PANEL_HOST=${AETHER_PANEL_HOST}
AETHER_PANEL_PORT=${AETHER_PANEL_PORT}
EOF
}

is_pid_running() {
  local pid="${1:-0}"
  [[ "${pid}" =~ ^[0-9]+$ ]] || return 1
  (( pid > 0 )) || return 1
  kill -0 "${pid}" 2>/dev/null
}

read_server_pid() {
  if [[ -f "${SERVER_PID_FILE}" ]]; then
    tr -dc '0-9' < "${SERVER_PID_FILE}"
  fi
}

server_is_running() {
  local pid
  pid="$(read_server_pid || true)"
  [[ -n "${pid}" ]] && is_pid_running "${pid}"
}

write_server_pid() {
  ensure_data_dir
  echo "$1" > "${SERVER_PID_FILE}"
}

clear_server_pid() {
  rm -f "${SERVER_PID_FILE}"
}

local_ip_guess() {
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
  fi
  if [[ -z "${ip}" ]] && command -v hostname >/dev/null 2>&1; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  echo "${ip}"
}

current_panel_url() {
  load_runtime
  if [[ "${AETHER_PANEL_HOST}" == "0.0.0.0" ]]; then
    echo "http://127.0.0.1:${AETHER_PANEL_PORT}"
  else
    echo "http://${AETHER_PANEL_HOST}:${AETHER_PANEL_PORT}"
  fi
}

print_panel_urls() {
  load_runtime
  local local_url="http://127.0.0.1:${AETHER_PANEL_PORT}"
  echo "${local_url}"
  if [[ "${AETHER_PANEL_HOST}" == "0.0.0.0" ]]; then
    local lan_ip
    lan_ip="$(local_ip_guess)"
    if [[ -n "${lan_ip}" ]]; then
      echo "http://${lan_ip}:${AETHER_PANEL_PORT}"
    fi
  elif [[ "${AETHER_PANEL_HOST}" != "127.0.0.1" && "${AETHER_PANEL_HOST}" != "localhost" ]]; then
    echo "http://${AETHER_PANEL_HOST}:${AETHER_PANEL_PORT}"
  fi
}

open_url() {
  local url="$1"
  if command -v termux-open-url >/dev/null 2>&1; then
    termux-open-url "${url}" >/dev/null 2>&1 || true
    return 0
  fi
  if command -v am >/dev/null 2>&1; then
    am start -a android.intent.action.VIEW -d "${url}" >/dev/null 2>&1 || true
    return 0
  fi
  return 1
}

wait_for_http() {
  local url="$1"
  local max_tries="${2:-25}"
  local i
  for ((i=1; i<=max_tries; i++)); do
    if curl -fsS --max-time 2 "${url}/api/status" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.4
  done
  return 1
}

print_sources() {
  load_settings
  echo "Dashboard source: ${AETHER_WEB_REPO} @ ${AETHER_WEB_REF}"
  echo "Aether core source: ${AETHER_CORE_REPO}"
}

#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

show_sources() {
  section "Sources"
  print_sources
  echo "Dashboard panel port: ${AETHER_PANEL_PORT:-${PANEL_DEFAULT_PORT}}"
  echo "Aether SOCKS proxy port inside the UI stays on: 127.0.0.1:1819"
}

start_local() {
  load_settings
  "${APP_DIR}/bin/aether-web-server.sh" start 127.0.0.1 "${AETHER_PANEL_PORT}"
  "${APP_DIR}/bin/aether-web-server.sh" open || true
}

start_lan() {
  load_settings
  "${APP_DIR}/bin/aether-web-server.sh" start 0.0.0.0 "${AETHER_PANEL_PORT}"
  "${APP_DIR}/bin/aether-web-server.sh" open || true
}

install_core() {
  load_settings
  AETHER_RELEASE_REPO="${AETHER_CORE_REPO}" AETHER_WEB_DATA="${DATA_DIR}" "${CORE_INSTALLER}" install
}

update_core() {
  load_settings
  AETHER_RELEASE_REPO="${AETHER_CORE_REPO}" AETHER_WEB_DATA="${DATA_DIR}" "${CORE_INSTALLER}" update
}

core_status() {
  load_settings
  AETHER_RELEASE_REPO="${AETHER_CORE_REPO}" AETHER_WEB_DATA="${DATA_DIR}" "${CORE_INSTALLER}" status
}

remove_core() {
  load_settings
  AETHER_RELEASE_REPO="${AETHER_CORE_REPO}" AETHER_WEB_DATA="${DATA_DIR}" "${CORE_INSTALLER}" uninstall
}

update_panel() {
  AETHER_WEB_DATA="${DATA_DIR}" "${APP_DIR}/bin/aether-web-selfupdate.sh"
}

open_if_running() {
  if server_is_running; then
    "${APP_DIR}/bin/aether-web-server.sh" open
  else
    warn "Dashboard is not running yet."
  fi
}

uninstall_everything() {
  warn "This will remove the dashboard from Termux."
  read -r -p "Continue? [y/N]: " ans
  case "${ans:-n}" in
    y|Y|yes|YES)
      "${APP_DIR}/bin/aether-web-server.sh" stop >/dev/null 2>&1 || true
      rm -rf "${APP_DIR}"
      rm -f "${PREFIX}/bin/aether-web" "${PREFIX}/bin/aether-web-server" "${PREFIX}/bin/aether-web-update" "${PREFIX}/bin/aether-web-uninstall"
      success "Aether Web removed from Termux."
      ;;
    *)
      warn "Canceled."
      ;;
  esac
}

show_menu() {
  while true; do
    load_settings
    load_runtime
    clear
    echo -e "${GREEN}=== Aether Termux Web ===${RESET}"
    echo "Dashboard source : ${AETHER_WEB_REPO} @ ${AETHER_WEB_REF}"
    echo "Aether core     : ${AETHER_CORE_REPO}"
    echo "Panel port       : ${AETHER_PANEL_PORT}"
    echo "SOCKS proxy      : 127.0.0.1:1819"
    echo
    if server_is_running; then
      echo -e "${GREEN}[running]${RESET} Dashboard is active."
      print_panel_urls | sed 's/^/  /'
    else
      echo -e "${YELLOW}[stopped]${RESET} Dashboard is not running."
    fi
    echo
    echo "1) Start dashboard (local only) + open browser"
    echo "2) Start dashboard (LAN/Wi-Fi) + open browser"
    echo "3) Open browser if dashboard is already running"
    echo "4) Stop dashboard"
    echo "5) Install Aether core"
    echo "6) Update Aether core from main/original repo"
    echo "7) Show Aether core status"
    echo "8) Update this dashboard from current fork/repo"
    echo "9) Remove Aether core"
    echo "10) Show sources"
    echo "11) Uninstall dashboard"
    echo "0) Exit"
    echo
    read -r -p "Select an option [0-11]: " choice
    echo
    case "${choice}" in
      1) start_local ;;
      2) start_lan ;;
      3) open_if_running ;;
      4) "${APP_DIR}/bin/aether-web-server.sh" stop ;;
      5) install_core ;;
      6) update_core ;;
      7) core_status ;;
      8) update_panel ;;
      9) remove_core ;;
      10) show_sources ;;
      11) uninstall_everything; break ;;
      0) break ;;
      *) warn "Invalid option." ;;
    esac
    echo
    read -r -p "Press Enter to continue..." _
  done
}

case "${1:-menu}" in
  menu) show_menu ;;
  start) start_local ;;
  lan) start_lan ;;
  stop) "${APP_DIR}/bin/aether-web-server.sh" stop ;;
  open) open_if_running ;;
  status) "${APP_DIR}/bin/aether-web-server.sh" status ;;
  install-core) install_core ;;
  update-core) update_core ;;
  core-status) core_status ;;
  remove-core) remove_core ;;
  update-panel) update_panel ;;
  uninstall) uninstall_everything ;;
  sources) show_sources ;;
  *)
    echo "Usage: aether-web [menu|start|lan|stop|open|status|install-core|update-core|core-status|remove-core|update-panel|sources|uninstall]"
    exit 1
    ;;
esac

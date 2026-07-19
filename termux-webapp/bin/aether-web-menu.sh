#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

lang() {
  local key="$1"
  case "${AETHER_WEB_LANG:-fa}" in
    en)
      case "$key" in
        title) echo "Aether Termux Web" ;;
        sources) echo "Sources" ;;
        panel_port) echo "Dashboard panel port" ;;
        socks_port) echo "Aether SOCKS proxy port inside the UI stays on: 127.0.0.1:1819" ;;
        dashboard_not_running) echo "Dashboard is not running yet." ;;
        uninstall_warn) echo "This will remove the dashboard from Termux." ;;
        continue_prompt) echo "Continue? [y/N]: " ;;
        canceled) echo "Canceled." ;;
        removed) echo "Aether Web removed from Termux." ;;
        dashboard_source) echo "Dashboard source" ;;
        core_source) echo "Aether core" ;;
        panel_port_label) echo "Panel port" ;;
        socks_label) echo "SOCKS proxy" ;;
        running) echo "[running] Dashboard is active." ;;
        stopped) echo "[stopped] Dashboard is not running." ;;
        menu_1) echo "1) Start dashboard (local only) + open browser" ;;
        menu_2) echo "2) Start dashboard (LAN/Wi-Fi) + open browser" ;;
        menu_3) echo "3) Open browser if dashboard is already running" ;;
        menu_4) echo "4) Stop dashboard" ;;
        menu_5) echo "5) Install Aether core" ;;
        menu_6) echo "6) Update Aether core from main/original repo" ;;
        menu_7) echo "7) Show Aether core status" ;;
        menu_8) echo "8) Update this dashboard from current fork/repo" ;;
        menu_9) echo "9) Remove Aether core" ;;
        menu_10) echo "10) Show sources" ;;
        menu_11) echo "11) Change language" ;;
        menu_12) echo "12) Uninstall dashboard" ;;
        menu_0) echo "0) Exit" ;;
        select) echo "Select an option [0-12]: " ;;
        invalid) echo "Invalid option." ;;
        continue_enter) echo "Press Enter to continue..." ;;
        choose_lang) echo "Choose language:" ;;
        choose_lang_1) echo "1) فارسی" ;;
        choose_lang_2) echo "2) English" ;;
        choose_lang_prompt) echo "Select [1-2]: " ;;
        lang_saved) echo "Language saved." ;;
        usage) echo "Usage: aether-web [menu|start|lan|stop|open|status|install-core|update-core|core-status|remove-core|update-panel|sources|lang|uninstall]" ;;
      esac
      ;;
    *)
      case "$key" in
        title) echo "Aether Termux Web" ;;
        sources) echo "سورس‌ها" ;;
        panel_port) echo "پورت پنل داشبورد" ;;
        socks_port) echo "پورت پراکسی SOCKS خود Aether داخل UI همان: 127.0.0.1:1819" ;;
        dashboard_not_running) echo "داشبورد هنوز اجرا نشده است." ;;
        uninstall_warn) echo "این کار داشبورد را از ترموکس حذف می‌کند." ;;
        continue_prompt) echo "ادامه بدهم؟ [y/N]: " ;;
        canceled) echo "لغو شد." ;;
        removed) echo "Aether Web از ترموکس حذف شد." ;;
        dashboard_source) echo "سورس داشبورد" ;;
        core_source) echo "هسته Aether" ;;
        panel_port_label) echo "پورت پنل" ;;
        socks_label) echo "پراکسی SOCKS" ;;
        running) echo "[running] داشبورد فعال است." ;;
        stopped) echo "[stopped] داشبورد فعال نیست." ;;
        menu_1) echo "1) اجرای داشبورد لوکال + باز شدن خودکار مرورگر" ;;
        menu_2) echo "2) اجرای داشبورد روی LAN/Wi-Fi + باز شدن خودکار مرورگر" ;;
        menu_3) echo "3) اگر داشبورد اجراست، مرورگر را باز کن" ;;
        menu_4) echo "4) توقف داشبورد" ;;
        menu_5) echo "5) نصب هسته Aether" ;;
        menu_6) echo "6) آپدیت هسته Aether از ریپوی اصلی" ;;
        menu_7) echo "7) نمایش وضعیت هسته Aether" ;;
        menu_8) echo "8) آپدیت خود داشبورد از همین فورک/ریپو" ;;
        menu_9) echo "9) حذف هسته Aether" ;;
        menu_10) echo "10) نمایش سورس‌ها" ;;
        menu_11) echo "11) تغییر زبان" ;;
        menu_12) echo "12) حذف داشبورد" ;;
        menu_0) echo "0) خروج" ;;
        select) echo "یک گزینه انتخاب کن [0-12]: " ;;
        invalid) echo "گزینه نامعتبر است." ;;
        continue_enter) echo "برای ادامه Enter بزن..." ;;
        choose_lang) echo "زبان را انتخاب کن:" ;;
        choose_lang_1) echo "1) فارسی" ;;
        choose_lang_2) echo "2) English" ;;
        choose_lang_prompt) echo "انتخاب [1-2]: " ;;
        lang_saved) echo "زبان ذخیره شد." ;;
        usage) echo "Usage: aether-web [menu|start|lan|stop|open|status|install-core|update-core|core-status|remove-core|update-panel|sources|lang|uninstall]" ;;
      esac
      ;;
  esac
}

save_language() {
  local selected="$1"
  load_settings
  write_settings "${AETHER_WEB_REPO}" "${AETHER_WEB_REF}" "${AETHER_CORE_REPO}" "$selected" "${AETHER_PANEL_PORT}"
  export AETHER_WEB_LANG="$selected"
  success "$(lang lang_saved)"
}

change_language() {
  clear
  echo -e "${GREEN}=== $(lang title) ===${RESET}"
  echo "$(lang choose_lang)"
  echo "$(lang choose_lang_1)"
  echo "$(lang choose_lang_2)"
  echo
  read -r -p "$(lang choose_lang_prompt)" ans
  case "${ans}" in
    1) save_language fa ;;
    2) save_language en ;;
    *) warn "$(lang invalid)" ;;
  esac
}

show_sources() {
  section "$(lang sources)"
  print_sources
  echo "$(lang panel_port): ${AETHER_PANEL_PORT:-${PANEL_DEFAULT_PORT}}"
  echo "$(lang socks_port)"
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
    warn "$(lang dashboard_not_running)"
  fi
}

uninstall_everything() {
  warn "$(lang uninstall_warn)"
  read -r -p "$(lang continue_prompt)" ans
  case "${ans:-n}" in
    y|Y|yes|YES)
      "${APP_DIR}/bin/aether-web-server.sh" stop >/dev/null 2>&1 || true
      rm -rf "${APP_DIR}"
      rm -f "${PREFIX}/bin/aether-web" "${PREFIX}/bin/aether-web-server" "${PREFIX}/bin/aether-web-update" "${PREFIX}/bin/aether-web-uninstall"
      success "$(lang removed)"
      ;;
    *)
      warn "$(lang canceled)"
      ;;
  esac
}

show_menu() {
  while true; do
    load_settings
    load_runtime
    clear
    echo -e "${GREEN}=== $(lang title) ===${RESET}"
    echo "$(lang dashboard_source) : ${AETHER_WEB_REPO} @ ${AETHER_WEB_REF}"
    echo "$(lang core_source)      : ${AETHER_CORE_REPO}"
    echo "$(lang panel_port_label) : ${AETHER_PANEL_PORT}"
    echo "$(lang socks_label)      : 127.0.0.1:1819"
    echo
    if server_is_running; then
      echo -e "${GREEN}$(lang running)${RESET}"
      print_panel_urls | sed 's/^/  /'
    else
      echo -e "${YELLOW}$(lang stopped)${RESET}"
    fi
    echo
    for key in menu_1 menu_2 menu_3 menu_4 menu_5 menu_6 menu_7 menu_8 menu_9 menu_10 menu_11 menu_12 menu_0; do
      echo "$(lang "$key")"
    done
    echo
    read -r -p "$(lang select)" choice
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
      11) change_language ;;
      12) uninstall_everything; break ;;
      0) break ;;
      *) warn "$(lang invalid)" ;;
    esac
    echo
    read -r -p "$(lang continue_enter)" _
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
  sources) show_sources ;;
  lang) change_language ;;
  uninstall) uninstall_everything ;;
  *)
    echo "$(lang usage)"
    exit 1
    ;;
esac

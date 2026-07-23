#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

start_server() {
  local host="${1:-${PANEL_DEFAULT_HOST}}"
  local port="${2:-${PANEL_DEFAULT_PORT}}"

  ensure_data_dir

  if server_is_running; then
    local pid
    pid="$(read_server_pid)"
    success "Dashboard already running with PID ${pid}."
    print_panel_urls
    return 0
  fi

  if [[ ! -f "${SERVER_SCRIPT}" ]]; then
    error "Dashboard server not found at ${SERVER_SCRIPT}"
    exit 1
  fi

  export AETHER_PANEL_HOST="${host}"
  export AETHER_PANEL_PORT="${port}"
  save_runtime

  info "Starting dashboard on ${host}:${port} ..."
  nohup python3 "${SERVER_SCRIPT}" --host "${host}" --port "${port}" >> "${SERVER_LOG_FILE}" 2>&1 &
  local pid=$!
  write_server_pid "${pid}"

  local probe_url="http://127.0.0.1:${port}"
  if wait_for_http "${probe_url}" 25; then
    success "Dashboard is ready."
    print_panel_urls
  else
    warn "Dashboard process started but health check did not answer yet."
    warn "Check log: ${SERVER_LOG_FILE}"
    print_panel_urls
  fi
}

stop_server() {
  if ! server_is_running; then
    clear_server_pid
    warn "Dashboard is not running."
    return 0
  fi

  local pid
  pid="$(read_server_pid)"
  info "Stopping dashboard PID ${pid} ..."

  kill "${pid}" 2>/dev/null || true
  local i
  for ((i=1; i<=20; i++)); do
    if ! is_pid_running "${pid}"; then
      break
    fi
    sleep 0.25
  done

  if is_pid_running "${pid}"; then
    warn "Dashboard did not stop gracefully. Killing..."
    kill -9 "${pid}" 2>/dev/null || true
  fi

  clear_server_pid
  success "Dashboard stopped."
}

show_status() {
  load_runtime
  if server_is_running; then
    local pid
    pid="$(read_server_pid)"
    success "Dashboard is running (PID ${pid})."
  else
    warn "Dashboard is not running."
  fi
  echo "Host: ${AETHER_PANEL_HOST:-${PANEL_DEFAULT_HOST}}"
  echo "Port: ${AETHER_PANEL_PORT:-${PANEL_DEFAULT_PORT}}"
  echo "URLs:"
  print_panel_urls | sed 's/^/  - /'
  echo "Log: ${SERVER_LOG_FILE}"
}

open_dashboard() {
  local url
  url="$(current_panel_url)"
  if open_url "${url}"; then
    success "Browser opened: ${url}"
  else
    warn "Could not auto-open browser. Open this manually: ${url}"
  fi
}

case "${1:-status}" in
  start)
    start_server "${2:-${PANEL_DEFAULT_HOST}}" "${3:-${PANEL_DEFAULT_PORT}}"
    ;;
  stop)
    stop_server
    ;;
  restart)
    stop_server || true
    start_server "${2:-${PANEL_DEFAULT_HOST}}" "${3:-${PANEL_DEFAULT_PORT}}"
    ;;
  status)
    show_status
    ;;
  open)
    open_dashboard
    ;;
  urls)
    print_panel_urls
    ;;
  *)
    echo "Usage: $0 [start [host [port]]|stop|restart [host [port]]|status|open|urls]"
    exit 1
    ;;
esac

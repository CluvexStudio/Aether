#!/data/data/com.termux/files/usr/bin/bash
set -uo pipefail

readonly REPO="CluvexStudio/Aether"
readonly BIN_NAME="aether"
readonly PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
readonly INSTALL_PATH="${PREFIX}/bin/${BIN_NAME}"
readonly VERSION_FILE="${PREFIX}/etc/${BIN_NAME}.version"
readonly API_BASE="https://api.github.com/repos/${REPO}"

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly RESET='\033[0m'

info()    { echo -e "${BLUE}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[-]${RESET} $*" >&2; }

TMP_DIR=""
cleanup() {
  [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]] && rm -rf "${TMP_DIR}"
}
trap cleanup EXIT INT TERM

ensure_termux() {
  if [[ ! -d "/data/data/com.termux/files/usr" ]]; then
    error "This script is designed for Termux. \$PREFIX not found."
    exit 1
  fi
}

check_dependencies() {
  local missing=()
  local deps=("curl" "tar" "grep" "sed" "sha256sum")

  for dep in "${deps[@]}"; do
    command -v "${dep}" &>/dev/null || missing+=("${dep}")
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    info "Installing missing dependencies: ${missing[*]}"
    pkg update -y &>/dev/null
    if ! pkg install -y "${missing[@]}"; then
      error "Failed to install dependencies: ${missing[*]}"
      exit 1
    fi
  fi
}

detect_arch() {
  local machine
  machine="$(uname -m)"
  case "${machine}" in
    aarch64|arm64)
      echo "arm64" ;;
    armv7l|armv8l|arm)
      echo "armv7" ;;
    x86_64|amd64)
      echo "x86_64" ;;
    *)
      echo "unsupported" ;;
  esac
}

fetch_release_json() {
  local tag="$1"
  local url
  if [[ "${tag}" == "latest" ]]; then
    url="${API_BASE}/releases/latest"
  else
    url="${API_BASE}/releases/tags/${tag}"
  fi

  local response
  response="$(curl -fsSL -H "Accept: application/vnd.github+json" "${url}")" || {
    error "Failed to reach GitHub API (${url})."
    return 1
  }
  echo "${response}"
}

extract_tag_name() {
  grep -m1 '"tag_name"' | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/'
}

extract_asset_url() {
  local filename="$1"
  grep -o "\"browser_download_url\": *\"[^\"]*${filename}\"" | sed -E 's/.*"(https[^"]+)"/\1/' | head -n1
}

do_install() {
  local requested_tag="${1:-latest}"

  ensure_termux
  check_dependencies

  local arch
  arch="$(detect_arch)"
  if [[ "${arch}" == "unsupported" ]]; then
    error "Unsupported architecture: $(uname -m)"
    exit 1
  fi
  local archive="aether-android-${arch}.tar.gz"

  info "Detected architecture: $(uname -m) -> asset: ${archive}"
  info "Looking up release (${requested_tag})..."

  local release_json
  release_json="$(fetch_release_json "${requested_tag}")" || exit 1

  local tag_name
  tag_name="$(echo "${release_json}" | extract_tag_name)"
  if [[ -z "${tag_name}" ]]; then
    error "Could not resolve a release tag for '${requested_tag}'."
    exit 1
  fi

  local asset_url checksum_url
  asset_url="$(echo "${release_json}" | extract_asset_url "${archive}")"
  checksum_url="$(echo "${release_json}" | extract_asset_url "${archive}.sha256")"

  if [[ -z "${asset_url}" ]]; then
    error "No asset named '${archive}' found in release ${tag_name}."
    error "This device architecture may not have a prebuilt binary."
    exit 1
  fi

  if [[ -f "${VERSION_FILE}" ]] && [[ "$(cat "${VERSION_FILE}")" == "${tag_name}" ]]; then
    success "Aether ${tag_name} is already installed. Nothing to do."
    return 0
  fi

  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aether-install.XXXXXX")"
  local archive_path="${TMP_DIR}/${archive}"

  info "Downloading ${archive} (${tag_name})..."
  if ! curl -fL --progress-bar -o "${archive_path}" "${asset_url}"; then
    error "Download failed."
    exit 1
  fi

  if [[ -n "${checksum_url}" ]]; then
    info "Verifying checksum..."
    local expected_sum
    expected_sum="$(curl -fsSL "${checksum_url}" | awk '{print $1}')"
    local actual_sum
    actual_sum="$(sha256sum "${archive_path}" | awk '{print $1}')"
    if [[ -z "${expected_sum}" || "${expected_sum}" != "${actual_sum}" ]]; then
      error "Checksum mismatch! Expected ${expected_sum:-<unknown>}, got ${actual_sum}."
      exit 1
    fi
    success "Checksum verified."
  else
    warn "No checksum file found for this asset; skipping verification."
  fi

  info "Extracting..."
  tar -xzf "${archive_path}" -C "${TMP_DIR}"

  local binary_path="${TMP_DIR}/${BIN_NAME}"
  if [[ ! -f "${binary_path}" ]]; then
    binary_path="$(find "${TMP_DIR}" -maxdepth 2 -type f -name "${BIN_NAME}" | head -n1)"
  fi

  if [[ -z "${binary_path}" || ! -f "${binary_path}" ]]; then
    error "Could not find the '${BIN_NAME}' binary inside the archive."
    exit 1
  fi

  if ! mkdir -p "${PREFIX}/bin" "${PREFIX}/etc"; then
    error "Could not create ${PREFIX}/bin or ${PREFIX}/etc"
    exit 1
  fi

  if ! chmod +x "${binary_path}"; then
    error "Could not mark the downloaded binary executable"
    exit 1
  fi

  if ! cp -f "${binary_path}" "${INSTALL_PATH}"; then
    error "Could not copy the binary to ${INSTALL_PATH}"
    error "If aether is currently running, stop it first and try again."
    exit 1
  fi

  if ! echo "${tag_name}" > "${VERSION_FILE}"; then
    error "Installed the binary but could not record the version in ${VERSION_FILE}"
    exit 1
  fi

  success "Aether ${tag_name} installed. Run it with: ${BIN_NAME}"
  info "Once running, SOCKS5 proxy will listen on 127.0.0.1:1819"
}

do_update() {
  if [[ ! -f "${VERSION_FILE}" ]]; then
    warn "Aether is not installed yet. Installing latest release instead."
    do_install "latest"
    return
  fi
  info "Currently installed: $(cat "${VERSION_FILE}")"
  do_install "latest"
}

do_uninstall() {
  if [[ -f "${INSTALL_PATH}" ]]; then
    rm -f "${INSTALL_PATH}" "${VERSION_FILE}"
    success "Aether has been uninstalled."
  else
    warn "Aether is not installed."
  fi
}

do_status() {
  if [[ -f "${INSTALL_PATH}" ]]; then
    success "Installed at: ${INSTALL_PATH}"
    [[ -f "${VERSION_FILE}" ]] && info "Version: $(cat "${VERSION_FILE}")"
  else
    warn "Aether is not installed."
  fi
}

show_menu() {
  clear
  echo -e "${GREEN}=== Aether Termux Installer ===${RESET}"
  do_status
  echo ""
  echo "1) Install / reinstall latest"
  echo "2) Update"
  echo "3) Uninstall"
  echo "4) Status"
  echo "0) Exit"
  echo -ne "${GREEN}Select option [0-4]: ${RESET}"
  read -r choice
  case "${choice}" in
    1) do_install "latest" ;;
    2) do_update ;;
    3) do_uninstall ;;
    4) do_status ;;
    0) exit 0 ;;
    *) error "Invalid option." ;;
  esac
}

main() {
  local cmd="${1:-}"
  case "${cmd}" in
    install)   do_install "${2:-latest}" ;;
    update)    do_update ;;
    uninstall) do_uninstall ;;
    status)    do_status ;;
    "")        show_menu ;;
    *)
      error "Unknown command: ${cmd}"
      echo "Usage: $0 [install [tag]|update|uninstall|status]"
      exit 1
      ;;
  esac
}

main "$@"

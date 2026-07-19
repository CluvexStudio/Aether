#!/data/data/com.termux/files/usr/bin/bash
set -uo pipefail

readonly BIN_NAME="aether"
readonly PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
readonly APP_DIR="${AETHER_WEB_APP_DIR:-${PREFIX}/opt/aether-web}"
readonly DATA_DIR="${AETHER_WEB_DATA:-${HOME}/.config/aether-web}"
readonly SETTINGS_FILE="${DATA_DIR}/sources.conf"

if [[ -f "${SETTINGS_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${SETTINGS_FILE}"
fi

readonly REPO="${AETHER_RELEASE_REPO:-${AETHER_CORE_REPO:-noob-coder-clude/Aether}}"
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
    error "This script is designed for Termux."
    exit 1
  fi
}

check_dependencies() {
  local missing=()
  local deps=(curl tar grep sed sha256sum awk)

  for dep in "${deps[@]}"; do
    command -v "${dep}" >/dev/null 2>&1 || missing+=("${dep}")
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    info "Installing missing dependencies: ${missing[*]}"
    pkg update -y >/dev/null
    pkg install -y "${missing[@]}" || {
      error "Failed to install dependencies."
      exit 1
    }
  fi
}

detect_arch() {
  case "$(uname -m)" in
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv8l|arm) echo "armv7" ;;
    x86_64|amd64) echo "x86_64" ;;
    *)
      error "Unsupported architecture: $(uname -m)"
      exit 1
      ;;
  esac
}

fetch_release_json() {
  local tag="$1"
  local url
  if [[ "${tag}" == "latest" || -z "${tag}" ]]; then
    url="${API_BASE}/releases/latest"
  else
    url="${API_BASE}/releases/tags/${tag}"
  fi
  curl -fsSL -H "Accept: application/vnd.github+json" "${url}"
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

  local arch archive release_json tag_name asset_url checksum_url expected_sum actual_sum
  arch="$(detect_arch)"
  archive="aether-android-${arch}.tar.gz"

  info "Release source: ${REPO}"
  info "Detected architecture: ${arch}"
  release_json="$(fetch_release_json "${requested_tag}")" || {
    error "Failed to fetch release metadata from GitHub."
    exit 1
  }

  tag_name="$(echo "${release_json}" | extract_tag_name)"
  [[ -n "${tag_name}" ]] || {
    error "Could not resolve release tag."
    exit 1
  }

  asset_url="$(echo "${release_json}" | extract_asset_url "${archive}")"
  checksum_url="$(echo "${release_json}" | extract_asset_url "${archive}.sha256")"

  [[ -n "${asset_url}" ]] || {
    error "Asset ${archive} not found in release ${tag_name}."
    exit 1
  }

  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aether-web-install.XXXXXX")"
  local archive_path="${TMP_DIR}/${archive}"

  info "Downloading ${archive} (${tag_name})..."
  curl -fL --progress-bar -o "${archive_path}" "${asset_url}" || {
    error "Download failed."
    exit 1
  }

  if [[ -n "${checksum_url}" ]]; then
    info "Verifying checksum..."
    expected_sum="$(curl -fsSL "${checksum_url}" | awk '{print $1}')"
    actual_sum="$(sha256sum "${archive_path}" | awk '{print $1}')"
    [[ -n "${expected_sum}" && "${expected_sum}" == "${actual_sum}" ]] || {
      error "Checksum mismatch."
      exit 1
    }
    success "Checksum verified."
  else
    warn "No checksum file found. Skipping verification."
  fi

  tar -xzf "${archive_path}" -C "${TMP_DIR}"
  local binary_path="${TMP_DIR}/${BIN_NAME}"
  [[ -f "${binary_path}" ]] || binary_path="$(find "${TMP_DIR}" -maxdepth 3 -type f -name "${BIN_NAME}" | head -n1)"
  [[ -n "${binary_path}" && -f "${binary_path}" ]] || {
    error "Could not locate the aether binary inside the archive."
    exit 1
  }

  mkdir -p "${PREFIX}/bin" "${PREFIX}/etc"
  chmod +x "${binary_path}"
  cp -f "${binary_path}" "${INSTALL_PATH}"
  echo "${tag_name}" > "${VERSION_FILE}"

  success "Aether ${tag_name} installed at ${INSTALL_PATH}"
}

do_update() {
  do_install "latest"
}

do_uninstall() {
  rm -f "${INSTALL_PATH}" "${VERSION_FILE}"
  success "Aether removed from Termux."
}

do_status() {
  echo "Core release repo: ${REPO}"
  if [[ -f "${INSTALL_PATH}" ]]; then
    success "Installed: ${INSTALL_PATH}"
    [[ -f "${VERSION_FILE}" ]] && info "Version: $(cat "${VERSION_FILE}")"
    "${INSTALL_PATH}" --version 2>/dev/null || true
  else
    warn "Aether is not installed."
  fi
}

main() {
  local cmd="${1:-status}"
  case "${cmd}" in
    install) do_install "${2:-latest}" ;;
    update) do_update ;;
    uninstall) do_uninstall ;;
    status) do_status ;;
    *)
      error "Usage: $0 [install [tag]|update|uninstall|status]"
      exit 1
      ;;
  esac
}

main "$@"

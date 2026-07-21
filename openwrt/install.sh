#!/bin/sh
# install.sh — Install Aether on THIS OpenWrt device
#
# Usage (on the router):
#   cd /tmp/aether-openwrt   # or wherever you extracted the package
#   chmod +x install.sh
#   ./install.sh
#
# Optional:
#   ./install.sh --start     # install and start immediately
#   ./install.sh --force-config  # overwrite existing /etc/config/aether
#
# Expected package layout (same directory as this script):
#   install.sh
#   uninstall.sh
#   aether-openwrt-musl          # OR aether / aether-linux-x86_64
#   files/
#     etc/config/aether
#     etc/init.d/aether
#     usr/bin/aether-ctl
#     usr/libexec/rpcd/luci-app-aether
#     usr/share/rpcd/acl.d/luci-app-aether.json
#     usr/share/luci/menu.d/luci-app-aether.json
#     www/luci-static/resources/view/aether.js

set -e

START_NOW=0
FORCE_CONFIG=0
SKIP_CURL=0
for arg in "$@"; do
	case "$arg" in
		--start) START_NOW=1 ;;
		--force-config) FORCE_CONFIG=1 ;;
		--no-curl) SKIP_CURL=1 ;;
		-h|--help)
			echo "Usage: $0 [--start] [--force-config] [--no-curl]"
			exit 0
			;;
	esac
done

# Resolve script directory (works when run as ./install.sh)
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FILES_DIR="$SCRIPT_DIR/files"

# Find binary: prefer package name, then common aliases
BINARY=""
for cand in \
	"$SCRIPT_DIR/aether-openwrt-musl" \
	"$SCRIPT_DIR/aether" \
	"$SCRIPT_DIR/aether-linux-x86_64" \
	"$SCRIPT_DIR/bin/aether" \
	"$SCRIPT_DIR/bin/aether-openwrt-musl"
do
	if [ -f "$cand" ]; then
		BINARY="$cand"
		break
	fi
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

info()  { printf "%b[+]%b %s\n" "$GREEN" "$RESET" "$*"; }
warn()  { printf "%b[!]%b %s\n" "$YELLOW" "$RESET" "$*"; }
error() { printf "%b[-]%b %s\n" "$RED" "$RESET" "$*" >&2; }

die() { error "$*"; exit 1; }

need_root() {
	if [ "$(id -u)" -ne 0 ]; then
		die "Run as root on the OpenWrt device (e.g. ssh root@router, then ./install.sh)"
	fi
}

need_file() {
	[ -f "$1" ] || die "Missing required file: $1"
}

copy_file() {
	src="$1"
	dst="$2"
	mode="$3"
	need_file "$src"
	mkdir -p "$(dirname "$dst")"
	cp -f "$src" "$dst"
	if [ -n "$mode" ]; then
		chmod "$mode" "$dst"
	fi
	info "Installed $dst"
}

# --- preflight ---
need_root

[ -d "$FILES_DIR" ] || die "Missing files/ directory next to install.sh (got: $FILES_DIR)"
[ -n "$BINARY" ] || die "Missing Aether binary next to install.sh (expected aether-openwrt-musl or aether)"

# Basic OpenWrt sanity
[ -x /sbin/uci ] || die "This does not look like OpenWrt (/sbin/uci missing)"
[ -d /etc/init.d ] || die "This does not look like OpenWrt (/etc/init.d missing)"

ARCH=$(uname -m 2>/dev/null || echo unknown)
case "$ARCH" in
	x86_64|amd64) : ;;
	*)
		warn "Architecture is $ARCH — package binary is usually x86_64 musl."
		warn "Continuing anyway; if it fails with 'not found', rebuild for this arch."
		;;
esac

echo "========================================="
echo " Aether OpenWrt Installer (local)"
echo " Source: $SCRIPT_DIR"
echo " Arch:   $ARCH"
echo "========================================="
echo ""

# Stop previous instance so binary can be replaced
info "Stopping previous Aether (if any)..."
/etc/init.d/aether stop 2>/dev/null || true
killall aether 2>/dev/null || true
sleep 1

# Binary
copy_file "$BINARY" /usr/bin/aether 755
if ! /usr/bin/aether --version >/dev/null 2>&1; then
	error "Binary installed but will not run."
	error "Likely wrong libc/arch (need static musl build for this router)."
	/usr/bin/aether --version 2>&1 || true
	exit 1
fi
info "Binary OK: $(/usr/bin/aether --version 2>&1)"

# Config
if [ -f /etc/config/aether ] && [ "$FORCE_CONFIG" -eq 0 ]; then
	warn "Keeping existing /etc/config/aether (use --force-config to overwrite)"
else
	copy_file "$FILES_DIR/etc/config/aether" /etc/config/aether 644
fi

# Core files
copy_file "$FILES_DIR/etc/init.d/aether" /etc/init.d/aether 755
copy_file "$FILES_DIR/usr/bin/aether-ctl" /usr/bin/aether-ctl 755
copy_file "$FILES_DIR/usr/libexec/rpcd/luci-app-aether" /usr/libexec/rpcd/luci-app-aether 755
copy_file "$FILES_DIR/usr/share/rpcd/acl.d/luci-app-aether.json" /usr/share/rpcd/acl.d/luci-app-aether.json 644
copy_file "$FILES_DIR/usr/share/luci/menu.d/luci-app-aether.json" /usr/share/luci/menu.d/luci-app-aether.json 644
copy_file "$FILES_DIR/www/luci-static/resources/view/aether.js" /www/luci-static/resources/view/aether.js 644

# Install curl if not present (needed for connection tests)
if [ "$SKIP_CURL" -eq 0 ] && ! command -v curl >/dev/null 2>&1; then
	info "Installing curl (needed for connection tests)..."
	if command -v apk >/dev/null 2>&1; then
		apk add --no-cache curl 2>/dev/null || warn "Could not install curl (optional)"
	elif command -v opkg >/dev/null 2>&1; then
		opkg update >/dev/null 2>&1
		opkg install curl 2>/dev/null || warn "Could not install curl (optional)"
	fi
fi

# Identity storage
mkdir -p /etc/aether 2>/dev/null
chmod 700 /etc/aether 2>/dev/null || true

# Register init script (does not start unless UCI enabled / --start)
if [ -x /etc/init.d/aether ]; then
	/etc/init.d/aether enable 2>/dev/null || true
	info "Service registered (enabled on boot only if UCI enabled=1)"
fi

# Reload LuCI ACL / menu
if [ -x /etc/init.d/rpcd ]; then
	info "Restarting rpcd..."
	/etc/init.d/rpcd restart 2>/dev/null || true
fi

if [ "$START_NOW" -eq 1 ]; then
	info "Starting Aether..."
	if command -v aether-ctl >/dev/null 2>&1; then
		aether-ctl start || /etc/init.d/aether start
	else
		/etc/init.d/aether start
	fi
fi

echo ""
info "========================================="
info " Installation complete!"
info "========================================="
echo ""
echo "  CLI:     aether-ctl start | stop | status"
echo "  Service: /etc/init.d/aether start"
echo "  Config:  /etc/config/aether"
echo "  LuCI:    Services → Aether"
echo "           (hard-refresh browser: Ctrl+F5)"
echo ""
echo "Quick start:"
echo "  aether-ctl start"
echo "  aether-ctl status"
echo ""

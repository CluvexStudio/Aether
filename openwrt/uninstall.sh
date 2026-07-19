#!/bin/sh
# uninstall.sh — Remove Aether from THIS OpenWrt device
#
# Usage (on the router):
#   ./uninstall.sh
#   ./uninstall.sh --purge     # also remove config + identity data

set -e

PURGE=0
for arg in "$@"; do
	case "$arg" in
		--purge) PURGE=1 ;;
		-h|--help)
			echo "Usage: $0 [--purge]"
			exit 0
			;;
	esac
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

info()  { printf "%b[+]%b %s\n" "$GREEN" "$RESET" "$*"; }
warn()  { printf "%b[!]%b %s\n" "$YELLOW" "$RESET" "$*"; }
error() { printf "%b[-]%b %s\n" "$RED" "$RESET" "$*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
	error "Run as root on the OpenWrt device"
	exit 1
fi

echo "========================================="
echo " Aether OpenWrt Uninstaller (local)"
echo " Purge: $([ "$PURGE" -eq 1 ] && echo yes || echo no)"
echo "========================================="
echo ""

info "Stopping Aether..."
/etc/init.d/aether stop 2>/dev/null || true
killall aether 2>/dev/null || true
/etc/init.d/aether disable 2>/dev/null || true

info "Removing files..."
rm -f /usr/bin/aether
rm -f /usr/bin/aether-ctl
rm -f /etc/init.d/aether
rm -f /usr/libexec/rpcd/luci-app-aether
rm -f /usr/share/rpcd/acl.d/luci-app-aether.json
rm -f /usr/share/luci/menu.d/luci-app-aether.json
rm -f /www/luci-static/resources/view/aether.js
rm -f /www/luci-static/resources/aether.js 2>/dev/null || true

if [ "$PURGE" -eq 1 ]; then
	warn "Purging config and identity data..."
	rm -f /etc/config/aether
	rm -rf /etc/aether
	rm -f /etc/aether-masque /etc/aether-lastconn.toml /etc/aether-masque-lastconn.toml 2>/dev/null || true
	# sibling identity files if any
	rm -f /etc/aether*.toml /etc/aether* 2>/dev/null || true
fi

if [ -x /etc/init.d/rpcd ]; then
	info "Restarting rpcd..."
	/etc/init.d/rpcd restart 2>/dev/null || true
fi

echo ""
info "Aether removed from this device."
[ "$PURGE" -eq 1 ] && info "Config and identity data purged."
echo ""

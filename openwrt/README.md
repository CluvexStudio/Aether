# Aether for OpenWrt

An optional OpenWrt integration package for [Aether](https://github.com/CluvexStudio/Aether).
This directory provides everything needed to run Aether on an OpenWrt router — it does **not** modify the existing Aether source code.

Tested on **OpenWrt 25.12.5** (x86_64, musl).

Features:

- Static musl binary (glibc binaries won't run on OpenWrt)
- procd service integration (auto-start on boot)
- CLI: `aether-ctl`
- LuCI: **Services → Aether** (status + Start/Stop + settings)

## Install (on the router)

1. Copy/download this whole package folder to the router (USB, scp, wget, etc.).
2. SSH into the router and install:

```sh
cd /path/to/aether-openwrt   # folder that contains install.sh + files/ + binary
chmod +x install.sh uninstall.sh
./install.sh
```

Optional:

```sh
./install.sh --start          # install and start now
./install.sh --force-config   # overwrite existing /etc/config/aether
```

3. Use:

```sh
aether-ctl start
aether-ctl status
```

LuCI: open the router web UI → **Services → Aether**  
Hard-refresh the browser once (`Ctrl+F5`).

## Package contents

```text
aether-openwrt/
  install.sh                 # run ON the router
  uninstall.sh
  aether-openwrt-musl        # static binary (or name it "aether")
  README.md
  BUILD-MUSL.md
  build-musl.sh
  CLEAN-TEST.md
  musl-compat/musl_compat.c
  files/
    etc/config/aether
    etc/init.d/aether
    usr/bin/aether-ctl
    usr/libexec/rpcd/luci-app-aether
    usr/share/rpcd/acl.d/luci-app-aether.json
    usr/share/luci/menu.d/luci-app-aether.json
    www/luci-static/resources/view/aether.js
```

The binary may be named any of:
- `aether-openwrt-musl` (preferred)
- `aether`
- `aether-linux-x86_64`

## Uninstall

On the router:

```sh
./uninstall.sh
./uninstall.sh --purge   # also remove config + identity
```

## CLI

```sh
aether-ctl start|stop|restart|status|show|version
aether-ctl set protocol masque
aether-ctl set scan_mode turbo
aether-ctl set obfuscation_profile firewall
aether-ctl set http2_mode 1
aether-ctl set enabled 1
```

## How to get the package onto the router

Examples:

```sh
# From your PC (if scp/sftp works):
scp -r openwrt root@router_ip:/tmp/aether-openwrt

# Or tar + pipe (works without sftp-server):
tar czf - -C openwrt . | ssh root@router_ip "mkdir -p /tmp/aether-openwrt && tar xzf - -C /tmp/aether-openwrt"

# Then on router:
ssh root@router_ip
cd /tmp/aether-openwrt
chmod +x install.sh
./install.sh --start
```

## Build the musl binary (developer)

On a Linux/WSL host (not required on the router):

```sh
./build-musl.sh
# place result as ./aether-openwrt-musl in this package
```

See `BUILD-MUSL.md`.

## Notes

- OpenWrt uses **musl**. Glibc release binaries will not run.
- Installer must be run **as root on the router**.
- LuCI status/control uses built-in `service` / `rc` / `uci` / `file` RPCs.
- `enabled` in UCI = start on boot; LuCI Start/Stop = manual control.

## License

Same as Aether (AGPL-3.0) unless noted otherwise.

# Aether for OpenWrt

An optional OpenWrt integration package for [Aether](https://github.com/CluvexStudio/Aether).

This adds everything needed to run Aether on an OpenWrt router. It does **not** modify the existing Aether source code. Tested on OpenWrt 25.12.5 (x86_64 and armv7, musl).

Works with both:
- **x86_64 musl** — `aether-linux-x86_64-musl.tar.gz` (from CI or Releases)
- **armv7 musl** — `aether-linux-armv7-musl.tar.gz` (from CI or Releases)

Features:

- Static musl binary (glibc binaries won't run on OpenWrt)
- procd service integration (auto-start on boot)
- CLI: `aether-ctl`
- LuCI web interface: **Services → Aether**

## Install on the router

1. Download the binary from the [latest release](../../releases) — look for `aether-linux-x86_64-musl.tar.gz`. Extract it and place the `aether` file in this `openwrt/` directory.

2. Copy the whole `openwrt/` folder to the router:

```sh
scp -r openwrt root@192.168.1.1:/tmp/aether
```

3. SSH into the router and run the installer:

```sh
ssh root@192.168.1.1
cd /tmp/aether
chmod +x install.sh
./install.sh --start
```

4. Verify it's running:

```sh
aether-ctl status
```

5. Open the router web UI → **Services → Aether** (hard-refresh browser once with `Ctrl+F5`).

Optional:

```sh
./install.sh --start          # install and start now
./install.sh --force-config   # overwrite existing /etc/config/aether
./install.sh --no-curl        # skip curl installation (needed for connection tests)
```

## Uninstall

```sh
./uninstall.sh           # remove files
./uninstall.sh --purge   # also remove config and identity data
```

## CLI commands

```sh
aether-ctl start
aether-ctl stop
aether-ctl restart
aether-ctl status
aether-ctl show
aether-ctl version
aether-ctl set protocol masque
aether-ctl set scan_mode turbo
aether-ctl set obfuscation_profile firewall
aether-ctl set enabled 1
```

## Build the binary locally (optional)

The CI builds the binary automatically. If you want to build it yourself:

```sh
# On a Linux host (not on the router)
cd openwrt/
./build-musl.sh
```

See `BUILD-MUSL.md` for full prerequisites and details.

## Package contents

```text
openwrt/
  install.sh              # installer (runs on the router)
  uninstall.sh
  release.yml             # CI workflow
  build-musl.sh           # local build script
  musl-compat/
    musl_compat.c         # fopen64 shim (for manual builds)
  files/
    etc/config/aether           # UCI config
    etc/init.d/aether           # procd service
    usr/bin/aether-ctl          # CLI tool
    usr/libexec/rpcd/luci-app-aether
    usr/share/rpcd/acl.d/luci-app-aether.json
    usr/share/luci/menu.d/luci-app-aether.json
    www/luci-static/resources/view/aether.js
```

## Notes

- OpenWrt uses **musl**. Glibc release binaries will not run.
- Installer must be run **as root on the router**.
- `curl` is auto-installed for connection tests. Use `--no-curl` to skip.
- LuCI status/control uses built-in `service` / `rc` / `uci` / `file` RPCs.
- `enabled` in UCI = start on boot; LuCI Start/Stop = manual control.

## License

Same as Aether (AGPL-3.0).

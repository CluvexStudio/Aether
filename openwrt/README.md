# Aether for OpenWrt

An optional OpenWrt integration package for [Aether](https://github.com/CluvexStudio/Aether).
This directory provides everything needed to run Aether on an OpenWrt router — it does **not** modify the existing Aether source code.

Tested on **OpenWrt 25.12.5** (x86_64, musl).

Features:

- Static musl binary (glibc binaries won't run on OpenWrt)
- procd service integration (auto-start on boot)
- CLI: `aether-ctl`
- LuCI: **Services → Aether** (status + Start/Stop + settings)

## How the binary is built

The OpenWrt binary is **not** shipped in this directory. It is built from source by CI (GitHub Actions) every time the release workflow runs. The `linux-openwrt` job in `release.yml`:

1. Checks out the Aether source
2. Installs the AmanoTeam/musl-gcc-cross toolchain
3. Cross-compiles Aether with `cargo build --release --target x86_64-unknown-linux-musl`
4. Uploads `aether-linux-x86_64-musl.tar.gz` as a build artifact

The build uses the same musl cross-compilation approach as the existing `linux-armv7-musl` job, with bindgen sysroot configuration and modern musl time_t support.

See `release.yml` (the `linux-openwrt` job) for the full CI workflow, or `BUILD-MUSL.md` for the manual build steps.

## Getting the binary

### Option A: Download from CI (recommended)

1. Go to the [Actions](../../actions) tab
2. Click the latest workflow run
3. Download `aether-linux-x86_64-musl.tar.gz` from the artifacts
4. Extract it:

```sh
tar xzf aether-linux-x86_64-musl.tar.gz
# The extracted "aether" binary goes into this openwrt/ directory
cp aether ./aether-openwrt-musl
```

### Option B: Build locally

On a Linux/WSL host (not on the router):

```sh
cd openwrt/
./build-musl.sh
# Binary is placed as ./aether-openwrt-musl
```

See `BUILD-MUSL.md` for full prerequisites and details.

## Install (on the router)

1. Place this package folder (with the binary) on the router (USB, scp, wget, etc.)
2. SSH into the router and install:

```sh
cd /path/to/openwrt   # folder that contains install.sh + files/ + binary
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
openwrt/
  release.yml             # CI workflow (musl cross-compile job)
  install.sh              # run ON the router
  uninstall.sh
  build-musl.sh           # local build script (alternative to CI)
  musl-compat/
    musl_compat.c         # fopen64 shim source (for manual builds)
  README.md
  BUILD-MUSL.md           # detailed build guide
  CLEAN-TEST.md           # quick retest guide
  files/
    etc/config/aether
    etc/init.d/aether
    usr/bin/aether-ctl
    usr/libexec/rpcd/luci-app-aether
    usr/share/rpcd/acl.d/luci-app-aether.json
    usr/share/luci/menu.d/luci-app-aether.json
    www/luci-static/resources/view/aether.js
```

The binary (built by CI or locally) should be placed alongside `install.sh` as:
- `aether-openwrt-musl` (preferred), or
- `aether`

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

## Notes

- OpenWrt uses **musl**. Glibc release binaries will not run.
- Installer must be run **as root on the router**.
- LuCI status/control uses built-in `service` / `rc` / `uci` / `file` RPCs.
- `enabled` in UCI = start on boot; LuCI Start/Stop = manual control.

## License

Same as Aether (AGPL-3.0) unless noted otherwise.

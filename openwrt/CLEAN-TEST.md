# Clean OpenWrt retest (install ON the router)

## Prerequisites

The CI-built binary must be in this directory as `aether-openwrt-musl`
(or `aether`). Download from Actions artifacts or build locally with
`./build-musl.sh`.

## User package flow

1. Place the binary (`aether-openwrt-musl`) in this directory alongside `install.sh`.
2. Transfer the whole package to the router.
3. On the router:

```sh
cd /tmp/aether-openwrt
chmod +x install.sh uninstall.sh
./install.sh --start
```

4. Use:

```sh
aether-ctl status
```

LuCI: `http://<router-ip>` → **Services → Aether** (hard refresh once).

## From your PC: put package on router

```bash
# transfer without sftp-server:
scp -r openwrt root@router_ip:/tmp/aether-openwrt

# Then on router:
ssh root@router_ip
cd /tmp/aether-openwrt
chmod +x install.sh
./install.sh --start
```

## Verify checklist

```sh
aether-ctl version
aether-ctl status
logread -e aether | tail -20
```

SOCKS from LAN:

```bash
curl -x socks5h://router_ip:1819 https://www.cloudflare.com/cdn-cgi/trace
```

Uninstall:

```sh
./uninstall.sh --purge
```

## Package must contain

- `install.sh` (local installer)
- `uninstall.sh`
- `aether-openwrt-musl` or `aether` (static musl binary)
- `files/**` (system files)

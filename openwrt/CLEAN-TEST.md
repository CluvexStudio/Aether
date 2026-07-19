# Clean OpenWrt retest (install ON the router)

## User package flow

1. Download / copy the package folder (or the `.tar.gz`) onto the router.
2. On the router:

```sh
cd /tmp
tar xzf aether-openwrt-1.2.0-x86_64.tar.gz
cd aether-openwrt-1.2.0-x86_64
chmod +x install.sh uninstall.sh
./install.sh --start
```

3. Use:

```sh
aether-ctl status
```

LuCI: `http://<router-ip>` → **Services → Aether** (hard refresh once).

## From your PC: put package on router

```bash
# create archive (optional; already available after pack.sh)
cd openwrt
bash ./pack.sh .

# transfer without sftp-server:
cat aether-openwrt-1.2.0-x86_64.tar.gz | ssh root@router_ip "cat > /tmp/aether-openwrt-1.2.0-x86_64.tar.gz"
ssh root@router_ip "cd /tmp && tar xzf aether-openwrt-1.2.0-x86_64.tar.gz && cd aether-openwrt-1.2.0-x86_64 && chmod +x install.sh && ./install.sh --start"
```

Or copy the whole `openwrt/` folder and run `./install.sh` inside it on the router.

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

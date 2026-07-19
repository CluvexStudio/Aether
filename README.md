# Aether

### اینترنت آزاد برای همه :))
**[راهنمای فارسی](README.fa.md)** · **[English Guide](Docs/GUIDE.en.md)** · **[راهنمای کامل فارسی](Docs/GUIDE.fa.md)**

Telegram: https://t.me/CluvexStudio

Aether is a censorship circumvention client designed for heavily restricted networks. It automatically discovers reachable routes, establishes an encrypted tunnel, and exposes a local SOCKS5 proxy for your applications.

Unlike traditional VPN clients, Aether is built for environments where Deep Packet Inspection (DPI), protocol fingerprinting, UDP throttling, and endpoint blocking are common.

## Features

- Automatic endpoint discovery, with end-to-end data-plane validation so a gateway is only trusted once it actually passes traffic, not just once it answers the handshake
- MASQUE (HTTP/3 & HTTP/2), with optional TLS ClientHello fragmentation on HTTP/2
- WireGuard support
- Nested WireGuard mode (`gool`)
- Traffic obfuscation
- Automatic reconnection, and quick-reconnect to your last known-good gateway to skip rescanning
- Local SOCKS5 proxy
- Command-line flags, environment variables, or interactive prompts — your choice
- Linux, Windows, macOS, Android (Termux), and OpenWrt routers

## Download

Prebuilt binaries are available on the Releases page for:

- Linux (x86_64, ARM64, ARMv7)
- Linux musl (ARMv7 — static, for OpenWrt/Alpine)
- Windows
- macOS
- Android (Termux)

### Termux (Android) — one-line install

```bash
curl -fsSL https://raw.githubusercontent.com/CluvexStudio/aether/main/aether.sh -o aether.sh && chmod +x aether.sh && ./aether.sh install
```

This detects your device architecture, downloads the matching release, verifies its checksum, and installs `aether` into `$PREFIX/bin`. Run it afterwards with:

```bash
aether
```

To update later, run `./aether.sh update`. To remove it, run `./aether.sh uninstall`.

### OpenWrt — install and run as a service

Download the statically-linked musl binary from [Releases](https://github.com/CluvexStudio/Aether/releases) (`aether-linux-armv7-musl.tar.gz` for ARMv7 routers like Google Wifi / IPQ4019):

```bash
# On the router (SSH in first: ssh root@192.168.1.1)
cd /tmp
wget https://github.com/CluvexStudio/Aether/releases/latest/download/aether-linux-armv7-musl.tar.gz
tar xzf aether-linux-armv7-musl.tar.gz
mv aether /usr/bin/aether
chmod +x /usr/bin/aether
```

Create a procd init script so it starts automatically and restarts on crash:

```bash
cat > /etc/init.d/aether << 'INITEOF'
#!/bin/sh /etc/rc.common

START=91
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/aether --masque --scan balanced --noize firewall --bind 0.0.0.0:1819 --quick-reconnect -4
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param respawn 3600 5 0
    procd_close_instance
}
INITEOF

chmod 755 /etc/init.d/aether
service aether enable
service aether start
```

The proxy will be available at `<router-ip>:1819` for all devices on your network. See [Docs/GUIDE.en.md](Docs/GUIDE.en.md#openwrt) for the full guide including firewall rules, LAN proxy setup, and troubleshooting.

## Build

### Requirements

- Rust (latest stable)
- C/C++ compiler
- CMake

The `quiche` repository must be placed alongside `aether`:

```text
<repo>/
  aether/
  quiche/
```

Build:

```bash
cargo build --release
```

Binary:

```text
target/release/aether
```

## Docker

You can run Aether in an isolated environment using Docker. The official image is available on GitHub Container Registry (GHCR).

Pull and run the pre-built image (interactive mode is required for initial setup):

```bash
docker run -it -p 1819:1819 ghcr.io/cluvexstudio/aether:latest
```

You can also bypass prompts by providing environment variables:

```bash
docker run -it -p 1819:1819 \
  -e AETHER_PROTOCOL=masque \
  -e AETHER_SCAN=balanced \
  ghcr.io/cluvexstudio/aether:latest
```

If you prefer to build the image manually from source:

```bash
docker build -t aether .
docker run -it -p 1819:1819 aether
```

## Usage

Run with no arguments and answer the prompts:

```bash
./target/release/aether
```

Or skip the prompts with flags:

```bash
./target/release/aether --masque -4 --scan turbo --noize firewall
```

On Windows, double-click `run-aether.bat` (included in the release zip) instead — it opens a terminal, runs `aether.exe`, and keeps the window open afterwards so you can read any errors.

Every prompt has a flag and an environment variable equivalent. Run `./target/release/aether --help` for the full list, or see the guides linked below.

After startup, a SOCKS5 proxy will be available at:

```
127.0.0.1:1819
```

Example:

```bash
curl -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace
```

## Supported Protocols

### MASQUE (Recommended)

Encapsulates traffic over HTTP/3 (QUIC) or HTTP/2 (TLS), making it resemble ordinary HTTPS traffic.

### WireGuard

Fast and lightweight transport for networks with less aggressive inspection.

### Nested WireGuard (`gool`)

A WireGuard tunnel running inside another WireGuard tunnel, providing an additional encryption layer.

## Documentation

Detailed documentation is available in:

- [Docs/GUIDE.en.md](Docs/GUIDE.en.md) — English guide
- [Docs/GUIDE.fa.md](Docs/GUIDE.fa.md) — راهنمای فارسی

## Credits

Developed by **CluvexStudio**. :))

MASQUE support is built on top of Cloudflare's **Quiche** library.


## Contributing

> **Experienced network developers and protocol engineers are welcome to contribute.**

> **Please keep the codebase clean, maintainable, and well-engineered. Low-quality or vibe-coded contributions will not be accepted.**

## Donate

If Aether has been useful to you, consider supporting its development:

- **TRX (Tron):** `TRxVSHcoADZnBfztFmFb2TQopusAwWYEVR`
- **BTC:** `bc1qnjnvzsa5avgj7n0uy383cv5zdxfjnvvp257egm`
- **TON:** `UQAH75bXaaRUhZMwiF0ZujOXFDDmvLSPASKoOsWF0HNasiaM`

## License

See the LICENSE file for licensing information.

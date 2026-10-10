# Aether

![Aether](Docs/Aether.png)

### اینترنت آزاد برای همه:))
**[راهنمای فارسی](README.fa.md)** · **[English Guide](Docs/DOCS.en.md)** · **[راهنمای کامل فارسی](Docs/DOCS.fa.md)**

Telegram: https://t.me/CluvexStudio

Aether is a censorship circumvention client designed for heavily restricted networks. It automatically discovers reachable routes, establishes an encrypted tunnel, and exposes a local SOCKS5 proxy for your applications.

Unlike traditional VPN clients, Aether is built for environments where Deep Packet Inspection (DPI), protocol fingerprinting, UDP throttling, and endpoint blocking are common.

## Features

- Automatic endpoint discovery, with end-to-end data-plane validation so a gateway is only trusted once it actually passes traffic, not just once it answers the handshake
- MASQUE (HTTP/3 & HTTP/2), with optional TLS ClientHello fragmentation on HTTP/2
- WireGuard support
- WireGuard over MASQUE (`--gool`), a WireGuard tunnel inside a MASQUE one for a different exit address
- Nested WireGuard mode (`--gool-classic`), with both hops discovered by the scan or given by hand
- Nested MASQUE mode (`--mim`), a masque tunnel inside another one for a different exit address
- Traffic obfuscation
- Routing rules by domain, address, or port, matched from the TLS server name so they keep working behind a tun front end
- Upstream proxy support, so Aether can dial out through another VPN or proxy already running on the machine
- Optional Tor exit (`--tor`), with Tor carried inside the tunnel, so the exit address is a Tor exit
- Automatic reconnection, and quick-reconnect to your last known-good gateway to skip rescanning
- Local SOCKS5 proxy
- Command-line flags, environment variables, or interactive prompts — your choice
- Linux, Windows, macOS and Android (Termux)

## Download

Prebuilt binaries are on the [Releases](https://github.com/CluvexStudio/Aether/releases/latest) page. Pick the archive that matches your system:

| System | Archive |
| --- | --- |
| Windows x86_64 | `aether-windows-x86_64.zip` |
| macOS on Apple Silicon (M1 and later) | `aether-macos-arm64.tar.gz` |
| macOS on Intel | `aether-macos-x86_64.tar.gz` |
| Linux x86_64 / arm64 / armv7 (glibc 2.34 or newer) | `aether-linux-x86_64.tar.gz`, `aether-linux-arm64.tar.gz`, `aether-linux-armv7.tar.gz` |
| Linux with musl or an older glibc, fully static | `aether-linux-x86_64-musl.tar.gz`, `aether-linux-aarch64-musl.tar.gz`, `aether-linux-armv7-musl.tar.gz` |
| OpenWrt routers | the `-musl` archive for the router's CPU, see [OpenWrt](#openwrt) |
| Android (Termux) | the installer below |

Every archive has a matching `.sha256` file, and `SHA256SUMS.txt` lists them all. On a Mac, `uname -m` prints `arm64` or `x86_64`. The macOS binaries are not notarized, so clear the download quarantine once after extracting:

```bash
tar -xzf aether-macos-x86_64.tar.gz
xattr -d com.apple.quarantine aether
./aether
```

### Termux (Android) — one-line install

```bash
curl -fsSL https://raw.githubusercontent.com/CluvexStudio/aether/main/aether.sh -o aether.sh && chmod +x aether.sh && ./aether.sh install
```

This detects your device architecture, downloads the matching release, verifies its checksum, and installs `aether` into `$PREFIX/bin`. Run it afterwards with:

```bash
aether
```

To update later, run `./aether.sh update`. To remove it, run `./aether.sh uninstall`.

### OpenWrt

Aether runs on OpenWrt as a single static binary of 7 to 10 MB. Choose the archive by the output of `uname -m`:

| `uname -m` | Typical routers | Archive |
| --- | --- | --- |
| `aarch64` | MediaTek MT7981/MT7986 (e.g. Xiaomi AX3000T), Qualcomm IPQ807x, Raspberry Pi 4/5 | `aether-linux-aarch64-musl.tar.gz` |
| `armv7l` | Qualcomm IPQ40xx (e.g. Google Wifi), MediaTek MT7623, other Cortex-A7/A9/A15 boards | `aether-linux-armv7-musl.tar.gz` |
| `x86_64` | x86 mini PCs and VMs | `aether-linux-x86_64-musl.tar.gz` |

MIPS routers (`mips`/`mipsel`, e.g. MT7621) are not supported.

```sh
cd /tmp
A=aether-linux-aarch64-musl.tar.gz
wget https://github.com/CluvexStudio/Aether/releases/latest/download/$A
wget https://github.com/CluvexStudio/Aether/releases/latest/download/$A.sha256
sha256sum -c $A.sha256 && tar -xzf $A && mv aether /usr/bin/aether
mkdir -p /etc/aether
aether --config /etc/aether/aether.toml
```

Keep `--config` on persistent storage such as `/etc/aether`: `/tmp` is wiped at every reboot, and a lost identity means a new device registration on each boot, which Cloudflare rate limits. To share the proxy with your LAN, bind it to the router's LAN address, for example `--bind 192.168.1.1:1819`; it has no authentication, so never expose it on the WAN. If `wget` reports an SSL error, run `opkg update && opkg install ca-bundle`, or copy the file over with `scp`.

If the router also sends its own traffic into a tun front end (hev-socks5-tunnel, tun2socks), start Aether with `--mark 0xff` so every socket it opens to the internet carries that firewall mark, and let marked packets bypass the tun, for example with `ip rule add fwmark 0xff lookup main priority 100`. Setting a mark needs root.

## Build

### Requirements

- Rust 1.98 or newer
- C/C++ compiler
- CMake

The `quiche` repository must be placed alongside `aether`:

```text
<repo>/
  aether/
  quiche/
```

Build from the repository root; the Cargo manifest is `aether/Cargo.toml`, so enter that directory first:

```bash
cd aether
cargo build --release
```

Binary, relative to the repository root:

```text
aether/target/release/aether
```

## Docker

You can run Aether in an isolated environment using Docker. The official image is available on GitHub Container Registry (GHCR).

> **The SOCKS5 proxy has no authentication.** Anyone who can reach the port can use your tunnel. Every command below publishes the port to `127.0.0.1` only, so it stays reachable from your own machine and nothing else. Do not replace it with `-p 1819:1819`, because that form listens on every interface of the host and turns the proxy into an open relay. If you genuinely need to serve other machines, put an authenticated front end in front of it and firewall the port.

The `-v aether-data:/data` volume keeps the generated WARP identity between runs. Without it every start registers a brand new device, and Cloudflare begins rate limiting your address.

Pull and run the pre-built image (interactive mode is required for initial setup):

```bash
docker run -it -p 127.0.0.1:1819:1819 -v aether-data:/data ghcr.io/cluvexstudio/aether:latest
```

You can also bypass prompts by providing environment variables:

```bash
docker run -it -p 127.0.0.1:1819:1819 -v aether-data:/data \
  -e AETHER_PROTOCOL=masque \
  -e AETHER_SCAN=balanced \
  ghcr.io/cluvexstudio/aether:latest
```

If you prefer to build the image manually from source:

```bash
docker build -t aether .
docker run -it -p 127.0.0.1:1819:1819 -v aether-data:/data aether
```

## Usage

The examples below use the binary you built, run from inside `aether/`. With a release download, run `./aether` (or `aether.exe` on Windows) from the folder you extracted it to instead.

Run with no arguments and answer the prompts:

```bash
./target/release/aether
```

Or skip the prompts with flags:

```bash
./target/release/aether --masque -4 --scan turbo --noize firewall
```

On Windows, double-click `run-aether.bat` (included in the release zip) instead — it opens a terminal, runs `aether.exe`, and keeps the window open afterwards so you can read any errors.

Every prompt has a flag and an environment variable equivalent. Run `aether help` (or `--help`) for the full list — every flag, every variable, and what each one does — or see the guides linked below.

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

### Nested MASQUE (`--mim`)

A MASQUE tunnel carried inside another MASQUE tunnel. The inner hop is dialled from inside the outer one, so Cloudflare sees the outer edge instead of your address and hands the inner tunnel a different exit IP — the same idea as `gool`, with a MASQUE tunnel inside instead of a WireGuard one. Both hops use HTTP/3, or both use HTTP/2 with `--h2`.

```bash
./target/release/aether --mim
```

### WireGuard over MASQUE (`--gool`)

A WireGuard tunnel carried inside a MASQUE tunnel. Your network sees only the MASQUE hop; the WireGuard hop is dialled from inside it, so Cloudflare sees the MASQUE edge instead of your address and hands the WireGuard tunnel a different exit IP. The MASQUE hop is found by the scan or named with `--peer`; the WireGuard hop is the endpoint its key names, on port 2408, unless `--gool-peer` names another.

```bash
./target/release/aether --gool
```

### Nested WireGuard (`--gool-classic`)

The older gool: a WireGuard tunnel running inside another WireGuard tunnel, providing an additional encryption layer.

Its two hops are found by the scan by default. If you already know addresses that work on your network, name them instead with `--wiw-outer 162.159.192.1:2408 --wiw-inner 188.114.96.1:2408`, or both at once with `--wiw-peers 162.159.192.1:2408,188.114.96.1:2408`. The port is required — which port gets through is what differs between networks, so none is assumed. Give only one and the scan finds the other.

## Tor

Built with the `tor` feature, Aether carries a Tor implementation (arti) and can combine it with the tunnel three ways:

| Mode | Flag | Path | Exit address |
| --- | --- | --- | --- |
| Tor through the tunnel | `--tor` | you → WARP → Tor → internet | a Tor exit |
| The tunnel through Tor | `--tor-reverse` | you → Tor → WARP → internet | a WARP exit |
| Tor alone | `--tor-only` | you → Tor → internet | a Tor exit |

```bash
cd aether
cargo build --release --features tor
./target/release/aether --masque --tor
```

With `--tor` the usual proxy on `127.0.0.1:1819` keeps the WARP exit and a second one on `127.0.0.1:1820` comes out of Tor. Because Tor rides inside the tunnel, a network that blocks Tor never sees it. Any transport can carry it — `--masque` over HTTP/3 or HTTP/2, `--wg`, `--gool`, `--mim` — with nothing in between: `--wg --tor` has the WireGuard tunnel carry Tor directly. The other direction cannot do that, because Tor carries TCP only and WARP's WireGuard endpoints answer on UDP alone, so `--tor-reverse` runs MASQUE over HTTP/2 (for `--gool`, its MASQUE hop) and refuses `--wg` and `--gool-classic`. `--tor-reverse` and `--tor-only` reach Tor directly, and where Tor is blocked they fetch their own bridges from bridgedb and run them through the pluggable transports shipped in the `pt/` folder beside the binary, so there is nothing to install and nothing to paste in. See [Docs/DOCS.en.md](Docs/DOCS.en.md#tor).

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

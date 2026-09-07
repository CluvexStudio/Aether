# Aether

[![GitHub release](https://img.shields.io/github/v/release/CluvexStudio/Aether)](https://github.com/CluvexStudio/Aether/releases)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos%20%7C%20android-lightgrey)](https://github.com/CluvexStudio/Aether/releases)
[![Rust](https://img.shields.io/badge/rust-1.91%2B-orange)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-AGPL--3.0--only-blue)](LICENSE)

![Aether](Docs/Aether.png)

### اینترنت آزاد برای همه :))

**[راهنمای فارسی](README.fa.md)** · **[English guide](Docs/GUIDE.en.md)** · **[راهنمای کامل فارسی](Docs/GUIDE.fa.md)** · **[Reference (EN)](Docs/DOCS.en.md)** · **[مرجع کامل (FA)](Docs/DOCS.fa.md)**

Telegram: https://t.me/CluvexStudio

Aether is a censorship-circumvention client built for heavily restricted networks. It automatically discovers reachable routes, proves each one with real end-to-end traffic before trusting it, then serves the tunnel as a local SOCKS5 proxy for your applications.

Unlike traditional VPN clients, Aether assumes Deep Packet Inspection, protocol fingerprinting, UDP throttling, and endpoint blocking — and keeps working through them.

## Contents

- [Features](#features)
- [Quickstart](#quickstart)
- [Scan modes](#scan-modes)
- [Protocols](#protocols)
- [Configuration](#configuration)
- [Install](#install)
- [Build from source](#build-from-source)
- [Docker](#docker)
- [Testing](#testing)
- [Documentation](#documentation)
- [Security notes](#security-notes)
- [Contributing](#contributing)
- [Donate](#donate)
- [License](#license)
- [Credits](#credits)

## Features

- **Validated scanning** — a gateway is trusted only after it carries real traffic, never just for answering a handshake; recent winners are remembered so reconnects usually skip the scan entirely
- **MASQUE** over HTTP/3 (QUIC) and HTTP/2 (TCP), with optional TLS ClientHello fragmentation on the HTTP/2 transport
- **WireGuard**, plus nested WireGuard (`gool`, warp-in-warp) with both hops discovered or hand-picked
- **Traffic obfuscation** profiles (`off` → `aggressive`) tuned per transport
- **Routing rules** by domain, address, or port, matched from the TLS server name so they keep working behind a tun front end
- **Upstream proxy support** — dial out through another VPN or proxy already running on the machine
- **Automatic reconnection** with quick-reconnect to the last known-good gateway
- **Local SOCKS5 proxy**, no authentication, bound to loopback by default
- Flags, environment variables, or interactive prompts — every prompt has both
- Linux, Windows, macOS, Android (Termux)

## Quickstart

Answer the prompts:

```bash
./aether
```

Or skip them:

```bash
./aether --masque -4 --scan turbo --noize firewall
```

On Windows, double-click `run-aether.bat` from the release zip instead — it keeps the window open so you can read any errors.

Verify the tunnel (expect `warp=on`):

```bash
curl -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace
```

Run `aether help` for the full reference — every flag, every variable, what each one does.

## Scan modes

| Mode | Behavior | Reach for it when… |
|---|---|---|
| `turbo` | First responder wins | You want the fastest connect |
| `balanced` *(default)* | Collects a few, keeps the fastest | Everyday use |
| `thorough` | Sweeps whole subnets | Nothing else finds a route |
| `stealth` | Minimal in-flight probes | The network notices scanning |
| `ironclad` | A real HTTP request per candidate | You need maximum certainty |

Related knobs: `--peer` / `--wiw-outer` / `--wiw-inner` pin endpoints and skip scanning; `--no-quick-reconnect` forces a fresh sweep; `AETHER_PROBE_JITTER_MS` smooths probe bursts on hostile networks.

## Protocols

### MASQUE (recommended)

Traffic encapsulated over HTTP/3 (QUIC) or HTTP/2 (TLS) — it looks like ordinary HTTPS.

### WireGuard

Fast, lightweight transport for networks with less aggressive inspection.

### Nested WireGuard (`gool`)

A WireGuard tunnel inside another WireGuard tunnel — an extra encryption layer. Both hops are found by the scan by default; if you already know addresses that work, name them:

```bash
./aether --gool --wiw-outer 162.159.192.1:2408 --wiw-inner 188.114.96.1:2408
```

The port is required — which port gets through is exactly what differs between networks, so none is assumed. Name one hop and the scan finds the other.

## Configuration

Three equivalent ways, pick one per setting: interactive prompt, `--flag`, or `AETHER_*` environment variable. Examples:

```bash
export AETHER_PROTOCOL=masque AETHER_SCAN=balanced AETHER_NOIZE=firewall
./aether
```

The proxy listens on `--bind` (`127.0.0.1:1819` by default). Identities live next to the config files (`aether.toml`, plus `-wg` / `-masque` variants) — back them up; re-registering too often gets rate-limited.

## Install

Prebuilt binaries on the [Releases](https://github.com/CluvexStudio/Aether/releases) page for Linux, Windows, macOS, and Android (Termux).

### Termux — one line

```bash
curl -fsSL https://raw.githubusercontent.com/CluvexStudio/Aether/main/aether.sh -o aether.sh && chmod +x aether.sh && ./aether.sh install
```

Afterwards just run `aether`. Update with `./aether.sh update`, remove with `./aether.sh uninstall`.

## Build from source

Requirements: Rust 1.91+, a C/C++ compiler, CMake — plus the `quiche` checkout placed alongside `aether`:

```text
<repo>/
  aether/
  quiche/
```

```bash
cargo build --release
# binary: aether/target/release/aether
```

## Docker

> **The SOCKS5 proxy has no authentication.** Every command below publishes the port to `127.0.0.1` only. Never use `-p 1819:1819` (all interfaces = open relay). To serve other machines, put an authenticated front end in front and firewall the port.

The `-v aether-data:/data` volume keeps the generated WARP identity between runs — without it every start registers a new device and Cloudflare rate-limits your address.

```bash
docker run -it -p 127.0.0.1:1819:1819 -v aether-data:/data ghcr.io/cluvexstudio/aether:latest
```

Headless with environment variables:

```bash
docker run -it -p 127.0.0.1:1819:1819 -v aether-data:/data \
  -e AETHER_PROTOCOL=masque \
  -e AETHER_SCAN=balanced \
  ghcr.io/cluvexstudio/aether:latest
```

Or build it yourself:

```bash
docker build -t aether .
docker run -it -p 127.0.0.1:1819:1819 -v aether-data:/data aether
```

## Testing

```bash
cargo test
```

Unit tests run offline. A few live network probes exist for characterizing new networks but stay `#[ignore]`d by default — run one explicitly only when you mean to touch the wire:

```bash
cargo test -- --ignored report_which_masque_ranges_answer_on_this_network
```

## Documentation

- [Docs/GUIDE.en.md](Docs/GUIDE.en.md) — complete English guide
- [Docs/GUIDE.fa.md](Docs/GUIDE.fa.md) — راهنمای کامل فارسی
- [Docs/DOCS.en.md](Docs/DOCS.en.md) — command/environment reference (EN)
- [Docs/DOCS.fa.md](Docs/DOCS.fa.md) — مرجع کامل دستورات و متغیرها (FA)

## Security notes

- The SOCKS proxy has **no authentication** — keep it on loopback.
- Identities (`aether*.toml`) are device credentials — treat them like passwords and don't share them.
- `--upstream` sends your traffic through another local proxy first; make sure you trust it.

## Contributing

> **Experienced network developers and protocol engineers are welcome to contribute.**

> **Please keep the codebase clean, maintainable, and well-engineered. Low-quality or vibe-coded contributions will not be accepted.**

Run `cargo test` before every pull request. Live-network tests stay ignored unless the change is specifically about them.

## Donate

If Aether has been useful to you, consider supporting its development:

- **TRX (Tron):** `TRxVSHcoADZnBfztFmFb2TQopusAwWYEVR`
- **BTC:** `bc1qnjnvzsa5avgj7n0uy383cv5zdxfjnvvp257egm`
- **TON:** `UQAH75bXaaRUhZMwiF0ZujOXFDDmvLSPASKoOsWF0HNasiaM`

## License

AGPL-3.0-only — see [LICENSE](LICENSE).

## Credits

Developed by **CluvexStudio**. :))

MASQUE support is built on top of Cloudflare's **Quiche** library.

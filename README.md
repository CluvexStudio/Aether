# Aether

### اینترنت آزاد برای همه :))
**[راهنمای فارسی](README.fa.md)** · **[English Guide](Docs/GUIDE.en.md)** · **[راهنمای کامل فارسی](Docs/GUIDE.fa.md)**

Telegram: https://t.me/CluvexStudio

Aether is a censorship circumvention client designed for heavily restricted networks. It automatically discovers reachable routes, establishes an encrypted tunnel, and exposes a local SOCKS5 proxy for your applications.

Unlike traditional VPN clients, Aether is built for environments where Deep Packet Inspection (DPI), protocol fingerprinting, UDP throttling, and endpoint blocking are common.

## Features

- Automatic endpoint discovery
- MASQUE (HTTP/3 & HTTP/2)
- WireGuard support
- Nested WireGuard mode (`gool`)
- Traffic obfuscation
- Automatic reconnection
- Local SOCKS5 proxy
- Linux, Windows, macOS and Android (Termux)

## Download

Prebuilt binaries are available on the Releases page for:

- Linux
- Windows
- macOS
- Android (Termux)

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

## Usage

Run:

```bash
./target/release/aether
```

Aether will ask you to select:

- Protocol
- Obfuscation profile
- Listening port
- Scan mode

After startup, a SOCKS5 proxy will be available at:

```
127.0.0.1:10808
```

Example:

```bash
curl -x socks5h://127.0.0.1:10808 https://www.cloudflare.com/cdn-cgi/trace
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

## License

See the LICENSE file for licensing information.

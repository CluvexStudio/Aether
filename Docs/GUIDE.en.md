# Complete Guide to Aether

This document tries to gather in one place everything you need to work with Aether. It is written plainly, step by step, so that even if this is your first time you will not get lost.

## What Aether actually does

Aether is a tunnel. Its job is to open an encrypted path out of a restricted network and bring up a local proxy next to you called SOCKS5. After that, any application that knows how to go through a proxy — a browser, a terminal, or your whole system — sends its traffic through this tunnel.

The proxy's default address is `127.0.0.1:1819`.

## Running it: prompts, flags, or environment variables

Aether can be driven three ways, and you can mix them:

1. **Interactive prompts** — just run the binary with no arguments and answer the questions.
2. **Command-line flags** — a short, memorable syntax for the common choices.
3. **Environment variables** — for scripts, services, and full control (every flag maps to one).

The flag syntax looks like this:

```
./aether --bind 127.0.0.1:1819 -4 --masque --turbo --noize firewall
./aether --wg --scan balanced --keepalive 25
./aether --gool --wg-peer 162.159.192.1:2408 --dual
```

Run `./aether --help` to see the full list. The most common ones:

```
--bind <addr>            local SOCKS5 listen address (default 127.0.0.1:1819)
-4 / -6 / --dual          scan IPv4 only / IPv6 only / both
--peer <ip:port>          force a peer and skip scanning
--masque / --wg / --gool  choose the transport
--scan <mode>             turbo | balanced | thorough | stealth
--turbo/--balanced/--thorough/--stealth  shortcuts for --scan
--noize <profile>         obfuscation profile
--h2, --http2             use HTTP/2 instead of HTTP/3 for MASQUE
--fragment                fragment the TLS ClientHello (HTTP/2 only)
--quick-reconnect         skip the prompt, always reuse the last working gateway
--no-quick-reconnect      skip the prompt, always scan fresh
```

Any flag you don't pass falls back to its environment variable, and any environment variable you don't set falls back to the interactive prompt (or a sane default). Setting a flag or variable is what suppresses the corresponding prompt.

## Three transports, three different logics

When you run Aether, the first thing it asks is which protocol to use. You have three choices:

### 1) MASQUE

This is the most modern mode and also the default. Your traffic is hidden inside an encrypted connection that looks exactly like ordinary web traffic. On networks that inspect everything carefully, this is the quietest and least troublesome option. If you do not know where to start, start here.

### 2) WireGuard

A classic tunnel, lean and very fast. It has the least overhead, so when it works it feels the fastest. Good for networks that only block known addresses and are not looking too closely at the shape of the traffic.

### 3) Tunnel-in-tunnel (gool)

Here one WireGuard session is wrapped inside another WireGuard session. That means two layers of encryption stacked on top of each other. This is a little slower, but when a single layer is not enough for clean passage it can make the difference. If plain WireGuard connects but is not stable, try this mode.

## Scanning: why it has no fixed address

Aether does not nail any address inside itself. The reason is simple: every network and every operator is different, and an address that works on one network today may not respond at all on another. So instead of guessing, it runs a scan: it tries a set of different addresses and ports, measures the real response and the response time (ping), and picks the best one it finds.

At startup it asks how serious the scan should be. You have four modes:

- **turbo** — fast, satisfied with the first answer it catches. For when you just want to connect quickly.
- **balanced** — the default, balanced mode. Good for most situations.
- **thorough** — deep, looks for the best ping. Slower but a higher-quality result.
- **stealth** — calm and patient. Scans slowly to make less noise on the network.

It also asks whether to look on IPv4 addresses, IPv6, or both. If your network has no IPv6, stay on IPv4.

## The noise system and obfuscation profiles

This is the most important part that keeps Aether alive on a strict network.

### What the problem is

Deep packet inspection devices (DPI) look, at the start of every connection, for a fixed signature. Every protocol's handshake has a specific shape, and that shape gives it away.

### Aether's solution

Before the real conversation begins, Aether sends some "junk" and random packets so that the start of the connection does not look like a recognizable pattern from the outside. It can also pause a little between handshake stages and send packets at irregular intervals, so that the timing pattern of the traffic is not predictable either.

### Profiles for MASQUE

- **firewall** (default and recommended for Iran) — balanced; it gets through well without sacrificing too much speed.
- **gfw** — heavier. Try this when firewall does not work.
- **off** — no obfuscation. Only for open networks or for testing.

### Profiles for WireGuard and gool

- **balanced** (default and recommended for Iran) — the sweet spot between stealth and speed.
- **aggressive** — the heaviest. Sends the most decoy packets and obfuscation layers. For very strict networks.
- **light** — minimal. A little obfuscation with the least overhead.
- **off** — no obfuscation.

### The simple rule

Start from the default. If it did not connect or kept dropping, take it one step heavier (for MASQUE go to gfw, for WireGuard go to aggressive). If your network is open and you only want speed, come down to light or off.

## The difference between h2 and h3 in MASQUE and choosing between them

This section is specific to MASQUE and will be very useful to you.

MASQUE in Aether has two paths to carry the traffic:

### h3 (default)

h3 means HTTP/3, which rides on QUIC, and QUIC itself runs on UDP. Its advantage is that it is fast, its handshake is shorter and needs fewer round trips to connect, and when a packet is lost the whole connection does not stall. On most healthy networks, h3 gives the best experience.

### h2

h2 means HTTP/2, which runs on TLS and TCP — exactly what every ordinary HTTPS site uses. It is a little slower than h3, because when a packet is lost TCP holds up the rest. But it has one big advantage: it looks exactly like ordinary web traffic and it runs on TCP.

### When to choose which

The rule of thumb is simple:

- **Try h3 first** (the default). If it connected and was stable, you are done.
- **If the network blocks or throttles UDP or QUIC** — meaning h3 does not connect at all or keeps dropping — switch to h2. Some networks deliberately throttle UDP so QUIC does not work; in that case h2, which runs on TCP, slips through the restriction.

To turn on h2, all you need is to set the following variable before running (or pass `--h2`):

```
AETHER_MASQUE_HTTP2=1 ./target/release/aether
./target/release/aether --h2
```

The values `1`, `true`, `h2`, `yes`, and `on` all turn on h2. If you do not set this, it is always h3.

### Fragmenting the ClientHello (h2 only)

On some networks, DPI blocks the connection the moment it sees a complete, single TLS ClientHello record with a recognizable SNI. When you run MASQUE over h2, Aether can split that first TLS flight into several small chunks and send them with a short random delay in between, so no single packet on the wire contains the whole handshake or the SNI in one piece. This is the same idea used elsewhere as "TLS ClientHello fragmentation" — this is only available for h2 because it needs a TCP stream to fragment; h3 runs over QUIC/UDP where the concept does not apply the same way.

It is off by default because it adds a small delay to every reconnect. Turn it on with:

```
AETHER_MASQUE_H2_FRAGMENT=1 ./target/release/aether --h2
./target/release/aether --h2 --fragment
```

You can tune the chunk size and delay:

```
AETHER_MASQUE_H2_FRAGMENT_SIZE=8-24 AETHER_MASQUE_H2_FRAGMENT_DELAY=5-15 ./target/release/aether --h2 --fragment
./target/release/aether --h2 --fragment --fragment-size 8-24 --fragment-delay 5-15
```

Both accept either a single number or an `a-b` range in bytes (for size) or milliseconds (for delay). If your network is aggressively blocking h2's TLS handshake specifically, try this before giving up on h2 entirely.

### Why a gateway is only accepted after real data flows

Both scanning and the live tunnel used to trust a MASQUE gateway as soon as the CONNECT-IP request came back with `:status 200`. On some networks that is not enough: the handshake and the control response go through, but the DPI system silently drops any data sent afterwards. The result looked like a working connection that never actually passed traffic.

Aether now pushes a small end-to-end probe packet through the tunnel and waits for a real reply before it trusts a gateway or opens the local SOCKS5 port. This applies to the scan (so a "no clean endpoint" result now genuinely means no candidate could pass data, not just that no candidate answered) and to the live tunnel (SOCKS5 stays closed until the very first connection has proven it can carry real traffic, instead of opening immediately after the handshake). If you need the old, faster-but-less-certain behavior, set `AETHER_MASQUE_NO_DATA_CHECK=1` or pass `--no-data-check`.

## Staying connected and automatic reconnection

A tunnel can appear to be open while in practice it is dead; that is, the proxy is still open but no data is being exchanged. This happened mostly on gool, when the outer layer was cut by the network but the proxy did not know.

If a MASQUE tunnel drops or fails its data-plane validation, Aether now reconnects on its own: it waits a short delay (default 2 seconds, `AETHER_MASQUE_RECONNECT_SECS`) and scans again for a fresh gateway, instead of exiting.

## Reconnecting quickly with your last known-good gateway

Scanning takes time, and if you connect from the same network often, rescanning every single time is wasted effort. Aether remembers the last gateway that actually worked (saved next to your identity config, in a small `*-lastconn.toml` file — never committed to git, see `.gitignore`).

The next time you start Aether, if a saved gateway exists, it asks:

```
Last working gateway: 162.159.198.1:443 (profile 'firewall')
Reconnect to it now without rescanning? [Y/n]:
```

- Answer yes (or just press Enter) and Aether re-verifies that specific gateway is still alive — a single quick check, not a full scan — and connects immediately if it passes.
- Answer no and Aether ignores the cache and goes through the normal scan exactly as before.
- If the cached gateway no longer works, Aether says so and falls back to a full scan automatically, so you are never stuck on a dead cached endpoint.

To skip the prompt entirely (useful for services and scripts), set `AETHER_QUICK_RECONNECT=1` (or pass `--quick-reconnect`) to always try the cache first, or `AETHER_QUICK_RECONNECT=0` (or `--no-quick-reconnect`) to always scan fresh.

## Full table of environment variables

Every prompt has a variable equivalent. If you set a variable beforehand, Aether no longer asks that question. This is excellent for automated runs and scripting.

### General selection

- `AETHER_PROTOCOL` — protocol: `masque`, `wg`, or `gool`.
- `AETHER_SOCKS` — the proxy listen address. Default `127.0.0.1:1819`.
- `AETHER_NOIZE` — obfuscation profile (explained above).
- `AETHER_SCAN` — scan mode: `turbo`, `balanced`, `thorough`, `stealth`.
- `AETHER_IP` — IP version for scanning: IPv4, IPv6, or both.

### Specific to MASQUE

- `AETHER_MASQUE_HTTP2` (`--h2`, `--http2`) — if it is `1`/`true`/`h2`/`yes`/`on`, it uses h2. Otherwise h3.
- `AETHER_MASQUE_H2_PEER` (`--h2-peer`) — manual override of the destination address for h2 mode.
- `AETHER_MASQUE_H2_FRAGMENT` (`--fragment`) — fragment the TLS ClientHello on h2. Off by default.
- `AETHER_MASQUE_H2_FRAGMENT_SIZE` (`--fragment-size`) — fragment chunk size in bytes, `n` or `a-b`. Default `16-32`.
- `AETHER_MASQUE_H2_FRAGMENT_DELAY` (`--fragment-delay`) — delay between fragments in ms, `n` or `a-b`. Default `2-10`.
- `AETHER_MASQUE_NO_DATA_CHECK` (`--no-data-check`) — if set, a `:status 200` alone is enough; the end-to-end data-plane probe is skipped.
- `AETHER_MASQUE_VALIDATE_SECS` (`--validate-secs`) — seconds to wait for the data-plane probe to succeed before giving up on a gateway. Default `10`.
- `AETHER_MASQUE_RECONNECT_SECS` (`--reconnect-secs`) — delay before automatically reconnecting after the tunnel drops or fails validation. Default `2`.

### Specific to WireGuard and gool

- `AETHER_WG_KEEPALIVE` (`--keepalive`) — the keepalive packet interval in seconds. Default `5`.
- `AETHER_WG_NO_DATA_CHECK` (`--no-data-check`) — if set, real data passage is not verified during the scan (faster but less reliable).
- `AETHER_WG_NO_PROFILE_RETRY` (`--no-profile-retry`) — if set, on a failed scan it does not retry with other noise profiles.

### Quick reconnect

- `AETHER_QUICK_RECONNECT` (`--quick-reconnect` / `--no-quick-reconnect`) — set to `1` to always reuse the last known-good gateway without asking, or `0` to always scan fresh without asking. Unset means Aether asks you at startup if a cached gateway exists.

### Forcing the endpoint and the config path

- `AETHER_PEER` or `AETHER_WG_PEER` (`--peer`, `--wg-peer`) — if you want to give a fixed address yourself and bypass the scan.
- `AETHER_CONFIG` (`--config`) — the path of the base config file. Default `aether.toml`.
- `AETHER_WG_CONFIG` and `AETHER_MASQUE_CONFIG` (`--wg-config`, `--masque-config`) — the config path specific to each protocol.
- `AETHER_TLS_GROUPS` (`--tls-groups`) — override the TLS key-share groups advertised in the handshake. Default mimics Chrome (`P-256:X25519:P-384`).

## Practical examples

### The simplest case

Just run it and answer the questions with a number:

```
./target/release/aether
```

### MASQUE on h2 for a network that has blocked UDP

```
AETHER_PROTOCOL=masque AETHER_MASQUE_HTTP2=1 AETHER_NOIZE=firewall ./target/release/aether
```

### Fast WireGuard on a strict network

```
AETHER_PROTOCOL=wg AETHER_NOIZE=aggressive AETHER_SCAN=thorough ./target/release/aether
```

### gool with a custom port

```
AETHER_PROTOCOL=gool AETHER_SOCKS=127.0.0.1:1080 ./target/release/aether
```

### MASQUE on h2 with ClientHello fragmentation, for a network that blocks the h2 handshake specifically

```
./target/release/aether --masque --h2 --fragment --noize firewall
```

### Always reconnect fast without being asked (service / script use)

```
AETHER_QUICK_RECONNECT=1 ./target/release/aether --masque
```

### Running with Docker

You can run the official Aether Docker image directly from the GitHub Container Registry (GHCR), which provides an isolated environment without needing to install Rust or C++ compilers.

```bash
docker run -it -p 1819:1819 \
  -e AETHER_PROTOCOL=masque \
  -e AETHER_SCAN=balanced \
  ghcr.io/cluvexstudio/aether:latest
```
*(The `-it` flag is necessary for interactive prompts if you do not provide the environment variables beforehand.)*

If you prefer to build the image locally:

```bash
docker build -t aether .
docker run -it -p 1819:1819 aether
```

## Testing whether it works

As soon as it says the proxy is listening, run this:

```
curl -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace
```

If you got an answer and saw something like `warp=on` or connection details inside it, it means the tunnel is up and your traffic is passing through it.

## When something does not work

- **It does not connect at all:** first change the protocol. If MASQUE did not work on h3, turn on h2. If h2's handshake itself gets blocked, try `--fragment`. If nothing on MASQUE works, try WireGuard or gool.
- **The scan finds a gateway but the tunnel never passes traffic ("connects" but nothing loads):** this is exactly what the data-plane validation now catches — a gateway that answers the handshake but silently drops data. Aether will reject that gateway and keep scanning automatically. If it happens constantly and you'd rather connect anyway, you can disable the check with `--no-data-check`, but expect the same silent-drop behavior you had before.
- **It connects but keeps dropping:** take the noise profile one step heavier.
- **The scan takes too long:** set the scan mode to turbo.
- **It is slow:** if you are on gool, come to single-layer WireGuard; and if you are on h2 and your network leaves UDP open, try h3.
- **You keep waiting through a full scan every time you reconnect on the same network:** say yes to the "reconnect to last working gateway" prompt, or set `AETHER_QUICK_RECONNECT=1` permanently.

## Summary

If you want it in one sentence: start from MASQUE with the default profile, if UDP is blocked turn on h2 (and fragment the ClientHello if h2 itself gets blocked), and if it is still strict, make the noise profile heavier or move to WireGuard and gool. Aether takes care of the rest — including refusing gateways that don't actually pass data, and reconnecting on its own if the tunnel drops.

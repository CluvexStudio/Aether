# Complete Guide to Aether

This document tries to gather in one place everything you need to work with Aether. It is written plainly, step by step, so that even if this is your first time you will not get lost.

## What Aether actually does

Aether is a tunnel. Its job is to open an encrypted path out of a restricted network and bring up a local proxy next to you called SOCKS5. After that, any application that knows how to go through a proxy — a browser, a terminal, or your whole system — sends its traffic through this tunnel.

The proxy's default address is `127.0.0.1:1819`.

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

To turn on h2, all you need is to set the following variable before running:

```
AETHER_MASQUE_HTTP2=1 ./target/release/aether
```

The values `1`, `true`, `h2`, `yes`, and `on` all turn on h2. If you do not set this, it is always h3.

## Staying connected and automatic reconnection

A tunnel can appear to be open while in practice it is dead; that is, the proxy is still open but no data is being exchanged. This happened mostly on gool, when the outer layer was cut by the network but the proxy did not know.

Aether has a watchdog that watches the flow of data. If it sees that you are sending but for a long time (default 20 seconds) nothing comes back, it concludes that the path is dead; it tears it down and automatically reconnects to a freshly scanned endpoint. When you have no traffic (idle), it does not reconnect pointlessly.

## Full table of environment variables

Every prompt has a variable equivalent. If you set a variable beforehand, Aether no longer asks that question. This is excellent for automated runs and scripting.

### General selection

- `AETHER_PROTOCOL` — protocol: `masque`, `wg`, or `gool`.
- `AETHER_SOCKS` — the proxy listen address. Default `127.0.0.1:1819`.
- `AETHER_NOIZE` — obfuscation profile (explained above).
- `AETHER_SCAN` — scan mode: `turbo`, `balanced`, `thorough`, `stealth`.
- `AETHER_IP` — IP version for scanning: IPv4, IPv6, or both.

### Specific to MASQUE

- `AETHER_MASQUE_HTTP2` — if it is `1`/`true`/`h2`/`yes`/`on`, it uses h2. Otherwise h3.
- `AETHER_MASQUE_H2_PEER` — manual override of the destination address for h2 mode.

### Specific to WireGuard and gool

- `AETHER_WG_KEEPALIVE` — the keepalive packet interval in seconds. Default `5`.
- `AETHER_WG_STALL` — the threshold for detecting a stall and reconnecting, in seconds. Default `20`.
- `AETHER_NO_WATCHDOG` — if set, the watchdog and automatic reconnection are turned off.
- `AETHER_WG_NO_DATA_CHECK` — if set, real data passage is not verified during the scan (faster but less reliable).
- `AETHER_WG_NO_PROFILE_RETRY` — if set, on a failed scan it does not retry with other noise profiles.

### Forcing the endpoint and the config path

- `AETHER_PEER` or `AETHER_WG_PEER` — if you want to give a fixed address yourself and bypass the scan.
- `AETHER_CONFIG` — the path of the base config file. Default `aether.toml`.
- `AETHER_WG_CONFIG` and `AETHER_MASQUE_CONFIG` — the config path specific to each protocol.

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

### Running with Docker

Docker provides an isolated environment and doesn't require installing Rust or any C++ compilers on your host machine.

```bash
docker build -t aether .
docker run -it -p 1819:1819 \
  -e AETHER_PROTOCOL=masque \
  -e AETHER_SCAN=balanced \
  aether
```
*(The `-it` flag is necessary for interactive prompts if you do not provide the environment variables beforehand.)*

## Testing whether it works

As soon as it says the proxy is listening, run this:

```
curl -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace
```

If you got an answer and saw something like `warp=on` or connection details inside it, it means the tunnel is up and your traffic is passing through it.

## When something does not work

- **It does not connect at all:** first change the protocol. If MASQUE did not work on h3, turn on h2. If it still did not work, try WireGuard or gool.
- **It connects but keeps dropping:** take the noise profile one step heavier.
- **The scan takes too long:** set the scan mode to turbo.
- **It is slow:** if you are on gool, come to single-layer WireGuard; and if you are on h2 and your network leaves UDP open, try h3.

## Summary

If you want it in one sentence: start from MASQUE with the default profile, if UDP is blocked turn on h2, and if it is still strict, make the noise profile heavier or move to WireGuard and gool. Aether takes care of the rest.

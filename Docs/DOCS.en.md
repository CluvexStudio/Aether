# Aether

Aether is a user-space proxy client for Cloudflare WARP. It builds a tunnel out
of a filtered network and exposes a local SOCKS5 proxy on `127.0.0.1:1819`.
Point a browser, a terminal, or a system proxy at that address and the traffic
leaves through the tunnel.

It needs no root and installs no network driver. Everything happens inside the
process: the tunnel, a user-space TCP/IP stack, and the proxy.

## Contents

- [Running it](#running-it)
- [Transports](#transports)
- [Finding an endpoint](#finding-an-endpoint)
- [Obfuscation](#obfuscation)
- [Zero Trust](#zero-trust)
- [Routing rules](#routing-rules)
- [Identity files](#identity-files)
- [Using Aether as a library](#using-aether-as-a-library)
- [Environment variables](#environment-variables)

## Running it

Run `aether` with no arguments and it asks a few questions, or pass flags and it
asks nothing. Every flag also has an environment variable, so the same settings
work in a container or a service unit. `aether --help` lists all of them.

```sh
aether
aether --masque --scan balanced
aether --wg --noize aggressive --bind 127.0.0.1:1080
```

Check that it works:

```sh
curl -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace
```

The reply should show a Cloudflare colo and `warp=on`.

For clients that cannot speak SOCKS, add an HTTP CONNECT proxy:

```sh
aether --http-proxy 127.0.0.1:1820
```

Both listeners serve the same tunnel. Bind them to `0.0.0.0` only if you mean to
share the tunnel with your network; nothing authenticates the callers.

## Transports

| Transport | Flag | Carrier |
| --- | --- | --- |
| MASQUE | `--masque` (default) | QUIC/HTTP-3 on UDP 443, or HTTP/2 on TCP 443 |
| WireGuard | `--wg` | WireGuard on UDP 2408 and documented fallbacks |
| WARP-in-WARP | `--gool` | a WireGuard tunnel inside another one |

MASQUE is the default because it looks like ordinary HTTPS traffic and Cloudflare
treats it as the primary protocol. Use WireGuard when UDP QUIC is throttled but
plain UDP still passes. `--gool` adds a second hop for networks that recognise a
single WARP handshake; it costs latency, so reach for it last.

MASQUE has two carriers. HTTP/3 over QUIC is the default. If UDP 443 is blocked
outright, `--h2` moves the same tunnel onto TCP 443, which survives networks that
drop QUIC entirely.

```sh
aether --masque --h2
```

## Finding an endpoint

Cloudflare answers on many edge addresses and a filtered network usually blocks
some of them, so Aether does not ship a single fixed address. It sweeps the
documented ranges, verifies candidates, and keeps the one that carries real
traffic. A handshake alone is not enough: a candidate has to pass an end-to-end
data check before the proxy opens.

| Mode | Behaviour |
| --- | --- |
| `turbo` | stops at the first candidate that answers |
| `balanced` | default, collects a few and keeps the fastest |
| `thorough` | sweeps whole ranges, best when everything looks blocked |
| `stealth` | few probes in flight, for networks that notice scanning |
| `ironclad` | full tunnel and a real HTTP request per candidate |

Skip the scan when you already know a good address:

```sh
aether --peer 162.159.196.1:443
```

The last working endpoint is saved, and `--quick-reconnect` reuses it without a
new sweep. An endpoint that just failed is held on a cooldown so the next attempt
does not land on it again.

## Obfuscation

Some networks fingerprint the first packets of a handshake. Aether can pad and
reshape them so the opening exchange does not match a known pattern.

| Profile | Use it when |
| --- | --- |
| `off` | the network does no inspection |
| `light` | mild interference, lowest overhead |
| `balanced` | default, a good starting point |
| `aggressive` | the handshake is being fingerprinted |

```sh
aether --noize aggressive
```

Two extras apply to MASQUE only:

- `--fragment` splits the TLS ClientHello on the HTTP/2 carrier, which defeats
  inspectors that read the SNI from a single packet. `--fragment-size` and
  `--fragment-delay` tune it.
- `--ech auto` fetches an Encrypted Client Hello config and hides the SNI
  altogether, when the network permits it.

## Zero Trust

With `--team <name>` Aether enrols as a managed device on your organization's
Cloudflare Zero Trust account instead of registering an anonymous consumer
device. It works on both MASQUE and WireGuard, and one team identity is shared
between them, so switching transport does not consume a second device seat.

Three ways to sign in:

| Method | Flags | Suits |
| --- | --- | --- |
| Email code | `--access-email <addr>` | a person at a keyboard |
| Service token | `--access-id`, `--access-secret` | servers and CI |
| Existing token | `--access-token <jwt>` | a token you already hold |

```sh
aether --team acme --access-email me@example.com
```

Cloudflare emails a one-time code and Aether asks for it. The code can be typed
into a terminal or fed on standard input, which is how the desktop and Android
clients answer it. You get three attempts. The resulting token is cached for the
life of the process, so a reconnect does not ask again.

`--gateway` sends HTTP and HTTPS through the organization's Gateway proxy so its
filtering and logging apply. It is off by default because it adds a hop inside
the tunnel and records your browsing. If the proxy stops answering, Aether falls
back to direct tunnel egress rather than breaking every connection.

## Routing rules

Two lists decide what a destination is allowed to do. `--route-block` refuses the
connection outright. `--route-direct` sends it out of your real interface instead
of the tunnel, which is what banking apps, LAN services, and domestic sites that
reject foreign addresses need. Block is checked first, then direct, otherwise the
tunnel is used.

```sh
aether --route-block ads.example.com,port:25 --route-direct private,bank.ir
```

| Entry | Matches |
| --- | --- |
| `example.com` | the name and every subdomain |
| `full:example.com` | that exact name only |
| `keyword:doubleclick` | any name containing it |
| `regexp:^ad[0-9]+` | a regular expression |
| `10.0.0.0/8` | a network, or a bare address |
| `port:25`, `port:3000-3010` | a port or a range |
| `private` | LAN, loopback and CGNAT space |

Long lists belong in a file:

```ini
[block]
ads.example.com
port:25

[direct]
private
bank.ir
```

```sh
aether --routes /etc/aether/routes.conf
```

Rules apply to TCP and UDP. Per-application rules are deliberately not here: in
tun mode the traffic has already lost its application identity by the time it
reaches Aether, so that split belongs to the platform client.

## Identity files

On first run Aether registers a device and writes the credentials next to the
config path, default `aether.toml`. Keep the file: deleting it registers a new
device.

| File | Holds |
| --- | --- |
| `aether.toml` | the WireGuard identity |
| `aether-masque.toml` | the MASQUE identity and its certificate |
| `aether-team-<name>.toml` | one identity per Zero Trust team |
| `aether-*-lastconn.toml` | the last working endpoint |

Override any of them with `--config`, `--wg-config`, `--masque-config`. The files
contain private keys and are written owner-readable only.

## Using Aether as a library

Besides the `aether` binary, the crate builds `libaether.a` and `libaether.so`
with a C API, so a host application can link the core instead of spawning it.
This is what the iOS client needs, and it lets a Go program use Aether through
cgo.

```sh
cargo build --release            # binary and both libraries
cargo build --release --bin aether   # binary only
```

The C API is handle based and polled rather than callback based, so it is safe to
call from any language runtime. `aether_core_start` runs the whole pipeline and
returns a job handle; `aether_job_poll` reports progress; `aether_job_cancel`
stops it. Separate entry points cover the individual steps: identity, Zero Trust
sign-in, endpoint scan, verification, and the tunnel. Every reply is JSON, every
returned string is released with `aether_string_free`, and no panic crosses the
boundary. The header is `ios/Shared/aether.h` in the Oblivion client.

The data path is channel based and contains no tun device code, so an embedder
feeds packets in and reads them out directly.

## Environment variables

Every flag has an equivalent variable. Flags win when both are set.

| Variable | Sets |
| --- | --- |
| `AETHER_SOCKS` | SOCKS5 listen address |
| `AETHER_HTTP_PROXY` | HTTP CONNECT listen address |
| `AETHER_PROTOCOL` | `masque`, `wg`, `gool` |
| `AETHER_SCAN` | scan mode |
| `AETHER_NOIZE` | obfuscation profile |
| `AETHER_IP` | `4`, `6`, `dual` |
| `AETHER_PEER`, `AETHER_WG_PEER` | force an endpoint |
| `AETHER_QUICK_RECONNECT` | reuse the saved endpoint |
| `AETHER_MASQUE_HTTP2`, `AETHER_MASQUE_H2_PEER` | HTTP/2 carrier |
| `AETHER_ECH` | `auto` or a base64 config |
| `AETHER_MASQUE_H2_FRAGMENT`, `_SIZE`, `_DELAY` | ClientHello fragmenting |
| `AETHER_MASQUE_STARTUP_SECS` | startup deadline |
| `AETHER_MASQUE_VALIDATE_SECS`, `AETHER_WG_VALIDATE_SECS` | data-check timeout |
| `AETHER_MASQUE_NO_DATA_CHECK`, `AETHER_WG_NO_DATA_CHECK` | skip the data check |
| `AETHER_MASQUE_RECONNECT_SECS`, `AETHER_WG_RECONNECT_SECS` | reconnect delay |
| `AETHER_WG_KEEPALIVE` | WireGuard keepalive |
| `AETHER_WG_NO_PROFILE_RETRY` | do not retry other profiles |
| `AETHER_WG_ENDPOINT_COOLDOWN_SECS` | how long a failed endpoint is skipped |
| `AETHER_DNS` | resolvers used inside the tunnel |
| `AETHER_TEAM` | Zero Trust team name |
| `AETHER_ACCESS_EMAIL` | email for the one-time code |
| `AETHER_ACCESS_CLIENT_ID`, `AETHER_ACCESS_CLIENT_SECRET` | service token |
| `AETHER_ACCESS_TOKEN` | an enrolment token you already hold |
| `AETHER_GATEWAY` | route HTTP through the organization gateway |
| `AETHER_ROUTE_BLOCK`, `AETHER_ROUTE_DIRECT`, `AETHER_ROUTES_FILE` | routing rules |
| `AETHER_CONFIG`, `AETHER_WG_CONFIG`, `AETHER_MASQUE_CONFIG` | identity paths |
| `AETHER_TLS_GROUPS` | TLS key share groups |
| `AETHER_PERF_PROFILE` | `low`, `medium`, `high` |
| `AETHER_LOG_LEVEL` | `error` to `trace` |

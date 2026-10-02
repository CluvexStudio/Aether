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
- [TLS](#tls)
- [Zero Trust](#zero-trust)
- [Routing rules](#routing-rules)
- [Upstream proxy](#upstream-proxy)
- [Tor](#tor)
- [Firewall mark](#firewall-mark)
- [Proxy limits and timeouts](#proxy-limits-and-timeouts)
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
| MASQUE-in-MASQUE | `--mim` | a MASQUE tunnel inside another one |

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

### MASQUE-in-MASQUE

`--mim` runs a second MASQUE tunnel inside the first one, the way `--gool` nests
WireGuard. The outer hop is dialled from your network; the inner hop is dialled
from inside it, so Cloudflare sees the outer edge's address rather than yours and
gives the inner tunnel a different exit. Use it when a single tunnel keeps coming
out in the country you are trying to leave.

Both hops use the same carrier: HTTP/3 inside HTTP/3 by default, or HTTP/2 inside
HTTP/2 with `--h2`. The inner hop gets its own identity file, named
`<masque config>-secondary.toml`, and a smaller link size so its packets fit
inside the outer tunnel.

```sh
aether --mim
aether --mim --h2
aether --mim --mim-outer 162.159.192.1:443 --mim-inner 162.159.204.1:443
```

The outer hop is scanned for as usual and the inner edge is picked for you; name
either with `--mim-outer` / `--mim-inner`, or both with `--mim-peers`. The two
hops must be different addresses. It costs a second registration and one more
round trip than a single tunnel, so reach for it when you need the exit address
changed.

### QUIC v2 opener

Some networks block QUIC v1 on every port while letting QUIC v2 through, because
their filter only learned to recognise v1. Before each HTTP/3 handshake Aether
sends one opener packet that carries the QUIC v2 version number but is otherwise a
plain long-header Initial. The filter sees a v2 flow and lets it pass; the
Cloudflare edge does not speak v2 and answers with a Version Negotiation pointing
back to v1; Aether then runs the ordinary v1 handshake on that same socket, which
the filter now treats as an allowed flow. On an open network this only adds one
short round trip. Combine it with a non-443 port (the scan already tries 443, 500,
1701, 4500, 4443, 8443 and 8095) where 443 is the one being blocked. Turn it off
with `--no-quic-v2` or `AETHER_QUIC_V2=0`. It does not apply to `--h2`, which is
TCP.

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

### Choosing the WARP-in-WARP hops yourself

`--peer` names one endpoint and warp-in-warp needs two, so each hop has its own
setting. Name both and no scan runs at all; name one and the scan finds the
other:

```sh
aether --gool --wiw-outer 162.159.192.1:2408 --wiw-inner 188.114.96.1:2408
aether --gool --wiw-peers 162.159.192.1:2408,188.114.96.1:2408
aether --gool --wiw-outer 162.159.192.1:2408   # the inner hop is scanned for
aether --gool --wiw-inner 188.114.96.1:1701    # the outer hop is scanned for
```

The port is required and none is filled in for you: which port answers is
exactly what differs between one network and the next, so an assumed one would
only send you at an address nobody offered. The two hops also have to sit on
different addresses — a second tunnel leaving through the edge it arrived on
gains nothing — and a scan run for one hop leaves the other's address out of
the sweep.

Naming a hop is enough to select warp-in-warp, so `--gool` alongside it is
optional, and `--wg-peer` names the outer hop. An endpoint you named is kept
across reconnects rather than swapped for a scanned one, so a hop that stops
answering is retried instead of replaced. `--wiw-scan` scans for both, ignoring
an endpoint left in the environment.

Nothing here is asked at startup. `--gool` on its own scans for both hops and
prints a line above the scan mode question naming the alternative.

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

One extra applies to MASQUE only: `--fragment` splits the TLS ClientHello on the
HTTP/2 carrier, which defeats inspectors that read the SNI from a single packet.
`--fragment-size` and `--fragment-delay` tune it.

## TLS

Four kinds of TLS handshake carry the tunnel and its setup: MASQUE on HTTP/3 and on
HTTP/2, the calls to the WARP API, and the DNS-over-HTTPS lookup of the ECH config.
All four send Chrome's ClientHello as BoringSSL writes it: TLS 1.3 and 1.2, Chrome's
cipher suites, GREASE values (RFC 8701), the extensions in a new order on every
handshake, signed certificate timestamps and OCSP asked for. They offer `h2` then
`http/1.1`, as Chrome does, but `h3` over QUIC, which carries TLS 1.3 alone; the
HTTP/2 carrier speaks HTTP/2, which Cloudflare picks. Certificates are not checked.
Zero Trust sign-in, the Tor bridge and relay lists and the exit-location lookup keep
a TLS of their own. Three options change the fingerprint of all four:

- `--tls-ciphers` sets the TLS 1.2 cipher suites, listed after the TLS 1.3 ones,
  which stay as they are: names separated by `:`, as BoringSSL reads a cipher
  string. HTTP/3 lists none. Without it they are Chrome's, from Chrome's own rule
  `ALL:!aPSK:!ECDSA+SHA1:!3DES`, in Chrome's order: AES-GCM first on hardware with
  AES instructions, ChaCha20 first elsewhere.
- `--tls-groups` sets the groups, in order, the first one getting a key share
  (default `P-256:X25519:P-384`).
- `--disable-grease` leaves out the GREASE values, which all four otherwise put in
  the cipher suites, the extensions, the groups, the key shares and the versions.

A cipher or group name BoringSSL does not know stops the core as it starts, with
the option named.

`--ech auto` fetches an Encrypted Client Hello config and hides the server name
altogether, when the network permits it, on the MASQUE handshakes, on both
carriers, and on the calls to the WARP API. It asks `udp://1.1.1.1` for the HTTPS
record of `cloudflare-ech.com`; `--ech-dns` names another resolver
(`udp://ip[:port]` or `tcp://ip[:port]`, on port 53 unless one is given, or a
DNS-over-HTTPS `https://` URL, on port 443 unless it names one) and `--ech-domain`
another domain. After a DNS-over-HTTPS URL, `@address=` sends the connection to
another IP address or domain, on the URL's port, and `@sni=` puts another name in
the ClientHello, while the URL's host stays the HTTP host:
`https://doq.dns4all.eu/dns-query@address=2.2.2.2@sni=google.com` connects to
2.2.2.2, names google.com in the ClientHello and asks doq.dns4all.eu over HTTP.
That lookup goes without ECH, as the config it fetches is the one ECH needs.
`--ech <base64>` takes the config itself instead, as the `ech` value of such a
record shows it. One config serves both: a session that starts after calls to the
WARP API offers the one they used. Without a config it can offer, because the
lookup failed or the config is not one the TLS library can use, no name goes out
in the clear: the WARP API is not asked, the MASQUE session does not start, and the
core says why.

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

### Name rules behind a tun

Name rules also match when the proxy is handed an address instead of a name, which
is what a tun front end does. Aether reads the name from the TLS server name or the
HTTP `Host` header of the first bytes and decides on that; address and port rules
still apply when no name is found.

The name is used for the decision only, so the connection still goes to the address
the client asked for.

| Variable | Default | Sets |
| --- | --- | --- |
| `AETHER_ROUTE_SNIFF` | on | `0` turns it off |
| `AETHER_ROUTE_SNIFF_MS` | `400` | how long to wait for those first bytes |

## Upstream proxy

`--upstream` sends everything Aether dials through another proxy, which is how you
chain it behind a VPN or proxy app already running on the machine.

```sh
aether --upstream socks5://127.0.0.1:1080
aether --upstream socks5://alice:s3cret@127.0.0.1:1080
aether --upstream http://proxy.example:8080
```

A bare `host:port` is read as SOCKS5. Bracket an IPv6 address. Percent-encode a
password containing `@` or `:`, so `p@ss` is written `p%40ss`. Aether speaks plain
HTTP to an `http://` or `https://` upstream, so an `https://` one with a password is
refused rather than sending the password in the clear.

| Proxy | Carries |
| --- | --- |
| SOCKS5 with UDP associate | every transport: MASQUE on HTTP/3 and HTTP/2, WireGuard, `gool` |
| HTTP CONNECT | the HTTP/2 carrier only, since CONNECT cannot carry UDP |

With an HTTP proxy, add `--h2` so the whole tunnel stays on TCP:

```sh
aether --masque --h2 --upstream http://proxy.example:8080
```

The endpoint scan, the obfuscation packets, the registration and Zero Trust sign-in
calls and the ECH lookup go through the proxy too, and a SOCKS5 proxy resolves the
API host names itself. A destination matched by `--route-direct` does not, because
that rule exists to bypass the tunnel.

The same setting is available as `AETHER_UPSTREAM`.

## Tor

Aether carries a Tor implementation (arti) and can combine it with the tunnel in
three ways. All of them need a build made with the tor feature, because it is a
large dependency:

```sh
cd aether
cargo build --release --features tor
```

| Mode | Flag | Path | Exit address |
| --- | --- | --- | --- |
| Tor through the tunnel | `--tor` | you, WARP, Tor, the internet | a Tor exit |
| The tunnel through Tor | `--tor-reverse` | you, Tor, WARP, the internet | a WARP exit |
| Tor alone | `--tor-only` | you, Tor, the internet | a Tor exit |

### Tor through the tunnel

```sh
aether --masque --tor
```

Tor's guards are dialled through the tunnel, so a network that blocks Tor never
sees it. Any transport can carry it — `--masque` over HTTP/3 or HTTP/2, `--wg`,
`--gool`, `--mim` — because Tor's own traffic is TCP and it simply rides the
tunnel's proxy. Nothing sits in between: with `--wg --tor` the WireGuard tunnel
carries Tor directly. The usual proxy on `127.0.0.1:1819` keeps the WARP exit, and
a second one on `127.0.0.1:1820` comes out of Tor, so an application can use either:

```sh
curl -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace
curl -x socks5h://127.0.0.1:1820 https://check.torproject.org/api/ip
```

### The tunnel through Tor

```sh
aether --masque --tor-reverse
```

The other way round: Tor is bootstrapped first, and the tunnel is then dialled
through it, so the WARP edge is reached from a Tor exit and the network you are on
never sees WARP at all. The proxy on `127.0.0.1:1819` comes out of WARP as usual.
Tor carries TCP only, and WARP's WireGuard endpoints answer on UDP alone, so this
mode runs MASQUE over HTTP/2 and refuses WireGuard and `gool`. If you want
WireGuard in the path, put Tor inside the tunnel with `--tor` instead, where the
WireGuard tunnel carries Tor directly. This mode also needs Tor reachable before
anything else works, so on a network that blocks Tor, give it bridges.

### Tor alone

```sh
aether --tor-only
```

No tunnel and no WARP identity: the proxy on `--bind` is plain Tor.

### Bridges

On a network that blocks Tor outright, `--tor` still works, because Tor rides
inside the tunnel. `--tor-reverse` and `--tor-only` have to reach Tor first, so
they turn to bridges on their own:

```sh
aether --tor-only
```

Aether tries Tor plainly for a moment, and when that gets nowhere it asks
bridgedb which bridges suit the country it appears to be in, then works through
them one transport at a time: obfs4 first, then webtunnel, then snowflake.
Whichever gets through is remembered for next time.

The release archives carry the transport binaries in a `pt/` folder beside
`aether`, and that folder is the first place Aether looks, so a release needs no
setting up. Failing that it searches `PATH`, the usual system directories, and
Tor Browser's own bundled transports.

A bridge counts as working only once a stream has actually opened through it, so
a client that reaches 100% but cannot carry traffic is dropped and the next
bridge is tried.

To pin everything down by hand instead:

```sh
aether --tor-only \
  --tor-bridge "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=... iat-mode=0" \
  --tor-pt /usr/bin/lyrebird
```

Repeat `--tor-bridge` for more than one. `--tor-pt` names the pluggable transport
binary the bridge needs (obfs4 is assumed; write `snowflake=/path` for another).
`--tor-bridges` goes to bridges at once without trying Tor plainly first, and
`--no-tor-bridges` never uses them at all.

| Setting | Default | What it does |
| --- | --- | --- |
| `--tor`, `--tor-reverse`, `--tor-only`, `AETHER_TOR` | off | which mode |
| `--tor-bind`, `AETHER_TOR_BIND` | `127.0.0.1:1820` | the Tor proxy address |
| `--tor-dir`, `AETHER_TOR_DIR` | `<config>-tor` | directory cache and state |
| `--tor-bridge`, `AETHER_TOR_BRIDGES` | fetched as needed | bridge lines, `;` separated; also `auto` or `off` |
| `--tor-bridges` | | go to bridges at once, without trying Tor plainly |
| `--no-tor-bridges` | | never use bridges, however blocked the network looks |
| `--tor-pt`, `AETHER_TOR_PT` | found on its own | transport binaries, `;` separated |
| `--tor-pt-dir`, `AETHER_TOR_PT_DIR` | `pt/` beside the binary | another folder to search for them |
| `AETHER_TOR_COUNTRY` | detected | which country to ask bridgedb about, e.g. `ir` |
| `AETHER_TOR_DIRECT_SECS` | 75 | how long to try Tor plainly before bridges |
| `AETHER_TOR_STALL_SECS` | 75 | drop a bridge after this long without headway |
| `AETHER_TOR_BRIDGE_SECS` | 360 | the longest any one bridge may take |
| `AETHER_TOR_CHECK` | `check.torproject.org:443` | what Tor must reach before it counts as up |
| `AETHER_TOR_LOG` | `info` | how loud Tor is: `info`, `debug`, `trace` |

Host names are handed to Tor rather than resolved here, so nothing leaks to the
local resolver and `.onion` addresses work. Only CONNECT is carried: Tor has no
UDP. The first bootstrap takes a while because it downloads the directory.

## Firewall mark

On a Linux router that sends its own traffic into a tun front end (hev-socks5-tunnel,
tun2socks), Aether's outgoing connections would loop back into that tun. `--mark`
puts a firewall mark (`SO_MARK`) on every socket Aether opens to the internet: the
tunnels, the endpoint scan, the upstream proxy and `--route-direct` connections.
Rules can then let marked packets bypass the tun:

```sh
aether --mark 0xff
ip rule add fwmark 0xff lookup main priority 100
```

The mark is a decimal or `0x` number and needs root or `CAP_NET_ADMIN`; Aether stops
at startup if it cannot set it, rather than send unmarked traffic. It only works on
Linux and Android. The registration calls are not marked, so let the first start
finish before the tun rules are in place. The same setting is available as
`AETHER_MARK`.

## Proxy limits and timeouts

These keep a busy proxy from running out of file descriptors or memory. The defaults
suit most setups.

| Variable | Default | What it does |
| --- | --- | --- |
| `AETHER_MAX_CLIENTS` | 512 to 8192, by resources | clients served at once; past it new ones wait for a free slot |
| `AETHER_HALF_CLOSE_SECS` | `30` | how long a connection the client has finished sending on may stay silent before it is closed |
| `AETHER_TCP_KEEPALIVE_SECS` | `60` | idle time before a keep-alive checks the other end of a connection; three unanswered ones close it |
| `AETHER_TCP_CONNECT_SECS` | `30` | how long a connection through the tunnel may take to open |

Aether also raises its own open-file limit to the system's hard limit at startup. A
listen address that is already taken, or reserved by Windows (see `netsh interface
ipv4 show excludedportrange protocol=tcp`), stops Aether at startup with an error.

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

### When an identity stops being accepted

Cloudflare can stop accepting a device that is still in your file. The handshake
keeps succeeding in that state and no traffic passes, so Aether checks the saved
identity on startup and reports it:

```text
[-] cloudflare no longer accepts the saved identity for device <id>
[-] the tunnel will handshake but carry no traffic until this identity is replaced
```

It then registers a fresh device and rewrites the file. Set `AETHER_REPROVISION=0`
to be told without anything being replaced.

Only the account API refusing the device counts. Being offline or rate limited does
not discard an identity.

### Where the WARP API is asked

Registering a device, enrolling its MASQUE key and refreshing a profile are calls
to the WARP API, `api.cloudflareclient.com`, made as described under TLS above.
`--enroll-address` sends them to another address, an IP address or a domain name,
on port 443 unless a port follows it, an IPv6 address then in brackets:
`188.114.97.6`, `188.114.97.6:2053`, `[2606:4700::1]:8443`. Only the connection goes
there: the API's name stays the server name of the ClientHello and the HTTP host,
which carries no port. A name is looked up first, by the proxy with `--upstream`
and by the system resolver otherwise; with `--mark` and no `--upstream` only an IP
address is taken, since that lookup would leave outside the mark and loop back into
the tunnel. With `--ech` the API's name goes only inside the encrypted ClientHello,
and an IP address for `--enroll-address` keeps it out of the DNS lookup as well.

```sh
aether --register all --ech auto --enroll-address 141.101.113.10
```

## Using Aether as a library

Besides the `aether` binary, the crate builds `libaether.a` and `libaether.so`
with a C API, so a host application can link the core instead of spawning it.
This is what the iOS client needs, and it lets a Go program use Aether through
cgo.

The manifest is `aether/Cargo.toml`, so from the repository root enter the crate first. The binary and the libraries land in `aether/target/release/`.

```sh
cd aether
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
| `AETHER_WIW_OUTER_PEER`, `AETHER_WIW_INNER_PEER` | force one warp-in-warp hop |
| `AETHER_WIW_PEERS` | force both hops, or `auto` to always scan |
| `AETHER_MIM_OUTER_PEER`, `AETHER_MIM_INNER_PEER` | force one masque-in-masque hop |
| `AETHER_MIM_PEERS` | force both masque hops, or `auto` to always scan |
| `AETHER_ROUTE_SNIFF`, `AETHER_ROUTE_SNIFF_MS` | reading the server name off the first bytes |
| `AETHER_WG_STALE_SECS` | silence before a wireguard tunnel counts as dead |
| `AETHER_MASQUE_H2_KEEPALIVE_SECS`, `_TIMEOUT_SECS` | HTTP/2 keepalive |
| `AETHER_IRONCLAD_PORT` | port the ironclad scan makes its real request to |
| `AETHER_REPROVISION` | replace an identity Cloudflare refused |
| `AETHER_QUICK_RECONNECT` | reuse the saved endpoint |
| `AETHER_MASQUE_HTTP2`, `AETHER_MASQUE_H2_PEER` | HTTP/2 carrier; `--h3` sets it to `0` |
| `AETHER_QUIC_V2` | `0` turns off the QUIC v2 opener (on by default) |
| `AETHER_ECH` | `auto` or a base64 config, for MASQUE and the WARP API |
| `AETHER_ECH_DNS` | resolver `--ech auto` asks (`udp://`, `tcp://` or `https://`) |
| `AETHER_ECH_DOMAIN` | domain whose ECH config `--ech auto` takes |
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
| `AETHER_ROUTE_SNIFF`, `AETHER_ROUTE_SNIFF_MS` | reading the name off the first bytes |
| `AETHER_UPSTREAM` | dial out through another proxy |
| `AETHER_MARK` | firewall mark for outgoing sockets |
| `AETHER_MAX_CLIENTS`, `AETHER_HALF_CLOSE_SECS` | proxy client limit and half-closed timeout |
| `AETHER_TCP_KEEPALIVE_SECS`, `AETHER_TCP_CONNECT_SECS` | keep-alive and connect timeout inside the tunnel |
| `AETHER_REPROVISION` | replace an identity Cloudflare refuses |
| `AETHER_CONFIG`, `AETHER_WG_CONFIG`, `AETHER_MASQUE_CONFIG` | identity paths |
| `AETHER_ENROLL_ADDRESS` | where the calls to the WARP API go |
| `AETHER_TLS_GROUPS` | TLS groups (see TLS) |
| `AETHER_TLS_CIPHERS` | TLS 1.2 cipher suites (see TLS) |
| `AETHER_DISABLE_GREASE` | `1` leaves GREASE out (see TLS) |
| `AETHER_PERF_PROFILE` | `low`, `medium`, `high` |
| `AETHER_LOG_LEVEL` | `error` to `trace` |

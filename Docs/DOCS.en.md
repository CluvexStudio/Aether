# Aether v1.5.0 — Changes and New Features

**[نسخه فارسی](DOCS.fa.md)** · **[English Guide](GUIDE.en.md)** · **[راهنمای فارسی](GUIDE.fa.md)**

This document covers everything that changed between v1.4.0 and v1.5.0: two new
subsystems, a set of security fixes, and a batch of reliability fixes in the
data path. For day-to-day usage see `GUIDE.en.md`.

---

## Table of contents

1. [Zero Trust: WARP for organizations](#1-zero-trust-warp-for-organizations)
2. [Routing rules](#2-routing-rules)
3. [Security fixes](#3-security-fixes)
4. [Reliability fixes in the data path](#4-reliability-fixes-in-the-data-path)
5. [Registration resilience](#5-registration-resilience)
6. [Endpoint discovery](#6-endpoint-discovery)
7. [Dependency updates](#7-dependency-updates)
8. [Installer and container](#8-installer-and-container)
9. [Reference: new flags and environment variables](#9-reference-new-flags-and-environment-variables)
10. [Known issues](#10-known-issues)

---

## 1. Zero Trust: WARP for organizations

Until now Aether always registered as an anonymous consumer WARP device. It can
now enrol into a Cloudflare Zero Trust organization instead, so it connects as a
managed device belonging to your team account. This works on both MASQUE and
WireGuard.

```bash
aether --team your-team --access-email you@example.com
```

### 1.1 Three ways to sign in

An organization decides who is allowed to enrol, so Aether has to prove who it
is. There are three paths, and you pick the one that fits how the machine is
operated.

**Email one-time code.** For a normal interactive machine. Aether asks Cloudflare
to email a code to the address you gave, then prompts you for it.

```bash
aether --team your-team --access-email you@example.com
```

**Access service token.** For servers, containers, and CI, where nobody is
sitting there to read a mailbox. Create a service token in the Zero Trust
dashboard and pass both halves.

```bash
aether --team your-team --access-id <client-id> --access-secret <client-secret>
```

**A token you already hold.** If you signed in at
`https://<team>.cloudflareaccess.com/warp` in a browser and copied the enrolment
token out, hand it over directly.

```bash
aether --team your-team --access-token <jwt>
```

All three accept environment variables instead of flags, which is usually what
you want for the secret ones: `AETHER_TEAM`, `AETHER_ACCESS_EMAIL`,
`AETHER_ACCESS_CLIENT_ID`, `AETHER_ACCESS_CLIENT_SECRET`, `AETHER_ACCESS_TOKEN`.

### 1.2 Sign in once per process

The enrolment token is cached in memory for the lifetime of the process. A
reconnect, a scan retry, or a protocol switch reuses it. Previously each of
those would have started a fresh sign-in, which for the email path meant a new
code in your inbox every time the tunnel bounced.

### 1.3 One team identity shared across protocols

The registered device is stored in a single per-team identity file, and both
MASQUE and WireGuard read it. Switching protocols reuses the same device.

This matters for two reasons. Signing in twice for what is really one machine is
annoying, and more importantly every registration consumes a device seat on your
organization's account, so the old behaviour quietly burned seats every time you
changed transport.

Note that the addresses inside that identity differ per protocol, because
Cloudflare assigns them that way: a team device gets a `100.96.x.x` address for
MASQUE and a `172.16.x.x` address for WireGuard. Aether keeps both and uses
whichever the active transport needs.

### 1.4 The assigned endpoint is verified, not trusted

A team account can be handed a specific endpoint to connect to. Aether probes
that endpoint first and only uses it if it actually answers; otherwise it falls
back to a normal edge scan.

This is deliberate. Setting the assigned endpoint as a hard override would have
been simpler, but a stale or misconfigured assignment would then strand you on a
dead peer with no way out short of editing the config by hand.

### 1.5 The device profile is refreshed on startup

Aether re-fetches the device record from Cloudflare each time it starts. If an
administrator changed your addresses or your endpoint on the dashboard, the
change is picked up. Before this, the only way to see a dashboard change was to
delete the local identity file and re-enrol.

### 1.6 Gateway proxy, off by default

An organization can run all HTTP and HTTPS through its Gateway proxy so that its
filtering and logging apply. `--gateway` (or `AETHER_GATEWAY`) turns that on.

It is off by default, and that is a deliberate choice. Turning it on adds a hop
inside the tunnel, and it means your browsing is logged by the organization.
Neither is something a censorship-circumvention client should opt you into
silently. Turn it on when you actually want the organization's policy enforced.

When it is on and the proxy stops answering, Aether fails open: it logs the
problem once and sends traffic straight out of the tunnel instead of breaking
every connection on ports 80 and 443.

### 1.7 Enrolling from inside the program

No environment variables needed. The interactive menu has a fourth entry: pick
Zero Trust, type the team name, give an email, enter the code that arrives, and
you land back on the transport menu already signed in.

```
Protocol:
  [1] MASQUE (modern, QUIC/H3, default)
  [2] WireGuard (classic, faster)
  [3] WARP-in-WARP / gool
  [4] Zero Trust: sign in to an organization (WARP for teams)
Choose [1-4] (default 1):
```

A team you have enrolled in before is offered as the default and reused without
signing in again, because the device identity is already on disk and the profile
refresh uses the device's own token rather than an Access token.

A mistyped code no longer kills startup either. You get three attempts before it
gives up.

### 1.8 Smaller thing

`--warp` is accepted as an alias for `--wg` / `--wireguard`.

---

## 2. Routing rules

Not everything should go through the tunnel. Banking apps reject foreign
addresses, LAN services are unreachable through it, and some traffic you would
rather refuse outright. v1.5.0 adds two rule lists for this, in the style of
Xray's routing configuration.

- **block** — the connection is refused. The client sees a SOCKS5 failure.
- **direct** — the connection leaves through your real interface, bypassing the
  tunnel.
- Anything that matches neither is proxied, as before.

`block` is checked first, so a destination in both lists is blocked.

### 2.1 On the command line

```bash
aether --route-block ads.example.com,tracker.example.net \
       --route-direct 192.168.0.0/16,bank.example.ir
```

Entries are separated by a comma, a semicolon, or a newline. The equivalent
environment variables are `AETHER_ROUTE_BLOCK` and `AETHER_ROUTE_DIRECT`.

### 2.2 From a file

A long list does not belong on a command line. `--routes <path>` (or
`AETHER_ROUTES_FILE`) reads both lists from a file split into two sections:

```
[block]
domain:ads.example.com
keyword:tracker
port:25

[direct]
private
ip:192.168.0.0/16
domain:bank.example.ir
regexp:^.*\.example\.ir$
```

Blank lines are skipped and a line starting with `#` is a comment. Rules given
on the command line and rules from the file are combined, not overridden.

### 2.3 Rule syntax

| Prefix | Matches |
| --- | --- |
| `domain:` or `suffix:` | the domain and all subdomains |
| `full:` or `exact:` | that exact domain only |
| `keyword:` | any domain containing the substring |
| `regexp:` or `regex:` | domains matching the regular expression |
| `ip:` or `cidr:` | a single address or a CIDR block |
| `port:` | one port, or an inclusive range such as `8000-8100` |
| `private` | loopback, LAN, link-local, and CGNAT addresses, plus `localhost` |

A bare entry with no prefix is inferred: `private` is the private matcher, an
address or CIDR becomes an IP rule, and anything else becomes a domain suffix
rule. A leading `*.` is stripped, so `*.example.com` and `example.com` behave
the same.

### 2.4 TCP and UDP

Rules apply to both. Direct UDP is not smuggled back through the tunnel's relay:
it gets a dedicated socket with its own reply pump, so a direct DNS query or
QUIC session behaves like it came from the machine itself.

### 2.5 Why there are no per-application rules

This came up as a request and the answer is that the core is the wrong place for
it.

In tun mode the packets reaching Aether have already been stripped of any
application identity. There is no reliable way to recover which process a packet
came from once it is on the tun interface, so a per-app list in the core cannot
be honoured for the mode where people mostly want it.

The place that does know is the Android client, via
`VpnService.addDisallowedApplication`, which excludes chosen apps from the VPN
before their traffic ever reaches the tunnel. That is the same split Xray uses:
destination rules in the core, app rules in the platform layer.

---

## 3. Security fixes

### 3.1 SOCKS5 UDP relay accepted datagrams from anyone

The most serious one. When a client used UDP ASSOCIATE, Aether opened a relay
socket and then forwarded whatever arrived on it, from any source address.

Anything else running on the machine could send datagrams to that port and get
them relayed through your tunnel, and read the replies. With the SOCKS listener
bound to a non-loopback address, which is what the Docker image does, the same
was true for anything on the network.

The relay is now pinned to the peer that opened the TCP control connection.
Datagrams from any other source are dropped.

### 3.2 The ECH DNS resolver accepted any reply

The DNS query used to fetch the ECH configuration read the first UDP packet that
arrived on the socket and parsed it as the answer. It checked nothing: not the
transaction ID, not the question, not even whether the packet was a response.

Anyone able to send a packet to that socket, which off-path means anyone who can
guess the ephemeral port, could feed Aether an ECH configuration of their
choosing. Replies are now validated against the query: transaction ID, the
response bit, question count, the queried name compared case-insensitively, and
the record type. Non-matching replies are discarded and the socket keeps
listening until a real answer arrives or the deadline passes.

The timeout was also changed from per-receive to an absolute deadline. As it
was, a stream of junk packets reset the clock on every one, so the wait could be
extended indefinitely.

### 3.3 The tunnel health probe accepted a wrong answer

The probe that confirms a tunnel really carries traffic fetches a URL that
returns `204 No Content`, and it used to decide success by searching the raw
response bytes for the substring `204`. A response of `200 OK` carrying
`Content-Length: 204` passed. So did anything else with those three digits
anywhere in a header.

The probe now reads the status line and parses the actual status code. It also
waits for a complete line rather than the first 12 bytes, and uses an absolute
deadline instead of a per-chunk timeout, which previously let a slow drip of
bytes keep the probe alive indefinitely.

### 3.4 Container defaults

The image set `AETHER_SOCKS=0.0.0.0:1819` and the documented `docker run` lines
published it with a bare `-p 1819:1819`, which puts an open, unauthenticated
SOCKS5 proxy on every interface of the host.

The documented commands now bind it to the host loopback and keep the identity
in a named volume:

```bash
docker run -it -p 127.0.0.1:1819:1819 -v aether-data:/data ghcr.io/cluvexstudio/aether:latest
```

The guides spell out what changing that publish spec exposes. The image also
declares `AETHER_CONFIG=/data/aether.toml` and `VOLUME ["/data"]`, so the
identity survives a container restart instead of a fresh device being registered
on every run.

The in-container bind address stays `0.0.0.0:1819` on purpose: Docker publishes
a port by connecting to it from the host network namespace, so binding to
loopback inside the container would break `-p` entirely. The host-side spec is
the correct place to control exposure.

---

## 4. Reliability fixes in the data path

### 4.1 The netstack could deadlock

The user-space network stack drove its TCP and UDP sockets from an async loop
that awaited on the channels to the application and to the tunnel. If an
application stopped reading, or the outbound queue filled up, the loop blocked
inside those awaits and therefore stopped draining inbound packets from the
tunnel.

That is a circular wait. The stack waited for the application to consume, and
the application waited for the stack to deliver. Nothing broke the cycle, so a
single slow consumer could wedge the whole tunnel.

Socket servicing and the transmit flush are now synchronous and non-blocking.
They reserve capacity and give up immediately if there is none, reporting
backpressure to the loop, which retries after 2 ms. The inbound side keeps
draining throughout. Outbound packets dropped under pressure are counted and
reported every 512.

Two other things in the same loop:

- The poll delay is now capped at 250 ms whenever any connection is open, so a
  long delay computed by the stack can no longer stall timers that were due
  sooner.
- A TCP socket whose application has gone away is now closed. Previously it was
  left open, which leaked the connection.

### 4.2 The QUIC loop could spin at 100% CPU

Two `select!` branches read from channels. When a channel closed, the receive
returned `None` immediately and forever, so the branch was always ready and the
loop span as fast as the scheduler allowed, burning a core for nothing. Those
branches are now disabled once their channel is done.

### 4.3 A full inbound queue could kill the QUIC connection

Datagram draining awaited on the send to the inbound queue, from inside the QUIC
event loop. A full queue therefore stopped the loop from processing ACKs and
timeouts, so under load the connection stalled and eventually died. Delivery is
now non-blocking, and a datagram that arrives with no room is dropped, which is
the correct behaviour for a datagram transport.

### 4.4 Transient UDP errors tore down WireGuard tunnels

On a connected UDP socket the kernel reports an ICMP port-unreachable as a
`ConnectionRefused` on the *next* receive. A single one of those, or a
`WouldBlock`, or an `Interrupted`, used to end the receive loop and take the
tunnel with it. These are ordinary events on a UDP path, especially while an
endpoint is coming up.

Errors are now classified. Transient ones back off 50 ms and retry, up to 64
consecutive failures before giving up. A genuinely broken socket is still fatal.

### 4.5 Post-handshake junk was re-sent on every handshake

When the obfuscation profile asked for junk packets after the handshake, they
were sent on every handshake-complete event and each one spawned a task. The
long-lived tunnels that rehandshake periodically therefore sent junk repeatedly,
which is both wasteful and a signature. It now fires once per tunnel.

### 4.6 Background tasks could outlive their tunnel

The WireGuard tunnel aborted its four background tasks after its select
returned. Any early return skipped the cleanup and left them running. Cleanup is
now tied to a guard that aborts on drop, so it happens on every exit path.

### 4.7 gool dropped silently after an hour or two

Reported as issue #65: WARP-in-WARP ran fine for one to two hours, then traffic
stopped. The log still showed the successful startup lines and nothing else. No
error, no reconnect. Only a process restart brought it back, and
`AETHER_QUICK_RECONNECT=1` made no difference.

The cause was that gool started each tunnel as a detached background task and
then blocked on the SOCKS5 server:

- The health check did fire and the tunnel did return an error.
- That error went to a task nobody was watching, so it was logged and dropped.
- The SOCKS5 listener kept accepting connections into a tunnel that no longer
  carried traffic.
- The reconnect loop sat behind the SOCKS server, which never returns, so it
  never got control.

Plain WireGuard was never affected because it awaits the tunnel and runs SOCKS
as the background task, which is the correct way round.

Both tunnels are now supervised together with the SOCKS server. Whichever ends
first tears the other two down and returns, so the reconnect loop runs. The
outer and inner tunnels are labelled separately in the log, so a drop says which
layer failed.

Two related leaks fixed in the same path:

- Each reconnect left the previous netstack, the two UDP forwarder tasks, and
  the forwarder socket running. On a long-lived service that reconnects often,
  those accumulated. Cleanup is now tied to a guard that runs on every exit
  path.
- Rebinding the SOCKS5 listener could fail with `Address already in use`
  (`os error 98`), because the old listener task was aborted but not awaited, so
  the port was sometimes still held. The abort is now awaited before the next
  bind.

### 4.8 The MASQUE HTTP/2 capsule writer

`send_capsule` compared the wrong side of the reserved-capacity result. It could
spin in a tight loop, and it could write a capsule before the peer had granted
room for it. It now waits until the granted capacity actually covers the
capsule.

The HTTP/2 datagram framing was also settled: the Cloudflare edge expects the
bare IP packet in the capsule on the HTTP/2 path, while HTTP/3 carries a context
identifier. The receive path accepts either and validates that the payload
really is an IP packet before handing it on.

### 4.9 Log noise during scans

A TLS pin mismatch was logged as a warning on every handshake, and the
verification mode was announced on every connection. During a scan of hundreds
of candidates that buried everything useful. The mismatch is now a debug
message, and the verification mode is announced once.

---

## 5. Registration resilience

### 5.1 A camouflaged fallback for first-time registration

Registration talks to `api.cloudflareclient.com`. On networks that block or
poison it, a first-time user could never get an identity, and so could never
connect at all.

There is now a fallback path that:

- connects straight to a Cloudflare edge address with no DNS lookup, choosing
  randomly within `141.101.113.0/24` and also trying resolved addresses,
- rotates between three TLS fingerprints until one gets through:
  `split-tls12` (a TLS 1.2 profile with legacy ciphers and a fragmented
  ClientHello), `plain-tls13` (a modern profile), and `chrome` (Chrome's key
  share ordering),
- speaks HTTP/1.1 itself, handling chunked responses, and reports a rejection
  status rather than hiding it behind a generic failure.

### 5.2 Retries with backoff

Registration and profile calls retried nothing. A single transient error failed
the whole startup. They now retry with backoff and honour a `Retry-After`
response header instead of hammering the API.

---

## 6. Endpoint discovery

### 6.1 Missing Zero Trust ranges

Zero Trust accounts are handed edge addresses outside the consumer ranges, so
scanning never found them. Added:

- `162.159.193.0/24` and `2606:4700:100::/48` to the WireGuard ranges, with
  `162.159.193.1` as a seed,
- UDP port `4500` to the MASQUE port list.

### 6.2 Scan order now follows the documentation

Someone reported that the scan order was wrong, and it was. Two things matter
about these tables: the first port in the list becomes the primary port for the
entire sweep, and the ranges are probed round-robin in list order, so whatever
sits at the front gets the scan budget.

Cloudflare's
[client firewall reference](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/)
documents the following. Content was rephrased for compliance with licensing
restrictions.

| | WireGuard | MASQUE |
| --- | --- | --- |
| IPv4 | `162.159.193.0/24` | `162.159.197.0/24` |
| IPv6 | `2606:4700:100::/48` | `2606:4700:102::/48` |
| Default port | UDP `2408` | UDP `443` |
| Fallback ports | UDP `500`, `1701`, `4500` | UDP `500`, `1701`, `4500`, `4443`, `8443`, `8095`, TCP `443` |

The same page notes that `162.159.192.0/24` is the consumer WARP range rather
than a Zero Trust requirement, and lists `162.159.36.1` and `162.159.46.1` as
DNS-over-HTTPS addresses.

What was wrong and what changed:

- **WireGuard swept UDP 500 as its primary port.** The documented default is
  `2408`, which was buried in the middle of the port list. `2408` now leads,
  followed by the documented fallbacks `500`, `1701`, `4500`, then the observed
  ports.
- **MASQUE led with two DNS-over-HTTPS ranges.** `162.159.36.0/24` and
  `162.159.46.0/24` serve DoH over TCP and will never answer a MASQUE handshake,
  yet they were probed first while the documented ingress range
  `162.159.197.0/24` sat seventh. `162.159.197.0/24` now leads and the two DoH
  ranges are swept last. They are kept rather than deleted, since a wasted probe
  at the end of the list costs nothing.
- **MASQUE IPv6 had the documented range last.** `2606:4700:102::/48` now leads.
- **The documented range was not in the seed list.** `162.159.197.3` is now the
  first seed. Cloudflare documents it as the address the client uses for its
  outside-tunnel connectivity check, which makes it a known-live probe target.
- **MASQUE fallback ports were out of documented order.** Now `443`, `500`,
  `1701`, `4500`, `4443`, `8443`, `8095`.

The consumer ranges stay first by default, because connecting without `--team`
is the default mode. When a team is configured, the Zero Trust ranges are
promoted to the front of both the IPv4 and IPv6 lists, without dropping any
entry.

Tests lock in the leading port, the leading range for each protocol and address
family, the documented fallback order, the DoH ranges staying at the tail, and
that promotion never loses a prefix. Every prefix and seed is also parsed, so a
typo in a future edit fails the build rather than silently shrinking the search
space.

---

## 7. Dependency updates

### 7.1 quiche 0.29.2 to 0.29.3

The vendored quiche was updated, which brings three upstream fixes:

- The path-event queue is bounded. A peer rotating source ports could previously
  grow it without limit, which is a memory-exhaustion vector. A regression test
  covers the port-rotation case.
- HTTP/3 QPACK now accounts for the 32-byte per-field overhead when checking a
  field section against the announced maximum, so an oversized section is
  rejected as the specification requires.
- The maximum priority-update size is enforced.

Two local patches were reapplied on top: the minimum client Initial length stays
at 1242 bytes, and the boring dependency stays on the version the rest of the
tree uses.

### 7.2 h2 pinned

`h2` was on a floating minor version, so a release build could pick up a
different HTTP/2 implementation than the one that was tested. It is now pinned
to an exact version.

---

## 8. Installer and container

### 8.1 The installer ignored an unsupported architecture

`detect_arch` ran inside a command substitution, so its `exit 1` on an
unrecognised machine only exited the subshell. The script carried on and tried
to download an asset whose name was missing the architecture. The check now
happens in the caller, which can actually stop.

Every install step is also checked. In particular, failing to overwrite the
binary now says so and points out that a running aether holds it busy, instead
of reporting success and leaving the old version in place.

### 8.2 Container

Covered in [3.4](#34-container-defaults): `AETHER_CONFIG`, `VOLUME ["/data"]`,
`EXPOSE 1819`, and corrected `docker run` lines throughout the documentation.

---

## 9. Reference: new flags and environment variables

### Zero Trust

| Flag | Environment variable | Meaning |
| --- | --- | --- |
| `--team <name>` | `AETHER_TEAM` | enrol into this Zero Trust organization |
| `--access-email <addr>` | `AETHER_ACCESS_EMAIL` | sign in with a one-time code sent to this address |
| `--access-id <id>` | `AETHER_ACCESS_CLIENT_ID` | service token client id |
| `--access-secret <secret>` | `AETHER_ACCESS_CLIENT_SECRET` | service token client secret |
| `--access-token <jwt>` | `AETHER_ACCESS_TOKEN` | an enrolment token you already hold |
| `--gateway` | `AETHER_GATEWAY` | send HTTP and HTTPS through the organization's Gateway proxy (off by default) |

`--organization` is accepted as an alias for `--team`, and `AETHER_TEAM_ENDPOINT`
overrides the endpoint for a team connection.

### Routing

| Flag | Environment variable | Meaning |
| --- | --- | --- |
| `--route-block <list>` | `AETHER_ROUTE_BLOCK` | refuse these destinations |
| `--route-direct <list>` | `AETHER_ROUTE_DIRECT` | send these outside the tunnel |
| `--routes <path>` | `AETHER_ROUTES_FILE` | read both lists from a file |

### Other

| Flag | Environment variable | Meaning |
| --- | --- | --- |
| `--dns <list>` | `AETHER_DNS` | resolvers used inside the tunnel, default `1.1.1.1,1.0.0.1` |
| `--warp` | — | alias for `--wg` |

---

## 10. Known issues

**A team identity file disappeared once.** During testing an
`aether-team-<name>.toml` vanished between two runs without a `.toml.corrupt`
file being written, which is the path the code takes when it rejects a config it
cannot parse. It has not been reproduced and the cause is not known, so it is
recorded here rather than claimed as fixed. Losing the file costs a re-enrolment
and a device seat, not any traffic.

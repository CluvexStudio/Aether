use std::env;

const USAGE: &str = "\
Aether — a censorship circumvention client. It finds a way out of a filtered
network, opens an encrypted tunnel, and serves it as a local SOCKS5 proxy.

Usage:
  aether [OPTIONS]
  aether help              show this text

Run it with no options and it asks for what it needs: protocol, scan mode, IP
version. Every question has a flag, and every flag has an environment variable
of its own. Setting either one is what stops the question being asked, and a
flag beats a variable.

  aether                                   answer the questions as they come
  aether --masque --turbo -4               nothing asked, straight to work
  aether --wg --thorough --noize gfw       classic wireguard on a strict network
  aether --gool --wiw-outer 162.159.192.1:2408 --wiw-inner 188.114.96.1:2408
  aether --mim                             two masque hops, for a different exit

Connection:
  --bind <addr>            local SOCKS5 listen address (default 127.0.0.1:1819)
  --http-proxy <addr>      also expose an HTTP CONNECT proxy on this address
                           (off by default, e.g. 127.0.0.1:1820)
  --upstream <url>         dial out through a proxy already running here, e.g.
                           socks5://127.0.0.1:1080 or http://user:pass@host:8080
  --mark <n>               put this firewall mark (SO_MARK) on every socket aether
                           opens to the internet, e.g. 0xff, so a tun front end on
                           the same Linux router can let them past instead of
                           looping them back in (Linux and Android, needs root or
                           CAP_NET_ADMIN)
  --exit-loc <spec>        refuse a tunnel whose exit country is not wanted, checked
                           through the finished tunnel before socks5 opens and again
                           every minute after: !IR,AZ,RU blocks those, DE,SE allows
                           only those. Off unless you pass this flag: without it
                           nothing is looked up and no tunnel is refused
  --exit-loc-secs <n>      how often to recheck the exit country (default 60)
  --stats                  log how much has gone up and down and how long the
                           tunnel has been up (off by default)
  --stats-secs <n>         how often to log that line (default 60)
  --quick-reconnect        auto-accept reconnecting with the last known working gateway
  --no-quick-reconnect     always scan fresh, ignore any saved last-connection gateway
  -4                       scan/connect over IPv4 only (default)
  -6                       scan/connect over IPv6 only
  --dual                   scan/connect over both IPv4 and IPv6
  --ip <v4|v6|both>        the same choice written out
  --peer <ip:port>         force a MASQUE/WireGuard peer, skip scanning
  --wg-peer <ip:port>      force a WireGuard peer (warp-in-warp outer), skip scanning

Protocol:
  --masque                 use MASQUE over QUIC/HTTP-3 (default)
  --wg, --wireguard, --warp
                           use classic WireGuard
  --gool, --wiw            use WARP-in-WARP (wireguard tunneled in wireguard)
  --mim, --masque-in-masque
                           use MASQUE-in-MASQUE: a masque tunnel carried inside
                           another one, which changes the address you come out
                           of the way gool does, on the same carrier for both
                           hops (HTTP/3 in HTTP/3, or --h2 for HTTP/2 in HTTP/2)
  --protocol <name>        masque | wg | gool | mim

WARP-in-WARP endpoints:
  Both hops are found by the scan unless you name them here. The port is
  required: which port gets through is exactly what differs between networks,
  so none is assumed for you. Name one hop and the scan finds the other,
  keeping your address out of the sweep. The two hops must be different
  addresses, and naming one selects warp-in-warp on its own, so --gool
  alongside is optional.
  --wiw-outer <ip:port>    the outer hop, the one your network sees
  --wiw-inner <ip:port>    the inner hop, reached through the outer one
  --wiw-peers <out[,in]>   both hops in one value, or only the outer one
  --wiw-scan               scan for both, ignoring any endpoint left in the
                           environment

MASQUE-in-MASQUE endpoints:
  The outer hop is found by the scan and the inner one is picked for you, both
  unless you name them here. The port is required, and the two hops must be
  different addresses. Naming one selects masque-in-masque on its own.
  --mim-outer <ip:port>    the outer hop, the one your network sees
  --mim-inner <ip:port>    the inner hop, reached through the outer one
  --mim-peers <out[,in]>   both hops in one value, or only the outer one
  --mim-scan               find the outer hop by scanning, ignoring any endpoint
                           left in the environment

Scan mode:
  --scan <mode>            turbo | balanced | thorough | verified | ironclad
  --turbo                  stop at the first candidate that answers
  --balanced               default: collect a few, keep the fastest
  --thorough               sweep whole ranges, for when everything looks blocked
  --verified               dial only the edges measured to answer connect-ip,
                           never a guessed neighbour. On --gool and --mim it also
                           keeps the two hops in separate ranges, which is what
                           moves the exit address; the plain modes are untouched
  --ironclad               open a real tunnel and make a real HTTP request per
                           candidate, so a gateway is only trusted once it has
                           genuinely carried traffic

Obfuscation:
  --noize <profile>        off | light | firewall | balanced | gfw | aggressive
                           firewall is the default for MASQUE, balanced for
                           WireGuard and gool; reach for gfw when the default
                           does not get through

MASQUE transport:
  --h2, --http2            use HTTP/2 (TCP) instead of HTTP/3 (QUIC)
  --h3, --quic             use HTTP/3 (QUIC), without asking
  --no-quic-v2             do not send the QUIC v2 version-negotiation opener
                           (it is on by default; it opens a path for HTTP/3 on
                           networks that block QUIC v1 but let QUIC v2 through)
  --h2-peer <ip:port>      override the peer used for the HTTP/2 transport
  --ech <auto|base64>      enable Encrypted Client Hello
  --no-data-check          skip the end-to-end data-plane validation
  --validate-secs <n>      seconds to wait for data-plane validation (default 10)
  --startup-secs <n>       total MASQUE startup deadline (default 30)
  --reconnect-secs <n>     delay before reconnecting after a tunnel drop (default 2)
  --dns <list>             resolvers used inside the tunnel (default 1.1.1.1,1.0.0.1)
  --fragment               fragment the TLS ClientHello on the HTTP/2 transport
  --fragment-size <n|a-b>  fragment chunk size in bytes (default 16-32)
  --fragment-delay <n|a-b> delay between fragments in ms (default 2-10)

WireGuard:
  --keepalive <n>          persistent keepalive interval in seconds (default 5)
  --no-profile-retry       don't retry other obfuscation profiles during scan

Tor:
  Three ways to use tor, all needing a build made with the tor feature:
  cargo build --release --features tor

  --tor                    carry tor inside the tunnel: aether -> warp -> tor ->
                           internet. The usual proxy keeps the warp exit and a
                           second one, on --tor-bind, comes out of tor. Any
                           transport carries it, with nothing in between, so
                           --wg --tor has the wireguard tunnel carry tor itself
  --tor-reverse            the other way round: dial the tunnel through tor, so
                           warp is reached from a tor exit and your network never
                           sees warp. Tor carries tcp only and the wireguard
                           endpoints of warp answer on udp alone, so this runs
                           masque over http/2 and refuses --wg and --gool
  --tor-only               no tunnel at all: the proxy on --bind is plain tor
  --tor-bind <addr>        where the tor proxy listens with --tor and
                           --tor-reverse (default 127.0.0.1:1820)
  --tor-http <addr>        also serve tor as an http/connect proxy here, for
                           clients that cannot speak socks5 (off by default)
  --tor-bridge-file <path> read bridge lines from this file, one per line, the
                           same shape torrc uses; blank lines and # are skipped
  --tor-relays <what>      running tor relays from onionoo, used as plain
                           bridges: auto (default, alongside bridgedb), only,
                           off, or a count such as 80. bridgedb hands out a
                           handful of bridges that are enumerated and blocked
                           early; onionoo lists every running relay, which is a
                           far larger pool to measure against
  --tor-relay-ports <set>  which relay ports to consider: web (default, only
                           80 and 443, the ports a restrictive firewall tends
                           to leave open) or any. the ports tor itself is known
                           for are always skipped
  --tor-dir <path>         where tor keeps its directory cache and state
                           (default <config>-tor beside the identity file)

  --psiphon                carry psiphon inside the tunnel: aether -> warp ->
                           psiphon -> internet, served on --psiphon-bind
  --psiphon-reverse        the other way round: dial the tunnel through psiphon.
                           psiphon carries tcp only, so this runs masque over
                           http/2 and refuses --wg and --gool
  --psiphon-only           no tunnel at all: the proxy on --bind is plain psiphon
  --psiphon-mode <shape>   auto (default, let psiphon pick), cdn (only fronted
                           meek through a cdn, for networks that block the rest)
                           or direct (no fronting)
  --psiphon-config <path>  a psiphon json config of your own, laid over the
                           built-in one. only needed to use different
                           credentials or server list settings
  --psiphon-cdn-ips <list> addresses to try as cdn fronting edges, comma or
                           space separated. left empty, the list built into
                           psiphon is used
  --psiphon-cdn-sni <list> server names to present to those edges
  --psiphon-bind <addr>    where the psiphon proxy listens with --psiphon and
                           --psiphon-reverse (default 127.0.0.1:1821)
  --psiphon-http <addr>    also serve psiphon as an http/connect proxy here
  --psiphon-region <cc>    ask psiphon to leave from this country, e.g. DE. the
                           log lists what is on offer as AvailableEgressRegions
  --psiphon-dir <path>     where psiphon keeps its data (default
                           <config>-psiphon beside the identity file)
  --psiphon-bin <path>     the psiphon-tunnel-core binary to run, when it is not
                           next to aether, in ./pt, or on PATH

  On a network that blocks tor, aether fetches its own bridges from bridgedb and
  finds the pluggable transports already on this machine, tor browser's included.
  Nothing below is needed for that; it is there to override what it picks.

  --tor-bridges            go to bridges at once, without trying tor plainly first
  --no-tor-bridges         never use bridges, however blocked the network looks
  --tor-bridge <line>      a bridge line of your own, instead of the fetched ones.
                           Repeat it for more than one, e.g.
                           --tor-bridge \"obfs4 1.2.3.4:443 FINGERPRINT cert=... iat-mode=0\"
  --tor-pt [name=]<path>   the pluggable transport binary a bridge needs, e.g.
                           --tor-pt /usr/bin/lyrebird (obfs4 is assumed) or
                           --tor-pt snowflake=/usr/bin/snowflake-client
  --tor-pt-dir <path>      another folder to look in for those binaries

Zero Trust (WARP for organizations):
  --team <name>            enrol into a Zero Trust organization by team name
  --access-id <id>         service token client id (headless enrolment)
  --access-secret <secret> service token client secret (headless enrolment)
  --access-email <addr>    sign in with a one-time code emailed to this address
  --access-token <jwt>     an enrolment token you already obtained by signing in
                           at https://<team>.cloudflareaccess.com/warp
  --gateway                send http and https through the organization's gateway
                           proxy so its filtering and logging apply (off by default:
                           it adds a hop inside the tunnel and logs your browsing)

Routing (which traffic goes where):
  --route-block <list>     never let these reach the network at all
  --route-direct <list>    send these straight out, bypassing the tunnel
  --routes <path>          load both lists from a file with [block] and [direct]
                           sections
                           list entries are comma or newline separated and may be:
                             example.com          the name and every subdomain
                             full:example.com     that exact name only
                             keyword:doubleclick  any name containing it
                             regexp:^ad[0-9]+     a regular expression
                             10.0.0.0/8           a network, or a bare address
                             port:25              a port, or port:3000-3010
                             private              lan, loopback and cgnat space
                           block is checked first, then direct, otherwise the
                           tunnel is used

Config files:
  --config <path>          base identity config path (default aether.toml)
  --wg-config <path>       identity config path for WireGuard
  --masque-config <path>   identity config path for MASQUE
                           warp-in-warp adds a second identity of its own beside
                           the wireguard one, named <config>-secondary.toml

Advanced:
  --tls-groups <list>      TLS key share groups, e.g. \"P-256:X25519:P-384\"
  --perf <low|medium|high> force a resource profile instead of auto-detecting from cpu/ram
                           (low: routers/small boards, medium: typical desktop, high: servers)
  --log-level <level>      error | warn | info | debug | trace (default info)
                           info: connection stages, validation, reconnects, retries
                           debug: adds per-tunnel internals useful for troubleshooting
                           trace: everything, including per-packet noise
  --verbose                shortcut for --log-level debug (RUST_LOG overrides both)

  -v, --version            show version and exit
  -h, --help, help         show this help and exit

Environment variables:
  Every flag above has one, for scripts and services. The last few have no flag
  of their own.

  AETHER_SOCKS                     --bind
  AETHER_HTTP_PROXY                --http-proxy
  AETHER_UPSTREAM                  --upstream
  AETHER_MARK                      --mark
  AETHER_STATS                     --stats
  AETHER_STATS_SECS                --stats-secs
  AETHER_EXIT_LOC                  --exit-loc
  AETHER_EXIT_LOC_SECS             --exit-loc-secs
  AETHER_TOR                       chain for --tor, reverse, or only
  AETHER_TOR_BRIDGES               --tor-bridge, several separated by ;
                                   auto for --tor-bridges, off for --no-tor-bridges
  AETHER_TOR_PT                    --tor-pt, several separated by ;
  AETHER_TOR_PT_DIR                --tor-pt-dir, several separated by ;
  AETHER_TOR_BIND                  --tor-bind
  AETHER_TOR_HTTP                  --tor-http
  AETHER_TOR_BRIDGE_FILE           --tor-bridge-file
  AETHER_TOR_RELAYS                --tor-relays
  AETHER_TOR_RELAY_PORTS           --tor-relay-ports
  AETHER_PSIPHON                   --psiphon (chain), --psiphon-reverse,
                                   --psiphon-only
  AETHER_PSIPHON_CONFIG            --psiphon-config
  AETHER_PSIPHON_MODE              --psiphon-mode
  AETHER_PSIPHON_CDN_IPS           --psiphon-cdn-ips
  AETHER_PSIPHON_CDN_SNI           --psiphon-cdn-sni
  AETHER_PSIPHON_BIND              --psiphon-bind
  AETHER_PSIPHON_HTTP              --psiphon-http
  AETHER_PSIPHON_REGION            --psiphon-region
  AETHER_PSIPHON_DIR               --psiphon-dir
  AETHER_PSIPHON_BIN               --psiphon-bin
  AETHER_PSIPHON_READY_SECS        how long to wait for psiphon to tunnel (180)
  AETHER_TOR_DIR                   --tor-dir
  AETHER_TOR_DIRECT_SECS           how long to try tor plainly before bridges (75)
  AETHER_TOR_STALL_SECS            give up on a bridge after this long with no
                                   headway, however far it got (75)
  AETHER_TOR_BRIDGE_SECS           the longest any one bridge may take (360)
  AETHER_TOR_COUNTRY               ask bridgedb for this country, e.g. ir
  AETHER_TOR_CHECK                 host:port tor must reach before it counts as
                                   working (check.torproject.org:443)
  AETHER_TOR_LOG                   how loud tor is: info, debug or trace
  AETHER_QUICK_RECONNECT           1 or 0, for --quick-reconnect
  AETHER_IP                        --ip: v4, v6 or both
  AETHER_PEER                      --peer
  AETHER_WG_PEER                   --wg-peer
  AETHER_PROTOCOL                  --protocol: masque, wg, gool or mim
  AETHER_WIW_OUTER_PEER            --wiw-outer
  AETHER_WIW_INNER_PEER            --wiw-inner
  AETHER_WIW_PEERS                 --wiw-peers, or auto for --wiw-scan
  AETHER_MIM_OUTER_PEER            --mim-outer
  AETHER_MIM_INNER_PEER            --mim-inner
  AETHER_MIM_PEERS                 --mim-peers, or auto for --mim-scan
  AETHER_SCAN                      --scan
  AETHER_NOIZE                     --noize
  AETHER_MASQUE_HTTP2              --h2 (1), or --h3 (0)
  AETHER_QUIC_V2                   0 for --no-quic-v2 (the opener is on by default)
  AETHER_MASQUE_H2_PEER            --h2-peer
  AETHER_ECH                       --ech
  AETHER_MASQUE_NO_DATA_CHECK      --no-data-check, MASQUE side
  AETHER_WG_NO_DATA_CHECK          --no-data-check, WireGuard side
  AETHER_MASQUE_VALIDATE_SECS      --validate-secs, MASQUE side
  AETHER_WG_VALIDATE_SECS          --validate-secs, WireGuard side
  AETHER_MASQUE_STARTUP_SECS       --startup-secs
  AETHER_MASQUE_RECONNECT_SECS     --reconnect-secs, MASQUE side
  AETHER_WG_RECONNECT_SECS         --reconnect-secs, WireGuard side
  AETHER_DNS                       --dns
  AETHER_MASQUE_H2_FRAGMENT        --fragment
  AETHER_MASQUE_H2_FRAGMENT_SIZE   --fragment-size
  AETHER_MASQUE_H2_FRAGMENT_DELAY  --fragment-delay
  AETHER_WG_KEEPALIVE              --keepalive
  AETHER_WG_NO_PROFILE_RETRY       --no-profile-retry
  AETHER_TEAM                      --team
  AETHER_ACCESS_CLIENT_ID          --access-id
  AETHER_ACCESS_CLIENT_SECRET      --access-secret
  AETHER_ACCESS_TOKEN              --access-token
  AETHER_ACCESS_EMAIL              --access-email
  AETHER_GATEWAY                   --gateway
  AETHER_ROUTE_BLOCK               --route-block
  AETHER_ROUTE_DIRECT              --route-direct
  AETHER_ROUTES_FILE               --routes
  AETHER_CONFIG                    --config
  AETHER_WG_CONFIG                 --wg-config
  AETHER_MASQUE_CONFIG             --masque-config
  AETHER_TLS_GROUPS                --tls-groups
  AETHER_PERF_PROFILE              --perf
  AETHER_LOG_LEVEL                 --log-level

  AETHER_ROUTE_SNIFF               0 to stop reading the server name from the
                                   first bytes of a connection (on by default,
                                   which is what makes routing rules work behind
                                   a tun front end)
  AETHER_ROUTE_SNIFF_MS            how long to wait for those bytes (default 400)
  AETHER_WG_ENDPOINT_COOLDOWN_SECS how long an endpoint that failed twice is left
                                   out of rescans (default 300)
  AETHER_WG_STALE_SECS             silence on a wireguard tunnel before it counts
                                   as dead (default 10)
  AETHER_MASQUE_H2_KEEPALIVE_SECS  HTTP/2 keepalive interval (default 15)
  AETHER_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS
                                   how long a keepalive may go unanswered (default 20)
  AETHER_IRONCLAD_PORT             port the ironclad scan makes its real HTTP
                                   request to (default 80)
  AETHER_MAX_CLIENTS               proxy clients served at once; past it new ones
                                   wait for a free slot (default by resources,
                                   512 to 8192)
  AETHER_HALF_CLOSE_SECS           how long a connection the client has finished
                                   sending on may sit silent before it is closed
                                   (default 30)
  AETHER_TCP_KEEPALIVE_SECS        idle time before a keep-alive checks that the
                                   other end of a connection is still there;
                                   three unanswered ones close it (default 60)
  AETHER_TCP_CONNECT_SECS          how long a connection through the tunnel may
                                   take to open (default 30)
  AETHER_REPROVISION               0 to stop replacing an identity Cloudflare has
                                   refused with a freshly registered one
  RUST_LOG                         standard rust log filter; overrides --log-level

After startup the proxy is at the address --bind names, 127.0.0.1:1819 by
default. Check it with:

  curl -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace

The reply should show a Cloudflare colo and warp=on. The proxy has no
authentication, so bind it to 0.0.0.0 only when you mean to share the tunnel
with your network.
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed {
    Run,
    Done,
}

pub fn parse_and_apply() -> crate::error::Result<Parsed> {
    parse_args(env::args().skip(1).collect())
}

pub fn parse_args(args: Vec<String>) -> crate::error::Result<Parsed> {
    let mut i = 0;

    while i < args.len() {
        let arg = args[i].as_str();

        macro_rules! next_value {
            () => {{
                i += 1;
                args.get(i).ok_or_else(|| {
                    crate::error::AetherError::Other(format!("{arg} requires a value"))
                })?
            }};
        }

        match arg {
            "-v" | "--version" => {
                println!("aether {}", env!("CARGO_PKG_VERSION"));
                return Ok(Parsed::Done);
            }

            "-h" | "--help" | "help" => {
                print!("{USAGE}");
                return Ok(Parsed::Done);
            }

            "--bind" => set("AETHER_SOCKS", next_value!()),
            "--http-proxy" => set("AETHER_HTTP_PROXY", next_value!()),
            "--upstream" => set("AETHER_UPSTREAM", next_value!()),
            "--tor" => set("AETHER_TOR", "chain"),
            "--tor-reverse" => set("AETHER_TOR", "reverse"),
            "--tor-only" => set("AETHER_TOR", "only"),
            "--tor-bridge" => append("AETHER_TOR_BRIDGES", next_value!()),
            "--tor-bridges" => set("AETHER_TOR_BRIDGES", "auto"),
            "--tor-bridge-file" => set("AETHER_TOR_BRIDGE_FILE", next_value!()),
            "--tor-relays" => set("AETHER_TOR_RELAYS", next_value!()),
            "--tor-relay-ports" => set("AETHER_TOR_RELAY_PORTS", next_value!()),
            "--no-tor-bridges" => set("AETHER_TOR_BRIDGES", "off"),
            "--tor-pt" => append("AETHER_TOR_PT", next_value!()),
            "--tor-pt-dir" => append("AETHER_TOR_PT_DIR", next_value!()),
            "--tor-bind" => set("AETHER_TOR_BIND", next_value!()),
            "--tor-http" => set("AETHER_TOR_HTTP", next_value!()),
            "--tor-dir" => set("AETHER_TOR_DIR", next_value!()),
            "--psiphon" => set("AETHER_PSIPHON", "chain"),
            "--psiphon-reverse" => set("AETHER_PSIPHON", "reverse"),
            "--psiphon-only" => set("AETHER_PSIPHON", "only"),
            "--psiphon-config" => set("AETHER_PSIPHON_CONFIG", next_value!()),
            "--psiphon-bind" => set("AETHER_PSIPHON_BIND", next_value!()),
            "--psiphon-http" => set("AETHER_PSIPHON_HTTP", next_value!()),
            "--psiphon-region" => set("AETHER_PSIPHON_REGION", next_value!()),
            "--psiphon-mode" => set("AETHER_PSIPHON_MODE", next_value!()),
            "--psiphon-cdn-ips" => set("AETHER_PSIPHON_CDN_IPS", next_value!()),
            "--psiphon-cdn-sni" => set("AETHER_PSIPHON_CDN_SNI", next_value!()),
            "--psiphon-dir" => set("AETHER_PSIPHON_DIR", next_value!()),
            "--psiphon-bin" => set("AETHER_PSIPHON_BIN", next_value!()),
            "--mark" => set("AETHER_MARK", next_value!()),
            "--exit-loc" => set("AETHER_EXIT_LOC", next_value!()),
            "--exit-loc-secs" => set("AETHER_EXIT_LOC_SECS", next_value!()),
            "--stats" => set("AETHER_STATS", "1"),
            "--stats-secs" => set("AETHER_STATS_SECS", next_value!()),
            "--quick-reconnect" => set("AETHER_QUICK_RECONNECT", "1"),
            "--no-quick-reconnect" => set("AETHER_QUICK_RECONNECT", "0"),

            "-4" => set("AETHER_IP", "v4"),
            "-6" => set("AETHER_IP", "v6"),
            "--dual" => set("AETHER_IP", "both"),
            "--ip" => set("AETHER_IP", next_value!()),

            "--peer" => set("AETHER_PEER", next_value!()),
            "--wg-peer" => set("AETHER_WG_PEER", next_value!()),

            "--wiw-outer" | "--gool-outer" | "--outer-peer" => {
                set("AETHER_WIW_OUTER_PEER", next_value!())
            }
            "--wiw-inner" | "--gool-inner" | "--inner-peer" => {
                set("AETHER_WIW_INNER_PEER", next_value!())
            }
            "--wiw-peers" | "--gool-peers" => set("AETHER_WIW_PEERS", next_value!()),
            "--wiw-scan" | "--gool-scan" => set("AETHER_WIW_PEERS", "auto"),

            "--masque" => set("AETHER_PROTOCOL", "masque"),
            "--wg" | "--wireguard" | "--warp" => set("AETHER_PROTOCOL", "wg"),
            "--gool" | "--wiw" => set("AETHER_PROTOCOL", "gool"),
            "--mim" | "--masque-in-masque" => set("AETHER_PROTOCOL", "mim"),
            "--mim-outer" => set("AETHER_MIM_OUTER_PEER", next_value!()),
            "--mim-inner" => set("AETHER_MIM_INNER_PEER", next_value!()),
            "--mim-peers" => set("AETHER_MIM_PEERS", next_value!()),
            "--mim-scan" => set("AETHER_MIM_PEERS", "auto"),
            "--protocol" => set("AETHER_PROTOCOL", next_value!()),

            "--scan" => set("AETHER_SCAN", next_value!()),
            "--turbo" => set("AETHER_SCAN", "turbo"),
            "--balanced" => set("AETHER_SCAN", "balanced"),
            "--thorough" => set("AETHER_SCAN", "thorough"),
            "--verified" | "--stealth" => set("AETHER_SCAN", "verified"),
            "--ironclad" => set("AETHER_SCAN", "ironclad"),

            "--noize" => set("AETHER_NOIZE", next_value!()),

            "--h2" | "--http2" => set("AETHER_MASQUE_HTTP2", "1"),
            "--h3" | "--quic" => set("AETHER_MASQUE_HTTP2", "0"),
            "--no-quic-v2" => set("AETHER_QUIC_V2", "0"),
            "--h2-peer" => set("AETHER_MASQUE_H2_PEER", next_value!()),
            "--ech" => set("AETHER_ECH", next_value!()),
            "--no-data-check" => {
                set("AETHER_MASQUE_NO_DATA_CHECK", "1");
                set("AETHER_WG_NO_DATA_CHECK", "1");
            }
            "--validate-secs" => {
                let value = next_value!().clone();
                set("AETHER_MASQUE_VALIDATE_SECS", &value);
                set("AETHER_WG_VALIDATE_SECS", &value);
            }
            "--startup-secs" => set("AETHER_MASQUE_STARTUP_SECS", next_value!()),
            "--reconnect-secs" => {
                let value = next_value!().clone();
                set("AETHER_MASQUE_RECONNECT_SECS", &value);
                set("AETHER_WG_RECONNECT_SECS", &value);
            }
            "--dns" => set("AETHER_DNS", next_value!()),
            "--fragment" => set("AETHER_MASQUE_H2_FRAGMENT", "1"),
            "--fragment-size" => set("AETHER_MASQUE_H2_FRAGMENT_SIZE", next_value!()),
            "--fragment-delay" => set("AETHER_MASQUE_H2_FRAGMENT_DELAY", next_value!()),

            "--keepalive" => set("AETHER_WG_KEEPALIVE", next_value!()),
            "--no-profile-retry" => set("AETHER_WG_NO_PROFILE_RETRY", "1"),

            "--config" => set("AETHER_CONFIG", next_value!()),
            "--wg-config" => set("AETHER_WG_CONFIG", next_value!()),
            "--masque-config" => set("AETHER_MASQUE_CONFIG", next_value!()),

            "--team" | "--organization" => set("AETHER_TEAM", next_value!()),
            "--access-id" => set("AETHER_ACCESS_CLIENT_ID", next_value!()),
            "--access-secret" => set("AETHER_ACCESS_CLIENT_SECRET", next_value!()),
            "--access-token" => set("AETHER_ACCESS_TOKEN", next_value!()),
            "--access-email" => set("AETHER_ACCESS_EMAIL", next_value!()),
            "--gateway" => set("AETHER_GATEWAY", "1"),

            "--route-block" => set("AETHER_ROUTE_BLOCK", next_value!()),
            "--route-direct" => set("AETHER_ROUTE_DIRECT", next_value!()),
            "--routes" => set("AETHER_ROUTES_FILE", next_value!()),

            "--tls-groups" => set("AETHER_TLS_GROUPS", next_value!()),
            "--perf" => set("AETHER_PERF_PROFILE", next_value!()),
            "--log-level" => set("AETHER_LOG_LEVEL", next_value!()),
            "--verbose" => set("AETHER_LOG_LEVEL", "debug"),

            other => {
                return Err(crate::error::AetherError::Other(format!(
                    "unknown option '{other}'\n\n{USAGE}"
                )));
            }
        }

        i += 1;
    }

    Ok(Parsed::Run)
}

fn set(key: &str, value: &str) {
    std::env::set_var(key, value);
}

fn append(key: &str, value: &str) {
    match std::env::var(key) {
        Ok(existing) if !existing.trim().is_empty() => {
            std::env::set_var(key, format!("{existing};{value}"))
        }
        _ => std::env::set_var(key, value),
    }
}

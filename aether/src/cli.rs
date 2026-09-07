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

Connection:
  --bind <addr>            local SOCKS5 listen address (default 127.0.0.1:1819)
  --http-proxy <addr>      also expose an HTTP CONNECT proxy on this address
                           (off by default, e.g. 127.0.0.1:1820)
  --upstream <url>         dial out through a proxy already running here, e.g.
                           socks5://127.0.0.1:1080 or http://user:pass@host:8080
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
  --protocol <name>        masque | wg | gool

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

Scan mode:
  --scan <mode>            turbo | balanced | thorough | stealth | ironclad
  --turbo                  stop at the first candidate that answers
  --balanced               default: collect a few, keep the fastest
  --thorough               sweep whole ranges, for when everything looks blocked
  --stealth                few probes in flight, for networks that notice scanning
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
  AETHER_QUICK_RECONNECT           1 or 0, for --quick-reconnect
  AETHER_IP                        --ip: v4, v6 or both
  AETHER_PEER                      --peer
  AETHER_WG_PEER                   --wg-peer
  AETHER_PROTOCOL                  --protocol: masque, wg or gool
  AETHER_WIW_OUTER_PEER            --wiw-outer
  AETHER_WIW_INNER_PEER            --wiw-inner
  AETHER_WIW_PEERS                 --wiw-peers, or auto for --wiw-scan
  AETHER_SCAN                      --scan
  AETHER_NOIZE                     --noize
  AETHER_MASQUE_HTTP2              --h2
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
  AETHER_PROBE_JITTER_MS           max random delay per probe, smooths scan
                                   bursts on hostile networks (default 0)
  AETHER_MASQUE_H2_KEEPALIVE_SECS  HTTP/2 keepalive interval (default 15)
  AETHER_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS
                                   how long a keepalive may go unanswered (default 20)
  AETHER_IRONCLAD_PORT             port the ironclad scan makes its real HTTP
                                   request to (default 80)
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

pub fn parse_and_apply() -> crate::error::Result<()> {
    parse_args(env::args().skip(1).collect())
}

pub fn parse_args(args: Vec<String>) -> crate::error::Result<()> {
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
                std::process::exit(0);
            }

            "-h" | "--help" | "help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }

            "--bind" => set("AETHER_SOCKS", next_value!()),
            "--http-proxy" => set("AETHER_HTTP_PROXY", next_value!()),
            "--upstream" => set("AETHER_UPSTREAM", next_value!()),
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
            "--protocol" => set("AETHER_PROTOCOL", next_value!()),

            "--scan" => set("AETHER_SCAN", next_value!()),
            "--turbo" => set("AETHER_SCAN", "turbo"),
            "--balanced" => set("AETHER_SCAN", "balanced"),
            "--thorough" => set("AETHER_SCAN", "thorough"),
            "--stealth" => set("AETHER_SCAN", "stealth"),
            "--ironclad" => set("AETHER_SCAN", "ironclad"),

            "--noize" => set("AETHER_NOIZE", next_value!()),

            "--h2" | "--http2" => set("AETHER_MASQUE_HTTP2", "1"),
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

    Ok(())
}

fn set(key: &str, value: &str) {
    std::env::set_var(key, value);
}

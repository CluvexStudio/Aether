use std::env;

const USAGE: &str = "\
Usage: aether [OPTIONS]

Connection:
  --bind <addr>            local SOCKS5 listen address (default 127.0.0.1:1819)
  --quick-reconnect        auto-accept reconnecting with the last known working gateway
  --no-quick-reconnect     always scan fresh, ignore any saved last-connection gateway
  -4                       scan/connect over IPv4 only (default)
  -6                       scan/connect over IPv6 only
  --dual                   scan/connect over both IPv4 and IPv6
  --peer <ip:port>         force a MASQUE/WireGuard peer, skip scanning
  --wg-peer <ip:port>      force a WireGuard peer (warp-in-warp outer), skip scanning

Protocol:
  --masque                 use MASQUE over QUIC/HTTP-3 (default)
  --wg, --wireguard        use classic WireGuard
  --gool, --wiw            use WARP-in-WARP (wireguard tunneled in wireguard)

Scan mode:
  --scan <mode>            turbo | balanced | thorough | stealth
  --turbo                  shortcut for --scan turbo
  --balanced               shortcut for --scan balanced
  --thorough               shortcut for --scan thorough
  --stealth                shortcut for --scan stealth
  --ironclad               shortcut for --scan ironclad (real tunnel + real HTTP check per candidate)

Obfuscation:
  --noize <profile>        obfuscation profile (off, light/firewall, balanced, gfw/aggressive, ...)

MASQUE transport:
  --h2, --http2            use HTTP/2 (TCP) instead of HTTP/3 (QUIC)
  --h2-peer <ip:port>      override the peer used for the HTTP/2 transport
  --ech <auto|base64>      enable Encrypted Client Hello
  --no-data-check          skip the end-to-end data-plane validation
  --validate-secs <n>      seconds to wait for data-plane validation (default 10)
  --reconnect-secs <n>     delay before reconnecting after a tunnel drop (default 2)
  --fragment               fragment the TLS ClientHello on the HTTP/2 transport
  --fragment-size <n|a-b>  fragment chunk size in bytes (default 16-32)
  --fragment-delay <n|a-b> delay between fragments in ms (default 2-10)

Health monitoring:
  --health-interval <n>    background tunnel health check interval in seconds (default 20, 0 to disable)
  --health-fails <n>       consecutive failed health checks before reconnect (default 2)
  --health-timeout <n>     timeout for each health check probe in seconds (default 5)
  --health-url <url>       custom probe URL for health check (default http://www.gstatic.com/generate_204)


WireGuard:
  --keepalive <n>          persistent keepalive interval in seconds (default 5)
  --no-profile-retry       don't retry other obfuscation profiles during scan

Config files:
  --config <path>          base identity config path (default aether.toml)
  --wg-config <path>       identity config path for WireGuard
  --masque-config <path>   identity config path for MASQUE

Advanced:
  --tls-groups <list>      TLS key share groups, e.g. \"P-256:X25519:P-384\"

Logging:
  -v, --verbose            detailed debug logs (use -vv for trace)
  -l, --log-level <level>  set log level (error, warn, info, debug, trace)

  -V, --version            show version and exit
  -h, --help               show this help and exit
";

pub fn parse_and_apply() -> crate::error::Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    parse_args(&args)
}

pub fn parse_args(args: &[String]) -> crate::error::Result<()> {
    let mut i = 0;
    let mut verbose_count = 0;

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
            "-V" | "--version" => {
                println!("aether {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }

            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }

            "-v" | "--verbose" => {
                verbose_count += 1;
            }
            "-vv" => {
                verbose_count += 2;
            }
            "-vvv" => {
                verbose_count += 3;
            }
            "-l" | "--log-level" => {
                set("AETHER_LOG", next_value!());
            }

            "--bind" => set("AETHER_SOCKS", next_value!()),
            "--quick-reconnect" => set("AETHER_QUICK_RECONNECT", "1"),
            "--no-quick-reconnect" => set("AETHER_QUICK_RECONNECT", "0"),

            "-4" => set("AETHER_IP", "v4"),
            "-6" => set("AETHER_IP", "v6"),
            "--dual" => set("AETHER_IP", "both"),
            "--ip" => set("AETHER_IP", next_value!()),

            "--peer" => set("AETHER_PEER", next_value!()),
            "--wg-peer" => set("AETHER_WG_PEER", next_value!()),

            "--masque" => set("AETHER_PROTOCOL", "masque"),
            "--wg" | "--wireguard" => set("AETHER_PROTOCOL", "wg"),
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
            "--validate-secs" => set("AETHER_MASQUE_VALIDATE_SECS", next_value!()),
            "--reconnect-secs" => {
                let val = next_value!();
                set("AETHER_MASQUE_RECONNECT_SECS", val);
                set("AETHER_WG_RECONNECT_SECS", val);
            }
            "--fragment" => set("AETHER_MASQUE_H2_FRAGMENT", "1"),
            "--fragment-size" => set("AETHER_MASQUE_H2_FRAGMENT_SIZE", next_value!()),
            "--fragment-delay" => set("AETHER_MASQUE_H2_FRAGMENT_DELAY", next_value!()),

            "--health-interval" => set("AETHER_HEALTH_INTERVAL", next_value!()),
            "--health-fails" => set("AETHER_HEALTH_MAX_FAILS", next_value!()),
            "--health-timeout" => set("AETHER_HEALTH_TIMEOUT", next_value!()),
            "--health-url" => set("AETHER_HEALTH_PROBE_URL", next_value!()),


            "--keepalive" => set("AETHER_WG_KEEPALIVE", next_value!()),
            "--no-profile-retry" => set("AETHER_WG_NO_PROFILE_RETRY", "1"),

            "--config" => set("AETHER_CONFIG", next_value!()),
            "--wg-config" => set("AETHER_WG_CONFIG", next_value!()),
            "--masque-config" => set("AETHER_MASQUE_CONFIG", next_value!()),

            "--tls-groups" => set("AETHER_TLS_GROUPS", next_value!()),

            other => {
                return Err(crate::error::AetherError::Other(format!(
                    "unknown option '{other}'\n\n{USAGE}"
                )));
            }
        }

        i += 1;
    }

    if verbose_count > 0 && std::env::var("AETHER_LOG").is_err() {
        if verbose_count == 1 {
            set("AETHER_LOG", "info,aether=debug");
        } else {
            set("AETHER_LOG", "info,aether=trace");
        }
    }

    Ok(())
}

fn set(key: &str, value: &str) {
    std::env::set_var(key, value);
}

#[cfg(test)]
pub static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse_log_levels() {
        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("AETHER_LOG");
        parse_args(&["--verbose".to_string()]).unwrap();
        assert_eq!(std::env::var("AETHER_LOG").unwrap(), "info,aether=debug");

        std::env::remove_var("AETHER_LOG");
        parse_args(&["-v".to_string()]).unwrap();
        assert_eq!(std::env::var("AETHER_LOG").unwrap(), "info,aether=debug");

        std::env::remove_var("AETHER_LOG");
        parse_args(&["-vv".to_string()]).unwrap();
        assert_eq!(std::env::var("AETHER_LOG").unwrap(), "info,aether=trace");

        std::env::remove_var("AETHER_LOG");
        parse_args(&["-l".to_string(), "warn".to_string()]).unwrap();
        assert_eq!(std::env::var("AETHER_LOG").unwrap(), "warn");

        std::env::remove_var("AETHER_LOG");
        parse_args(&["--log-level".to_string(), "trace".to_string()]).unwrap();
        assert_eq!(std::env::var("AETHER_LOG").unwrap(), "trace");
    }

    #[test]
    fn test_cli_parse_health_options() {
        let _guard = ENV_MUTEX.lock().unwrap();
        parse_args(&[
            "--health-interval".to_string(),
            "10".to_string(),
            "--health-fails".to_string(),
            "4".to_string(),
            "--health-timeout".to_string(),
            "3".to_string(),
            "--health-url".to_string(),
            "http://cp.cloudflare.com/generate_204".to_string(),
            "--reconnect-secs".to_string(),
            "5".to_string(),
        ])
        .unwrap();

        assert_eq!(std::env::var("AETHER_HEALTH_INTERVAL").unwrap(), "10");
        assert_eq!(std::env::var("AETHER_HEALTH_MAX_FAILS").unwrap(), "4");
        assert_eq!(std::env::var("AETHER_HEALTH_TIMEOUT").unwrap(), "3");
        assert_eq!(
            std::env::var("AETHER_HEALTH_PROBE_URL").unwrap(),
            "http://cp.cloudflare.com/generate_204"
        );
        assert_eq!(std::env::var("AETHER_MASQUE_RECONNECT_SECS").unwrap(), "5");
        assert_eq!(std::env::var("AETHER_WG_RECONNECT_SECS").unwrap(), "5");
    }
}






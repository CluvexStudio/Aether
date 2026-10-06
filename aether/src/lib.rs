#![allow(dead_code)]
pub mod account;
pub mod aethernoize;
pub mod api;
pub mod bridges;
pub mod cli;
pub mod config;
pub mod consts;
pub mod dns;
pub mod egress;
pub mod error;
pub mod exitloc;
pub mod ffi;
pub mod fragment;
pub mod https;
pub mod lastconn;
pub mod masque;
pub mod masque_h2;
pub mod netstack;
pub mod noize;
pub mod prober;
pub mod psiphon;
pub mod quic;
pub mod routing;
pub mod sniff;
pub mod socks;
pub mod stats;
pub mod sysprofile;
pub mod tls;
pub mod tor;
pub mod tunnelping;
pub mod upstream;
pub mod wg_prober;
pub mod wireguard;
pub mod zerotrust;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use error::{AetherError, Result};

fn parse_local_v4(s: &str) -> Ipv4Addr {
    s.split('/')
        .next()
        .unwrap_or(s)
        .parse()
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

const TUNNEL_MTU: usize = 1280;
const INNER_MTU: usize = 1200;

const H2_TUNNEL_MTU: usize = 1500;

fn masque_tunnel_mtu() -> usize {
    if let Some(mtu) = std::env::var("AETHER_MASQUE_MTU")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|mtu| (576..=1500).contains(mtu))
    {
        return mtu;
    }

    if masque_h2::enabled() {
        H2_TUNNEL_MTU
    } else {
        TUNNEL_MTU
    }
}
const DEFAULT_CONFIG: &str = "aether.toml";

pub async fn run() -> Result<()> {
    run_with(std::env::args().skip(1).collect()).await
}

pub async fn run_with(args: Vec<String>) -> Result<()> {
    if cli::parse_args(args)? == cli::Parsed::Done {
        return Ok(());
    }

    let level = std::env::var("AETHER_LOG_LEVEL")
        .ok()
        .map(|v| v.trim().to_lowercase())
        .filter(|v| matches!(v.as_str(), "error" | "warn" | "info" | "debug" | "trace"))
        .unwrap_or_else(|| "info".to_string());
    let default_filter = format!("info,aether={level}");
    let _ =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
            .format_timestamp_millis()
            .try_init();

    log::info!("Aether v{}", env!("CARGO_PKG_VERSION"));
    sysprofile::log_summary();
    sysprofile::raise_fd_limit();
    egress::init()?;
    stats::init();
    stats::spawn_reporter();

    install_netstack_panic_guard();
    // A cipher string or a group list BoringSSL does not take, or an address the calls to the
    // WARP API cannot use, stops the core here, with its option named.
    tls::check_tls_options()?;
    account::check_api_address()?;
    // The key of the WARP API calls of an earlier run of the library is not this run's.
    account::forget_api_ech();

    let base_config = std::env::var("AETHER_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string());

    // A registration serves no proxy, so it needs none of the listeners checked below.
    if let Some(wanted) = register_request()? {
        return register_identities(wanted, &base_config).await;
    }

    let listen: SocketAddr = std::env::var("AETHER_SOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:1819".parse().unwrap());

    drop(socks::bind_listener("socks5", listen).await?);
    drop(bind_http_proxy().await?);

    if tor::mode() == tor::Mode::Only {
        return tor::run_only(listen, tor::state_dir(&base_config)).await;
    }

    if psiphon::mode() == psiphon::Mode::Only {
        return psiphon::run_only(listen, psiphon::state_dir(&base_config)).await;
    }

    if tor::mode() == tor::Mode::Reverse && psiphon::mode() == psiphon::Mode::Reverse {
        return Err(AetherError::Other(
            "--tor-reverse and --psiphon-reverse both want to carry the tunnel; pick one, or put \
             the other inside it with --tor or --psiphon"
                .into(),
        ));
    }

    let pinned_wiw = wiw_endpoints_from_env()?;
    let pinned_mim = mim_endpoints_from_env()?;

    let protocol = match std::env::var("AETHER_PROTOCOL") {
        Ok(v) => Protocol::parse(&v),
        Err(_) if !pinned_wiw.is_empty() => Protocol::WarpInWarp,
        Err(_) if !pinned_mim.is_empty() => Protocol::MasqueInMasque,
        Err(_)
            if std::env::var("AETHER_PEER").is_ok() || std::env::var("AETHER_WG_PEER").is_ok() =>
        {
            Protocol::Masque
        }
        Err(_) => select_protocol(&base_config).await,
    };

    if tor::mode() == tor::Mode::Only {
        return tor::run_only(listen, tor::state_dir(&base_config)).await;
    }

    if psiphon::mode() == psiphon::Mode::Only {
        return psiphon::run_only(listen, psiphon::state_dir(&base_config)).await;
    }

    if protocol != Protocol::WarpInWarp && !pinned_wiw.is_empty() {
        log::warn!(
            "[-] the warp-in-warp endpoints you set are ignored on {}; they only apply to --gool",
            protocol.label()
        );
    }

    if protocol != Protocol::MasqueInMasque && !pinned_mim.is_empty() {
        log::warn!(
            "[-] the masque-in-masque endpoints you set are ignored on {}; they only apply to --mim",
            protocol.label()
        );
    }

    match tor::mode() {
        tor::Mode::Chain => {
            let through = listen;
            let state = tor::state_dir(&base_config);
            tokio::spawn(async move {
                if let Err(e) = tor::run_chain(through, state).await {
                    log::error!("[-] tor: {e}");
                }
            });
        }
        tor::Mode::Reverse => {
            if needs_udp_to_warp(protocol, gool_classic()) {
                return Err(AetherError::Other(format!(
                    "tor carries tcp only and warp's wireguard endpoints answer on udp alone, so \
                     {} can never be reached through tor; use --masque or --gool, which this mode \
                     runs over http/2, or put tor inside the tunnel instead with --tor",
                    protocol.label()
                )));
            }

            let socks = tor::start_reverse(tor::state_dir(&base_config)).await?;
            std::env::set_var("AETHER_UPSTREAM", format!("socks5://{socks}"));
            std::env::set_var("AETHER_MASQUE_HTTP2", "1");
            log::info!("[+] the tunnel is dialled through tor on the http/2 carrier");
        }
        tor::Mode::Only | tor::Mode::Off => {}
    }

    match psiphon::mode() {
        psiphon::Mode::Chain => {
            let through = listen;
            let state = psiphon::state_dir(&base_config);
            tokio::spawn(async move {
                if let Err(e) = psiphon::run_chain(through, state).await {
                    log::error!("[-] psiphon: {e}");
                }
            });
        }
        psiphon::Mode::Reverse => {
            if needs_udp_to_warp(protocol, gool_classic()) {
                return Err(AetherError::Other(format!(
                    "psiphon carries tcp only and warp's wireguard endpoints answer on udp alone, \
                     so {} can never be reached through psiphon; use --masque or --gool, which this \
                     mode runs over http/2, or put psiphon inside the tunnel instead with --psiphon",
                    protocol.label()
                )));
            }

            let socks = psiphon::start_reverse(psiphon::state_dir(&base_config)).await?;
            std::env::set_var("AETHER_UPSTREAM", format!("socks5://{socks}"));
            std::env::set_var("AETHER_MASQUE_HTTP2", "1");
            log::info!("[+] the tunnel is dialled through psiphon on the http/2 carrier");
        }
        psiphon::Mode::Only | psiphon::Mode::Off => {}
    }

    match protocol {
        Protocol::Masque => {
            select_masque_transport().await;
            let config_path = masque_config_path(&base_config);
            let identity = load_or_provision_masque(&config_path).await?;
            log::info!(
                "[+] identity ready: device={} ipv4={} ipv6={}",
                identity.device_id,
                identity.ipv4,
                identity.ipv6
            );
            // Every MASQUE handshake of the session offers it, on either carrier, until it ends.
            let _ech = tls::EchSession::start(resolve_ech().await?);
            let lastconn_path = lastconn_path(&config_path);
            run_masque(identity, listen, lastconn_path, None).await
        }
        Protocol::WireGuard => {
            let config_path = warp_config_path(&base_config);
            let identity = load_or_provision_warp(&config_path).await?;
            log::info!(
                "[+] identity ready: device={} ipv4={} ipv6={}",
                identity.device_id,
                identity.ipv4,
                identity.ipv6
            );

            let lastconn_path = lastconn_path(&config_path);
            run_wireguard(identity, listen, lastconn_path).await
        }
        Protocol::WarpInWarp if !gool_classic() => {
            select_masque_transport().await;
            let config_path = masque_config_path(&base_config);
            let identity = load_or_provision_masque(&config_path).await?;
            let inner_path = gool_identity_path(&config_path);
            log::info!(
                "[+] gool: masque device={} carries the wireguard identity in {inner_path}",
                identity.device_id
            );
            let _ech = tls::EchSession::start(resolve_ech().await?);
            let lastconn_path = lastconn_path(&config_path);
            run_masque(identity, listen, lastconn_path, Some(inner_path)).await
        }
        Protocol::WarpInWarp => {
            let primary_path = warp_config_path(&base_config);
            let secondary_path = derive_sibling_path(&primary_path, "secondary");
            let primary = load_or_provision_warp(&primary_path).await?;
            let secondary = load_or_provision_warp(&secondary_path).await?;
            log::info!(
                "[+] outer device={} ipv4={} | inner device={} ipv4={}",
                primary.device_id,
                primary.ipv4,
                secondary.device_id,
                secondary.ipv4
            );
            run_gool(primary, secondary, listen).await
        }
        Protocol::MasqueInMasque => {
            select_masque_transport().await;
            let primary_path = masque_config_path(&base_config);
            let secondary_path = derive_sibling_path(&primary_path, "secondary");
            let primary = load_or_provision_masque(&primary_path).await?;
            let secondary = load_or_provision_masque(&secondary_path).await?;
            log::info!(
                "[+] outer device={} ipv4={} | inner device={} ipv4={}",
                primary.device_id,
                primary.ipv4,
                secondary.device_id,
                secondary.ipv4
            );
            // Every MASQUE handshake of the session offers it, on either carrier, until it ends.
            let _ech = tls::EchSession::start(resolve_ech().await?);
            run_mim(primary, secondary, listen).await
        }
    }
}

const WG_EXAMPLE_PORT: u16 = 2408;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct WiwEndpoints {
    outer: Option<SocketAddr>,
    inner: Option<SocketAddr>,
}

impl WiwEndpoints {
    fn is_empty(&self) -> bool {
        self.outer.is_none() && self.inner.is_none()
    }

    fn checked(self) -> Result<Self> {
        match (self.outer, self.inner) {
            (Some(outer), Some(inner)) if outer.ip() == inner.ip() => {
                Err(AetherError::Other(format!(
                    "the two hops need separate edges, but both point at {}",
                    outer.ip()
                )))
            }
            _ => Ok(self),
        }
    }
}

fn parse_endpoint(raw: &str) -> Result<SocketAddr> {
    let text = raw.trim();

    if let Ok(peer) = text.parse::<SocketAddr>() {
        return Ok(peer);
    }

    let portless = text.parse::<IpAddr>().ok().or_else(|| {
        text.strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .and_then(|inner| inner.parse::<IpAddr>().ok())
    });

    if let Some(address) = portless {
        return Err(AetherError::Other(format!(
            "{text} carries no port, and the port is required; write it out, as in {}",
            SocketAddr::new(address, WG_EXAMPLE_PORT)
        )));
    }

    Err(AetherError::Other(format!(
        "'{text}' is not an endpoint; write an address and a port together, \
         such as 162.159.192.1:{WG_EXAMPLE_PORT}"
    )))
}

fn parse_endpoint_list(raw: &str) -> Result<Vec<SocketAddr>> {
    let mut peers = Vec::new();

    for part in raw.split([',', ';', ' ']) {
        if part.trim().is_empty() {
            continue;
        }
        peers.push(parse_endpoint(part)?);
    }

    match peers.len() {
        0 => Err(AetherError::Other(
            "no endpoint was given; expected one or two addresses".to_string(),
        )),
        1 | 2 => Ok(peers),
        found => Err(AetherError::Other(format!(
            "warp-in-warp has two hops, but {found} addresses were given"
        ))),
    }
}

fn env_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn wiw_scan_requested(lookup: &dyn Fn(&str) -> Option<String>) -> bool {
    match lookup("AETHER_WIW_PEERS") {
        Some(value) => matches!(
            value.to_lowercase().as_str(),
            "auto" | "scan" | "none" | "off" | "0"
        ),
        None => false,
    }
}

fn scan_keyword(value: &str) -> bool {
    matches!(
        value.to_lowercase().as_str(),
        "auto" | "scan" | "none" | "off" | "0"
    )
}

fn nested_endpoints_of(
    lookup: &dyn Fn(&str) -> Option<String>,
    list_key: &str,
    outer_key: &str,
    inner_key: &str,
) -> Result<WiwEndpoints> {
    let mut chosen = WiwEndpoints::default();

    if let Some(list) = lookup(list_key) {
        if !scan_keyword(&list) {
            let peers = parse_endpoint_list(&list)?;
            chosen.outer = peers.first().copied();
            chosen.inner = peers.get(1).copied();
        }
    }

    if let Some(value) = lookup(outer_key) {
        chosen.outer = Some(parse_endpoint(&value)?);
    }

    if let Some(value) = lookup(inner_key) {
        chosen.inner = Some(parse_endpoint(&value)?);
    }

    chosen.checked()
}

fn wiw_endpoints_of(lookup: &dyn Fn(&str) -> Option<String>) -> Result<WiwEndpoints> {
    nested_endpoints_of(
        lookup,
        "AETHER_WIW_PEERS",
        "AETHER_WIW_OUTER_PEER",
        "AETHER_WIW_INNER_PEER",
    )
}

fn wiw_endpoints_from_env() -> Result<WiwEndpoints> {
    wiw_endpoints_of(&env_value)
}

fn mim_endpoints_of(lookup: &dyn Fn(&str) -> Option<String>) -> Result<WiwEndpoints> {
    nested_endpoints_of(
        lookup,
        "AETHER_MIM_PEERS",
        "AETHER_MIM_OUTER_PEER",
        "AETHER_MIM_INNER_PEER",
    )
}

fn mim_endpoints_from_env() -> Result<WiwEndpoints> {
    mim_endpoints_of(&env_value)
}

fn wiw_endpoints_with_fallback(lookup: &dyn Fn(&str) -> Option<String>) -> Result<WiwEndpoints> {
    let mut chosen = wiw_endpoints_of(lookup)?;

    if chosen.outer.is_some() {
        return Ok(chosen);
    }

    let forced = lookup("AETHER_WG_PEER").or_else(|| lookup("AETHER_PEER"));
    let Some(forced) = forced else {
        return Ok(chosen);
    };

    let peers = parse_endpoint_list(&forced)?;
    chosen.outer = peers.first().copied();
    if chosen.inner.is_none() {
        chosen.inner = peers.get(1).copied();
    }

    chosen.checked()
}

async fn run_gool(
    primary: account::Identity,
    secondary: account::Identity,
    listen: SocketAddr,
) -> Result<()> {
    let pinned = wiw_endpoints_with_fallback(&env_value)?;

    match (pinned.outer, pinned.inner) {
        (Some(outer), Some(inner)) => log::info!(
            "[+] warp-in-warp endpoints given by hand: {outer} (outer) and {inner} (inner); the scan is skipped"
        ),
        (Some(outer), None) => log::info!(
            "[+] outer warp-in-warp endpoint given by hand: {outer}; scanning for the inner one"
        ),
        (None, Some(inner)) => log::info!(
            "[+] inner warp-in-warp endpoint given by hand: {inner}; scanning for the outer one"
        ),
        (None, None) => {}
    }

    let mut outer_peer = pinned.outer;
    let mut inner_peer = pinned.inner;
    let mut consecutive_fails: u32 = 0;
    const MAX_CONSECUTIVE_FAILS: u32 = 2;
    let mut scan_settings: Option<(String, prober::IpScan)> = None;

    loop {
        if consecutive_fails >= MAX_CONSECUTIVE_FAILS {
            let mut rescanning = false;

            if pinned.outer.is_none() {
                if let Some(peer) = outer_peer.take() {
                    log::warn!(
                        "[-] outer endpoint {peer} failed {consecutive_fails} times in a row; blacklisting and rescanning"
                    );
                    rescanning = true;
                }
            }

            if pinned.inner.is_none() {
                if let Some(peer) = inner_peer.take() {
                    log::warn!(
                        "[-] inner endpoint {peer} failed {consecutive_fails} times in a row; blacklisting and rescanning"
                    );
                    rescanning = true;
                }
            }

            if !rescanning {
                log::warn!(
                    "[-] the endpoints you chose failed {consecutive_fails} times in a row; still retrying them, drop --wiw-outer/--wiw-inner to let the scan pick instead"
                );
            }

            consecutive_fails = 0;
        }

        let (peer, inner_peer_now) = match (outer_peer, inner_peer) {
            (Some(outer), Some(inner)) => (outer, inner),
            (known_outer, known_inner) => {
                let wanted =
                    usize::from(known_outer.is_none()) + usize::from(known_inner.is_none());
                let avoid: HashSet<IpAddr> = known_outer
                    .into_iter()
                    .chain(known_inner)
                    .map(|peer| peer.ip())
                    .collect();

                let (mode_str, ip) = match &scan_settings {
                    Some(settings) => settings.clone(),
                    None => {
                        let mode_str = select_scan_mode_str(WIW_MANUAL_TIP).await;
                        let ip = select_ip_version().await;
                        scan_settings.insert((mode_str, ip)).clone()
                    }
                };

                let found = match select_wg_peers(&primary, &mode_str, ip, wanted, &avoid).await {
                    Ok(found) => found,
                    Err(e) => {
                        log::warn!("[-] no usable WARP endpoint found: {e}; rescanning shortly");
                        tokio::time::sleep(wg_reconnect_delay()).await;
                        continue;
                    }
                };

                let mut found = found;
                if verified_scan_selected(&scan_settings) {
                    spread_hops(&mut found);
                }

                let mut found = found.into_iter();
                let outer = known_outer.or_else(|| found.next());
                let inner = known_inner.or_else(|| found.next());

                match (outer, inner) {
                    (Some(outer), Some(inner)) => (outer, inner),
                    _ => {
                        log::warn!(
                            "[-] the scan only turned up one edge, so warp-in-warp would use it twice; rescanning"
                        );
                        outer_peer = pinned.outer;
                        inner_peer = pinned.inner;
                        tokio::time::sleep(wg_reconnect_delay()).await;
                        continue;
                    }
                }
            }
        };

        log::info!("[+] using cloudflare edge {peer} (outer) and {inner_peer_now} (inner)");
        outer_peer = Some(peer);
        inner_peer = Some(inner_peer_now);

        match run_warp_in_warp(
            primary.clone(),
            secondary.clone(),
            peer,
            inner_peer_now,
            listen,
        )
        .await
        {
            Ok(()) => log::warn!("[-] gool tunnel closed; reconnecting"),
            Err(e) => log::warn!("[-] gool tunnel ended: {e}; reconnecting"),
        }
        consecutive_fails += 1;

        tokio::time::sleep(wg_reconnect_delay()).await;
    }
}

fn install_netstack_panic_guard() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let from_netstack = info
            .location()
            .map(|l| l.file().contains("smoltcp"))
            .unwrap_or(false);
        if from_netstack {
            log::debug!("[netstack] recovered from a malformed segment: {info}");
        } else {
            default_hook(info);
        }
    }));
}

fn noize_config() -> noize::NoizeConfig {
    let profile = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "firewall".to_string());
    log::info!("[+] obfuscation profile: {profile}");
    noize::from_profile(&profile)
}

fn aethernoize_config() -> aethernoize::AetherNoizeConfig {
    let profile = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "balanced".to_string());
    log::info!("[+] aethernoize profile: {profile}");
    aethernoize::from_profile(&profile)
}

fn team_scope() -> Option<String> {
    zerotrust::TeamSettings::from_env().map(|settings| settings.team)
}

fn enrolled_teams(base: &str) -> Vec<String> {
    let dir_end = base
        .rfind(|c| c == '/' || c == '\\')
        .map(|i| i + 1)
        .unwrap_or(0);
    let dir = if dir_end == 0 { "." } else { &base[..dir_end] };
    let stem = match base[dir_end..].rfind('.') {
        Some(rel) => &base[dir_end..dir_end + rel],
        None => &base[dir_end..],
    };
    let prefix = format!("{stem}-team-");

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut teams: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        let Some(team) = rest.strip_suffix(".toml") else {
            continue;
        };
        if team.is_empty() || team.ends_with("-secondary") || team.ends_with("-lastconn") {
            continue;
        }
        if !teams.iter().any(|known| known == team) {
            teams.push(team.to_string());
        }
    }
    teams.sort();
    teams
}

async fn enrol_zero_trust(base: &str) {
    let known = enrolled_teams(base);

    let prompt = match known.first() {
        Some(team) => format!(
            "\nZero Trust organization.\n  already enrolled: {}\nTeam name from \
             <team>.cloudflareaccess.com, or blank to reuse '{}': ",
            known.join(", "),
            team
        ),
        None => "\nZero Trust organization.\nTeam name from <team>.cloudflareaccess.com \
                 (blank to cancel): "
            .to_string(),
    };

    let answer = prompt_line(&prompt).await.unwrap_or_default();
    let answer = answer.trim().to_string();

    let team = if answer.is_empty() {
        match known.first() {
            Some(team) => team.clone(),
            None => {
                log::info!("[*] Zero Trust skipped; staying on personal WARP");
                return;
            }
        }
    } else {
        match zerotrust::normalize_team(&answer) {
            Some(team) => team,
            None => {
                log::warn!("[-] '{answer}' is not a usable team name");
                return;
            }
        }
    };

    std::env::set_var("AETHER_TEAM", &team);

    if known.iter().any(|enrolled| *enrolled == team) {
        log::info!("[+] reusing the saved enrolment for team {team}; no sign-in needed");
        return;
    }

    let needs_method = match zerotrust::TeamSettings::from_env() {
        Some(settings) => {
            !(settings.token.is_some() || settings.has_service_token() || settings.email.is_some())
        }
        None => {
            std::env::remove_var("AETHER_TEAM");
            return;
        }
    };

    if needs_method {
        let email = prompt_line("Email address for the one-time login code (blank to cancel): ")
            .await
            .unwrap_or_default();
        let email = email.trim().to_string();

        if email.is_empty() {
            log::warn!("[-] no email given; staying on personal WARP");
            std::env::remove_var("AETHER_TEAM");
            return;
        }

        std::env::set_var("AETHER_ACCESS_EMAIL", &email);
    }

    let settings = match zerotrust::TeamSettings::from_env() {
        Some(settings) => settings,
        None => {
            std::env::remove_var("AETHER_TEAM");
            return;
        }
    };

    match zerotrust::resolve_token(&settings).await {
        Ok(_) => log::info!("[+] signed in to team {team}; now pick the transport to use"),
        Err(error) => {
            log::error!("[-] Zero Trust sign-in failed: {error}");
            log::warn!("[-] staying on personal WARP");
            std::env::remove_var("AETHER_TEAM");
            std::env::remove_var("AETHER_ACCESS_EMAIL");
        }
    }
}

async fn provision_account() -> Result<account::Identity> {
    match zerotrust::TeamSettings::from_env() {
        Some(settings) => {
            log::info!(
                "[*] enrolling this device into the Zero Trust organization {} ({})",
                settings.team,
                settings.team_domain()
            );
            let identity =
                account::provision_team(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, &settings)
                    .await?;
            Ok(account::refresh_profile(identity).await)
        }
        None => account::provision_wg(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, None).await,
    }
}

async fn adopt_team_profile(identity: account::Identity) -> account::Identity {
    if team_scope().is_none() {
        return identity;
    }

    let identity = account::refresh_profile(identity).await;

    if !identity.gateway_proxy.is_empty() {
        if std::env::var("AETHER_GATEWAY").is_ok() {
            socks::set_gateway_proxy(&identity.gateway_proxy);
        } else {
            log::debug!(
                "[zerotrust] the organization offers a gateway proxy at {}; pass --gateway to route http through it",
                identity.gateway_proxy
            );
        }
    }

    if !identity.assigned_endpoint.is_empty() && std::env::var("AETHER_PEER").is_err() {
        let port = if std::env::var("AETHER_PROTOCOL")
            .map(|value| value == "wg" || value == "gool")
            .unwrap_or(false)
        {
            2408
        } else {
            443
        };
        let peer = format!("{}:{port}", identity.assigned_endpoint);
        if peer.parse::<SocketAddr>().is_ok() {
            log::info!("[+] the organization assigned endpoint {peer}; trying it before scanning");
            std::env::set_var("AETHER_TEAM_ENDPOINT", &peer);
        }
    }

    identity
}

fn warp_config_path(base: &str) -> String {
    if let Ok(p) = std::env::var("AETHER_WG_CONFIG") {
        return p;
    }
    match team_scope() {
        Some(team) => derive_sibling_path(base, &format!("team-{team}")),
        None => base.to_string(),
    }
}

fn masque_config_path(base: &str) -> String {
    if let Ok(p) = std::env::var("AETHER_MASQUE_CONFIG") {
        return p;
    }
    match team_scope() {
        Some(team) => derive_sibling_path(base, &format!("team-{team}")),
        None => derive_sibling_path(base, "masque"),
    }
}

/// Where gool keeps the wireguard identity it carries inside its masque tunnel: beside the masque identity at
/// `masque_config`, named `<masque config>-gool.toml`. The tunnel and `--register gool` both find it here.
fn gool_identity_path(masque_config: &str) -> String {
    derive_sibling_path(masque_config, "gool")
}

fn derive_sibling_path(base: &str, suffix: &str) -> String {
    let dir_end = base
        .rfind(|c| c == '/' || c == '\\')
        .map(|i| i + 1)
        .unwrap_or(0);
    match base[dir_end..].rfind('.') {
        Some(rel) => {
            let dot = dir_end + rel;
            format!("{}-{}{}", &base[..dot], suffix, &base[dot..])
        }
        None => format!("{base}-{suffix}"),
    }
}

fn keep_saved_identity() -> bool {
    !matches!(
        std::env::var("AETHER_REPROVISION").as_deref(),
        Ok("0") | Ok("off") | Ok("false")
    )
}

async fn load_or_provision_warp(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing warp identity from {config_path}");
        let identity = adopt_team_profile(identity).await;
        if !identity.refused {
            config::save(config_path, &identity)?;
            return Ok(identity);
        }
        if !keep_saved_identity() {
            return Ok(identity);
        }
        log::warn!("[*] registering a fresh wireguard account to replace the refused identity");
    }

    log::info!("[+] no warp identity found; provisioning dedicated wireguard account");
    let identity = provision_account().await?;
    let identity = adopt_team_profile(identity).await;
    enable_warp_on(&identity).await?;
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new warp identity to {config_path}");
    Ok(identity)
}

/// Enables WARP on a device just registered, as the WARP toggle of the app does. A new identity is
/// saved only once this is done, and an identity file already there is never asked about again;
/// a failure here fails the registration, and nothing is saved.
async fn enable_warp_on(identity: &account::Identity) -> Result<()> {
    account::enable_warp(&identity.device_id, &identity.access_token).await?;
    log::info!("[+] warp enabled for device {}", identity.device_id);
    Ok(())
}

/// The MASQUE identity saved at `config_path`, used as it is, or a new one registered now and given
/// its MASQUE key, saved once WARP is enabled on it, see [`enable_warp_on`].
async fn load_or_provision_masque(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing masque identity from {config_path}");
        let refused = if identity.has_masque_credentials() {
            let identity = adopt_team_profile(identity).await;
            if !identity.refused {
                config::save(config_path, &identity)?;
                return Ok(identity);
            }
            identity
        } else {
            log::info!("[+] masque identity needs a certificate; enrolling masque key");
            match account::ensure_masque_enrolled(&identity).await {
                Ok(enrollment) => {
                    let identity = account::Identity {
                        cert_pem: enrollment.cert_pem,
                        key_pem: enrollment.key_pem,
                        cert_issued_at: enrollment.issued_at,
                        ..identity
                    };
                    config::save(config_path, &identity)?;
                    return Ok(identity);
                }
                Err(AetherError::IdentityRefused(reason)) => {
                    log::warn!("[-] the saved masque identity was refused: {reason}");
                    account::Identity {
                        refused: true,
                        ..identity
                    }
                }
                Err(error) => return Err(error),
            }
        };

        if !keep_saved_identity() {
            return Ok(refused);
        }
        log::warn!("[*] registering a fresh masque account to replace the refused identity");
    }

    log::info!("[+] no masque identity found; provisioning dedicated masque account");
    let identity = provision_account().await?;
    let enrollment = account::ensure_masque_enrolled(&identity).await?;
    let identity = account::Identity {
        cert_pem: enrollment.cert_pem,
        key_pem: enrollment.key_pem,
        cert_issued_at: enrollment.issued_at,
        ..identity
    };
    let identity = adopt_team_profile(identity).await;
    enable_warp_on(&identity).await?;
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new masque identity to {config_path}");
    Ok(identity)
}

/// The identities `--register` asks for: those of one protocol, both hops of a two-hop one, or
/// all five.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegisterSet {
    wireguard: bool,
    wireguard_inner: bool,
    masque: bool,
    masque_inner: bool,
    /// The wireguard identity gool carries inside its masque tunnel, see [`gool_identity_path`].
    gool: bool,
}

/// How `--register` makes an identity it does not find.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provision {
    Warp,
    Masque,
    Gool,
}

impl RegisterSet {
    fn parse(value: &str) -> Result<Self> {
        let none = RegisterSet {
            wireguard: false,
            wireguard_inner: false,
            masque: false,
            masque_inner: false,
            gool: false,
        };
        match value.trim().to_lowercase().as_str() {
            "all" => Ok(RegisterSet {
                wireguard: true,
                wireguard_inner: true,
                masque: true,
                masque_inner: true,
                gool: true,
            }),
            "masque" => Ok(RegisterSet {
                masque: true,
                ..none
            }),
            "wg" | "wireguard" | "warp" => Ok(RegisterSet {
                wireguard: true,
                ..none
            }),
            // What --gool runs: wireguard carried inside masque.
            "gool" | "wg-over-masque" => Ok(RegisterSet {
                masque: true,
                gool: true,
                ..none
            }),
            // What --gool-classic runs: wireguard inside wireguard.
            "gool-classic" | "wiw" | "warp-in-warp" => Ok(RegisterSet {
                wireguard: true,
                wireguard_inner: true,
                ..none
            }),
            "mim" | "masque-in-masque" => Ok(RegisterSet {
                masque: true,
                masque_inner: true,
                ..none
            }),
            other => Err(AetherError::Other(format!(
                "--register takes masque, wg, gool, gool-classic, mim or all, not '{other}'"
            ))),
        }
    }
}

fn register_request() -> Result<Option<RegisterSet>> {
    env_value("AETHER_REGISTER")
        .map(|value| RegisterSet::parse(&value))
        .transpose()
}

/// `--register`: makes sure the identities `wanted` names exist, registering the missing ones,
/// and returns without scanning or opening a tunnel. An identity file already there is kept,
/// never replaced. With a carrier around the tunnel the registrations go through it, whatever
/// the protocol: they are https requests, which tor and psiphon carry, so the refusal of
/// wireguard behind them concerns the tunnel alone. A carrier inside the tunnel, or on its own,
/// plays no part in a registration.
async fn register_identities(wanted: RegisterSet, base_config: &str) -> Result<()> {
    let carrier = match (tor::mode(), psiphon::mode()) {
        (tor::Mode::Reverse, psiphon::Mode::Reverse) => {
            return Err(AetherError::Other(
                "--tor-reverse and --psiphon-reverse both want to carry the registration; \
                 pick one"
                    .into(),
            ));
        }
        (tor::Mode::Reverse, _) => Some((
            "tor",
            tor::start_reverse(tor::state_dir(base_config)).await?,
        )),
        (_, psiphon::Mode::Reverse) => Some((
            "psiphon",
            psiphon::start_reverse(psiphon::state_dir(base_config)).await?,
        )),
        _ => None,
    };
    if let Some((name, socks)) = carrier {
        std::env::set_var("AETHER_UPSTREAM", format!("socks5://{socks}"));
        log::info!("[+] the identities are registered through {name}");
    }

    let wireguard = warp_config_path(base_config);
    let masque = masque_config_path(base_config);
    let identities = [
        (
            wanted.wireguard,
            "wireguard",
            wireguard.clone(),
            Provision::Warp,
        ),
        (
            wanted.wireguard_inner,
            "wireguard inner",
            derive_sibling_path(&wireguard, "secondary"),
            Provision::Warp,
        ),
        (wanted.masque, "masque", masque.clone(), Provision::Masque),
        (
            wanted.masque_inner,
            "masque inner",
            derive_sibling_path(&masque, "secondary"),
            Provision::Masque,
        ),
        (
            wanted.gool,
            "gool",
            gool_identity_path(&masque),
            Provision::Gool,
        ),
    ];

    let mut ready = Vec::new();
    for (asked, label, path, provision) in identities {
        if !asked {
            continue;
        }
        let identity = match provision {
            Provision::Warp => load_or_provision_warp(&path).await?,
            Provision::Masque => load_or_provision_masque(&path).await?,
            Provision::Gool => load_or_provision_gool(&path).await?,
        };
        log::info!(
            "[+] {label} identity ready: device={} ipv4={} ipv6={}",
            identity.device_id,
            identity.ipv4,
            identity.ipv6
        );
        ready.push(label);
    }

    log::info!("[+] identities ready: {}", ready.join(", "));
    Ok(())
}

async fn select_peer(identity: &account::Identity, protocol: Protocol) -> Result<SocketAddr> {
    let force_peer = match protocol {
        Protocol::Masque | Protocol::MasqueInMasque => std::env::var("AETHER_PEER").ok(),
        Protocol::WireGuard | Protocol::WarpInWarp => std::env::var("AETHER_WG_PEER")
            .ok()
            .or_else(|| std::env::var("AETHER_PEER").ok()),
    };

    if let Some(p) = force_peer {
        let peer: SocketAddr = p
            .parse()
            .map_err(|_| AetherError::Other(format!("bad peer address {p}")))?;
        log::info!("[+] using forced peer {peer} (probe skipped)");
        return Ok(peer);
    }

    log::info!("[+] selected protocol: {}", protocol.label());

    let mode_str = select_scan_mode_str("").await;
    let ip = select_ip_version().await;

    match protocol {
        Protocol::Masque | Protocol::MasqueInMasque => {
            log::info!("[*] hunting for a working MASQUE gateway (deep connect-ip verification)");
            let mode = prober::ScanMode::parse(&mode_str);
            let probe = prober::MasqueProbe {
                sni: consts::CONNECT_SNI.to_string(),
                authority: quic::default_authority().to_string(),
                path: quic::default_path().to_string(),
                cert_pem: std::sync::Arc::from(identity.cert_pem.clone()),
                key_pem: std::sync::Arc::from(identity.key_pem.clone()),
                ech_config_list: None,
                noize: noize_config(),
                ports: prober::MASQUE_PORTS.to_vec(),
                ip,
                local_ipv4: parse_local_v4(&identity.ipv4),
            };

            let best = prober::hunt_best_gateway(&probe, mode).await?;
            log::info!(
                "[+] selected MASQUE gateway {}:{} (rtt {:?})",
                best.ip,
                best.port,
                best.rtt
            );
            Ok(SocketAddr::new(best.ip, best.port))
        }
        Protocol::WireGuard | Protocol::WarpInWarp => {
            let peers = select_wg_peers(identity, &mode_str, ip, 1, &HashSet::new()).await?;
            Ok(peers[0])
        }
    }
}

async fn select_wg_peers(
    identity: &account::Identity,
    mode_str: &str,
    ip: prober::IpScan,
    want: usize,
    avoid: &HashSet<IpAddr>,
) -> Result<Vec<SocketAddr>> {
    log::info!(
        "[*] hunting for {want} working WireGuard endpoint(s) (handshake + data-plane verification)"
    );
    let mode = wg_prober::WgScanMode::parse(mode_str);

    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;

    let ports = wireguard::WG_PORTS.to_vec();
    let excluded: HashSet<SocketAddr> = avoid
        .iter()
        .flat_map(|address| {
            ports
                .iter()
                .map(move |port| SocketAddr::new(*address, *port))
        })
        .collect();

    if !avoid.is_empty() {
        log::info!(
            "[*] the scan leaves out {} address(es) already taken by the other hop",
            avoid.len()
        );
    }

    let probe = wg_prober::WgProbe {
        private_key: std::sync::Arc::new(private_key),
        peer_public_key: std::sync::Arc::new(peer_public),
        client_id: identity.client_id.clone(),
        local_ipv4: identity
            .ipv4
            .parse()
            .map_err(|_| AetherError::Other("invalid ipv4".into()))?,
        aethernoize: aethernoize_config(),
        ports,
        ip,
        excluded,
    };

    let found = wg_prober::hunt_wg_endpoints(&probe, mode, want).await?;

    let picked: Vec<wg_prober::WgProbeResult> = found
        .into_iter()
        .filter(|pr| !avoid.contains(&pr.ip))
        .take(want)
        .collect();

    if picked.is_empty() {
        return Err(AetherError::NoCleanEndpoint);
    }

    for pr in &picked {
        log::info!(
            "[+] selected WireGuard endpoint {}:{} (rtt {:?})",
            pr.ip,
            pr.port,
            pr.rtt
        );
    }

    Ok(picked
        .into_iter()
        .map(|pr| SocketAddr::new(pr.ip, pr.port))
        .collect())
}

/// The ECH key of the session, by --ech (AETHER_ECH): none without it; with it, the key it
/// gives in base64, or with auto, the key the lookup of --ech-dns and --ech-domain finds; a
/// key the calls to the WARP API offered in this run serves without a second lookup. With
/// ECH asked for and no key BoringSSL can offer, the session does not start, so that the
/// server name never goes out in the clear.
async fn resolve_ech() -> Result<Option<Vec<u8>>> {
    let setting = std::env::var(tls::SESSION_ECH_OPTION.variable).ok();
    if setting.as_deref().is_some_and(|value| !value.is_empty()) {
        if let Some(key) = account::api_ech_in_use() {
            log::info!(
                "[+] offering the ECHConfigList the WARP API took ({} bytes)",
                key.len()
            );
            return Ok(Some(key));
        }
    }
    let key = tls::ech_key(&tls::SESSION_ECH_OPTION, setting.as_deref(), || {
        dns::fetch_ech_config(&dns::SESSION_ECH)
    })
    .await?;
    if key.is_none() {
        log::info!("[+] ECH off; the server name goes out in cleartext");
    }
    Ok(key)
}

fn masque_reconnect_delay() -> std::time::Duration {
    let secs = std::env::var("AETHER_MASQUE_RECONNECT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(2);
    std::time::Duration::from_secs(secs)
}

fn masque_startup_timeout() -> std::time::Duration {
    let secs = std::env::var("AETHER_MASQUE_STARTUP_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(30);
    std::time::Duration::from_secs(secs)
}

async fn hunt_masque_peer(
    identity: &account::Identity,
    mode_str: &str,
    ip: prober::IpScan,
    avoid: &HashSet<IpAddr>,
) -> Result<SocketAddr> {
    log::info!(
        "[*] hunting for a working MASQUE gateway (deep connect-ip + data-plane verification)"
    );
    let mode = prober::ScanMode::parse(mode_str);
    let probe = prober::MasqueProbe {
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: std::sync::Arc::from(identity.cert_pem.clone()),
        key_pem: std::sync::Arc::from(identity.key_pem.clone()),
        ech_config_list: tls::session_ech().map(std::sync::Arc::from),
        noize: noize_config(),
        ports: prober::MASQUE_PORTS.to_vec(),
        ip,
        local_ipv4: parse_local_v4(&identity.ipv4),
    };

    let best = prober::hunt_best_gateway_avoiding(&probe, mode, avoid).await?;
    log::info!(
        "[+] selected MASQUE gateway {}:{} (rtt {:?})",
        best.ip,
        best.port,
        best.rtt
    );
    Ok(SocketAddr::new(best.ip, best.port))
}

fn masque_carrier() -> &'static str {
    if masque_h2::enabled() {
        lastconn::CARRIER_MASQUE_H2
    } else {
        lastconn::CARRIER_MASQUE_H3
    }
}

fn lastconn_path(config_path: &str) -> String {
    derive_sibling_path(config_path, "lastconn")
}

/// Whether `peer` serves MASQUE, by a quick check on the carrier the session uses, which
/// offers `ech`: the session's key, or that of a job of the library.
async fn quick_verify_masque_peer(
    identity: &account::Identity,
    peer: SocketAddr,
    ech: Option<Vec<u8>>,
) -> bool {
    let vp = quic::VerifyParams {
        peer,
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        ech_config_list: ech.clone(),
        noize: noize_config(),
        timeout: std::time::Duration::from_secs(5),
        local_ipv4: parse_local_v4(&identity.ipv4),
    };

    if masque_h2::enabled() {
        let cfg = masque_h2::H2TunnelConfig {
            peer: masque_h2::h2_peer(peer),
            sni: consts::CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: true,
            pin_endpoint: true,
            expected_pins: consts::MASQUE_PINS.iter().map(|p| p.to_vec()).collect(),
            ech_config_list: ech,
        };
        return masque_h2::verify_h2(&cfg, std::time::Duration::from_secs(5))
            .await
            .is_ok();
    }

    quic::verify_masque(&vp).await.is_ok()
}

async fn want_quick_reconnect(cached: &lastconn::LastConnection) -> bool {
    match std::env::var("AETHER_QUICK_RECONNECT").as_deref() {
        Ok("1") | Ok("true") | Ok("yes") | Ok("on") => return true,
        Ok("0") | Ok("false") | Ok("no") | Ok("off") => return false,
        _ => {}
    }

    let answer = prompt_line(&format!(
        "\nLast working gateway: {} (profile '{}')\nReconnect to it now without rescanning? [Y/n]: ",
        cached.peer, cached.profile
    ))
    .await;

    !matches!(answer.as_deref(), Some(a) if a.eq_ignore_ascii_case("n") || a.eq_ignore_ascii_case("no"))
}

async fn run_masque(
    identity: account::Identity,
    listen: SocketAddr,
    lastconn_path: String,
    gool_inner: Option<String>,
) -> Result<()> {
    let forced = std::env::var("AETHER_PEER").ok();

    let mut quick_peer: Option<SocketAddr> = None;

    if forced.is_none() {
        if let Some(assigned) = std::env::var("AETHER_TEAM_ENDPOINT")
            .ok()
            .and_then(|value| value.parse::<SocketAddr>().ok())
        {
            log::info!("[*] verifying the endpoint the organization assigned: {assigned}");
            if quick_verify_masque_peer(&identity, assigned, tls::session_ech()).await {
                log::info!("[+] the assigned endpoint {assigned} works; skipping the scan");
                quick_peer = Some(assigned);
            } else {
                log::warn!(
                    "[-] the assigned endpoint {assigned} did not answer; falling back to scanning"
                );
            }
        }
    }

    if forced.is_none() && quick_peer.is_none() {
        if let Some(cached) = lastconn::load(&lastconn_path) {
            let ring = lastconn::usable_peers(&cached, masque_carrier());
            if !ring.is_empty() && want_quick_reconnect(&cached).await {
                for peer in ring {
                    log::info!("[*] verifying cached gateway {peer} before reuse");
                    if quick_verify_masque_peer(&identity, peer, tls::session_ech()).await {
                        log::info!("[+] cached gateway {peer} still works; skipping scan");
                        quick_peer = Some(peer);
                        break;
                    }
                    log::warn!("[-] cached gateway {peer} no longer answers; trying the next one");
                }
                if quick_peer.is_none() {
                    log::warn!("[-] no remembered gateway answers; scanning fresh");
                }
            }
        }
    }

    let (mode_str, ip) = if forced.is_some() || quick_peer.is_some() {
        scan_settings_from_env()
    } else {
        let mode_str = select_scan_mode_str("").await;
        let ip = select_ip_version().await;
        (mode_str, ip)
    };

    let mut last_good_peer: Option<SocketAddr> = None;
    let mut strikes = GatewayStrikes::default();

    loop {
        // A gateway named by hand stays, whatever happens to it: it was asked for on purpose.
        if forced.is_none() {
            if let Some(peer) = strikes.give_up(Instant::now(), MASQUE_GATEWAY_REST) {
                log::warn!(
                    "[-] gateway {peer} failed {MASQUE_GATEWAY_STRIKES} times in a row; leaving it out of the scans for {:?}",
                    MASQUE_GATEWAY_REST
                );
                last_good_peer = None;
            }
        }

        let peer = if let Some(p) = quick_peer.take() {
            p
        } else {
            let retried = match last_good_peer {
                Some(p) => {
                    log::info!("[*] retrying last known-good gateway {p} before rescanning");
                    if quick_verify_masque_peer(&identity, p, tls::session_ech()).await {
                        Some(p)
                    } else {
                        log::warn!(
                            "[-] last known-good gateway {p} no longer responds; rescanning"
                        );
                        None
                    }
                }
                None => None,
            };

            match retried {
                Some(p) => p,
                None => match &forced {
                    Some(p) => match p.parse::<SocketAddr>() {
                        Ok(peer) => {
                            log::info!("[+] using forced peer {peer} (probe skipped)");
                            peer
                        }
                        Err(_) => return Err(AetherError::Other(format!("bad peer address {p}"))),
                    },
                    None => match hunt_masque_peer(
                        &identity,
                        &mode_str,
                        ip,
                        &strikes.left_out(Instant::now()),
                    )
                    .await
                    {
                        Ok(peer) => peer,
                        Err(e) => {
                            log::warn!(
                                "[-] no usable MASQUE gateway found: {e}; rescanning shortly"
                            );
                            tokio::time::sleep(masque_reconnect_delay()).await;
                            continue;
                        }
                    },
                },
            }
        };

        log::info!("[+] using cloudflare edge {peer}");

        if forced.is_none() {
            let profile = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "firewall".to_string());
            lastconn::save(
                &lastconn_path,
                &peer.to_string(),
                &profile,
                masque_carrier(),
            );
        }

        last_good_peer = Some(peer);
        strikes.using(peer);

        let started = Instant::now();
        let ended = match &gool_inner {
            Some(path) => run_gool_tunnel(&identity, peer, tls::session_ech(), listen, path).await,
            None => run_masque_tunnel(&identity, peer, tls::session_ech(), listen).await,
        };
        strikes.ended(started.elapsed());
        match ended {
            Ok(()) => log::warn!("[-] MASQUE tunnel closed; reconnecting"),
            Err(e) => log::warn!("[-] MASQUE tunnel ended: {e}; reconnecting"),
        }

        tokio::time::sleep(masque_reconnect_delay()).await;
    }
}

/// How long a tunnel has to stay up for its end not to count against its MASQUE gateway or
/// WireGuard endpoint: one that carried the traffic this long proves the gateway good, so its end,
/// a network change say, clears the ends counted before it. Only tunnels that end sooner, one
/// after another, make a run leave a gateway or an endpoint.
const TUNNEL_STAYED_UP: std::time::Duration = std::time::Duration::from_secs(300);

/// The ends in a row of the tunnels through one gateway or endpoint, `in_a_row` before, after one
/// more that `lasted` this long: one more, or none once that tunnel stayed up [`TUNNEL_STAYED_UP`].
fn count_tunnel_end(in_a_row: u32, lasted: std::time::Duration) -> u32 {
    if lasted >= TUNNEL_STAYED_UP {
        0
    } else {
        in_a_row.saturating_add(1)
    }
}

/// How many times in a row the tunnel through a MASQUE gateway may end, each time sooner than
/// [`TUNNEL_STAYED_UP`], before the run leaves the gateway, as the WireGuard run leaves an endpoint.
const MASQUE_GATEWAY_STRIKES: u32 = 2;

/// How long a MASQUE gateway the run left stays out of its scans: as long as a WireGuard endpoint
/// by default (`wg_endpoint_cooldown`).
const MASQUE_GATEWAY_REST: std::time::Duration = std::time::Duration::from_secs(300);

/// The gateways that failed a MASQUE run: the one in use, how many times in a row its tunnel
/// ended soon after it started, and those left out of the scans until a while has passed. The
/// check before a reconnect only proves that a gateway answers, so a tunnel that ends every time,
/// as it does on an exit the exit rule refuses, would otherwise hold the run on one gateway for
/// good.
#[derive(Debug, Default)]
struct GatewayStrikes {
    current: Option<SocketAddr>,
    in_a_row: u32,
    resting: HashMap<IpAddr, Instant>,
}

impl GatewayStrikes {
    /// The tunnel goes through `peer` now; another gateway than the last starts with none.
    fn using(&mut self, peer: SocketAddr) {
        if self.current != Some(peer) {
            self.current = Some(peer);
            self.in_a_row = 0;
        }
    }

    /// The tunnel through the gateway in use ended, for whatever reason, after it `lasted` this
    /// long, see [`count_tunnel_end`].
    fn ended(&mut self, lasted: std::time::Duration) {
        self.in_a_row = count_tunnel_end(self.in_a_row, lasted);
    }

    /// The gateway in use, once its tunnel ended `MASQUE_GATEWAY_STRIKES` times in a row: its
    /// address rests until `rest` after `now`, out of the scans, and the count starts over.
    fn give_up(&mut self, now: Instant, rest: std::time::Duration) -> Option<SocketAddr> {
        if self.in_a_row < MASQUE_GATEWAY_STRIKES {
            return None;
        }
        self.in_a_row = 0;
        let peer = self.current.take()?;
        self.resting.insert(peer.ip(), now + rest);
        Some(peer)
    }

    /// The addresses the scans leave out at `now`.
    fn left_out(&mut self, now: Instant) -> HashSet<IpAddr> {
        self.resting.retain(|_, until| *until > now);
        self.resting.keys().copied().collect()
    }
}

struct MasqueHop {
    stack: netstack::StackHandle,
    exit: TunnelExit,
    _ctrl: tokio::sync::mpsc::Sender<quic::Control>,
    _guard: TaskGuard,
}

#[allow(clippy::too_many_arguments)]
async fn establish_masque(
    identity: &account::Identity,
    peer: SocketAddr,
    ech: Option<Vec<u8>>,
    h2: bool,
    mtu: usize,
    datagram: usize,
    version_bait: bool,
    startup: std::time::Duration,
    label: &str,
) -> Result<MasqueHop> {
    let (chans, internals) = quic::channels();
    let quic::Channels {
        outbound_tx,
        inbound_rx,
        ctrl_tx,
    } = chans;

    let stack = netstack::spawn(&identity.ipv4, &identity.ipv6, mtu, inbound_rx, outbound_tx)?;

    let mut guard = TaskGuard::new();

    let (addr_tx, mut addr_rx) = tokio::sync::mpsc::channel::<quic::AssignedAddr>(8);
    let bridge_stack = stack.clone();
    let bridge_task = tokio::spawn(async move {
        while let Some(a) = addr_rx.recv().await {
            let res = match a.ip {
                IpAddr::V4(v4) => bridge_stack.set_addrs(Some((v4, a.prefix)), None).await,
                IpAddr::V6(v6) => bridge_stack.set_addrs(None, Some((v6, a.prefix))).await,
            };
            if let Err(e) = res {
                log::warn!("[-] failed to sync edge address into netstack: {e}");
            }
        }
    });
    guard.push(bridge_task.abort_handle());

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

    let tunnel_task = if h2 {
        let h2cfg = masque_h2::H2TunnelConfig {
            peer,
            sni: consts::CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: false,
            pin_endpoint: true,
            expected_pins: consts::MASQUE_PINS.iter().map(|p| p.to_vec()).collect(),
            ech_config_list: ech,
        };
        log::info!("[+] [{label}] MASQUE transport: HTTP/2 (TCP) to {peer} (inner mtu {mtu})");
        tokio::spawn(masque_h2::run(
            h2cfg,
            internals,
            Some(addr_tx),
            Some(ready_tx),
        ))
    } else {
        let cfg = quic::TunnelConfig {
            peer,
            sni: consts::CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            ech_config_list: ech,
            noize: noize_config(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: false,
            max_datagram: datagram,
            version_bait,
        };
        log::info!(
            "[+] [{label}] MASQUE transport: HTTP/3 (QUIC) to {peer} (inner mtu {mtu}, datagram {})",
            cfg.datagram_budget()
        );
        tokio::spawn(quic::run(cfg, internals, Some(addr_tx), Some(ready_tx)))
    };
    guard.push(tunnel_task.abort_handle());

    let startup_timeout = startup;
    match tokio::time::timeout(startup_timeout, ready_rx).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            let joined = tunnel_task.await;
            let msg = match joined {
                Ok(Ok(())) => format!("[{label}] tunnel exited before validation"),
                Ok(Err(e)) => format!("[{label}] tunnel failed before validation: {e}"),
                Err(e) => format!("[{label}] tunnel task join error: {e}"),
            };
            return Err(AetherError::Other(msg));
        }
        Err(_) => {
            tunnel_task.abort();
            let _ = tunnel_task.await;
            return Err(AetherError::Other(format!(
                "[{label}] tunnel startup timed out after {startup_timeout:?}"
            )));
        }
    }

    Ok(MasqueHop {
        stack,
        exit: tunnel_task,
        _ctrl: ctrl_tx,
        _guard: guard,
    })
}

async fn exit_policy_guard(
    stack: &netstack::StackHandle,
    policy: &Option<exitloc::Policy>,
) -> AetherError {
    match policy {
        Some(policy) => exitloc::watch(stack, policy).await,
        None => std::future::pending().await,
    }
}

async fn run_masque_tunnel(
    identity: &account::Identity,
    peer: SocketAddr,
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
) -> Result<()> {
    let h2 = masque_h2::enabled();
    let dial = if h2 { masque_h2::h2_peer(peer) } else { peer };

    let mut hop = establish_masque(
        identity,
        dial,
        ech,
        h2,
        masque_tunnel_mtu(),
        quic::MAX_DATAGRAM_SIZE,
        true,
        masque_startup_timeout(),
        "masque",
    )
    .await?;

    let policy = exitloc::Policy::from_env();
    exitloc::settle(&hop.stack, &policy, "masque").await?;

    let socks_listener = socks::bind_listener("socks5", listen).await?;
    let http_listener = bind_http_proxy().await?;

    let mut tasks = TaskGuard::new();

    let socks_stack = hop.stack.clone();
    let socks_task = tokio::spawn(async move { socks::serve(socks_listener, socks_stack).await });
    tasks.push(socks_task.abort_handle());

    let http_task = spawn_http_proxy(http_listener, &hop.stack);
    if let Some(task) = &http_task {
        tasks.push(task.abort_handle());
    }

    let tunnel_result = tokio::select! {
        result = &mut hop.exit => result,
        reason = exit_policy_guard(&hop.stack, &policy) => return Err(reason),
    };

    if let Some(task) = &http_task {
        task.abort();
    }
    socks_task.abort();

    match tunnel_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(AetherError::Other(format!("tunnel exited: {e}"))),
        Err(e) => Err(AetherError::Other(format!("tunnel task join error: {e}"))),
    }
}

const MASQUE_DATAGRAM_OVERHEAD: usize = quic::MAX_DATAGRAM_SIZE - TUNNEL_MTU;

fn mim_inner_budget(outer_mtu: usize, inner_peer: SocketAddr, h2: bool) -> (usize, usize) {
    if h2 {
        let mtu = outer_mtu.saturating_sub(100).clamp(576, 1500);
        return (quic::MAX_DATAGRAM_SIZE, mtu);
    }

    let headers = if inner_peer.is_ipv4() { 28 } else { 48 };
    let datagram = outer_mtu
        .saturating_sub(headers)
        .clamp(quic::MIN_DATAGRAM_SIZE, quic::MAX_DATAGRAM_SIZE);
    let mtu = datagram
        .saturating_sub(MASQUE_DATAGRAM_OVERHEAD)
        .clamp(576, 1500);
    (datagram, mtu)
}

const MASQUE_INNER_PORT: u16 = 443;
const MIM_INNER_TRIES: usize = 6;

fn mim_inner_startup() -> std::time::Duration {
    masque_startup_timeout().min(std::time::Duration::from_secs(12))
}

fn edge_network(ip: IpAddr) -> Option<[u8; 3]> {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            Some([octets[0], octets[1], octets[2]])
        }
        IpAddr::V6(_) => None,
    }
}

fn verified_scan_selected(settings: &Option<(String, prober::IpScan)>) -> bool {
    let named = match settings {
        Some((mode, _)) => mode.clone(),
        None => std::env::var("AETHER_SCAN").unwrap_or_default(),
    };
    prober::ScanMode::parse(&named) == prober::ScanMode::Verified
}

fn spread_hops(found: &mut [SocketAddr]) {
    if found.len() < 2 {
        return;
    }
    let first = found[0];
    let network = edge_network(first.ip());
    if let Some(other) = found
        .iter()
        .position(|peer| edge_network(peer.ip()) != network)
    {
        if other >= 1 {
            found.swap(1, other);
        }
    }
}

fn masque_verified_ladder(outer: SocketAddr, count: usize) -> Vec<SocketAddr> {
    if outer.is_ipv6() {
        return Vec::new();
    }

    let mut out: Vec<SocketAddr> = Vec::new();
    let mut seen: HashSet<SocketAddr> = HashSet::new();
    let outer_network = edge_network(outer.ip());

    let verified: Vec<IpAddr> = prober::MASQUE_VERIFIED_GATEWAYS
        .iter()
        .filter_map(|entry| entry.parse().ok())
        .collect();

    let push =
        |out: &mut Vec<SocketAddr>, seen: &mut HashSet<SocketAddr>, ip: IpAddr, port: u16| {
            let peer = SocketAddr::new(ip, port);
            if ip != outer.ip() && seen.insert(peer) {
                out.push(peer);
            }
        };

    for ip in verified
        .iter()
        .filter(|ip| edge_network(**ip) != outer_network)
    {
        push(&mut out, &mut seen, *ip, MASQUE_INNER_PORT);
    }
    for ip in &verified {
        push(&mut out, &mut seen, *ip, MASQUE_INNER_PORT);
    }
    for &port in prober::MASQUE_ALT_PORTS {
        for ip in &verified {
            push(&mut out, &mut seen, *ip, port);
        }
    }

    out.truncate(count.max(1));
    out
}

fn inner_masque_candidates(outer: SocketAddr, count: usize, verified: bool) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    let mut seen: HashSet<SocketAddr> = HashSet::new();

    if verified {
        let room = count.saturating_sub(2).max(1);
        for peer in masque_verified_ladder(outer, room) {
            if seen.insert(peer) {
                out.push(peer);
            }
        }
    }

    for peer in sibling_candidates(outer, count) {
        if out.len() >= count {
            break;
        }
        if seen.insert(peer) {
            out.push(peer);
        }
    }

    out.truncate(count.max(1));
    out
}

fn sibling_candidates(outer: SocketAddr, count: usize) -> Vec<SocketAddr> {
    use rand::RngExt;

    let mut rng = rand::rng();
    let mut out: Vec<SocketAddr> = Vec::new();

    match outer.ip() {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let mut hosts: Vec<u8> = (1..=254u8).filter(|host| *host != octets[3]).collect();
            for index in (1..hosts.len()).rev() {
                let other = rng.random_range(0..=index);
                hosts.swap(index, other);
            }
            for host in hosts.into_iter().take(count) {
                let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], host);
                out.push(SocketAddr::new(IpAddr::V4(ip), MASQUE_INNER_PORT));
            }
        }
        IpAddr::V6(v6) => {
            let mut segments = v6.segments();
            let last = segments[7];
            let mut seen: HashSet<u16> = HashSet::new();
            while out.len() < count && seen.len() < count * 8 {
                let candidate = rng.random_range(1..=u16::MAX);
                if candidate == last || !seen.insert(candidate) {
                    continue;
                }
                segments[7] = candidate;
                out.push(SocketAddr::new(
                    IpAddr::V6(std::net::Ipv6Addr::from(segments)),
                    MASQUE_INNER_PORT,
                ));
            }
        }
    }

    out
}

async fn spawn_tcp_forwarder(
    outer: &netstack::StackHandle,
    remote: SocketAddr,
) -> Result<(SocketAddr, TaskGuard)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let local = listener.local_addr()?;
    let stack = outer.clone();

    let task = tokio::spawn(async move {
        let mut clients = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((sock, _)) = accepted else { break };
                    let stack = stack.clone();
                    clients.spawn(async move {
                        match stack.open_tcp(remote).await {
                            Ok(conn) => {
                                let (sender, from_stack) = conn.into_split();
                                socks::relay_tunneled(
                                    sock,
                                    sender,
                                    from_stack,
                                    socks::half_close_linger(),
                                )
                                .await;
                            }
                            Err(e) => log::warn!(
                                "[-] the inner hop could not reach {remote} through the outer tunnel: {e}"
                            ),
                        }
                    });
                }
                Some(_) = clients.join_next(), if !clients.is_empty() => {}
            }
        }
    });

    Ok((local, TaskGuard(vec![task.abort_handle()])))
}

async fn run_masque_in_masque(
    primary: &account::Identity,
    secondary: &account::Identity,
    peer: SocketAddr,
    inner_peers: &[SocketAddr],
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
) -> Result<()> {
    let h2 = masque_h2::enabled();
    let outer_mtu = masque_tunnel_mtu();

    log::info!("[*] establishing outer MASQUE tunnel to {peer}...");
    let mut outer = establish_masque(
        primary,
        peer,
        ech,
        h2,
        outer_mtu,
        quic::MAX_DATAGRAM_SIZE,
        true,
        masque_startup_timeout(),
        "outer",
    )
    .await?;

    let mut chosen: Option<(SocketAddr, MasqueHop, TaskGuard)> = None;

    for inner_peer in inner_peers
        .iter()
        .copied()
        .filter(|candidate| candidate.ip() != peer.ip())
    {
        let (inner_datagram, inner_mtu) = mim_inner_budget(outer_mtu, inner_peer, h2);

        if !h2 && inner_datagram + 28 > outer_mtu {
            log::warn!(
                "[-] the outer link carries {outer_mtu} bytes, too little for an inner quic \
                 datagram; raise AETHER_MASQUE_MTU or use --h2 for both hops"
            );
        }

        let (forwarder, forwarder_guard) = if h2 {
            spawn_tcp_forwarder(&outer.stack, inner_peer).await?
        } else {
            spawn_udp_forwarder(&outer.stack, inner_peer).await?
        };
        log::info!(
            "[*] trying inner MASQUE edge {inner_peer} through the outer tunnel via {forwarder}"
        );

        match establish_masque(
            secondary,
            forwarder,
            None,
            h2,
            inner_mtu,
            inner_datagram,
            false,
            mim_inner_startup(),
            "inner",
        )
        .await
        {
            Ok(hop) => {
                log::info!("[+] inner MASQUE tunnel established through {inner_peer}");
                chosen = Some((inner_peer, hop, forwarder_guard));
                break;
            }
            Err(e) => log::info!(
                "[-] inner edge {inner_peer} does not serve masque from inside the tunnel: {e}"
            ),
        }
    }

    let Some((inner_peer, mut inner, _forwarder_guard)) = chosen else {
        return Err(AetherError::Other(
            "no inner masque edge answered through the outer tunnel".into(),
        ));
    };

    let policy = exitloc::Policy::from_env();
    exitloc::settle(&inner.stack, &policy, "masque-in-masque").await?;

    let socks_listener = socks::bind_listener("socks5", listen).await?;
    let http_listener = bind_http_proxy().await?;

    let mut tasks = TaskGuard::new();
    let http_task = spawn_http_proxy(http_listener, &inner.stack);
    if let Some(task) = &http_task {
        tasks.push(task.abort_handle());
    }

    let socks_stack = inner.stack.clone();
    let mut socks_task =
        tokio::spawn(async move { socks::serve(socks_listener, socks_stack).await });
    tasks.push(socks_task.abort_handle());

    log::info!("[+] masque-in-masque ready: {peer} (outer) and {inner_peer} (inner)");

    #[derive(PartialEq)]
    enum Winner {
        Outer,
        Inner,
        Socks,
        Policy,
    }

    let (outcome, winner) = tokio::select! {
        result = &mut outer.exit => (join_outcome("outer masque tunnel", result), Winner::Outer),
        result = &mut inner.exit => (join_outcome("inner masque tunnel", result), Winner::Inner),
        result = &mut socks_task => (join_outcome("socks5 server", result), Winner::Socks),
        reason = exit_policy_guard(&inner.stack, &policy) => (Err(reason), Winner::Policy),
    };

    if winner != Winner::Outer {
        outer.exit.abort();
        let _ = (&mut outer.exit).await;
    }
    if winner != Winner::Inner {
        inner.exit.abort();
        let _ = (&mut inner.exit).await;
    }
    if winner != Winner::Socks {
        socks_task.abort();
        let _ = (&mut socks_task).await;
    }

    outcome
}

async fn run_mim(
    primary: account::Identity,
    secondary: account::Identity,
    listen: SocketAddr,
) -> Result<()> {
    let pinned = mim_endpoints_from_env()?;

    match (pinned.outer, pinned.inner) {
        (Some(outer), Some(inner)) => log::info!(
            "[+] masque-in-masque endpoints given by hand: {outer} (outer) and {inner} (inner); the scan is skipped"
        ),
        (Some(outer), None) => log::info!(
            "[+] outer masque-in-masque endpoint given by hand: {outer}; the inner one is chosen for you"
        ),
        (None, Some(inner)) => log::info!(
            "[+] inner masque-in-masque endpoint given by hand: {inner}; scanning for the outer one"
        ),
        (None, None) => {}
    }

    let mut outer_peer = pinned.outer;
    let mut inner_peer = pinned.inner;
    let mut consecutive_fails: u32 = 0;
    let mut scan_settings: Option<(String, prober::IpScan)> = None;
    const MAX_CONSECUTIVE_FAILS: u32 = 2;

    loop {
        if consecutive_fails >= MAX_CONSECUTIVE_FAILS {
            if pinned.outer.is_none() {
                if let Some(peer) = outer_peer.take() {
                    log::warn!(
                        "[-] outer edge {peer} failed {consecutive_fails} times in a row; rescanning"
                    );
                }
            }
            if pinned.inner.is_none() {
                if let Some(peer) = inner_peer.take() {
                    log::warn!(
                        "[-] inner edge {peer} failed {consecutive_fails} times in a row; trying another"
                    );
                }
            }
            consecutive_fails = 0;
        }

        let outer = match outer_peer {
            Some(peer) => peer,
            None => {
                let (mode_str, ip) = match &scan_settings {
                    Some(settings) => settings.clone(),
                    None => {
                        let mode_str = select_scan_mode_str(MIM_MANUAL_TIP).await;
                        let ip = select_ip_version().await;
                        scan_settings.insert((mode_str, ip)).clone()
                    }
                };

                match hunt_masque_peer(&primary, &mode_str, ip, &HashSet::new()).await {
                    Ok(peer) => peer,
                    Err(e) => {
                        log::warn!("[-] no usable MASQUE gateway found: {e}; rescanning shortly");
                        tokio::time::sleep(masque_reconnect_delay()).await;
                        continue;
                    }
                }
            }
        };

        let candidates = match inner_peer {
            Some(peer) => vec![peer],
            None => inner_masque_candidates(
                outer,
                MIM_INNER_TRIES,
                verified_scan_selected(&scan_settings),
            ),
        };

        if candidates.is_empty() {
            return Err(AetherError::Other(
                "no second masque edge is known for the inner hop".into(),
            ));
        }

        outer_peer = Some(outer);

        match run_masque_in_masque(
            &primary,
            &secondary,
            outer,
            &candidates,
            tls::session_ech(),
            listen,
        )
        .await
        {
            Ok(()) => log::warn!("[-] masque-in-masque tunnel closed; reconnecting"),
            Err(e) => log::warn!("[-] masque-in-masque tunnel ended: {e}; reconnecting"),
        }
        consecutive_fails += 1;

        tokio::time::sleep(masque_reconnect_delay()).await;
    }
}

fn wg_keepalive_secs() -> u16 {
    std::env::var("AETHER_WG_KEEPALIVE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(5)
}

fn wg_profile_candidates() -> Vec<(String, aethernoize::AetherNoizeConfig)> {
    let primary = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "balanced".to_string());
    log::info!("[+] aethernoize primary profile: {primary}");

    let mut names = vec![primary.clone()];
    if std::env::var("AETHER_WG_NO_PROFILE_RETRY").is_err() {
        for fallback in ["balanced", "aggressive", "light", "off"] {
            if !names.iter().any(|n| n.eq_ignore_ascii_case(fallback)) {
                names.push(fallback.to_string());
            }
        }
    }

    names
        .into_iter()
        .map(|n| {
            let cfg = aethernoize::from_profile(&n);
            (n, cfg)
        })
        .collect()
}

async fn hunt_wg_peer_with_profile(
    identity: &account::Identity,
    mode_str: &str,
    ip: prober::IpScan,
    profile: aethernoize::AetherNoizeConfig,
    excluded: &HashSet<SocketAddr>,
) -> Result<SocketAddr> {
    let mode = wg_prober::WgScanMode::parse(mode_str);
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;

    let probe = wg_prober::WgProbe {
        private_key: std::sync::Arc::new(private_key),
        peer_public_key: std::sync::Arc::new(peer_public),
        client_id: identity.client_id,
        local_ipv4: identity
            .ipv4
            .parse()
            .map_err(|_| AetherError::Other("invalid ipv4".into()))?,
        aethernoize: profile,
        ports: wireguard::WG_PORTS.to_vec(),
        ip,
        excluded: excluded.clone(),
    };

    let best = wg_prober::hunt_best_wg_endpoint(&probe, mode).await?;
    Ok(SocketAddr::new(best.ip, best.port))
}

fn wg_reconnect_delay() -> std::time::Duration {
    let secs = std::env::var("AETHER_WG_RECONNECT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(2);
    std::time::Duration::from_secs(secs)
}

fn wg_endpoint_cooldown() -> std::time::Duration {
    let secs = std::env::var("AETHER_WG_ENDPOINT_COOLDOWN_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(300);
    std::time::Duration::from_secs(secs)
}

async fn hunt_wg_peer(
    identity: &account::Identity,
    candidates: &[(String, aethernoize::AetherNoizeConfig)],
    mode_str: &str,
    ip: prober::IpScan,
    excluded: &HashSet<SocketAddr>,
) -> Result<(SocketAddr, aethernoize::AetherNoizeConfig, String)> {
    let multi = candidates.len() > 1;
    for (name, profile) in candidates {
        log::info!(
            "[*] hunting for a working WireGuard endpoint (handshake + data-plane verification, aethernoize='{name}')"
        );
        match hunt_wg_peer_with_profile(identity, mode_str, ip, profile.clone(), excluded).await {
            Ok(peer) => {
                log::info!(
                    "[+] selected WireGuard endpoint {peer} using aethernoize profile '{name}'"
                );
                return Ok((peer, profile.clone(), name.clone()));
            }
            Err(e) => {
                if multi {
                    log::warn!("[-] profile '{name}' found no data-plane endpoint: {e}; trying next profile");
                } else {
                    log::warn!("[-] profile '{name}' found no data-plane endpoint: {e}");
                }
            }
        }
    }
    Err(AetherError::NoCleanEndpoint)
}

async fn run_wireguard(
    identity: account::Identity,
    listen: SocketAddr,
    lastconn_path: String,
) -> Result<()> {
    let candidates = wg_profile_candidates();

    let forced = std::env::var("AETHER_WG_PEER")
        .ok()
        .or_else(|| std::env::var("AETHER_PEER").ok());

    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

    let mut quick: Option<(SocketAddr, aethernoize::AetherNoizeConfig, String)> = None;

    if forced.is_none() {
        if let Some(assigned) = std::env::var("AETHER_TEAM_ENDPOINT")
            .ok()
            .and_then(|value| value.parse::<SocketAddr>().ok())
        {
            log::info!("[*] verifying the endpoint the organization assigned: {assigned}");
            for (name, profile) in &candidates {
                match wireguard::verify_endpoint(
                    assigned,
                    private_key,
                    peer_public,
                    identity.client_id,
                    ipv4,
                    profile,
                    std::time::Duration::from_secs(8),
                    None,
                )
                .await
                {
                    Ok(rtt) => {
                        log::info!(
                            "[+] the assigned endpoint {assigned} works with profile '{name}' (rtt {rtt:?}); skipping the scan"
                        );
                        quick = Some((assigned, profile.clone(), name.clone()));
                        break;
                    }
                    Err(e) => {
                        log::debug!(
                            "[-] assigned endpoint {assigned} failed profile '{name}': {e}"
                        );
                    }
                }
            }
            if quick.is_none() {
                log::warn!(
                    "[-] the assigned endpoint {assigned} did not pass validation; falling back to scanning"
                );
            }
        }
    }

    if forced.is_none() && quick.is_none() {
        if let Some(cached) = lastconn::load(&lastconn_path) {
            let ring = lastconn::usable_peers(&cached, lastconn::CARRIER_WIREGUARD);
            if !ring.is_empty() && want_quick_reconnect(&cached).await {
                let profile = aethernoize::from_profile(&cached.profile);
                for peer in ring {
                    log::info!("[*] verifying cached WireGuard endpoint {peer} before reuse");
                    match wireguard::verify_endpoint(
                        peer,
                        private_key,
                        peer_public,
                        identity.client_id,
                        ipv4,
                        &profile,
                        std::time::Duration::from_secs(6),
                        None,
                    )
                    .await
                    {
                        Ok(rtt) => {
                            log::info!(
                                "[+] cached endpoint {peer} still works (rtt {:?}); skipping scan",
                                rtt
                            );
                            quick = Some((peer, profile.clone(), cached.profile.clone()));
                            break;
                        }
                        Err(e) => {
                            log::warn!(
                                "[-] cached endpoint {peer} no longer answers ({e}); trying the next one"
                            );
                        }
                    }
                }
                if quick.is_none() {
                    log::warn!("[-] no remembered endpoint answers; scanning fresh");
                }
            }
        }
    }

    let (mode_str, ip) = if forced.is_some() || quick.is_some() {
        scan_settings_from_env()
    } else {
        let mode_str = select_scan_mode_str("").await;
        let ip = select_ip_version().await;
        (mode_str, ip)
    };

    let mut last_good: Option<(SocketAddr, aethernoize::AetherNoizeConfig, String)> = None;
    let mut consecutive_fails_on_peer: u32 = 0;
    let mut endpoint_cooldowns: HashMap<SocketAddr, Instant> = HashMap::new();
    const MAX_CONSECUTIVE_FAILS: u32 = 2;

    loop {
        let now = Instant::now();
        endpoint_cooldowns.retain(|_, until| *until > now);
        if consecutive_fails_on_peer >= MAX_CONSECUTIVE_FAILS {
            if let Some((peer, _, _)) = last_good.take() {
                let cooldown = wg_endpoint_cooldown();
                endpoint_cooldowns.insert(peer, now + cooldown);
                log::warn!(
                    "[-] endpoint {peer} failed {consecutive_fails_on_peer} times in a row; excluding it for {:?}",
                    cooldown
                );
            }
            consecutive_fails_on_peer = 0;
        }

        let (peer, profile, profile_name) = if let Some(q) = quick.take() {
            q
        } else {
            let retried = match &last_good {
                Some((p, profile, _)) => {
                    log::info!(
                        "[*] retrying last known-good WireGuard endpoint {p} before rescanning"
                    );
                    match wireguard::verify_endpoint(
                        *p,
                        private_key,
                        peer_public,
                        identity.client_id,
                        ipv4,
                        profile,
                        std::time::Duration::from_secs(6),
                        None,
                    )
                    .await
                    {
                        Ok(_) => Some(last_good.clone().unwrap()),
                        Err(e) => {
                            log::warn!("[-] last known-good endpoint {p} no longer responds ({e}); rescanning");
                            None
                        }
                    }
                }
                None => None,
            };

            match retried {
                Some(v) => v,
                None => {
                    if let Some(ref p) = forced {
                        let peer: SocketAddr = p
                            .parse()
                            .map_err(|_| AetherError::Other(format!("bad peer address {p}")))?;
                        log::info!("[+] using forced peer {peer} (probe skipped)");

                        let mut chosen = None;
                        for (name, profile) in &candidates {
                            log::info!(
                                "[*] testing forced peer {peer} with aethernoize profile '{name}'"
                            );
                            match wireguard::verify_endpoint(
                                peer,
                                private_key,
                                peer_public,
                                identity.client_id,
                                ipv4,
                                profile,
                                std::time::Duration::from_secs(10),
                                None,
                            )
                            .await
                            {
                                Ok(rtt) => {
                                    log::info!(
                                        "[+] profile '{}' passed handshake + data-plane (rtt {:?})",
                                        name,
                                        rtt
                                    );
                                    chosen = Some((peer, profile.clone(), name.clone()));
                                    break;
                                }
                                Err(e) => {
                                    log::warn!("[-] profile '{name}' failed on forced peer: {e}");
                                }
                            }
                        }
                        match chosen {
                            Some(v) => v,
                            None => {
                                log::warn!(
                                    "[-] forced peer {peer} failed with every aethernoize profile; retrying shortly"
                                );
                                tokio::time::sleep(wg_reconnect_delay()).await;
                                continue;
                            }
                        }
                    } else {
                        let excluded: HashSet<SocketAddr> =
                            endpoint_cooldowns.keys().copied().collect();
                        match hunt_wg_peer(&identity, &candidates, &mode_str, ip, &excluded).await {
                            Ok(v) => v,
                            Err(e) => {
                                log::warn!("[-] no usable WireGuard endpoint found: {e}; rescanning shortly");
                                tokio::time::sleep(wg_reconnect_delay()).await;
                                continue;
                            }
                        }
                    }
                }
            }
        };

        log::info!("[+] using cloudflare edge {peer}");

        if forced.is_none() {
            lastconn::save(
                &lastconn_path,
                &peer.to_string(),
                &profile_name,
                lastconn::CARRIER_WIREGUARD,
            );
        }

        let is_same_peer_as_before = last_good.as_ref().map(|(p, _, _)| *p) == Some(peer);
        if !is_same_peer_as_before {
            consecutive_fails_on_peer = 0;
        }
        last_good = Some((peer, profile.clone(), profile_name));

        let started = Instant::now();
        match run_wireguard_tunnel(identity.clone(), peer, profile, listen).await {
            Ok(()) => log::warn!("[-] WireGuard tunnel closed; reconnecting"),
            Err(e) => log::warn!("[-] WireGuard tunnel ended: {e}; reconnecting"),
        }
        consecutive_fails_on_peer = count_tunnel_end(consecutive_fails_on_peer, started.elapsed());

        tokio::time::sleep(wg_reconnect_delay()).await;
    }
}

fn wg_tunnel_validate_timeout() -> std::time::Duration {
    let secs = std::env::var("AETHER_WG_VALIDATE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(10);
    std::time::Duration::from_secs(secs)
}

async fn run_wireguard_tunnel(
    identity: account::Identity,
    peer: SocketAddr,
    aethernoize: aethernoize::AetherNoizeConfig,
    listen: SocketAddr,
) -> Result<()> {
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

    log::info!("[*] validating WireGuard tunnel with {peer} (handshake + data-plane) before exposing socks5...");
    let (_, session) = wireguard::verify_endpoint_keep_session(
        peer,
        private_key,
        peer_public,
        identity.client_id,
        ipv4,
        &aethernoize,
        wg_tunnel_validate_timeout(),
        Some(wg_keepalive_secs()),
    )
    .await
    .map_err(|e| AetherError::Other(format!("tunnel failed validation: {e}")))?;
    log::info!("[+] wireguard tunnel validated (end-to-end data confirmed); exposing socks5");

    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());

    let tunnel = wireguard::WgTunnel::from_established(
        session,
        std::sync::Arc::new(aethernoize),
        inbound_tx,
        ipv4,
    );

    let stack = netstack::spawn(
        &identity.ipv4,
        &identity.ipv6,
        TUNNEL_MTU,
        inbound_rx,
        outbound_tx,
    )?;

    let mut tasks = TaskGuard::new();

    let policy = exitloc::Policy::from_env();
    exitloc::settle(&stack, &policy, "wireguard").await?;

    let socks_listener = socks::bind_listener("socks5", listen).await?;
    let http_listener = bind_http_proxy().await?;

    let socks_stack = stack.clone();
    let socks_task = tokio::spawn(async move { socks::serve(socks_listener, socks_stack).await });
    tasks.push(socks_task.abort_handle());

    let http_task = spawn_http_proxy(http_listener, &stack);
    if let Some(task) = &http_task {
        tasks.push(task.abort_handle());
    }

    let tunnel_result = tokio::select! {
        result = tunnel.run(outbound_rx) => result,
        reason = exit_policy_guard(&stack, &policy) => return Err(reason),
    };

    if let Some(task) = &http_task {
        task.abort();
    }

    socks_task.abort();
    let _ = socks_task.await;

    drop(stack);

    match tunnel_result {
        Ok(()) => Ok(()),
        Err(e) => Err(AetherError::Other(format!("wireguard tunnel exited: {e}"))),
    }
}

type TunnelExit = tokio::task::JoinHandle<Result<()>>;

fn http_proxy_listen() -> Option<SocketAddr> {
    let raw = std::env::var("AETHER_HTTP_PROXY").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<SocketAddr>() {
        Ok(addr) => Some(addr),
        Err(_) => {
            log::warn!("[-] ignoring an unparsable http proxy address: {trimmed}");
            None
        }
    }
}

async fn bind_http_proxy() -> Result<Option<tokio::net::TcpListener>> {
    match http_proxy_listen() {
        Some(listen) => Ok(Some(socks::bind_listener("http proxy", listen).await?)),
        None => Ok(None),
    }
}

fn spawn_http_proxy(
    listener: Option<tokio::net::TcpListener>,
    stack: &netstack::StackHandle,
) -> Option<TunnelExit> {
    let listener = listener?;
    let stack = stack.clone();
    Some(tokio::spawn(async move {
        socks::serve_http(listener, stack).await
    }))
}

async fn establish_wg(
    identity: &account::Identity,
    peer: SocketAddr,
    mtu: usize,
    obfuscate: bool,
    keepalive: u16,
    label: &'static str,
) -> Result<(netstack::StackHandle, TunnelExit)> {
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;

    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

    let profile = if obfuscate {
        aethernoize_config()
    } else {
        aethernoize::from_profile("off")
    };

    log::info!("[*] [{label}] validating WireGuard tunnel with {peer} (handshake + data-plane)...");
    let (_, session) = wireguard::verify_endpoint_keep_session(
        peer,
        private_key,
        peer_public,
        identity.client_id,
        ipv4,
        &profile,
        wg_tunnel_validate_timeout(),
        Some(keepalive),
    )
    .await
    .map_err(|e| AetherError::Other(format!("[{label}] tunnel failed validation: {e}")))?;
    log::info!("[+] [{label}] wireguard tunnel validated (end-to-end data confirmed)");

    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());

    let tunnel = wireguard::WgTunnel::from_established(
        session,
        std::sync::Arc::new(profile),
        inbound_tx,
        ipv4,
    );
    let stack = netstack::spawn(&identity.ipv4, &identity.ipv6, mtu, inbound_rx, outbound_tx)?;

    let exit = tokio::spawn(async move {
        match tunnel.run(outbound_rx).await {
            Ok(()) => {
                log::warn!("[-] [{label}] wireguard tunnel closed");
                Ok(())
            }
            Err(e) => {
                log::warn!("[-] [{label}] wireguard tunnel exited: {e}");
                Err(AetherError::Other(format!("[{label}] {e}")))
            }
        }
    });

    Ok((stack, exit))
}

struct TaskGuard(Vec<tokio::task::AbortHandle>);

impl TaskGuard {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, handle: tokio::task::AbortHandle) {
        self.0.push(handle);
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        for handle in self.0.drain(..) {
            handle.abort();
        }
    }
}

async fn spawn_udp_forwarder(
    outer: &netstack::StackHandle,
    remote: SocketAddr,
) -> Result<(SocketAddr, TaskGuard)> {
    let sock = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
    let local = sock.local_addr()?;

    let udp = outer.open_udp().await?;
    let (udp_tx, mut udp_rx) = udp.into_split();

    let inner_peer: std::sync::Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(None));

    let up_sock = sock.clone();
    let up_peer = inner_peer.clone();
    let up_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = up_sock.recv_from(&mut buf).await {
            {
                let mut known = up_peer.lock().await;
                if *known != Some(from) {
                    if let Some(previous) = *known {
                        log::debug!("inner udp forwarder follows {from} now, was {previous}");
                    }
                    *known = Some(from);
                }
            }
            if udp_tx.send_to(remote, buf[..n].to_vec()).await.is_err() {
                break;
            }
        }
    });

    let down_sock = sock.clone();
    let down_peer = inner_peer.clone();
    let down_task = tokio::spawn(async move {
        while let Some((_src, data)) = udp_rx.recv().await {
            let dst = *down_peer.lock().await;
            if let Some(dst) = dst {
                let _ = down_sock.send_to(&data, dst).await;
            }
        }
    });

    let guard = TaskGuard(vec![up_task.abort_handle(), down_task.abort_handle()]);

    Ok((local, guard))
}

async fn run_warp_in_warp(
    primary: account::Identity,
    secondary: account::Identity,
    peer: SocketAddr,
    inner_peer: SocketAddr,
    listen: SocketAddr,
) -> Result<()> {
    if inner_peer.ip() == peer.ip() {
        return Err(AetherError::Other(format!(
            "warp-in-warp needs two separate edges but both hops landed on {}",
            peer.ip()
        )));
    }

    let mut tasks = TaskGuard::new();

    log::info!("[*] establishing outer WARP tunnel to {peer}...");
    let (outer_stack, mut outer_exit) =
        establish_wg(&primary, peer, TUNNEL_MTU, true, 5, "outer").await?;
    tasks.push(outer_exit.abort_handle());

    let (forwarder, _forwarder_guard) = spawn_udp_forwarder(&outer_stack, inner_peer).await?;
    log::info!("[+] inner endpoint {inner_peer} tunneled through outer warp via {forwarder}");

    log::info!("[*] establishing inner WARP tunnel (warp-in-warp)...");
    let (inner_stack, mut inner_exit) =
        establish_wg(&secondary, forwarder, INNER_MTU, false, 20, "inner").await?;
    tasks.push(inner_exit.abort_handle());

    let policy = exitloc::Policy::from_env();
    exitloc::settle(&inner_stack, &policy, "warp-in-warp").await?;
    let policy_stack = inner_stack.clone();

    let socks_listener = socks::bind_listener("socks5", listen).await?;
    let http_listener = bind_http_proxy().await?;

    let http_task = spawn_http_proxy(http_listener, &inner_stack);
    if let Some(task) = &http_task {
        tasks.push(task.abort_handle());
    }
    let mut socks_task =
        tokio::spawn(async move { socks::serve(socks_listener, inner_stack).await });
    tasks.push(socks_task.abort_handle());

    #[derive(PartialEq)]
    enum Winner {
        Outer,
        Inner,
        Socks,
        Policy,
    }

    let (outcome, winner) = tokio::select! {
        result = &mut outer_exit => (join_outcome("outer wireguard tunnel", result), Winner::Outer),
        result = &mut inner_exit => (join_outcome("inner wireguard tunnel", result), Winner::Inner),
        result = &mut socks_task => (join_outcome("socks5 server", result), Winner::Socks),
        reason = exit_policy_guard(&policy_stack, &policy) => (Err(reason), Winner::Policy),
    };

    if let Some(task) = &http_task {
        task.abort();
    }

    if winner != Winner::Outer {
        outer_exit.abort();
        let _ = outer_exit.await;
    }
    if winner != Winner::Inner {
        inner_exit.abort();
        let _ = inner_exit.await;
    }
    if winner != Winner::Socks {
        socks_task.abort();
        let _ = socks_task.await;
    }

    drop(outer_stack);

    outcome
}

/// Whether a tunnel of `protocol` needs UDP to reach WARP, which Tor and Psiphon around the tunnel
/// do not carry: WireGuard does, and so does the classic gool, WireGuard in WireGuard. Gool over
/// masque dials MASQUE alone, which runs over HTTP/2.
fn needs_udp_to_warp(protocol: Protocol, classic_gool: bool) -> bool {
    match protocol {
        Protocol::WireGuard => true,
        Protocol::WarpInWarp => classic_gool,
        Protocol::Masque | Protocol::MasqueInMasque => false,
    }
}

fn gool_classic() -> bool {
    matches!(
        std::env::var("AETHER_GOOL_MODE").as_deref(),
        Ok("wiw") | Ok("wg") | Ok("classic")
    ) || ["AETHER_WIW_OUTER_PEER", "AETHER_WIW_INNER_PEER", "AETHER_WIW_PEERS"]
        .iter()
        .any(|key| env_value(key).is_some())
}

fn gool_inner_peers(identity: &account::Identity) -> Result<Vec<SocketAddr>> {
    if let Some(value) = env_value("AETHER_GOOL_INNER") {
        return Ok(vec![parse_endpoint(&value)?]);
    }
    let mut peers: Vec<SocketAddr> = Vec::new();
    let named = std::iter::once(identity.assigned_endpoint.trim())
        .chain(wireguard::wg_seeds_v4());
    for host in named {
        if let Ok(ip) = host.parse::<IpAddr>() {
            let peer = SocketAddr::new(ip, WG_EXAMPLE_PORT);
            if !peers.contains(&peer) {
                peers.push(peer);
            }
        }
    }
    Ok(peers)
}

async fn gool_inner_identity(
    outer: &netstack::StackHandle,
    inner_path: &str,
) -> Result<account::Identity> {
    if let Some(identity) = config::load(inner_path)? {
        log::info!("[+] loaded the gool wireguard identity from {inner_path}");
        return Ok(identity);
    }

    let listener = socks::bind_listener("socks5", "127.0.0.1:0".parse().unwrap()).await?;
    let through = listener.local_addr()?;
    let stack = outer.clone();
    let socks_task = tokio::spawn(async move { socks::serve(listener, stack).await });
    let _socks_guard = TaskGuard(vec![socks_task.abort_handle()]);

    log::info!("[*] registering the gool wireguard identity through the masque tunnel");
    // Through the tunnel for this registration alone: AETHER_UPSTREAM, which the rest of the
    // process dials out through, stays as it is.
    let tunnel = upstream::Upstream::parse(&format!("socks5h://{through}"))?;
    let identity = upstream::through(tunnel, provision_gool(inner_path)).await?;
    log::info!(
        "[+] gool wireguard identity registered from inside warp and saved to {inner_path}: device={} ipv4={}",
        identity.device_id,
        identity.ipv4
    );
    Ok(identity)
}

/// `--register gool`: the wireguard identity gool carries inside its masque tunnel, saved at `path`,
/// or a new one registered now, from where the other identities are registered. The tunnel
/// registers one from inside warp only when there is none, see [`gool_inner_identity`].
async fn load_or_provision_gool(path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(path)? {
        log::info!("[+] loaded the gool wireguard identity from {path}");
        return Ok(identity);
    }
    let identity = provision_gool(path).await?;
    log::info!(
        "[+] gool wireguard identity registered and saved to {path}: device={} ipv4={}",
        identity.device_id,
        identity.ipv4
    );
    Ok(identity)
}

/// Registers the wireguard identity gool carries inside its masque tunnel, enables WARP on it and
/// saves it at `path` once both are done, see [`enable_warp_on`]. The tunnel tries again at each
/// reconnect, so a device registered here whose enabling failed is kept for the next try of this
/// run, which enables it rather than registering yet another, unless the API refused it.
async fn provision_gool(path: &str) -> Result<account::Identity> {
    let kept = GOOL_NOT_ENABLED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    let registered = match kept {
        Some(identity) => identity,
        None => account::provision_wg(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, None).await?,
    };
    if let Err(error) = enable_warp_on(&registered).await {
        if worth_enabling_again(&error) {
            *GOOL_NOT_ENABLED.lock().unwrap_or_else(|e| e.into_inner()) = Some(registered);
        }
        return Err(error);
    }
    config::save(path, &registered)?;
    Ok(registered)
}

/// The gool device of this run that is registered but not enabled yet, see [`provision_gool`].
static GOOL_NOT_ENABLED: std::sync::Mutex<Option<account::Identity>> = std::sync::Mutex::new(None);

/// Whether a device whose WARP enabling ended in `error` is worth enabling again rather than
/// registering anew: not when the API refused the device itself.
fn worth_enabling_again(error: &AetherError) -> bool {
    !matches!(error, AetherError::IdentityRefused(_))
}

const GOOL_INNER_ATTEMPTS: u32 = 2;

async fn run_gool_tunnel(
    identity: &account::Identity,
    peer: SocketAddr,
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
    inner_path: &str,
) -> Result<()> {
    let h2 = masque_h2::enabled();
    let dial = if h2 { masque_h2::h2_peer(peer) } else { peer };

    let mut outer = establish_masque(
        identity,
        dial,
        ech,
        h2,
        masque_tunnel_mtu(),
        quic::MAX_DATAGRAM_SIZE,
        true,
        masque_startup_timeout(),
        "outer",
    )
    .await?;

    let inner_identity = gool_inner_identity(&outer.stack, inner_path).await?;
    let candidates = gool_inner_peers(&inner_identity)?;

    let mut established = None;
    let mut last_error = AetherError::Other("no wireguard endpoint to try".into());
    'peers: for inner_peer in candidates {
        let (forwarder, forwarder_guard) = spawn_udp_forwarder(&outer.stack, inner_peer).await?;
        log::info!("[*] wireguard to {inner_peer} rides inside the masque tunnel via {forwarder}");
        for attempt in 1..=GOOL_INNER_ATTEMPTS {
            match establish_wg(&inner_identity, forwarder, INNER_MTU, false, 25, "inner").await {
                Ok(hop) => {
                    established = Some((inner_peer, hop, forwarder_guard));
                    break 'peers;
                }
                Err(e) => {
                    log::warn!("[-] inner wireguard {inner_peer} attempt {attempt} failed: {e}");
                    last_error = e;
                }
            }
        }
    }
    let Some((inner_peer, (inner_stack, mut inner_exit), _forwarder_guard)) = established else {
        return Err(last_error);
    };
    if inner_identity.assigned_endpoint != inner_peer.ip().to_string()
        && env_value("AETHER_GOOL_INNER").is_none()
    {
        let remembered = account::Identity {
            assigned_endpoint: inner_peer.ip().to_string(),
            ..inner_identity.clone()
        };
        if config::save(inner_path, &remembered).is_ok() {
            log::info!("[+] gool remembers {} as its wireguard endpoint", inner_peer.ip());
        }
    }

    let policy = exitloc::Policy::from_env();
    exitloc::settle(&inner_stack, &policy, "gool").await?;
    let policy_stack = inner_stack.clone();

    let socks_listener = socks::bind_listener("socks5", listen).await?;
    let http_listener = bind_http_proxy().await?;

    let mut tasks = TaskGuard::new();
    let http_task = spawn_http_proxy(http_listener, &inner_stack);
    if let Some(task) = &http_task {
        tasks.push(task.abort_handle());
    }
    let socks_stack = inner_stack.clone();
    let mut socks_task =
        tokio::spawn(async move { socks::serve(socks_listener, socks_stack).await });
    tasks.push(socks_task.abort_handle());

    log::info!("[+] gool ready: masque {peer} carries wireguard {inner_peer}");

    #[derive(PartialEq)]
    enum Winner {
        Outer,
        Inner,
        Socks,
        Policy,
    }

    let (outcome, winner) = tokio::select! {
        result = &mut outer.exit => (join_outcome("outer masque tunnel", result), Winner::Outer),
        result = &mut inner_exit => (join_outcome("inner wireguard tunnel", result), Winner::Inner),
        result = &mut socks_task => (join_outcome("socks5 server", result), Winner::Socks),
        reason = exit_policy_guard(&policy_stack, &policy) => (Err(reason), Winner::Policy),
    };

    if winner != Winner::Outer {
        outer.exit.abort();
        let _ = (&mut outer.exit).await;
    }
    if winner != Winner::Inner {
        inner_exit.abort();
        let _ = (&mut inner_exit).await;
    }
    if winner != Winner::Socks {
        socks_task.abort();
        let _ = (&mut socks_task).await;
    }

    outcome
}

fn join_outcome(
    what: &str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    match result {
        Ok(Ok(())) => Err(AetherError::Other(format!("{what} stopped"))),
        Ok(Err(e)) => Err(e),
        Err(e) if e.is_cancelled() => Err(AetherError::Other(format!("{what} was cancelled"))),
        Err(e) => Err(AetherError::Other(format!("{what} panicked: {e}"))),
    }
}

async fn prompt_line(prompt: &str) -> Option<String> {
    use std::io::IsTerminal;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    if !std::io::stdin().is_terminal() {
        return None;
    }

    let mut stdout = tokio::io::stdout();
    let _ = stdout.write_all(prompt.as_bytes()).await;
    let _ = stdout.flush().await;

    let mut line = String::new();
    let mut reader = BufReader::new(tokio::io::stdin());
    match reader.read_line(&mut line).await {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

const SCAN_MODE_PROMPT: &str = "\nScan mode:\n  [1] turbo     (fast, first hit)\n  [2] balanced  (default)\n  [3] thorough  (deep, best ping)\n  [4] verified  (measured edges only, never a guessed neighbour; on gool and\n                 mim it keeps the two hops in different ranges, which is what\n                 moves the exit address)\n  [5] ironclad  (real tunnel + real HTTP check per candidate, guaranteed working)\nChoose [1-5] (default 2): ";

const MIM_MANUAL_TIP: &str = "\n(tip: you can skip this scan and give the two masque hops yourself:\n        aether --mim --mim-outer <ip:port> --mim-inner <ip:port>\n      the port is required, and naming just the outer one lets aether pick\n      the inner edge for you)\n";

const WIW_MANUAL_TIP: &str = "\n(tip: you can skip this scan and give the two gool hops yourself:\n        aether --gool --wiw-outer <ip:port> --wiw-inner <ip:port>\n      the port is required, and naming just one of the two lets the scan\n      find the other)\n";

async fn select_scan_mode() -> prober::ScanMode {
    if let Ok(v) = std::env::var("AETHER_SCAN") {
        return prober::ScanMode::parse(&v);
    }

    let answer = prompt_line(SCAN_MODE_PROMPT).await;

    match answer.as_deref() {
        Some("1") => prober::ScanMode::Turbo,
        Some("3") => prober::ScanMode::Thorough,
        Some("4") => prober::ScanMode::Verified,
        Some("5") => prober::ScanMode::Ironclad,
        _ => prober::ScanMode::Balanced,
    }
}

async fn select_scan_mode_str(tip: &str) -> String {
    if let Ok(v) = std::env::var("AETHER_SCAN") {
        return v;
    }

    let answer = prompt_line(&format!("{tip}{SCAN_MODE_PROMPT}")).await;

    match answer.as_deref() {
        Some("1") => "turbo".to_string(),
        Some("3") => "thorough".to_string(),
        Some("4") => "verified".to_string(),
        Some("5") => "ironclad".to_string(),
        _ => "balanced".to_string(),
    }
}

async fn select_protocol(base: &str) -> Protocol {
    if let Ok(v) = std::env::var("AETHER_PROTOCOL") {
        return Protocol::parse(&v);
    }

    loop {
        let mut extra = String::new();
        let mut next = 5u8;
        let take = |line: &str, extra: &mut String, next: &mut u8| -> String {
            let key = next.to_string();
            extra.push_str(&format!("  [{key}] {line}\n"));
            *next += 1;
            key
        };

        let (tor_alone, tor_chain) = if cfg!(feature = "tor") {
            (
                take("Tor alone, with no warp under it", &mut extra, &mut next),
                take(
                    "Tor and warp chained, either way round",
                    &mut extra,
                    &mut next,
                ),
            )
        } else {
            (String::new(), String::new())
        };

        let psiphon_alone = take(
            "Psiphon alone, with no warp under it",
            &mut extra,
            &mut next,
        );
        let psiphon_chain = take(
            "Psiphon and warp chained, either way round",
            &mut extra,
            &mut next,
        );

        let last = next;
        let zero_trust_key = last.to_string();
        let zero_trust = match team_scope() {
            Some(team) => {
                format!("  [{last}] Zero Trust: signed in to {team}, pick another team\n")
            }
            None => {
                format!("  [{last}] Zero Trust: sign in to an organization (WARP for teams)\n")
            }
        };

        let answer = prompt_line(&format!(
            "\nProtocol:\n  [1] MASQUE (modern, QUIC/H3, default)\n  \
             [2] WireGuard (classic, faster)\n  [3] WARP-in-WARP / gool\n  \
             [4] MASQUE-in-MASQUE (two masque hops, for a different exit address)\n\
             {extra}{zero_trust}Choose [1-{last}] (default 1): "
        ))
        .await;

        let choice = answer.as_deref().unwrap_or_default();

        match choice {
            "2" => return Protocol::WireGuard,
            "3" => return select_gool().await,
            "4" => return Protocol::MasqueInMasque,
            _ if choice == zero_trust_key => {
                enrol_zero_trust(base).await;
                continue;
            }
            _ if !tor_alone.is_empty() && choice == tor_alone => {
                std::env::set_var("AETHER_TOR", "only");
                return Protocol::Masque;
            }
            _ if !tor_chain.is_empty() && choice == tor_chain => return select_tor_chain().await,
            _ if choice == psiphon_alone => {
                std::env::set_var("AETHER_PSIPHON", "only");
                return Protocol::Masque;
            }
            _ if choice == psiphon_chain => return select_psiphon_chain().await,
            _ => return Protocol::Masque,
        }
    }
}

async fn select_gool() -> Protocol {
    let answer = prompt_line(
        "\nWhich gool?\n  \
         [1] gool over masque: wireguard carried inside a masque tunnel, for a foreign exit \
         address (default)\n  \
         [2] classic gool: wireguard carried inside wireguard, a plain warp exit\n\
         Choose [1-2] (default 1): ",
    )
    .await;

    if matches!(answer.as_deref(), Some("2")) {
        std::env::set_var("AETHER_GOOL_MODE", "classic");
    }
    Protocol::WarpInWarp
}

async fn select_psiphon_chain() -> Protocol {
    let answer = prompt_line(
        "\nWhich way round?\n  \
         [1] psiphon inside warp: you, warp, psiphon, the internet. The exit is a psiphon \
         exit, and a network that blocks psiphon never sees it (default)\n  \
         [2] warp inside psiphon: you, psiphon, warp, the internet. The exit is a warp exit \
         reached from a psiphon exit, and your network never sees warp\n\
         Choose [1-2] (default 1): ",
    )
    .await;

    if matches!(answer.as_deref(), Some("2")) {
        std::env::set_var("AETHER_PSIPHON", "reverse");
        log::info!("[*] the tunnel will be dialled through psiphon, on the http/2 carrier");
        return Protocol::Masque;
    }

    std::env::set_var("AETHER_PSIPHON", "chain");
    log::info!("[*] psiphon will be carried inside the tunnel");
    select_chain_carrier("psiphon").await
}

async fn select_tor_chain() -> Protocol {
    let answer = prompt_line(
        "\nWhich way round?\n  \
         [1] tor inside warp: you, warp, tor, the internet. The exit is a tor exit, and a \
         network that blocks tor never sees it (default)\n  \
         [2] warp inside tor: you, tor, warp, the internet. The exit is a warp exit reached \
         from a tor exit, and your network never sees warp\n\
         Choose [1-2] (default 1): ",
    )
    .await;

    if matches!(answer.as_deref(), Some("2")) {
        std::env::set_var("AETHER_TOR", "reverse");
        log::info!("[*] the tunnel will be dialled through tor, on the http/2 carrier");
        return Protocol::Masque;
    }

    std::env::set_var("AETHER_TOR", "chain");
    log::info!("[*] tor will be carried inside the tunnel");
    select_chain_carrier("tor").await
}

async fn select_chain_carrier(what: &str) -> Protocol {
    let answer = prompt_line(&format!(
        "\nWhat carries {what}?\n  \
         [1] MASQUE, over quic/h3 or http/2, asked next (default)\n  \
         [2] WireGuard, warp over udp\n  \
         [3] WARP-in-WARP / gool\n  \
         [4] MASQUE-in-MASQUE\n\
         Choose [1-4] (default 1): "
    ))
    .await;

    match answer.as_deref() {
        Some("2") => Protocol::WireGuard,
        Some("3") => select_gool().await,
        Some("4") => Protocol::MasqueInMasque,
        _ => Protocol::Masque,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Masque,
    WireGuard,
    WarpInWarp,
    MasqueInMasque,
}

impl Protocol {
    fn parse(s: &str) -> Protocol {
        match s.trim().to_lowercase().as_str() {
            "wg" | "wireguard" => Protocol::WireGuard,
            "gool" | "wiw" | "warp-in-warp" | "warpinwarp" => Protocol::WarpInWarp,
            "mim" | "m2" | "masque-in-masque" | "masqueinmasque" => Protocol::MasqueInMasque,
            _ => Protocol::Masque,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Protocol::Masque => "MASQUE",
            Protocol::WireGuard => "WireGuard",
            Protocol::WarpInWarp => "WARP-in-WARP (gool)",
            Protocol::MasqueInMasque => "MASQUE-in-MASQUE",
        }
    }
}

async fn select_masque_transport() {
    if std::env::var("AETHER_MASQUE_HTTP2").is_ok() || std::env::var("AETHER_PEER").is_ok() {
        return;
    }

    let answer = prompt_line(
        "\nMASQUE transport:\n  [1] HTTP/3 (QUIC)  (default; fastest handshake, best on healthy UDP networks)\n  [2] HTTP/2 (TCP)   (looks like ordinary HTTPS; use if UDP/QUIC is blocked or throttled)\nChoose [1-2] (default 1): ",
    )
    .await;

    if matches!(answer.as_deref(), Some("2")) {
        std::env::set_var("AETHER_MASQUE_HTTP2", "1");
    }
}

fn scan_settings_from_env() -> (String, prober::IpScan) {
    let mode = std::env::var("AETHER_SCAN").unwrap_or_default();
    let ip = std::env::var("AETHER_IP")
        .map(|value| prober::IpScan::parse(&value))
        .unwrap_or(prober::IpScan::V4);
    (mode, ip)
}

async fn select_ip_version() -> prober::IpScan {
    if let Ok(v) = std::env::var("AETHER_IP") {
        return prober::IpScan::parse(&v);
    }

    let answer = prompt_line(
        "\nIP version to scan:\n  [1] IPv4 (default)\n  [2] IPv6\n  [3] Both\nChoose [1-3] (default 1): ",
    )
    .await;

    match answer.as_deref() {
        Some("2") => prober::IpScan::V6,
        Some("3") => prober::IpScan::Both,
        _ => prober::IpScan::V4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let values: BTreeMap<String, String> = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        move |key: &str| values.get(key).cloned()
    }

    #[test]
    fn tor_and_psiphon_around_the_tunnel_refuse_only_what_needs_udp() {
        assert!(needs_udp_to_warp(Protocol::WireGuard, false));
        assert!(needs_udp_to_warp(Protocol::WarpInWarp, true));
        // Gool over masque reaches WARP by MASQUE alone; its WireGuard rides inside that tunnel.
        assert!(!needs_udp_to_warp(Protocol::WarpInWarp, false));
        assert!(!needs_udp_to_warp(Protocol::Masque, true));
        assert!(!needs_udp_to_warp(Protocol::MasqueInMasque, false));
    }

    #[test]
    fn a_gool_device_is_enabled_again_unless_the_api_refused_it() {
        assert!(worth_enabling_again(&AetherError::Api(
            "enabling warp: timed out".into()
        )));
        assert!(!worth_enabling_again(&AetherError::IdentityRefused(
            "enabling warp: 401".into()
        )));
    }

    /// How long a tunnel lasted that ended soon after it started.
    const SOON: std::time::Duration = std::time::Duration::from_secs(10);

    #[test]
    fn a_masque_gateway_is_left_once_its_tunnel_ended_twice_in_a_row() {
        let gateway: SocketAddr = "162.159.198.1:443".parse().unwrap();
        let now = Instant::now();
        let rest = std::time::Duration::from_secs(300);
        let mut strikes = GatewayStrikes::default();

        strikes.using(gateway);
        strikes.ended(SOON);
        assert_eq!(strikes.give_up(now, rest), None);
        // The reconnect goes back to it, and it ends again.
        strikes.using(gateway);
        strikes.ended(SOON);
        assert_eq!(strikes.give_up(now, rest), Some(gateway));
        // Out of the scans on any port until it has rested; the count starts over.
        assert!(strikes.left_out(now).contains(&gateway.ip()));
        assert_eq!(strikes.give_up(now, rest), None);
        assert!(strikes.left_out(now + rest).is_empty());
    }

    #[test]
    fn another_masque_gateway_starts_with_no_strikes() {
        let first: SocketAddr = "162.159.198.1:443".parse().unwrap();
        let second: SocketAddr = "162.159.198.2:443".parse().unwrap();
        let now = Instant::now();
        let rest = std::time::Duration::from_secs(300);
        let mut strikes = GatewayStrikes::default();

        strikes.using(first);
        strikes.ended(SOON);
        strikes.using(second);
        strikes.ended(SOON);
        assert_eq!(strikes.give_up(now, rest), None);
        assert!(strikes.left_out(now).is_empty());
        // A tunnel that has not ended yet counts for nothing either.
        strikes.using(second);
        assert_eq!(strikes.give_up(now, rest), None);
    }

    #[test]
    fn a_tunnel_that_stayed_up_clears_the_ends_before_it() {
        let gateway: SocketAddr = "162.159.198.1:443".parse().unwrap();
        let now = Instant::now();
        let rest = std::time::Duration::from_secs(300);
        let mut strikes = GatewayStrikes::default();

        // Hours on the gateway, a network change, hours again, another one: it is not left.
        strikes.using(gateway);
        strikes.ended(TUNNEL_STAYED_UP * 36);
        strikes.using(gateway);
        strikes.ended(TUNNEL_STAYED_UP * 24);
        assert_eq!(strikes.give_up(now, rest), None);
        // One that ends soon, then one that stays up: still not.
        strikes.using(gateway);
        strikes.ended(SOON);
        strikes.using(gateway);
        strikes.ended(TUNNEL_STAYED_UP);
        assert_eq!(strikes.give_up(now, rest), None);
        // Two that end soon, one after the other, are what leaves it.
        strikes.using(gateway);
        strikes.ended(SOON);
        assert_eq!(strikes.give_up(now, rest), None);
        strikes.using(gateway);
        strikes.ended(SOON);
        assert_eq!(strikes.give_up(now, rest), Some(gateway));
    }

    #[test]
    fn only_a_tunnel_that_ended_soon_counts_against_its_gateway_or_endpoint() {
        // The WireGuard run counts its endpoint's ends with it too.
        let almost = TUNNEL_STAYED_UP - std::time::Duration::from_secs(1);
        assert_eq!(count_tunnel_end(0, std::time::Duration::ZERO), 1);
        assert_eq!(count_tunnel_end(1, almost), 2);
        assert_eq!(count_tunnel_end(1, TUNNEL_STAYED_UP), 0);
        assert_eq!(count_tunnel_end(7, TUNNEL_STAYED_UP * 2), 0);
        assert_eq!(count_tunnel_end(u32::MAX, SOON), u32::MAX);
    }

    #[test]
    fn register_names_the_identities_of_one_protocol_or_all_five() {
        let all = RegisterSet::parse("all").expect("all");
        assert!(all.wireguard && all.wireguard_inner && all.masque && all.masque_inner && all.gool);

        let masque = RegisterSet::parse(" MASQUE ").expect("masque");
        assert!(masque.masque && !masque.masque_inner && !masque.gool);
        assert!(!masque.wireguard && !masque.wireguard_inner);

        let wireguard = RegisterSet::parse("wg").expect("wg");
        assert!(wireguard.wireguard && !wireguard.wireguard_inner);
        assert!(!wireguard.masque && !wireguard.masque_inner && !wireguard.gool);

        // What --gool runs: masque, and the wireguard identity it carries inside.
        for word in ["gool", "GOOL", "wg-over-masque"] {
            let gool = RegisterSet::parse(word).expect(word);
            assert!(gool.masque && gool.gool, "{word}");
            assert!(
                !gool.masque_inner && !gool.wireguard && !gool.wireguard_inner,
                "{word}"
            );
        }

        // What --gool-classic runs: both wireguard hops.
        for word in ["gool-classic", "wiw", "warp-in-warp"] {
            let classic = RegisterSet::parse(word).expect(word);
            assert!(classic.wireguard && classic.wireguard_inner, "{word}");
            assert!(
                !classic.masque && !classic.masque_inner && !classic.gool,
                "{word}"
            );
        }

        let mim = RegisterSet::parse("mim").expect("mim");
        assert!(mim.masque && mim.masque_inner && !mim.gool);
        assert!(!mim.wireguard && !mim.wireguard_inner);

        assert!(RegisterSet::parse("everything").is_err());
    }

    #[test]
    fn gool_keeps_its_wireguard_identity_beside_the_masque_one() {
        assert_eq!(
            gool_identity_path("/data/files/aether/aether-masque.toml"),
            "/data/files/aether/aether-masque-gool.toml"
        );
        assert_eq!(
            gool_identity_path(r"C:\keys\aether-masque.toml"),
            r"C:\keys\aether-masque-gool.toml"
        );
    }

    #[test]
    fn masque_in_masque_is_selected_by_name() {
        for written in ["mim", "m2", "masque-in-masque", "MIM", "MasqueInMasque"] {
            assert_eq!(
                Protocol::parse(written),
                Protocol::MasqueInMasque,
                "{written}"
            );
        }
    }

    #[test]
    fn the_masque_hops_can_be_named_by_hand() {
        let chosen = mim_endpoints_of(&env(&[
            ("AETHER_MIM_OUTER_PEER", "162.159.192.1:443"),
            ("AETHER_MIM_INNER_PEER", "188.114.96.1:443"),
        ]))
        .expect("both hops");

        assert_eq!(chosen.outer, Some("162.159.192.1:443".parse().unwrap()));
        assert_eq!(chosen.inner, Some("188.114.96.1:443".parse().unwrap()));
    }

    #[test]
    fn the_same_masque_edge_cannot_serve_as_both_hops() {
        assert!(mim_endpoints_of(&env(&[(
            "AETHER_MIM_PEERS",
            "162.159.192.1:443,162.159.192.1:8443"
        )]))
        .is_err());
    }

    #[test]
    fn an_inner_quic_datagram_fits_inside_the_outer_link() {
        let inner: SocketAddr = "162.159.192.1:443".parse().unwrap();
        let (datagram, mtu) = mim_inner_budget(TUNNEL_MTU, inner, false);

        assert!(
            datagram + 28 <= TUNNEL_MTU,
            "a {datagram} byte datagram plus headers must fit {TUNNEL_MTU}"
        );
        assert!(
            datagram >= quic::MIN_DATAGRAM_SIZE,
            "quic needs at least 1200"
        );
        assert!(
            mtu < datagram,
            "the inner link has to leave room for quic itself"
        );
    }

    #[test]
    fn an_ipv6_inner_hop_leaves_room_for_the_bigger_header() {
        let v4: SocketAddr = "162.159.192.1:443".parse().unwrap();
        let v6: SocketAddr = "[2606:4700:d0::a29f:c001]:443".parse().unwrap();

        let (over_v4, _) = mim_inner_budget(TUNNEL_MTU, v4, false);
        let (over_v6, _) = mim_inner_budget(TUNNEL_MTU, v6, false);
        assert!(
            over_v6 < over_v4,
            "{over_v6} should leave more room than {over_v4}"
        );
        assert!(over_v6 + 48 <= TUNNEL_MTU);
    }

    #[test]
    fn an_http2_pair_keeps_the_full_datagram_budget() {
        let inner: SocketAddr = "162.159.192.1:443".parse().unwrap();
        let (datagram, mtu) = mim_inner_budget(H2_TUNNEL_MTU, inner, true);

        assert_eq!(datagram, quic::MAX_DATAGRAM_SIZE);
        assert!(
            mtu < H2_TUNNEL_MTU,
            "the inner link stays under the outer one"
        );
    }

    #[test]
    fn the_inner_edges_come_from_the_range_that_answered() {
        let outer: SocketAddr = "162.159.198.104:8443".parse().unwrap();
        let candidates = inner_masque_candidates(outer, MIM_INNER_TRIES, false);

        assert_eq!(candidates.len(), MIM_INNER_TRIES);
        for candidate in &candidates {
            assert_ne!(
                candidate.ip(),
                outer.ip(),
                "the inner hop needs its own edge"
            );
            assert_eq!(candidate.port(), MASQUE_INNER_PORT);
            match candidate.ip() {
                IpAddr::V4(v4) => {
                    let outer_octets = match outer.ip() {
                        IpAddr::V4(ip) => ip.octets(),
                        IpAddr::V6(_) => unreachable!(),
                    };
                    assert_eq!(
                        v4.octets()[..3],
                        outer_octets[..3],
                        "same /24 as the edge that worked"
                    );
                }
                IpAddr::V6(_) => unreachable!(),
            }
        }

        let all: HashSet<SocketAddr> = candidates.iter().copied().collect();
        assert_eq!(all.len(), candidates.len(), "candidates must be distinct");
    }

    #[test]
    fn the_verified_ladder_leaves_the_outer_range_first() {
        let outer: SocketAddr = "162.159.198.1:443".parse().unwrap();
        let candidates = inner_masque_candidates(outer, MIM_INNER_TRIES, true);

        assert!(!candidates.is_empty());
        assert!(candidates.iter().all(|peer| peer.ip() != outer.ip()));

        let first = candidates[0];
        assert_ne!(
            edge_network(first.ip()),
            edge_network(outer.ip()),
            "the first inner candidate must leave the outer range"
        );

        let verified: HashSet<IpAddr> = prober::MASQUE_VERIFIED_GATEWAYS
            .iter()
            .filter_map(|entry| entry.parse().ok())
            .collect();
        let measured = candidates
            .iter()
            .take_while(|peer| verified.contains(&peer.ip()))
            .count();
        assert!(measured > 0, "the measured edges must come first");
        assert!(
            candidates.len() > measured,
            "a guessed neighbour must stay on the end: a verified address is only \
             verified for the path it was measured on"
        );
    }

    #[test]
    fn a_verified_ladder_is_not_used_for_an_ipv6_outer() {
        let outer: SocketAddr = "[2606:4700:d0::a29f:c601]:443".parse().unwrap();
        let candidates = inner_masque_candidates(outer, 4, true);

        assert!(candidates.iter().all(|candidate| candidate.is_ipv6()));
    }

    #[test]
    fn spreading_hops_puts_a_different_range_second() {
        let mut found: Vec<SocketAddr> = vec![
            "162.159.192.1:2408".parse().unwrap(),
            "162.159.192.9:2408".parse().unwrap(),
            "188.114.96.1:2408".parse().unwrap(),
        ];
        spread_hops(&mut found);

        assert_eq!(edge_network(found[0].ip()), Some([162, 159, 192]));
        assert_ne!(
            edge_network(found[1].ip()),
            edge_network(found[0].ip()),
            "the second hop must sit in another range"
        );
    }

    #[test]
    fn an_ipv6_outer_edge_yields_ipv6_inner_candidates() {
        let outer: SocketAddr = "[2606:4700:d0::a29f:c601]:443".parse().unwrap();
        let candidates = inner_masque_candidates(outer, 4, false);

        assert_eq!(candidates.len(), 4);
        assert!(candidates.iter().all(|candidate| candidate.is_ipv6()));
        assert!(candidates
            .iter()
            .all(|candidate| candidate.ip() != outer.ip()));
    }

    #[test]
    fn an_address_and_a_port_are_read_together() {
        let peer = parse_endpoint("162.159.192.1:894").expect("address and port");
        assert_eq!(peer, "162.159.192.1:894".parse().unwrap());
    }

    #[test]
    fn an_address_without_a_port_is_refused_rather_than_guessed_at() {
        let message = parse_endpoint("162.159.192.1")
            .expect_err("the port carries too much meaning to be assumed")
            .to_string();
        assert!(
            message.contains("162.159.192.1:2408"),
            "the error should spell out the shape wanted, got: {message}"
        );
    }

    #[test]
    fn an_ipv6_address_without_a_port_is_refused_the_same_way() {
        for written in ["2606:4700:d0::a29f:c001", "[2606:4700:d0::a29f:c001]"] {
            let message = parse_endpoint(written).expect_err(written).to_string();
            assert!(
                message.contains("[2606:4700:d0::a29f:c001]:2408"),
                "the error should bracket the address it suggests, got: {message}"
            );
        }
    }

    #[test]
    fn surrounding_whitespace_is_forgiven() {
        let peer = parse_endpoint("  162.159.192.1:2408  ").expect("padded");
        assert_eq!(peer, "162.159.192.1:2408".parse().unwrap());
    }

    #[test]
    fn ipv6_is_read_when_it_is_bracketed_and_carries_its_port() {
        let peer = parse_endpoint("[2606:4700:d0::a29f:c001]:2408").expect("ipv6 endpoint");
        assert_eq!(peer, "[2606:4700:d0::a29f:c001]:2408".parse().unwrap());
    }

    #[test]
    fn nonsense_is_reported_with_an_example_to_copy() {
        let message = parse_endpoint("not-an-address")
            .expect_err("a hostname is not an address")
            .to_string();
        assert!(
            message.contains("162.159.192.1:2408"),
            "the error should show the shape expected, got: {message}"
        );
    }

    #[test]
    fn an_impossible_port_is_rejected_rather_than_wrapped() {
        assert!(parse_endpoint("162.159.192.1:70000").is_err());
    }

    #[test]
    fn a_pair_may_be_written_with_a_comma_or_a_space() {
        for written in [
            "162.159.192.1:2408,162.159.195.1:500",
            "162.159.192.1:2408, 162.159.195.1:500",
            "162.159.192.1:2408 162.159.195.1:500",
        ] {
            let peers = parse_endpoint_list(written).expect(written);
            assert_eq!(peers.len(), 2, "{written} names two hops");
            assert_eq!(peers[0], "162.159.192.1:2408".parse().unwrap());
            assert_eq!(peers[1], "162.159.195.1:500".parse().unwrap());
        }
    }

    #[test]
    fn a_third_address_is_refused_because_there_are_only_two_hops() {
        let outcome = parse_endpoint_list("1.1.1.1:2408,2.2.2.2:2408,3.3.3.3:2408");
        assert!(outcome.is_err());
    }

    #[test]
    fn the_pair_setting_fills_the_outer_hop_first() {
        let chosen = wiw_endpoints_of(&env(&[(
            "AETHER_WIW_PEERS",
            "162.159.192.1:2408,162.159.195.1:500",
        )]))
        .expect("a usable pair");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("162.159.195.1:500".parse().unwrap()));
    }

    #[test]
    fn one_address_pins_the_outer_hop_and_leaves_the_inner_one_to_the_scan() {
        let chosen = wiw_endpoints_of(&env(&[("AETHER_WIW_PEERS", "162.159.192.1:894")]))
            .expect("a single hop");
        assert_eq!(chosen.outer, Some("162.159.192.1:894".parse().unwrap()));
        assert_eq!(chosen.inner, None);
    }

    #[test]
    fn a_hop_named_on_its_own_wins_over_the_pair() {
        let chosen = wiw_endpoints_of(&env(&[
            ("AETHER_WIW_PEERS", "162.159.192.1:2408,162.159.195.1:500"),
            ("AETHER_WIW_INNER_PEER", "188.114.96.1:1701"),
        ]))
        .expect("the inner override");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("188.114.96.1:1701".parse().unwrap()));
    }

    #[test]
    fn only_the_inner_hop_may_be_pinned() {
        let chosen = wiw_endpoints_of(&env(&[("AETHER_WIW_INNER_PEER", "188.114.96.1:2408")]))
            .expect("the inner hop");
        assert_eq!(chosen.outer, None);
        assert_eq!(chosen.inner, Some("188.114.96.1:2408".parse().unwrap()));
    }

    #[test]
    fn one_address_cannot_serve_as_both_hops() {
        let outcome = wiw_endpoints_of(&env(&[
            ("AETHER_WIW_OUTER_PEER", "162.159.192.1:2408"),
            ("AETHER_WIW_INNER_PEER", "162.159.192.1:894"),
        ]));

        let message = outcome
            .expect_err("the same edge twice is not warp-in-warp")
            .to_string();
        assert!(
            message.contains("162.159.192.1"),
            "the error should name the address, got: {message}"
        );
    }

    #[test]
    fn asking_for_a_scan_leaves_both_hops_open() {
        for written in ["auto", "scan", "off", "none", "0"] {
            let lookup = env(&[("AETHER_WIW_PEERS", written)]);
            assert!(wiw_scan_requested(&lookup), "{written} means scan");
            assert!(
                wiw_endpoints_of(&lookup).expect(written).is_empty(),
                "{written} should pin nothing"
            );
        }
    }

    #[test]
    fn nothing_set_pins_nothing() {
        assert!(wiw_endpoints_of(&env(&[])).expect("empty").is_empty());
    }

    #[test]
    fn a_malformed_address_is_an_error_rather_than_a_silent_scan() {
        assert!(wiw_endpoints_of(&env(&[("AETHER_WIW_OUTER_PEER", "162.159.192")])).is_err());
    }

    #[test]
    fn a_hop_set_without_a_port_is_an_error_rather_than_a_silent_scan() {
        assert!(wiw_endpoints_of(&env(&[("AETHER_WIW_OUTER_PEER", "162.159.192.1")])).is_err());
    }

    #[test]
    fn the_older_wg_peer_setting_still_names_the_outer_hop() {
        let chosen = wiw_endpoints_with_fallback(&env(&[("AETHER_WG_PEER", "162.159.192.1:2408")]))
            .expect("the documented --gool --wg-peer pairing");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, None);
    }

    #[test]
    fn the_generic_peer_setting_is_the_last_fallback() {
        let chosen = wiw_endpoints_with_fallback(&env(&[("AETHER_PEER", "162.159.192.1:2408")]))
            .expect("--peer names the outer hop too");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
    }

    #[test]
    fn a_hop_chosen_for_warp_in_warp_beats_the_older_setting() {
        let chosen = wiw_endpoints_with_fallback(&env(&[
            ("AETHER_WG_PEER", "162.159.192.1:2408"),
            ("AETHER_WIW_OUTER_PEER", "188.114.96.1:2408"),
        ]))
        .expect("the warp-in-warp setting is the specific one");
        assert_eq!(chosen.outer, Some("188.114.96.1:2408".parse().unwrap()));
    }

    #[test]
    fn the_older_setting_may_carry_both_hops_at_once() {
        let chosen = wiw_endpoints_with_fallback(&env(&[(
            "AETHER_WG_PEER",
            "162.159.192.1:2408,188.114.96.1:2408",
        )]))
        .expect("a pair");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("188.114.96.1:2408".parse().unwrap()));
    }

    #[test]
    fn the_older_setting_does_not_overwrite_a_pinned_inner_hop() {
        let chosen = wiw_endpoints_with_fallback(&env(&[
            ("AETHER_WG_PEER", "162.159.192.1:2408,188.114.96.1:2408"),
            ("AETHER_WIW_INNER_PEER", "162.159.195.1:2408"),
        ]))
        .expect("the inner hop stays where it was put");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("162.159.195.1:2408".parse().unwrap()));
    }
}

#![allow(dead_code)]
pub mod account;
pub mod api;
pub mod apifront;
pub mod cli;
pub mod config;
pub mod consts;
pub mod dns;
pub mod error;
pub mod ffi;
pub mod fragment;
pub mod lastconn;
pub mod masque;
pub mod masque_h2;
pub mod netstack;
pub mod noize;
pub mod prober;
pub mod routing;
pub mod quic;
pub mod socks;
pub mod sysprofile;
pub mod tls;
pub mod aethernoize;
pub mod tunnelping;
pub mod wireguard;
pub mod wg_prober;
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
const DEFAULT_CONFIG: &str = "aether.toml";

pub async fn run() -> Result<()> {
    run_with(std::env::args().skip(1).collect()).await
}

pub async fn run_with(args: Vec<String>) -> Result<()> {
    cli::parse_args(args)?;

    let level = std::env::var("AETHER_LOG_LEVEL")
        .ok()
        .map(|v| v.trim().to_lowercase())
        .filter(|v| matches!(v.as_str(), "error" | "warn" | "info" | "debug" | "trace"))
        .unwrap_or_else(|| "info".to_string());
    let default_filter = format!("info,aether={level}");
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(default_filter),
    )
    .format_timestamp_millis()
    .try_init();

    log::info!("Aether v{}", env!("CARGO_PKG_VERSION"));
    sysprofile::log_summary();

    install_netstack_panic_guard();

    let listen: SocketAddr = std::env::var("AETHER_SOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:1819".parse().unwrap());

    let base_config = std::env::var("AETHER_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string());

    let protocol = if std::env::var("AETHER_PEER").is_ok() || std::env::var("AETHER_WG_PEER").is_ok() {
        match std::env::var("AETHER_PROTOCOL") {
            Ok(v) => Protocol::parse(&v),
            Err(_) => Protocol::Masque,
        }
    } else {
        select_protocol(&base_config).await
    };

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
            let ech = resolve_ech().await;
            let lastconn_path = lastconn_path(&config_path);
            run_masque(identity, ech, listen, lastconn_path).await
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
        Protocol::WarpInWarp => {
            let primary_path = warp_config_path(&base_config);
            let secondary_path = derive_sibling_path(&primary_path, "secondary");
            let primary = load_or_provision_warp(&primary_path).await?;
            let secondary = load_or_provision_warp(&secondary_path).await?;
            log::info!(
                "[+] outer device={} ipv4={} | inner device={} ipv4={}",
                primary.device_id, primary.ipv4, secondary.device_id, secondary.ipv4
            );
            run_gool(primary, secondary, listen).await
        }
    }
}

async fn run_gool(
    primary: account::Identity,
    secondary: account::Identity,
    listen: SocketAddr,
) -> Result<()> {
    let mut last_peer: Option<SocketAddr> = None;
    let mut consecutive_fails: u32 = 0;
    const MAX_CONSECUTIVE_FAILS: u32 = 2;

    loop {
        let peer = if consecutive_fails < MAX_CONSECUTIVE_FAILS {
            if let Some(p) = last_peer {
                Some(p)
            } else {
                None
            }
        } else {
            if let Some(p) = last_peer {
                log::warn!(
                    "[-] outer endpoint {p} failed {consecutive_fails} times in a row; blacklisting and rescanning"
                );
            }
            None
        };

        let peer = match peer {
            Some(p) => p,
            None => {
                let p = match select_peer(&primary, Protocol::WireGuard).await {
                    Ok(p) => p,
                    Err(e) => {
                        log::warn!("[-] no usable outer WARP endpoint found: {e}; rescanning shortly");
                        tokio::time::sleep(wg_reconnect_delay()).await;
                        continue;
                    }
                };
                consecutive_fails = 0;
                p
            }
        };

        log::info!("[+] using cloudflare edge {peer} (outer)");
        last_peer = Some(peer);

        match run_warp_in_warp(primary.clone(), secondary.clone(), peer, listen).await {
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
    let dir_end = base.rfind(|c| c == '/' || c == '\\').map(|i| i + 1).unwrap_or(0);
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

fn derive_sibling_path(base: &str, suffix: &str) -> String {
    let dir_end = base.rfind(|c| c == '/' || c == '\\').map(|i| i + 1).unwrap_or(0);
    match base[dir_end..].rfind('.') {
        Some(rel) => {
            let dot = dir_end + rel;
            format!("{}-{}{}", &base[..dot], suffix, &base[dot..])
        }
        None => format!("{base}-{suffix}"),
    }
}

async fn load_or_provision_warp(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing warp identity from {config_path}");
        let identity = adopt_team_profile(identity).await;
        config::save(config_path, &identity)?;
        return Ok(identity);
    }

    log::info!("[+] no warp identity found; provisioning dedicated wireguard account");
    let identity = provision_account().await?;
    let identity = adopt_team_profile(identity).await;
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new warp identity to {config_path}");
    Ok(identity)
}

async fn load_or_provision_masque(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing masque identity from {config_path}");
        if identity.has_masque_credentials() {
            let identity = adopt_team_profile(identity).await;
            config::save(config_path, &identity)?;
            return Ok(identity);
        }
        log::info!("[+] masque identity needs a certificate; enrolling masque key");
        let enrollment = account::ensure_masque_enrolled(&identity).await?;
        let identity = account::Identity {
            cert_pem: enrollment.cert_pem,
            key_pem: enrollment.key_pem,
            cert_issued_at: enrollment.issued_at,
            ..identity
        };
        config::save(config_path, &identity)?;
        return Ok(identity);
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
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new masque identity to {config_path}");
    Ok(identity)
}

async fn select_peer(identity: &account::Identity, protocol: Protocol) -> Result<SocketAddr> {
    let force_peer = match protocol {
        Protocol::Masque => std::env::var("AETHER_PEER").ok(),
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
    
    let mode_str = select_scan_mode_str().await;
    let ip = select_ip_version().await;

    match protocol {
        Protocol::Masque => {
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
            log::info!("[+] selected MASQUE gateway {}:{} (rtt {:?})", best.ip, best.port, best.rtt);
            Ok(SocketAddr::new(best.ip, best.port))
        }
        Protocol::WireGuard | Protocol::WarpInWarp => {
            log::info!("[*] hunting for a working WireGuard endpoint (handshake + data-plane verification)");
            let mode = wg_prober::WgScanMode::parse(&mode_str);
            
            let private_key = identity.private_key_bytes()?;
            let peer_public = identity.peer_public_key_bytes()?;
            
            let probe = wg_prober::WgProbe {
                private_key: std::sync::Arc::new(private_key),
                peer_public_key: std::sync::Arc::new(peer_public),
                client_id: identity.client_id.clone(),
                local_ipv4: identity.ipv4.parse().map_err(|_| AetherError::Other("invalid ipv4".into()))?,
                aethernoize: aethernoize_config(),
                ports: wireguard::WG_PORTS.to_vec(),
                ip,
                excluded: HashSet::new(),
            };

            let best = wg_prober::hunt_best_wg_endpoint(&probe, mode).await?;
            log::info!("[+] selected WireGuard endpoint {}:{} (rtt {:?})", best.ip, best.port, best.rtt);
            Ok(SocketAddr::new(best.ip, best.port))
        }
    }
}

async fn resolve_ech() -> Option<Vec<u8>> {
    match std::env::var("AETHER_ECH") {
        Ok(v) if v.eq_ignore_ascii_case("auto") => match dns::fetch_ech_config().await {
            Ok(raw) => {
                log::info!("[+] fetched ECHConfigList automatically ({} bytes)", raw.len());
                Some(raw)
            }
            Err(e) => {
                log::warn!("[-] ECH auto-fetch failed ({e}); continuing without ECH");
                None
            }
        },
        Ok(b64) if !b64.is_empty() => match tls::decode_ech_config_list(&b64) {
            Ok(v) => {
                log::info!("[+] using ECHConfigList from AETHER_ECH");
                Some(v)
            }
            Err(e) => {
                log::warn!("[-] bad AETHER_ECH: {e}; continuing without ECH");
                None
            }
        },
        _ => {
            log::info!("[+] ECH disabled (warp masque endpoint does not accept ECH); SNI sent in cleartext");
            None
        }
    }
}

fn masque_reconnect_delay() -> std::time::Duration {
    let secs = std::env::var("AETHER_MASQUE_RECONNECT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2);
    std::time::Duration::from_secs(secs)
}

fn masque_startup_timeout() -> std::time::Duration {
    let secs = std::env::var("AETHER_MASQUE_STARTUP_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(30);
    std::time::Duration::from_secs(secs)
}

async fn hunt_masque_peer(
    identity: &account::Identity,
    mode_str: &str,
    ip: prober::IpScan,
) -> Result<SocketAddr> {
    log::info!("[*] hunting for a working MASQUE gateway (deep connect-ip + data-plane verification)");
    let mode = prober::ScanMode::parse(mode_str);
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


fn lastconn_path(config_path: &str) -> String {
    derive_sibling_path(config_path, "lastconn")
}

async fn quick_verify_masque_peer(identity: &account::Identity, peer: SocketAddr) -> bool {
    let vp = quic::VerifyParams {
        peer,
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        ech_config_list: None,
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
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
    lastconn_path: String,
) -> Result<()> {
    let forced = std::env::var("AETHER_PEER").ok();

    let mut quick_peer: Option<SocketAddr> = None;

    if forced.is_none() {
        if let Some(assigned) = std::env::var("AETHER_TEAM_ENDPOINT")
            .ok()
            .and_then(|value| value.parse::<SocketAddr>().ok())
        {
            log::info!("[*] verifying the endpoint the organization assigned: {assigned}");
            if quick_verify_masque_peer(&identity, assigned).await {
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
            if let Ok(peer) = cached.peer.parse::<SocketAddr>() {
                if want_quick_reconnect(&cached).await {
                    log::info!("[*] verifying cached gateway {peer} before reuse");
                    if quick_verify_masque_peer(&identity, peer).await {
                        log::info!("[+] cached gateway {peer} still works; skipping scan");
                        quick_peer = Some(peer);
                    } else {
                        log::warn!("[-] cached gateway {peer} no longer works; scanning fresh");
                    }
                }
            }
        }
    }

    let (mode_str, ip) = if forced.is_some() || quick_peer.is_some() {
        (String::new(), prober::IpScan::V4)
    } else {
        let mode_str = select_scan_mode_str().await;
        let ip = select_ip_version().await;
        (mode_str, ip)
    };

    let mut last_good_peer: Option<SocketAddr> = None;

    loop {
        let peer = if let Some(p) = quick_peer.take() {
            p
        } else {
            let retried = match last_good_peer {
                Some(p) => {
                    log::info!("[*] retrying last known-good gateway {p} before rescanning");
                    if quick_verify_masque_peer(&identity, p).await {
                        Some(p)
                    } else {
                        log::warn!("[-] last known-good gateway {p} no longer responds; rescanning");
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
                    None => match hunt_masque_peer(&identity, &mode_str, ip).await {
                        Ok(peer) => peer,
                        Err(e) => {
                            log::warn!("[-] no usable MASQUE gateway found: {e}; rescanning shortly");
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
            lastconn::save(&lastconn_path, &peer.to_string(), &profile);
        }

        last_good_peer = Some(peer);

        match run_masque_tunnel(&identity, peer, ech.clone(), listen).await {
            Ok(()) => log::warn!("[-] MASQUE tunnel closed; reconnecting"),
            Err(e) => log::warn!("[-] MASQUE tunnel ended: {e}; reconnecting"),
        }

        tokio::time::sleep(masque_reconnect_delay()).await;
    }
}

async fn run_masque_tunnel(
    identity: &account::Identity,
    peer: SocketAddr,
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
) -> Result<()> {
    let (chans, internals) = quic::channels();

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
    };

    let quic::Channels {
        outbound_tx,
        inbound_rx,
        ctrl_tx,
    } = chans;

    let stack =
        netstack::spawn(&identity.ipv4, &identity.ipv6, TUNNEL_MTU, inbound_rx, outbound_tx)?;
    let _ctrl = ctrl_tx;

    let mut tasks = TaskGuard::new();

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
    tasks.push(bridge_task.abort_handle());

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

    let tunnel_task = if masque_h2::enabled() {
        let h2cfg = masque_h2::H2TunnelConfig {
            peer: masque_h2::h2_peer(peer),
            sni: consts::CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: false,
            pin_endpoint: true,
            expected_pins: consts::MASQUE_PINS.iter().map(|p| p.to_vec()).collect(),
        };
        log::info!("[+] MASQUE transport: HTTP/2 (TCP) to {}", h2cfg.peer);
        tokio::spawn(masque_h2::run(h2cfg, internals, Some(addr_tx), Some(ready_tx)))
    } else {
        log::info!("[+] MASQUE transport: HTTP/3 (QUIC) to {}", peer);
        tokio::spawn(quic::run(cfg, internals, Some(addr_tx), Some(ready_tx)))
    };
    tasks.push(tunnel_task.abort_handle());

    let startup_timeout = masque_startup_timeout();
    match tokio::time::timeout(startup_timeout, ready_rx).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            let joined = tunnel_task.await;
            let msg = match joined {
                Ok(Ok(())) => "tunnel exited before validation".to_string(),
                Ok(Err(e)) => format!("tunnel failed before validation: {e}"),
                Err(e) => format!("tunnel task join error: {e}"),
            };
            return Err(AetherError::Other(msg));
        }
        Err(_) => {
            tunnel_task.abort();
            let _ = tunnel_task.await;
            return Err(AetherError::Other(format!(
                "tunnel startup timed out after {:?}",
                startup_timeout
            )));
        }
    }

    let socks_stack = stack.clone();
    let socks_task = tokio::spawn(async move {
        log::info!("[+] socks5 server listening on {listen}");
        socks::serve(listen, socks_stack).await
    });
    tasks.push(socks_task.abort_handle());

    let http_task = spawn_http_proxy(&stack);
    if let Some(task) = &http_task {
        tasks.push(task.abort_handle());
    }

    let tunnel_result = tunnel_task.await;

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
        .unwrap_or(2);
    std::time::Duration::from_secs(secs)
}

fn wg_endpoint_cooldown() -> std::time::Duration {
    let secs = std::env::var("AETHER_WG_ENDPOINT_COOLDOWN_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
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
                log::info!("[+] selected WireGuard endpoint {peer} using aethernoize profile '{name}'");
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

async fn run_wireguard(identity: account::Identity, listen: SocketAddr, lastconn_path: String) -> Result<()> {
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
                        log::debug!("[-] assigned endpoint {assigned} failed profile '{name}': {e}");
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
            if let Ok(peer) = cached.peer.parse::<SocketAddr>() {
                if want_quick_reconnect(&cached).await {
                    let profile = aethernoize::from_profile(&cached.profile);
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
                            log::info!("[+] cached endpoint {peer} still works (rtt {:?}); skipping scan", rtt);
                            quick = Some((peer, profile, cached.profile.clone()));
                        }
                        Err(e) => {
                            log::warn!("[-] cached endpoint {peer} no longer works ({e}); scanning fresh");
                        }
                    }
                }
            }
        }
    }

    let (mode_str, ip) = if forced.is_some() || quick.is_some() {
        (String::new(), prober::IpScan::V4)
    } else {
        let mode_str = select_scan_mode_str().await;
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
                    log::info!("[*] retrying last known-good WireGuard endpoint {p} before rescanning");
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
                            log::info!("[*] testing forced peer {peer} with aethernoize profile '{name}'");
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
                                    log::info!("[+] profile '{}' passed handshake + data-plane (rtt {:?})", name, rtt);
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
                            None => return Err(AetherError::NoCleanEndpoint),
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
            lastconn::save(&lastconn_path, &peer.to_string(), &profile_name);
        }

        let is_same_peer_as_before = last_good.as_ref().map(|(p, _, _)| *p) == Some(peer);
        if !is_same_peer_as_before {
            consecutive_fails_on_peer = 0;
        }
        last_good = Some((peer, profile.clone(), profile_name));

        match run_wireguard_tunnel(identity.clone(), peer, profile, listen).await {
            Ok(()) => {
                log::warn!("[-] WireGuard tunnel closed; reconnecting");
                consecutive_fails_on_peer += 1;
            }
            Err(e) => {
                log::warn!("[-] WireGuard tunnel ended: {e}; reconnecting");
                consecutive_fails_on_peer += 1;
            }
        }

        tokio::time::sleep(wg_reconnect_delay()).await;
    }
}

fn wg_tunnel_validate_timeout() -> std::time::Duration {
    let secs = std::env::var("AETHER_WG_VALIDATE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
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
    let ipv4: std::net::Ipv4Addr = identity.ipv4.parse()
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

    let tunnel = wireguard::WgTunnel::from_established(session, std::sync::Arc::new(aethernoize), inbound_tx, ipv4);

    let stack = netstack::spawn(&identity.ipv4, &identity.ipv6, TUNNEL_MTU, inbound_rx, outbound_tx)?;

    let mut tasks = TaskGuard::new();

    let socks_stack = stack.clone();
    let socks_task = tokio::spawn(async move {
        log::info!("[+] socks5 server listening on {listen}");
        socks::serve(listen, socks_stack).await
    });
    tasks.push(socks_task.abort_handle());

    let http_task = spawn_http_proxy(&stack);
    if let Some(task) = &http_task {
        tasks.push(task.abort_handle());
    }

    let tunnel_result = tunnel.run(outbound_rx).await;

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

fn spawn_http_proxy(stack: &netstack::StackHandle) -> Option<TunnelExit> {
    let listen = http_proxy_listen()?;
    let stack = stack.clone();
    Some(tokio::spawn(async move {
        log::info!("[+] http proxy listening on {listen}");
        socks::serve_http(listen, stack).await
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

    let tunnel = wireguard::WgTunnel::from_established(session, std::sync::Arc::new(profile), inbound_tx, ipv4);
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
        loop {
            match up_sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    *up_peer.lock().await = Some(from);
                    if udp_tx.send_to(remote, buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
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
    listen: SocketAddr,
) -> Result<()> {
    log::info!("[*] establishing outer WARP tunnel to {peer}...");
    let (outer_stack, mut outer_exit) = establish_wg(&primary, peer, TUNNEL_MTU, true, 5, "outer").await?;

    let (forwarder, _forwarder_guard) = spawn_udp_forwarder(&outer_stack, peer).await?;
    log::info!("[+] inner endpoint tunneled through outer warp via {forwarder}");

    log::info!("[*] establishing inner WARP tunnel (warp-in-warp)...");
    let (inner_stack, mut inner_exit) =
        establish_wg(&secondary, forwarder, INNER_MTU, false, 20, "inner").await?;

    log::info!("[+] socks5 server listening on {listen}");
    let http_task = spawn_http_proxy(&inner_stack);
    let mut socks_task = tokio::spawn(async move { socks::serve(listen, inner_stack).await });

    let outcome = tokio::select! {
        result = &mut outer_exit => join_outcome("outer wireguard tunnel", result),
        result = &mut inner_exit => join_outcome("inner wireguard tunnel", result),
        result = &mut socks_task => join_outcome("socks5 server", result),
    };

    if let Some(task) = &http_task {
        task.abort();
    }
    outer_exit.abort();
    inner_exit.abort();
    socks_task.abort();

    let _ = outer_exit.await;
    let _ = inner_exit.await;
    let _ = socks_task.await;

    drop(outer_stack);

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

const SCAN_MODE_PROMPT: &str = "\nScan mode:\n  [1] turbo     (fast, first hit)\n  [2] balanced  (default)\n  [3] thorough  (deep, best ping)\n  [4] stealth   (quiet, patient)\n  [5] ironclad  (real tunnel + real HTTP check per candidate, guaranteed working)\nChoose [1-5] (default 2): ";

async fn select_scan_mode() -> prober::ScanMode {
    if let Ok(v) = std::env::var("AETHER_SCAN") {
        return prober::ScanMode::parse(&v);
    }

    let answer = prompt_line(SCAN_MODE_PROMPT).await;

    match answer.as_deref() {
        Some("1") => prober::ScanMode::Turbo,
        Some("3") => prober::ScanMode::Thorough,
        Some("4") => prober::ScanMode::Stealth,
        Some("5") => prober::ScanMode::Ironclad,
        _ => prober::ScanMode::Balanced,
    }
}

async fn select_scan_mode_str() -> String {
    if let Ok(v) = std::env::var("AETHER_SCAN") {
        return v;
    }

    let answer = prompt_line(SCAN_MODE_PROMPT).await;

    match answer.as_deref() {
        Some("1") => "turbo".to_string(),
        Some("3") => "thorough".to_string(),
        Some("4") => "stealth".to_string(),
        Some("5") => "ironclad".to_string(),
        _ => "balanced".to_string(),
    }
}

async fn select_protocol(base: &str) -> Protocol {
    if let Ok(v) = std::env::var("AETHER_PROTOCOL") {
        return Protocol::parse(&v);
    }

    loop {
        let zero_trust = match team_scope() {
            Some(team) => format!("  [4] Zero Trust: signed in to {team}, pick another team\n"),
            None => "  [4] Zero Trust: sign in to an organization (WARP for teams)\n".to_string(),
        };

        let answer = prompt_line(&format!(
            "\nProtocol:\n  [1] MASQUE (modern, QUIC/H3, default)\n  \
             [2] WireGuard (classic, faster)\n  [3] WARP-in-WARP / gool\n{zero_trust}\
             Choose [1-4] (default 1): "
        ))
        .await;

        match answer.as_deref() {
            Some("2") => return Protocol::WireGuard,
            Some("3") => return Protocol::WarpInWarp,
            Some("4") => {
                enrol_zero_trust(base).await;
                continue;
            }
            _ => return Protocol::Masque,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Masque,
    WireGuard,
    WarpInWarp,
}

impl Protocol {
    fn parse(s: &str) -> Protocol {
        match s.trim().to_lowercase().as_str() {
            "wg" | "wireguard" => Protocol::WireGuard,
            "gool" | "wiw" | "warp-in-warp" | "warpinwarp" => Protocol::WarpInWarp,
            _ => Protocol::Masque,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Protocol::Masque => "MASQUE",
            Protocol::WireGuard => "WireGuard",
            Protocol::WarpInWarp => "WARP-in-WARP (gool)",
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

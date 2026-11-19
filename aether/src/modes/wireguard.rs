use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use super::{
    aethernoize_config, count_tunnel_end, exit_policy_guard, scan_settings_from_env, team_endpoint,
    Listeners, TunnelError, TunnelExit, TUNNEL_MTU,
};
use crate::error::{AetherError, Result};
use crate::prompt::{select_ip_version, select_scan_mode_str, want_quick_reconnect};
use crate::{
    account, aethernoize, exitloc, lastconn, netstack, prober, sysprofile, wg_prober, wireguard,
};

pub(crate) async fn select_wg_peers(
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
        client_id: identity.client_id,
        local_ipv4: identity.local_ipv4()?,
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

fn wg_keepalive_secs() -> u16 {
    crate::settings::var("AETHER_WG_KEEPALIVE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(5)
}

fn wg_profile_candidates() -> Vec<(String, aethernoize::AetherNoizeConfig)> {
    let primary = crate::settings::var("AETHER_NOIZE").unwrap_or_else(|_| "balanced".to_string());
    log::info!("[+] aethernoize primary profile: {primary}");

    let mut names = vec![primary.clone()];
    if crate::settings::var("AETHER_WG_NO_PROFILE_RETRY").is_err() {
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
        local_ipv4: identity.local_ipv4()?,
        aethernoize: profile,
        ports: wireguard::WG_PORTS.to_vec(),
        ip,
        excluded: excluded.clone(),
    };

    let best = wg_prober::hunt_best_wg_endpoint(&probe, mode).await?;
    Ok(SocketAddr::new(best.ip, best.port))
}

pub(crate) fn wg_reconnect_delay() -> std::time::Duration {
    let secs = crate::settings::var("AETHER_WG_RECONNECT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(2);
    std::time::Duration::from_secs(secs)
}

fn wg_endpoint_cooldown() -> std::time::Duration {
    let secs = crate::settings::var("AETHER_WG_ENDPOINT_COOLDOWN_SECS")
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

fn pinned_peer() -> Option<String> {
    crate::settings::var("AETHER_WG_PEER")
        .ok()
        .or_else(|| crate::settings::var("AETHER_PEER").ok())
}

pub(crate) async fn run_wireguard(
    identity: account::Identity,
    listeners: Listeners,
    lastconn_path: String,
) -> Result<()> {
    let candidates = wg_profile_candidates();

    let forced = pinned_peer();

    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4 = identity.local_ipv4()?;

    let mut quick: Option<(SocketAddr, aethernoize::AetherNoizeConfig, String)> = None;

    if forced.is_none() {
        if let Some(assigned) = team_endpoint() {
            log::info!("[*] verifying the endpoint the organization assigned: {assigned}");
            for (name, profile) in &candidates {
                match wireguard::verify_endpoint(
                    &wireguard::Probe {
                        peer: assigned,
                        private_key,
                        peer_public,
                        client_id: identity.client_id,
                        local_ipv4: ipv4,
                        aethernoize: profile,
                        keepalive: None,
                    },
                    std::time::Duration::from_secs(8),
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
                        &wireguard::Probe {
                            peer,
                            private_key,
                            peer_public,
                            client_id: identity.client_id,
                            local_ipv4: ipv4,
                            aethernoize: &profile,
                            keepalive: None,
                        },
                        std::time::Duration::from_secs(6),
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
                        &wireguard::Probe {
                            peer: *p,
                            private_key,
                            peer_public,
                            client_id: identity.client_id,
                            local_ipv4: ipv4,
                            aethernoize: profile,
                            keepalive: None,
                        },
                        std::time::Duration::from_secs(6),
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
                            .map_err(|_| AetherError::from(TunnelError::BadPeer(p.to_string())))?;
                        log::info!("[+] using forced peer {peer} (probe skipped)");

                        let mut chosen = None;
                        for (name, profile) in &candidates {
                            log::info!(
                                "[*] testing forced peer {peer} with aethernoize profile '{name}'"
                            );
                            match wireguard::verify_endpoint(
                                &wireguard::Probe {
                                    peer,
                                    private_key,
                                    peer_public,
                                    client_id: identity.client_id,
                                    local_ipv4: ipv4,
                                    aethernoize: profile,
                                    keepalive: None,
                                },
                                std::time::Duration::from_secs(10),
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
        match run_wireguard_tunnel(
            identity.clone(),
            peer,
            profile,
            wg_keepalive_secs(),
            &listeners,
        )
        .await
        {
            Ok(()) => log::warn!("[-] WireGuard tunnel closed; reconnecting"),
            Err(e) => log::warn!("[-] WireGuard tunnel ended: {e}; reconnecting"),
        }
        consecutive_fails_on_peer = count_tunnel_end(consecutive_fails_on_peer, started.elapsed());

        tokio::time::sleep(wg_reconnect_delay()).await;
    }
}

fn wg_tunnel_validate_timeout() -> std::time::Duration {
    let secs = crate::settings::var("AETHER_WG_VALIDATE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(10);
    std::time::Duration::from_secs(secs)
}

pub(crate) async fn run_wireguard_tunnel(
    identity: account::Identity,
    peer: SocketAddr,
    aethernoize: aethernoize::AetherNoizeConfig,
    keepalive: u16,
    listeners: &Listeners,
) -> Result<()> {
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4 = identity.local_ipv4()?;

    log::info!("[*] validating WireGuard tunnel with {peer} (handshake + data-plane) before serving socks5...");
    let (_, session) = wireguard::verify_endpoint_keep_session(
        &wireguard::Probe {
            peer,
            private_key,
            peer_public,
            client_id: identity.client_id,
            local_ipv4: ipv4,
            aethernoize: &aethernoize,
            keepalive: Some(keepalive),
        },
        wg_tunnel_validate_timeout(),
    )
    .await
    .map_err(|e| AetherError::from(TunnelError::Validation(e.to_string())))?;
    log::info!("[+] wireguard tunnel validated (end-to-end data confirmed); serving socks5");

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

    let policy = exitloc::Policy::from_env();
    exitloc::settle(&stack, &policy, "wireguard").await?;

    let tunnel_result = tokio::select! {
        result = tunnel.run(outbound_rx) => result,
        reason = exit_policy_guard(&stack, &policy) => return Err(reason),
        never = listeners.serve(&stack) => match never {},
    };

    drop(stack);

    match tunnel_result {
        Ok(()) => Ok(()),
        Err(e) => Err(AetherError::from(TunnelError::WireGuardExited(
            e.to_string(),
        ))),
    }
}

pub(crate) async fn establish_wg(
    identity: &account::Identity,
    peer: SocketAddr,
    mtu: usize,
    obfuscate: bool,
    keepalive: u16,
    label: &'static str,
) -> Result<(netstack::StackHandle, TunnelExit)> {
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;

    let ipv4 = identity.local_ipv4()?;

    let profile = if obfuscate {
        aethernoize_config()
    } else {
        aethernoize::from_profile("off")
    };

    log::info!("[*] [{label}] validating WireGuard tunnel with {peer} (handshake + data-plane)...");
    let (_, session) = wireguard::verify_endpoint_keep_session(
        &wireguard::Probe {
            peer,
            private_key,
            peer_public,
            client_id: identity.client_id,
            local_ipv4: ipv4,
            aethernoize: &profile,
            keepalive: Some(keepalive),
        },
        wg_tunnel_validate_timeout(),
    )
    .await
    .map_err(|e| {
        AetherError::from(TunnelError::LabelledValidation {
            label: label.to_string(),
            reason: e.to_string(),
        })
    })?;
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
                Err(AetherError::from(TunnelError::Labelled {
                    label: label.to_string(),
                    reason: e.to_string(),
                }))
            }
        }
    });

    Ok((stack, exit))
}

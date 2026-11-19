use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use super::{
    count_tunnel_end, env_value, exit_policy_guard, masque_tunnel_mtu, spread_hops,
    verified_scan_selected, Listeners, TunnelError, INNER_MTU, TUNNEL_MTU,
};
use crate::error::{AetherError, Result};
use crate::modes::endpoints::{parse_endpoint, wiw_endpoints_with_fallback, WG_EXAMPLE_PORT};
use crate::modes::masque::{establish_masque, masque_startup_timeout};
use crate::modes::wireguard::{establish_wg, select_wg_peers, wg_reconnect_delay};
use crate::prompt::{select_ip_version, select_scan_mode_str, WIW_MANUAL_TIP};
use crate::provision::provision_gool;
use crate::relay::{join_outcome, spawn_udp_forwarder, TaskGuard};
use crate::{
    account, config, exitloc, masque_h2, netstack, prober, quic, socks, upstream, wireguard,
};

pub(crate) async fn run_gool(
    primary: account::Identity,
    secondary: account::Identity,
    listeners: Listeners,
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

        let started = Instant::now();
        match run_warp_in_warp(
            primary.clone(),
            secondary.clone(),
            peer,
            inner_peer_now,
            &listeners,
        )
        .await
        {
            Ok(()) => log::warn!("[-] gool tunnel closed; reconnecting"),
            Err(e) => log::warn!("[-] gool tunnel ended: {e}; reconnecting"),
        }
        consecutive_fails = count_tunnel_end(consecutive_fails, started.elapsed());

        tokio::time::sleep(wg_reconnect_delay()).await;
    }
}

async fn run_warp_in_warp(
    primary: account::Identity,
    secondary: account::Identity,
    peer: SocketAddr,
    inner_peer: SocketAddr,
    listeners: &Listeners,
) -> Result<()> {
    if inner_peer.ip() == peer.ip() {
        return Err(AetherError::from(TunnelError::SameEdge(peer.ip())));
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

    #[derive(PartialEq)]
    enum Winner {
        Outer,
        Inner,
        Policy,
    }

    let (outcome, winner) = tokio::select! {
        result = &mut outer_exit => (join_outcome("outer wireguard tunnel", result), Winner::Outer),
        result = &mut inner_exit => (join_outcome("inner wireguard tunnel", result), Winner::Inner),
        never = listeners.serve(&inner_stack) => match never {},
        reason = exit_policy_guard(&inner_stack, &policy) => (Err(reason), Winner::Policy),
    };

    if winner != Winner::Outer {
        outer_exit.abort();
        let _ = outer_exit.await;
    }
    if winner != Winner::Inner {
        inner_exit.abort();
        let _ = inner_exit.await;
    }

    drop(inner_stack);
    drop(outer_stack);

    outcome
}

pub(crate) fn gool_classic() -> bool {
    matches!(
        crate::settings::var("AETHER_GOOL_MODE").as_deref(),
        Ok("wiw") | Ok("wg") | Ok("classic")
    ) || [
        "AETHER_WIW_OUTER_PEER",
        "AETHER_WIW_INNER_PEER",
        "AETHER_WIW_PEERS",
    ]
    .iter()
    .any(|key| env_value(key).is_some())
}

fn gool_inner_peers(identity: &account::Identity) -> Result<Vec<SocketAddr>> {
    if let Some(value) = env_value("AETHER_GOOL_INNER") {
        return Ok(vec![parse_endpoint(&value)?]);
    }
    let mut peers: Vec<SocketAddr> = Vec::new();
    let named = std::iter::once(identity.assigned_endpoint.trim()).chain(wireguard::wg_seeds_v4());
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

    let listener = socks::bind_listener("socks5", "127.0.0.1:0".parse().unwrap(), "--bind").await?;
    let through = listener.local_addr()?;
    let stack = outer.clone();
    let socks_task = tokio::spawn(async move { socks::serve(listener, stack).await });
    let _socks_guard = TaskGuard(vec![socks_task.abort_handle()]);

    log::info!("[*] registering the gool wireguard identity through the masque tunnel");
    let tunnel = upstream::Upstream::parse(&format!("socks5h://{through}"))?;
    let identity = upstream::through(tunnel, provision_gool(inner_path)).await?;
    log::info!(
        "[+] gool wireguard identity registered from inside warp and saved to {inner_path}: device={} ipv4={}",
        identity.device_id,
        identity.ipv4
    );
    Ok(identity)
}

const GOOL_INNER_ATTEMPTS: u32 = 2;

pub(crate) async fn run_gool_tunnel(
    identity: &account::Identity,
    peer: SocketAddr,
    ech: Option<Vec<u8>>,
    listeners: &Listeners,
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
    let mut last_error = AetherError::from(TunnelError::NoWireGuardEndpoint);
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
            log::info!(
                "[+] gool remembers {} as its wireguard endpoint",
                inner_peer.ip()
            );
        }
    }

    let policy = exitloc::Policy::from_env();
    exitloc::settle(&inner_stack, &policy, "gool").await?;

    log::info!("[+] gool ready: masque {peer} carries wireguard {inner_peer}");

    #[derive(PartialEq)]
    enum Winner {
        Outer,
        Inner,
        Policy,
    }

    let (outcome, winner) = tokio::select! {
        result = &mut outer.exit => (join_outcome("outer masque tunnel", result), Winner::Outer),
        result = &mut inner_exit => (join_outcome("inner wireguard tunnel", result), Winner::Inner),
        never = listeners.serve(&inner_stack) => match never {},
        reason = exit_policy_guard(&inner_stack, &policy) => (Err(reason), Winner::Policy),
    };

    if winner != Winner::Outer {
        outer.exit.abort();
        let _ = (&mut outer.exit).await;
    }
    if winner != Winner::Inner {
        inner_exit.abort();
        let _ = (&mut inner_exit).await;
    }

    outcome
}

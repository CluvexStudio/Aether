use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use super::{
    count_tunnel_end, edge_network, exit_policy_guard, masque_tunnel_mtu, verified_scan_selected,
    Listeners, TunnelError, TUNNEL_MTU,
};
use crate::error::{AetherError, Result};
use crate::modes::endpoints::mim_endpoints_from_env;
use crate::modes::masque::{
    establish_masque, hunt_masque_peer, masque_reconnect_delay, masque_startup_timeout, MasqueHop,
};
use crate::prompt::{select_ip_version, select_scan_mode_str, MIM_MANUAL_TIP};
use crate::relay::{join_outcome, spawn_tcp_forwarder, spawn_udp_forwarder, TaskGuard};
use crate::{account, exitloc, masque_h2, prober, quic, tls};

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

async fn run_masque_in_masque(
    primary: &account::Identity,
    secondary: &account::Identity,
    peer: SocketAddr,
    inner_peers: &[SocketAddr],
    ech: Option<Vec<u8>>,
    listeners: &Listeners,
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
        return Err(AetherError::from(TunnelError::NoInnerMasqueEdge));
    };

    let policy = exitloc::Policy::from_env();
    exitloc::settle(&inner.stack, &policy, "masque-in-masque").await?;

    log::info!("[+] masque-in-masque ready: {peer} (outer) and {inner_peer} (inner)");

    #[derive(PartialEq)]
    enum Winner {
        Outer,
        Inner,
        Policy,
    }

    let (outcome, winner) = tokio::select! {
        result = &mut outer.exit => (join_outcome("outer masque tunnel", result), Winner::Outer),
        result = &mut inner.exit => (join_outcome("inner masque tunnel", result), Winner::Inner),
        never = listeners.serve(&inner.stack) => match never {},
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

    outcome
}

pub(crate) async fn run_mim(
    primary: account::Identity,
    secondary: account::Identity,
    listeners: Listeners,
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

                let avoid: HashSet<IpAddr> =
                    pinned.inner.map(|peer| peer.ip()).into_iter().collect();
                match hunt_masque_peer(&primary, &mode_str, ip, &avoid).await {
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
            return Err(AetherError::from(TunnelError::NoSecondMasqueEdge));
        }

        outer_peer = Some(outer);

        let started = Instant::now();
        match run_masque_in_masque(
            &primary,
            &secondary,
            outer,
            &candidates,
            tls::session_ech(),
            &listeners,
        )
        .await
        {
            Ok(()) => log::warn!("[-] masque-in-masque tunnel closed; reconnecting"),
            Err(e) => log::warn!("[-] masque-in-masque tunnel ended: {e}; reconnecting"),
        }
        consecutive_fails = count_tunnel_end(consecutive_fails, started.elapsed());

        tokio::time::sleep(masque_reconnect_delay()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modes::H2_TUNNEL_MTU;

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
    fn an_ipv6_outer_edge_yields_ipv6_inner_candidates() {
        let outer: SocketAddr = "[2606:4700:d0::a29f:c601]:443".parse().unwrap();
        let candidates = inner_masque_candidates(outer, 4, false);

        assert_eq!(candidates.len(), 4);
        assert!(candidates.iter().all(|candidate| candidate.is_ipv6()));
        assert!(candidates
            .iter()
            .all(|candidate| candidate.ip() != outer.ip()));
    }
}

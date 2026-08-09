use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::StreamExt;
use rand::Rng;

use crate::aethernoize::AetherNoizeConfig;
use crate::error::{AetherError, Result};
use crate::prober::IpScan;
use crate::wireguard;

#[derive(Debug, Clone, Copy)]
pub struct WgProbeResult {
    pub ip: IpAddr,
    pub port: u16,
    pub rtt: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgScanMode {
    Turbo,
    Balanced,
    Thorough,
    Stealth,
    Ironclad,
}

impl WgScanMode {
    pub fn parse(s: &str) -> WgScanMode {
        match s.trim().to_lowercase().as_str() {
            "turbo" | "fast" => WgScanMode::Turbo,
            "thorough" | "deep" | "pro" => WgScanMode::Thorough,
            "stealth" | "quiet" => WgScanMode::Stealth,
            "ironclad" | "real" | "verify" | "guaranteed" => WgScanMode::Ironclad,
            _ => WgScanMode::Balanced,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            WgScanMode::Turbo => "turbo",
            WgScanMode::Balanced => "balanced",
            WgScanMode::Thorough => "thorough",
            WgScanMode::Stealth => "stealth",
            WgScanMode::Ironclad => "ironclad",
        }
    }

    fn strategy(&self) -> WgStrategy {
        match self {
            WgScanMode::Turbo => WgStrategy {
                concurrency: 12,
                per_probe_timeout: Duration::from_millis(5000),
                overall_deadline: Duration::from_secs(30),
                quiet_after_first: Duration::from_secs(0),
                target_successes: 1,
                early_exit_first: true,
                full_subnet: false,
                sample_per_cidr: 40,
                anchor_port_count: 4,
                pool_port_waves: 2,
            },
            WgScanMode::Balanced => WgStrategy {
                concurrency: 8,
                per_probe_timeout: Duration::from_millis(7000),
                overall_deadline: Duration::from_secs(80),
                quiet_after_first: Duration::from_secs(12),
                target_successes: 5,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 120,
                anchor_port_count: 4,
                pool_port_waves: 3,
            },
            WgScanMode::Thorough => WgStrategy {
                concurrency: 10,
                per_probe_timeout: Duration::from_millis(9000),
                overall_deadline: Duration::from_secs(250),
                quiet_after_first: Duration::from_secs(25),
                target_successes: 0,
                early_exit_first: false,
                full_subnet: true,
                sample_per_cidr: 0,
                anchor_port_count: 8,
                pool_port_waves: 4,
            },
            WgScanMode::Stealth => WgStrategy {
                concurrency: 3,
                per_probe_timeout: Duration::from_millis(10000),
                overall_deadline: Duration::from_secs(150),
                quiet_after_first: Duration::from_secs(20),
                target_successes: 3,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 50,
                anchor_port_count: 4,
                pool_port_waves: 2,
            },
            WgScanMode::Ironclad => WgStrategy {
                concurrency: 4,
                per_probe_timeout: Duration::from_millis(15000),
                overall_deadline: Duration::from_secs(180),
                quiet_after_first: Duration::from_secs(15),
                target_successes: 3,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 120,
                anchor_port_count: 6,
                pool_port_waves: 3,
            },
        }
    }
}

const WG_IRONCLAD_TCPING_TIMEOUT: Duration = Duration::from_secs(10);

struct WgStrategy {
    concurrency: usize,
    per_probe_timeout: Duration,
    overall_deadline: Duration,
    quiet_after_first: Duration,
    target_successes: usize,
    early_exit_first: bool,
    full_subnet: bool,
    sample_per_cidr: usize,
    anchor_port_count: usize,
    pool_port_waves: usize,
}

#[derive(Clone)]
pub struct WgProbe {
    pub private_key: Arc<[u8; 32]>,
    pub peer_public_key: Arc<[u8; 32]>,
    pub client_id: [u8; 3],
    pub local_ipv4: Ipv4Addr,
    pub aethernoize: AetherNoizeConfig,
    pub ports: Vec<u16>,
    pub ip: IpScan,
    pub excluded: HashSet<SocketAddr>,
}

pub async fn hunt_best_wg_endpoint(probe: &WgProbe, mode: WgScanMode) -> Result<WgProbeResult> {
    let mut st = mode.strategy();
    st.concurrency = crate::sysprofile::cap_concurrency(st.concurrency);
    let timeout = st.per_probe_timeout;
    let mut effective_ip = probe.ip;
    if probe.ip.want_v6() && !crate::prober::host_has_ipv6().await {
        if probe.ip.want_v4() {
            log::warn!("[-] host has no IPv6 route; falling back to IPv4-only scan");
            effective_ip = IpScan::V4;
        } else {
            log::warn!("[-] host has no IPv6 route; IPv6 scan needs native IPv6 connectivity");
            return Err(AetherError::NoCleanEndpoint);
        }
    }
    let candidates = build_wg_candidates(&st, &probe.ports, effective_ip, &probe.excluded);

    log::info!(
        "[*] wireguard scan mode={} ip={} candidates={} ports={:?} concurrency={} per_probe={:?} budget={:?}",
        mode.label(),
        effective_ip.label(),
        candidates.len(),
        probe.ports,
        st.concurrency,
        st.per_probe_timeout,
        st.overall_deadline,
    );

    let ironclad = mode == WgScanMode::Ironclad;

    let stream = futures::stream::iter(
        candidates
            .into_iter()
            .map(|(ip, port)| verify_one_wg(probe, ip, port, timeout, ironclad)),
    )
    .buffer_unordered(st.concurrency);
    tokio::pin!(stream);

    let deadline = Instant::now() + st.overall_deadline;
    let mut best: Option<WgProbeResult> = None;
    let mut found = 0usize;
    let mut quiet_until: Option<Instant> = None;

    loop {
        let effective = match quiet_until {
            Some(q) => q.min(deadline),
            None => deadline,
        };
        let remaining = effective.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            if best.is_some() {
                if quiet_until.is_some() {
                    log::info!("[+] no new endpoints recently, finalizing selection");
                } else {
                    log::warn!("[-] scan deadline reached");
                }
            } else {
                log::warn!("[-] scan deadline reached with no endpoint");
            }
            break;
        }

        tokio::select! {
            item = stream.next() => {
                match item {
                    None => break,
                    Some(None) => continue,
                    Some(Some(pr)) => {
                        log::info!("[+] wg candidate ok {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
                        if st.early_exit_first {
                            return Ok(pr);
                        }
                        best = Some(match best {
                            Some(cur) if cur.rtt <= pr.rtt => cur,
                            _ => pr,
                        });
                        found += 1;

                        if st.target_successes > 0 && found >= st.target_successes && quiet_until.is_none() {
                            log::info!("[+] reached target of {} endpoints, selecting best", st.target_successes);
                            if !st.quiet_after_first.is_zero() {
                                quiet_until = Some(Instant::now() + st.quiet_after_first);
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
            _ = tokio::time::sleep(remaining) => {
                if best.is_some() {
                    if quiet_until.is_some() {
                        log::info!("[+] no new endpoints recently, finalizing selection");
                    } else {
                        log::warn!("[-] scan deadline reached");
                    }
                } else {
                    log::warn!("[-] scan deadline reached with no endpoint");
                }
                break;
            }
        }
    }

    match best {
        Some(pr) => {
            log::info!("[+] best wg endpoint {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
            Ok(pr)
        }
        None => Err(AetherError::NoCleanEndpoint),
    }
}

async fn verify_one_wg(
    probe: &WgProbe,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    ironclad: bool,
) -> Option<WgProbeResult> {
    let peer = SocketAddr::new(ip, port);

    let (rtt, session) = match wireguard::verify_endpoint_keep_session(
        peer,
        *probe.private_key,
        *probe.peer_public_key,
        probe.client_id,
        probe.local_ipv4,
        &probe.aethernoize,
        timeout,
        None,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            log::trace!("wg probe {ip}:{port} -> {e}");
            return None;
        }
    };

    if !ironclad {
        return Some(WgProbeResult { ip, port, rtt });
    }

    let params = crate::tunnelping::WgPingParams {
        local_ipv4: probe.local_ipv4,
        local_ipv6: "::1".parse().unwrap(),
        aethernoize: probe.aethernoize.clone(),
    };
    match crate::tunnelping::wg_http_ping_established(session, &params, WG_IRONCLAD_TCPING_TIMEOUT).await {
        Ok(http_rtt) => {
            log::info!(
                "[+] ironclad verified wg {ip}:{port} real http round trip rtt={:?}",
                http_rtt
            );
            Some(WgProbeResult { ip, port, rtt: http_rtt })
        }
        Err(e) => {
            log::trace!("[-] ironclad wg {ip}:{port} failed real http check: {e}");
            None
        }
    }
}

fn build_wg_candidates(
    st: &WgStrategy,
    ports: &[u16],
    ip: IpScan,
    excluded: &HashSet<SocketAddr>,
) -> Vec<(IpAddr, u16)> {
    let ports: Vec<u16> = {
        let mut seen_port: HashSet<u16> = HashSet::new();
        let deduped: Vec<u16> = ports.iter().copied().filter(|p| seen_port.insert(*p)).collect();
        if deduped.is_empty() {
            vec![2408]
        } else {
            deduped
        }
    };

    let mut anchors: Vec<IpAddr> = Vec::new();
    let mut pool: Vec<IpAddr> = Vec::new();

    if ip.want_v4() {
        for s in wireguard::wg_seeds_v4() {
            if let Ok(a) = s.parse::<Ipv4Addr>() {
                anchors.push(IpAddr::V4(a));
            }
        }
        let cidr_hosts: Vec<Vec<Ipv4Addr>> = wireguard::wg_prefixes_v4()
            .iter()
            .map(|c| {
                if st.full_subnet {
                    enumerate_cidr_v4(c)
                } else {
                    sample_cidr_v4(c, st.sample_per_cidr)
                }
            })
            .collect();
        let max_len = cidr_hosts.iter().map(|v| v.len()).max().unwrap_or(0);
        for i in 0..max_len {
            for hosts in &cidr_hosts {
                if let Some(a) = hosts.get(i) {
                    pool.push(IpAddr::V4(*a));
                }
            }
        }
    }

    if ip.want_v6() {
        for s in wireguard::WG_SEEDS_V6 {
            if let Ok(a) = s.parse::<Ipv6Addr>() {
                anchors.push(IpAddr::V6(a));
            }
        }
        let per = if st.sample_per_cidr == 0 { 80 } else { st.sample_per_cidr };
        let cidr6: Vec<Vec<Ipv6Addr>> = wireguard::wg_prefixes_v6()
            .iter()
            .map(|c| sample_cidr_v6(c, per, wireguard::WG_PREFIXES_V4))
            .collect();
        let max6 = cidr6.iter().map(|v| v.len()).max().unwrap_or(0);
        for i in 0..max6 {
            for hosts in &cidr6 {
                if let Some(a) = hosts.get(i) {
                    pool.push(IpAddr::V6(*a));
                }
            }
        }
    }

    let mut out: Vec<(IpAddr, u16)> = Vec::new();
    let mut seen: HashSet<(IpAddr, u16)> = HashSet::new();
    let port_count = ports.len();

    let mut push = |ip: IpAddr, port: u16| {
        if !excluded.contains(&SocketAddr::new(ip, port)) && seen.insert((ip, port)) {
            out.push((ip, port));
        }
    };

    // Test known-good anchors on the documented priority ports before spending
    // the scan budget on randomly sampled addresses.
    for port in ports.iter().take(st.anchor_port_count.max(1)) {
        for anchor in &anchors {
            push(*anchor, *port);
        }
    }

    // Cover the sampled pool in waves. Every address gets one attempt before a
    // second port is tried, while successive waves rotate the assigned port.
    for wave in 0..st.pool_port_waves.max(1) {
        for (idx, candidate_ip) in pool.iter().enumerate() {
            let port = ports[(idx + wave) % port_count];
            push(*candidate_ip, port);
        }
    }

    out
}

fn parse_cidr_v4(cidr: &str) -> Option<(u32, u8)> {
    let (ip, prefix) = cidr.split_once('/')?;
    Some((u32::from(ip.parse::<Ipv4Addr>().ok()?), prefix.parse().ok()?))
}

fn enumerate_cidr_v4(cidr: &str) -> Vec<Ipv4Addr> {
    let (base, prefix) = match parse_cidr_v4(cidr) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let host_bits = 32u32.saturating_sub(prefix as u32);
    if host_bits == 0 {
        return vec![Ipv4Addr::from(base)];
    }
    if host_bits > 12 {
        return Vec::new();
    }
    let size = 1u32 << host_bits;
    (1..size.saturating_sub(1))
        .map(|off| Ipv4Addr::from(base + off))
        .collect()
}

fn sample_cidr_v4(cidr: &str, n: usize) -> Vec<Ipv4Addr> {
    let (base, prefix) = match parse_cidr_v4(cidr) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let host_bits = 32u32.saturating_sub(prefix as u32);
    let size = if host_bits >= 32 { u32::MAX } else { 1u32 << host_bits };
    if size <= 2 {
        return vec![Ipv4Addr::from(base)];
    }

    let usable = size - 2;
    let want = (n as u32).min(usable);
    let mut rng = rand::thread_rng();
    let mut chosen: HashSet<u32> = HashSet::with_capacity(want as usize);
    let mut out = Vec::with_capacity(want as usize);

    while (out.len() as u32) < want {
        let off = 1 + rng.gen_range(0..usable);
        if chosen.insert(off) {
            out.push(Ipv4Addr::from(base + off));
        }
    }

    out
}

fn parse_cidr_v6(cidr: &str) -> Option<(u128, u8)> {
    let (ip, prefix) = cidr.split_once('/')?;
    Some((u128::from(ip.parse::<Ipv6Addr>().ok()?), prefix.parse().ok()?))
}

fn sample_cidr_v6(cidr: &str, n: usize, v4_cidrs: &[&str]) -> Vec<Ipv6Addr> {
    let (base, prefix) = match parse_cidr_v6(cidr) {
        Some(v) => v,
        None => return Vec::new(),
    };
    if 128u32.saturating_sub(prefix as u32) == 0 {
        return vec![Ipv6Addr::from(base)];
    }

    let v4: Vec<(u32, u8)> = v4_cidrs.iter().filter_map(|c| parse_cidr_v4(c)).collect();
    let mut rng = rand::thread_rng();
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let embedded = if v4.is_empty() {
            rng.gen::<u32>() as u128
        } else {
            let (b, p) = v4[rng.gen_range(0..v4.len())];
            let host_bits = 32u32.saturating_sub(p as u32);
            let host = if host_bits == 0 {
                0
            } else {
                rng.gen::<u32>() & ((1u32 << host_bits) - 1)
            };
            (b | host) as u128
        };
        out.push(Ipv6Addr::from(base | embedded));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn anchors_cover_priority_ports_before_the_sampled_pool() {
        let strategy = WgScanMode::Balanced.strategy();
        let ports = [2408, 500, 1701, 4500, 854];
        let candidates = build_wg_candidates(
            &strategy,
            &ports,
            IpScan::V4,
            &HashSet::new(),
        );

        for seed in wireguard::wg_seeds_v4() {
            let ip = IpAddr::V4(seed.parse().expect("wireguard seed"));
            for port in &ports[..4] {
                assert!(
                    candidates.contains(&(ip, *port)),
                    "anchor {ip} should be tested on port {port}"
                );
            }
        }
    }

    #[test]
    fn sampled_ips_receive_multiple_rotated_port_attempts() {
        let mut strategy = WgScanMode::Balanced.strategy();
        strategy.sample_per_cidr = 1;
        let candidates = build_wg_candidates(
            &strategy,
            &[2408, 500, 1701, 4500],
            IpScan::V4,
            &HashSet::new(),
        );
        let anchors: HashSet<IpAddr> = wireguard::wg_seeds_v4()
            .into_iter()
            .map(|seed| IpAddr::V4(seed.parse().expect("wireguard seed")))
            .collect();
        let mut ports_per_ip: HashMap<IpAddr, HashSet<u16>> = HashMap::new();

        for (ip, port) in candidates {
            if !anchors.contains(&ip) {
                ports_per_ip.entry(ip).or_default().insert(port);
            }
        }

        assert!(
            ports_per_ip.values().any(|ports| ports.len() >= 3),
            "sampled IPs should be tried across multiple port waves"
        );
    }

    #[test]
    fn cooled_down_endpoint_is_excluded_from_the_scan() {
        let strategy = WgScanMode::Turbo.strategy();
        let peer: SocketAddr = "162.159.192.1:2408".parse().unwrap();
        let excluded = HashSet::from([peer]);
        let candidates = build_wg_candidates(
            &strategy,
            &[2408, 500, 1701, 4500],
            IpScan::V4,
            &excluded,
        );

        assert!(!candidates.contains(&(peer.ip(), peer.port())));
    }
}

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::StreamExt;
use rand::Rng;

use crate::error::{AetherError, Result};
use crate::noize::NoizeConfig;
use crate::quic;

pub const MASQUE_DOCUMENTED_CIDRS_V4: &[&str] = &["162.159.197.0/24", "162.159.198.0/24"];

pub const MASQUE_DOH_CIDRS_V4: &[&str] = &["162.159.36.0/24", "162.159.46.0/24"];

pub const MASQUE_CIDRS_V4: &[&str] = &[
    "162.159.196.0/24",
    "162.159.195.0/24",
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.204.0/24",
    "162.159.197.0/24",
    "162.159.198.0/24",
    "172.65.251.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
    "162.159.36.0/24",
    "162.159.46.0/24",
];

pub const MASQUE_SEEDS: &[&str] = &[
    "162.159.196.1",
    "162.159.195.1",
    "162.159.192.1",
    "162.159.197.3",
    "162.159.197.1",
    "162.159.198.2",
    "162.159.198.1",
    "162.159.193.1",
];

pub const MASQUE_PORTS: &[u16] = &[443, 500, 1701, 4500, 4443, 8443, 8095];

pub const MASQUE_CIDRS_V6: &[&str] = &[
    "2606:4700:d0::/48",
    "2606:4700:102::/48",
    "2606:4700:d1::/48",
];

pub const MASQUE_ZT_CIDRS_V4: &[&str] = &["162.159.197.0/24"];

pub const MASQUE_ZT_CIDRS_V6: &[&str] = &["2606:4700:102::/48"];

pub fn zero_trust_mode() -> bool {
    std::env::var("AETHER_TEAM")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

pub fn prioritize(all: &[&'static str], first: &[&'static str]) -> Vec<&'static str> {
    if !zero_trust_mode() {
        return all.to_vec();
    }

    let mut out: Vec<&'static str> = Vec::with_capacity(all.len());
    for entry in first {
        if all.contains(entry) {
            out.push(entry);
        }
    }
    for entry in all {
        if !out.contains(entry) {
            out.push(entry);
        }
    }
    out
}

pub fn masque_cidrs_v4() -> Vec<&'static str> {
    prioritize(MASQUE_CIDRS_V4, MASQUE_ZT_CIDRS_V4)
}

pub fn masque_cidrs_v6() -> Vec<&'static str> {
    prioritize(MASQUE_CIDRS_V6, MASQUE_ZT_CIDRS_V6)
}

pub const MASQUE_SEEDS_V6: &[&str] = &["2606:4700:d0::a29f:c602", "2606:4700:d1::a29f:c602", "2606:4700:d0::a29f:c601", "2606:4700:d0::a29f:c001"];

#[derive(Debug, Clone, Copy)]
pub struct ProbeResult {
    pub ip: IpAddr,
    pub port: u16,
    pub rtt: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpScan {
    V4,
    V6,
    Both,
}

impl IpScan {
    pub fn parse(s: &str) -> IpScan {
        match s.trim().to_lowercase().as_str() {
            "6" | "v6" | "ipv6" => IpScan::V6,
            "both" | "all" | "dual" => IpScan::Both,
            _ => IpScan::V4,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            IpScan::V4 => "ipv4",
            IpScan::V6 => "ipv6",
            IpScan::Both => "dual-stack",
        }
    }

    pub fn want_v4(&self) -> bool {
        matches!(self, IpScan::V4 | IpScan::Both)
    }

    pub fn want_v6(&self) -> bool {
        matches!(self, IpScan::V6 | IpScan::Both)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Turbo,
    Balanced,
    Thorough,
    Stealth,
    Ironclad,
}

impl ScanMode {
    pub fn parse(s: &str) -> ScanMode {
        match s.trim().to_lowercase().as_str() {
            "turbo" | "fast" => ScanMode::Turbo,
            "thorough" | "deep" | "pro" => ScanMode::Thorough,
            "stealth" | "quiet" => ScanMode::Stealth,
            "ironclad" | "real" | "verify" | "guaranteed" => ScanMode::Ironclad,
            _ => ScanMode::Balanced,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ScanMode::Turbo => "turbo",
            ScanMode::Balanced => "balanced",
            ScanMode::Thorough => "thorough",
            ScanMode::Stealth => "stealth",
            ScanMode::Ironclad => "ironclad",
        }
    }

    fn strategy(&self) -> Strategy {
        match self {
            ScanMode::Turbo => Strategy {
                concurrency: 20,
                per_probe_timeout: Duration::from_millis(6000),
                overall_deadline: Duration::from_secs(45),
                quiet_after_first: Duration::from_secs(0),
                target_successes: 1,
                early_exit_first: true,
                full_subnet: false,
                sample_per_cidr: 64,
            },
            ScanMode::Balanced => Strategy {
                concurrency: 16,
                per_probe_timeout: Duration::from_millis(6000),
                overall_deadline: Duration::from_secs(120),
                quiet_after_first: Duration::from_secs(20),
                target_successes: 6,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 140,
            },
            ScanMode::Thorough => Strategy {
                concurrency: 20,
                per_probe_timeout: Duration::from_millis(10000),
                overall_deadline: Duration::from_secs(300),
                quiet_after_first: Duration::from_secs(30),
                target_successes: 0,
                early_exit_first: false,
                full_subnet: true,
                sample_per_cidr: 0,
            },
            ScanMode::Stealth => Strategy {
                concurrency: 3,
                per_probe_timeout: Duration::from_millis(12000),
                overall_deadline: Duration::from_secs(180),
                quiet_after_first: Duration::from_secs(25),
                target_successes: 4,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 64,
            },
            ScanMode::Ironclad => Strategy {
                concurrency: 4,
                per_probe_timeout: Duration::from_millis(15000),
                overall_deadline: Duration::from_secs(180),
                quiet_after_first: Duration::from_secs(15),
                target_successes: 3,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 140,
            },
        }
    }
}

const IRONCLAD_TCPING_TIMEOUT: Duration = Duration::from_secs(10);

struct Strategy {
    concurrency: usize,
    per_probe_timeout: Duration,
    overall_deadline: Duration,
    quiet_after_first: Duration,
    target_successes: usize,
    early_exit_first: bool,
    full_subnet: bool,
    sample_per_cidr: usize,
}

#[derive(Clone)]
pub struct MasqueProbe {
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Arc<[u8]>,
    pub key_pem: Arc<[u8]>,
    pub ech_config_list: Option<Arc<[u8]>>,
    pub noize: NoizeConfig,
    pub ports: Vec<u16>,
    pub ip: IpScan,
    pub local_ipv4: Ipv4Addr,
}

pub async fn host_has_ipv6() -> bool {
    match tokio::net::UdpSocket::bind("[::]:0").await {
        Ok(sock) => sock.connect("[2606:4700:d0::a29f:c001]:443").await.is_ok(),
        Err(_) => false,
    }
}

pub async fn hunt_best_gateway(probe: &MasqueProbe, mode: ScanMode) -> Result<ProbeResult> {
    let mut st = mode.strategy();
    st.concurrency = crate::sysprofile::cap_concurrency(st.concurrency);
    let timeout = st.per_probe_timeout;
    let mut effective_ip = probe.ip;
    if probe.ip.want_v6() && !host_has_ipv6().await {
        if probe.ip.want_v4() {
            log::warn!("[-] host has no IPv6 route; falling back to IPv4-only scan");
            effective_ip = IpScan::V4;
        } else {
            log::warn!("[-] host has no IPv6 route; IPv6 scan needs native IPv6 connectivity");
            return Err(AetherError::NoCleanEndpoint);
        }
    }
    let candidates = build_candidates(&st, &probe.ports, effective_ip);

    log::info!(
        "[*] scan mode={} ip={} candidates={} ports={:?} concurrency={} per_probe={:?} budget={:?}",
        mode.label(),
        effective_ip.label(),
        candidates.len(),
        probe.ports,
        st.concurrency,
        st.per_probe_timeout,
        st.overall_deadline,
    );

    let ironclad = mode == ScanMode::Ironclad;

    let stream = futures::stream::iter(
        candidates
            .into_iter()
            .map(|(ip, port)| verify_one(probe, ip, port, timeout, ironclad)),
    )
    .buffer_unordered(st.concurrency);
    tokio::pin!(stream);

    let deadline = Instant::now() + st.overall_deadline;
    let mut best: Option<ProbeResult> = None;
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
                    log::info!("[+] no new gateways recently, finalizing selection");
                } else {
                    log::warn!("[-] scan deadline reached");
                }
            } else {
                log::warn!("[-] scan deadline reached with no gateway");
            }
            break;
        }

        tokio::select! {
            item = stream.next() => {
                match item {
                    None => break,
                    Some(None) => continue,
                    Some(Some(pr)) => {
                        log::info!("[+] candidate ok {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
                        if st.early_exit_first {
                            return Ok(pr);
                        }
                        best = Some(match best {
                            Some(cur) if cur.rtt <= pr.rtt => cur,
                            _ => pr,
                        });
                        found += 1;
                        
                        if st.target_successes > 0 && found >= st.target_successes && quiet_until.is_none() {
                            log::info!("[+] reached target of {} gateways, selecting best", st.target_successes);
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
                        log::info!("[+] no new gateways recently, finalizing selection");
                    } else {
                        log::warn!("[-] scan deadline reached");
                    }
                } else {
                    log::warn!("[-] scan deadline reached with no gateway");
                }
                break;
            }
        }
    }

    match best {
        Some(pr) => {
            log::info!("[+] best gateway {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
            Ok(pr)
        }
        None => Err(AetherError::NoCleanEndpoint),
    }
}

async fn verify_one(
    probe: &MasqueProbe,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    ironclad: bool,
) -> Option<ProbeResult> {
    if ironclad {
        let params = crate::tunnelping::MasquePingParams {
            peer: SocketAddr::new(ip, port),
            sni: probe.sni.clone(),
            authority: probe.authority.clone(),
            path: probe.path.clone(),
            cert_pem: probe.cert_pem.to_vec(),
            key_pem: probe.key_pem.to_vec(),
            noize: probe.noize.clone(),
            local_ipv4: probe.local_ipv4,
            local_ipv4_str: probe.local_ipv4.to_string(),
            local_ipv6_str: String::new(),
        };
        return match crate::tunnelping::masque_http_ping(&params, IRONCLAD_TCPING_TIMEOUT).await {
            Ok(rtt) => {
                log::info!("[+] ironclad verified {ip}:{port} real http round trip rtt={:?}", rtt);
                Some(ProbeResult { ip, port, rtt })
            }
            Err(e) => {
                log::trace!("[-] ironclad {ip}:{port} failed real http check: {e}");
                None
            }
        };
    }

    if crate::masque_h2::enabled() {
        let cfg = crate::masque_h2::H2TunnelConfig {
            peer: SocketAddr::new(ip, port),
            sni: probe.sni.clone(),
            authority: probe.authority.clone(),
            path: probe.path.clone(),
            cert_pem: probe.cert_pem.to_vec(),
            key_pem: probe.key_pem.to_vec(),
            local_ipv4: probe.local_ipv4,
            quiet: true,
            pin_endpoint: true,
            expected_pins: crate::consts::MASQUE_PINS.iter().map(|p| p.to_vec()).collect(),
        };
        return match crate::masque_h2::verify_h2(&cfg, timeout).await {
            Ok(rtt) => Some(ProbeResult { ip, port, rtt }),
            Err(e) => {
                log::trace!("h2 probe {ip}:{port} -> {e}");
                None
            }
        };
    }

    let vp = quic::VerifyParams {
        peer: SocketAddr::new(ip, port),
        sni: probe.sni.clone(),
        authority: probe.authority.clone(),
        path: probe.path.clone(),
        cert_pem: probe.cert_pem.to_vec(),
        key_pem: probe.key_pem.to_vec(),
        ech_config_list: probe.ech_config_list.as_ref().map(|a| a.to_vec()),
        noize: probe.noize.clone(),
        timeout,
        local_ipv4: probe.local_ipv4,
    };

    match quic::verify_masque(&vp).await {
        Ok(rtt) => Some(ProbeResult { ip, port, rtt }),
        Err(e) => {
            log::trace!("probe {ip}:{port} -> {e}");
            None
        }
    }
}

fn build_candidates(st: &Strategy, ports: &[u16], ip: IpScan) -> Vec<(IpAddr, u16)> {
    let primary = ports.first().copied().unwrap_or(443);
    let mut out: Vec<(IpAddr, u16)> = Vec::new();
    let mut seen: HashSet<(IpAddr, u16)> = HashSet::new();

    let seeds: Vec<Ipv4Addr> = MASQUE_SEEDS.iter().filter_map(|s| s.parse().ok()).collect();
    let seeds6: Vec<Ipv6Addr> = MASQUE_SEEDS_V6.iter().filter_map(|s| s.parse().ok()).collect();

    if ip.want_v4() {
        for a in &seeds {
            if seen.insert((IpAddr::V4(*a), primary)) {
                out.push((IpAddr::V4(*a), primary));
            }
        }
        let cidr_hosts: Vec<Vec<Ipv4Addr>> = masque_cidrs_v4()
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
                    if seen.insert((IpAddr::V4(*a), primary)) {
                        out.push((IpAddr::V4(*a), primary));
                    }
                }
            }
        }
    }

    if ip.want_v6() {
        for a in &seeds6 {
            if seen.insert((IpAddr::V6(*a), primary)) {
                out.push((IpAddr::V6(*a), primary));
            }
        }
        let per = if st.sample_per_cidr == 0 { 96 } else { st.sample_per_cidr };
        let cidr6: Vec<Vec<Ipv6Addr>> = masque_cidrs_v6()
            .iter()
            .map(|c| sample_cidr_v6(c, per, MASQUE_CIDRS_V4))
            .collect();
        let max6 = cidr6.iter().map(|v| v.len()).max().unwrap_or(0);
        for i in 0..max6 {
            for hosts in &cidr6 {
                if let Some(a) = hosts.get(i) {
                    if seen.insert((IpAddr::V6(*a), primary)) {
                        out.push((IpAddr::V6(*a), primary));
                    }
                }
            }
        }
    }

    if ip.want_v4() {
        for a in &seeds {
            for &port in ports {
                if port != primary && seen.insert((IpAddr::V4(*a), port)) {
                    out.push((IpAddr::V4(*a), port));
                }
            }
        }
    }
    if ip.want_v6() {
        for a in &seeds6 {
            for &port in ports {
                if port != primary && seen.insert((IpAddr::V6(*a), port)) {
                    out.push((IpAddr::V6(*a), port));
                }
            }
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

    #[test]
    fn the_documented_zero_trust_masque_ingress_range_is_scanned() {
        assert!(MASQUE_CIDRS_V4.contains(&"162.159.197.0/24"));
        assert!(MASQUE_CIDRS_V6.contains(&"2606:4700:102::/48"));
    }

    #[test]
    fn the_dns_over_https_ranges_are_swept_last_because_they_never_serve_masque() {
        let tail = &MASQUE_CIDRS_V4[MASQUE_CIDRS_V4.len() - MASQUE_DOH_CIDRS_V4.len()..];
        for entry in MASQUE_DOH_CIDRS_V4 {
            assert!(tail.contains(entry), "{entry} should be at the end");
        }
    }

    #[test]
    fn the_documented_default_masque_port_leads_the_sweep() {
        assert_eq!(MASQUE_PORTS.first(), Some(&443));
    }

    #[test]
    fn the_documented_masque_fallback_ports_keep_their_documented_order() {
        assert_eq!(MASQUE_PORTS, &[443, 500, 1701, 4500, 4443, 8443, 8095]);
    }

    #[test]
    fn without_a_team_the_range_order_is_left_alone() {
        std::env::remove_var("AETHER_TEAM");
        assert_eq!(prioritize(MASQUE_CIDRS_V4, MASQUE_ZT_CIDRS_V4), MASQUE_CIDRS_V4.to_vec());
    }

    #[test]
    fn prioritize_moves_the_wanted_entries_to_the_front_without_losing_any() {
        let all = ["a", "b", "c", "d"];
        let out = {
            let mut out: Vec<&'static str> = vec!["c"];
            for entry in all {
                if !out.contains(&entry) {
                    out.push(entry);
                }
            }
            out
        };
        assert_eq!(out, vec!["c", "a", "b", "d"]);
        assert_eq!(out.len(), all.len());
    }

    #[test]
    fn the_documented_masque_fallback_ports_are_all_covered() {
        for port in [443u16, 500, 1701, 4443, 4500, 8443, 8095] {
            assert!(
                MASQUE_PORTS.contains(&port),
                "documented fallback port {port} should be scanned"
            );
        }
    }

    async fn quic_answers(peer: SocketAddr, timeout: Duration) -> Option<Duration> {
        let bind = if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let sock = tokio::net::UdpSocket::bind(bind).await.ok()?;
        sock.connect(peer).await.ok()?;
        let local = sock.local_addr().ok()?;

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).ok()?;
        config.set_application_protos(&[b"h3"]).ok()?;
        config.verify_peer(false);
        config.set_max_idle_timeout(timeout.as_millis() as u64);
        config.set_initial_max_data(1_000_000);
        config.set_initial_max_stream_data_bidi_local(100_000);
        config.set_initial_max_streams_bidi(4);

        let mut scid = [0u8; 16];
        rand::thread_rng().fill(&mut scid[..]);
        let scid = quiche::ConnectionId::from_ref(&scid);

        let sni = crate::consts::CONNECT_SNI;
        let mut conn = quiche::connect(Some(sni), &scid, local, peer, &mut config).ok()?;

        let mut out = [0u8; 1350];
        let (written, _) = conn.send(&mut out).ok()?;

        let started = Instant::now();
        sock.send(&out[..written]).await.ok()?;

        let mut buf = [0u8; 1500];
        match tokio::time::timeout(timeout, sock.recv(&mut buf)).await {
            Ok(Ok(read)) if read > 0 => Some(started.elapsed()),
            _ => None,
        }
    }

    async fn tcp_answers(peer: SocketAddr, timeout: Duration) -> Option<Duration> {
        let started = Instant::now();
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(peer)).await {
            Ok(Ok(_)) => Some(started.elapsed()),
            _ => None,
        }
    }

    async fn first_answer(
        targets: &[SocketAddr],
        timeout: Duration,
        attempts: u32,
        udp: bool,
    ) -> Option<(SocketAddr, Duration)> {
        for _ in 0..attempts {
            let probes = targets.iter().copied().map(|peer| async move {
                let rtt = match udp {
                    true => quic_answers(peer, timeout).await,
                    false => tcp_answers(peer, timeout).await,
                };
                (peer, rtt)
            });

            let results: Vec<(SocketAddr, Option<Duration>)> = futures::stream::iter(probes)
                .buffer_unordered(targets.len().max(1))
                .collect()
                .await;

            if let Some((peer, Some(rtt))) = results.into_iter().find(|(_, rtt)| rtt.is_some()) {
                return Some((peer, rtt));
            }
        }
        None
    }

    fn hosts_of(cidr: &str, tails: &[u8]) -> Vec<Ipv4Addr> {
        let base: Ipv4Addr = cidr.split('/').next().unwrap().parse().expect("cidr base");
        let octets = base.octets();
        tails
            .iter()
            .map(|tail| Ipv4Addr::new(octets[0], octets[1], octets[2], *tail))
            .collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "probes the live cloudflare edge from this network to see which masque ranges answer"]
    async fn report_which_masque_ranges_answer_on_this_network() {
        const TAILS: &[u8] = &[1, 2, 3];

        let timeout = Duration::from_millis(
            std::env::var("AETHER_PROBE_TIMEOUT_MS")
                .ok()
                .and_then(|raw| raw.trim().parse::<u64>().ok())
                .filter(|ms| *ms > 0)
                .unwrap_or(10_000),
        );

        let attempts = std::env::var("AETHER_PROBE_ATTEMPTS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u32>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(2);

        let ports: Vec<u16> = match std::env::var("AETHER_PROBE_PORTS") {
            Ok(raw) => raw
                .split(',')
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .collect(),
            Err(_) => vec![443],
        };
        let ports = if ports.is_empty() { vec![443] } else { ports };

        println!();
        println!("probing the masque ranges from this network");
        println!("  udp timeout {timeout:?}, {attempts} attempt(s), hosts {TAILS:?}");
        println!("  udp ports {ports:?}");
        println!("  override: AETHER_PROBE_TIMEOUT_MS, AETHER_PROBE_ATTEMPTS, AETHER_PROBE_PORTS");
        println!();

        let control: Vec<SocketAddr> = vec![
            "1.1.1.1:443".parse().unwrap(),
            "8.8.8.8:443".parse().unwrap(),
        ];

        let control_quic = first_answer(&control, timeout, attempts, true).await;
        let control_tcp = first_answer(&control, timeout, attempts, false).await;

        println!("control targets (public resolvers, not cloudflare warp edges)");
        match control_quic {
            Some((peer, rtt)) => println!("  quic/udp 443 works: {peer} in {}ms", rtt.as_millis()),
            None => println!("  quic/udp 443 got no answer at all"),
        }
        match control_tcp {
            Some((peer, rtt)) => println!("  tcp 443 works:      {peer} in {}ms", rtt.as_millis()),
            None => println!("  tcp 443 got no answer at all"),
        }
        println!();

        let mut udp_ok = Vec::new();
        let mut tcp_only = Vec::new();
        let mut silent = Vec::new();

        for cidr in MASQUE_CIDRS_V4 {
            let note = if MASQUE_DOCUMENTED_CIDRS_V4.contains(cidr) {
                " [documented]"
            } else if MASQUE_DOH_CIDRS_V4.contains(cidr) {
                " [dns-over-https]"
            } else {
                ""
            };

            let hosts = hosts_of(cidr, TAILS);

            let mut udp_hit: Option<(SocketAddr, Duration)> = None;
            for port in &ports {
                let targets: Vec<SocketAddr> = hosts
                    .iter()
                    .map(|ip| SocketAddr::new(IpAddr::V4(*ip), *port))
                    .collect();
                udp_hit = first_answer(&targets, timeout, attempts, true).await;
                if udp_hit.is_some() {
                    break;
                }
            }

            let tcp_targets: Vec<SocketAddr> = hosts
                .iter()
                .map(|ip| SocketAddr::new(IpAddr::V4(*ip), 443))
                .collect();
            let tcp_hit = first_answer(&tcp_targets, timeout, attempts, false).await;

            match (udp_hit, tcp_hit) {
                (Some((peer, rtt)), _) => {
                    println!("  UDP OK    {cidr}{note}  {peer} in {}ms", rtt.as_millis());
                    udp_ok.push(*cidr);
                }
                (None, Some((peer, rtt))) => {
                    println!(
                        "  TCP ONLY  {cidr}{note}  {peer} in {}ms, udp stayed silent",
                        rtt.as_millis()
                    );
                    tcp_only.push(*cidr);
                }
                (None, None) => {
                    println!("  SILENT    {cidr}{note}");
                    silent.push(*cidr);
                }
            }
        }

        println!();
        println!("masque over quic works on ({}):", udp_ok.len());
        for cidr in &udp_ok {
            println!("  {cidr}");
        }
        println!();
        println!("reachable over tcp only ({}):", tcp_only.len());
        for cidr in &tcp_only {
            println!("  {cidr}");
        }
        println!();
        println!("no answer on either ({}):", silent.len());
        for cidr in &silent {
            println!("  {cidr}");
        }

        println!();
        println!("verdict");
        if !udp_ok.is_empty() {
            println!("  put these ranges first in MASQUE_CIDRS_V4: {udp_ok:?}");
        } else if control_quic.is_none() {
            println!("  this network answers no quic at all, not even a public resolver,");
            println!("  so udp 443 is blocked here rather than these ranges being blocked.");
            println!("  reordering MASQUE_CIDRS_V4 cannot help; masque needs its http/2");
            println!("  fallback over tcp 443 (--masque-http2) on this network.");
        } else {
            println!("  quic works to other hosts but every warp range stayed silent,");
            println!("  so these ranges really are filtered here.");
            if !tcp_only.is_empty() {
                println!("  the tcp-only ranges above can still carry masque over http/2.");
            }
        }
        println!();
    }

    #[test]
    fn every_masque_prefix_and_seed_parses() {
        for entry in MASQUE_CIDRS_V4 {
            let (addr, bits) = entry.split_once('/').expect("cidr");
            assert!(addr.parse::<Ipv4Addr>().is_ok(), "{entry}");
            assert!(bits.parse::<u8>().is_ok(), "{entry}");
        }
        for entry in MASQUE_CIDRS_V6 {
            let (addr, bits) = entry.split_once('/').expect("cidr");
            assert!(addr.parse::<Ipv6Addr>().is_ok(), "{entry}");
            assert!(bits.parse::<u8>().is_ok(), "{entry}");
        }
        for seed in MASQUE_SEEDS {
            assert!(seed.parse::<Ipv4Addr>().is_ok(), "{seed}");
        }
        for seed in MASQUE_SEEDS_V6 {
            assert!(seed.parse::<Ipv6Addr>().is_ok(), "{seed}");
        }
    }
}

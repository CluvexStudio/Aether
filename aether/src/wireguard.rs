use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

use crate::aethernoize::{self, AetherNoizeConfig};
use crate::error::{AetherError, Result};
use rand::Rng;

const TIMER_TICK: Duration = Duration::from_millis(250);
const MAX_PACKET: usize = 65536;

const WG_MSG_TYPE_MIN: u8 = 1;
const WG_MSG_TYPE_MAX: u8 = 4;

fn inject_client_id(pkt: &mut [u8], client_id: &[u8; 3]) {
    if pkt.len() < 4 {
        return;
    }
    if pkt[0] < WG_MSG_TYPE_MIN || pkt[0] > WG_MSG_TYPE_MAX {
        return;
    }
    pkt[1..4].copy_from_slice(client_id);
}

fn strip_client_id(pkt: &mut [u8]) {
    if pkt.len() < 4 {
        return;
    }
    if pkt[0] < WG_MSG_TYPE_MIN || pkt[0] > WG_MSG_TYPE_MAX {
        return;
    }
    pkt[1..4].copy_from_slice(&[0u8; 3]);
}

#[derive(Clone)]
pub struct WgConfig {
    pub local_private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub peer_endpoint: SocketAddr,
    pub local_ipv4: Ipv4Addr,
    pub local_ipv6: Ipv6Addr,
    pub client_id: [u8; 3],
    pub preshared_key: Option<[u8; 32]>,
    pub persistent_keepalive: Option<u16>,
    pub aethernoize: Arc<AetherNoizeConfig>,
}

pub struct WgTunnel {
    tunn: Arc<Mutex<Box<Tunn>>>,
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    pub obf_sent: Arc<Mutex<bool>>,
    pub aethernoize: Arc<AetherNoizeConfig>,
    pub client_id: [u8; 3],
}

pub struct EstablishedSession {
    tunn: Arc<Mutex<Box<Tunn>>>,
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    client_id: [u8; 3],
}

impl WgTunnel {
    pub async fn new(cfg: WgConfig, inbound_tx: mpsc::Sender<Vec<u8>>) -> Result<Self> {
        let bind_addr = if cfg.peer_endpoint.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let sock = UdpSocket::bind(bind_addr).await?;
        sock.connect(cfg.peer_endpoint).await?;

        let local_secret = StaticSecret::from(cfg.local_private_key);
        let peer_public = PublicKey::from(cfg.peer_public_key);
        let preshared = cfg.preshared_key;

        let tunn = Tunn::new(local_secret, peer_public, preshared, cfg.persistent_keepalive, 0, None)
            .map_err(|e| AetherError::Other(format!("wireguard tunnel init: {e}")))?;

        Ok(Self {
            tunn: Arc::new(Mutex::new(Box::new(tunn))),
            sock: Arc::new(sock),
            peer: cfg.peer_endpoint,
            inbound_tx,
            obf_sent: Arc::new(Mutex::new(false)),
            aethernoize: cfg.aethernoize.clone(),
            client_id: cfg.client_id,
        })
    }

    pub fn from_established(
        session: EstablishedSession,
        aethernoize: Arc<AetherNoizeConfig>,
        inbound_tx: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        Self {
            tunn: session.tunn,
            sock: session.sock,
            peer: session.peer,
            inbound_tx,
            obf_sent: Arc::new(Mutex::new(true)),
            aethernoize,
            client_id: session.client_id,
        }
    }

    pub async fn run(self, mut outbound_rx: mpsc::Receiver<Vec<u8>>) -> Result<()> {
        let sock_r = self.sock.clone();
        let sock_w = self.sock.clone();
        let sock_t = self.sock.clone();
        let tunn_r = self.tunn.clone();
        let tunn_w = self.tunn.clone();
        let tunn_t = self.tunn.clone();
        let inbound_tx = self.inbound_tx.clone();
        let obf_sent = self.obf_sent.clone();
        let aethernoize = self.aethernoize.clone();
        let aethernoize_t = self.aethernoize.clone();
        let client_id = self.client_id;
        let peer = self.peer;

        let recv_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET];
            let mut tmp = vec![0u8; MAX_PACKET];
            loop {
                match sock_r.recv(&mut buf).await {
                    Ok(n) => {
                        strip_client_id(&mut buf[..n]);
                        let mut tunn = tunn_r.lock().await;
                        match tunn.decapsulate(None, &buf[..n], &mut tmp) {
                            TunnResult::Done => {}
                            TunnResult::Err(e) => {
                                log::debug!("decapsulate error: {e:?}");
                            }
                            TunnResult::WriteToNetwork(pkt) => {
                                let mut pkt_vec = pkt.to_vec();
                                inject_client_id(&mut pkt_vec, &client_id);
                                drop(tunn);
                                let _ = sock_r.send(&pkt_vec).await;
                            }
                            TunnResult::WriteToTunnelV4(pkt, _) | TunnResult::WriteToTunnelV6(pkt, _) => {
                                let pkt_vec = pkt.to_vec();
                                drop(tunn);
                                let _ = inbound_tx.send(pkt_vec).await;
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("recv error: {e}");
                        break;
                    }
                }
            }
        });

        let send_task = tokio::spawn(async move {
            while let Some(ip_packet) = outbound_rx.recv().await {
                let mut tunn = tunn_w.lock().await;
                let mut out_buf = vec![0u8; MAX_PACKET];

                match tunn.encapsulate(&ip_packet, &mut out_buf) {
                    TunnResult::Done => {}
                    TunnResult::Err(e) => {
                        log::debug!("encapsulate error: {e:?}");
                    }
                    TunnResult::WriteToNetwork(pkt) => {
                        let mut pkt_vec = pkt.to_vec();
                        inject_client_id(&mut pkt_vec, &client_id);
                        drop(tunn);

                        {
                            let mut sent = obf_sent.lock().await;
                            if !*sent && aethernoize.is_enabled() {
                                *sent = true;
                                drop(sent);
                                aethernoize::apply_obfuscation(&sock_w, peer, &aethernoize).await;
                            }
                        }

                        let _ = sock_w.send(&pkt_vec).await;

                        if aethernoize.jc_after_hs > 0 {
                            let sock_clone = sock_w.clone();
                            let cfg_clone = aethernoize.clone();
                            tokio::spawn(async move {
                                aethernoize::send_post_handshake_junk(&sock_clone, peer, &cfg_clone).await;
                            });
                        }
                    }
                    TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {}
                }
            }
        });

        let timer_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(TIMER_TICK);
            loop {
                interval.tick().await;
                let mut tunn = tunn_t.lock().await;
                let mut tmp = vec![0u8; MAX_PACKET];
                if let TunnResult::WriteToNetwork(pkt) = tunn.update_timers(&mut tmp) {
                    let mut pkt_vec = pkt.to_vec();
                    inject_client_id(&mut pkt_vec, &client_id);
                    drop(tunn);

                    if aethernoize_t.is_enabled() {
                        let sock_j = sock_t.clone();
                        let cfg_j = aethernoize_t.clone();
                        tokio::spawn(async move {
                            aethernoize::send_keepalive_junk(&sock_j, &cfg_j).await;
                            let _ = sock_j.send(&pkt_vec).await;
                        });
                    } else {
                        let _ = sock_t.send(&pkt_vec).await;
                    }
                }
            }
        });

        tokio::select! {
            _ = recv_task => log::info!("wireguard recv task ended"),
            _ = send_task => log::info!("wireguard send task ended"),
            _ = timer_task => log::info!("wireguard timer task ended"),
        }

        Ok(())
    }
}

fn build_dns_query() -> Vec<u8> {
    let id: u16 = rand::random();
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in ["cloudflare", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x01]);
    q
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_dataplane_probe(src: Ipv4Addr) -> Vec<u8> {
    let dns = build_dns_query();
    let udp_len = 8 + dns.len();
    let total_len = 20 + udp_len;
    let mut pkt = Vec::with_capacity(total_len);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    let id: u16 = rand::random();
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(64);
    pkt.push(17);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&Ipv4Addr::new(8, 8, 8, 8).octets());
    let csum = ipv4_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    let sport: u16 = rand::thread_rng().gen_range(20000..60000);
    pkt.extend_from_slice(&sport.to_be_bytes());
    pkt.extend_from_slice(&53u16.to_be_bytes());
    pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&dns);
    pkt
}

async fn send_dataplane_probe(
    sock: &UdpSocket,
    tunn: &mut Tunn,
    client_id: &[u8; 3],
    probe: &[u8],
    out_buf: &mut [u8],
) -> Result<()> {
    match tunn.encapsulate(probe, out_buf) {
        TunnResult::WriteToNetwork(pkt) => {
            let mut v = pkt.to_vec();
            inject_client_id(&mut v, client_id);
            sock.send(&v).await?;
        }
        TunnResult::Err(e) => {
            return Err(AetherError::Other(format!("dataplane encap: {e:?}")));
        }
        _ => {}
    }
    Ok(())
}

const DATAPLANE_REQUIRED_SUCCESSES: u32 = 2;
const DATAPLANE_PROBE_GAP: Duration = Duration::from_millis(600);

async fn verify_dataplane(
    sock: &UdpSocket,
    tunn: &mut Tunn,
    client_id: &[u8; 3],
    local_ipv4: Ipv4Addr,
    start: Instant,
    deadline: Instant,
) -> Result<Duration> {
    let probe = build_dataplane_probe(local_ipv4);
    let mut out_buf = vec![0u8; MAX_PACKET];
    let mut recv_buf = vec![0u8; MAX_PACKET];
    let mut tmp_buf = vec![0u8; MAX_PACKET];

    let mut successes: u32 = 0;
    let mut last_probe_at = Instant::now();
    send_dataplane_probe(sock, tunn, client_id, &probe, &mut out_buf).await?;
    let mut resend_at = last_probe_at + Duration::from_millis(700);

    loop {
        let now = Instant::now();
        if now >= deadline {
            log::debug!(
                "[wg] dataplane verify timed out ({}/{} confirmations)",
                successes, DATAPLANE_REQUIRED_SUCCESSES
            );
            return Err(AetherError::Other("dataplane timeout".into()));
        }
        if now >= resend_at {
            let _ = send_dataplane_probe(sock, tunn, client_id, &probe, &mut out_buf).await;
            last_probe_at = now;
            resend_at = now + Duration::from_millis(700);
        }
        let wait = deadline
            .saturating_duration_since(now)
            .min(resend_at.saturating_duration_since(now));

        tokio::select! {
            r = sock.recv(&mut recv_buf) => {
                let n = r?;
                strip_client_id(&mut recv_buf[..n]);
                match tunn.decapsulate(None, &recv_buf[..n], &mut tmp_buf) {
                    TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                        successes += 1;
                        log::debug!(
                            "[wg] dataplane round-trip {}/{} confirmed in {:?}",
                            successes, DATAPLANE_REQUIRED_SUCCESSES, start.elapsed()
                        );
                        if successes >= DATAPLANE_REQUIRED_SUCCESSES {
                            let elapsed = start.elapsed();
                            log::debug!("[wg] dataplane ok in {:?}", elapsed);
                            return Ok(elapsed);
                        }
                        let next_at = Instant::now().max(last_probe_at + DATAPLANE_PROBE_GAP);
                        let _ = send_dataplane_probe(sock, tunn, client_id, &probe, &mut out_buf).await;
                        last_probe_at = next_at;
                        resend_at = next_at + Duration::from_millis(700);
                    }
                    TunnResult::WriteToNetwork(pkt) => {
                        let mut v = pkt.to_vec();
                        inject_client_id(&mut v, client_id);
                        let _ = sock.send(&v).await;
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

pub async fn verify_endpoint(
    peer: SocketAddr,
    private_key: [u8; 32],
    peer_public: [u8; 32],
    client_id: [u8; 3],
    local_ipv4: Ipv4Addr,
    aethernoize: &AetherNoizeConfig,
    timeout: Duration,
) -> Result<Duration> {
    let (elapsed, _session) = verify_endpoint_keep_session(
        peer,
        private_key,
        peer_public,
        client_id,
        local_ipv4,
        aethernoize,
        timeout,
    )
    .await?;
    Ok(elapsed)
}

pub async fn verify_endpoint_keep_session(
    peer: SocketAddr,
    private_key: [u8; 32],
    peer_public: [u8; 32],
    client_id: [u8; 3],
    local_ipv4: Ipv4Addr,
    aethernoize: &AetherNoizeConfig,
    timeout: Duration,
) -> Result<(Duration, EstablishedSession)> {
    let data_check = std::env::var("AETHER_WG_NO_DATA_CHECK").is_err();
    log::debug!("[wg] verify {} obf={} data_check={}", peer, aethernoize.is_enabled(), data_check);

    let bind = if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(peer).await?;

    let start = Instant::now();
    let deadline = start + timeout;

    if aethernoize.is_enabled() {
        aethernoize::apply_obfuscation(&sock, peer, aethernoize).await;
    }

    let local_secret = StaticSecret::from(private_key);
    let peer_pk = PublicKey::from(peer_public);

    let mut tunn = Tunn::new(local_secret, peer_pk, None, Some(25), 0, None)
        .map_err(|e| AetherError::Other(format!("tunn init: {e}")))?;

    let mut out_buf = vec![0u8; MAX_PACKET];
    let mut recv_buf = vec![0u8; MAX_PACKET];
    let mut tmp_buf = vec![0u8; MAX_PACKET];

    match tunn.encapsulate(&[], &mut out_buf) {
        TunnResult::WriteToNetwork(pkt) => {
            let mut pkt_vec = pkt.to_vec();
            inject_client_id(&mut pkt_vec, &client_id);
            log::debug!("[wg] sending init {} bytes to {}", pkt_vec.len(), peer);
            sock.send(&pkt_vec).await?;
        }
        other => {
            log::warn!("[wg] unexpected encap result: {:?}", other);
            return Err(AetherError::Other("handshake init failed".into()));
        }
    }

    let mut attempts = 0;
    loop {
        if Instant::now() >= deadline {
            log::debug!("[wg] timeout after {} recv attempts", attempts);
            return Err(AetherError::Other("verify timeout".into()));
        }

        let remaining = deadline.saturating_duration_since(Instant::now());

        tokio::select! {
            r = sock.recv(&mut recv_buf) => {
                attempts += 1;
                let n = r?;
                log::debug!("[wg] recv {} bytes (attempt {})", n, attempts);
                strip_client_id(&mut recv_buf[..n]);

                match tunn.decapsulate(None, &recv_buf[..n], &mut tmp_buf) {
                    TunnResult::Done => {
                        let elapsed = start.elapsed();
                        log::debug!("[wg] handshake done in {:?}", elapsed);
                        if data_check {
                            let dp_elapsed = verify_dataplane(&sock, &mut tunn, &client_id, local_ipv4, start, deadline).await?;
                            return Ok((dp_elapsed, EstablishedSession {
                                tunn: Arc::new(Mutex::new(Box::new(tunn))),
                                sock: Arc::new(sock),
                                peer,
                                client_id,
                            }));
                        }
                        return Ok((elapsed, EstablishedSession {
                            tunn: Arc::new(Mutex::new(Box::new(tunn))),
                            sock: Arc::new(sock),
                            peer,
                            client_id,
                        }));
                    }
                    TunnResult::WriteToNetwork(pkt) => {
                        let mut pkt_vec = pkt.to_vec();
                        inject_client_id(&mut pkt_vec, &client_id);
                        log::debug!("[wg] sending response {} bytes", pkt_vec.len());
                        sock.send(&pkt_vec).await?;
                        let elapsed = start.elapsed();
                        log::debug!("[wg] handshake success in {:?}", elapsed);
                        if data_check {
                            let dp_elapsed = verify_dataplane(&sock, &mut tunn, &client_id, local_ipv4, start, deadline).await?;
                            return Ok((dp_elapsed, EstablishedSession {
                                tunn: Arc::new(Mutex::new(Box::new(tunn))),
                                sock: Arc::new(sock),
                                peer,
                                client_id,
                            }));
                        }
                        return Ok((elapsed, EstablishedSession {
                            tunn: Arc::new(Mutex::new(Box::new(tunn))),
                            sock: Arc::new(sock),
                            peer,
                            client_id,
                        }));
                    }
                    TunnResult::Err(e) => {
                        log::debug!("[wg] decap error: {:?}", e);
                    }
                    other => {
                        log::debug!("[wg] unexpected decap: {:?}", other);
                    }
                }
            }
            _ = tokio::time::sleep(remaining) => {
                log::debug!("[wg] sleep timeout");
                return Err(AetherError::Other("verify timeout".into()));
            }
        }
    }
}

pub const WG_PREFIXES_V4: &[&str] = &[
    "162.159.192.0/24",
    "162.159.195.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
];

pub const WG_PREFIXES_V6: &[&str] = &["2606:4700:d0::/64", "2606:4700:d1::/64"];

pub const WG_PORTS: &[u16] = &[
    500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945,
    946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371,
    2408, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281,
    7559, 8319, 8742, 8854, 8886,
];

pub const WG_SEEDS_V4: &[&str] = &[
    "162.159.192.1",
    "162.159.195.1",
    "188.114.96.1",
    "188.114.97.1",
];

pub const WG_SEEDS_V6: &[&str] = &["2606:4700:d0::a29f:c001", "2606:4700:d1::a29f:c001", "2606:4700:d0::a29f:c301", "2606:4700:d0::bc72:6001"];

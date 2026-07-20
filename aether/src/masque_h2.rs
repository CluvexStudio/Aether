use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use boring::pkey::PKey;
use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use boring::x509::X509;
use bytes::Bytes;
use http::Method;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use crate::consts;
use crate::error::{AetherError, Result};
use crate::fragment::{FragmentConfig, FragmentingStream};
use crate::masque::{self, Capsule, CapsuleParser};
use crate::quic::{AssignedAddr, Control, Internals};

const H2_ALPN: &[u8] = b"\x02h2";
const CHROME_GROUPS: &str = "P-256:X25519:P-384";

pub struct H2TunnelConfig {
    pub peer: SocketAddr,
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub local_ipv4: Ipv4Addr,
    pub quiet: bool,
}

fn log_or_debug(quiet: bool, msg: String) {
    if quiet {
        log::debug!("{msg}");
    } else {
        log::info!("{msg}");
    }
}

fn data_check_enabled() -> bool {
    std::env::var("AETHER_MASQUE_NO_DATA_CHECK").is_err()
}

fn validation_timeout() -> Duration {
    let secs = std::env::var("AETHER_MASQUE_VALIDATE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(10);
    Duration::from_secs(secs)
}

const DATA_PROBE_REQUIRED_SUCCESSES: u32 = 2;

fn h2_keepalive_interval() -> Duration {
    let secs = std::env::var("AETHER_MASQUE_H2_KEEPALIVE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(15);
    Duration::from_secs(secs)
}

fn h2_keepalive_timeout() -> Duration {
    let secs = std::env::var("AETHER_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(20);
    Duration::from_secs(secs)
}

pub fn enabled() -> bool {
    match std::env::var("AETHER_MASQUE_HTTP2") {
        Ok(v) => {
            let v = v.trim().to_lowercase();
            v == "1" || v == "true" || v == "h2" || v == "yes" || v == "on"
        }
        Err(_) => false,
    }
}

pub fn h2_peer(quic_peer: SocketAddr) -> SocketAddr {
    if let Ok(v) = std::env::var("AETHER_MASQUE_H2_PEER") {
        if let Ok(addr) = v.trim().parse::<SocketAddr>() {
            return addr;
        }
    }
    quic_peer
}

fn build_tls(cfg: &H2TunnelConfig) -> Result<boring::ssl::ConnectConfiguration> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| AetherError::Tls(e.to_string()))?;

    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder.set_grease_enabled(true);

    let groups = std::env::var("AETHER_TLS_GROUPS").ok();
    let groups = groups
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(CHROME_GROUPS);
    builder
        .set_curves_list(groups)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder
        .set_alpn_protos(H2_ALPN)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let cert = X509::from_pem(&cfg.cert_pem).map_err(|e| AetherError::Tls(e.to_string()))?;
    let key =
        PKey::private_key_from_pem(&cfg.key_pem).map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_certificate(&cert)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_private_key(&key)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder.set_verify(SslVerifyMode::NONE);

    let connector = builder.build();
    let mut config = connector
        .configure()
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    config.set_verify_hostname(false);
    config.set_use_server_name_indication(true);

    Ok(config)
}

fn build_connect_request(cfg: &H2TunnelConfig) -> Result<http::Request<()>> {
    let authority = format!("{}:443", cfg.authority);
    let uri = format!("https://{}", authority);
    http::Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("cf-connect-proto", consts::CF_CONNECT_PROTOCOL)
        .header("pq-enabled", "false")
        .header("user-agent", "")
        .body(())
        .map_err(|e| AetherError::Masque(format!("build request: {e}")))
}

pub async fn verify_h2(cfg: &H2TunnelConfig, timeout: Duration) -> Result<Duration> {
    let start = Instant::now();
    let data_check = data_check_enabled();

    let attempt = async {
        let tls_config = build_tls(cfg)?;
        let tcp = TcpStream::connect(cfg.peer).await.map_err(AetherError::Io)?;
        let _ = tcp.set_nodelay(true);
        let fragment = FragmentingStream::new(tcp, FragmentConfig::from_env());
        let tls = tokio_boring::connect(tls_config, &cfg.sni, fragment)
            .await
            .map_err(|e| AetherError::Tls(format!("h2 tls handshake: {e}")))?;
        let (h2, connection) = h2::client::handshake(tls)
            .await
            .map_err(|e| AetherError::Masque(format!("h2 handshake: {e}")))?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut h2 = h2
            .ready()
            .await
            .map_err(|e| AetherError::Masque(format!("h2 ready: {e}")))?;
        let req = build_connect_request(cfg)?;
        let (resp_fut, mut send_stream) = h2
            .send_request(req, false)
            .map_err(|e| AetherError::Masque(format!("send_request: {e}")))?;
        let response = resp_fut
            .await
            .map_err(|e| AetherError::Masque(format!("await response: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            driver.abort();
            return Err(AetherError::Masque(format!(
                "h2 connect-ip status {}",
                status.as_u16()
            )));
        }

        if !data_check {
            driver.abort();
            return Ok(());
        }

        let mut recv_body = response.into_body();
        let mut capsules = CapsuleParser::new();
        let probe = masque::build_dns_probe_packet(cfg.local_ipv4);
        let framed = masque::encode_datagram_capsule(&probe);
        if let Err(e) = send_capsule(&mut send_stream, Bytes::from(framed)).await {
            driver.abort();
            return Err(e);
        }

        let mut probe_successes: u32 = 0;

        loop {
            match futures::future::poll_fn(|cx| recv_body.poll_data(cx)).await {
                Some(Ok(chunk)) => {
                    let _ = recv_body.flow_control().release_capacity(chunk.len());
                    capsules.push(&chunk);
                    loop {
                        match capsules.next() {
                            Ok(Some(Capsule::Datagram(_))) => {
                                probe_successes += 1;
                                if probe_successes >= DATA_PROBE_REQUIRED_SUCCESSES {
                                    driver.abort();
                                    return Ok(());
                                }
                                let framed = masque::encode_datagram_capsule(&probe);
                                if let Err(e) =
                                    send_capsule(&mut send_stream, Bytes::from(framed)).await
                                {
                                    driver.abort();
                                    return Err(e);
                                }
                            }
                            Ok(Some(_)) => continue,
                            Ok(None) => break,
                            Err(_) => break,
                        }
                    }
                }
                Some(Err(e)) => {
                    driver.abort();
                    return Err(AetherError::Masque(format!("h2 body: {e}")));
                }
                None => {
                    driver.abort();
                    return Err(AetherError::Masque("h2 stream closed before data".into()));
                }
            }
        }
    };

    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(())) => Ok(start.elapsed()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(AetherError::Other("h2 verify timeout".into())),
    }
}

pub async fn run(
    cfg: H2TunnelConfig,
    internals: Internals,
    addr_tx: Option<mpsc::Sender<AssignedAddr>>,
    ready_tx: Option<oneshot::Sender<()>>,
) -> Result<()> {
    let (mut outbound_rx, inbound_tx, mut ctrl_rx) = internals.into_parts();
    let quiet = cfg.quiet;
    let data_check = data_check_enabled();
    let probe_packet = masque::build_dns_probe_packet(cfg.local_ipv4);
    let mut ready_tx = ready_tx;
    let mut ready_fired = false;
    let mut validate_successes: u32 = 0;

    let tls_config = build_tls(&cfg)?;

    log_or_debug(quiet, format!("[h2] connecting tcp to {}", cfg.peer));
    let tcp = TcpStream::connect(cfg.peer).await.map_err(AetherError::Io)?;
    let _ = tcp.set_nodelay(true);

    let frag_cfg = FragmentConfig::from_env();
    if frag_cfg.enabled {
        log_or_debug(quiet, format!(
            "[h2] fragmenting client hello: size={}..{} delay={}..{}ms",
            frag_cfg.size_min, frag_cfg.size_max, frag_cfg.delay_min_ms, frag_cfg.delay_max_ms
        ));
    }
    let fragment = FragmentingStream::new(tcp, frag_cfg);

    let tls = tokio_boring::connect(tls_config, &cfg.sni, fragment)
        .await
        .map_err(|e| AetherError::Tls(format!("h2 tls handshake: {e}")))?;
    log_or_debug(quiet, format!(
        "[h2] tls established; alpn={}",
        String::from_utf8_lossy(tls.ssl().selected_alpn_protocol().unwrap_or(b""))
    ));

    let (h2, mut connection) = h2::client::handshake(tls)
        .await
        .map_err(|e| AetherError::Masque(format!("h2 handshake: {e}")))?;

    let mut ping_pong = connection.ping_pong().ok_or_else(|| {
        AetherError::Masque("h2 connection does not support ping".into())
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            log::debug!("[h2] connection driver ended: {e}");
        }
    });

    let mut h2 = h2
        .ready()
        .await
        .map_err(|e| AetherError::Masque(format!("h2 ready: {e}")))?;

    let req = build_connect_request(&cfg)?;

    let (resp_fut, mut send_stream) = h2
        .send_request(req, false)
        .map_err(|e| AetherError::Masque(format!("send_request: {e}")))?;
    log_or_debug(quiet, format!("[h2] connect-ip request sent to {}", cfg.authority));

    let response = resp_fut
        .await
        .map_err(|e| AetherError::Masque(format!("await response: {e}")))?;
    let status = response.status();
    log_or_debug(quiet, format!("[h2] connect-ip status: {}", status.as_u16()));
    if !status.is_success() {
        return Err(AetherError::Masque(format!(
            "h2 connect-ip status {}",
            status.as_u16()
        )));
    }

    let mut recv_body = response.into_body();
    let mut capsules = CapsuleParser::new();

    let mut validate_deadline: Option<Instant> = None;
    if data_check {
        let framed = masque::encode_datagram_capsule(&probe_packet);
        if let Err(e) = send_capsule(&mut send_stream, Bytes::from(framed)).await {
            log::debug!("[h2] initial data-plane probe: {e}");
        }
        validate_deadline = Some(Instant::now() + validation_timeout());
        log_or_debug(quiet, "[h2] validating data-plane (end-to-end probe) before exposing socks5".to_string());
    } else if !ready_fired {
        ready_fired = true;
        if let Some(tx) = ready_tx.take() {
            let _ = tx.send(());
        }
    }

    let mut probe_interval = tokio::time::interval(Duration::from_millis(700));
    probe_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let keepalive_period = h2_keepalive_interval();
    let mut keepalive_interval = tokio::time::interval(keepalive_period);
    keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut awaiting_pong = false;
    let mut pong_deadline: Option<Instant> = None;
    let keepalive_timeout = h2_keepalive_timeout();

    loop {
        if data_check && !ready_fired {
            if let Some(dl) = validate_deadline {
                if Instant::now() >= dl {
                    log::warn!(
                        "[h2] data-plane validation timed out; edge accepts control but drops traffic"
                    );
                    let _ = send_stream.send_data(Bytes::new(), true);
                    return Err(AetherError::Masque(
                        "h2 data-plane validation timeout (handshake ok, no traffic)".into(),
                    ));
                }
            }
        }

        if let Some(dl) = pong_deadline {
            if Instant::now() >= dl {
                log::warn!(
                    "[h2] no PING response from edge within {:?}; connection is stalled",
                    keepalive_timeout
                );
                let _ = send_stream.send_data(Bytes::new(), true);
                return Err(AetherError::Masque("h2 keepalive timeout".into()));
            }
        }

        tokio::select! {
            biased;

            _ = keepalive_interval.tick(), if ready_fired && !awaiting_pong => {
                match ping_pong.send_ping(h2::Ping::opaque()) {
                    Ok(()) => {
                        awaiting_pong = true;
                        pong_deadline = Some(Instant::now() + keepalive_timeout);
                        log::debug!("[h2] keepalive ping sent");
                    }
                    Err(e) => log::debug!("[h2] keepalive ping send failed: {e}"),
                }
            }

            pong = std::future::poll_fn(|cx| ping_pong.poll_pong(cx)), if awaiting_pong => {
                match pong {
                    Ok(_) => {
                        awaiting_pong = false;
                        pong_deadline = None;
                        log::debug!("[h2] keepalive pong received");
                    }
                    Err(e) => {
                        log::warn!("[h2] keepalive ping failed: {e}");
                        let _ = send_stream.send_data(Bytes::new(), true);
                        return Err(AetherError::Masque(format!("h2 keepalive: {e}")));
                    }
                }
            }

            _ = probe_interval.tick(), if data_check && !ready_fired => {
                let framed = masque::encode_datagram_capsule(&probe_packet);
                if let Err(e) = send_capsule(&mut send_stream, Bytes::from(framed)).await {
                    log::debug!("[h2] data-plane probe resend: {e}");
                }
            }

            ctrl = ctrl_rx.recv() => {
                match ctrl {
                    Some(Control::Close) | None => {
                        let _ = send_stream.send_data(Bytes::new(), true);
                        log_or_debug(quiet, "[h2] closing tunnel".to_string());
                        return Ok(());
                    }
                    Some(Control::Migrate) => {}
                }
            }

            pkt = outbound_rx.recv() => {
                match pkt {
                    Some(ip_packet) => {
                        let framed = masque::encode_datagram_capsule(&ip_packet);
                        if let Err(e) = send_capsule(&mut send_stream, Bytes::from(framed)).await {
                            log::debug!("[h2] send: {e}");
                            return Err(e);
                        }
                    }
                    None => {
                        let _ = send_stream.send_data(Bytes::new(), true);
                        return Ok(());
                    }
                }
            }

            data = futures::future::poll_fn(|cx| recv_body.poll_data(cx)) => {
                match data {
                    Some(Ok(chunk)) => {
                        let _ = recv_body.flow_control().release_capacity(chunk.len());
                        capsules.push(&chunk);
                        let got_data = drain_capsules(&mut capsules, &inbound_tx, &addr_tx).await;
                        if got_data && !ready_fired {
                            validate_successes += 1;
                            log::debug!(
                                "[h2] data-plane round-trip {}/{} confirmed",
                                validate_successes, DATA_PROBE_REQUIRED_SUCCESSES
                            );
                            if validate_successes >= DATA_PROBE_REQUIRED_SUCCESSES {
                                ready_fired = true;
                                validate_deadline = None;
                                if let Some(tx) = ready_tx.take() {
                                    let _ = tx.send(());
                                }
                                log_or_debug(quiet, "[h2] tunnel validated (end-to-end data confirmed); exposing socks5".to_string());
                            } else {
                                let framed = masque::encode_datagram_capsule(&probe_packet);
                                if let Err(e) =
                                    send_capsule(&mut send_stream, Bytes::from(framed)).await
                                {
                                    log::debug!("[h2] follow-up data-plane probe: {e}");
                                }
                            }
                        }
                    }
                    Some(Err(e)) => {
                        log::warn!("[h2] recv body error: {e}");
                        return Err(AetherError::Masque(format!("h2 body: {e}")));
                    }
                    None => {
                        log_or_debug(quiet, "[h2] server closed stream".to_string());
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn send_capsule(send: &mut h2::SendStream<Bytes>, data: Bytes) -> Result<()> {
    let len = data.len();
    if len == 0 {
        return Ok(());
    }

    send.reserve_capacity(len);
    loop {
        match futures::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(n)) => {
                if n >= len {
                    break;
                }
            }
            Some(Err(e)) => return Err(AetherError::Masque(format!("h2 capacity: {e}"))),
            None => return Err(AetherError::Masque("h2 stream closed".into())),
        }
    }

    send.send_data(data, false)
        .map_err(|e| AetherError::Masque(format!("h2 send_data: {e}")))?;
    Ok(())
}

async fn drain_capsules(
    capsules: &mut CapsuleParser,
    inbound_tx: &mpsc::Sender<Vec<u8>>,
    addr_tx: &Option<mpsc::Sender<AssignedAddr>>,
) -> bool {
    let mut delivered = false;
    loop {
        match capsules.next() {
            Ok(Some(Capsule::Datagram(pkt))) => {
                delivered = true;
                if inbound_tx.send(pkt).await.is_err() {
                    return delivered;
                }
            }
            Ok(Some(Capsule::AddressAssign(addrs))) => {
                for a in addrs {
                    if let Some(ip) = bytes_to_ip(a.ip_version, &a.address) {
                        log::info!("[h2] edge assigned {}/{}", ip, a.prefix_len);
                        if let Some(tx) = addr_tx {
                            let _ = tx.try_send(AssignedAddr {
                                ip,
                                prefix: a.prefix_len,
                            });
                        }
                    }
                }
            }
            Ok(Some(Capsule::RouteAdvertisement(routes))) => {
                log::info!("[h2] received {} route advertisements", routes.len());
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => {
                log::debug!("[h2] capsule parse: {e}");
                break;
            }
        }
    }
    delivered
}

fn bytes_to_ip(version: u8, bytes: &[u8]) -> Option<IpAddr> {
    match version {
        4 if bytes.len() == 4 => Some(IpAddr::V4([bytes[0], bytes[1], bytes[2], bytes[3]].into())),
        6 if bytes.len() == 16 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(bytes);
            Some(IpAddr::V6(b.into()))
        }
        _ => None,
    }
}

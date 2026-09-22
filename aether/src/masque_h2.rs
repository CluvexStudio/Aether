use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use boring::pkey::PKey;
use boring::ssl::{SslConnector, SslMethod, SslVersion};
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
use crate::tls;

const H2_ALPN: &[u8] = b"\x02h2";
const CHROME_GROUPS: &str = "P-256:X25519:P-384";

/// The largest DATA frame we let the edge send us. The h2 default is the RFC
/// minimum of 16 KiB, so a fast stream pays four times the frame headers and
/// four times the wakeups it needs to.
const H2_MAX_FRAME_SIZE: u32 = 64 * 1024;

/// How much a single write to the edge may carry. Every capsule sent on its own
/// costs a DATA frame, a TLS record and a TCP segment, which for a 1280-byte
/// packet is mostly overhead, so packets already queued behind one another are
/// gathered up to this much and sent together.
const H2_SEND_BATCH_BYTES: usize = 32 * 1024;

/// How long the tunnel waits, on a clean shutdown, for the send task to put the
/// closing frame on the wire.
const SENDER_CLOSE_GRACE: Duration = Duration::from_millis(250);

struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Everything the send task accepts besides the packets on the outbound queue.
enum SenderMsg {
    /// A capsule that is already framed, used by the data-plane probes.
    Capsule(Bytes),
    /// End the request stream and stop.
    Finish,
}

/// HTTP/2 flow control decides how much data the edge may have in flight toward
/// us before it has to stop and wait for an acknowledgement, which puts a hard
/// ceiling of window / round-trip-time on a download. The h2 crate defaults to
/// the RFC minimum of 64 KiB on both the stream and the connection, and 64 KiB
/// over a 130 ms round trip is about 500 KB/s however fast the line underneath
/// really is. QUIC and WireGuard never run into this because their windows are
/// megabytes wide; this is what puts HTTP/2 on the same footing.
fn h2_builder() -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(crate::sysprofile::h2_stream_window_bytes())
        .initial_connection_window_size(crate::sysprofile::h2_connection_window_bytes())
        .max_frame_size(H2_MAX_FRAME_SIZE);
    builder
}

pub struct H2TunnelConfig {
    pub peer: SocketAddr,
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub local_ipv4: Ipv4Addr,
    pub quiet: bool,
    pub pin_endpoint: bool,
    pub expected_pins: Vec<Vec<u8>>,
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
        .map(|v| v.min(86_400))
        .unwrap_or(10);
    Duration::from_secs(secs)
}

const DATA_PROBE_REQUIRED_SUCCESSES: u32 = 2;
const DATA_PROBE_RESEND: Duration = Duration::from_millis(700);

fn h2_keepalive_interval() -> Duration {
    let secs = std::env::var("AETHER_MASQUE_H2_KEEPALIVE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(15);
    Duration::from_secs(secs)
}

fn h2_keepalive_timeout() -> Duration {
    let secs = std::env::var("AETHER_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
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

    // Install TLS verification:
    // pin_endpoint=true with pins: pin-based verification (SNI can be spoofed)
    // pin_endpoint=false: SslVerifyMode::NONE (default, required for Cloudflare MASQUE edges)
    let pin_refs: Vec<&[u8]> = cfg.expected_pins.iter().map(|p| p.as_slice()).collect();
    tls::install_verification(&mut *builder, cfg.pin_endpoint, &pin_refs)?;

    let connector = builder.build();
    let mut config = connector
        .configure()
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    // When using pin-based verification, SNI may be spoofed for DPI bypass,
    // so hostname verification against the cert's CN/SAN is not applicable.
    // Standard CA verification requires hostname matching.
    let use_pin_verification = cfg.pin_endpoint && !cfg.expected_pins.is_empty();
    config.set_verify_hostname(!use_pin_verification);
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

pub async fn dial(peer: std::net::SocketAddr) -> Result<TcpStream> {
    match crate::upstream::configured() {
        Some(proxy) => proxy.connect(peer).await,
        None => crate::egress::tcp_connect(peer)
            .await
            .map_err(AetherError::Io),
    }
}

pub async fn verify_h2(cfg: &H2TunnelConfig, timeout: Duration) -> Result<Duration> {
    let start = Instant::now();
    let data_check = data_check_enabled();

    let attempt = async {
        let tls_config = build_tls(cfg)?;
        let tcp = dial(cfg.peer).await?;
        let _ = tcp.set_nodelay(true);
        let fragment = FragmentingStream::new(tcp, FragmentConfig::from_env());
        let tls = tokio_boring::connect(tls_config, &cfg.sni, fragment)
            .await
            .map_err(|e| AetherError::Tls(format!("h2 tls handshake: {e}")))?;
        let (h2, connection) = h2_builder()
            .handshake(tls)
            .await
            .map_err(|e| AetherError::Masque(format!("h2 handshake: {e}")))?;
        let _driver = AbortOnDrop(
            tokio::spawn(async move {
                let _ = connection.await;
            })
            .abort_handle(),
        );
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
            return Err(AetherError::Masque(format!(
                "h2 connect-ip status {}",
                status.as_u16()
            )));
        }

        if !data_check {
            return Ok(());
        }

        let mut recv_body = response.into_body();
        let mut capsules = CapsuleParser::new();
        let probe = masque::build_dns_probe_packet(cfg.local_ipv4);
        let framed = masque::encode_datagram_capsule(&probe);
        send_capsule(&mut send_stream, Bytes::from(framed)).await?;

        let mut probe_successes: u32 = 0;
        let mut resend = tokio::time::interval(DATA_PROBE_RESEND);
        resend.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        resend.tick().await;

        loop {
            tokio::select! {
                biased;

                data = futures::future::poll_fn(|cx| recv_body.poll_data(cx)) => {
                    match data {
                        Some(Ok(chunk)) => {
                            let _ = recv_body.flow_control().release_capacity(chunk.len());
                            capsules.push(&chunk);
                            loop {
                                match capsules.next() {
                                    Ok(Some(Capsule::Datagram(_))) => {
                                        probe_successes += 1;
                                        if probe_successes >= DATA_PROBE_REQUIRED_SUCCESSES {
                                            return Ok(());
                                        }
                                        let framed = masque::encode_datagram_capsule(&probe);
                                        send_capsule(&mut send_stream, Bytes::from(framed)).await?;
                                        resend.reset();
                                    }
                                    Ok(Some(_)) => continue,
                                    Ok(None) => break,
                                    Err(_) => break,
                                }
                            }
                        }
                        Some(Err(e)) => {
                            return Err(AetherError::Masque(format!("h2 body: {e}")));
                        }
                        None => {
                            return Err(AetherError::Masque("h2 stream closed before data".into()));
                        }
                    }
                }

                _ = resend.tick() => {
                    let framed = masque::encode_datagram_capsule(&probe);
                    send_capsule(&mut send_stream, Bytes::from(framed)).await?;
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

async fn sleep_until_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending().await,
    }
}

pub async fn run(
    cfg: H2TunnelConfig,
    internals: Internals,
    addr_tx: Option<mpsc::Sender<AssignedAddr>>,
    ready_tx: Option<oneshot::Sender<()>>,
) -> Result<()> {
    let (outbound_rx, inbound_tx, mut ctrl_rx) = internals.into_parts();
    let quiet = cfg.quiet;
    let data_check = data_check_enabled();
    let probe_packet = masque::build_dns_probe_packet(cfg.local_ipv4);
    let mut ready_tx = ready_tx;
    let mut ready_fired = false;
    let mut validate_successes: u32 = 0;

    let tls_config = build_tls(&cfg)?;

    log_or_debug(quiet, format!("[h2] connecting tcp to {}", cfg.peer));
    let tcp = dial(cfg.peer).await?;
    let _ = tcp.set_nodelay(true);

    let frag_cfg = FragmentConfig::from_env();
    if frag_cfg.enabled {
        log_or_debug(
            quiet,
            format!(
                "[h2] fragmenting client hello: size={}..{} delay={}..{}ms",
                frag_cfg.size_min, frag_cfg.size_max, frag_cfg.delay_min_ms, frag_cfg.delay_max_ms
            ),
        );
    }
    let fragment = FragmentingStream::new(tcp, frag_cfg);

    let tls = tokio_boring::connect(tls_config, &cfg.sni, fragment)
        .await
        .map_err(|e| AetherError::Tls(format!("h2 tls handshake: {e}")))?;
    log_or_debug(
        quiet,
        format!(
            "[h2] tls established; alpn={}",
            String::from_utf8_lossy(tls.ssl().selected_alpn_protocol().unwrap_or(b""))
        ),
    );

    let (h2, mut connection) = h2_builder()
        .handshake(tls)
        .await
        .map_err(|e| AetherError::Masque(format!("h2 handshake: {e}")))?;

    // Worth saying out loud: this is the ceiling on a download, at
    // window / round-trip-time, and it is the first thing to look at when the
    // HTTP/2 carrier is slower than the line underneath it.
    log_or_debug(
        quiet,
        format!(
            "[h2] flow control: stream window {}KB, connection window {}KB, max frame {}KB",
            crate::sysprofile::h2_stream_window_bytes() / 1024,
            crate::sysprofile::h2_connection_window_bytes() / 1024,
            H2_MAX_FRAME_SIZE / 1024,
        ),
    );

    let mut ping_pong = connection
        .ping_pong()
        .ok_or_else(|| AetherError::Masque("h2 connection does not support ping".into()))?;

    let driver_handle = tokio::spawn(async move {
        if let Err(e) = connection.await {
            log::debug!("[h2] connection driver ended: {e}");
        }
    });
    let _driver_guard = AbortOnDrop(driver_handle.abort_handle());

    let mut h2 = h2
        .ready()
        .await
        .map_err(|e| AetherError::Masque(format!("h2 ready: {e}")))?;

    let req = build_connect_request(&cfg)?;

    let (resp_fut, send_stream) = h2
        .send_request(req, false)
        .map_err(|e| AetherError::Masque(format!("send_request: {e}")))?;
    log_or_debug(
        quiet,
        format!("[h2] connect-ip request sent to {}", cfg.authority),
    );

    let response = resp_fut
        .await
        .map_err(|e| AetherError::Masque(format!("await response: {e}")))?;
    let status = response.status();
    log_or_debug(
        quiet,
        format!("[h2] connect-ip status: {}", status.as_u16()),
    );
    if !status.is_success() {
        return Err(AetherError::Masque(format!(
            "h2 connect-ip status {}",
            status.as_u16()
        )));
    }

    let mut recv_body = response.into_body();
    let mut capsules = CapsuleParser::new();

    // Sending gets a task of its own. Kept in the receive loop, a send that has
    // to wait for the edge's window to open would stop poll_data from being
    // polled as well, so a busy upload would stall the download alongside it.
    let (sender_tx, sender_rx) = mpsc::channel::<SenderMsg>(16);
    let (outcome_tx, mut sender_outcome) = oneshot::channel::<Result<()>>();
    let sender_task = tokio::spawn(async move {
        let _ = outcome_tx.send(pump_outbound(send_stream, outbound_rx, sender_rx).await);
    });
    let _sender_guard = AbortOnDrop(sender_task.abort_handle());

    let mut validate_deadline: Option<Instant> = None;
    if data_check {
        let framed = masque::encode_datagram_capsule(&probe_packet);
        if sender_tx
            .send(SenderMsg::Capsule(Bytes::from(framed)))
            .await
            .is_err()
        {
            log::debug!("[h2] initial data-plane probe: the send path is gone");
        }
        validate_deadline = Some(Instant::now() + validation_timeout());
        log_or_debug(
            quiet,
            "[h2] validating data-plane (end-to-end probe) before exposing socks5".to_string(),
        );
    } else if !ready_fired {
        ready_fired = true;
        if let Some(tx) = ready_tx.take() {
            let _ = tx.send(());
        }
    }

    let mut probe_interval = tokio::time::interval(DATA_PROBE_RESEND);
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
                    close_sender(&sender_tx, &mut sender_outcome).await;
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
                close_sender(&sender_tx, &mut sender_outcome).await;
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
                        close_sender(&sender_tx, &mut sender_outcome).await;
                        return Err(AetherError::Masque(format!("h2 keepalive: {e}")));
                    }
                }
            }

            _ = probe_interval.tick(), if data_check && !ready_fired => {
                let framed = masque::encode_datagram_capsule(&probe_packet);
                if sender_tx.try_send(SenderMsg::Capsule(Bytes::from(framed))).is_err() {
                    log::trace!("[h2] data-plane probe resend was dropped");
                }
            }

            _ = sleep_until_deadline(pong_deadline) => {}

            ctrl = ctrl_rx.recv() => {
                match ctrl {
                    Some(Control::Close) | None => {
                        close_sender(&sender_tx, &mut sender_outcome).await;
                        log_or_debug(quiet, "[h2] closing tunnel".to_string());
                        return Ok(());
                    }
                    Some(Control::Migrate) => {}
                }
            }

            outcome = &mut sender_outcome => {
                return match outcome {
                    Ok(Ok(())) => {
                        log_or_debug(quiet, "[h2] send path closed".to_string());
                        Ok(())
                    }
                    Ok(Err(e)) => {
                        log::debug!("[h2] send: {e}");
                        Err(e)
                    }
                    Err(_) => Err(AetherError::Masque("h2 send task stopped".into())),
                };
            }

            data = futures::future::poll_fn(|cx| recv_body.poll_data(cx)) => {
                match data {
                    Some(Ok(chunk)) => {
                        let _ = recv_body.flow_control().release_capacity(chunk.len());
                        capsules.push(&chunk);
                        let got_data = drain_capsules(&mut capsules, &inbound_tx, &addr_tx);
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
                                if sender_tx
                                    .try_send(SenderMsg::Capsule(Bytes::from(framed)))
                                    .is_err()
                                {
                                    log::trace!("[h2] follow-up data-plane probe was dropped");
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

/// Ends the request stream and waits briefly for the send task to get the
/// closing frame out before the connection is torn down.
async fn close_sender(
    sender_tx: &mpsc::Sender<SenderMsg>,
    outcome: &mut oneshot::Receiver<Result<()>>,
) {
    if sender_tx.send(SenderMsg::Finish).await.is_ok() {
        let _ = tokio::time::timeout(SENDER_CLOSE_GRACE, outcome).await;
    }
}

/// Owns the request stream and is the only thing that writes to it, so capsules
/// cannot interleave and a wait for send capacity costs nothing but upload.
async fn pump_outbound(
    mut send: h2::SendStream<Bytes>,
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    mut control_rx: mpsc::Receiver<SenderMsg>,
) -> Result<()> {
    let mut batch: Vec<u8> = Vec::with_capacity(H2_SEND_BATCH_BYTES);

    loop {
        tokio::select! {
            biased;

            msg = control_rx.recv() => {
                match msg {
                    Some(SenderMsg::Capsule(framed)) => send_capsule(&mut send, framed).await?,
                    Some(SenderMsg::Finish) | None => {
                        let _ = send.send_data(Bytes::new(), true);
                        return Ok(());
                    }
                }
            }

            packet = outbound_rx.recv() => {
                let Some(packet) = packet else {
                    let _ = send.send_data(Bytes::new(), true);
                    return Ok(());
                };

                masque::append_datagram_capsule(&mut batch, &packet);

                // Anything already queued behind this packet rides along, so a
                // burst costs one frame rather than one frame per packet.
                while batch.len() < H2_SEND_BATCH_BYTES {
                    match outbound_rx.try_recv() {
                        Ok(next) => masque::append_datagram_capsule(&mut batch, &next),
                        Err(_) => break,
                    }
                }

                let framed = Bytes::copy_from_slice(&batch);
                batch.clear();
                send_capsule(&mut send, framed).await?;
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
    while send.capacity() < len {
        match futures::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(_)) => {}
            Some(Err(e)) => return Err(AetherError::Masque(format!("h2 capacity: {e}"))),
            None => return Err(AetherError::Masque("h2 stream closed".into())),
        }
    }

    send.send_data(data, false)
        .map_err(|e| AetherError::Masque(format!("h2 send_data: {e}")))?;
    Ok(())
}

fn drain_capsules(
    capsules: &mut CapsuleParser,
    inbound_tx: &mpsc::Sender<Vec<u8>>,
    addr_tx: &Option<mpsc::Sender<AssignedAddr>>,
) -> bool {
    let mut delivered = false;
    loop {
        match capsules.next() {
            Ok(Some(Capsule::Datagram(payload))) => {
                let pkt = match masque::strip_datagram_context(&payload) {
                    Some(inner) => inner,
                    None => {
                        log::trace!("[h2] discarding a datagram that is not an ip packet");
                        continue;
                    }
                };
                delivered = true;
                match inbound_tx.try_send(pkt) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        log::trace!("[h2] inbound queue full, dropping datagram");
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => return delivered,
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
                log::trace!("[h2] capsule parse: {e}");
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

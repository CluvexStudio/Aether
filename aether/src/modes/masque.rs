use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use super::{
    count_tunnel_end, exit_policy_guard, masque_tunnel_mtu, noize_config, noize_profile,
    parse_local_v4, scan_settings_from_env, team_endpoint, Listeners, TunnelError, TunnelExit,
};
use crate::error::{AetherError, Result};
use crate::modes::gool::run_gool_tunnel;
use crate::prompt::{select_ip_version, select_scan_mode_str, want_quick_reconnect};
use crate::relay::TaskGuard;
use crate::{
    account, consts, dns, exitloc, lastconn, masque_h2, netstack, noize, prober, quic, tls,
};

pub(crate) async fn resolve_ech() -> Result<Option<Vec<u8>>> {
    let setting = crate::settings::var(tls::SESSION_ECH_OPTION.variable).ok();
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

pub(crate) fn masque_reconnect_delay() -> std::time::Duration {
    let secs = crate::settings::var("AETHER_MASQUE_RECONNECT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(2);
    std::time::Duration::from_secs(secs)
}

pub(crate) fn masque_startup_timeout() -> std::time::Duration {
    let secs = crate::settings::var("AETHER_MASQUE_STARTUP_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(30);
    std::time::Duration::from_secs(secs)
}

pub(crate) async fn hunt_masque_peer(
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
        sni: quic::masque_sni()?,
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

pub(crate) async fn quick_verify_masque_peer(
    identity: &account::Identity,
    peer: SocketAddr,
    ech: Option<Vec<u8>>,
    noize: noize::NoizeConfig,
) -> bool {
    let sni = match quic::masque_sni() {
        Ok(sni) => sni,
        Err(e) => {
            log::warn!("[-] {e}");
            return false;
        }
    };
    let vp = quic::VerifyParams {
        peer,
        sni: sni.clone(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        ech_config_list: ech.clone(),
        noize,
        timeout: std::time::Duration::from_secs(5),
        local_ipv4: parse_local_v4(&identity.ipv4),
    };

    if masque_h2::enabled() {
        let cfg = masque_h2::H2TunnelConfig {
            peer: masque_h2::h2_peer(peer),
            sni,
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: true,
            pin_endpoint: true,
            expected_pins: consts::MASQUE_PINS,
            ech_config_list: ech,
        };
        return masque_h2::verify_h2(&cfg, std::time::Duration::from_secs(5))
            .await
            .is_ok();
    }

    quic::verify_masque(&vp).await.is_ok()
}

fn pinned_peer() -> Option<String> {
    crate::settings::var("AETHER_PEER").ok()
}

pub(crate) async fn run_masque(
    identity: account::Identity,
    listeners: Listeners,
    lastconn_path: String,
    gool_inner: Option<String>,
) -> Result<()> {
    let forced = pinned_peer();

    let mut quick_peer: Option<SocketAddr> = None;

    if forced.is_none() {
        if let Some(assigned) = team_endpoint() {
            log::info!("[*] verifying the endpoint the organization assigned: {assigned}");
            if quick_verify_masque_peer(&identity, assigned, tls::session_ech(), noize_config())
                .await
            {
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
                    if quick_verify_masque_peer(&identity, peer, tls::session_ech(), noize_config())
                        .await
                    {
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
                    if quick_verify_masque_peer(&identity, p, tls::session_ech(), noize_config())
                        .await
                    {
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
                        Err(_) => {
                            return Err(AetherError::from(TunnelError::BadPeer(p.to_string())))
                        }
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
            let profile = noize_profile();
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
            Some(path) => {
                run_gool_tunnel(&identity, peer, tls::session_ech(), &listeners, path).await
            }
            None => {
                run_masque_tunnel(
                    &identity,
                    peer,
                    tls::session_ech(),
                    noize_config(),
                    &listeners,
                )
                .await
            }
        };
        strikes.ended(started.elapsed());
        match ended {
            Ok(()) => log::warn!("[-] MASQUE tunnel closed; reconnecting"),
            Err(e) => log::warn!("[-] MASQUE tunnel ended: {e}; reconnecting"),
        }

        tokio::time::sleep(masque_reconnect_delay()).await;
    }
}

const MASQUE_GATEWAY_STRIKES: u32 = 2;

const MASQUE_GATEWAY_REST: std::time::Duration = std::time::Duration::from_secs(300);

#[derive(Debug, Default)]
struct GatewayStrikes {
    current: Option<SocketAddr>,
    in_a_row: u32,
    resting: HashMap<IpAddr, Instant>,
}

impl GatewayStrikes {
    fn using(&mut self, peer: SocketAddr) {
        if self.current != Some(peer) {
            self.current = Some(peer);
            self.in_a_row = 0;
        }
    }

    fn ended(&mut self, lasted: std::time::Duration) {
        self.in_a_row = count_tunnel_end(self.in_a_row, lasted);
    }

    fn give_up(&mut self, now: Instant, rest: std::time::Duration) -> Option<SocketAddr> {
        if self.in_a_row < MASQUE_GATEWAY_STRIKES {
            return None;
        }
        self.in_a_row = 0;
        let peer = self.current.take()?;
        self.resting.insert(peer.ip(), now + rest);
        Some(peer)
    }

    fn left_out(&mut self, now: Instant) -> HashSet<IpAddr> {
        self.resting.retain(|_, until| *until > now);
        self.resting.keys().copied().collect()
    }
}

pub(crate) struct MasqueHop {
    pub(crate) stack: netstack::StackHandle,
    pub(crate) exit: TunnelExit,
    _ctrl: tokio::sync::mpsc::Sender<quic::Control>,
    _guard: TaskGuard,
}

pub(crate) struct Hop<'a> {
    pub(crate) peer: SocketAddr,
    pub(crate) ech: Option<Vec<u8>>,
    pub(crate) noize: noize::NoizeConfig,
    pub(crate) h2: bool,
    pub(crate) mtu: usize,
    pub(crate) datagram: usize,
    pub(crate) version_bait: bool,
    pub(crate) startup: std::time::Duration,
    pub(crate) label: &'a str,
}

pub(crate) async fn establish_masque(
    identity: &account::Identity,
    hop: Hop<'_>,
) -> Result<MasqueHop> {
    let Hop {
        peer,
        ech,
        noize,
        h2,
        mtu,
        datagram,
        version_bait,
        startup,
        label,
    } = hop;
    let sni = quic::masque_sni()?;
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
            sni,
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: false,
            pin_endpoint: true,
            expected_pins: consts::MASQUE_PINS,
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
            sni,
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            ech_config_list: ech,
            noize,
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
            return Err(AetherError::from(match joined {
                Ok(Ok(())) => TunnelError::ExitedBeforeValidation {
                    label: label.to_string(),
                },
                Ok(Err(e)) => TunnelError::FailedBeforeValidation {
                    label: label.to_string(),
                    reason: e.to_string(),
                },
                Err(e) => TunnelError::LabelledJoin {
                    label: label.to_string(),
                    reason: e.to_string(),
                },
            }));
        }
        Err(_) => {
            tunnel_task.abort();
            let _ = tunnel_task.await;
            return Err(AetherError::from(TunnelError::StartupTimeout {
                label: label.to_string(),
                after: startup_timeout,
            }));
        }
    }

    Ok(MasqueHop {
        stack,
        exit: tunnel_task,
        _ctrl: ctrl_tx,
        _guard: guard,
    })
}

pub(crate) async fn run_masque_tunnel(
    identity: &account::Identity,
    peer: SocketAddr,
    ech: Option<Vec<u8>>,
    noize: noize::NoizeConfig,
    listeners: &Listeners,
) -> Result<()> {
    let h2 = masque_h2::enabled();
    let dial = if h2 { masque_h2::h2_peer(peer) } else { peer };

    let mut hop = establish_masque(
        identity,
        Hop {
            peer: dial,
            ech,
            noize,
            h2,
            mtu: masque_tunnel_mtu(),
            datagram: quic::MAX_DATAGRAM_SIZE,
            version_bait: true,
            startup: masque_startup_timeout(),
            label: "masque",
        },
    )
    .await?;

    let policy = exitloc::Policy::from_env();
    exitloc::settle(&hop.stack, &policy, "masque").await?;

    let tunnel_result = tokio::select! {
        result = &mut hop.exit => result,
        reason = exit_policy_guard(&hop.stack, &policy) => return Err(reason),
        never = listeners.serve(&hop.stack) => match never {},
    };

    match tunnel_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(AetherError::from(TunnelError::Exited(e.to_string()))),
        Err(e) => Err(AetherError::from(TunnelError::Join(e.to_string()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modes::{H2_TUNNEL_MTU, TUNNEL_MTU, TUNNEL_STAYED_UP};
    use crate::upstream;

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
        strikes.using(gateway);
        strikes.ended(SOON);
        assert_eq!(strikes.give_up(now, rest), Some(gateway));
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
        strikes.using(second);
        assert_eq!(strikes.give_up(now, rest), None);
    }

    #[test]
    fn a_tunnel_that_stayed_up_clears_the_ends_before_it() {
        let gateway: SocketAddr = "162.159.198.1:443".parse().unwrap();
        let now = Instant::now();
        let rest = std::time::Duration::from_secs(300);
        let mut strikes = GatewayStrikes::default();

        strikes.using(gateway);
        strikes.ended(TUNNEL_STAYED_UP * 36);
        strikes.using(gateway);
        strikes.ended(TUNNEL_STAYED_UP * 24);
        assert_eq!(strikes.give_up(now, rest), None);
        strikes.using(gateway);
        strikes.ended(SOON);
        strikes.using(gateway);
        strikes.ended(TUNNEL_STAYED_UP);
        assert_eq!(strikes.give_up(now, rest), None);
        strikes.using(gateway);
        strikes.ended(SOON);
        assert_eq!(strikes.give_up(now, rest), None);
        strikes.using(gateway);
        strikes.ended(SOON);
        assert_eq!(strikes.give_up(now, rest), Some(gateway));
    }

    type Reached = tokio::task::JoinHandle<(Option<String>, String)>;

    async fn h2_masque_server() -> (SocketAddr, Reached) {
        let (address, listener, acceptor) = crate::https::test_server(b"\x02h2").await;
        let reached = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("a connection");
            let tls = tokio_boring::accept(&acceptor, tcp)
                .await
                .expect("a handshake");
            let name = tls
                .ssl()
                .servername(boring::ssl::NameType::HOST_NAME)
                .map(str::to_string);
            let mut connection = h2::server::handshake(tls).await.expect("h2");
            let (request, _answer) = connection
                .accept()
                .await
                .expect("a request")
                .expect("a whole request");
            let authority = request.uri().authority().expect("an authority").to_string();
            (name, authority)
        });
        (address, reached)
    }

    async fn h3_masque_server() -> (SocketAddr, Reached) {
        use quiche::h3::NameValue;

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let address = socket.local_addr().expect("its address");
        let reached = tokio::spawn(async move {
            let pair = account::generate_masque_keypair().expect("a key and a certificate");
            let mut tls =
                boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).expect("tls");
            tls.set_certificate(
                &boring::x509::X509::from_pem(&pair.cert_pem).expect("a certificate"),
            )
            .expect("the certificate");
            tls.set_private_key(
                &boring::pkey::PKey::private_key_from_pem(&pair.key_pem).expect("a key"),
            )
            .expect("the key");
            let mut config =
                quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls)
                    .expect("a configuration");
            config
                .set_application_protos(&[consts::ALPN_H3])
                .expect("h3");
            config.set_initial_max_data(1 << 20);
            config.set_initial_max_stream_data_bidi_remote(1 << 20);
            config.set_initial_max_stream_data_uni(1 << 20);
            config.set_initial_max_streams_bidi(8);
            config.set_initial_max_streams_uni(8);
            config.enable_dgram(true, 64, 64);
            let mut h3_config = quiche::h3::Config::new().expect("h3");
            h3_config.enable_extended_connect(true);

            let mut conn: Option<quiche::Connection> = None;
            let mut h3: Option<quiche::h3::Connection> = None;
            let mut packet = vec![0u8; 65535];
            let mut out = vec![0u8; 1500];
            loop {
                let (read, from) = socket.recv_from(&mut packet).await.expect("a packet");
                if conn.is_none() {
                    if read <= 5 || packet[0] & 0xf0 != 0xc0 || packet[1..5] != [0, 0, 0, 1] {
                        continue;
                    }
                    let scid = [7u8; 16];
                    let scid = quiche::ConnectionId::from_ref(&scid);
                    conn = Some(
                        quiche::accept(&scid, None, address, from, &mut config)
                            .expect("a connection"),
                    );
                }
                let conn = conn.as_mut().expect("the connection");
                let _ = conn.recv(&mut packet[..read], quiche::RecvInfo { from, to: address });
                if conn.is_established() && h3.is_none() {
                    h3 =
                        Some(quiche::h3::Connection::with_transport(conn, &h3_config).expect("h3"));
                }
                if let Some(h3) = h3.as_mut() {
                    while let Ok((_, event)) = h3.poll(conn) {
                        if let quiche::h3::Event::Headers { list, .. } = event {
                            let authority = list
                                .iter()
                                .find(|header| header.name() == b":authority")
                                .map(|header| String::from_utf8_lossy(header.value()).into_owned())
                                .expect("an authority");
                            return (conn.server_name().map(str::to_string), authority);
                        }
                    }
                }
                while let Ok((written, sent)) = conn.send(&mut out) {
                    socket
                        .send_to(&out[..written], sent.to)
                        .await
                        .expect("a packet sent");
                }
            }
        });
        (address, reached)
    }

    #[tokio::test]
    async fn the_masque_handshakes_send_the_masque_sni_and_keep_the_authority() {
        let _setting = upstream::hold_setting().await;
        let _options = tls::hold_options().await;
        let identity = account::handshake_identity();
        let startup = std::time::Duration::from_secs(10);

        for (option, sni) in [
            (None, "www.cloudflare.com"),
            (Some(consts::CONNECT_SNI), consts::CONNECT_SNI),
        ] {
            match option {
                Some(name) => crate::settings::set("AETHER_MASQUE_SNI", name),
                None => crate::settings::remove("AETHER_MASQUE_SNI"),
            }
            for h2 in [false, true] {
                if h2 {
                    crate::settings::set("AETHER_MASQUE_HTTP2", "1");
                } else {
                    crate::settings::remove("AETHER_MASQUE_HTTP2");
                }
                for tunnel in [false, true] {
                    let case = format!("--masque-sni {option:?}, h2 {h2}, tunnel {tunnel}");
                    let (address, reached) = if h2 {
                        h2_masque_server().await
                    } else {
                        h3_masque_server().await
                    };
                    let client = async {
                        if tunnel {
                            let mtu = if h2 { H2_TUNNEL_MTU } else { TUNNEL_MTU };
                            let datagram = quic::MAX_DATAGRAM_SIZE;
                            let hop = establish_masque(
                                &identity,
                                Hop {
                                    peer: address,
                                    ech: None,
                                    noize: noize_config(),
                                    h2,
                                    mtu,
                                    datagram,
                                    version_bait: false,
                                    startup,
                                    label: "test",
                                },
                            );
                            let _ = hop.await;
                        } else {
                            quick_verify_masque_peer(&identity, address, None, noize_config())
                                .await;
                        }
                    };
                    let (name, authority) = tokio::select! {
                        biased;
                        reached = reached => reached.expect("the server"),
                        () = client => panic!("{case}: the request did not reach the server"),
                    };
                    assert_eq!(name.as_deref(), Some(sni), "{case}");
                    let host = if h2 {
                        "cloudflareaccess.com:443"
                    } else {
                        "cloudflareaccess.com"
                    };
                    assert_eq!(authority, host, "{case}");
                }
            }
        }
    }

    async fn h3_hello_server() -> (
        SocketAddr,
        tokio::task::JoinHandle<tls::client_hello::ClientHello>,
    ) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let address = socket.local_addr().expect("its address");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(
            None::<tls::client_hello::ClientHello>,
        ));
        let caught = seen.clone();
        let hello = tokio::spawn(async move {
            let pair = account::generate_masque_keypair().expect("a key and a certificate");
            let mut tls =
                boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).expect("tls");
            tls.set_certificate(
                &boring::x509::X509::from_pem(&pair.cert_pem).expect("a certificate"),
            )
            .expect("the certificate");
            tls.set_private_key(
                &boring::pkey::PKey::private_key_from_pem(&pair.key_pem).expect("a key"),
            )
            .expect("the key");
            tls.set_select_certificate_callback(move |hello| {
                *caught.lock().expect("the ClientHello") =
                    Some(tls::client_hello::parse_body(hello.as_bytes()));
                Ok(())
            });
            let mut config =
                quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls)
                    .expect("a configuration");
            config
                .set_application_protos(&[consts::ALPN_H3])
                .expect("h3");

            let mut conn: Option<quiche::Connection> = None;
            let mut packet = vec![0u8; 65535];
            let mut out = vec![0u8; 1500];
            loop {
                let (read, from) = socket.recv_from(&mut packet).await.expect("a packet");
                if conn.is_none() {
                    if read <= 5 || packet[0] & 0xf0 != 0xc0 || packet[1..5] != [0, 0, 0, 1] {
                        continue;
                    }
                    let scid = [7u8; 16];
                    let scid = quiche::ConnectionId::from_ref(&scid);
                    conn = Some(
                        quiche::accept(&scid, None, address, from, &mut config)
                            .expect("a connection"),
                    );
                }
                let conn = conn.as_mut().expect("the connection");
                let _ = conn.recv(&mut packet[..read], quiche::RecvInfo { from, to: address });
                if let Some(seen) = seen.lock().expect("the ClientHello").take() {
                    return seen;
                }
                while let Ok((written, sent)) = conn.send(&mut out) {
                    socket
                        .send_to(&out[..written], sent.to)
                        .await
                        .expect("a packet sent");
                }
            }
        });
        (address, hello)
    }

    async fn masque_client(
        identity: &account::Identity,
        address: SocketAddr,
        h2: bool,
        tunnel: bool,
    ) {
        if tunnel {
            let mtu = if h2 { H2_TUNNEL_MTU } else { TUNNEL_MTU };
            let datagram = quic::MAX_DATAGRAM_SIZE;
            let startup = std::time::Duration::from_secs(10);
            let hop = establish_masque(
                identity,
                Hop {
                    peer: address,
                    ech: None,
                    noize: noize_config(),
                    h2,
                    mtu,
                    datagram,
                    version_bait: false,
                    startup,
                    label: "test",
                },
            );
            let _ = hop.await;
        } else {
            quick_verify_masque_peer(identity, address, None, noize_config()).await;
        }
    }

    #[tokio::test]
    async fn the_masque_handshakes_take_the_tls13_order_and_the_key_shares_of_the_options() {
        let _setting = upstream::hold_setting().await;
        let _options = tls::hold_options().await;
        crate::settings::set(
            "AETHER_TLS13_CIPHERS",
            "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        );
        crate::settings::set(
            "AETHER_TLS_GROUPS",
            "X25519MLKEM768:X25519:P-256:P-384:P-521",
        );
        crate::settings::set("AETHER_TLS_KEY_SHARES", "X25519MLKEM768:X25519:P-256");
        let identity = account::handshake_identity();
        for h2 in [false, true] {
            for tunnel in [false, true] {
                let case = format!("h2 {h2}, tunnel {tunnel}");
                let hello = masque_hello(&identity, h2, tunnel, &case).await;
                assert_eq!(hello.key_shares(), [0x11ec, 0x001d, 0x0017], "{case}");
                assert_eq!(hello.tls13_suites(), [0x1301, 0x1303, 0x1302], "{case}");
            }
        }
    }

    async fn masque_hello(
        identity: &account::Identity,
        h2: bool,
        tunnel: bool,
        case: &str,
    ) -> tls::client_hello::ClientHello {
        if h2 {
            crate::settings::set("AETHER_MASQUE_HTTP2", "1");
        } else {
            crate::settings::remove("AETHER_MASQUE_HTTP2");
        }
        let (address, hello) = if h2 {
            tls::client_hello::catch().await
        } else {
            h3_hello_server().await
        };
        tokio::select! {
            biased;
            hello = hello => hello.expect("the ClientHello"),
            () = masque_client(identity, address, h2, tunnel) => {
                panic!("{case}: no ClientHello reached the server")
            }
        }
    }

    #[tokio::test]
    async fn the_masque_handshakes_carry_the_extensions_of_the_options() {
        let _setting = upstream::hold_setting().await;
        let _options = tls::hold_options().await;
        crate::settings::set("AETHER_ENABLE_GREASE_SIGALGS", "1");
        crate::settings::set(
            "AETHER_TLS_SIGALGS",
            "mldsa44:mldsa65:mldsa87:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256",
        );
        crate::settings::set("AETHER_TLS_CERT_COMPRESSION", "brotli");
        crate::settings::set("AETHER_TLS_ALPS", "new");
        crate::settings::set("AETHER_TLS_TRUST_ANCHORS", "11129.9.1");
        crate::settings::set("AETHER_TLS_SERVER_PADDING", "6000");
        crate::settings::set("AETHER_ENABLE_ECH_GREASE", "1");
        let identity = account::handshake_identity();
        for h2 in [false, true] {
            for tunnel in [false, true] {
                let case = format!("h2 {h2}, tunnel {tunnel}");
                let hello = masque_hello(&identity, h2, tunnel, &case).await;
                assert!(hello.has_grease_signature_algorithm(), "{case}");
                assert_eq!(
                    hello.signature_algorithms()[1..],
                    [0x0904, 0x0905, 0x0906, 0x0403, 0x0804],
                    "{case}"
                );
                assert_eq!(hello.cert_compression(), [2], "{case}");
                let protocol = if h2 { b"h2".to_vec() } else { b"h3".to_vec() };
                assert_eq!(hello.alps(0x44cd), Some(vec![protocol]), "{case}");
                assert!(hello.offers_ech(), "{case}");
                assert_eq!(
                    hello.extension(0xca34),
                    Some(&[0, 5, 4, 0xd6, 0x79, 0x09, 0x01][..]),
                    "{case}"
                );
                assert_eq!(hello.server_padding(), Some(6000), "{case}");
            }
        }

        for variable in [
            "AETHER_ENABLE_GREASE_SIGALGS",
            "AETHER_TLS_SIGALGS",
            "AETHER_TLS_CERT_COMPRESSION",
            "AETHER_TLS_ALPS",
            "AETHER_TLS_TRUST_ANCHORS",
            "AETHER_TLS_SERVER_PADDING",
            "AETHER_ENABLE_ECH_GREASE",
        ] {
            crate::settings::remove(variable);
        }
        crate::settings::set("AETHER_DISABLE_OCSP_STAPLING", "1");
        crate::settings::set("AETHER_DISABLE_SCT", "1");
        for h2 in [false, true] {
            let case = format!("h2 {h2}");
            let hello = masque_hello(&identity, h2, false, &case).await;
            assert!(
                !hello.has_extension(5) && !hello.has_extension(18),
                "{case}"
            );
            assert!(!hello.offers_ech(), "{case}");
            assert_eq!(hello.alps(0x44cd), None, "{case}");
        }
    }
}

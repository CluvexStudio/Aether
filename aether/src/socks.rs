use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::error::{AetherError, Result};
use crate::netstack::{StackHandle, TcpSender, UdpSender};
use crate::routing::{Action, Host, RuleSet};

const VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;
const REP_OK: u8 = 0x00;
const REP_GENERAL: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_NOT_SUPPORTED: u8 = 0x07;

#[derive(Debug)]
enum Target {
    Ip(IpAddr),
    Domain(String),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Ip(ip) => write!(f, "{ip}"),
            Target::Domain(name) => write!(f, "{name}"),
        }
    }
}

static GATEWAY_PROXY: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();

pub fn set_gateway_proxy(address: &str) {
    let trimmed = address.trim();
    if trimmed.is_empty() {
        return;
    }
    match trimmed.parse::<SocketAddr>() {
        Ok(parsed) => {
            if GATEWAY_PROXY.set(parsed).is_ok() {
                log::info!(
                    "[+] gateway filtering active: http and https will traverse {parsed} inside the tunnel"
                );
            }
        }
        Err(_) => log::warn!("[-] ignoring malformed gateway proxy address {trimmed}"),
    }
}

static ROUTES: std::sync::OnceLock<RuleSet> = std::sync::OnceLock::new();

fn routes() -> &'static RuleSet {
    ROUTES.get_or_init(RuleSet::from_env)
}

fn host_of(target: &Target) -> Host<'_> {
    match target {
        Target::Domain(name) => Host::Domain(name.as_str()),
        Target::Ip(ip) => Host::Ip(*ip),
    }
}

static GATEWAY_HEALTHY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

fn gateway_proxy() -> Option<SocketAddr> {
    if !GATEWAY_HEALTHY.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    GATEWAY_PROXY.get().copied()
}

fn retire_gateway(reason: &str) {
    if GATEWAY_HEALTHY.swap(false, std::sync::atomic::Ordering::Relaxed) {
        log::warn!(
            "[-] the gateway proxy is not reachable ({reason}); sending traffic straight through \
             the tunnel instead. organization http filtering will not apply"
        );
    }
}

pub(crate) fn should_use_gateway(port: u16) -> bool {
    matches!(port, 80 | 443)
}

pub(crate) fn build_proxy_connect(target: &str, port: u16) -> Vec<u8> {
    let authority = if target.contains(':') && !target.starts_with('[') {
        format!("[{target}]:{port}")
    } else {
        format!("{target}:{port}")
    };

    format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {}\r\n\r\n",
        crate::consts::UA_REGISTER
    )
    .into_bytes()
}

pub(crate) fn proxy_connect_succeeded(head: &[u8]) -> Option<bool> {
    let text = String::from_utf8_lossy(head);
    let line_end = text.find("\r\n")?;
    let status = text[..line_end]
        .split_whitespace()
        .nth(1)?
        .parse::<u16>()
        .ok()?;
    Some((200..300).contains(&status))
}

pub async fn serve(listen: SocketAddr, stack: StackHandle) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    log::info!("socks5 listening on {listen}");
    let bind_ip = listen.ip();

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                if let Some(delay) = accept_backoff(&error) {
                    log::warn!(
                        "socks5 accept failed: {error}; the listener stays open and retries"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                log::error!("socks5 listener cannot continue: {error}");
                return Err(error.into());
            }
        };

        let stack = stack.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(sock, stack, bind_ip).await {
                log::debug!("socks client {peer} ended: {e}");
            }
        });
    }
}

pub fn accept_backoff(error: &std::io::Error) -> Option<std::time::Duration> {
    use std::io::ErrorKind;
    use std::time::Duration;

    if matches!(
        error.kind(),
        ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionRefused
            | ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::TimedOut
            | ErrorKind::PermissionDenied
    ) {
        return Some(Duration::ZERO);
    }

    match error.raw_os_error() {
        Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOBUFS)
        | Some(libc::ENOMEM) => Some(Duration::from_millis(100)),
        _ => None,
    }
}

async fn handle_client(mut sock: TcpStream, stack: StackHandle, bind_ip: IpAddr) -> Result<()> {
    handshake(&mut sock).await?;

    let mut head = [0u8; 4];
    sock.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(AetherError::Other("bad socks version".into()));
    }

    let cmd = head[1];
    let atyp = head[3];
    let (target, port) = read_target(&mut sock, atyp).await?;

    match cmd {
        CMD_CONNECT => handle_connect(sock, stack, target, port).await,
        CMD_UDP_ASSOCIATE => {
            handle_udp_associate(sock, stack, bind_ip, target, port).await
        }
        _ => {
            reply(&mut sock, REP_NOT_SUPPORTED).await?;
            Err(AetherError::Other("unsupported socks command".into()))
        }
    }
}

async fn handshake(sock: &mut TcpStream) -> Result<()> {
    let mut prefix = [0u8; 2];
    sock.read_exact(&mut prefix).await?;
    if prefix[0] != VER {
        return Err(AetherError::Other("bad greeting version".into()));
    }
    let nmethods = prefix[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;
    sock.write_all(&[VER, 0x00]).await?;
    Ok(())
}

async fn read_target(sock: &mut TcpStream, atyp: u8) -> Result<(Target, u16)> {
    let target = match atyp {
        ATYP_V4 => {
            let mut b = [0u8; 4];
            sock.read_exact(&mut b).await?;
            Target::Ip(IpAddr::V4(Ipv4Addr::from(b)))
        }
        ATYP_V6 => {
            let mut b = [0u8; 16];
            sock.read_exact(&mut b).await?;
            Target::Ip(IpAddr::V6(b.into()))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name).await?;
            Target::Domain(String::from_utf8_lossy(&name).to_string())
        }
        _ => return Err(AetherError::Other("bad atyp".into())),
    };

    let mut port = [0u8; 2];
    sock.read_exact(&mut port).await?;
    Ok((target, u16::from_be_bytes(port)))
}

async fn reply(sock: &mut TcpStream, code: u8) -> Result<()> {
    sock.write_all(&[VER, code, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn reply_bound(sock: &mut TcpStream, bound: SocketAddr) -> Result<()> {
    let mut buf = vec![VER, REP_OK, 0x00];
    match bound.ip() {
        IpAddr::V4(v4) => {
            buf.push(ATYP_V4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(ATYP_V6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&bound.port().to_be_bytes());
    sock.write_all(&buf).await?;
    Ok(())
}

async fn resolve(stack: &StackHandle, target: Target) -> Result<IpAddr> {
    match target {
        Target::Ip(ip) => Ok(ip),
        Target::Domain(name) => {
            if let Ok(ip) = name.parse::<IpAddr>() {
                return Ok(ip);
            }
            dns_resolve(stack, &name).await
        }
    }
}

pub(crate) async fn dns_resolve(stack: &StackHandle, name: &str) -> Result<IpAddr> {
    let udp = stack.open_udp().await?;
    let (sender, mut from_stack) = udp.into_split();
    let outcome = dns_exchange(&sender, &mut from_stack, name).await;
    sender.close().await;
    outcome
}

pub(crate) fn resolver_addresses() -> Vec<SocketAddr> {
    let configured = std::env::var("AETHER_DNS").unwrap_or_default();
    let mut servers: Vec<SocketAddr> = Vec::new();

    for token in configured.split([',', ' ', ';']) {
        let entry = token.trim();
        if entry.is_empty() {
            continue;
        }
        let parsed = entry.parse::<SocketAddr>().ok().or_else(|| {
            entry
                .parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, 53))
        });
        if let Some(server) = parsed {
            if !servers.contains(&server) {
                servers.push(server);
            }
        }
    }

    if servers.is_empty() {
        servers.push("1.1.1.1:53".parse().unwrap());
        servers.push("1.0.0.1:53".parse().unwrap());
    }
    servers
}

async fn dns_exchange(
    sender: &UdpSender,
    from_stack: &mut mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    name: &str,
) -> Result<IpAddr> {
    let mut last = AetherError::Other("dns timeout".into());

    for server in resolver_addresses() {
        let (query, id) = build_dns_query(name, QTYPE_A);
        if let Err(error) = sender.send_to(server, query).await {
            last = error;
            continue;
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

        loop {
            let resp = match tokio::time::timeout_at(deadline, from_stack.recv()).await {
                Ok(Some(resp)) => resp,
                Ok(None) => return Err(AetherError::Other("dns channel closed".into())),
                Err(_) => {
                    last = AetherError::Other(format!("dns timeout from {server}"));
                    break;
                }
            };

            if !dns_response_matches(&resp.1, id, name, QTYPE_A) {
                continue;
            }
            if let Some(ip) = parse_dns_a(&resp.1) {
                return Ok(ip);
            }
            return Err(AetherError::Other(format!("no A record for {name}")));
        }
    }

    Err(last)
}

const QTYPE_A: u16 = 1;

fn build_dns_query(name: &str, qtype: u16) -> (Vec<u8>, u16) {
    let mut q = Vec::with_capacity(32 + name.len());
    let id: u16 = rand::random();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0x00, 0x01]);
    (q, id)
}

pub(crate) fn dns_response_matches(
    resp: &[u8],
    expected_id: u16,
    expected_name: &str,
    expected_qtype: u16,
) -> bool {
    if resp.len() < 12 {
        return false;
    }
    if u16::from_be_bytes([resp[0], resp[1]]) != expected_id {
        return false;
    }
    if resp[2] & 0x80 == 0 {
        return false;
    }
    if u16::from_be_bytes([resp[4], resp[5]]) != 1 {
        return false;
    }

    let mut pos = 12;
    for label in expected_name.split('.') {
        if label.is_empty() {
            continue;
        }
        let len = match resp.get(pos) {
            Some(value) => *value as usize,
            None => return false,
        };
        if len != label.len() {
            return false;
        }
        pos += 1;
        let end = match pos.checked_add(len) {
            Some(value) if value <= resp.len() => value,
            _ => return false,
        };
        if !resp[pos..end].eq_ignore_ascii_case(label.as_bytes()) {
            return false;
        }
        pos = end;
    }

    if resp.get(pos) != Some(&0) {
        return false;
    }
    pos += 1;

    if pos + 4 > resp.len() {
        return false;
    }
    u16::from_be_bytes([resp[pos], resp[pos + 1]]) == expected_qtype
}

fn parse_dns_a(resp: &[u8]) -> Option<IpAddr> {
    if resp.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let an = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let mut pos = 12;

    for _ in 0..qd {
        pos = skip_name(resp, pos)?;
        pos = pos.checked_add(4)?;
    }

    for _ in 0..an {
        pos = skip_name(resp, pos)?;
        if pos + 10 > resp.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > resp.len() {
            return None;
        }
        if rtype == 1 && rdlen == 4 {
            return Some(IpAddr::V4(Ipv4Addr::new(
                resp[pos],
                resp[pos + 1],
                resp[pos + 2],
                resp[pos + 3],
            )));
        }
        pos += rdlen;
    }
    None
}

fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)?;
        if len & 0xc0 == 0xc0 {
            return Some(pos + 2);
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos += 1 + len as usize;
    }
}

async fn handle_connect(
    mut sock: TcpStream,
    stack: StackHandle,
    target: Target,
    port: u16,
) -> Result<()> {
    match routes().decide(host_of(&target), port) {
        Action::Block => {
            log::debug!("[route] block tcp {target}:{port}");
            let _ = reply(&mut sock, REP_NOT_ALLOWED).await;
            return Ok(());
        }
        Action::Direct => {
            log::debug!("[route] direct tcp {target}:{port}");
            return handle_direct(sock, target, port).await;
        }
        Action::Proxy => {}
    }

    let via_gateway = gateway_proxy().filter(|_| should_use_gateway(port));

    let conn = match via_gateway {
        Some(proxy) => {
            let authority = match &target {
                Target::Domain(name) => name.clone(),
                Target::Ip(ip) => ip.to_string(),
            };
            match open_through_gateway(&stack, proxy, &authority, port).await {
                Ok(conn) => conn,
                Err(e) => {
                    retire_gateway(&e.to_string());
                    let ip = match resolve(&stack, target).await {
                        Ok(ip) => ip,
                        Err(e) => {
                            let _ = reply(&mut sock, REP_GENERAL).await;
                            return Err(e);
                        }
                    };
                    let dst = SocketAddr::new(ip, port);
                    match stack.open_tcp(dst).await {
                        Ok(c) => {
                            let (sender, from_stack) = c.into_split();
                            (sender, from_stack, Vec::new())
                        }
                        Err(e) => {
                            let _ = reply(&mut sock, REP_GENERAL).await;
                            return Err(e);
                        }
                    }
                }
            }
        }
        None => {
            let ip = match resolve(&stack, target).await {
                Ok(ip) => ip,
                Err(e) => {
                    let _ = reply(&mut sock, REP_GENERAL).await;
                    return Err(e);
                }
            };

            let dst = SocketAddr::new(ip, port);
            match stack.open_tcp(dst).await {
                Ok(c) => {
                    let (sender, from_stack) = c.into_split();
                    (sender, from_stack, Vec::new())
                }
                Err(e) => {
                    let _ = reply(&mut sock, REP_GENERAL).await;
                    return Err(e);
                }
            }
        }
    };

    reply_bound(&mut sock, "0.0.0.0:0".parse().unwrap()).await?;

    let (sender, mut from_stack, leftover) = conn;
    let (mut rd, mut wr) = sock.into_split();

    if !leftover.is_empty() && wr.write_all(&leftover).await.is_err() {
        return Ok(());
    }

    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => {
                    sender.close().await;
                    break;
                }
                Ok(n) => {
                    if sender.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => {
                    sender.close().await;
                    break;
                }
            }
        }
    });

    while let Some(chunk) = from_stack.recv().await {
        if wr.write_all(&chunk).await.is_err() {
            break;
        }
    }

    let _ = wr.shutdown().await;
    up.abort();
    Ok(())
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

fn expected_udp_source(control_peer: SocketAddr, requested: &Target) -> IpAddr {
    match requested {
        Target::Ip(ip) if !ip.is_unspecified() => normalize_ip(*ip),
        _ => normalize_ip(control_peer.ip()),
    }
}

fn udp_source_allowed(
    expected_ip: IpAddr,
    latched: Option<SocketAddr>,
    from: SocketAddr,
) -> bool {
    match latched {
        Some(known) => known == from,
        None => normalize_ip(from.ip()) == normalize_ip(expected_ip),
    }
}

async fn handle_direct(mut sock: TcpStream, target: Target, port: u16) -> Result<()> {
    let address = match &target {
        Target::Domain(name) => format!("{name}:{port}"),
        Target::Ip(ip) => SocketAddr::new(*ip, port).to_string(),
    };

    let upstream = match tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(&address),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            log::debug!("[route] direct connect to {address} failed: {error}");
            let _ = reply(&mut sock, REP_GENERAL).await;
            return Ok(());
        }
        Err(_) => {
            log::debug!("[route] direct connect to {address} timed out");
            let _ = reply(&mut sock, REP_GENERAL).await;
            return Ok(());
        }
    };

    let _ = upstream.set_nodelay(true);
    reply_bound(&mut sock, "0.0.0.0:0".parse().unwrap()).await?;

    let (mut client_rd, mut client_wr) = sock.into_split();
    let (mut remote_rd, mut remote_wr) = upstream.into_split();

    let up = tokio::spawn(async move { tokio::io::copy(&mut client_rd, &mut remote_wr).await });
    let _ = tokio::io::copy(&mut remote_rd, &mut client_wr).await;
    let _ = client_wr.shutdown().await;
    up.abort();
    Ok(())
}

const GATEWAY_HEAD_LIMIT: usize = 8192;
const GATEWAY_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

type GatewayChannel = (TcpSender, mpsc::Receiver<Vec<u8>>, Vec<u8>);

pub(crate) fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

async fn open_through_gateway(
    stack: &StackHandle,
    proxy: SocketAddr,
    authority: &str,
    port: u16,
) -> Result<GatewayChannel> {
    let conn = tokio::time::timeout(GATEWAY_PROBE_TIMEOUT, stack.open_tcp(proxy))
        .await
        .map_err(|_| AetherError::Other(format!("gateway {proxy} did not accept a connection")))??;
    let (sender, mut from_stack) = conn.into_split();

    sender.send(build_proxy_connect(authority, port)).await?;

    let mut head: Vec<u8> = Vec::new();
    loop {
        let chunk = tokio::time::timeout(GATEWAY_PROBE_TIMEOUT, from_stack.recv())
            .await
            .map_err(|_| AetherError::Other(format!("gateway {proxy} did not answer in time")))?
            .ok_or_else(|| AetherError::Other(format!("gateway {proxy} closed the connection")))?;

        head.extend_from_slice(&chunk);

        if let Some(at) = find_head_end(&head) {
            let accepted = proxy_connect_succeeded(&head).ok_or_else(|| {
                AetherError::Other(format!("gateway {proxy} sent a malformed response"))
            })?;

            if !accepted {
                let status = String::from_utf8_lossy(&head[..at])
                    .lines()
                    .next()
                    .unwrap_or("no status")
                    .trim()
                    .to_string();
                sender.close().await;
                return Err(AetherError::Other(format!(
                    "gateway refused {authority}:{port} ({status})"
                )));
            }

            return Ok((sender, from_stack, head[at..].to_vec()));
        }

        if head.len() > GATEWAY_HEAD_LIMIT {
            sender.close().await;
            return Err(AetherError::Other(format!(
                "gateway {proxy} sent an oversized response head"
            )));
        }
    }
}


async fn handle_udp_associate(
    mut sock: TcpStream,
    stack: StackHandle,
    bind_ip: IpAddr,
    requested: Target,
    _requested_port: u16,
) -> Result<()> {
    let control_peer = sock.peer_addr()?;
    let expected_ip = expected_udp_source(control_peer, &requested);

    let relay = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    let relay_addr = relay.local_addr()?;
    reply_bound(&mut sock, relay_addr).await?;

    let udp = stack.open_udp().await?;
    let (sender, mut from_stack) = udp.into_split();

    let direct_relay = UdpSocket::bind("0.0.0.0:0").await?;

    let mut client: Option<SocketAddr> = None;
    let mut refused: u64 = 0;
    let mut cbuf = vec![0u8; 65535];
    let mut dbuf = vec![0u8; 65535];
    let mut ctrl = [0u8; 256];

    loop {
        tokio::select! {
            r = relay.recv_from(&mut cbuf) => {
                let (n, from) = match r { Ok(v) => v, Err(_) => break };
                if !udp_source_allowed(expected_ip, client, from) {
                    refused += 1;
                    if refused == 1 || refused % 64 == 0 {
                        log::warn!(
                            "[-] udp relay {relay_addr} dropped a datagram from {from}; \
                             this association only serves {expected_ip} (refused={refused})"
                        );
                    }
                    continue;
                }
                if client.is_none() {
                    log::debug!("udp relay {relay_addr} latched to client {from}");
                    client = Some(from);
                }
                if let Some((dst, payload)) = parse_udp_request(&cbuf[..n]) {
                    let dst_port = payload.0;

                    match routes().decide(host_of(&dst), dst_port) {
                        Action::Block => {
                            log::debug!("[route] block udp {dst}:{dst_port}");
                            continue;
                        }
                        Action::Direct => {
                            let outside = match &dst {
                                Target::Ip(ip) => Some(SocketAddr::new(*ip, dst_port)),
                                Target::Domain(name) => {
                                    tokio::net::lookup_host((name.as_str(), dst_port))
                                        .await
                                        .ok()
                                        .and_then(|mut found| found.next())
                                }
                            };
                            match outside {
                                Some(addr) => {
                                    log::trace!("[route] direct udp {dst}:{dst_port}");
                                    let _ = direct_relay.send_to(&payload.1, addr).await;
                                }
                                None => log::debug!("[route] direct udp {dst} did not resolve"),
                            }
                            continue;
                        }
                        Action::Proxy => {}
                    }

                    let dst = match dst {
                        Target::Ip(ip) => SocketAddr::new(ip, dst_port),
                        Target::Domain(name) => {
                            match dns_resolve(&stack, &name).await {
                                Ok(ip) => SocketAddr::new(ip, dst_port),
                                Err(_) => continue,
                            }
                        }
                    };
                    let _ = sender.send_to(dst, payload.1).await;
                }
            }

            maybe = from_stack.recv() => {
                let (src, data) = match maybe { Some(v) => v, None => break };
                if let Some(c) = client {
                    let pkt = build_udp_reply(src, &data);
                    let _ = relay.send_to(&pkt, c).await;
                }
            }

            r = direct_relay.recv_from(&mut dbuf) => {
                let (n, from) = match r { Ok(v) => v, Err(_) => continue };
                if let Some(c) = client {
                    let pkt = build_udp_reply(from, &dbuf[..n]);
                    let _ = relay.send_to(&pkt, c).await;
                }
            }

            r = sock.read(&mut ctrl) => {
                match r { Ok(0) | Err(_) => break, Ok(_) => {} }
            }
        }
    }

    sender.close().await;
    Ok(())
}

fn parse_udp_request(buf: &[u8]) -> Option<(Target, (u16, Vec<u8>))> {
    if buf.len() < 4 || buf[2] != 0 {
        return None;
    }
    let atyp = buf[3];
    let mut pos = 4;
    let target = match atyp {
        ATYP_V4 => {
            if buf.len() < pos + 4 {
                return None;
            }
            let ip = Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]);
            pos += 4;
            Target::Ip(IpAddr::V4(ip))
        }
        ATYP_V6 => {
            if buf.len() < pos + 16 {
                return None;
            }
            let mut b = [0u8; 16];
            b.copy_from_slice(&buf[pos..pos + 16]);
            pos += 16;
            Target::Ip(IpAddr::V6(b.into()))
        }
        ATYP_DOMAIN => {
            let len = *buf.get(pos)? as usize;
            pos += 1;
            if buf.len() < pos + len {
                return None;
            }
            let name = String::from_utf8_lossy(&buf[pos..pos + len]).to_string();
            pos += len;
            Target::Domain(name)
        }
        _ => return None,
    };

    if buf.len() < pos + 2 {
        return None;
    }
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    Some((target, (port, buf[pos..].to_vec())))
}

fn build_udp_reply(src: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0x00, 0x00, 0x00];
    match src.ip() {
        IpAddr::V4(v4) => {
            pkt.push(ATYP_V4);
            pkt.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            pkt.push(ATYP_V6);
            pkt.extend_from_slice(&v6.octets());
        }
    }
    pkt.extend_from_slice(&src.port().to_be_bytes());
    pkt.extend_from_slice(data);
    pkt
}

#[cfg(test)]
mod accept_tests {
    use super::accept_backoff;
    use std::io::{Error, ErrorKind};

    #[test]
    fn a_dropped_client_never_takes_the_listener_down() {
        for kind in [
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionRefused,
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
            ErrorKind::TimedOut,
            ErrorKind::PermissionDenied,
        ] {
            assert!(
                accept_backoff(&Error::from(kind)).is_some(),
                "{kind:?} should keep the listener alive"
            );
        }
    }

    #[test]
    fn running_out_of_descriptors_backs_off_instead_of_spinning() {
        for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            let delay = accept_backoff(&Error::from_raw_os_error(code))
                .expect("resource exhaustion should be survivable");
            assert!(
                !delay.is_zero(),
                "os error {code} should pause before retrying"
            );
        }
    }

    #[test]
    fn a_broken_listener_is_still_fatal() {
        for kind in [ErrorKind::InvalidInput, ErrorKind::AddrNotAvailable] {
            assert!(
                accept_backoff(&Error::from(kind)).is_none(),
                "{kind:?} should stop the listener"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_resolvers(raw: &str) -> Vec<SocketAddr> {
        let mut servers: Vec<SocketAddr> = Vec::new();
        for token in raw.split([',', ' ', ';']) {
            let entry = token.trim();
            if entry.is_empty() {
                continue;
            }
            let parsed = entry.parse::<SocketAddr>().ok().or_else(|| {
                entry
                    .parse::<IpAddr>()
                    .ok()
                    .map(|ip| SocketAddr::new(ip, 53))
            });
            if let Some(server) = parsed {
                if !servers.contains(&server) {
                    servers.push(server);
                }
            }
        }
        servers
    }

    #[test]
    fn only_web_ports_are_sent_through_the_gateway() {
        assert!(should_use_gateway(80));
        assert!(should_use_gateway(443));
        assert!(!should_use_gateway(22));
        assert!(!should_use_gateway(853));
    }

    #[test]
    fn the_proxy_request_carries_the_domain_so_the_gateway_can_filter_it() {
        let wire = String::from_utf8(build_proxy_connect("example.com", 443)).expect("utf8");
        assert!(wire.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(wire.contains("Host: example.com:443\r\n"));
        assert!(wire.ends_with("\r\n\r\n"));
    }

    #[test]
    fn a_bare_ipv6_target_is_bracketed_for_the_proxy() {
        let wire = String::from_utf8(build_proxy_connect("2606:4700::1", 443)).expect("utf8");
        assert!(wire.starts_with("CONNECT [2606:4700::1]:443 HTTP/1.1\r\n"));
    }

    #[test]
    fn an_already_bracketed_target_is_left_alone() {
        let wire = String::from_utf8(build_proxy_connect("[2606:4700::1]", 443)).expect("utf8");
        assert!(wire.starts_with("CONNECT [2606:4700::1]:443 HTTP/1.1\r\n"));
    }

    #[test]
    fn the_gateway_verdict_is_read_from_the_status_line() {
        assert_eq!(
            proxy_connect_succeeded(b"HTTP/1.1 200 Connection established\r\n\r\n"),
            Some(true)
        );
        assert_eq!(
            proxy_connect_succeeded(b"HTTP/1.1 403 Forbidden\r\n\r\nblocked"),
            Some(false)
        );
        assert_eq!(
            proxy_connect_succeeded(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"),
            Some(false)
        );
        assert_eq!(proxy_connect_succeeded(b"garbage"), None);
        assert_eq!(proxy_connect_succeeded(b"HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn the_end_of_the_proxy_response_head_is_located() {
        assert_eq!(find_head_end(b"HTTP/1.1 200 OK\r\n\r\n"), Some(19));
        assert_eq!(find_head_end(b"HTTP/1.1 200 OK\r\n\r\npayload"), Some(19));
        assert_eq!(find_head_end(b"HTTP/1.1 200 OK\r\n"), None);
    }

    #[test]
    fn a_malformed_gateway_address_is_ignored_rather_than_fatal() {
        set_gateway_proxy("not an address");
        set_gateway_proxy("   ");
        assert!(gateway_proxy().is_none());
    }

    #[test]
    fn the_first_datagram_must_come_from_the_control_connection_address() {
        let expected: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(udp_source_allowed(
            expected,
            None,
            "127.0.0.1:51000".parse().unwrap()
        ));
        assert!(!udp_source_allowed(
            expected,
            None,
            "192.168.1.44:51000".parse().unwrap()
        ));
    }

    #[test]
    fn a_latched_client_cannot_be_replaced_by_another_source() {
        let expected: IpAddr = "10.0.0.5".parse().unwrap();
        let latched: Option<SocketAddr> = Some("10.0.0.5:40000".parse().unwrap());
        assert!(udp_source_allowed(
            expected,
            latched,
            "10.0.0.5:40000".parse().unwrap()
        ));
        assert!(!udp_source_allowed(
            expected,
            latched,
            "10.0.0.5:40001".parse().unwrap()
        ));
        assert!(!udp_source_allowed(
            expected,
            latched,
            "10.0.0.9:40000".parse().unwrap()
        ));
    }

    #[test]
    fn the_control_address_is_used_when_the_client_declares_a_wildcard() {
        let control: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let wildcard = Target::Ip("0.0.0.0".parse().unwrap());
        assert_eq!(
            expected_udp_source(control, &wildcard),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        let unset = Target::Domain(String::new());
        assert_eq!(
            expected_udp_source(control, &unset),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn an_explicit_client_address_in_the_request_is_honoured() {
        let control: SocketAddr = "192.168.1.10:1080".parse().unwrap();
        let declared = Target::Ip("192.168.1.77".parse().unwrap());
        assert_eq!(
            expected_udp_source(control, &declared),
            "192.168.1.77".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn a_v4_mapped_control_address_matches_a_plain_v4_datagram() {
        let control: SocketAddr = "[::ffff:127.0.0.1]:1080".parse().unwrap();
        let expected = expected_udp_source(control, &Target::Domain(String::new()));
        assert_eq!(expected, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert!(udp_source_allowed(
            expected,
            None,
            "127.0.0.1:9000".parse().unwrap()
        ));
    }

    #[test]
    fn plain_resolver_addresses_get_the_dns_port() {
        let servers = parse_resolvers("9.9.9.9, 8.8.4.4");
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].port(), 53);
        assert_eq!(servers[1].to_string(), "8.8.4.4:53");
    }

    #[test]
    fn an_explicit_resolver_port_survives() {
        let servers = parse_resolvers("127.0.0.1:5353");
        assert_eq!(servers[0].port(), 5353);
    }

    #[test]
    fn duplicate_and_malformed_resolvers_are_dropped() {
        let servers = parse_resolvers("1.1.1.1,1.1.1.1,not-an-ip,,1.0.0.1");
        assert_eq!(servers.len(), 2);
    }

    #[test]
    fn an_empty_resolver_list_falls_back_to_cloudflare() {
        assert!(parse_resolvers("   ").is_empty());
        let defaults = resolver_addresses();
        assert!(defaults.len() >= 2);
        assert_eq!(defaults[0].port(), 53);
    }

    fn reply(id: u16, name: &str, qtype: u16, qr: bool) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&id.to_be_bytes());
        msg.push(if qr { 0x81 } else { 0x01 });
        msg.push(0x80);
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&[0, 0, 0, 0]);
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg
    }

    #[test]
    fn build_dns_query_reports_the_id_it_wrote() {
        let (query, id) = build_dns_query("example.com", QTYPE_A);
        assert_eq!(u16::from_be_bytes([query[0], query[1]]), id);
    }

    #[test]
    fn accepts_the_matching_answer() {
        let msg = reply(0x4242, "example.com", QTYPE_A, true);
        assert!(dns_response_matches(&msg, 0x4242, "example.com", QTYPE_A));
    }

    #[test]
    fn rejects_an_answer_with_a_forged_transaction_id() {
        let msg = reply(0x1111, "example.com", QTYPE_A, true);
        assert!(!dns_response_matches(&msg, 0x4242, "example.com", QTYPE_A));
    }

    #[test]
    fn rejects_an_answer_for_another_domain() {
        let msg = reply(0x4242, "evil.example", QTYPE_A, true);
        assert!(!dns_response_matches(&msg, 0x4242, "example.com", QTYPE_A));
    }

    #[test]
    fn rejects_a_query_shaped_message() {
        let msg = reply(0x4242, "example.com", QTYPE_A, false);
        assert!(!dns_response_matches(&msg, 0x4242, "example.com", QTYPE_A));
    }

    #[test]
    fn rejects_truncated_input_without_panicking() {
        let msg = reply(0x4242, "example.com", QTYPE_A, true);
        for cut in 0..msg.len() {
            assert!(!dns_response_matches(
                &msg[..cut],
                0x4242,
                "example.com",
                QTYPE_A
            ));
        }
    }
}

const HTTP_HEAD_LIMIT: usize = 16 * 1024;

pub async fn serve_http(listen: SocketAddr, stack: StackHandle) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    log::info!("http proxy listening on {listen}");

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                if let Some(delay) = accept_backoff(&error) {
                    log::warn!(
                        "http proxy accept failed: {error}; the listener stays open and retries"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                log::error!("http proxy listener cannot continue: {error}");
                return Err(error.into());
            }
        };

        let stack = stack.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_http_client(sock, stack).await {
                log::debug!("http proxy client {peer} ended: {e}");
            }
        });
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct HttpRequestLine {
    pub method: String,
    pub authority: String,
    pub port: u16,
    pub rewritten: Option<String>,
}

pub fn parse_authority(raw: &str, default_port: u16) -> Option<(String, u16)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    if let Some(rest) = raw.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = match tail.strip_prefix(':') {
            Some(value) => value.parse().ok()?,
            None => default_port,
        };
        return Some((host.to_string(), port));
    }

    match raw.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            if host.is_empty() {
                return None;
            }
            Some((host.to_string(), port.parse().ok()?))
        }
        _ => Some((raw.to_string(), default_port)),
    }
}

pub fn parse_request_line(line: &str) -> Option<HttpRequestLine> {
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?;
    let version = parts.next().unwrap_or("HTTP/1.1");

    if method.eq_ignore_ascii_case("CONNECT") {
        let (authority, port) = parse_authority(target, 443)?;
        return Some(HttpRequestLine {
            method,
            authority,
            port,
            rewritten: None,
        });
    }

    let without_scheme = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("HTTP://"))?;
    let (authority_part, path) = match without_scheme.find('/') {
        Some(index) => (&without_scheme[..index], &without_scheme[index..]),
        None => (without_scheme, "/"),
    };
    let (authority, port) = parse_authority(authority_part, 80)?;

    Some(HttpRequestLine {
        method: method.clone(),
        authority,
        port,
        rewritten: Some(format!("{method} {path} {version}\r\n")),
    })
}

async fn read_head(sock: &mut TcpStream) -> Result<Vec<u8>> {
    let mut head = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];

    loop {
        let read = sock.read(&mut byte).await?;
        if read == 0 {
            return Err(AetherError::Other(
                "the http client closed before sending a request".into(),
            ));
        }
        head.push(byte[0]);

        if head.len() >= 4 && head[head.len() - 4..] == *b"\r\n\r\n" {
            return Ok(head);
        }
        if head.len() > HTTP_HEAD_LIMIT {
            return Err(AetherError::Other("http request head too large".into()));
        }
    }
}

async fn open_tunneled(
    stack: &StackHandle,
    target: Target,
    port: u16,
) -> Result<GatewayChannel> {
    let via_gateway = gateway_proxy().filter(|_| should_use_gateway(port));

    if let Some(proxy) = via_gateway {
        let authority = match &target {
            Target::Domain(name) => name.clone(),
            Target::Ip(ip) => ip.to_string(),
        };
        match open_through_gateway(stack, proxy, &authority, port).await {
            Ok(conn) => return Ok(conn),
            Err(e) => retire_gateway(&e.to_string()),
        }
    }

    let ip = resolve(stack, target).await?;
    let conn = stack.open_tcp(SocketAddr::new(ip, port)).await?;
    let (sender, from_stack) = conn.into_split();
    Ok((sender, from_stack, Vec::new()))
}

async fn handle_http_client(mut sock: TcpStream, stack: StackHandle) -> Result<()> {
    let head = read_head(&mut sock).await?;
    let text = String::from_utf8_lossy(&head).to_string();
    let first_line = text.lines().next().unwrap_or_default();

    let request = match parse_request_line(first_line) {
        Some(value) => value,
        None => {
            let _ = sock
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            return Err(AetherError::Other(format!(
                "unsupported http proxy request: {first_line}"
            )));
        }
    };

    let target = match request.authority.parse::<IpAddr>() {
        Ok(ip) => Target::Ip(ip),
        Err(_) => Target::Domain(request.authority.clone()),
    };

    let channel = match routes().decide(host_of(&target), request.port) {
        Action::Block => {
            log::debug!("[route] block http {}:{}", request.authority, request.port);
            let _ = sock
                .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
        Action::Direct => {
            log::debug!("[route] direct http {}:{}", request.authority, request.port);
            return relay_http_direct(sock, &request, &head).await;
        }
        Action::Proxy => match open_tunneled(&stack, target, request.port).await {
            Ok(channel) => channel,
            Err(error) => {
                let _ = sock
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    .await;
                return Err(error);
            }
        },
    };

    let (sender, mut from_stack, leftover) = channel;

    let preamble = match &request.rewritten {
        Some(line) => {
            let rest = text.split_once("\r\n").map(|(_, tail)| tail).unwrap_or("");
            Some(format!("{line}{rest}").into_bytes())
        }
        None => None,
    };

    if request.rewritten.is_none() {
        sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;
    }

    let (mut rd, mut wr) = sock.into_split();

    if !leftover.is_empty() && wr.write_all(&leftover).await.is_err() {
        return Ok(());
    }
    if let Some(bytes) = preamble {
        if sender.send(bytes).await.is_err() {
            return Ok(());
        }
    }

    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => {
                    sender.close().await;
                    break;
                }
                Ok(n) => {
                    if sender.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => {
                    sender.close().await;
                    break;
                }
            }
        }
    });

    while let Some(chunk) = from_stack.recv().await {
        if wr.write_all(&chunk).await.is_err() {
            break;
        }
    }

    let _ = wr.shutdown().await;
    up.abort();
    Ok(())
}

async fn relay_http_direct(
    mut sock: TcpStream,
    request: &HttpRequestLine,
    head: &[u8],
) -> Result<()> {
    let upstream = tokio::net::TcpStream::connect((
        request.authority.as_str(),
        request.port,
    ))
    .await;

    let mut upstream = match upstream {
        Ok(stream) => stream,
        Err(error) => {
            let _ = sock
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            return Err(error.into());
        }
    };

    match &request.rewritten {
        Some(line) => {
            let text = String::from_utf8_lossy(head).to_string();
            let rest = text.split_once("\r\n").map(|(_, tail)| tail).unwrap_or("");
            upstream
                .write_all(format!("{line}{rest}").as_bytes())
                .await?;
        }
        None => {
            sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
        }
    }

    let _ = tokio::io::copy_bidirectional(&mut sock, &mut upstream).await;
    Ok(())
}

#[cfg(test)]
mod http_proxy_tests {
    use super::{parse_authority, parse_request_line};

    #[test]
    fn a_connect_request_carries_the_host_and_port() {
        let parsed = parse_request_line("CONNECT ipwho.is:443 HTTP/1.1").expect("parsed");
        assert_eq!(parsed.method, "CONNECT");
        assert_eq!(parsed.authority, "ipwho.is");
        assert_eq!(parsed.port, 443);
        assert!(parsed.rewritten.is_none());
    }

    #[test]
    fn a_connect_request_without_a_port_defaults_to_https() {
        let parsed = parse_request_line("CONNECT example.com HTTP/1.1").expect("parsed");
        assert_eq!(parsed.port, 443);
    }

    #[test]
    fn an_absolute_get_is_rewritten_to_origin_form() {
        let parsed =
            parse_request_line("GET http://ip-api.com/json/?fields=query HTTP/1.1")
                .expect("parsed");
        assert_eq!(parsed.authority, "ip-api.com");
        assert_eq!(parsed.port, 80);
        assert_eq!(
            parsed.rewritten.as_deref(),
            Some("GET /json/?fields=query HTTP/1.1\r\n")
        );
    }

    #[test]
    fn an_absolute_url_without_a_path_gets_a_root_path() {
        let parsed = parse_request_line("GET http://example.com HTTP/1.1").expect("parsed");
        assert_eq!(parsed.rewritten.as_deref(), Some("GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn an_explicit_port_in_an_absolute_url_is_honoured() {
        let parsed =
            parse_request_line("GET http://example.com:8080/x HTTP/1.1").expect("parsed");
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.authority, "example.com");
    }

    #[test]
    fn ipv6_authorities_are_understood() {
        let parsed = parse_request_line("CONNECT [2606:4700::1]:443 HTTP/1.1").expect("parsed");
        assert_eq!(parsed.authority, "2606:4700::1");
        assert_eq!(parsed.port, 443);

        let bare = parse_authority("[2606:4700::1]", 443).expect("parsed");
        assert_eq!(bare, ("2606:4700::1".to_string(), 443));
    }

    #[test]
    fn origin_form_requests_are_refused_because_a_proxy_needs_the_host() {
        assert!(parse_request_line("GET /json HTTP/1.1").is_none());
    }

    #[test]
    fn https_absolute_urls_are_refused_since_clients_must_use_connect() {
        assert!(parse_request_line("GET https://example.com/ HTTP/1.1").is_none());
    }

    #[test]
    fn a_malformed_line_is_rejected() {
        assert!(parse_request_line("").is_none());
        assert!(parse_request_line("CONNECT").is_none());
    }
}

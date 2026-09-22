use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Semaphore};

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

pub(crate) fn warn_if_world_reachable(kind: &str, listen: SocketAddr) {
    if listen.ip().is_loopback() {
        return;
    }
    log::warn!(
        "[!] the {kind} listener is bound to {listen}, which is reachable from outside this machine. \
         It accepts every client without authentication, so anyone who can reach {listen} can send \
         traffic through your tunnel. Bind it to 127.0.0.1 unless you intend to share it."
    );
}

pub async fn bind_listener(kind: &str, listen: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(listen).await.map_err(|error| {
        AetherError::Other(format!(
            "the {kind} listener cannot use {listen}: {error}{}",
            bind_hint(&error)
        ))
    })
}

fn bind_hint(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::AddrInUse => {
            "; another program already listens there, so stop it or choose another port with --bind"
        }
        std::io::ErrorKind::PermissionDenied if cfg!(windows) => {
            "; Windows reserves some port ranges for Hyper-V and WSL (see `netsh interface ipv4 show \
             excludedportrange protocol=tcp`), so choose a port outside them with --bind"
        }
        std::io::ErrorKind::PermissionDenied => {
            "; ports below 1024 need extra privileges, so choose a higher one with --bind"
        }
        std::io::ErrorKind::AddrNotAvailable => {
            "; that address does not belong to this machine"
        }
        _ => "",
    }
}

pub async fn serve(listener: TcpListener, stack: StackHandle) -> Result<()> {
    let listen = listener.local_addr()?;
    log::info!("[+] socks5 server listening on {listen}");
    warn_if_world_reachable("socks5", listen);
    let bind_ip = listen.ip();

    accept_clients(listener, "socks5", client_limit(), move |sock, peer| {
        let stack = stack.clone();
        async move {
            if let Err(e) = handle_client(sock, stack, bind_ip).await {
                log::debug!("socks client {peer} ended: {e}");
            }
        }
    })
    .await
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const ACCEPT_WARN_EVERY: Duration = Duration::from_secs(10);

fn client_limit() -> usize {
    if let Some(limit) = std::env::var("AETHER_MAX_CLIENTS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&v| v > 0)
    {
        return limit;
    }

    let by_tier = match crate::sysprofile::tuning().tier {
        crate::sysprofile::Tier::Low => 512,
        crate::sysprofile::Tier::Medium => 2048,
        crate::sysprofile::Tier::High => 8192,
    };

    match crate::sysprofile::open_file_limit() {
        Some(files) => by_tier.min((files.saturating_sub(64) / 2).max(32)),
        None => by_tier,
    }
}

async fn accept_clients<F, Fut>(
    listener: TcpListener,
    kind: &'static str,
    max: usize,
    serve_one: F,
) -> Result<()>
where
    F: Fn(TcpStream, SocketAddr) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let limit = Arc::new(Semaphore::new(max));
    let mut clients = tokio::task::JoinSet::new();
    let mut last_accept_warning: Option<std::time::Instant> = None;
    let mut last_limit_warning: Option<std::time::Instant> = None;

    loop {
        if limit.available_permits() == 0 && due(&mut last_limit_warning, ACCEPT_WARN_EVERY) {
            log::warn!(
                "{kind}: {max} clients are connected, the most served at once; new ones wait \
                 until one finishes (AETHER_MAX_CLIENTS raises the limit)"
            );
        }

        tokio::select! {
            Some(_) = clients.join_next(), if !clients.is_empty() => {}
            permit = Arc::clone(&limit).acquire_owned() => {
                let permit = permit.expect("the client limit is never closed");
                let (sock, peer) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        if let Some(delay) = accept_backoff(&error) {
                            if due(&mut last_accept_warning, ACCEPT_WARN_EVERY) {
                                log::warn!(
                                    "{kind} accept failed: {error}; the listener stays open and retries"
                                );
                            }
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        log::error!("{kind} listener cannot continue: {error}");
                        return Err(error.into());
                    }
                };
                enable_keepalive(&sock);
                let client = serve_one(sock, peer);
                clients.spawn(async move {
                    client.await;
                    drop(permit);
                });
            }
        }
    }
}

fn due(last: &mut Option<std::time::Instant>, every: Duration) -> bool {
    let now = std::time::Instant::now();
    if last.is_some_and(|at| now.duration_since(at) < every) {
        return false;
    }
    *last = Some(now);
    true
}

fn enable_keepalive(sock: &TcpStream) {
    let idle = crate::netstack::tcp_keepalive();
    let probes = socket2::TcpKeepalive::new().with_time(idle);
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    let probes =
        probes.with_interval((idle / 4).clamp(Duration::from_secs(5), Duration::from_secs(30)));
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd"
    ))]
    let probes = probes.with_retries(4);

    if let Err(error) = socket2::SockRef::from(sock).set_tcp_keepalive(&probes) {
        log::debug!("could not enable keep-alive on a connection: {error}");
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
        Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOBUFS) | Some(libc::ENOMEM) => {
            Some(Duration::from_millis(100))
        }
        _ => None,
    }
}

async fn handle_client(mut sock: TcpStream, stack: StackHandle, bind_ip: IpAddr) -> Result<()> {
    let (cmd, target, port) = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_request(&mut sock))
        .await
        .map_err(|_| {
            AetherError::Other("the client did not finish the socks5 handshake in time".into())
        })??;

    match cmd {
        CMD_CONNECT => handle_connect(sock, stack, target, port).await,
        CMD_UDP_ASSOCIATE => handle_udp_associate(sock, stack, bind_ip, target, port).await,
        _ => {
            reply(&mut sock, REP_NOT_SUPPORTED).await?;
            Err(AetherError::Other("unsupported socks command".into()))
        }
    }
}

async fn read_request(sock: &mut TcpStream) -> Result<(u8, Target, u16)> {
    handshake(sock).await?;

    let mut head = [0u8; 4];
    sock.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(AetherError::Other("bad socks version".into()));
    }

    let (target, port) = read_target(sock, head[3]).await?;
    Ok((head[1], target, port))
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

fn decide_route(set: &RuleSet, target: &Target, sniffed: Option<&str>, port: u16) -> Action {
    match sniffed {
        Some(name) => match set.decide(Host::Domain(name), port) {
            Action::Proxy => set.decide(host_of(target), port),
            decided => decided,
        },
        None => set.decide(host_of(target), port),
    }
}

fn sniff_enabled() -> bool {
    !matches!(
        std::env::var("AETHER_ROUTE_SNIFF").as_deref(),
        Ok("0") | Ok("off") | Ok("false")
    )
}

fn sniff_window() -> Duration {
    let ms = std::env::var("AETHER_ROUTE_SNIFF_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(400);
    Duration::from_millis(ms)
}

async fn read_sniff_head(sock: &mut TcpStream) -> Option<Vec<u8>> {
    let mut head = vec![0u8; crate::sniff::PEEK_BUDGET];
    match tokio::time::timeout(sniff_window(), sock.read(&mut head)).await {
        Ok(Ok(0)) => None,
        Ok(Ok(read)) => {
            head.truncate(read);
            Some(head)
        }
        Ok(Err(_)) => None,
        Err(_) => Some(Vec::new()),
    }
}

async fn handle_connect(
    mut sock: TcpStream,
    stack: StackHandle,
    target: Target,
    port: u16,
) -> Result<()> {
    let mut head = Vec::new();
    let mut replied = false;
    let mut named: Option<String> = None;

    if matches!(target, Target::Ip(_)) && sniff_enabled() && routes().has_domain_rules() {
        reply_bound(&mut sock, "0.0.0.0:0".parse().unwrap()).await?;
        replied = true;

        head = match read_sniff_head(&mut sock).await {
            Some(bytes) => bytes,
            None => return Ok(()),
        };

        if head.is_empty() {
            log::trace!("[route] {target}:{port} sent nothing to read a name from");
        } else {
            named = crate::sniff::hostname(&head);
            if let Some(name) = &named {
                log::debug!("[route] {target}:{port} announced itself as {name}");
            }
        }
    }

    match decide_route(routes(), &target, named.as_deref(), port) {
        Action::Block => {
            log::debug!("[route] block tcp {target}:{port}");
            if !replied {
                let _ = reply(&mut sock, REP_NOT_ALLOWED).await;
            }
            return Ok(());
        }
        Action::Direct => {
            log::debug!("[route] direct tcp {target}:{port}");
            return handle_direct(sock, target, port, head, replied).await;
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

    if !replied {
        reply_bound(&mut sock, "0.0.0.0:0".parse().unwrap()).await?;
    }

    let (sender, from_stack, leftover) = conn;

    if !head.is_empty() && sender.send(head).await.is_err() {
        return Ok(());
    }

    if !leftover.is_empty() && sock.write_all(&leftover).await.is_err() {
        return Ok(());
    }

    relay_tunneled(sock, sender, from_stack, half_close_linger()).await;
    Ok(())
}

pub(crate) async fn serve_connector<F, Fut, S>(
    listener: TcpListener,
    kind: &'static str,
    connect: F,
) -> Result<()>
where
    F: Fn(String, u16) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = std::io::Result<S>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let listen = listener.local_addr()?;
    log::info!("[+] {kind} listening on {listen}");
    warn_if_world_reachable(kind, listen);

    accept_clients(listener, kind, client_limit(), move |sock, peer| {
        let connect = connect.clone();
        async move {
            if let Err(e) = serve_one_through(sock, connect).await {
                log::debug!("{kind} client {peer} ended: {e}");
            }
        }
    })
    .await
}

async fn serve_one_through<F, Fut, S>(mut sock: TcpStream, connect: F) -> Result<()>
where
    F: Fn(String, u16) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = std::io::Result<S>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (cmd, target, port) = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_request(&mut sock))
        .await
        .map_err(|_| {
            AetherError::Other("the client did not finish the socks5 handshake in time".into())
        })??;

    if cmd == CMD_UDP_ASSOCIATE {
        return handle_udp_over_connector(sock, connect, target).await;
    }

    if cmd != CMD_CONNECT {
        let _ = reply(&mut sock, REP_NOT_SUPPORTED).await;
        return Err(AetherError::Other(
            "only connect and udp associate are carried on this listener".into(),
        ));
    }

    let host = match &target {
        Target::Domain(name) => name.clone(),
        Target::Ip(ip) => ip.to_string(),
    };

    match connect(host.clone(), port).await {
        Ok(remote) => {
            reply_bound(&mut sock, "0.0.0.0:0".parse().unwrap()).await?;
            relay_generic(sock, remote, half_close_linger()).await;
            Ok(())
        }
        Err(error) => {
            let _ = reply(&mut sock, REP_GENERAL).await;
            Err(AetherError::Other(format!("{host}:{port}: {error}")))
        }
    }
}

const DNS_PORT: u16 = 53;
const DNS_OVER_TCP_TIMEOUT: Duration = Duration::from_secs(20);
const DNS_MAX_IN_FLIGHT: usize = 32;

async fn dns_over_stream<S>(mut stream: S, query: Vec<u8>) -> std::io::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    if query.len() > u16::MAX as usize {
        return Err(std::io::Error::other("dns query is too long to frame"));
    }

    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(&query);
    stream.write_all(&framed).await?;
    stream.flush().await?;

    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await?;
    let mut answer = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut answer).await?;
    Ok(answer)
}

async fn handle_udp_over_connector<F, Fut, S>(
    mut sock: TcpStream,
    connect: F,
    requested: Target,
) -> Result<()>
where
    F: Fn(String, u16) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = std::io::Result<S>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let control_peer = sock.peer_addr()?;
    let expected_ip = expected_udp_source(control_peer, &requested);
    let bind_ip = sock.local_addr()?.ip();

    let relay = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    let relay_addr = relay.local_addr()?;
    reply_bound(&mut sock, relay_addr).await?;

    let (answers_tx, mut answers_rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(64);
    let in_flight = Arc::new(Semaphore::new(DNS_MAX_IN_FLIGHT));

    let mut client: Option<SocketAddr> = None;
    let mut refused: u64 = 0;
    let mut dropped_udp: u64 = 0;
    let mut cbuf = vec![0u8; 65535];
    let mut ctrl = [0u8; 256];

    loop {
        tokio::select! {
            r = relay.recv_from(&mut cbuf) => {
                let (n, from) = match r { Ok(v) => v, Err(_) => break };
                if !udp_source_allowed(expected_ip, client, from) {
                    refused += 1;
                    if refused == 1 || refused.is_multiple_of(64) {
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

                let Some((dst, (dst_port, payload))) = parse_udp_request(&cbuf[..n]) else {
                    continue;
                };

                if dst_port != DNS_PORT {
                    dropped_udp += 1;
                    if dropped_udp == 1 || dropped_udp.is_multiple_of(64) {
                        log::debug!(
                            "[-] udp to {dst}:{dst_port} cannot be carried: this listener \
                             reaches the internet over tcp only (dropped={dropped_udp})"
                        );
                    }
                    continue;
                }

                let resolver = match dst {
                    Target::Ip(ip) => SocketAddr::new(ip, dst_port),
                    Target::Domain(name) => {
                        log::debug!("[-] dns resolver given as the name {name}; give an address instead");
                        continue;
                    }
                };

                let permit = match in_flight.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        log::debug!("[-] too many dns lookups are already in flight; dropping one");
                        continue;
                    }
                };

                let connect = connect.clone();
                let answers_tx = answers_tx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let exchange = async {
                        let stream = connect(resolver.ip().to_string(), resolver.port()).await?;
                        dns_over_stream(stream, payload).await
                    };
                    match tokio::time::timeout(DNS_OVER_TCP_TIMEOUT, exchange).await {
                        Ok(Ok(answer)) => {
                            let _ = answers_tx.send((resolver, answer)).await;
                        }
                        Ok(Err(e)) => log::debug!("dns over tcp to {resolver} failed: {e}"),
                        Err(_) => log::debug!("dns over tcp to {resolver} timed out"),
                    }
                });
            }

            maybe = answers_rx.recv() => {
                let Some((src, answer)) = maybe else { break };
                if let Some(c) = client {
                    let pkt = build_udp_reply(src, &answer);
                    let _ = relay.send_to(&pkt, c).await;
                }
            }

            r = sock.read(&mut ctrl) => {
                match r { Ok(0) | Err(_) => break, Ok(_) => {} }
            }
        }
    }

    Ok(())
}

pub(crate) async fn relay_generic<A, B>(client: A, remote: B, linger: Duration)
where
    A: AsyncRead + AsyncWrite + Send + Unpin,
    B: AsyncRead + AsyncWrite + Send + Unpin,
{
    let (mut client_rd, mut client_wr) = tokio::io::split(client);
    let (mut remote_rd, mut remote_wr) = tokio::io::split(remote);
    let activity = Activity::new();

    let upload = async {
        let _ = pump(&mut client_rd, &mut remote_wr, &activity, Way::Up).await;
        let _ = remote_wr.shutdown().await;
    };

    let download = async {
        if pump(&mut remote_rd, &mut client_wr, &activity, Way::Down)
            .await
            .is_ok()
        {
            let _ = client_wr.shutdown().await;
        }
    };

    relay_halves(upload, download, &activity, linger).await;
}

const RELAY_CHUNK: usize = 16384;

pub(crate) fn half_close_linger() -> Duration {
    let secs = std::env::var("AETHER_HALF_CLOSE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(30);
    Duration::from_secs(secs)
}

struct Activity {
    started: tokio::time::Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            started: tokio::time::Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let elapsed = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        self.last_ms.store(elapsed, Ordering::Relaxed);
    }

    fn quiet_until(&self, idle: Duration) -> tokio::time::Instant {
        self.started + Duration::from_millis(self.last_ms.load(Ordering::Relaxed)) + idle
    }
}

async fn relay_halves<U, D>(upload: U, download: D, activity: &Activity, linger: Duration)
where
    U: Future<Output = ()>,
    D: Future<Output = ()>,
{
    tokio::pin!(upload);
    tokio::pin!(download);

    tokio::select! {
        _ = &mut download => return,
        _ = &mut upload => {}
    }

    activity.touch();
    loop {
        tokio::select! {
            _ = &mut download => return,
            _ = tokio::time::sleep_until(activity.quiet_until(linger)) => {
                if activity.quiet_until(linger) <= tokio::time::Instant::now() {
                    return;
                }
            }
        }
    }
}

pub(crate) async fn relay_tunneled(
    sock: TcpStream,
    sender: TcpSender,
    mut from_stack: mpsc::Receiver<Vec<u8>>,
    linger: Duration,
) {
    let (mut rd, mut wr) = sock.into_split();
    let activity = Activity::new();

    let upload = async {
        let mut buf = vec![0u8; RELAY_CHUNK];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if sender.send(buf[..n].to_vec()).await.is_err() {
                        return;
                    }
                    crate::stats::add_up(n);
                    activity.touch();
                }
            }
        }
        sender.close().await;
    };

    let download = async {
        while let Some(chunk) = from_stack.recv().await {
            if wr.write_all(&chunk).await.is_err() {
                return;
            }
            crate::stats::add_down(chunk.len());
            activity.touch();
        }
        let _ = wr.shutdown().await;
    };

    relay_halves(upload, download, &activity, linger).await;
}

async fn relay_direct(client: TcpStream, remote: TcpStream, linger: Duration) {
    let (mut client_rd, mut client_wr) = client.into_split();
    let (mut remote_rd, mut remote_wr) = remote.into_split();
    let activity = Activity::new();

    let upload = async {
        let _ = pump(&mut client_rd, &mut remote_wr, &activity, Way::Up).await;
        let _ = remote_wr.shutdown().await;
    };

    let download = async {
        if pump(&mut remote_rd, &mut client_wr, &activity, Way::Down)
            .await
            .is_ok()
        {
            let _ = client_wr.shutdown().await;
        }
    };

    relay_halves(upload, download, &activity, linger).await;
}

#[derive(Clone, Copy)]
enum Way {
    Up,
    Down,
}

async fn pump<R, W>(from: &mut R, to: &mut W, activity: &Activity, way: Way) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; RELAY_CHUNK];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&buf[..n]).await?;
        to.flush().await?;
        match way {
            Way::Up => crate::stats::add_up(n),
            Way::Down => crate::stats::add_down(n),
        }
        activity.touch();
    }
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

fn udp_source_allowed(expected_ip: IpAddr, latched: Option<SocketAddr>, from: SocketAddr) -> bool {
    match latched {
        Some(known) => known == from,
        None => normalize_ip(from.ip()) == normalize_ip(expected_ip),
    }
}

async fn handle_direct(
    mut sock: TcpStream,
    target: Target,
    port: u16,
    head: Vec<u8>,
    replied: bool,
) -> Result<()> {
    let host = match &target {
        Target::Domain(name) => name.clone(),
        Target::Ip(ip) => ip.to_string(),
    };
    let client = sock.peer_addr()?.ip();

    let mut upstream =
        match tokio::time::timeout(DIRECT_CONNECT_TIMEOUT, connect_direct(&host, port, client))
            .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                log::debug!("[route] direct connect to {host}:{port} failed: {error}");
                if !replied {
                    let code = if error.kind() == std::io::ErrorKind::PermissionDenied {
                        REP_NOT_ALLOWED
                    } else {
                        REP_GENERAL
                    };
                    let _ = reply(&mut sock, code).await;
                }
                return Ok(());
            }
            Err(_) => {
                log::debug!("[route] direct connect to {host}:{port} timed out");
                if !replied {
                    let _ = reply(&mut sock, REP_GENERAL).await;
                }
                return Ok(());
            }
        };

    if !head.is_empty() && upstream.write_all(&head).await.is_err() {
        return Ok(());
    }

    if !replied {
        reply_bound(&mut sock, "0.0.0.0:0".parse().unwrap()).await?;
    }

    relay_direct(sock, upstream, half_close_linger()).await;
    Ok(())
}

const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

fn direct_target_allowed(client: IpAddr, address: IpAddr) -> bool {
    let address = normalize_ip(address);
    if address.is_loopback() || address.is_unspecified() {
        return normalize_ip(client).is_loopback();
    }
    true
}

async fn connect_direct(host: &str, port: u16, client: IpAddr) -> std::io::Result<TcpStream> {
    let mut last_error = None;
    for address in tokio::net::lookup_host((host, port)).await? {
        if !direct_target_allowed(client, address.ip()) {
            last_error = Some(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{address} is this machine's own loopback, which only local clients may reach"
                ),
            ));
            continue;
        }
        match crate::egress::tcp_connect(address).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                enable_keepalive(&stream);
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{host} did not resolve to any address"),
        )
    }))
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
        .map_err(|_| {
            AetherError::Other(format!("gateway {proxy} did not accept a connection"))
        })??;
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

    let direct_relay = crate::egress::udp_bind("0.0.0.0:0".parse().expect("a wildcard address"))?;

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
                    if refused == 1 || refused.is_multiple_of(64) {
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
                                Some(addr) if !direct_target_allowed(control_peer.ip(), addr.ip()) => {
                                    log::debug!(
                                        "[route] direct udp to {addr} refused: only local clients may reach this machine's loopback"
                                    );
                                }
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
mod relay_tests {
    use super::*;

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (dialed, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        (dialed.unwrap(), accepted.unwrap().0)
    }

    #[tokio::test]
    async fn a_far_end_that_never_closes_does_not_pin_a_half_closed_client() {
        let (mut client, proxied) = pair().await;
        let (dialed, mut far_end) = pair().await;
        let relay = tokio::spawn(relay_direct(proxied, dialed, Duration::from_millis(200)));

        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();

        let mut request = Vec::new();
        far_end.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");

        tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("the relay must let go once the answer stops coming")
            .unwrap();

        let mut rest = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut rest))
            .await
            .expect("the client must see the connection end");
        assert_eq!(read.unwrap(), 0);
        drop(far_end);
    }

    #[tokio::test]
    async fn the_answer_to_a_half_closed_request_still_arrives_whole() {
        let (mut client, proxied) = pair().await;
        let (dialed, mut far_end) = pair().await;
        let relay = tokio::spawn(relay_direct(proxied, dialed, Duration::from_secs(5)));

        client.write_all(b"GET").await.unwrap();
        client.shutdown().await.unwrap();

        let mut request = Vec::new();
        far_end.read_to_end(&mut request).await.unwrap();
        far_end.write_all(b"the answer").await.unwrap();
        drop(far_end);

        let mut answer = Vec::new();
        client.read_to_end(&mut answer).await.unwrap();
        assert_eq!(answer, b"the answer");
        tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("the relay ends with the far end")
            .unwrap();
    }

    #[tokio::test]
    async fn an_answer_that_keeps_moving_outlives_the_linger() {
        let (mut client, proxied) = pair().await;
        let (dialed, mut far_end) = pair().await;
        let relay = tokio::spawn(relay_direct(proxied, dialed, Duration::from_millis(500)));

        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        far_end.read_to_end(&mut request).await.unwrap();

        for byte in 0..20u8 {
            far_end.write_all(&[byte]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        drop(far_end);

        let mut answer = Vec::new();
        client.read_to_end(&mut answer).await.unwrap();
        assert_eq!(answer, (0..20u8).collect::<Vec<_>>());
        relay.await.unwrap();
    }

    #[test]
    fn only_local_clients_may_reach_this_machines_loopback_directly() {
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        let lan: IpAddr = "192.168.1.20".parse().unwrap();
        assert!(direct_target_allowed(local, "127.0.0.1".parse().unwrap()));
        assert!(direct_target_allowed(
            "::1".parse().unwrap(),
            "127.0.0.1".parse().unwrap()
        ));
        assert!(!direct_target_allowed(lan, "127.0.0.1".parse().unwrap()));
        assert!(!direct_target_allowed(lan, "127.8.9.10".parse().unwrap()));
        assert!(!direct_target_allowed(lan, "::1".parse().unwrap()));
        assert!(!direct_target_allowed(
            lan,
            "::ffff:127.0.0.1".parse().unwrap()
        ));
        assert!(!direct_target_allowed(lan, "0.0.0.0".parse().unwrap()));
        assert!(direct_target_allowed(lan, "192.168.1.1".parse().unwrap()));
        assert!(direct_target_allowed(lan, "93.184.216.34".parse().unwrap()));
    }

    #[tokio::test]
    async fn a_lan_client_is_refused_a_loopback_target() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let refused = connect_direct("127.0.0.1", port, "192.168.1.20".parse().unwrap())
            .await
            .expect_err("a lan client must not reach this machine's loopback");
        assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);

        assert!(
            connect_direct("127.0.0.1", port, "127.0.0.1".parse().unwrap())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn clients_past_the_limit_wait_for_a_free_slot() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (served_tx, mut served) = mpsc::unbounded_channel::<SocketAddr>();

        let server = tokio::spawn(accept_clients(
            listener,
            "test",
            1,
            move |mut sock, peer| {
                let served_tx = served_tx.clone();
                async move {
                    let _ = served_tx.send(peer);
                    let mut buf = [0u8; 16];
                    while let Ok(read) = sock.read(&mut buf).await {
                        if read == 0 {
                            break;
                        }
                    }
                }
            },
        ));

        let first = TcpStream::connect(address).await.unwrap();
        let first_served = tokio::time::timeout(Duration::from_secs(2), served.recv())
            .await
            .expect("the first client is served")
            .unwrap();
        assert_eq!(first_served, first.local_addr().unwrap());

        let second = TcpStream::connect(address).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), served.recv())
                .await
                .is_err(),
            "the second client must wait while the first holds the only slot"
        );

        drop(first);
        let second_served = tokio::time::timeout(Duration::from_secs(2), served.recv())
            .await
            .expect("the second client is served once the slot frees up")
            .unwrap();
        assert_eq!(second_served, second.local_addr().unwrap());
        server.abort();
    }
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

pub async fn serve_http(listener: TcpListener, stack: StackHandle) -> Result<()> {
    let listen = listener.local_addr()?;
    log::info!("[+] http proxy listening on {listen}");
    warn_if_world_reachable("http proxy", listen);

    accept_clients(listener, "http proxy", client_limit(), move |sock, peer| {
        let stack = stack.clone();
        async move {
            if let Err(e) = handle_http_client(sock, stack).await {
                log::debug!("http proxy client {peer} ended: {e}");
            }
        }
    })
    .await
}

pub(crate) async fn serve_http_connector<F, Fut, S>(
    listener: TcpListener,
    kind: &'static str,
    connect: F,
) -> Result<()>
where
    F: Fn(String, u16) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = std::io::Result<S>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let listen = listener.local_addr()?;
    log::info!("[+] {kind} listening on {listen}");
    warn_if_world_reachable(kind, listen);

    accept_clients(listener, kind, client_limit(), move |sock, peer| {
        let connect = connect.clone();
        async move {
            if let Err(e) = handle_http_through(sock, connect).await {
                log::debug!("{kind} client {peer} ended: {e}");
            }
        }
    })
    .await
}

async fn handle_http_through<F, Fut, S>(mut sock: TcpStream, connect: F) -> Result<()>
where
    F: Fn(String, u16) -> Fut,
    Fut: Future<Output = std::io::Result<S>>,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (head, early) = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_head(&mut sock))
        .await
        .map_err(|_| {
            AetherError::Other("the client did not send a request head in time".into())
        })??;
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

    match routes().decide(host_of(&target), request.port) {
        Action::Block => {
            log::debug!("[route] block http {}:{}", request.authority, request.port);
            let _ = sock
                .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
        Action::Direct => {
            log::debug!("[route] direct http {}:{}", request.authority, request.port);
            return relay_http_direct(sock, &request, &head, &early).await;
        }
        Action::Proxy => {}
    }

    let remote = match connect(request.authority.clone(), request.port).await {
        Ok(remote) => remote,
        Err(error) => {
            let _ = sock
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            return Err(AetherError::Other(format!(
                "{}:{}: {error}",
                request.authority, request.port
            )));
        }
    };

    let mut remote = remote;

    match &request.rewritten {
        Some(line) => {
            let rest = text.split_once("\r\n").map(|(_, tail)| tail).unwrap_or("");
            remote.write_all(format!("{line}{rest}").as_bytes()).await?;
        }
        None => {
            sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
        }
    }

    if !early.is_empty() {
        remote.write_all(&early).await?;
    }
    remote.flush().await?;

    relay_generic(sock, remote, half_close_linger()).await;
    Ok(())
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

async fn read_head(sock: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];

    loop {
        let read = sock.read(&mut chunk).await?;
        if read == 0 {
            return Err(AetherError::Other(
                "the http client closed before sending a request".into(),
            ));
        }

        let search_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..read]);

        if let Some(pos) = buf[search_from..].windows(4).position(|w| w == b"\r\n\r\n") {
            let early = buf.split_off(search_from + pos + 4);
            return Ok((buf, early));
        }

        if buf.len() > HTTP_HEAD_LIMIT {
            return Err(AetherError::Other("http request head too large".into()));
        }
    }
}

async fn open_tunneled(stack: &StackHandle, target: Target, port: u16) -> Result<GatewayChannel> {
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
    let (head, early) = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_head(&mut sock))
        .await
        .map_err(|_| {
            AetherError::Other("the client did not send a request head in time".into())
        })??;
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
            return relay_http_direct(sock, &request, &head, &early).await;
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

    let (sender, from_stack, leftover) = channel;

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

    if !leftover.is_empty() && sock.write_all(&leftover).await.is_err() {
        return Ok(());
    }
    if let Some(bytes) = preamble {
        if sender.send(bytes).await.is_err() {
            return Ok(());
        }
    }
    if !early.is_empty() && sender.send(early).await.is_err() {
        return Ok(());
    }

    relay_tunneled(sock, sender, from_stack, half_close_linger()).await;
    Ok(())
}

async fn relay_http_direct(
    mut sock: TcpStream,
    request: &HttpRequestLine,
    head: &[u8],
    early: &[u8],
) -> Result<()> {
    let client = sock.peer_addr()?.ip();
    let upstream = tokio::time::timeout(
        DIRECT_CONNECT_TIMEOUT,
        connect_direct(&request.authority, request.port, client),
    )
    .await
    .unwrap_or_else(|_| {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "direct connect to {}:{} timed out",
                request.authority, request.port
            ),
        ))
    });

    let mut upstream = match upstream {
        Ok(stream) => stream,
        Err(error) => {
            let answer: &[u8] = if error.kind() == std::io::ErrorKind::PermissionDenied {
                b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"
            } else {
                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
            };
            let _ = sock.write_all(answer).await;
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
    if !early.is_empty() {
        upstream.write_all(early).await?;
    }

    relay_direct(sock, upstream, half_close_linger()).await;
    Ok(())
}

#[cfg(test)]
mod http_proxy_tests {
    use super::{parse_authority, parse_request_line, read_head};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn head_over_socket(chunks: &[&[u8]]) -> (Vec<u8>, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let owned: Vec<Vec<u8>> = chunks.iter().map(|c| c.to_vec()).collect();
        let writer = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.expect("connect");
            for chunk in owned {
                client.write_all(&chunk).await.expect("write");
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            client.flush().await.expect("flush");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let (mut server, _) = listener.accept().await.expect("accept");
        let (head, mut leftover) = read_head(&mut server).await.expect("head");

        let mut more = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            server.read(&mut more),
        )
        .await
        .map(|r| r.unwrap_or(0))
        .unwrap_or(0);
        leftover.extend_from_slice(&more[..n]);

        writer.abort();
        (head, leftover)
    }

    #[tokio::test]
    async fn a_head_arriving_in_one_piece_is_read_exactly() {
        let (head, leftover) =
            head_over_socket(&[b"CONNECT a:443 HTTP/1.1\r\nHost: a\r\n\r\n"]).await;
        assert_eq!(head, b"CONNECT a:443 HTTP/1.1\r\nHost: a\r\n\r\n");
        assert!(leftover.is_empty());
    }

    #[tokio::test]
    async fn a_head_split_across_writes_is_still_assembled() {
        let (head, _) =
            head_over_socket(&[b"CONNECT a:443 HT", b"TP/1.1\r\nHos", b"t: a\r\n", b"\r\n"]).await;
        assert_eq!(head, b"CONNECT a:443 HTTP/1.1\r\nHost: a\r\n\r\n");
    }

    #[tokio::test]
    async fn bytes_after_the_head_are_kept_for_the_far_end() {
        let (head, leftover) =
            head_over_socket(&[b"CONNECT a:443 HTTP/1.1\r\n\r\n\x16\x03\x01pipelined"]).await;
        assert_eq!(head, b"CONNECT a:443 HTTP/1.1\r\n\r\n");
        assert_eq!(leftover, b"\x16\x03\x01pipelined");
    }

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
        let parsed = parse_request_line("GET http://ip-api.com/json/?fields=query HTTP/1.1")
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
        let parsed = parse_request_line("GET http://example.com:8080/x HTTP/1.1").expect("parsed");
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

#[cfg(test)]
mod sniff_route_tests {
    use super::*;

    fn ip(value: &str) -> Target {
        Target::Ip(value.parse().unwrap())
    }

    #[test]
    fn a_domain_rule_reaches_traffic_that_arrived_as_an_address() {
        let set = RuleSet::parse("ads.example", "");
        assert_eq!(
            decide_route(&set, &ip("93.184.216.34"), None, 443),
            Action::Proxy
        );
        assert_eq!(
            decide_route(&set, &ip("93.184.216.34"), Some("ads.example"), 443),
            Action::Block
        );
        assert_eq!(
            decide_route(&set, &ip("93.184.216.34"), Some("tracker.ads.example"), 443),
            Action::Block
        );
    }

    #[test]
    fn a_sniffed_name_can_send_traffic_direct() {
        let set = RuleSet::parse("", "internal.example");
        assert_eq!(
            decide_route(&set, &ip("10.1.2.3"), Some("internal.example"), 443),
            Action::Direct
        );
    }

    #[test]
    fn an_address_rule_still_applies_when_the_name_says_nothing() {
        let set = RuleSet::parse("10.0.0.0/8", "");
        assert_eq!(
            decide_route(&set, &ip("10.1.2.3"), Some("unlisted.example"), 443),
            Action::Block
        );
    }

    #[test]
    fn a_name_that_matches_nothing_leaves_the_address_decision_alone() {
        let set = RuleSet::parse("ads.example", "private");
        assert_eq!(
            decide_route(&set, &ip("192.168.1.5"), Some("unlisted.example"), 443),
            Action::Direct
        );
    }

    #[test]
    fn a_domain_target_is_decided_on_its_own_name() {
        let set = RuleSet::parse("ads.example", "");
        let target = Target::Domain("ads.example".to_string());
        assert_eq!(decide_route(&set, &target, None, 443), Action::Block);
    }

    #[tokio::test]
    async fn a_server_speaks_first_protocol_survives_the_sniff_window() {
        std::env::set_var("AETHER_ROUTE_SNIFF_MS", "50");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let quiet = tokio::spawn(async move {
            let _client = tokio::net::TcpStream::connect(address).await.unwrap();
            tokio::time::sleep(Duration::from_millis(400)).await;
        });

        let (mut server, _) = listener.accept().await.unwrap();
        let head = read_sniff_head(&mut server).await;
        std::env::remove_var("AETHER_ROUTE_SNIFF_MS");

        assert_eq!(
            head,
            Some(Vec::new()),
            "a client that waits for a greeting must not be treated as gone"
        );
        quiet.abort();
    }

    #[tokio::test]
    async fn a_client_that_hangs_up_is_reported_as_gone() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let client = tokio::net::TcpStream::connect(address).await.unwrap();
            drop(client);
        });

        let (mut server, _) = listener.accept().await.unwrap();
        assert_eq!(read_sniff_head(&mut server).await, None);
    }

    #[test]
    fn sniffing_is_on_unless_it_is_turned_off() {
        std::env::remove_var("AETHER_ROUTE_SNIFF");
        assert!(sniff_enabled());
        std::env::set_var("AETHER_ROUTE_SNIFF", "0");
        assert!(!sniff_enabled());
        std::env::set_var("AETHER_ROUTE_SNIFF", "off");
        assert!(!sniff_enabled());
        std::env::set_var("AETHER_ROUTE_SNIFF", "1");
        assert!(sniff_enabled());
        std::env::remove_var("AETHER_ROUTE_SNIFF");
    }
}

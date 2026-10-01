use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::error::AetherError;
use crate::Result;

const VER: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_USERPASS: u8 = 0x02;
const AUTH_REJECTED: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const CMD_ASSOCIATE: u8 = 0x03;
const ATYP_V4: u8 = 0x01;
const ATYP_NAME: u8 = 0x03;
const ATYP_V6: u8 = 0x04;
const REP_OK: u8 = 0x00;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Socks5,
    Http,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Socks5 => "socks5",
            Kind::Http => "http",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Upstream {
    pub kind: Kind,
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// The proxy AETHER_UPSTREAM names, as it names it now. It is looked up on every call rather
/// than once: --tor-reverse and --psiphon-reverse name their carrier only when it is up, and tor
/// looks the setting up while it bootstraps, to fetch bridges, so an answer kept from then sent
/// the registration and the tunnel past the carrier instead of through it. A setting is parsed,
/// and announced, only when it changes.
pub fn configured() -> Option<Upstream> {
    static SEEN: std::sync::Mutex<Option<(String, Option<Upstream>)>> = std::sync::Mutex::new(None);
    let raw = std::env::var("AETHER_UPSTREAM").unwrap_or_default();
    let mut seen = SEEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    remembered(&mut seen, raw)
}

/// The proxy `raw` names, parsed once per setting: while the setting stays the same, the proxy
/// `seen` holds for it is used again.
fn remembered(seen: &mut Option<(String, Option<Upstream>)>, raw: String) -> Option<Upstream> {
    if let Some((last, upstream)) = seen.as_ref() {
        if *last == raw {
            return upstream.clone();
        }
    }
    let upstream = Upstream::from_value(&raw);
    *seen = Some((raw, upstream.clone()));
    upstream
}

impl Upstream {
    pub fn from_env() -> Option<Self> {
        Self::from_value(&std::env::var("AETHER_UPSTREAM").ok()?)
    }

    /// The proxy `raw` names, announced in the log; none when it is blank or cannot be read.
    fn from_value(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }

        match Self::parse(trimmed) {
            Ok(upstream) => {
                log::info!(
                    "[+] dialling out through the {} proxy at {}:{}",
                    upstream.kind.label(),
                    upstream.host,
                    upstream.port
                );
                Some(upstream)
            }
            Err(error) => {
                log::error!("[-] the upstream proxy setting was ignored: {error}");
                None
            }
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        let (scheme, rest) = match raw.split_once("://") {
            Some((scheme, rest)) => (scheme.to_lowercase(), rest),
            None => ("socks5".to_string(), raw),
        };

        let kind = match scheme.as_str() {
            "socks5" | "socks5h" | "socks" => Kind::Socks5,
            "http" | "https" => Kind::Http,
            other => {
                return Err(AetherError::Other(format!(
                    "{other} is not an upstream proxy kind aether understands"
                )))
            }
        };

        let (credentials, endpoint) = match rest.rsplit_once('@') {
            Some((credentials, endpoint)) => (Some(credentials), endpoint),
            None => (None, rest),
        };

        if scheme == "https" {
            if credentials.is_some() {
                return Err(AetherError::Other(
                    "an https:// upstream with a password is refused: aether talks to its upstream \
                     over plain http, which would send the password in the clear; use http:// \
                     only if that is acceptable, or socks5://"
                        .into(),
                ));
            }
            log::warn!(
                "[-] the upstream is written as https:// but aether talks to it over plain http; \
                 the tunnel inside stays encrypted"
            );
        }

        let endpoint = endpoint.trim_end_matches('/');
        let (host, port) = split_endpoint(endpoint)?;

        let (user, password) = match credentials {
            Some(pair) => match pair.split_once(':') {
                Some((user, password)) => {
                    (Some(percent_decode(user)), Some(percent_decode(password)))
                }
                None => (Some(percent_decode(pair)), None),
            },
            None => (None, None),
        };

        Ok(Self {
            kind,
            host,
            port,
            user,
            password,
        })
    }

    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn url(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let scheme = match self.kind {
            Kind::Socks5 => "socks5h",
            Kind::Http => "http",
        };
        format!("{scheme}://{host}:{}", self.port)
    }

    pub fn as_reqwest_proxy(&self) -> Result<reqwest::Proxy> {
        let proxy = reqwest::Proxy::all(self.url())
            .map_err(|error| AetherError::Other(format!("{} is unusable: {error}", self.url())))?;

        match &self.user {
            Some(user) => Ok(proxy.basic_auth(user, self.password.as_deref().unwrap_or(""))),
            None => Ok(proxy),
        }
    }

    pub async fn connect(&self, target: SocketAddr) -> Result<TcpStream> {
        let attempt = async {
            let mut stream = crate::egress::tcp_connect_host(&self.host, self.port).await?;
            let _ = stream.set_nodelay(true);

            match self.kind {
                Kind::Socks5 => {
                    self.socks_greet(&mut stream).await?;
                    let request = encode_request(CMD_CONNECT, target);
                    stream.write_all(&request).await?;
                    read_reply(&mut stream).await?;
                }
                Kind::Http => self.http_connect(&mut stream, target).await?,
            }

            Ok(stream)
        };

        match tokio::time::timeout(HANDSHAKE_TIMEOUT, attempt).await {
            Ok(result) => result,
            Err(_) => Err(AetherError::Other(format!(
                "the upstream proxy at {} did not answer in time",
                self.endpoint()
            ))),
        }
    }

    pub async fn associate(&self) -> Result<UdpRelay> {
        if self.kind != Kind::Socks5 {
            return Err(AetherError::Other(
                "only a socks5 proxy can carry udp, an http proxy cannot".into(),
            ));
        }

        let attempt = async {
            let mut control = crate::egress::tcp_connect_host(&self.host, self.port).await?;
            let _ = control.set_nodelay(true);
            self.socks_greet(&mut control).await?;

            let unspecified = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            let request = encode_request(CMD_ASSOCIATE, unspecified);
            control.write_all(&request).await?;
            let bound = read_reply(&mut control).await?;

            let relay = relay_address(bound, &self.host, self.port).await?;
            let local = if relay.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = crate::egress::udp_bind(local.parse().expect("a wildcard address"))?;
            socket.connect(relay).await?;

            Ok(UdpRelay {
                socket,
                relay,
                _control: control,
            })
        };

        match tokio::time::timeout(HANDSHAKE_TIMEOUT, attempt).await {
            Ok(result) => result,
            Err(_) => Err(AetherError::Other(format!(
                "the upstream proxy at {} never opened a udp relay",
                self.endpoint()
            ))),
        }
    }

    async fn socks_greet(&self, stream: &mut TcpStream) -> Result<()> {
        let wants_auth = self.user.is_some();
        let greeting: Vec<u8> = if wants_auth {
            vec![VER, 1, AUTH_USERPASS]
        } else {
            vec![VER, 1, AUTH_NONE]
        };
        stream.write_all(&greeting).await?;

        let mut answer = [0u8; 2];
        stream.read_exact(&mut answer).await?;
        if answer[0] != VER {
            return Err(AetherError::Other(
                "the upstream proxy did not speak socks5".into(),
            ));
        }

        match answer[1] {
            AUTH_NONE if wants_auth => Err(AetherError::Other(
                "the upstream proxy skipped authentication even though credentials are configured"
                    .into(),
            )),
            AUTH_NONE => Ok(()),
            AUTH_USERPASS => self.socks_authenticate(stream).await,
            AUTH_REJECTED => Err(AetherError::Other(
                "the upstream proxy rejected every authentication method offered".into(),
            )),
            other => Err(AetherError::Other(format!(
                "the upstream proxy asked for authentication method {other}, which aether cannot do"
            ))),
        }
    }

    async fn socks_authenticate(&self, stream: &mut TcpStream) -> Result<()> {
        let user = self.user.clone().unwrap_or_default();
        let password = self.password.clone().unwrap_or_default();

        if user.len() > 255 || password.len() > 255 {
            return Err(AetherError::Other(
                "the upstream proxy credentials are longer than socks5 allows".into(),
            ));
        }

        let mut message = Vec::with_capacity(3 + user.len() + password.len());
        message.push(0x01);
        message.push(user.len() as u8);
        message.extend_from_slice(user.as_bytes());
        message.push(password.len() as u8);
        message.extend_from_slice(password.as_bytes());
        stream.write_all(&message).await?;

        let mut answer = [0u8; 2];
        stream.read_exact(&mut answer).await?;
        if answer[0] != 0x01 {
            return Err(AetherError::Other(
                "the upstream proxy answered the password negotiation with the wrong version"
                    .into(),
            ));
        }
        if answer[1] != 0x00 {
            return Err(AetherError::Other(
                "the upstream proxy refused the credentials supplied".into(),
            ));
        }
        Ok(())
    }

    async fn http_connect(&self, stream: &mut TcpStream, target: SocketAddr) -> Result<()> {
        let authority = format!("{target}");
        let mut request = format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
        );

        if let Some(user) = &self.user {
            let password = self.password.clone().unwrap_or_default();
            let token =
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
            request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
        }
        request.push_str("\r\n");

        stream.write_all(request.as_bytes()).await?;

        let mut head = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        loop {
            if head.len() > 8192 {
                return Err(AetherError::Other(
                    "the upstream proxy sent an oversized answer".into(),
                ));
            }
            if stream.read(&mut byte).await? == 0 {
                return Err(AetherError::Other(
                    "the upstream proxy closed before answering the connect".into(),
                ));
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }

        let status = http_status(&head)
            .ok_or_else(|| AetherError::Other("the upstream proxy answer was not http".into()))?;

        if !(200..300).contains(&status) {
            return Err(AetherError::Other(format!(
                "the upstream proxy answered {status} to the connect"
            )));
        }
        Ok(())
    }
}

pub struct UdpRelay {
    socket: UdpSocket,
    relay: SocketAddr,
    _control: TcpStream,
}

impl UdpRelay {
    pub fn relay(&self) -> SocketAddr {
        self.relay
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub async fn send_to(&self, payload: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        let mut framed = encode_udp_header(target);
        framed.extend_from_slice(payload);
        self.socket.send(&framed).await?;
        Ok(payload.len())
    }

    pub async fn recv_from(&self, out: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut framed = vec![0u8; out.len().max(2048) + 512];
        let read = self.socket.recv(&mut framed).await?;

        let (origin, offset) = decode_udp_header(&framed[..read]).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the udp relay sent a malformed header",
            )
        })?;

        let payload = &framed[offset..read];
        let copied = payload.len().min(out.len());
        out[..copied].copy_from_slice(&payload[..copied]);
        Ok((copied, origin))
    }
}

struct Detour {
    id: u64,
    shim: SocketAddr,
    peer: SocketAddr,
}

#[derive(Default)]
#[must_use = "the detour is closed as soon as its guard is dropped"]
pub struct DetourGuard(Option<(SocketAddr, u64, tokio::task::AbortHandle)>);

impl Drop for DetourGuard {
    fn drop(&mut self) {
        if let Some((client, id, pump)) = self.0.take() {
            pump.abort();
            forget_detour(client, id);
        }
    }
}

fn forget_detour(client: SocketAddr, id: u64) {
    if let Ok(mut map) = detours().lock() {
        if map.get(&client).is_some_and(|detour| detour.id == id) {
            map.remove(&client);
        }
    }
}

fn next_detour_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn detours() -> &'static std::sync::Mutex<std::collections::HashMap<SocketAddr, Detour>> {
    static DETOURS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<SocketAddr, Detour>>,
    > = std::sync::OnceLock::new();
    DETOURS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

pub fn relay_target(local: SocketAddr, intended: SocketAddr) -> SocketAddr {
    match detours().lock() {
        Ok(map) => map.get(&local).map(|d| d.shim).unwrap_or(intended),
        Err(_) => intended,
    }
}

pub fn real_source(local: SocketAddr, observed: SocketAddr) -> SocketAddr {
    match detours().lock() {
        Ok(map) => match map.get(&local) {
            Some(detour) if detour.shim == observed => detour.peer,
            _ => observed,
        },
        Err(_) => observed,
    }
}

pub async fn attach_detour(socket: &UdpSocket, peer: SocketAddr) -> Result<DetourGuard> {
    match configured() {
        Some(proxy) => attach_detour_via(&proxy, socket, peer).await,
        None => Ok(DetourGuard::default()),
    }
}

async fn attach_detour_via(
    proxy: &Upstream,
    socket: &UdpSocket,
    peer: SocketAddr,
) -> Result<DetourGuard> {
    if crate::routing::is_private(peer.ip()) {
        log::debug!("[*] {peer} is local, reaching it without the upstream proxy");
        return Ok(DetourGuard::default());
    }

    let relay = proxy.associate().await?;
    let client = socket.local_addr()?;
    let loopback = if client.is_ipv4() {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    };
    let shim = UdpSocket::bind(SocketAddr::new(loopback, 0)).await?;
    let shim_address = shim.local_addr()?;
    let id = next_detour_id();

    if let Ok(mut map) = detours().lock() {
        map.insert(
            client,
            Detour {
                id,
                shim: shim_address,
                peer,
            },
        );
    }

    log::info!(
        "[+] {peer} is reached through the upstream relay at {}",
        relay.relay()
    );

    let task = tokio::spawn(async move {
        if let Err(error) = pump(shim, client, peer, relay).await {
            log::warn!("[-] the upstream udp relay for {peer} stopped: {error}");
        }
        forget_detour(client, id);
    });

    Ok(DetourGuard(Some((client, id, task.abort_handle()))))
}

pub async fn bind_via_upstream(peer: SocketAddr) -> Result<(UdpSocket, SocketAddr, DetourGuard)> {
    let bind = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let socket = crate::egress::udp_bind(bind.parse().expect("a wildcard address"))?;
    let detour = attach_detour(&socket, peer).await?;

    let local = socket.local_addr()?;
    let target = relay_target(local, peer);
    socket.connect(target).await?;

    Ok((socket, target, detour))
}

fn from_detoured_socket(client: SocketAddr, origin: SocketAddr) -> bool {
    origin.port() == client.port()
        && (origin.ip() == client.ip()
            || (client.ip().is_unspecified() && origin.ip().is_loopback()))
}

async fn pump(
    shim: UdpSocket,
    client: SocketAddr,
    peer: SocketAddr,
    relay: UdpRelay,
) -> std::io::Result<()> {
    let mut from_client = vec![0u8; 65535];
    let mut from_relay = vec![0u8; 65535];
    let mut reply_to: Option<SocketAddr> = None;

    loop {
        tokio::select! {
            read = shim.recv_from(&mut from_client) => {
                let (len, origin) = read?;
                if !from_detoured_socket(client, origin) {
                    continue;
                }
                reply_to = Some(origin);
                relay.send_to(&from_client[..len], peer).await?;
            }
            read = relay.recv_from(&mut from_relay) => {
                let len = match read {
                    Ok((len, _origin)) => len,
                    Err(error) if error.kind() == std::io::ErrorKind::InvalidData => continue,
                    Err(error) => return Err(error),
                };
                if let Some(to) = reply_to {
                    shim.send_to(&from_relay[..len], to).await?;
                }
            }
        }
    }
}

fn split_endpoint(endpoint: &str) -> Result<(String, u16)> {
    let malformed = || {
        AetherError::Other(format!(
            "{endpoint} is not a host and port an upstream proxy can live at"
        ))
    };

    if let Some(rest) = endpoint.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or_else(malformed)?;
        let port = tail.strip_prefix(':').ok_or_else(malformed)?;
        let port = port.parse::<u16>().map_err(|_| malformed())?;
        if host.is_empty() || port == 0 {
            return Err(malformed());
        }
        return Ok((host.to_string(), port));
    }

    let (host, port) = endpoint.rsplit_once(':').ok_or_else(malformed)?;
    let port = port.parse::<u16>().map_err(|_| malformed())?;
    if host.is_empty() || port == 0 {
        return Err(malformed());
    }
    Ok((host.to_string(), port))
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' && at + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[at + 1..at + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                at += 3;
                continue;
            }
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn http_status(head: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(head);
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse::<u16>().ok()
}

pub fn encode_address(target: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(19);
    match target.ip() {
        IpAddr::V4(v4) => {
            out.push(ATYP_V4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(ATYP_V6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    out
}

pub fn encode_request(command: u8, target: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    out.push(VER);
    out.push(command);
    out.push(0x00);
    out.extend_from_slice(&encode_address(target));
    out
}

pub fn encode_udp_header(target: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    out.push(0x00);
    out.push(0x00);
    out.push(0x00);
    out.extend_from_slice(&encode_address(target));
    out
}

pub fn decode_udp_header(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    if buf.len() < 4 || buf[2] != 0x00 {
        return None;
    }

    match buf[3] {
        ATYP_V4 => {
            if buf.len() < 10 {
                return None;
            }
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Some((SocketAddr::new(IpAddr::V4(ip), port), 10))
        }
        ATYP_V6 => {
            if buf.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Some((SocketAddr::new(IpAddr::V6(octets.into()), port), 22))
        }
        ATYP_NAME => {
            let length = *buf.get(4)? as usize;
            let end = 5 + length;
            if buf.len() < end + 2 {
                return None;
            }
            let port = u16::from_be_bytes([buf[end], buf[end + 1]]);
            let name = std::str::from_utf8(&buf[5..end]).ok()?;
            let ip = name.parse::<IpAddr>().ok()?;
            Some((SocketAddr::new(ip, port), end + 2))
        }
        _ => None,
    }
}

async fn read_reply(stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;

    if head[0] != VER {
        return Err(AetherError::Other(
            "the upstream proxy answered with something other than socks5".into(),
        ));
    }
    if head[1] != REP_OK {
        return Err(AetherError::Other(format!(
            "the upstream proxy refused the request with code {}",
            head[1]
        )));
    }

    let ip = match head[3] {
        ATYP_V4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        ATYP_V6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            IpAddr::V6(octets.into())
        }
        ATYP_NAME => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            let mut name = vec![0u8; length[0] as usize];
            stream.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name)
                .parse::<IpAddr>()
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        }
        other => {
            return Err(AetherError::Other(format!(
                "the upstream proxy sent address type {other}, which aether cannot read"
            )))
        }
    };

    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
}

async fn relay_address(bound: SocketAddr, host: &str, port: u16) -> Result<SocketAddr> {
    if !bound.ip().is_unspecified() && bound.port() != 0 {
        return Ok(bound);
    }

    let relay_port = if bound.port() == 0 {
        port
    } else {
        bound.port()
    };

    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, relay_port));
    }

    tokio::net::lookup_host((host, relay_port))
        .await?
        .next()
        .ok_or_else(|| {
            AetherError::Other(format!("{host} does not resolve to a usable relay address"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_proxy_named_after_the_first_look_is_still_used() {
        // --tor-reverse names its carrier once tor is up, after tor looked for a proxy to fetch bridges through.
        let mut seen = None;
        assert!(remembered(&mut seen, String::new()).is_none());
        let carrier =
            remembered(&mut seen, "socks5://127.0.0.1:1820".to_string()).expect("the carrier");
        assert_eq!(carrier.port, 1820);
        assert_eq!(
            remembered(&mut seen, "socks5://127.0.0.1:1820".to_string()),
            Some(carrier)
        );
        assert!(remembered(&mut seen, "  ".to_string()).is_none());
    }

    #[test]
    fn a_bare_host_and_port_is_taken_as_socks5() {
        let upstream = Upstream::parse("127.0.0.1:1080").unwrap();
        assert_eq!(upstream.kind, Kind::Socks5);
        assert_eq!(upstream.host, "127.0.0.1");
        assert_eq!(upstream.port, 1080);
        assert!(upstream.user.is_none());
    }

    #[test]
    fn every_socks_spelling_is_accepted() {
        for raw in [
            "socks5://127.0.0.1:1080",
            "socks5h://127.0.0.1:1080",
            "socks://127.0.0.1:1080",
        ] {
            assert_eq!(Upstream::parse(raw).unwrap().kind, Kind::Socks5, "{raw}");
        }
    }

    #[test]
    fn an_http_proxy_is_recognised() {
        let upstream = Upstream::parse("http://proxy.example:8080").unwrap();
        assert_eq!(upstream.kind, Kind::Http);
        assert_eq!(upstream.host, "proxy.example");
        assert_eq!(upstream.port, 8080);
    }

    #[test]
    fn credentials_are_pulled_out_of_the_url() {
        let upstream = Upstream::parse("socks5://alice:s3cret@10.0.0.2:1080").unwrap();
        assert_eq!(upstream.user.as_deref(), Some("alice"));
        assert_eq!(upstream.password.as_deref(), Some("s3cret"));
        assert_eq!(upstream.host, "10.0.0.2");
    }

    #[test]
    fn a_password_holding_an_at_sign_survives() {
        let upstream = Upstream::parse("socks5://alice:p%40ss@10.0.0.2:1080").unwrap();
        assert_eq!(upstream.password.as_deref(), Some("p@ss"));
        assert_eq!(upstream.host, "10.0.0.2");
    }

    #[test]
    fn an_ipv6_endpoint_is_read_in_brackets() {
        let upstream = Upstream::parse("socks5://[::1]:1080").unwrap();
        assert_eq!(upstream.host, "::1");
        assert_eq!(upstream.port, 1080);
    }

    #[test]
    fn nonsense_is_refused_rather_than_guessed_at() {
        for raw in [
            "",
            "socks5://",
            "socks5://host",
            "socks5://host:0",
            "socks5://host:notaport",
            "ftp://host:21",
            "socks5://:1080",
        ] {
            assert!(Upstream::parse(raw).is_err(), "{raw} should be refused");
        }
    }

    #[test]
    fn a_connect_request_matches_the_socks5_wire_format() {
        let request = encode_request(CMD_CONNECT, "93.184.216.34:443".parse().unwrap());
        assert_eq!(
            request,
            vec![0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xbb]
        );
    }

    #[test]
    fn an_ipv6_request_carries_all_sixteen_octets() {
        let request = encode_request(CMD_CONNECT, "[::1]:80".parse().unwrap());
        assert_eq!(request[3], ATYP_V6);
        assert_eq!(request.len(), 4 + 16 + 2);
        assert_eq!(&request[request.len() - 2..], &[0x00, 0x50]);
    }

    #[test]
    fn a_udp_header_round_trips() {
        for raw in ["1.2.3.4:53", "[2606:4700::1111]:443"] {
            let target: SocketAddr = raw.parse().unwrap();
            let mut framed = encode_udp_header(target);
            let offset = framed.len();
            framed.extend_from_slice(b"payload");

            let (decoded, at) = decode_udp_header(&framed).unwrap();
            assert_eq!(decoded, target, "{raw}");
            assert_eq!(at, offset, "{raw}");
            assert_eq!(&framed[at..], b"payload", "{raw}");
        }
    }

    #[test]
    fn a_udp_header_that_is_fragmented_is_refused() {
        let mut framed = encode_udp_header("1.2.3.4:53".parse().unwrap());
        framed[2] = 0x01;
        assert!(decode_udp_header(&framed).is_none());
    }

    #[test]
    fn a_truncated_udp_header_is_refused_without_panicking() {
        let framed = encode_udp_header("[2606:4700::1111]:443".parse().unwrap());
        for cut in 0..framed.len() {
            assert!(decode_udp_header(&framed[..cut]).is_none(), "cut {cut}");
        }
    }

    async fn fake_socks_udp_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();

            let mut greeting = [0u8; 3];
            control.read_exact(&mut greeting).await.unwrap();
            control.write_all(&[VER, AUTH_NONE]).await.unwrap();

            let mut head = [0u8; 4];
            control.read_exact(&mut head).await.unwrap();
            assert_eq!(head[1], CMD_ASSOCIATE);
            let mut rest = [0u8; 6];
            control.read_exact(&mut rest).await.unwrap();

            let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay_address = relay.local_addr().unwrap();

            let mut answer = vec![VER, REP_OK, 0x00];
            answer.extend_from_slice(&encode_address(relay_address));
            control.write_all(&answer).await.unwrap();

            let mut buf = vec![0u8; 4096];
            let (len, from) = relay.recv_from(&mut buf).await.unwrap();
            let (target, offset) = decode_udp_header(&buf[..len]).unwrap();

            let mut echo = encode_udp_header(target);
            echo.extend_from_slice(b"pong:");
            echo.extend_from_slice(&buf[offset..len]);
            relay.send_to(&echo, from).await.unwrap();

            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(control);
        });

        (address, handle)
    }

    #[tokio::test]
    async fn a_datagram_makes_the_round_trip_through_a_socks5_relay() {
        let (proxy_address, server) = fake_socks_udp_server().await;
        std::env::set_var("AETHER_UPSTREAM", format!("socks5://{proxy_address}"));

        let proxy = Upstream::parse(&format!("socks5://{proxy_address}")).unwrap();
        let relay = proxy.associate().await.unwrap();

        let peer: SocketAddr = "203.0.113.9:2408".parse().unwrap();
        relay.send_to(b"ping", peer).await.unwrap();

        let mut out = vec![0u8; 1024];
        let (len, origin) = tokio::time::timeout(Duration::from_secs(3), relay.recv_from(&mut out))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&out[..len], b"pong:ping");
        assert_eq!(origin, peer);

        std::env::remove_var("AETHER_UPSTREAM");
        server.abort();
    }

    async fn round_trip_through_a_detour(bind: &str, peer: SocketAddr) {
        let (proxy_address, server) = fake_socks_udp_server().await;
        let proxy = Upstream::parse(&format!("socks5://{proxy_address}")).unwrap();

        let socket = UdpSocket::bind(bind).await.unwrap();
        let detour = attach_detour_via(&proxy, &socket, peer).await.unwrap();

        let local = socket.local_addr().unwrap();
        let target = relay_target(local, peer);
        assert_ne!(
            target, peer,
            "the datagram has to go to the shim, not straight to the peer"
        );
        socket.send_to(b"ping", target).await.unwrap();

        let mut buf = [0u8; 64];
        let (len, observed) =
            tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf))
                .await
                .expect("the answer must come back through the relay")
                .unwrap();
        assert_eq!(&buf[..len], b"pong:ping");
        assert_eq!(real_source(local, observed), peer);

        drop(detour);
        assert_eq!(
            relay_target(local, peer),
            peer,
            "dropping the guard retires the detour"
        );
        server.abort();
    }

    #[tokio::test]
    async fn a_wildcard_bound_socket_reaches_its_peer_through_the_relay() {
        round_trip_through_a_detour("0.0.0.0:0", "162.159.192.1:2408".parse().unwrap()).await;
    }

    #[tokio::test]
    async fn an_ipv6_socket_reaches_its_peer_through_the_relay() {
        if UdpSocket::bind("[::1]:0").await.is_err() {
            eprintln!("skipped: this machine has no IPv6 loopback");
            return;
        }
        round_trip_through_a_detour("[::]:0", "[2606:4700:d0::a29f:c001]:2408".parse().unwrap())
            .await;
    }

    #[test]
    fn only_the_detoured_socket_is_served_by_its_shim() {
        let wildcard: SocketAddr = "0.0.0.0:5000".parse().unwrap();
        assert!(from_detoured_socket(
            wildcard,
            "127.0.0.1:5000".parse().unwrap()
        ));
        assert!(!from_detoured_socket(
            wildcard,
            "127.0.0.1:5001".parse().unwrap()
        ));
        assert!(!from_detoured_socket(
            wildcard,
            "192.168.1.2:5000".parse().unwrap()
        ));

        let wildcard_v6: SocketAddr = "[::]:5000".parse().unwrap();
        assert!(from_detoured_socket(
            wildcard_v6,
            "[::1]:5000".parse().unwrap()
        ));
        assert!(!from_detoured_socket(
            wildcard_v6,
            "[::1]:5001".parse().unwrap()
        ));

        let bound: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        assert!(from_detoured_socket(
            bound,
            "127.0.0.1:5000".parse().unwrap()
        ));
    }

    async fn fake_socks_http_server() -> (SocketAddr, tokio::task::JoinHandle<Option<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.ok()?;

            let mut greeting = [0u8; 2];
            control.read_exact(&mut greeting).await.ok()?;
            let mut methods = vec![0u8; greeting[1] as usize];
            control.read_exact(&mut methods).await.ok()?;
            control.write_all(&[VER, AUTH_NONE]).await.ok()?;

            let mut head = [0u8; 4];
            control.read_exact(&mut head).await.ok()?;
            if head[1] != CMD_CONNECT {
                return None;
            }
            let target = match head[3] {
                ATYP_NAME => {
                    let mut len = [0u8; 1];
                    control.read_exact(&mut len).await.ok()?;
                    let mut name = vec![0u8; len[0] as usize];
                    control.read_exact(&mut name).await.ok()?;
                    String::from_utf8(name).ok()?
                }
                ATYP_V4 => {
                    let mut octets = [0u8; 4];
                    control.read_exact(&mut octets).await.ok()?;
                    Ipv4Addr::from(octets).to_string()
                }
                _ => return None,
            };
            let mut port = [0u8; 2];
            control.read_exact(&mut port).await.ok()?;

            let mut answer = vec![VER, REP_OK, 0x00];
            answer.extend_from_slice(&encode_address("127.0.0.1:1".parse().unwrap()));
            control.write_all(&answer).await.ok()?;

            let mut request = vec![0u8; 2048];
            let _ = control.read(&mut request).await.ok()?;
            control
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .ok()?;
            Some(target)
        });

        (address, handle)
    }

    #[tokio::test]
    async fn the_api_client_reaches_its_host_through_a_socks5_upstream() {
        let (proxy_address, server) = fake_socks_http_server().await;
        let upstream = Upstream::parse(&format!("socks5://{proxy_address}")).unwrap();
        let client = reqwest::Client::builder()
            .proxy(upstream.as_reqwest_proxy().unwrap())
            .build()
            .unwrap();

        let body = tokio::time::timeout(Duration::from_secs(5), async {
            client
                .get("http://api.example.test/ping")
                .send()
                .await?
                .text()
                .await
        })
        .await
        .expect("the request finishes")
        .expect("the request goes through the socks5 proxy");

        assert_eq!(body, "ok");
        assert_eq!(
            server.await.unwrap().as_deref(),
            Some("api.example.test"),
            "the name has to be resolved by the proxy, not looked up locally"
        );
    }

    #[test]
    fn a_password_is_never_sent_in_the_clear_to_an_https_upstream() {
        assert!(Upstream::parse("https://alice:s3cret@proxy.example:8443").is_err());
        let plain = Upstream::parse("https://proxy.example:8443").unwrap();
        assert_eq!(plain.kind, Kind::Http);
    }

    #[test]
    fn the_upstream_password_stays_out_of_debug_output() {
        let upstream = Upstream::parse("socks5://alice:s3cret@127.0.0.1:1080").unwrap();
        let shown = format!("{upstream:?}");
        assert!(!shown.contains("s3cret"), "{shown}");
        assert!(shown.contains("alice"));
    }

    #[tokio::test]
    async fn an_http_proxy_cannot_be_asked_to_carry_udp() {
        let proxy = Upstream::parse("http://127.0.0.1:8080").unwrap();
        assert!(proxy.associate().await.is_err());
    }

    #[tokio::test]
    async fn a_local_peer_is_reached_without_the_proxy() {
        std::env::set_var("AETHER_UPSTREAM", "socks5://127.0.0.1:9");
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        for local in ["127.0.0.1:53", "10.0.0.1:2408", "192.168.1.1:443"] {
            let peer: SocketAddr = local.parse().unwrap();
            assert!(
                attach_detour(&socket, peer).await.is_ok(),
                "{local} must not be sent through the proxy"
            );
            assert_eq!(
                relay_target(socket.local_addr().unwrap(), peer),
                peer,
                "{local} should still be dialled directly"
            );
        }

        std::env::remove_var("AETHER_UPSTREAM");
    }

    #[test]
    fn the_proxy_url_handed_to_the_api_client_is_well_formed() {
        assert_eq!(
            Upstream::parse("socks5://127.0.0.1:1080").unwrap().url(),
            "socks5h://127.0.0.1:1080"
        );
        assert_eq!(
            Upstream::parse("http://proxy.example:8080").unwrap().url(),
            "http://proxy.example:8080"
        );
        assert_eq!(
            Upstream::parse("socks5://[::1]:1080").unwrap().url(),
            "socks5h://[::1]:1080",
            "an ipv6 proxy host has to stay bracketed"
        );
    }

    #[test]
    fn every_shape_of_proxy_is_accepted_by_the_api_client() {
        for raw in [
            "socks5://127.0.0.1:1080",
            "socks5://alice:s3cret@127.0.0.1:1080",
            "http://proxy.example:8080",
            "http://alice:s3cret@proxy.example:8080",
            "socks5://[::1]:1080",
        ] {
            let upstream = Upstream::parse(raw).unwrap();
            assert!(
                upstream.as_reqwest_proxy().is_ok(),
                "{raw} should be usable for the api calls"
            );
        }
    }

    #[test]
    fn an_http_status_line_is_read() {
        assert_eq!(
            http_status(b"HTTP/1.1 200 Connection established\r\n\r\n"),
            Some(200)
        );
        assert_eq!(
            http_status(b"HTTP/1.0 407 Proxy Authentication Required\r\n\r\n"),
            Some(407)
        );
        assert_eq!(http_status(b"NOTHTTP 200 OK\r\n\r\n"), None);
        assert_eq!(http_status(b""), None);
    }
}

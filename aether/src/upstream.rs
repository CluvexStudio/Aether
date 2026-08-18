use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub kind: Kind,
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
}

pub fn configured() -> Option<&'static Upstream> {
    static UPSTREAM: std::sync::OnceLock<Option<Upstream>> = std::sync::OnceLock::new();
    UPSTREAM.get_or_init(Upstream::from_env).as_ref()
}

impl Upstream {
    pub fn from_env() -> Option<Self> {
        let raw = std::env::var("AETHER_UPSTREAM").ok()?;
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

        let endpoint = endpoint.trim_end_matches('/');
        let (host, port) = split_endpoint(endpoint)?;

        let (user, password) = match credentials {
            Some(pair) => match pair.split_once(':') {
                Some((user, password)) => (
                    Some(percent_decode(user)),
                    Some(percent_decode(password)),
                ),
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
            let mut stream = TcpStream::connect(self.endpoint()).await?;
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
            let mut control = TcpStream::connect(self.endpoint()).await?;
            let _ = control.set_nodelay(true);
            self.socks_greet(&mut control).await?;

            let unspecified = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            let request = encode_request(CMD_ASSOCIATE, unspecified);
            control.write_all(&request).await?;
            let bound = read_reply(&mut control).await?;

            let relay = relay_address(bound, &self.host, self.port).await?;
            let local = if relay.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let socket = UdpSocket::bind(local).await?;
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
            vec![VER, 2, AUTH_NONE, AUTH_USERPASS]
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
            let token = base64::engine::general_purpose::STANDARD
                .encode(format!("{user}:{password}"));
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

        let status = http_status(&head).ok_or_else(|| {
            AetherError::Other("the upstream proxy answer was not http".into())
        })?;

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
    shim: SocketAddr,
    peer: SocketAddr,
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

pub async fn attach_detour(socket: &UdpSocket, peer: SocketAddr) -> Result<()> {
    let proxy = match configured() {
        Some(proxy) => proxy,
        None => return Ok(()),
    };

    if crate::routing::is_private(peer.ip()) {
        log::debug!("[*] {peer} is local, reaching it without the upstream proxy");
        return Ok(());
    }

    let relay = proxy.associate().await?;
    let shim = UdpSocket::bind("127.0.0.1:0").await?;
    let shim_address = shim.local_addr()?;
    let client = socket.local_addr()?;

    if let Ok(mut map) = detours().lock() {
        map.insert(
            client,
            Detour {
                shim: shim_address,
                peer,
            },
        );
    }

    log::info!(
        "[+] {peer} is reached through the upstream relay at {}",
        relay.relay()
    );

    tokio::spawn(async move {
        if let Err(error) = pump(shim, client, peer, relay).await {
            log::warn!("[-] the upstream udp relay for {peer} stopped: {error}");
        }
        if let Ok(mut map) = detours().lock() {
            map.remove(&client);
        }
    });

    Ok(())
}

pub async fn bind_via_upstream(peer: SocketAddr) -> Result<(UdpSocket, SocketAddr)> {
    let bind = if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };

    let socket = UdpSocket::bind(bind).await?;
    attach_detour(&socket, peer).await?;

    let local = socket.local_addr()?;
    let target = relay_target(local, peer);
    socket.connect(target).await?;

    Ok((socket, target))
}

async fn pump(
    shim: UdpSocket,
    client: SocketAddr,
    peer: SocketAddr,
    relay: UdpRelay,
) -> std::io::Result<()> {
    let mut from_client = vec![0u8; 65535];
    let mut from_relay = vec![0u8; 65535];

    loop {
        tokio::select! {
            read = shim.recv_from(&mut from_client) => {
                let (len, origin) = read?;
                if origin != client {
                    continue;
                }
                relay.send_to(&from_client[..len], peer).await?;
            }
            read = relay.recv_from(&mut from_relay) => {
                let (len, _origin) = read?;
                shim.send_to(&from_relay[..len], client).await?;
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
            Some((
                SocketAddr::new(IpAddr::V6(octets.into()), port),
                22,
            ))
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

    let relay_port = if bound.port() == 0 { port } else { bound.port() };

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
        let (len, origin) =
            tokio::time::timeout(Duration::from_secs(3), relay.recv_from(&mut out))
                .await
                .unwrap()
                .unwrap();

        assert_eq!(&out[..len], b"pong:ping");
        assert_eq!(origin, peer);

        std::env::remove_var("AETHER_UPSTREAM");
        server.abort();
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
        assert_eq!(http_status(b"HTTP/1.1 200 Connection established\r\n\r\n"), Some(200));
        assert_eq!(http_status(b"HTTP/1.0 407 Proxy Authentication Required\r\n\r\n"), Some(407));
        assert_eq!(http_status(b"NOTHTTP 200 OK\r\n\r\n"), None);
        assert_eq!(http_status(b""), None);
    }
}

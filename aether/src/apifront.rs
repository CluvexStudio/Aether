use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use rand::RngExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{AetherError, Result};
use crate::fragment::{FragmentConfig, FragmentingStream};

const EDGE_PREFIX: [u8; 3] = [141, 101, 113];
const EDGE_SAMPLES: usize = 3;
const RESOLVED_SAMPLES: usize = 2;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_BODY: usize = 512 * 1024;

const LEGACY_CIPHERS: &str = "ECDHE-ECDSA-CHACHA20-POLY1305:\
ECDHE-ECDSA-AES128-GCM-SHA256:\
ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES256-SHA:\
ECDHE-RSA-AES128-SHA:\
AES256-SHA";

const LEGACY_GROUPS: &str = "X25519:P-256";
const MODERN_GROUPS: &str = "X25519:P-256:P-384";
const CHROME_GROUPS: &str = "P-256:X25519:P-384";

const ALPN_HTTP1: &[u8] = b"\x08http/1.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fingerprint {
    SplitLegacy,
    SplitModern,
    Modern,
    ChromeLike,
}

impl Fingerprint {
    pub fn label(self) -> &'static str {
        match self {
            Fingerprint::SplitLegacy => "split-tls12",
            Fingerprint::SplitModern => "split-tls13",
            Fingerprint::Modern => "plain-tls13",
            Fingerprint::ChromeLike => "chrome",
        }
    }

    fn all() -> [Fingerprint; 4] {
        [
            Fingerprint::SplitLegacy,
            Fingerprint::SplitModern,
            Fingerprint::Modern,
            Fingerprint::ChromeLike,
        ]
    }

    fn fragments(self) -> FragmentConfig {
        match self {
            Fingerprint::SplitLegacy | Fingerprint::SplitModern => FragmentConfig {
                enabled: true,
                size_min: 24,
                size_max: 48,
                delay_min_ms: 2,
                delay_max_ms: 8,
                sni_split: true,
            },
            _ => FragmentConfig::disabled(),
        }
    }

    fn configure(self) -> Result<boring::ssl::ConnectConfiguration> {
        let mut builder =
            SslConnector::builder(SslMethod::tls()).map_err(|e| AetherError::Tls(e.to_string()))?;

        // TLS server-certificate verification disabled (unconditional).
        builder.set_verify(SslVerifyMode::NONE);

        let tls = |error: boring::error::ErrorStack| AetherError::Tls(error.to_string());

        match self {
            Fingerprint::SplitLegacy => {
                builder
                    .set_min_proto_version(Some(SslVersion::TLS1_2))
                    .map_err(tls)?;
                builder
                    .set_max_proto_version(Some(SslVersion::TLS1_2))
                    .map_err(tls)?;
                builder.set_grease_enabled(false);
                builder.set_cipher_list(LEGACY_CIPHERS).map_err(tls)?;
                builder.set_curves_list(LEGACY_GROUPS).map_err(tls)?;
                builder.set_alpn_protos(ALPN_HTTP1).map_err(tls)?;
            }
            Fingerprint::SplitModern => {
                builder
                    .set_min_proto_version(Some(SslVersion::TLS1_3))
                    .map_err(tls)?;
                builder
                    .set_max_proto_version(Some(SslVersion::TLS1_3))
                    .map_err(tls)?;
                builder.set_grease_enabled(false);
                builder.set_curves_list(MODERN_GROUPS).map_err(tls)?;
                builder.set_alpn_protos(ALPN_HTTP1).map_err(tls)?;
            }
            Fingerprint::Modern => {
                builder
                    .set_min_proto_version(Some(SslVersion::TLS1_2))
                    .map_err(tls)?;
                builder
                    .set_max_proto_version(Some(SslVersion::TLS1_3))
                    .map_err(tls)?;
                builder.set_grease_enabled(false);
                builder.set_curves_list(MODERN_GROUPS).map_err(tls)?;
                builder.set_alpn_protos(ALPN_HTTP1).map_err(tls)?;
            }
            Fingerprint::ChromeLike => {
                builder
                    .set_min_proto_version(Some(SslVersion::TLS1_2))
                    .map_err(tls)?;
                builder
                    .set_max_proto_version(Some(SslVersion::TLS1_3))
                    .map_err(tls)?;
                builder.set_grease_enabled(true);
                builder.set_permute_extensions(true);
                builder.set_curves_list(CHROME_GROUPS).map_err(tls)?;
                builder.set_alpn_protos(ALPN_HTTP1).map_err(tls)?;
                builder.enable_signed_cert_timestamps();
                builder.enable_ocsp_stapling();
            }
        }

        // --get-warp-key-tls-ciphers: the TLS 1.2 suites of a fingerprint that offers TLS 1.2,
        // in place of its own.
        if self.offers_tls12() {
            if let Some(list) = crate::tls::WARP_KEY_TLS_CIPHERS.configured() {
                crate::tls::set_tls12_ciphers(&mut builder, &list)?;
            }
        }

        builder.build().configure().map_err(tls)
    }

    /// Whether the ClientHello of the fingerprint offers TLS 1.2, and so lists TLS 1.2 suites.
    fn offers_tls12(self) -> bool {
        self != Fingerprint::SplitModern
    }
}

#[derive(Debug, Clone)]
pub struct ApiRequest {
    pub method: String,
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ApiResponse {
    pub status: u16,
    pub body: String,
    pub route: String,
}

pub fn random_edge_address() -> SocketAddr {
    let host = rand::rng().random_range(1..=254u8);
    let ip = Ipv4Addr::new(EDGE_PREFIX[0], EDGE_PREFIX[1], EDGE_PREFIX[2], host);
    SocketAddr::new(IpAddr::V4(ip), 443)
}

async fn candidates(host: &str) -> Vec<SocketAddr> {
    let mut list: Vec<SocketAddr> = Vec::new();

    while list.len() < EDGE_SAMPLES {
        let candidate = random_edge_address();
        if !list.contains(&candidate) {
            list.push(candidate);
        }
    }

    // A name looked up here would leave outside the upstream proxy that carries everything else.
    if crate::upstream::configured().is_some() {
        return list;
    }

    if let Ok(resolved) = tokio::net::lookup_host((host, 443)).await {
        for address in resolved
            .filter(|entry| entry.is_ipv4())
            .take(RESOLVED_SAMPLES)
        {
            if !list.contains(&address) {
                list.push(address);
            }
        }
    }

    list
}

fn render_request(request: &ApiRequest) -> Vec<u8> {
    let mut head = String::new();
    head.push_str(&format!("{} {} HTTP/1.1\r\n", request.method, request.path));
    head.push_str(&format!("Host: {}\r\n", request.host));

    for (name, value) in &request.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }

    head.push_str("Accept-Encoding: identity\r\n");
    head.push_str(&format!(
        "Content-Length: {}\r\n",
        request.body.as_ref().map(Vec::len).unwrap_or(0)
    ));
    head.push_str("Connection: close\r\n\r\n");

    let mut wire = head.into_bytes();
    if let Some(body) = &request.body {
        wire.extend_from_slice(body);
    }
    wire
}

fn parse_response(raw: &[u8]) -> Result<(u16, String)> {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| AetherError::Api("truncated response head".into()))?;

    let head = String::from_utf8_lossy(&raw[..split]);
    let mut body = raw[split + 4..].to_vec();

    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| AetherError::Api("empty response".into()))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|token| token.parse::<u16>().ok())
        .ok_or_else(|| AetherError::Api(format!("bad status line: {status_line}")))?;

    let chunked = lines.any(|line| {
        let lowered = line.to_lowercase();
        lowered.starts_with("transfer-encoding:") && lowered.contains("chunked")
    });

    if chunked {
        body = dechunk(&body);
    }

    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cursor = 0usize;

    while cursor < body.len() {
        let line_end = match body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
        {
            Some(offset) => cursor + offset,
            None => break,
        };
        let line = String::from_utf8_lossy(&body[cursor..line_end]);
        let token = line.split(';').next().unwrap_or("").trim();
        let size = match usize::from_str_radix(token, 16) {
            Ok(0) | Err(_) => break,
            Ok(value) => value,
        };
        let start = line_end + 2;
        let end = match start.checked_add(size) {
            Some(end) if end <= body.len() => end,
            _ => break,
        };
        out.extend_from_slice(&body[start..end]);
        cursor = end + 2;
    }

    out
}

/// A TCP connection to `address`, through the upstream proxy when there is one.
async fn dial(address: SocketAddr) -> Result<tokio::net::TcpStream> {
    let tcp = match crate::upstream::configured() {
        Some(proxy) => tokio::time::timeout(CONNECT_TIMEOUT, proxy.connect(address))
            .await
            .map_err(|_| AetherError::Api(format!("connect to {address} timed out")))?
            .map_err(|e| {
                AetherError::Api(format!("connect to {address} through the proxy: {e}"))
            })?,
        None => tokio::time::timeout(CONNECT_TIMEOUT, crate::egress::tcp_connect(address))
            .await
            .map_err(|_| AetherError::Api(format!("connect to {address} timed out")))?
            .map_err(|e| AetherError::Api(format!("connect to {address}: {e}")))?,
    };
    tcp.set_nodelay(true).ok();
    Ok(tcp)
}

/// Sends `request` over `tls`, the connection to `address`, and reads the answer to its end.
async fn converse<S>(
    tls: &mut S,
    request: &ApiRequest,
    address: SocketAddr,
) -> Result<(u16, String)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let wire = render_request(request);

    let collected = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
        tls.write_all(&wire).await?;
        tls.flush().await?;

        let mut buffer = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let read = tls.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.len() > MAX_BODY {
                break;
            }
        }
        Ok::<Vec<u8>, std::io::Error>(buffer)
    })
    .await
    .map_err(|_| AetherError::Api(format!("exchange with {address} timed out")))?
    .map_err(|e| AetherError::Api(format!("exchange with {address}: {e}")))?;

    parse_response(&collected)
}

async fn exchange(
    request: &ApiRequest,
    address: SocketAddr,
    fingerprint: Fingerprint,
) -> Result<ApiResponse> {
    let tcp = dial(address).await?;

    let config = fingerprint.configure()?;
    let stream = FragmentingStream::new(tcp, fingerprint.fragments());

    let mut tls = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        tokio_boring::connect(config, &request.host, stream),
    )
    .await
    .map_err(|_| AetherError::Api(format!("tls handshake with {address} timed out")))?
    .map_err(|e| AetherError::Api(format!("tls handshake with {address}: {e}")))?;

    if tls.ssl().selected_alpn_protocol() == Some(b"h2") {
        return Err(AetherError::Api(format!(
            "{address} negotiated http/2 which this path does not speak"
        )));
    }

    let (status, body) = converse(&mut tls, request, address).await?;

    Ok(ApiResponse {
        status,
        body,
        route: format!("{address} / {}", fingerprint.label()),
    })
}

/// The TLS of the ECH route: Chrome's fingerprint, which offers ECH, with `ech` offered in
/// place of the server name. As Chrome's, its ClientHello offers TLS 1.2 next to TLS 1.3,
/// with --get-warp-key-tls-ciphers for its TLS 1.2 suites. The name goes only into the
/// encrypted ClientHello, which offers TLS 1.3 alone; a server that answers with TLS 1.2
/// has turned the ECH down, and BoringSSL ends that handshake with ECH_REJECTED.
fn ech_configuration(ech: &[u8]) -> Result<boring::ssl::ConnectConfiguration> {
    let mut config = Fingerprint::ChromeLike.configure()?;
    // BoringSSL takes a key it offers nothing from, and the name would go in the clear.
    crate::tls::ensure_offerable(ech)?;
    config
        .set_ech_config_list(ech)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    Ok(config)
}

/// One request over ECH to `address`, a Cloudflare edge: the handshake offers `ech`, and the
/// name of `request`'s host goes inside the encrypted ClientHello, never in the clear. A
/// server that turns `ech` down hands back the key it holds now, which takes its place, and
/// the handshake is made once more with it. A handshake that went without ECH carries nothing.
pub async fn exchange_over_ech(
    request: &ApiRequest,
    address: SocketAddr,
    ech: &mut Vec<u8>,
) -> Result<ApiResponse> {
    let mut retried = false;
    let mut tls = loop {
        let config = ech_configuration(ech)?;
        let stream = FragmentingStream::new(dial(address).await?, FragmentConfig::disabled());
        let handshake = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            tokio_boring::connect(config, &request.host, stream),
        )
        .await
        .map_err(|_| AetherError::Api(format!("tls handshake with {address} timed out")))?;
        match handshake {
            Ok(tls) => break tls,
            Err(e) => {
                let message = e.to_string();
                let retry = if !retried && message.contains("ECH_REJECTED") {
                    e.ssl()
                        .and_then(|ssl| ssl.get_ech_retry_configs())
                        .filter(|configs| !configs.is_empty())
                        .and_then(crate::tls::usable_retry)
                } else {
                    None
                };
                let Some(retry) = retry else {
                    return Err(AetherError::Api(format!(
                        "tls handshake with {address}: {message}"
                    )));
                };
                log::debug!(
                    "[apifront] {address} turned the ECH key down; offering the one it handed back ({} bytes)",
                    retry.len()
                );
                *ech = retry;
                retried = true;
            }
        }
    };

    if !tls.ssl().ech_accepted() {
        return Err(AetherError::Ech("the handshake went without ECH".into()));
    }

    let (status, body) = converse(&mut tls, request, address).await?;

    Ok(ApiResponse {
        status,
        body,
        route: format!("{address} / ech"),
    })
}

pub async fn fetch(request: &ApiRequest) -> Result<ApiResponse> {
    let addresses = candidates(&request.host).await;
    if addresses.is_empty() {
        return Err(AetherError::Api(
            "no camouflaged route to the api was available".into(),
        ));
    }

    let mut rejection: Option<ApiResponse> = None;
    let mut failure: Option<AetherError> = None;

    for fingerprint in Fingerprint::all() {
        for address in &addresses {
            match exchange(request, *address, fingerprint).await {
                Ok(response) if (200..300).contains(&response.status) => {
                    return Ok(response);
                }
                Ok(response) => {
                    log::debug!(
                        "[apifront] {} answered {} via {}",
                        request.host,
                        response.status,
                        response.route
                    );
                    if rejection.is_none() || response.status != 403 {
                        rejection = Some(response);
                    }
                }
                Err(error) => {
                    log::debug!("[apifront] {} attempt failed: {error}", fingerprint.label());
                    failure = Some(error);
                }
            }
        }
    }

    if let Some(response) = rejection {
        return Ok(response);
    }

    Err(failure.unwrap_or_else(|| AetherError::Api("every camouflaged route failed".into())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_random_edge_address_stays_inside_the_cloudflare_range() {
        for _ in 0..64 {
            let address = random_edge_address();
            assert_eq!(address.port(), 443);
            match address.ip() {
                IpAddr::V4(v4) => {
                    let octets = v4.octets();
                    assert_eq!([octets[0], octets[1], octets[2]], EDGE_PREFIX);
                    assert!(octets[3] >= 1 && octets[3] <= 254);
                }
                IpAddr::V6(_) => panic!("the edge range is ipv4 only"),
            }
        }
    }

    #[test]
    fn the_request_carries_the_host_header_and_a_length() {
        let request = ApiRequest {
            method: "POST".to_string(),
            host: "api.cloudflareclient.com".to_string(),
            path: "/v0a4471/reg".to_string(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: Some(b"{\"a\":1}".to_vec()),
        };

        let wire = String::from_utf8(render_request(&request)).expect("utf8");
        assert!(wire.starts_with("POST /v0a4471/reg HTTP/1.1\r\n"));
        assert!(wire.contains("Host: api.cloudflareclient.com\r\n"));
        assert!(wire.contains("Content-Type: application/json\r\n"));
        assert!(wire.contains("Content-Length: 7\r\n"));
        assert!(wire.ends_with("\r\n\r\n{\"a\":1}"));
    }

    #[test]
    fn a_body_less_request_still_declares_a_zero_length() {
        let request = ApiRequest {
            method: "GET".to_string(),
            host: "example.invalid".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: None,
        };
        let wire = String::from_utf8(render_request(&request)).expect("utf8");
        assert!(wire.contains("Content-Length: 0\r\n"));
    }

    #[test]
    fn a_plain_response_is_parsed() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":\"x\"}";
        let (status, body) = parse_response(raw).expect("parsed");
        assert_eq!(status, 200);
        assert_eq!(body, "{\"id\":\"x\"}");
    }

    #[test]
    fn a_chunked_response_is_reassembled() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n4\r\n:1}\n\r\n0\r\n\r\n";
        let (status, body) = parse_response(raw).expect("parsed");
        assert_eq!(status, 200);
        assert_eq!(body, "{\"a\":1}\n");
    }

    #[test]
    fn a_rejection_status_is_reported_rather_than_hidden() {
        let raw = b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 30\r\n\r\nslow down";
        let (status, body) = parse_response(raw).expect("parsed");
        assert_eq!(status, 429);
        assert_eq!(body, "slow down");
    }

    #[test]
    fn a_headless_response_is_an_error() {
        assert!(parse_response(b"garbage").is_err());
    }

    #[test]
    fn a_chunked_body_is_joined_on_bytes_without_panicking() {
        let text = "ééé".as_bytes();
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        raw.extend_from_slice(format!("{:x}\r\n", 3).as_bytes());
        raw.extend_from_slice(&text[..3]);
        raw.extend_from_slice(format!("\r\n{:x}\r\n", text.len() - 3).as_bytes());
        raw.extend_from_slice(&text[3..]);
        raw.extend_from_slice(b"\r\n0\r\n\r\n");
        let (status, body) = parse_response(&raw).expect("parsed");
        assert_eq!(status, 200);
        assert_eq!(body, "ééé");

        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nabc\r\n";
        let (_, body) = parse_response(raw).expect("parsed");
        assert!(body.is_empty());
    }

    #[test]
    fn each_fingerprint_builds_a_usable_configuration() {
        for fingerprint in Fingerprint::all() {
            assert!(
                fingerprint.configure().is_ok(),
                "{} should configure",
                fingerprint.label()
            );
        }
    }

    #[test]
    fn only_the_split_profiles_chop_the_client_hello() {
        assert!(Fingerprint::SplitLegacy.fragments().enabled);
        assert!(Fingerprint::SplitModern.fragments().enabled);
        assert!(!Fingerprint::Modern.fragments().enabled);
        assert!(!Fingerprint::ChromeLike.fragments().enabled);
    }

    /// Cloudflare's key of cloudflare-ech.com on 2026-10-01.
    const CLOUDFLARE_ECH: &str =
        "AEX+DQBBrwAgACCbK1mYDYFz/BAn6S5t+Q/v+Oej3eFNxtPWgz50fNnFPAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=";

    /// The ClientHello of the ECH route, as a server on this machine reads it before it hangs
    /// up.
    async fn ech_route_hello() -> crate::tls::client_hello::ClientHello {
        let request = ApiRequest {
            method: "GET".to_string(),
            host: "api.cloudflareclient.com".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: None,
        };
        let mut ech = crate::tls::decode_ech_config_list(CLOUDFLARE_ECH).expect("base64");
        let (server, hello) = crate::tls::client_hello::catch().await;
        assert!(exchange_over_ech(&request, server, &mut ech).await.is_err());
        hello.await.expect("the ClientHello")
    }

    #[tokio::test]
    async fn the_ech_route_offers_tls12_as_chrome_does_with_the_warp_key_ciphers() {
        let own = ech_route_hello().await;
        assert!(own.offers_ech());
        assert_eq!(own.server_name().as_deref(), Some("cloudflare-ech.com"));
        assert_eq!(own.versions(), [0x0304, 0x0303]);
        assert!(!own.tls12_suites().is_empty());

        // Any other test that reads the variable meanwhile gets a list BoringSSL takes.
        std::env::set_var(
            crate::tls::WARP_KEY_TLS_CIPHERS.variable,
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:AES256-SHA",
        );
        let listed = ech_route_hello().await;
        std::env::remove_var(crate::tls::WARP_KEY_TLS_CIPHERS.variable);
        assert!(listed.offers_ech());
        assert_eq!(listed.tls12_suites(), [0xc02f, 0xcca9, 0x0035]);
    }

    #[tokio::test]
    #[ignore = "needs live network access to the cloudflare edge"]
    async fn every_fingerprint_reaches_the_live_edge() {
        let request = ApiRequest {
            method: "GET".to_string(),
            host: "api.cloudflareclient.com".to_string(),
            path: "/v0a4471/reg/nonexistent".to_string(),
            headers: vec![("User-Agent".to_string(), "WARP for Android".to_string())],
            body: None,
        };

        let mut reached = 0;
        for fingerprint in Fingerprint::all() {
            let address = random_edge_address();
            match exchange(&request, address, fingerprint).await {
                Ok(response) => {
                    reached += 1;
                    println!(
                        "{} -> {} via {}",
                        fingerprint.label(),
                        response.status,
                        response.route
                    );
                }
                Err(error) => println!("{} failed: {error}", fingerprint.label()),
            }
        }

        assert!(reached > 0, "no fingerprint reached the edge");
    }
}

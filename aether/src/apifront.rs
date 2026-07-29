use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use boring::ssl::{SslConnector, SslMethod, SslVersion};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
    Modern,
    ChromeLike,
}

impl Fingerprint {
    pub fn label(self) -> &'static str {
        match self {
            Fingerprint::SplitLegacy => "split-tls12",
            Fingerprint::Modern => "plain-tls13",
            Fingerprint::ChromeLike => "chrome",
        }
    }

    fn all() -> [Fingerprint; 3] {
        [
            Fingerprint::SplitLegacy,
            Fingerprint::Modern,
            Fingerprint::ChromeLike,
        ]
    }

    fn fragments(self) -> FragmentConfig {
        match self {
            Fingerprint::SplitLegacy => FragmentConfig {
                enabled: true,
                size_min: 24,
                size_max: 48,
                delay_min_ms: 2,
                delay_max_ms: 8,
            },
            _ => FragmentConfig::disabled(),
        }
    }

    fn configure(self) -> Result<boring::ssl::ConnectConfiguration> {
        let mut builder =
            SslConnector::builder(SslMethod::tls()).map_err(|e| AetherError::Tls(e.to_string()))?;

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

        builder.build().configure().map_err(tls)
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
    let host = rand::thread_rng().gen_range(1..=254u8);
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

    if let Ok(resolved) = tokio::net::lookup_host((host, 443)).await {
        for address in resolved.filter(|entry| entry.is_ipv4()).take(RESOLVED_SAMPLES) {
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
    let text = String::from_utf8_lossy(raw);
    let split = text
        .find("\r\n\r\n")
        .ok_or_else(|| AetherError::Api("truncated response head".into()))?;

    let head = &text[..split];
    let mut body = text[split + 4..].to_string();

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

    Ok((status, body))
}

fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut cursor = 0usize;

    while cursor < body.len() {
        let line_end = match body[cursor..].find("\r\n") {
            Some(offset) => cursor + offset,
            None => break,
        };
        let token = body[cursor..line_end].split(';').next().unwrap_or("").trim();
        let size = match usize::from_str_radix(token, 16) {
            Ok(0) | Err(_) => break,
            Ok(value) => value,
        };
        let start = line_end + 2;
        let end = start + size;
        if end > body.len() {
            break;
        }
        out.push_str(&body[start..end]);
        cursor = end + 2;
    }

    out
}

async fn exchange(
    request: &ApiRequest,
    address: SocketAddr,
    fingerprint: Fingerprint,
) -> Result<ApiResponse> {
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| AetherError::Api(format!("connect to {address} timed out")))?
        .map_err(|e| AetherError::Api(format!("connect to {address}: {e}")))?;
    tcp.set_nodelay(true).ok();

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

    let (status, body) = parse_response(&collected)?;

    Ok(ApiResponse {
        status,
        body,
        route: format!("{address} / {}", fingerprint.label()),
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

    Err(failure
        .unwrap_or_else(|| AetherError::Api("every camouflaged route failed".into())))
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
    fn only_the_legacy_profile_splits_the_client_hello() {
        assert!(Fingerprint::SplitLegacy.fragments().enabled);
        assert!(!Fingerprint::Modern.fragments().enabled);
        assert!(!Fingerprint::ChromeLike.fragments().enabled);
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

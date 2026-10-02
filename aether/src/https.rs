//! HTTPS over BoringSSL for the calls that are not tunnels: the calls to the WARP API and the
//! DoH lookup of the ECH key. The ClientHello is the core's fingerprint (see
//! `tls::Fingerprint`), offering HTTP/2 then HTTP/1.1, and ECH when the caller gives a key; the
//! request goes over HTTP/2 when the server picks it, over HTTP/1.1 otherwise.

use std::time::Duration;

use boring::ssl::{ConnectConfiguration, SslConnector, SslMethod};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{AetherError, Result};
use crate::tls::Fingerprint;

/// ALPN: HTTP/2, then HTTP/1.1, as Chrome offers them.
const ALPN_H2_HTTP1: &[u8] = b"\x02h2\x08http/1.1";

/// The most of an answer that is read.
const MAX_BODY: usize = 512 * 1024;

/// A request: `host` is the HTTP host, of Host or :authority, a name or an IP address, an IPv6
/// one without brackets, and `path` the path with its query. The connection goes to `host` on
/// `port`, and the ClientHello names `host`, unless `address` and `sni` name others; offering
/// ECH, the name goes inside the encrypted ClientHello.
pub struct Request<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub port: u16,
    /// Where the connection goes instead of `host`: a name or an IP address, on `port`.
    pub address: Option<&'a str>,
    /// The server name of the ClientHello instead of `host`.
    pub sni: Option<&'a str>,
    pub path: &'a str,
    pub headers: &'a [(String, String)],
    pub body: Option<&'a [u8]>,
}

/// An answer, read to its end.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: http::HeaderMap,
    pub body: Vec<u8>,
    /// The protocol the server picked: "h2" or "http/1.1".
    pub protocol: &'static str,
}

/// Sends `request` with the TLS fingerprint `fingerprint`, and gives up after `timeout`. With
/// `ech`, an ECHConfigList, the handshake offers it and goes no further without it: a server
/// that turns it down hands back the key it holds now, which takes its place in `ech`, and the
/// handshake is made once more with that one.
pub async fn send(
    request: &Request<'_>,
    fingerprint: &Fingerprint,
    ech: Option<&mut Vec<u8>>,
    timeout: Duration,
) -> Result<Response> {
    tokio::time::timeout(timeout, exchange(request, fingerprint, ech))
        .await
        .map_err(|_| {
            AetherError::Api(format!(
                "{} did not answer within {}s",
                authority(request.host, request.port),
                timeout.as_secs()
            ))
        })?
}

async fn exchange(
    request: &Request<'_>,
    fingerprint: &Fingerprint,
    mut ech: Option<&mut Vec<u8>>,
) -> Result<Response> {
    let address = request.address.unwrap_or(request.host);
    let mut retried = false;
    let tls = loop {
        let mut config = configuration(fingerprint)?;
        if let Some(list) = ech.as_deref() {
            // BoringSSL takes a key it offers nothing from, and the name would go in the clear.
            crate::tls::ensure_offerable(list)?;
            config
                .set_ech_config_list(list)
                .map_err(|e| AetherError::Tls(e.to_string()))?;
        }
        let tcp = dial(address, request.port).await?;
        let _ = tcp.set_nodelay(true);
        match tokio_boring::connect(config, request.sni.unwrap_or(request.host), tcp).await {
            Ok(tls) => break tls,
            Err(e) => {
                let message = e.to_string();
                // BoringSSL reports a key the server turned down as ECH_REJECTED, and only then
                // hands out the key the server sent back.
                let retry = match ech.as_deref_mut() {
                    Some(list) if !retried && message.contains("ECH_REJECTED") => e
                        .ssl()
                        .and_then(|ssl| ssl.get_ech_retry_configs())
                        .filter(|configs| !configs.is_empty())
                        .and_then(crate::tls::usable_retry)
                        .map(|retry| (list, retry)),
                    _ => None,
                };
                let Some((list, retry)) = retry else {
                    return Err(AetherError::Tls(format!(
                        "handshake with {}: {message}",
                        authority(address, request.port)
                    )));
                };
                log::debug!(
                    "[https] {} turned the ECH key down; offering the one it handed back ({} bytes)",
                    authority(address, request.port),
                    retry.len()
                );
                *list = retry;
                retried = true;
            }
        }
    };
    // Nothing goes over a handshake that went without the key it was given.
    if ech.is_some() && !tls.ssl().ech_accepted() {
        return Err(AetherError::Ech("the handshake went without ECH".into()));
    }
    if tls.ssl().selected_alpn_protocol() == Some(b"h2") {
        over_http2(tls, request).await
    } else {
        over_http1(tls, request).await
    }
}

/// The TLS of a request: the fingerprint, offering HTTP/2 then HTTP/1.1.
fn configuration(fingerprint: &Fingerprint) -> Result<ConnectConfiguration> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| AetherError::Tls(e.to_string()))?;
    // TLS server-certificate verification disabled (unconditional), as the fingerprint has it:
    // the server name may be neither the HTTP host nor the address.
    fingerprint.apply(&mut builder, ALPN_H2_HTTP1)?;
    builder
        .build()
        .configure()
        .map_err(|e| AetherError::Tls(e.to_string()))
}

/// A TCP connection to `host`:`port`: through the upstream proxy when there is one, which looks
/// a name up itself, or else straight, with the socket mark.
async fn dial(host: &str, port: u16) -> Result<TcpStream> {
    match crate::upstream::configured() {
        Some(proxy) => proxy.connect_host(host, port).await,
        None => crate::egress::tcp_connect_host(host, port)
            .await
            .map_err(|e| AetherError::Api(format!("connect to {}: {e}", authority(host, port)))),
    }
}

/// `host`:`port` as a URL writes it: an IPv6 address in brackets, and the port left out when
/// it is 443.
fn authority(host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    }
}

async fn over_http2<S>(tls: S, request: &Request<'_>) -> Result<Response>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let failed = |what: &str, e: h2::Error| AetherError::Api(format!("h2 {what}: {e}"));
    let (client, connection) = h2::client::handshake(tls)
        .await
        .map_err(|e| failed("handshake", e))?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    let outcome = async {
        let mut client = client.ready().await.map_err(|e| failed("ready", e))?;
        let mut head = http::Request::builder().method(request.method).uri(format!(
            "https://{}{}",
            authority(request.host, request.port),
            request.path
        ));
        for (name, value) in request.headers {
            head = head.header(name.as_str(), value.as_str());
        }
        if let Some(body) = request.body {
            head = head.header(http::header::CONTENT_LENGTH, body.len());
        }
        let head = head
            .body(())
            .map_err(|e| AetherError::Api(format!("h2 request: {e}")))?;

        let (answer, mut stream) = client
            .send_request(head, request.body.is_none())
            .map_err(|e| failed("request", e))?;
        if let Some(body) = request.body {
            stream
                .send_data(Bytes::copy_from_slice(body), true)
                .map_err(|e| failed("request body", e))?;
        }

        let (parts, mut body) = answer.await.map_err(|e| failed("answer", e))?.into_parts();
        let mut data = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(|e| failed("answer body", e))?;
            let _ = body.flow_control().release_capacity(chunk.len());
            data.extend_from_slice(&chunk);
            if data.len() > MAX_BODY {
                return Err(AetherError::Api("the answer is too large".into()));
            }
        }
        Ok(Response {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body: data,
            protocol: "h2",
        })
    }
    .await;

    driver.abort();
    outcome
}

async fn over_http1<S>(mut tls: S, request: &Request<'_>) -> Result<Response>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        request.method,
        request.path,
        authority(request.host, request.port)
    );
    for (name, value) in request.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = request.body {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("Connection: close\r\n\r\n");
    let mut wire = head.into_bytes();
    if let Some(body) = request.body {
        wire.extend_from_slice(body);
    }

    let failed = |e: std::io::Error| AetherError::Api(format!("http/1.1: {e}"));
    tls.write_all(&wire).await.map_err(failed)?;
    tls.flush().await.map_err(failed)?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match tls.read(&mut chunk).await {
            Ok(0) => break,
            Ok(read) => {
                raw.extend_from_slice(&chunk[..read]);
                if raw.len() > MAX_BODY {
                    return Err(AetherError::Api("the answer is too large".into()));
                }
                if http1_complete(&raw) {
                    break;
                }
            }
            // A server that hangs up without a close_notify once its answer is whole.
            Err(_) if http1_complete(&raw) => break,
            Err(e) => return Err(failed(e)),
        }
    }

    let (status, fields, body) = parse_http1(&raw)?;
    let mut headers = http::HeaderMap::new();
    for (name, value) in fields {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(&value),
        ) {
            headers.append(name, value);
        }
    }
    Ok(Response {
        status,
        headers,
        body,
        protocol: "http/1.1",
    })
}

/// Whether `raw` holds a whole HTTP/1.1 answer, by its Content-Length or its last chunk; an
/// answer with neither ends only with the connection.
fn http1_complete(raw: &[u8]) -> bool {
    let Some(split) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&raw[..split]).to_lowercase();
    let body = &raw[split + 4..];
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim() {
            "content-length" => {
                return value
                    .trim()
                    .parse::<usize>()
                    .is_ok_and(|length| body.len() >= length)
            }
            "transfer-encoding" if value.contains("chunked") => return chunks_complete(body),
            _ => {}
        }
    }
    false
}

/// Whether `body`, chunked, has come to its last chunk and the end of its trailer.
fn chunks_complete(body: &[u8]) -> bool {
    let line_end = |from: usize| {
        body.get(from..)?
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|offset| from + offset)
    };
    let mut at = 0;
    loop {
        let Some(end) = line_end(at) else {
            return false;
        };
        let size = String::from_utf8_lossy(&body[at..end]);
        let Ok(size) = usize::from_str_radix(size.split(';').next().unwrap_or("").trim(), 16)
        else {
            return false;
        };
        at = end + 2;
        if size == 0 {
            // The trailer: lines up to an empty one.
            loop {
                let Some(end) = line_end(at) else {
                    return false;
                };
                if end == at {
                    return true;
                }
                at = end + 2;
            }
        }
        at = match size.checked_add(2).and_then(|span| at.checked_add(span)) {
            Some(next) if next <= body.len() => next,
            _ => return false,
        };
    }
}

/// The status, the header fields and the body of `raw`, an HTTP/1.1 response read to its end;
/// a chunked body comes back joined.
fn parse_http1(raw: &[u8]) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
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

    let fields: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect();
    let chunked = fields.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding") && value.to_lowercase().contains("chunked")
    });

    if chunked {
        body = dechunk(&body);
    }

    Ok((status, fields, body))
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

/// A TLS server on this machine for the tests, which picks `alpn` when the client offers it.
#[cfg(test)]
pub(crate) async fn test_server(
    alpn: &'static [u8],
) -> (
    std::net::SocketAddr,
    tokio::net::TcpListener,
    std::sync::Arc<boring::ssl::SslAcceptor>,
) {
    let pair = crate::account::generate_masque_keypair().expect("a key and a certificate");
    let mut builder =
        boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())
            .expect("tls");
    builder
        .set_certificate(&boring::x509::X509::from_pem(&pair.cert_pem).expect("a certificate"))
        .expect("the certificate");
    builder
        .set_private_key(&boring::pkey::PKey::private_key_from_pem(&pair.key_pem).expect("a key"))
        .expect("the key");
    builder.set_alpn_select_callback(move |_, offered| {
        boring::ssl::select_next_proto(alpn, offered).ok_or(boring::ssl::AlpnError::NOACK)
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a port");
    let address = listener.local_addr().expect("its address");
    (address, listener, std::sync::Arc::new(builder.build()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers() -> Vec<(String, String)> {
        vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("CF-Client-Version".to_string(), "a-test".to_string()),
        ]
    }

    #[tokio::test]
    async fn a_request_goes_over_http2_when_the_server_picks_it() {
        let _setting = crate::upstream::hold_setting().await;
        let (address, listener, acceptor) = test_server(b"\x02h2").await;
        let served = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("a connection");
            let tls = tokio_boring::accept(&acceptor, tcp)
                .await
                .expect("a handshake");
            let mut connection = h2::server::handshake(tls).await.expect("an h2 connection");
            let (request, mut respond) = connection
                .accept()
                .await
                .expect("a request")
                .expect("a whole request");
            let (parts, mut body) = request.into_parts();
            let mut sent = Vec::new();
            while let Some(chunk) = body.data().await {
                sent.extend_from_slice(&chunk.expect("the body"));
            }
            let answer = http::Response::builder()
                .status(429)
                .header("retry-after", "7")
                .body(())
                .unwrap();
            let mut stream = respond.send_response(answer, false).expect("an answer");
            stream
                .send_data(Bytes::from_static(b"{\"slow\":\"down\"}"), true)
                .expect("its body");
            // Drives the connection until the client goes away.
            while let Some(Ok(_)) = connection.accept().await {}
            (parts, sent)
        });

        let headers = headers();
        let request = Request {
            method: "POST",
            host: "127.0.0.1",
            port: address.port(),
            address: None,
            sni: None,
            path: "/v0a4471/reg",
            headers: &headers,
            body: Some(b"{\"key\":\"x\"}"),
        };
        let response = send(
            &request,
            &Fingerprint::default(),
            None,
            Duration::from_secs(10),
        )
        .await
        .expect("an answer");
        assert_eq!(response.protocol, "h2");
        assert_eq!(response.status, 429);
        assert_eq!(response.headers["retry-after"], "7");
        assert_eq!(response.body, b"{\"slow\":\"down\"}");

        let (parts, sent) = served.await.expect("the server");
        assert_eq!(parts.method, "POST");
        assert_eq!(
            parts.uri.to_string(),
            format!("https://127.0.0.1:{}/v0a4471/reg", address.port())
        );
        assert_eq!(parts.headers["cf-client-version"], "a-test");
        assert_eq!(parts.headers["content-length"], "11");
        assert_eq!(sent, b"{\"key\":\"x\"}");
    }

    #[tokio::test]
    async fn a_request_goes_over_http1_otherwise_and_ends_with_its_answer() {
        let _setting = crate::upstream::hold_setting().await;
        let (address, listener, acceptor) = test_server(b"\x08http/1.1").await;
        let served = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("a connection");
            let mut tls = tokio_boring::accept(&acceptor, tcp)
                .await
                .expect("a handshake");
            let mut sent = Vec::new();
            let mut chunk = [0u8; 4096];
            while !sent.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = tls.read(&mut chunk).await.expect("the request");
                sent.extend_from_slice(&chunk[..read]);
            }
            tls.write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n3\r\n-h1\r\n0\r\n\r\n",
            )
            .await
            .expect("the answer");
            // The connection stays open: the client has to see that the answer is whole.
            let _ = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut chunk)).await;
            String::from_utf8_lossy(&sent).into_owned()
        });

        let headers = headers();
        let request = Request {
            method: "GET",
            host: "127.0.0.1",
            port: address.port(),
            address: None,
            sni: None,
            path: "/v0a4471/reg/a-device?x=1",
            headers: &headers,
            body: None,
        };
        let response = send(
            &request,
            &Fingerprint::default(),
            None,
            Duration::from_secs(5),
        )
        .await
        .expect("an answer before the connection ends");
        assert_eq!(response.protocol, "http/1.1");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok-h1");

        let sent = served.await.expect("the server");
        assert!(sent.starts_with(&format!(
            "GET /v0a4471/reg/a-device?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n",
            address.port()
        )));
        assert!(sent.contains("CF-Client-Version: a-test\r\n"));
        assert!(sent.ends_with("Connection: close\r\n\r\n"));
        assert!(!sent.contains("Content-Length"));
    }

    /// The ClientHello of a request to `host` on this machine with `fingerprint`, offering
    /// `ech` when given, as the server reads it before it hangs up.
    async fn hello(
        host: &str,
        fingerprint: &Fingerprint,
        ech: Option<&mut Vec<u8>>,
    ) -> crate::tls::client_hello::ClientHello {
        let (address, hello) = crate::tls::client_hello::catch().await;
        let headers = headers();
        let request = Request {
            method: "GET",
            host,
            port: address.port(),
            address: Some("127.0.0.1"),
            sni: None,
            path: "/",
            headers: &headers,
            body: None,
        };
        assert!(send(&request, fingerprint, ech, Duration::from_secs(10))
            .await
            .is_err());
        hello.await.expect("the ClientHello")
    }

    #[tokio::test]
    async fn the_client_hello_is_the_fingerprints_with_http2_first() {
        let _setting = crate::upstream::hold_setting().await;
        let own = hello("api.example.test", &Fingerprint::default(), None).await;
        assert_eq!(own.alpn(), [b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert_eq!(own.versions(), [0x0304, 0x0303]);
        assert_eq!(own.server_name().as_deref(), Some("api.example.test"));
        assert!(own.has_grease());
        assert!(!own.offers_ech());
        assert!(!own.tls12_suites().is_empty());

        // Every name BoringSSL knows, AES256-SHA among them, in the list's order.
        let changed = Fingerprint {
            ciphers: Some(
                "ECDHE-ECDSA-CHACHA20-POLY1305:AES256-SHA:ECDHE-RSA-AES128-GCM-SHA256".to_string(),
            ),
            groups: "X25519:P-256".to_string(),
            grease: false,
        };
        let listed = hello("api.example.test", &changed, None).await;
        assert_eq!(listed.tls12_suites(), [0xcca9, 0x0035, 0xc02f]);
        assert_eq!(listed.groups(), [0x001d, 0x0017]);
        assert!(!listed.has_grease());
        assert_eq!(listed.alpn(), own.alpn());
    }

    /// Cloudflare's key of cloudflare-ech.com on 2026-10-01.
    const CLOUDFLARE_ECH: &str =
        "AEX+DQBBrwAgACCbK1mYDYFz/BAn6S5t+Q/v+Oej3eFNxtPWgz50fNnFPAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=";

    #[tokio::test]
    async fn with_an_ech_key_the_name_goes_inside_the_encrypted_client_hello() {
        let _setting = crate::upstream::hold_setting().await;
        let mut ech = crate::tls::decode_ech_config_list(CLOUDFLARE_ECH).expect("base64");
        let outer = hello("api.example.test", &Fingerprint::default(), Some(&mut ech)).await;
        assert!(outer.offers_ech());
        // The key's public name in the clear, the host only inside.
        assert_eq!(outer.server_name().as_deref(), Some("cloudflare-ech.com"));
        // As Chrome's, the outer ClientHello offers TLS 1.2 as well, with the fingerprint's
        // suites; a server that answers with TLS 1.2 has turned the ECH down.
        assert_eq!(outer.versions(), [0x0304, 0x0303]);
        assert!(!outer.tls12_suites().is_empty());
        assert_eq!(outer.alpn(), [b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[tokio::test]
    async fn a_key_that_cannot_be_offered_goes_no_further() {
        let _setting = crate::upstream::hold_setting().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let headers = headers();
        let request = Request {
            method: "GET",
            host: "api.example.test",
            port: listener.local_addr().expect("its address").port(),
            address: Some("127.0.0.1"),
            sni: None,
            path: "/",
            headers: &headers,
            body: None,
        };
        // BoringSSL would take this list and offer nothing from it: its only config is of
        // another version, so the name would go in the clear.
        let mut unusable = vec![0, 6, 0xfe, 0x0c, 0, 2, 0, 0];
        let refused = send(
            &request,
            &Fingerprint::default(),
            Some(&mut unusable),
            Duration::from_secs(5),
        )
        .await
        .expect_err("no request without ECH");
        assert!(
            refused.to_string().contains("cannot be offered"),
            "{refused}"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(300), listener.accept())
                .await
                .is_err(),
            "nothing was sent"
        );
    }

    /// The server name of the ClientHello and the :authority of a request to `host` on this
    /// machine, sent to `address` with `sni` when given.
    async fn server_name_and_authority(
        host: &str,
        address: Option<&str>,
        sni: Option<&str>,
    ) -> (Option<String>, String) {
        let (listening, listener, acceptor) = test_server(b"\x02h2").await;
        let served = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("a connection");
            let tls = tokio_boring::accept(&acceptor, tcp)
                .await
                .expect("a handshake");
            let name = tls
                .ssl()
                .servername(boring::ssl::NameType::HOST_NAME)
                .map(str::to_string);
            let mut connection = h2::server::handshake(tls).await.expect("h2");
            let (request, mut respond) = connection
                .accept()
                .await
                .expect("a request")
                .expect("a whole request");
            let authority = request.uri().authority().expect("an authority").to_string();
            let answer = http::Response::builder().status(204).body(()).unwrap();
            respond.send_response(answer, true).expect("an answer");
            while let Some(Ok(_)) = connection.accept().await {}
            (name, authority)
        });
        let headers = headers();
        let request = Request {
            method: "GET",
            host,
            port: listening.port(),
            address,
            sni,
            path: "/",
            headers: &headers,
            body: None,
        };
        let response = send(
            &request,
            &Fingerprint::default(),
            None,
            Duration::from_secs(10),
        )
        .await
        .expect("an answer");
        assert_eq!(response.status, 204);
        served.await.expect("the server")
    }

    #[tokio::test]
    async fn a_request_goes_to_its_address_with_its_server_name_and_its_host() {
        let _setting = crate::upstream::hold_setting().await;
        let (name, authority) = server_name_and_authority(
            "doh.example.test",
            Some("127.0.0.1"),
            Some("front.example.test"),
        )
        .await;
        assert_eq!(name.as_deref(), Some("front.example.test"));
        assert!(authority.starts_with("doh.example.test:"), "{authority}");

        // Without them the host is all three: the address, the server name and the HTTP host.
        let (name, authority) = server_name_and_authority("localhost", None, None).await;
        assert_eq!(name.as_deref(), Some("localhost"));
        assert!(authority.starts_with("localhost:"), "{authority}");
    }

    #[test]
    fn an_answer_is_whole_by_its_length_or_its_last_chunk() {
        assert!(http1_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        ));
        assert!(!http1_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok"
        ));
        assert!(!http1_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"));
        assert!(!http1_complete(b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nok"));

        let chunked = b"HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n";
        assert!(http1_complete(chunked));
        for cut in 0..chunked.len() {
            assert!(!http1_complete(&chunked[..cut]), "{cut}");
        }
        // The bytes of a last chunk at the end of a chunk's data end nothing.
        assert!(!http1_complete(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nabcd0\r\n\r\n"
        ));
        // A chunk size past what memory holds ends nothing, and overflows nothing.
        assert!(!http1_complete(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nabc"
        ));
        // A trailer comes before the end.
        assert!(!http1_complete(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Sum: 1\r\n"
        ));
        assert!(http1_complete(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Sum: 1\r\n\r\n"
        ));
    }

    #[test]
    fn a_plain_answer_is_parsed() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":\"x\"}";
        let (status, fields, body) = parse_http1(raw).expect("parsed");
        assert_eq!(status, 200);
        assert_eq!(
            fields,
            [("Content-Type".to_string(), "application/json".to_string())]
        );
        assert_eq!(body, b"{\"id\":\"x\"}");
    }

    #[test]
    fn a_chunked_answer_is_joined() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n4\r\n:1}\n\r\n0\r\n\r\n";
        let (status, _, body) = parse_http1(raw).expect("parsed");
        assert_eq!(status, 200);
        assert_eq!(body, b"{\"a\":1}\n");
    }

    #[test]
    fn a_rejection_is_reported_rather_than_hidden() {
        let raw = b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 30\r\n\r\nslow down";
        let (status, fields, body) = parse_http1(raw).expect("parsed");
        assert_eq!(status, 429);
        assert!(fields.contains(&("Retry-After".to_string(), "30".to_string())));
        assert_eq!(body, b"slow down");
    }

    #[test]
    fn a_headless_answer_is_an_error() {
        assert!(parse_http1(b"garbage").is_err());
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
        let (status, _, body) = parse_http1(&raw).expect("parsed");
        assert_eq!(status, 200);
        assert_eq!(body, text);

        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nabc\r\n";
        let (_, _, body) = parse_http1(raw).expect("parsed");
        assert!(body.is_empty());
    }

    #[test]
    fn an_authority_brackets_ipv6_and_leaves_out_port_443() {
        assert_eq!(
            authority("api.cloudflareclient.com", 443),
            "api.cloudflareclient.com"
        );
        assert_eq!(authority("1.1.1.1", 8443), "1.1.1.1:8443");
        assert_eq!(authority("2606:4700::1111", 443), "[2606:4700::1111]");
        assert_eq!(authority("::1", 853), "[::1]:853");
    }
}

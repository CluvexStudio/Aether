//! HTTPS over BoringSSL for the calls that are not tunnels: the direct route to the WARP API
//! and the DoH lookups of the ECH keys. The ClientHello is Chrome's, as apifront's chrome
//! fingerprint writes it, offering HTTP/2 then HTTP/1.1; the request goes over HTTP/2 when the
//! server picks it, over HTTP/1.1 otherwise.

use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::apifront::Fingerprint;
use crate::error::{AetherError, Result};
use crate::tls::CipherOption;

/// ALPN: HTTP/2, then HTTP/1.1, as Chrome offers them.
const ALPN_H2_HTTP1: &[u8] = b"\x02h2\x08http/1.1";

/// The most of an answer that is read.
const MAX_BODY: usize = 512 * 1024;

/// A request: `host` is the HTTP host, of Host or :authority, a name or an IP address, an IPv6
/// one without brackets, and `path` the path with its query. The connection goes to `host` on
/// `port`, and the ClientHello names `host`, unless `address` and `sni` name others.
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

/// Sends `request`, with the TLS 1.2 suites of `ciphers` when the option is given, and gives up
/// after `timeout`.
pub async fn send(
    request: &Request<'_>,
    ciphers: &CipherOption,
    timeout: Duration,
) -> Result<Response> {
    tokio::time::timeout(timeout, exchange(request, ciphers))
        .await
        .map_err(|_| {
            AetherError::Api(format!(
                "{} did not answer within {}s",
                authority(request.host, request.port),
                timeout.as_secs()
            ))
        })?
}

async fn exchange(request: &Request<'_>, ciphers: &CipherOption) -> Result<Response> {
    let address = request.address.unwrap_or(request.host);
    let tcp = dial(address, request.port).await?;
    let _ = tcp.set_nodelay(true);
    // TLS server-certificate verification disabled (unconditional), as the fingerprint has it:
    // the server name may be neither the HTTP host nor the address.
    let config = Fingerprint::ChromeLike.configure_for(ALPN_H2_HTTP1, ciphers)?;
    let tls = tokio_boring::connect(config, request.sni.unwrap_or(request.host), tcp)
        .await
        .map_err(|e| {
            AetherError::Tls(format!(
                "handshake with {}: {e}",
                authority(address, request.port)
            ))
        })?;
    if tls.ssl().selected_alpn_protocol() == Some(b"h2") {
        over_http2(tls, request).await
    } else {
        over_http1(tls, request).await
    }
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

    let (status, fields, body) = crate::apifront::parse_http1(&raw)?;
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

    /// A cipher option of the tests' own, so that no other test sees its variable.
    const CIPHERS: CipherOption = CipherOption {
        flag: "--https-test-ciphers",
        variable: "AETHER_HTTPS_TEST_CIPHERS",
    };

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
        let response = send(&request, &CIPHERS, Duration::from_secs(10))
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
        let response = send(&request, &CIPHERS, Duration::from_secs(5))
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

    #[tokio::test]
    async fn the_client_hello_is_chromes_with_http2_first_and_the_options_suites() {
        let _setting = crate::upstream::hold_setting().await;
        let hello = |list: Option<&'static str>| async move {
            let (address, hello) = crate::tls::client_hello::catch().await;
            if let Some(list) = list {
                std::env::set_var(CIPHERS.variable, list);
            }
            let headers = headers();
            let request = Request {
                method: "GET",
                host: "127.0.0.1",
                port: address.port(),
                address: None,
                sni: None,
                path: "/",
                headers: &headers,
                body: None,
            };
            assert!(send(&request, &CIPHERS, Duration::from_secs(10))
                .await
                .is_err());
            std::env::remove_var(CIPHERS.variable);
            hello.await.expect("the ClientHello")
        };

        let own = hello(None).await;
        assert_eq!(own.alpn(), [b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert_eq!(own.versions(), [0x0304, 0x0303]);
        assert!(own.has_grease());
        assert!(!own.tls12_suites().is_empty());

        // Every name BoringSSL knows, AES256-SHA among them, in the list's order.
        let listed = hello(Some(
            "ECDHE-ECDSA-CHACHA20-POLY1305:AES256-SHA:ECDHE-RSA-AES128-GCM-SHA256",
        ))
        .await;
        assert_eq!(listed.tls12_suites(), [0xcca9, 0x0035, 0xc02f]);
        assert_eq!(listed.alpn(), own.alpn());
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
        let response = send(&request, &CIPHERS, Duration::from_secs(10))
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

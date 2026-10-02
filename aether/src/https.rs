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

/// The largest header list an HTTP/2 answer may have: Chrome's.
const MAX_HEADER_LIST: u32 = 256 * 1024;

/// The longest line of a chunked body, a chunk size or a field of its trailer, that is read.
const MAX_LINE: usize = 8 * 1024;

/// A request: `host` is the HTTP host, of Host or :authority, a name or an IP address, an IPv6
/// one without brackets, on `port`, which Host and :authority leave out when it is 443, and
/// `path` the path with its query. The connection goes to `host` on `port`, and the ClientHello
/// names `host`, unless `address` and `sni` name others; offering ECH, the name goes inside the
/// encrypted ClientHello.
pub struct Request<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub port: u16,
    /// Where the connection goes instead of `host` on `port`: a name or an IP address, and its
    /// port.
    pub address: Option<(&'a str, u16)>,
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
    let (address, port) = request.address.unwrap_or((request.host, request.port));
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
        let tcp = dial(address, port).await?;
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
                        authority(address, port)
                    )));
                };
                log::debug!(
                    "[https] {} turned the ECH key down; offering the one it handed back ({} bytes)",
                    authority(address, port),
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
    // As Chrome: no server push, whose streams would cost memory MAX_BODY does not count.
    let mut builder = h2::client::Builder::new();
    builder
        .enable_push(false)
        .max_header_list_size(MAX_HEADER_LIST);
    let (client, connection) = builder
        .handshake(tls)
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

    let mut answer = Http1Answer::default();
    let mut chunk = [0u8; 8192];
    loop {
        match tls.read(&mut chunk).await {
            // The connection ended, with a close_notify or without one, which BoringSSL tells
            // alike: whether the answer came whole is for `finish` to say.
            Ok(0) => break,
            Ok(read) => {
                if answer.push(&chunk[..read])? {
                    break;
                }
            }
            Err(e) => return Err(failed(e)),
        }
    }

    let (status, fields, body) = answer.finish()?;
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

/// An HTTP/1.1 answer as it comes in, each byte looked at about once: its head, past any
/// interim (1xx) answers before it, then its body, which ends as RFC 9112 (6.3) has it: at
/// the head for a 204 or a 304, at the last chunk, after Content-Length bytes, or with the
/// connection.
#[derive(Default)]
struct Http1Answer {
    raw: Vec<u8>,
    /// Where the head being read starts: past the interim answers.
    head_start: usize,
    /// How far the search for the end of that head has looked.
    searched: usize,
    head: Option<Http1Head>,
}

struct Http1Head {
    status: u16,
    fields: Vec<(String, String)>,
    /// Where the body starts in the answer.
    body_start: usize,
    framing: Framing,
}

/// Where the body of an answer ends.
enum Framing {
    /// After this many bytes.
    Length(usize),
    /// At its last chunk and the end of its trailer.
    Chunked(Dechunker),
    /// With the connection.
    Close,
}

impl Http1Answer {
    /// Takes `bytes`, the next of the answer, and says whether the answer is whole.
    fn push(&mut self, bytes: &[u8]) -> Result<bool> {
        self.raw.extend_from_slice(bytes);
        if self.raw.len() > MAX_BODY {
            return Err(AetherError::Api("the answer is too large".into()));
        }
        while self.head.is_none() {
            let from = self.searched.saturating_sub(3).max(self.head_start);
            let Some(offset) = self.raw[from..]
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
            else {
                self.searched = self.raw.len();
                return Ok(false);
            };
            let end = from + offset;
            let (status, fields) = http1_head(&self.raw[self.head_start..end])?;
            if (100..200).contains(&status) && status != 101 {
                // An interim answer, before the answer itself.
                self.head_start = end + 4;
                self.searched = self.head_start;
                continue;
            }
            let framing = framing(status, &fields)?;
            self.head = Some(Http1Head {
                status,
                fields,
                body_start: end + 4,
                framing,
            });
        }
        let head = self.head.as_mut().expect("the head");
        let body = &self.raw[head.body_start..];
        Ok(match &mut head.framing {
            Framing::Length(length) => body.len() >= *length,
            Framing::Chunked(dechunker) => dechunker.advance(body)?,
            Framing::Close => false,
        })
    }

    /// The status, the header fields and the body of the answer once the connection has
    /// ended, the body joined when it was chunked; an error when the connection ended before
    /// the answer did.
    fn finish(self) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
        let Some(head) = self.head else {
            return Err(AetherError::Api(if self.raw.is_empty() {
                "empty response".into()
            } else {
                "truncated response head".into()
            }));
        };
        let body = &self.raw[head.body_start..];
        let body = match head.framing {
            Framing::Length(length) if body.len() < length => {
                return Err(AetherError::Api(format!(
                    "the answer ended after {} of its {length} bytes",
                    body.len()
                )))
            }
            Framing::Length(length) => body[..length].to_vec(),
            Framing::Chunked(dechunker) => dechunker.finish()?,
            Framing::Close => body.to_vec(),
        };
        Ok((head.status, head.fields, body))
    }
}

/// The status and the header fields of `head`, the head of an answer without its last CRLF.
fn http1_head(head: &[u8]) -> Result<(u16, Vec<(String, String)>)> {
    let head = String::from_utf8_lossy(head);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|token| token.parse::<u16>().ok())
        .ok_or_else(|| AetherError::Api(format!("bad status line: {status_line}")))?;
    let fields = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect();
    Ok((status, fields))
}

/// Where the body of an answer with `status` and header `fields` ends (RFC 9112, 6.3): chunked
/// goes before any Content-Length.
fn framing(status: u16, fields: &[(String, String)]) -> Result<Framing> {
    if status == 204 || status == 304 {
        return Ok(Framing::Length(0));
    }
    let field = |wanted: &str| {
        fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value)
    };
    if field("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        return Ok(Framing::Chunked(Dechunker::default()));
    }
    match field("content-length") {
        Some(value) => value
            .parse::<usize>()
            .map(Framing::Length)
            .map_err(|_| AetherError::Api(format!("bad Content-Length: {value}"))),
        None => Ok(Framing::Close),
    }
}

/// A chunked body (RFC 9112, 7.1), joined as it comes in, each byte looked at about once.
#[derive(Default)]
struct Dechunker {
    /// Where the next piece of the body starts: a chunk size, a chunk's data, or a field of
    /// the trailer.
    at: usize,
    /// How far the search for the end of the line at `at` has looked.
    searched: usize,
    /// The size of the chunk whose data comes next, when it is data that comes next.
    data: Option<usize>,
    /// Whether the last chunk has come, so that the trailer comes next.
    trailer: bool,
    done: bool,
    joined: Vec<u8>,
}

impl Dechunker {
    /// Goes on with `body`, the whole body so far, and says whether its last chunk and its
    /// trailer have come; an error for what is no chunked body.
    fn advance(&mut self, body: &[u8]) -> Result<bool> {
        let malformed = |what: &str| AetherError::Api(format!("a chunked answer with {what}"));
        while !self.done {
            if let Some(size) = self.data {
                // The chunk's data, then CRLF.
                let end = self
                    .at
                    .checked_add(size)
                    .and_then(|end| end.checked_add(2))
                    .ok_or_else(|| malformed("a chunk too large"))?;
                if body.len() < end {
                    return Ok(false);
                }
                if &body[end - 2..end] != b"\r\n" {
                    return Err(malformed("no line end after a chunk"));
                }
                self.joined.extend_from_slice(&body[self.at..end - 2]);
                self.at = end;
                self.searched = end;
                self.data = None;
                continue;
            }
            // A line: a chunk size, or a field of the trailer.
            let from = self.searched.saturating_sub(1).max(self.at);
            let Some(offset) = body[from..].windows(2).position(|window| window == b"\r\n") else {
                if body.len() - self.at > MAX_LINE {
                    return Err(malformed("a line too long"));
                }
                self.searched = body.len();
                return Ok(false);
            };
            let end = from + offset;
            let line = &body[self.at..end];
            self.at = end + 2;
            self.searched = self.at;
            if self.trailer {
                self.done = line.is_empty();
                continue;
            }
            let size = std::str::from_utf8(line)
                .ok()
                .and_then(|line| {
                    let size = line.split(';').next().unwrap_or("").trim();
                    usize::from_str_radix(size, 16).ok()
                })
                .ok_or_else(|| malformed("a bad chunk size"))?;
            match size {
                0 => self.trailer = true,
                size => self.data = Some(size),
            }
        }
        Ok(true)
    }

    /// The body, joined; an error unless its last chunk and its trailer have come.
    fn finish(self) -> Result<Vec<u8>> {
        if self.done {
            Ok(self.joined)
        } else {
            Err(AetherError::Api(
                "the chunked answer ended before its last chunk".into(),
            ))
        }
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
            // The client turned server push off in its settings, as Chrome does.
            let push = http::Request::get("https://127.0.0.1/pushed")
                .body(())
                .unwrap();
            assert!(respond.push_request(push).is_err(), "a push went through");
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
            address: Some(("127.0.0.1", address.port())),
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
        assert_eq!(
            own.tls12_suites(),
            crate::tls::client_hello::chrome_tls12_suites()
        );

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
        assert_eq!(
            outer.tls12_suites(),
            crate::tls::client_hello::chrome_tls12_suites()
        );
        assert_eq!(outer.alpn(), [b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[tokio::test]
    async fn a_key_that_cannot_be_offered_goes_no_further() {
        let _setting = crate::upstream::hold_setting().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let headers = headers();
        let port = listener.local_addr().expect("its address").port();
        let request = Request {
            method: "GET",
            host: "api.example.test",
            port,
            address: Some(("127.0.0.1", port)),
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
    /// machine, sent to `address` with `sni` when given. The host is on the port the server
    /// listens on, or on `port` when given, as the address is on the server's port.
    async fn server_name_and_authority(
        host: &str,
        port: Option<u16>,
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
            port: port.unwrap_or(listening.port()),
            address: address.map(|address| (address, listening.port())),
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
            None,
            Some("127.0.0.1"),
            Some("front.example.test"),
        )
        .await;
        assert_eq!(name.as_deref(), Some("front.example.test"));
        assert!(authority.starts_with("doh.example.test:"), "{authority}");

        // Without them the host is all three: the address, the server name and the HTTP host.
        let (name, authority) = server_name_and_authority("localhost", None, None, None).await;
        assert_eq!(name.as_deref(), Some("localhost"));
        assert!(authority.starts_with("localhost:"), "{authority}");

        // An address on a port of its own: the connection goes there, while the host keeps
        // its port, 443, which the authority leaves out.
        let (name, authority) =
            server_name_and_authority("api.example.test", Some(443), Some("127.0.0.1"), None).await;
        assert_eq!(name.as_deref(), Some("api.example.test"));
        assert_eq!(authority, "api.example.test");
    }

    /// Whether `raw` is a whole HTTP/1.1 answer, read at once. Read a byte at a time, it has
    /// to turn whole on its last byte and not before.
    fn whole(raw: &[u8]) -> bool {
        let at_once = Http1Answer::default().push(raw).expect("an answer so far");
        let mut answer = Http1Answer::default();
        for (index, byte) in raw.iter().enumerate() {
            let now = answer
                .push(std::slice::from_ref(byte))
                .expect("an answer so far");
            assert_eq!(now, at_once && index + 1 == raw.len(), "byte {index}");
        }
        at_once
    }

    /// `raw` read as an HTTP/1.1 answer that the connection ends after.
    fn read(raw: &[u8]) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
        let mut answer = Http1Answer::default();
        answer.push(raw)?;
        answer.finish()
    }

    #[test]
    fn an_answer_is_whole_by_its_length_or_its_last_chunk() {
        assert!(whole(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
        assert!(!whole(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok"));
        assert!(!whole(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"));
        assert!(!whole(b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nok"));
        // A 204 ends with its head.
        assert!(whole(b"HTTP/1.1 204 No Content\r\nServer: x\r\n\r\n"));

        assert!(whole(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"
        ));
        // The bytes of a last chunk at the end of a chunk's data end nothing.
        assert!(!whole(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nabcd0\r\n\r\n"
        ));
        // A trailer comes before the end.
        assert!(!whole(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Sum: 1\r\n"
        ));
        assert!(whole(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Sum: 1\r\n\r\n"
        ));
        // Chunk sizes with leading zeros, in upper case, with an extension.
        assert!(whole(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n00A;x=y\r\n0123456789\r\n0\r\n\r\n"
        ));
    }

    #[test]
    fn a_plain_answer_is_parsed() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":\"x\"}";
        let (status, fields, body) = read(raw).expect("parsed");
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
        let (status, _, body) = read(raw).expect("parsed");
        assert_eq!(status, 200);
        assert_eq!(body, b"{\"a\":1}\n");
    }

    #[test]
    fn a_rejection_is_reported_rather_than_hidden() {
        let raw = b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 30\r\n\r\nslow down";
        let (status, fields, body) = read(raw).expect("parsed");
        assert_eq!(status, 429);
        assert!(fields.contains(&("Retry-After".to_string(), "30".to_string())));
        assert_eq!(body, b"slow down");
    }

    #[test]
    fn a_headless_answer_is_an_error() {
        assert!(read(b"garbage").is_err());
        assert!(read(b"").is_err());
        assert!(read(b"\r\n\r\n").is_err());
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
        assert!(whole(&raw));
        let (status, _, body) = read(&raw).expect("parsed");
        assert_eq!(status, 200);
        assert_eq!(body, text);
    }

    #[test]
    fn what_is_no_chunked_body_is_an_error() {
        let chunked = |body: &[u8]| {
            let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            raw.extend_from_slice(body);
            Http1Answer::default().push(&raw)
        };
        // A chunk size past what memory holds overflows nothing.
        assert!(chunked(b"ffffffffffffffff\r\nabc").is_err());
        assert!(chunked(b"zz\r\nabc").is_err());
        assert!(chunked(b"\r\nabc").is_err());
        assert!(chunked(b"2\r\nokX\r\n0\r\n\r\n").is_err());
        assert!(chunked(&vec![b'1'; MAX_LINE + 1]).is_err());
    }

    #[test]
    fn an_answer_the_connection_cuts_short_is_an_error_not_a_body() {
        let cut = read(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc").expect_err("cut");
        assert!(cut.to_string().contains("3 of its 10 bytes"), "{cut}");
        assert!(read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n").is_err());
        assert!(read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n").is_err());
        assert!(read(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n").is_err());
        assert!(read(b"HTTP/1.1 200 OK\r\nContent-Length: two\r\n\r\nok").is_err());
    }

    #[test]
    fn a_body_ends_where_its_head_says() {
        // Past Content-Length, nothing belongs to the answer.
        let (_, _, body) = read(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA").unwrap();
        assert_eq!(body, b"ok");
        // Chunked goes before a Content-Length (RFC 9112, 6.3).
        let both = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut raw = both.to_vec();
        raw.extend_from_slice(b"5\r\nhe");
        assert!(!Http1Answer::default().push(&raw).unwrap());
        assert!(read(&raw).is_err());
        raw.extend_from_slice(b"llo\r\n0\r\n\r\n");
        assert!(whole(&raw));
        assert_eq!(read(&raw).unwrap().2, b"hello");
    }

    #[test]
    fn an_interim_answer_is_passed_over() {
        let raw = b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        assert!(whole(raw));
        let (status, fields, body) = read(raw).expect("parsed");
        assert_eq!(status, 200);
        assert_eq!(fields, [("Content-Length".to_string(), "2".to_string())]);
        assert_eq!(body, b"ok");
    }

    #[test]
    fn an_answer_that_comes_a_byte_at_a_time_is_read_in_linear_time() {
        // Chunks of one byte, the most lines an answer can have, then a head that never ends:
        // each read looks at its own bytes, not at all that came before.
        let mut chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        while chunked.len() < 200 * 1024 {
            chunked.extend_from_slice(b"1\r\na\r\n");
        }
        chunked.extend_from_slice(b"0\r\n\r\n");
        let endless_head = [b'x'; 200 * 1024];
        let started = std::time::Instant::now();
        for raw in [&chunked[..], &endless_head[..]] {
            let mut answer = Http1Answer::default();
            let mut ended = false;
            for byte in raw {
                ended = answer
                    .push(std::slice::from_ref(byte))
                    .expect("an answer so far");
            }
            assert_eq!(ended, raw.len() == chunked.len());
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
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

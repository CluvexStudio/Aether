use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{AetherError, Result};
use crate::netstack::StackHandle;
use crate::routing::{Action, Host, RuleSet};
use crate::socks;

/// Minimal HTTP CONNECT proxy (and absolute-URI GET/POST for plain HTTP).
/// Used by the port 1820

static ROUTES: std::sync::OnceLock<RuleSet> = std::sync::OnceLock::new();

fn routes() -> &'static RuleSet {
    ROUTES.get_or_init(RuleSet::from_env)
}

pub async fn serve(listen: SocketAddr, stack: StackHandle) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    log::info!("http proxy listening on {listen}");

    loop {
        let (sock, peer) = listener.accept().await?;
        let stack = stack.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(sock, stack).await {
                log::debug!("http proxy client {peer} ended: {e}");
            }
        });
    }
}

async fn handle_client(sock: TcpStream, stack: StackHandle) -> Result<()> {
    let mut reader = BufReader::new(sock);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    if request_line.is_empty() {
        return Ok(());
    }

    // Drain headers (we ignore them for CONNECT / simple proxy).
    let mut header = String::new();
    loop {
        header.clear();
        let n = reader.read_line(&mut header).await?;
        if n == 0 {
            break;
        }
        let t = header.trim_end();
        if t.is_empty() {
            break;
        }
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(AetherError::Other("bad http request line".into()));
    }
    let method = parts[0].to_ascii_uppercase();
    let target = parts[1];

    let (host, port) = if method == "CONNECT" {
        parse_host_port(target, 443)?
    } else {
        // Absolute-form: GET http://host:port/path HTTP/1.1
        parse_absolute_uri(target)?
    };

    // Route decision – same logic as socks.rs
    let host_enum = if let Ok(ip) = host.parse::<IpAddr>() {
        Host::Ip(ip)
    } else {
        Host::Domain(host.as_str())
    };
    match routes().decide(host_enum, port) {
        Action::Block => {
            log::debug!("[route] block http {host}:{port}");
            let mut sock = reader.into_inner();
            let _ = sock
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
        Action::Direct => {
            log::debug!("[route] direct http {host}:{port}");
            return handle_direct(reader.into_inner(), &host, port).await;
        }
        Action::Proxy => {}
    }

    let ip = if let Ok(ip) = host.parse::<IpAddr>() {
        ip
    } else {
        socks::dns_resolve(&stack, &host).await?
    };
    let dst = SocketAddr::new(ip, port);

    let conn = match stack.open_tcp(dst).await {
        Ok(c) => c,
        Err(e) => {
            let mut sock = reader.into_inner();
            let _ = sock
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            return Err(e);
        }
    };

    let mut sock = reader.into_inner();

    if method == "CONNECT" {
        sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        relay_bidirectional(sock, conn).await
    } else {
        // Rebuild a relative request for the origin server.
        let path = absolute_uri_path(target);
        let rebuilt = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        let (sender, mut from_stack) = conn.into_split();
        if sender.send(rebuilt.into_bytes()).await.is_err() {
            return Err(AetherError::Other("tunnel send failed".into()));
        }
        let (mut rd, mut wr) = sock.into_split();

        let up = tokio::spawn(async move {
            let mut buf = vec![0u8; 32768];
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
}

async fn relay_bidirectional(sock: TcpStream, conn: crate::netstack::TcpConn) -> Result<()> {
    let (sender, mut from_stack) = conn.into_split();
    let (mut rd, mut wr) = sock.into_split();

    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 32768];
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

async fn handle_direct(mut sock: TcpStream, host: &str, port: u16) -> Result<()> {
    use std::time::Duration;

    let address = format!("{host}:{port}");

    let upstream = match tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(&address),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            log::debug!("[route] direct connect to {address} failed: {error}");
            let _ = sock
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
        Err(_) => {
            log::debug!("[route] direct connect to {address} timed out");
            let _ = sock
                .write_all(b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    };

    let _ = upstream.set_nodelay(true);
    let _ = sock
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await;

    let (mut client_rd, mut client_wr) = sock.into_split();
    let (mut remote_rd, mut remote_wr) = upstream.into_split();

    let up = tokio::spawn(async move { tokio::io::copy(&mut client_rd, &mut remote_wr).await });
    let _ = tokio::io::copy(&mut remote_rd, &mut client_wr).await;
    let _ = client_wr.shutdown().await;
    up.abort();
    Ok(())
}

fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        // [ipv6]:port
        let end = rest
            .find(']')
            .ok_or_else(|| AetherError::Other("bad ipv6 host".into()))?;
        let host = rest[..end].to_string();
        let port = if rest[end + 1..].starts_with(':') {
            rest[end + 2..]
                .parse()
                .map_err(|_| AetherError::Other("bad port".into()))?
        } else {
            default_port
        };
        return Ok((host, port));
    }
    if let Some((h, p)) = s.rsplit_once(':') {
        if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            let port: u16 = p
                .parse()
                .map_err(|_| AetherError::Other("bad port".into()))?;
            return Ok((h.to_string(), port));
        }
    }
    Ok((s.to_string(), default_port))
}

fn parse_absolute_uri(uri: &str) -> Result<(String, u16)> {
    let uri = uri.trim();
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))
        .unwrap_or(uri);
    let authority = rest.split('/').next().unwrap_or(rest);
    let default = if uri.starts_with("https://") { 443 } else { 80 };
    parse_host_port(authority, default)
}

fn absolute_uri_path(uri: &str) -> String {
    let uri = uri.trim();
    if let Some(rest) = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))
    {
        if let Some(idx) = rest.find('/') {
            return rest[idx..].to_string();
        }
        return "/".to_string();
    }
    if uri.starts_with('/') {
        uri.to_string()
    } else {
        format!("/{uri}")
    }
}

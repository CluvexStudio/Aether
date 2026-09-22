use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::error::{AetherError, Result};

static MARK: AtomicU32 = AtomicU32::new(0);

pub fn init() -> Result<()> {
    let raw = match std::env::var("AETHER_MARK") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            MARK.store(0, Ordering::Relaxed);
            return Ok(());
        }
    };

    let mark = parse_mark(&raw).ok_or_else(|| {
        AetherError::Other(format!(
            "'{}' is not a socket mark; give a number such as 255 or 0xff",
            raw.trim()
        ))
    })?;

    if mark == 0 {
        MARK.store(0, Ordering::Relaxed);
        return Ok(());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let probe = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        probe.set_mark(mark).map_err(|error| {
            AetherError::Other(format!(
                "cannot mark sockets with {mark:#x}: {error}; marking needs root or CAP_NET_ADMIN"
            ))
        })?;
        MARK.store(mark, Ordering::Relaxed);
        log::info!("[+] outgoing sockets carry firewall mark {mark:#x}");
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    log::warn!("[-] --mark only works on Linux and Android; sockets stay unmarked here");

    Ok(())
}

fn parse_mark(raw: &str) -> Option<u32> {
    let text = raw.trim();
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => text.parse::<u32>().ok(),
    }
}

pub fn mark() -> u32 {
    MARK.load(Ordering::Relaxed)
}

pub fn apply(socket: SockRef<'_>) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mark = MARK.load(Ordering::Relaxed);
        if mark != 0 {
            socket.set_mark(mark)?;
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = socket;
    Ok(())
}

pub async fn tcp_connect(address: SocketAddr) -> io::Result<TcpStream> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    apply(SockRef::from(&socket))?;
    socket.connect(address).await
}

pub async fn tcp_connect_host(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut last_error = None;
    for address in tokio::net::lookup_host((host, port)).await? {
        match tcp_connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{host} did not resolve to any address"),
        )
    }))
}

pub fn udp_bind(address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    apply(SockRef::from(&socket))?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    UdpSocket::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_are_read_in_decimal_and_in_hex() {
        assert_eq!(parse_mark("255"), Some(255));
        assert_eq!(parse_mark(" 0xff "), Some(255));
        assert_eq!(parse_mark("0X1F"), Some(31));
        assert_eq!(parse_mark("0"), Some(0));
        assert_eq!(parse_mark("mark"), None);
        assert_eq!(parse_mark("-1"), None);
        assert_eq!(parse_mark("0x1_0000_0000"), None);
    }

    #[tokio::test]
    async fn unmarked_sockets_still_connect_and_bind() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (dialed, accepted) = tokio::join!(tcp_connect(address), listener.accept());
        assert!(dialed.is_ok() && accepted.is_ok());

        let host = tcp_connect_host("localhost", address.port());
        let (dialed, _) = tokio::join!(host, listener.accept());
        assert!(dialed.is_ok(), "a name resolves and connects");

        let socket = udp_bind("127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(socket.local_addr().unwrap().port() != 0);
    }
}

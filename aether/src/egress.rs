use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
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

/// How long a connection attempt runs alone before the next address is tried beside it
/// (RFC 8305, the Connection Attempt Delay).
const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// A TCP connection to `host`, a name or an IP address, on `port`. The addresses a name
/// resolves to are tried as RFC 8305 has it, so that one whose packets vanish, an IPv6 one on
/// a network whose IPv6 is broken say, holds the others up by a quarter of a second rather
/// than by the whole time the caller allows.
pub async fn tcp_connect_host(host: &str, port: u16) -> io::Result<TcpStream> {
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{host} did not resolve to any address"),
        ));
    }
    race(
        interleaved(addresses),
        CONNECTION_ATTEMPT_DELAY,
        tcp_connect,
    )
    .await
}

/// `addresses` in the order to try them: one of the family of the first, then one of the
/// other, by turns, each family in its own order (RFC 8305, 4).
fn interleaved(addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(lead_v4) = addresses.first().map(SocketAddr::is_ipv4) else {
        return addresses;
    };
    let (mut lead, mut other): (VecDeque<_>, VecDeque<_>) = addresses
        .into_iter()
        .partition(|address| address.is_ipv4() == lead_v4);
    let mut order = Vec::with_capacity(lead.len() + other.len());
    while !lead.is_empty() || !other.is_empty() {
        order.extend(lead.pop_front());
        order.extend(other.pop_front());
    }
    order
}

/// The first connection `connect` opens to one of `addresses`, tried in order: each attempt
/// runs alone for `delay`, or until it fails, before the next starts beside it, and the first
/// to connect wins (RFC 8305, 5); the others are dropped. When all of them fail, the error of
/// the last to fail.
async fn race<T, F, A>(addresses: Vec<SocketAddr>, delay: Duration, connect: F) -> io::Result<T>
where
    F: Fn(SocketAddr) -> A,
    A: Future<Output = io::Result<T>>,
{
    let mut waiting = addresses.into_iter();
    let mut attempts = FuturesUnordered::new();
    let mut last_error = None;
    loop {
        if attempts.is_empty() {
            match waiting.next() {
                Some(address) => attempts.push(connect(address)),
                None => {
                    return Err(last_error.unwrap_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "no address to connect to")
                    }))
                }
            }
        }
        tokio::select! {
            Some(outcome) = attempts.next() => match outcome {
                Ok(stream) => return Ok(stream),
                // A failed attempt makes way for the next one at once.
                Err(error) => {
                    last_error = Some(error);
                    attempts.extend(waiting.next().map(&connect));
                }
            },
            _ = tokio::time::sleep(delay) => attempts.extend(waiting.next().map(&connect)),
        }
    }
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

    fn at(text: &str) -> SocketAddr {
        text.parse().expect("an address")
    }

    #[test]
    fn the_addresses_of_a_name_are_tried_by_turns_of_family() {
        let (v6a, v6b) = (at("[2606:4700::1]:443"), at("[2606:4700::2]:443"));
        let (v4a, v4b, v4c) = (
            at("104.16.0.1:443"),
            at("104.16.0.2:443"),
            at("104.16.0.3:443"),
        );
        assert_eq!(
            interleaved(vec![v6a, v6b, v4a, v4b, v4c]),
            [v6a, v4a, v6b, v4b, v4c]
        );
        assert_eq!(interleaved(vec![v4a, v6a, v4b, v6b]), [v4a, v6a, v4b, v6b]);
        assert_eq!(interleaved(vec![v4a, v4b, v6a]), [v4a, v6a, v4b]);
        assert_eq!(interleaved(vec![v4a]), [v4a]);
        assert!(interleaved(Vec::new()).is_empty());
    }

    /// An attempt for `race` that never answers on port 1, fails at once on port 2, and
    /// connects at once on any other port, which it gives back.
    async fn attempt(address: SocketAddr) -> io::Result<u16> {
        match address.port() {
            1 => std::future::pending().await,
            2 => Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused")),
            port => Ok(port),
        }
    }

    /// `race` over `addresses`, which has to end within five seconds.
    async fn raced(addresses: Vec<SocketAddr>, delay: Duration) -> io::Result<u16> {
        tokio::time::timeout(Duration::from_secs(5), race(addresses, delay, attempt))
            .await
            .expect("an end within five seconds")
    }

    #[tokio::test]
    async fn an_address_that_never_answers_holds_the_next_up_by_the_delay_alone() {
        let started = std::time::Instant::now();
        let delay = Duration::from_millis(100);
        let won = raced(vec![at("10.0.0.1:1"), at("10.0.0.2:443")], delay).await;
        assert_eq!(won.ok(), Some(443));
        assert!(started.elapsed() >= delay);
    }

    #[tokio::test]
    async fn a_failed_attempt_makes_way_for_the_next_at_once() {
        let delay = Duration::from_secs(30);
        let won = raced(vec![at("10.0.0.1:2"), at("10.0.0.2:443")], delay).await;
        assert_eq!(won.ok(), Some(443));
    }

    #[tokio::test]
    async fn the_first_to_connect_wins_and_the_rest_are_never_tried() {
        let tried = std::sync::Mutex::new(Vec::new());
        let addresses = vec![at("10.0.0.1:443"), at("10.0.0.2:8443")];
        let won = race(addresses, Duration::from_secs(30), |address| {
            tried.lock().unwrap().push(address);
            attempt(address)
        })
        .await;
        assert_eq!(won.ok(), Some(443));
        assert_eq!(*tried.lock().unwrap(), [at("10.0.0.1:443")]);
    }

    #[tokio::test]
    async fn when_every_attempt_fails_the_last_error_is_given() {
        let delay = Duration::from_millis(10);
        let failed = raced(vec![at("10.0.0.1:2"), at("10.0.0.2:2")], delay).await;
        assert_eq!(
            failed.expect_err("no connection").kind(),
            io::ErrorKind::ConnectionRefused
        );
        let none = raced(Vec::new(), delay).await;
        assert_eq!(
            none.expect_err("nothing to try").kind(),
            io::ErrorKind::NotFound
        );
    }
}

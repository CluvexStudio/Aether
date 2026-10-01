use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout_at;

use crate::error::{AetherError, Result};

/// The resolver the ECHConfigList is asked for unless --ech-dns names another.
pub const DEFAULT_ECH_DNS: &str = "udp://1.1.1.1";

/// The domain whose ECHConfigList the handshakes offer unless --ech-domain names another.
pub const DEFAULT_ECH_DOMAIN: &str = "cloudflare-ech.com";

const RR_HTTPS: u16 = 65;
const SVCPARAM_ECH: u16 = 5;

/// How long the lookup of the ECHConfigList may take, over any transport.
const ECH_LOOKUP_TIMEOUT: Duration = Duration::from_secs(12);

/// Over UDP the question goes out again after this long without an answer, until the
/// lookup gives up.
const UDP_RESEND_AFTER: Duration = Duration::from_secs(2);

/// The resolver the ECHConfigList is asked for: a DNS server over UDP or TCP, or a
/// DNS-over-HTTPS endpoint (RFC 8484).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EchDns {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Https(String),
}

impl EchDns {
    /// The resolver `value` names: `udp://ip[:port]` or `tcp://ip[:port]`, on port 53
    /// unless one is given and with an IPv6 address in brackets, or an `https://` URL,
    /// on port 443 unless it names one.
    pub fn parse(value: &str) -> std::result::Result<Self, String> {
        let value = value.trim();
        if let Some(rest) = strip_scheme(value, "https://") {
            let host = rest.split(['/', '?', '#']).next().unwrap_or("");
            return if host.is_empty() {
                Err(format!("{value} names no host"))
            } else {
                Ok(EchDns::Https(value.to_string()))
            };
        }
        let (rest, tcp) = if let Some(rest) = strip_scheme(value, "udp://") {
            (rest, false)
        } else if let Some(rest) = strip_scheme(value, "tcp://") {
            (rest, true)
        } else {
            return Err(format!("{value} is no udp://, tcp:// or https:// address"));
        };
        let address = socket_address(rest.trim_end_matches('/'), 53)
            .ok_or_else(|| format!("{value} names no IP address"))?;
        Ok(if tcp {
            EchDns::Tcp(address)
        } else {
            EchDns::Udp(address)
        })
    }
}

impl std::fmt::Display for EchDns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EchDns::Udp(address) => write!(f, "udp://{address}"),
            EchDns::Tcp(address) => write!(f, "tcp://{address}"),
            EchDns::Https(url) => f.write_str(url),
        }
    }
}

/// `value` after `scheme`, which it starts with in any case; None when it does not.
fn strip_scheme<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    let head = value.get(..scheme.len())?;
    if head.eq_ignore_ascii_case(scheme) {
        Some(&value[scheme.len()..])
    } else {
        None
    }
}

/// `text` as an address: `ip:port`, `[ipv6]:port`, or an IP address alone, on
/// `default_port`.
fn socket_address(text: &str, default_port: u16) -> Option<SocketAddr> {
    if let Ok(address) = text.parse::<SocketAddr>() {
        return Some(address);
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, default_port));
    }
    let inner = text.strip_prefix('[')?.strip_suffix(']')?;
    inner
        .parse::<Ipv6Addr>()
        .ok()
        .map(|ip| SocketAddr::new(IpAddr::V6(ip), default_port))
}

/// Whether `name` is a domain whose HTTPS record can be asked for: labels of letters,
/// digits, '-' and '_', of 1 to 63 bytes each and 253 in all, a trailing dot allowed.
pub fn valid_domain(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// The resolver of --ech-dns (AETHER_ECH_DNS), or the default one.
fn configured_dns() -> std::result::Result<EchDns, String> {
    let value = std::env::var("AETHER_ECH_DNS").unwrap_or_default();
    let value = value.trim();
    EchDns::parse(if value.is_empty() {
        DEFAULT_ECH_DNS
    } else {
        value
    })
}

/// The domain of --ech-domain (AETHER_ECH_DOMAIN), or the default one.
fn configured_domain() -> std::result::Result<String, String> {
    let value = std::env::var("AETHER_ECH_DOMAIN").unwrap_or_default();
    let value = value.trim();
    let name = if value.is_empty() {
        DEFAULT_ECH_DOMAIN
    } else {
        value
    };
    if valid_domain(name) {
        Ok(name.trim_end_matches('.').to_string())
    } else {
        Err(format!("{name} is no domain name"))
    }
}

/// Fetches the ECHConfigList the handshakes offer: the ech parameter of the HTTPS
/// record of the domain of --ech-domain, asked of the resolver of --ech-dns, through
/// the upstream proxy when there is one.
pub async fn fetch_ech_config() -> Result<Vec<u8>> {
    let dns = configured_dns().map_err(|e| AetherError::Ech(format!("--ech-dns: {e}")))?;
    let domain = configured_domain().map_err(|e| AetherError::Ech(format!("--ech-domain: {e}")))?;
    let lookup = async {
        match &dns {
            EchDns::Udp(server) => query_udp(*server, &domain).await,
            EchDns::Tcp(server) => query_tcp(*server, &domain).await,
            EchDns::Https(url) => query_https(url, &domain).await,
        }
    };
    let ech = match tokio::time::timeout(ECH_LOOKUP_TIMEOUT, lookup).await {
        Ok(Ok(ech)) => ech,
        Ok(Err(e)) => {
            let reason = match e {
                AetherError::Ech(reason) => reason,
                other => other.to_string(),
            };
            return Err(AetherError::Ech(format!(
                "{domain} via {dns} failed: {reason}"
            )));
        }
        Err(_) => {
            return Err(AetherError::Ech(format!(
                "{dns} did not answer for {domain}"
            )));
        }
    };
    log::info!(
        "fetched ECHConfigList ({} bytes) for {domain} via {dns}",
        ech.len()
    );
    Ok(ech)
}

async fn query_udp(server: SocketAddr, domain: &str) -> Result<Vec<u8>> {
    let (sock, _, _detour) = crate::upstream::bind_via_upstream(server).await?;
    let (query, id) = build_query(domain, RR_HTTPS);
    let mut buf = [0u8; 4096];

    // Asked again and again until an answer comes or the lookup gives up, see
    // fetch_ech_config.
    loop {
        sock.send(&query).await?;
        let resend_at = tokio::time::Instant::now() + UDP_RESEND_AFTER;
        while let Ok(received) = timeout_at(resend_at, sock.recv(&mut buf)).await {
            let n = received?;
            if response_matches(&buf[..n], id, domain, RR_HTTPS) {
                return answer_ech(&buf[..n], domain);
            }
            log::debug!("discarding an ech dns reply that does not match the query");
        }
    }
}

async fn query_tcp(server: SocketAddr, domain: &str) -> Result<Vec<u8>> {
    let mut stream = match crate::upstream::configured() {
        Some(proxy) => proxy.connect(server).await?,
        None => crate::egress::tcp_connect(server).await?,
    };
    let (query, id) = build_query(domain, RR_HTTPS);
    stream.write_all(&tcp_message(&query)).await?;

    let mut length = [0u8; 2];
    stream.read_exact(&mut length).await?;
    let mut msg = vec![0u8; u16::from_be_bytes(length) as usize];
    stream.read_exact(&mut msg).await?;

    if !response_matches(&msg, id, domain, RR_HTTPS) {
        return Err(AetherError::Ech(
            "the reply does not match the query".into(),
        ));
    }
    answer_ech(&msg, domain)
}

async fn query_https(url: &str, domain: &str) -> Result<Vec<u8>> {
    let mut builder = reqwest::Client::builder()
        .timeout(ECH_LOOKUP_TIMEOUT)
        // TLS server-certificate verification disabled (unconditional).
        .danger_accept_invalid_certs(true);
    if let Some(upstream) = crate::upstream::configured() {
        builder = builder.proxy(upstream.as_reqwest_proxy()?);
    }
    let client = builder
        .build()
        .map_err(|e| AetherError::Ech(e.to_string()))?;

    // RFC 8484 asks for the ID 0, which keeps the answers cacheable.
    let (mut query, _) = build_query(domain, RR_HTTPS);
    query[0] = 0;
    query[1] = 0;
    let response = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
        .header(reqwest::header::ACCEPT, "application/dns-message")
        .body(query)
        .send()
        .await
        .map_err(|e| AetherError::Ech(e.to_string()))?;
    if !response.status().is_success() {
        return Err(AetherError::Ech(format!("answered {}", response.status())));
    }
    let msg = response
        .bytes()
        .await
        .map_err(|e| AetherError::Ech(e.to_string()))?;

    if !response_matches(&msg, 0, domain, RR_HTTPS) {
        return Err(AetherError::Ech(
            "the reply does not match the query".into(),
        ));
    }
    answer_ech(&msg, domain)
}

/// `msg` as it goes over TCP: behind its length, in two bytes in network order (RFC
/// 1035, 4.2.2).
fn tcp_message(msg: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(msg.len() + 2);
    framed.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    framed.extend_from_slice(msg);
    framed
}

/// The ech parameter of the HTTPS record in `msg`, a reply about `domain`.
fn answer_ech(msg: &[u8], domain: &str) -> Result<Vec<u8>> {
    match parse_https_ech(msg) {
        Some(ech) if !ech.is_empty() => Ok(ech),
        _ => Err(AetherError::Ech(format!(
            "{domain} has no HTTPS record with an ech parameter"
        ))),
    }
}

pub fn response_matches(
    msg: &[u8],
    expected_id: u16,
    expected_name: &str,
    expected_qtype: u16,
) -> bool {
    if msg.len() < 12 {
        return false;
    }
    if u16::from_be_bytes([msg[0], msg[1]]) != expected_id {
        return false;
    }
    if msg[2] & 0x80 == 0 {
        return false;
    }
    if u16::from_be_bytes([msg[4], msg[5]]) != 1 {
        return false;
    }

    let mut pos = 12;
    for label in expected_name.split('.') {
        if label.is_empty() {
            continue;
        }
        let len = match msg.get(pos) {
            Some(value) => *value as usize,
            None => return false,
        };
        if len != label.len() {
            return false;
        }
        pos += 1;
        let end = match pos.checked_add(len) {
            Some(value) if value <= msg.len() => value,
            _ => return false,
        };
        if !msg[pos..end].eq_ignore_ascii_case(label.as_bytes()) {
            return false;
        }
        pos = end;
    }

    if msg.get(pos) != Some(&0) {
        return false;
    }
    pos += 1;

    if pos + 4 > msg.len() {
        return false;
    }

    u16::from_be_bytes([msg[pos], msg[pos + 1]]) == expected_qtype
}

fn build_query(name: &str, qtype: u16) -> (Vec<u8>, u16) {
    let mut q = Vec::with_capacity(32 + name.len());
    let id: u16 = rand::random();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0x00, 0x01]);
    (q, id)
}

fn parse_https_ech(msg: &[u8]) -> Option<Vec<u8>> {
    if msg.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;

    for _ in 0..qd {
        pos = skip_name(msg, pos)?;
        pos = pos.checked_add(4)?;
    }

    for _ in 0..an {
        pos = skip_name(msg, pos)?;
        if pos + 10 > msg.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            return None;
        }
        if rtype == RR_HTTPS {
            if let Some(ech) = parse_svcparams_ech(msg, pos, rdlen) {
                return Some(ech);
            }
        }
        pos += rdlen;
    }
    None
}

fn parse_svcparams_ech(msg: &[u8], rdata_start: usize, rdlen: usize) -> Option<Vec<u8>> {
    let end = rdata_start + rdlen;
    if rdata_start + 2 > end {
        return None;
    }
    let mut p = skip_name(msg, rdata_start + 2)?;

    while p + 4 <= end {
        let key = u16::from_be_bytes([msg[p], msg[p + 1]]);
        let len = u16::from_be_bytes([msg[p + 2], msg[p + 3]]) as usize;
        p += 4;
        if p + len > end {
            return None;
        }
        if key == SVCPARAM_ECH {
            return Some(msg[p..p + len].to_vec());
        }
        p += len;
    }
    None
}

fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)?;
        if len & 0xc0 == 0xc0 {
            return Some(pos + 2);
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos += 1 + len as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ech_dns_names_a_resolver_over_udp_tcp_or_https() {
        let at = |text: &str| text.parse::<SocketAddr>().unwrap();
        assert_eq!(
            EchDns::parse("udp://1.1.1.1"),
            Ok(EchDns::Udp(at("1.1.1.1:53")))
        );
        assert_eq!(
            EchDns::parse(" UDP://8.8.8.8:5353 "),
            Ok(EchDns::Udp(at("8.8.8.8:5353")))
        );
        assert_eq!(
            EchDns::parse("tcp://1.1.1.1"),
            Ok(EchDns::Tcp(at("1.1.1.1:53")))
        );
        assert_eq!(
            EchDns::parse("tcp://[2606:4700:4700::1111]"),
            Ok(EchDns::Tcp(at("[2606:4700:4700::1111]:53")))
        );
        assert_eq!(
            EchDns::parse("udp://[::1]:5353/"),
            Ok(EchDns::Udp(at("[::1]:5353")))
        );
        assert_eq!(
            EchDns::parse("https://doq.dns4all.eu/dns-query"),
            Ok(EchDns::Https(
                "https://doq.dns4all.eu/dns-query".to_string()
            ))
        );
        assert_eq!(
            EchDns::parse("https://1.1.1.1:8443/dns-query"),
            Ok(EchDns::Https("https://1.1.1.1:8443/dns-query".to_string()))
        );
        assert_eq!(
            EchDns::parse(DEFAULT_ECH_DNS),
            Ok(EchDns::Udp(at("1.1.1.1:53")))
        );
        assert_eq!(
            EchDns::parse("tcp://[::1]").unwrap().to_string(),
            "tcp://[::1]:53"
        );
    }

    #[test]
    fn an_ech_dns_without_a_scheme_or_an_ip_address_is_refused() {
        for text in [
            "1.1.1.1",
            "dns.google",
            "tls://1.1.1.1",
            "udp://dns.google",
            "tcp://",
            "udp://1.1.1.1:99999",
            "https://",
            "https:///dns-query",
            "",
        ] {
            assert!(EchDns::parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn the_ech_domain_is_a_dns_name() {
        for name in [
            DEFAULT_ECH_DOMAIN,
            "crypto.cloudflare.com",
            "ip.gs",
            "ip.gs.",
            "_ech.example",
        ] {
            assert!(valid_domain(name), "{name}");
        }
        let long = format!("{}.com", "a".repeat(64));
        for name in [
            "",
            ".",
            "a..b",
            "with space.com",
            "https://ip.gs",
            "ip.gs/",
            long.as_str(),
        ] {
            assert!(!valid_domain(name), "{name}");
        }
    }

    #[test]
    fn a_message_over_tcp_goes_behind_its_length() {
        assert_eq!(tcp_message(&[7, 8, 9]), vec![0, 3, 7, 8, 9]);
        assert_eq!(tcp_message(&[0u8; 300])[..2], [1, 44]);
    }

    fn reply(id: u16, name: &str, qtype: u16, qr: bool, qdcount: u16) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&id.to_be_bytes());
        msg.push(if qr { 0x81 } else { 0x01 });
        msg.push(0x80);
        msg.extend_from_slice(&qdcount.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&[0, 0, 0, 0]);
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg
    }

    #[test]
    fn build_query_reports_the_id_it_wrote() {
        let (query, id) = build_query("cloudflare-ech.com", RR_HTTPS);
        assert_eq!(u16::from_be_bytes([query[0], query[1]]), id);
    }

    #[test]
    fn accepts_a_reply_that_matches_the_query() {
        let msg = reply(0x1234, "cloudflare-ech.com", RR_HTTPS, true, 1);
        assert!(response_matches(
            &msg,
            0x1234,
            "cloudflare-ech.com",
            RR_HTTPS
        ));
    }

    #[test]
    fn rejects_a_spoofed_reply_with_the_wrong_transaction_id() {
        let msg = reply(0x9999, "cloudflare-ech.com", RR_HTTPS, true, 1);
        assert!(!response_matches(
            &msg,
            0x1234,
            "cloudflare-ech.com",
            RR_HTTPS
        ));
    }

    #[test]
    fn rejects_a_reply_for_a_different_name() {
        let msg = reply(0x1234, "attacker.example", RR_HTTPS, true, 1);
        assert!(!response_matches(
            &msg,
            0x1234,
            "cloudflare-ech.com",
            RR_HTTPS
        ));
    }

    #[test]
    fn rejects_a_reply_for_a_different_record_type() {
        let msg = reply(0x1234, "cloudflare-ech.com", 1, true, 1);
        assert!(!response_matches(
            &msg,
            0x1234,
            "cloudflare-ech.com",
            RR_HTTPS
        ));
    }

    #[test]
    fn rejects_a_message_that_is_not_a_response() {
        let msg = reply(0x1234, "cloudflare-ech.com", RR_HTTPS, false, 1);
        assert!(!response_matches(
            &msg,
            0x1234,
            "cloudflare-ech.com",
            RR_HTTPS
        ));
    }

    #[test]
    fn rejects_a_reply_with_an_unexpected_question_count() {
        let msg = reply(0x1234, "cloudflare-ech.com", RR_HTTPS, true, 2);
        assert!(!response_matches(
            &msg,
            0x1234,
            "cloudflare-ech.com",
            RR_HTTPS
        ));
    }

    #[test]
    fn rejects_truncated_input_without_panicking() {
        let msg = reply(0x1234, "cloudflare-ech.com", RR_HTTPS, true, 1);
        for cut in 0..msg.len() {
            assert!(!response_matches(
                &msg[..cut],
                0x1234,
                "cloudflare-ech.com",
                RR_HTTPS
            ));
        }
    }

    #[test]
    fn name_comparison_is_case_insensitive() {
        let msg = reply(0x1234, "CloudFlare-ECH.com", RR_HTTPS, true, 1);
        assert!(response_matches(
            &msg,
            0x1234,
            "cloudflare-ech.com",
            RR_HTTPS
        ));
    }
}

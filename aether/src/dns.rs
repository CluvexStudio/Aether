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
    Https(DohEndpoint),
}

/// A DNS-over-HTTPS endpoint. The host of its URL is the HTTP host, of Host or :authority,
/// and also where the connection goes and the server name of the ClientHello, unless
/// `address` and `sni` name others.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohEndpoint {
    pub url: String,
    /// Where the connection goes: an IP address or a domain name, on the URL's port.
    pub address: Option<String>,
    /// The server name of the ClientHello: a domain name.
    pub sni: Option<String>,
}

impl DohEndpoint {
    /// `value`: an `https://` URL, then `@address=` an IP address or a domain name and
    /// `@sni=` a domain name, each at most once and in either order.
    fn parse(value: &str) -> std::result::Result<Self, String> {
        let mut pieces = value.split('@');
        let url = pieces.next().unwrap_or("").trim();
        let host = strip_scheme(url, "https://")
            .and_then(|rest| rest.split(['/', '?', '#']).next())
            .unwrap_or("");
        if host.is_empty() {
            return Err(format!("{value} names no host"));
        }
        let mut endpoint = DohEndpoint {
            url: url.to_string(),
            address: None,
            sni: None,
        };
        for piece in pieces {
            let neither = || format!("@{piece} in {value} is neither @address= nor @sni=");
            let (name, setting) = piece.split_once('=').ok_or_else(neither)?;
            let setting = setting.trim();
            let bare = setting
                .strip_prefix('[')
                .and_then(|inside| inside.strip_suffix(']'))
                .unwrap_or(setting);
            let (slot, checked) = match name.trim().to_ascii_lowercase().as_str() {
                "address" => (
                    &mut endpoint.address,
                    match bare.parse::<IpAddr>() {
                        Ok(ip) => Some(ip.to_string()),
                        Err(_) => valid_domain(setting).then(|| setting.to_string()),
                    }
                    .ok_or_else(|| {
                        format!(
                            "@address={setting} is no IP address or domain name; the port is the URL's"
                        )
                    }),
                ),
                "sni" => (
                    &mut endpoint.sni,
                    (bare.parse::<IpAddr>().is_err() && valid_domain(setting))
                        .then(|| setting.to_string())
                        .ok_or_else(|| format!("@sni={setting} is no domain name")),
                ),
                _ => return Err(neither()),
            };
            if slot.is_some() {
                return Err(format!("{value} names @{} twice", name.trim()));
            }
            *slot = Some(checked?);
        }
        Ok(endpoint)
    }
}

impl EchDns {
    /// The resolver `value` names: `udp://ip[:port]` or `tcp://ip[:port]`, on port 53
    /// unless one is given and with an IPv6 address in brackets, or an `https://` URL,
    /// on port 443 unless it names one, with `@address=` and `@sni=` after it if need be,
    /// see `DohEndpoint`.
    pub fn parse(value: &str) -> std::result::Result<Self, String> {
        let value = value.trim();
        if strip_scheme(value, "https://").is_some() {
            return DohEndpoint::parse(value).map(EchDns::Https);
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
            EchDns::Https(endpoint) => {
                f.write_str(&endpoint.url)?;
                if let Some(address) = &endpoint.address {
                    write!(f, "@address={address}")?;
                }
                if let Some(sni) = &endpoint.sni {
                    write!(f, "@sni={sni}")?;
                }
                Ok(())
            }
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

/// Where an ECHConfigList is looked up: the options that name the resolver and the
/// domain, and the variables they set.
#[derive(Debug, Clone, Copy)]
pub struct EchLookup {
    pub dns_flag: &'static str,
    pub dns_variable: &'static str,
    pub domain_flag: &'static str,
    pub domain_variable: &'static str,
    /// The TLS 1.2 cipher suites the lookup lists over DNS-over-HTTPS: those of the
    /// handshakes the key is for.
    pub ciphers: &'static crate::tls::CipherOption,
}

/// The lookup of --ech auto, whose key the MASQUE handshakes of a session offer.
pub const SESSION_ECH: EchLookup = EchLookup {
    dns_flag: "--ech-dns",
    dns_variable: "AETHER_ECH_DNS",
    domain_flag: "--ech-domain",
    domain_variable: "AETHER_ECH_DOMAIN",
    ciphers: &crate::tls::TLS_CIPHERS,
};

/// The lookup of --get-warp-key-ech auto, whose key the calls to the WARP API offer.
pub const WARP_KEY_ECH: EchLookup = EchLookup {
    dns_flag: "--get-warp-key-ech-dns",
    dns_variable: "AETHER_GET_WARP_KEY_ECH_DNS",
    domain_flag: "--get-warp-key-ech-domain",
    domain_variable: "AETHER_GET_WARP_KEY_ECH_DOMAIN",
    ciphers: &crate::tls::WARP_KEY_TLS_CIPHERS,
};

/// The resolver `lookup` names, or the default one.
fn configured_dns(lookup: &EchLookup) -> std::result::Result<EchDns, String> {
    let value = std::env::var(lookup.dns_variable).unwrap_or_default();
    let value = value.trim();
    EchDns::parse(if value.is_empty() {
        DEFAULT_ECH_DNS
    } else {
        value
    })
}

/// The domain `lookup` names, or the default one.
fn configured_domain(lookup: &EchLookup) -> std::result::Result<String, String> {
    let value = std::env::var(lookup.domain_variable).unwrap_or_default();
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

/// Fetches an ECHConfigList: the ech parameter of the HTTPS record of the domain
/// `lookup` names, asked of the resolver it names, through the upstream proxy when there
/// is one.
pub async fn fetch_ech_config(lookup: &EchLookup) -> Result<Vec<u8>> {
    let dns = configured_dns(lookup)
        .map_err(|e| AetherError::Ech(format!("{}: {e}", lookup.dns_flag)))?;
    let domain = configured_domain(lookup)
        .map_err(|e| AetherError::Ech(format!("{}: {e}", lookup.domain_flag)))?;
    let ciphers = lookup.ciphers;
    let lookup = async {
        match &dns {
            EchDns::Udp(server) => query_udp(*server, &domain).await,
            EchDns::Tcp(server) => query_tcp(*server, &domain).await,
            EchDns::Https(endpoint) => query_https(endpoint, &domain, ciphers).await,
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

/// Asks `endpoint`, a DoH endpoint, for the HTTPS record of `domain`, over BoringSSL with
/// Chrome's ClientHello (see `https`), which lists the TLS 1.2 cipher suites `ciphers` gives,
/// if any. The URL's host is the HTTP host; the connection goes to the endpoint's address and
/// the ClientHello names its sni when it has them, the URL's host otherwise.
async fn query_https(
    endpoint: &DohEndpoint,
    domain: &str,
    ciphers: &crate::tls::CipherOption,
) -> Result<Vec<u8>> {
    let url = &endpoint.url;
    let parsed = reqwest::Url::parse(url).map_err(|e| AetherError::Ech(format!("{url}: {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| AetherError::Ech(format!("{url} names no host")))?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let path = match parsed.query() {
        Some(query) => format!("{}?{query}", parsed.path()),
        None => parsed.path().to_string(),
    };

    // RFC 8484 asks for the ID 0, which keeps the answers cacheable.
    let (mut query, _) = build_query(domain, RR_HTTPS);
    query[0] = 0;
    query[1] = 0;
    let headers = [
        (
            "Content-Type".to_string(),
            "application/dns-message".to_string(),
        ),
        ("Accept".to_string(), "application/dns-message".to_string()),
    ];
    let request = crate::https::Request {
        method: "POST",
        host,
        port: parsed.port_or_known_default().unwrap_or(443),
        address: endpoint.address.as_deref(),
        sni: endpoint.sni.as_deref(),
        path: &path,
        headers: &headers,
        body: Some(&query),
    };
    let response = crate::https::send(&request, ciphers, ECH_LOOKUP_TIMEOUT)
        .await
        .map_err(|e| AetherError::Ech(e.to_string()))?;
    if !(200..300).contains(&response.status) {
        return Err(AetherError::Ech(format!("answered {}", response.status)));
    }
    let msg = response.body;

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
            Ok(doh("https://doq.dns4all.eu/dns-query", None, None))
        );
        assert_eq!(
            EchDns::parse("https://1.1.1.1:8443/dns-query"),
            Ok(doh("https://1.1.1.1:8443/dns-query", None, None))
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

    fn doh(url: &str, address: Option<&str>, sni: Option<&str>) -> EchDns {
        EchDns::Https(DohEndpoint {
            url: url.to_string(),
            address: address.map(str::to_string),
            sni: sni.map(str::to_string),
        })
    }

    #[test]
    fn a_doh_url_takes_an_address_and_a_server_name_of_their_own() {
        let url = "https://doq.dns4all.eu/dns-query";
        for (text, address, sni) in [
            (
                "https://doq.dns4all.eu/dns-query@address=2.2.2.2@sni=google.com",
                Some("2.2.2.2"),
                Some("google.com"),
            ),
            (
                " https://doq.dns4all.eu/dns-query@SNI=google.com@Address=2.2.2.2 ",
                Some("2.2.2.2"),
                Some("google.com"),
            ),
            (
                "https://doq.dns4all.eu/dns-query@address=[2606:4700::1111]",
                Some("2606:4700::1111"),
                None,
            ),
            (
                "https://doq.dns4all.eu/dns-query@address=2606:4700::1111",
                Some("2606:4700::1111"),
                None,
            ),
            (
                "https://doq.dns4all.eu/dns-query@address=front.example.net",
                Some("front.example.net"),
                None,
            ),
            (
                "https://doq.dns4all.eu/dns-query@sni=google.com",
                None,
                Some("google.com"),
            ),
        ] {
            assert_eq!(EchDns::parse(text), Ok(doh(url, address, sni)), "{text}");
        }
        assert_eq!(
            EchDns::parse("https://doq.dns4all.eu@address=2.2.2.2"),
            Ok(doh("https://doq.dns4all.eu", Some("2.2.2.2"), None))
        );
        // As it is read, and as the log shows it.
        let text = "https://doq.dns4all.eu/dns-query@address=2.2.2.2@sni=google.com";
        assert_eq!(EchDns::parse(text).unwrap().to_string(), text);
    }

    #[test]
    fn a_doh_url_with_a_parameter_it_cannot_use_is_refused() {
        for text in [
            "https://doq.dns4all.eu/dns-query@address=",
            "https://doq.dns4all.eu/dns-query@address=2.2.2.2:443",
            "https://doq.dns4all.eu/dns-query@address=not a name",
            "https://doq.dns4all.eu/dns-query@sni=",
            "https://doq.dns4all.eu/dns-query@sni=2.2.2.2",
            "https://doq.dns4all.eu/dns-query@sni=[::1]",
            "https://doq.dns4all.eu/dns-query@sni=google.com@sni=bing.com",
            "https://doq.dns4all.eu/dns-query@address=1.1.1.1@address=2.2.2.2",
            "https://doq.dns4all.eu/dns-query@port=443",
            "https://doq.dns4all.eu/dns-query@google.com",
            "https://user@doq.dns4all.eu/dns-query",
            "https://@address=2.2.2.2",
        ] {
            assert!(EchDns::parse(text).is_err(), "{text}");
        }
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

    #[test]
    fn each_lookup_lists_the_suites_of_the_handshakes_its_key_is_for() {
        assert_eq!(SESSION_ECH.ciphers.flag, "--tls-ciphers");
        assert_eq!(WARP_KEY_ECH.ciphers.flag, "--get-warp-key-tls-ciphers");
    }

    /// The ClientHello of `lookup` over DoH, as a server on this machine reads it before it
    /// hangs up.
    async fn doh_hello(lookup: &EchLookup) -> crate::tls::client_hello::ClientHello {
        let (server, hello) = crate::tls::client_hello::catch().await;
        std::env::set_var(lookup.dns_variable, format!("https://{server}/dns-query"));
        assert!(fetch_ech_config(lookup).await.is_err());
        std::env::remove_var(lookup.dns_variable);
        hello.await.expect("the ClientHello")
    }

    #[tokio::test]
    async fn a_doh_lookup_lists_the_tls12_suites_of_its_cipher_option() {
        let _setting = crate::upstream::hold_setting().await;
        // A lookup and an option of the test's own, so that no other test sees their variables.
        const CIPHERS: crate::tls::CipherOption = crate::tls::CipherOption {
            flag: "--doh-test-ciphers",
            variable: "AETHER_DOH_TEST_CIPHERS",
        };
        const LOOKUP: EchLookup = EchLookup {
            dns_flag: "--doh-test-dns",
            dns_variable: "AETHER_DOH_TEST_DNS",
            domain_flag: "--doh-test-domain",
            domain_variable: "AETHER_DOH_TEST_DOMAIN",
            ciphers: &CIPHERS,
        };
        let own = doh_hello(&LOOKUP).await;
        std::env::set_var(
            CIPHERS.variable,
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:AES256-SHA",
        );
        let listed = doh_hello(&LOOKUP).await;
        std::env::remove_var(CIPHERS.variable);
        // BoringSSL's ClientHello, Chrome's, offering HTTP/2 first.
        assert!(own.has_grease());
        assert_eq!(own.alpn(), [b"h2".to_vec(), b"http/1.1".to_vec()]);
        // Every suite of the list, in its order, AES256-SHA among them.
        assert_eq!(listed.tls12_suites(), [0xc02f, 0xcca9, 0x0035]);
        assert_ne!(own.tls12_suites(), listed.tls12_suites());
    }

    /// A reply to `query` that holds one HTTPS record for its name, with `ech` for its ech
    /// parameter.
    fn https_reply(query: &[u8], ech: &[u8]) -> Vec<u8> {
        let mut rdata = vec![0x00, 0x01, 0x00];
        rdata.extend_from_slice(&SVCPARAM_ECH.to_be_bytes());
        rdata.extend_from_slice(&(ech.len() as u16).to_be_bytes());
        rdata.extend_from_slice(ech);

        let mut msg = query.to_vec();
        msg[2] |= 0x80;
        msg[6..8].copy_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&[0xc0, 0x0c]);
        msg.extend_from_slice(&RR_HTTPS.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&300u32.to_be_bytes());
        msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        msg.extend_from_slice(&rdata);
        msg
    }

    /// What a DoH server on this machine was asked.
    struct Asked {
        method: String,
        path: String,
        kind: String,
        /// The server name of the ClientHello.
        server_name: Option<String>,
        /// The HTTP host: Host, or :authority.
        host: String,
    }

    /// A DoH server on this machine that speaks the protocol of `alpn` and answers one query
    /// with `ech`; the task ends with what it was asked.
    async fn doh_server(
        alpn: &'static [u8],
        ech: &'static [u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<Asked>) {
        let (address, listener, acceptor) = crate::https::test_server(alpn).await;
        let served = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("a connection");
            let mut tls = tokio_boring::accept(&acceptor, tcp)
                .await
                .expect("a handshake");
            let server_name = tls
                .ssl()
                .servername(boring::ssl::NameType::HOST_NAME)
                .map(str::to_string);
            if alpn == b"\x02h2" {
                let mut connection = h2::server::handshake(tls).await.expect("h2");
                let (request, mut respond) = connection
                    .accept()
                    .await
                    .expect("a request")
                    .expect("a whole request");
                let (parts, mut body) = request.into_parts();
                let mut query = Vec::new();
                while let Some(chunk) = body.data().await {
                    query.extend_from_slice(&chunk.expect("the query"));
                }
                let answer = http::Response::builder()
                    .status(200)
                    .header("content-type", "application/dns-message")
                    .body(())
                    .unwrap();
                let mut stream = respond.send_response(answer, false).expect("an answer");
                stream
                    .send_data(bytes::Bytes::from(https_reply(&query, ech)), true)
                    .expect("its body");
                while let Some(Ok(_)) = connection.accept().await {}
                let kind = parts.headers["content-type"].to_str().unwrap().to_string();
                let path = parts.uri.path_and_query().map(|path| path.to_string());
                Asked {
                    method: parts.method.to_string(),
                    path: path.unwrap_or_default(),
                    kind,
                    server_name,
                    host: parts
                        .uri
                        .authority()
                        .map(|a| a.to_string())
                        .unwrap_or_default(),
                }
            } else {
                let mut raw = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head_end, length) = loop {
                    let read = tls.read(&mut chunk).await.expect("the request");
                    raw.extend_from_slice(&chunk[..read]);
                    if let Some(end) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&raw[..end]).to_lowercase();
                        let length = head
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .and_then(|value| value.trim().parse::<usize>().ok())
                            .expect("a length");
                        break (end + 4, length);
                    }
                };
                while raw.len() < head_end + length {
                    let read = tls.read(&mut chunk).await.expect("the query");
                    raw.extend_from_slice(&chunk[..read]);
                }
                let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
                let reply = https_reply(&raw[head_end..head_end + length], ech);
                let mut wire = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                    reply.len()
                )
                .into_bytes();
                wire.extend_from_slice(&reply);
                tls.write_all(&wire).await.expect("the answer");
                let mut words = head.split_whitespace();
                let method = words.next().unwrap_or("").to_string();
                let path = words.next().unwrap_or("").to_string();
                let field = |name: &str| {
                    head.lines()
                        .find_map(|line| line.strip_prefix(name))
                        .unwrap_or("")
                        .trim()
                        .to_string()
                };
                Asked {
                    method,
                    path,
                    kind: field("Content-Type: "),
                    server_name,
                    host: field("Host: "),
                }
            }
        });
        (address, served)
    }

    #[tokio::test]
    async fn a_doh_lookup_reads_the_key_over_http2_or_http1() {
        let _setting = crate::upstream::hold_setting().await;
        const CIPHERS: crate::tls::CipherOption = crate::tls::CipherOption {
            flag: "--doh-server-test-ciphers",
            variable: "AETHER_DOH_SERVER_TEST_CIPHERS",
        };
        const LOOKUP: EchLookup = EchLookup {
            dns_flag: "--doh-server-test-dns",
            dns_variable: "AETHER_DOH_SERVER_TEST_DNS",
            domain_flag: "--doh-server-test-domain",
            domain_variable: "AETHER_DOH_SERVER_TEST_DOMAIN",
            ciphers: &CIPHERS,
        };
        const KEY: &[u8] = b"\x00\x05a key";
        for alpn in [&b"\x02h2"[..], &b"\x08http/1.1"[..]] {
            let (server, served) = doh_server(alpn, KEY).await;
            std::env::set_var(
                LOOKUP.dns_variable,
                format!("https://{server}/dns-query?ct"),
            );
            let key = fetch_ech_config(&LOOKUP).await;
            std::env::remove_var(LOOKUP.dns_variable);
            assert_eq!(key.expect("the key").as_slice(), KEY, "{alpn:?}");
            let asked = served.await.expect("the server");
            assert_eq!(asked.method, "POST");
            assert_eq!(asked.path, "/dns-query?ct");
            assert_eq!(asked.kind, "application/dns-message");
            // An address for its host: neither a server name nor a host of its own.
            assert_eq!(asked.server_name, None);
            assert_eq!(asked.host, server.to_string());
        }
    }

    #[tokio::test]
    async fn a_doh_lookup_goes_to_its_address_with_its_server_name() {
        let _setting = crate::upstream::hold_setting().await;
        const CIPHERS: crate::tls::CipherOption = crate::tls::CipherOption {
            flag: "--doh-front-test-ciphers",
            variable: "AETHER_DOH_FRONT_TEST_CIPHERS",
        };
        const LOOKUP: EchLookup = EchLookup {
            dns_flag: "--doh-front-test-dns",
            dns_variable: "AETHER_DOH_FRONT_TEST_DNS",
            domain_flag: "--doh-front-test-domain",
            domain_variable: "AETHER_DOH_FRONT_TEST_DOMAIN",
            ciphers: &CIPHERS,
        };
        const KEY: &[u8] = b"\x00\x05a key";
        for alpn in [&b"\x02h2"[..], &b"\x08http/1.1"[..]] {
            let (server, served) = doh_server(alpn, KEY).await;
            // doh.example.test is never looked up: the connection goes to the address.
            std::env::set_var(
                LOOKUP.dns_variable,
                format!(
                    "https://doh.example.test:{}/dns-query@address=127.0.0.1@sni=front.example.test",
                    server.port()
                ),
            );
            let key = fetch_ech_config(&LOOKUP).await;
            std::env::remove_var(LOOKUP.dns_variable);
            assert_eq!(key.expect("the key").as_slice(), KEY, "{alpn:?}");
            let asked = served.await.expect("the server");
            assert_eq!(asked.server_name.as_deref(), Some("front.example.test"));
            assert_eq!(asked.host, format!("doh.example.test:{}", server.port()));
            assert_eq!(asked.path, "/dns-query");
        }
    }
}

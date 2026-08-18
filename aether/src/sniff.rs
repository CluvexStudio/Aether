const TLS_HANDSHAKE: u8 = 0x16;
const TLS_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const SNI_HOST_NAME: u8 = 0x00;

const MAX_HOST_LEN: usize = 253;

pub const PEEK_BUDGET: usize = 4096;

fn be16(buf: &[u8], at: usize) -> Option<usize> {
    let hi = *buf.get(at)? as usize;
    let lo = *buf.get(at + 1)? as usize;
    Some((hi << 8) | lo)
}

fn be24(buf: &[u8], at: usize) -> Option<usize> {
    let a = *buf.get(at)? as usize;
    let b = *buf.get(at + 1)? as usize;
    let c = *buf.get(at + 2)? as usize;
    Some((a << 16) | (b << 8) | c)
}

fn plausible_host(raw: &[u8]) -> Option<String> {
    if raw.is_empty() || raw.len() > MAX_HOST_LEN {
        return None;
    }

    let name = std::str::from_utf8(raw).ok()?.trim().trim_end_matches('.');
    if name.is_empty() || name.len() > MAX_HOST_LEN {
        return None;
    }

    let allowed = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_');
    if !allowed || !name.contains('.') {
        return None;
    }

    if name.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    Some(name.to_lowercase())
}

pub fn tls_sni(buf: &[u8]) -> Option<String> {
    if *buf.first()? != TLS_HANDSHAKE {
        return None;
    }

    let record_len = be16(buf, 3)?;
    let record_end = 5usize.checked_add(record_len)?.min(buf.len());

    let body = buf.get(5..record_end)?;
    if *body.first()? != TLS_CLIENT_HELLO {
        return None;
    }

    let hello_len = be24(body, 1)?;
    let hello_end = 4usize.checked_add(hello_len)?.min(body.len());
    let hello = body.get(4..hello_end)?;

    let mut at = 2 + 32;

    let session_len = *hello.get(at)? as usize;
    at = at.checked_add(1 + session_len)?;

    let cipher_len = be16(hello, at)?;
    at = at.checked_add(2 + cipher_len)?;

    let compression_len = *hello.get(at)? as usize;
    at = at.checked_add(1 + compression_len)?;

    let extensions_len = be16(hello, at)?;
    at = at.checked_add(2)?;
    let extensions_end = at.checked_add(extensions_len)?.min(hello.len());

    while at + 4 <= extensions_end {
        let kind = be16(hello, at)? as u16;
        let len = be16(hello, at + 2)?;
        let data_start = at + 4;
        let data_end = data_start.checked_add(len)?;
        if data_end > extensions_end {
            return None;
        }

        if kind == EXT_SERVER_NAME {
            let data = hello.get(data_start..data_end)?;
            return first_server_name(data);
        }

        at = data_end;
    }

    None
}

fn first_server_name(data: &[u8]) -> Option<String> {
    let list_len = be16(data, 0)?;
    let list_end = 2usize.checked_add(list_len)?.min(data.len());

    let mut at = 2usize;
    while at + 3 <= list_end {
        let kind = *data.get(at)?;
        let len = be16(data, at + 1)?;
        let start = at + 3;
        let end = start.checked_add(len)?;
        if end > list_end {
            return None;
        }

        if kind == SNI_HOST_NAME {
            return plausible_host(data.get(start..end)?);
        }

        at = end;
    }

    None
}

pub fn http_host(buf: &[u8]) -> Option<String> {
    let head_end = buf.len().min(PEEK_BUDGET);
    let head = buf.get(..head_end)?;

    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");

    let request_line = lines.next()?;
    if !looks_like_http(request_line) {
        return None;
    }

    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = match line.split_once(':') {
            Some(pair) => pair,
            None => continue,
        };
        if !name.eq_ignore_ascii_case("host") {
            continue;
        }

        let value = value.trim();
        let without_port = match value.rsplit_once(':') {
            Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
            _ => value,
        };
        return plausible_host(without_port.as_bytes());
    }

    None
}

fn looks_like_http(line: &str) -> bool {
    const METHODS: [&str; 9] = [
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ",
    ];
    METHODS.iter().any(|method| line.starts_with(method)) && line.contains("HTTP/")
}

pub fn hostname(buf: &[u8]) -> Option<String> {
    tls_sni(buf).or_else(|| http_host(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(server_name: Option<&str>) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(name) = server_name {
            let mut entry = Vec::new();
            entry.push(SNI_HOST_NAME);
            entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
            entry.extend_from_slice(name.as_bytes());

            let mut sni = Vec::new();
            sni.extend_from_slice(&(entry.len() as u16).to_be_bytes());
            sni.extend_from_slice(&entry);

            extensions.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
            extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni);
        }

        extensions.extend_from_slice(&0x002bu16.to_be_bytes());
        extensions.extend_from_slice(&2u16.to_be_bytes());
        extensions.extend_from_slice(&[0x03, 0x04]);

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0x11; 32]);
        hello.push(0);
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut body = Vec::new();
        body.push(TLS_CLIENT_HELLO);
        let len = hello.len();
        body.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        body.extend_from_slice(&hello);

        let mut record = Vec::new();
        record.push(TLS_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        record
    }

    #[test]
    fn the_server_name_is_read_out_of_a_client_hello() {
        let hello = client_hello(Some("example.com"));
        assert_eq!(tls_sni(&hello).as_deref(), Some("example.com"));
        assert_eq!(hostname(&hello).as_deref(), Some("example.com"));
    }

    #[test]
    fn a_client_hello_without_a_server_name_yields_nothing() {
        let hello = client_hello(None);
        assert_eq!(tls_sni(&hello), None);
    }

    #[test]
    fn a_server_name_is_lowercased_and_stripped_of_a_trailing_dot() {
        let hello = client_hello(Some("Example.COM."));
        assert_eq!(tls_sni(&hello).as_deref(), Some("example.com"));
    }

    #[test]
    fn a_truncated_client_hello_is_refused_without_panicking() {
        let hello = client_hello(Some("example.com"));
        for cut in 0..hello.len() {
            let _ = tls_sni(&hello[..cut]);
        }
    }

    #[test]
    fn random_bytes_are_never_mistaken_for_a_server_name() {
        let mut seed = 0x12345678u32;
        for _ in 0..2000 {
            let mut buf = Vec::new();
            for _ in 0..64 {
                seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                buf.push((seed >> 16) as u8);
            }
            let _ = hostname(&buf);
        }
    }

    #[test]
    fn a_literal_address_in_the_server_name_is_not_treated_as_a_domain() {
        let hello = client_hello(Some("192.168.1.1"));
        assert_eq!(tls_sni(&hello), None);
    }

    #[test]
    fn the_host_header_is_read_out_of_a_plain_request() {
        let request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        assert_eq!(http_host(request).as_deref(), Some("example.com"));
        assert_eq!(hostname(request).as_deref(), Some("example.com"));
    }

    #[test]
    fn a_port_on_the_host_header_is_dropped() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(http_host(request).as_deref(), Some("example.com"));
    }

    #[test]
    fn the_host_header_is_found_whatever_its_capitalisation() {
        let request = b"POST /submit HTTP/1.1\r\nHOST: Example.Com\r\n\r\n";
        assert_eq!(http_host(request).as_deref(), Some("example.com"));
    }

    #[test]
    fn a_body_that_is_not_http_is_refused() {
        assert_eq!(http_host(b"SSH-2.0-OpenSSH_9.6\r\n"), None);
        assert_eq!(http_host(b"\x00\x01\x02\x03"), None);
        assert_eq!(http_host(b""), None);
    }

    #[test]
    fn a_host_header_carrying_an_address_is_ignored() {
        let request = b"GET / HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n";
        assert_eq!(http_host(request), None);
    }

    #[test]
    fn a_single_label_host_is_ignored_because_rules_are_written_with_dots() {
        let request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(http_host(request), None);
    }

    #[test]
    fn an_over_long_name_is_refused() {
        let long = format!("{}.com", "a".repeat(300));
        assert_eq!(plausible_host(long.as_bytes()), None);
    }
}

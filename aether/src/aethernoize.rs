use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::{Rng, RngExt};
use regex::Regex;
use tokio::net::UdpSocket;

#[derive(Debug, Clone)]
pub struct AetherNoizeConfig {
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub i3: Option<String>,
    pub i4: Option<String>,
    pub i5: Option<String>,
    pub jc: usize,
    pub jc_before_hs: usize,
    pub jc_after_i1: usize,
    pub jc_after_hs: usize,
    pub jmin: usize,
    pub jmax: usize,
    pub junk_interval: Duration,
    pub handshake_delay: Duration,
    pub allow_zero_size: bool,
}

impl AetherNoizeConfig {
    pub fn off() -> Self {
        Self {
            i1: None,
            i2: None,
            i3: None,
            i4: None,
            i5: None,
            jc: 0,
            jc_before_hs: 0,
            jc_after_i1: 0,
            jc_after_hs: 0,
            jmin: 0,
            jmax: 0,
            junk_interval: Duration::ZERO,
            handshake_delay: Duration::ZERO,
            allow_zero_size: false,
        }
    }

    pub fn light() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><r 20-32>".to_string()),
            i2: Some("<rc 24-48>".to_string()),
            i3: None,
            i4: None,
            i5: None,
            jc: 4,
            jc_before_hs: 2,
            jc_after_i1: 1,
            jc_after_hs: 1,
            jmin: 48,
            jmax: 190,
            junk_interval: Duration::from_millis(3),
            handshake_delay: Duration::from_millis(5),
            allow_zero_size: false,
        }
    }

    pub fn balanced() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><rc 20-40>".to_string()),
            i2: Some("<b 504f5354><rd 10-20><rc 20-30>".to_string()),
            i3: Some("<r 30-50>".to_string()),
            i4: None,
            i5: None,
            jc: 6,
            jc_before_hs: 3,
            jc_after_i1: 2,
            jc_after_hs: 1,
            jmin: 64,
            jmax: 256,
            junk_interval: Duration::from_millis(2),
            handshake_delay: Duration::from_millis(8),
            allow_zero_size: false,
        }
    }

    pub fn aggressive() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><rc 40-64>".to_string()),
            i2: Some("<b 504f5354><t><rd 15-30><rc 30-50>".to_string()),
            i3: Some("<b 474554><rc 40-60>".to_string()),
            i4: Some("<r 60-100>".to_string()),
            i5: Some("<c><rd 20-40>".to_string()),
            jc: 10,
            jc_before_hs: 4,
            jc_after_i1: 3,
            jc_after_hs: 3,
            jmin: 80,
            jmax: 384,
            junk_interval: Duration::from_millis(1),
            handshake_delay: Duration::from_millis(12),
            allow_zero_size: false,
        }
    }

    pub fn firewall() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><rc 24-44>".to_string()),
            i2: Some("<b 504f5354><c><rd 12-24><rc 24-36>".to_string()),
            i3: Some("<b 474554><r 30-50>".to_string()),
            i4: None,
            i5: None,
            jc: 7,
            jc_before_hs: 3,
            jc_after_i1: 2,
            jc_after_hs: 2,
            jmin: 64,
            jmax: 300,
            junk_interval: Duration::from_millis(2),
            handshake_delay: Duration::from_millis(10),
            allow_zero_size: false,
        }
    }

    pub fn gfw() -> Self {
        Self {
            i1: Some("<b 16030100><c><rc 48-72>".to_string()),
            i2: Some("<b 0d0a0d0a><t><rd 20-40><rc 36-60>".to_string()),
            i3: Some("<b 474554202f20485454502f312e31><rc 40-64>".to_string()),
            i4: Some("<b 504f5354><c><r 64-110>".to_string()),
            i5: Some("<rd 24-48><rc 32-56>".to_string()),
            jc: 12,
            jc_before_hs: 5,
            jc_after_i1: 3,
            jc_after_hs: 4,
            jmin: 96,
            jmax: 420,
            junk_interval: Duration::from_millis(1),
            handshake_delay: Duration::from_millis(16),
            allow_zero_size: true,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.jc > 0 || self.i1.is_some()
    }
}

pub fn from_profile(name: &str) -> AetherNoizeConfig {
    match name.trim().to_ascii_lowercase().as_str() {
        "off" | "none" => AetherNoizeConfig::off(),
        "light" => AetherNoizeConfig::light(),
        "firewall" => AetherNoizeConfig::firewall(),
        "gfw" => AetherNoizeConfig::gfw(),
        "aggressive" | "heavy" => AetherNoizeConfig::aggressive(),
        _ => AetherNoizeConfig::balanced(),
    }
}

fn parse_range(data: &str) -> usize {
    let mut parts = data.split('-');
    if let (Some(min_str), Some(max_str)) = (parts.next(), parts.next()) {
        let min: usize = min_str.trim().parse().unwrap_or(0);
        let max: usize = max_str.trim().parse().unwrap_or(0);
        if max > min && min > 0 {
            return rand::rng().random_range(min..=max).min(2048);
        }
    }
    data.trim().parse().unwrap_or(0).min(2048)
}

static CPS_COUNTER: AtomicU32 = AtomicU32::new(1);

pub fn parse_cps(spec: &str) -> Vec<u8> {
    let mut out = Vec::new();

    let tag_regex = {
        static TAG_REGEX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        TAG_REGEX.get_or_init(|| Regex::new(r"<([a-z]+)\s*([^>]*)>").expect("static tag pattern"))
    };

    for cap in tag_regex.captures_iter(spec) {
        let tag_type = cap.get(1).map_or("", |m| m.as_str());
        let tag_data = cap.get(2).map_or("", |m| m.as_str()).trim();

        match tag_type {
            "b" => {
                let hex_str: String = tag_data.chars().filter(|c| !c.is_whitespace()).collect();
                let clean = hex_str
                    .strip_prefix("0x")
                    .or_else(|| hex_str.strip_prefix("0X"))
                    .unwrap_or(&hex_str);
                if let Ok(decoded) = hex::decode(clean) {
                    out.extend_from_slice(&decoded);
                }
            }
            "t" => {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                out.extend_from_slice(&ts.to_be_bytes());
            }
            "c" => {
                let counter = CPS_COUNTER.fetch_add(1, Ordering::Relaxed);
                out.extend_from_slice(&counter.to_be_bytes());
            }
            "r" => {
                let len = parse_range(tag_data);
                if len > 0 {
                    let mut r = vec![0u8; len];
                    rand::rng().fill_bytes(&mut r);
                    out.extend_from_slice(&r);
                }
            }
            "rc" => {
                let len = parse_range(tag_data);
                if len > 0 {
                    let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                    let mut r = vec![0u8; len];
                    for b in r.iter_mut() {
                        *b = chars[rand::rng().random_range(0..chars.len())];
                    }
                    out.extend_from_slice(&r);
                }
            }
            "rd" => {
                let len = parse_range(tag_data);
                if len > 0 {
                    let chars = b"0123456789";
                    let mut r = vec![0u8; len];
                    for b in r.iter_mut() {
                        *b = chars[rand::rng().random_range(0..chars.len())];
                    }
                    out.extend_from_slice(&r);
                }
            }
            _ => {}
        }
    }

    out
}

fn wrap_ikev2(payload: &[u8]) -> Vec<u8> {
    if payload.is_empty() {
        return payload.to_vec();
    }

    let mut initiator_spi = [0u8; 8];
    let mut responder_spi = [0u8; 8];

    if payload.len() >= 8 {
        initiator_spi.copy_from_slice(&payload[..8]);
    } else {
        rand::rng().fill_bytes(&mut initiator_spi);
    }
    rand::rng().fill_bytes(&mut responder_spi);

    let total_length = 28u32 + 24 + payload.len() as u32;
    let sa_payload_length = 24u16 + payload.len() as u16;

    let mut header = Vec::with_capacity(total_length as usize);

    header.extend_from_slice(&initiator_spi);
    header.extend_from_slice(&responder_spi);
    header.push(0x21);
    header.push(0x20);
    header.push(0x22);
    header.push(0x08);
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    header.extend_from_slice(&total_length.to_be_bytes());

    header.push(0x00);
    header.push(0x00);
    header.extend_from_slice(&sa_payload_length.to_be_bytes());

    header.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x14, 0x01, 0x01, 0x00, 0x04, 0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00,
        0x0c, 0x00, 0x00, 0x00, 0x00,
    ]);

    header.extend_from_slice(payload);
    header
}

fn generate_junk(cfg: &AetherNoizeConfig) -> Vec<u8> {
    let (min_size, max_size) = match (cfg.jmin, cfg.jmax) {
        (0, 0) if cfg.allow_zero_size => return vec![],
        (0, 0) => return vec![0x00],
        (min, 0) if !cfg.allow_zero_size => (min.max(1), min.max(1)),
        (min, max) if !cfg.allow_zero_size => (min.max(1), max.max(min)),
        (min, max) => (min, max.max(min)),
    };

    let size = if max_size == min_size {
        min_size
    } else {
        rand::rng().random_range(min_size..=max_size)
    };

    if size == 0 {
        return if cfg.allow_zero_size {
            vec![]
        } else {
            vec![0x00]
        };
    }

    let mut junk = vec![0u8; size];
    rand::rng().fill_bytes(&mut junk);
    junk
}

async fn send_connected(sock: &UdpSocket, pkt: &[u8]) {
    let _ = sock.send(pkt).await;
}

pub async fn apply_obfuscation(sock: &UdpSocket, _peer: SocketAddr, cfg: &AetherNoizeConfig) {
    if !cfg.is_enabled() {
        return;
    }

    if let Some(ref i1) = cfg.i1 {
        let payload = parse_cps(i1);
        if !payload.is_empty() {
            let framed = wrap_ikev2(&payload);
            send_connected(sock, &framed).await;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    for _ in 0..cfg.jc_after_i1 {
        let junk = generate_junk(cfg);
        send_connected(sock, &junk).await;
        if !cfg.junk_interval.is_zero() {
            tokio::time::sleep(cfg.junk_interval).await;
        }
    }

    for _ in 0..cfg.jc_before_hs {
        let junk = generate_junk(cfg);
        send_connected(sock, &junk).await;
        if !cfg.junk_interval.is_zero() {
            tokio::time::sleep(cfg.junk_interval).await;
        }
    }

    for sig in [&cfg.i2, &cfg.i3, &cfg.i4, &cfg.i5].iter() {
        if let Some(s) = sig {
            let pkt = parse_cps(s);
            if !pkt.is_empty() {
                send_connected(sock, &pkt).await;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }

    if !cfg.handshake_delay.is_zero() {
        tokio::time::sleep(cfg.handshake_delay).await;
    }
}

pub async fn send_post_handshake_junk(
    sock: &UdpSocket,
    _peer: SocketAddr,
    cfg: &AetherNoizeConfig,
) {
    for _ in 0..cfg.jc_after_hs {
        let junk = generate_junk(cfg);
        send_connected(sock, &junk).await;
        if !cfg.junk_interval.is_zero() {
            tokio::time::sleep(cfg.junk_interval).await;
        }
    }
}

pub async fn send_keepalive_junk(sock: &UdpSocket, cfg: &AetherNoizeConfig) {
    if !cfg.is_enabled() {
        return;
    }

    let base = cfg.jc_before_hs.max(1);
    let extra = rand::rng().random_range(0..=base);
    let count = base + extra;

    for _ in 0..count {
        let mut junk = generate_junk(cfg);
        if let Some(first) = junk.first_mut() {
            if *first >= 1 && *first <= 4 {
                *first = first.wrapping_add(0x40);
            }
        }
        send_connected(sock, &junk).await;

        let jitter = rand::rng().random_range(0..=8);
        let gap = cfg.junk_interval + Duration::from_millis(jitter);
        if !gap.is_zero() {
            tokio::time::sleep(gap).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_advertised_profile_resolves_to_its_own_shape() {
        assert!(!from_profile("off").is_enabled());
        assert_eq!(from_profile("light").jc, AetherNoizeConfig::light().jc);
        assert_eq!(
            from_profile("firewall").jc,
            AetherNoizeConfig::firewall().jc
        );
        assert_eq!(from_profile("gfw").jc, AetherNoizeConfig::gfw().jc);
        assert_eq!(
            from_profile("aggressive").jc,
            AetherNoizeConfig::aggressive().jc
        );
    }

    #[test]
    fn firewall_and_gfw_are_not_silently_balanced() {
        let balanced = AetherNoizeConfig::balanced();
        assert_ne!(from_profile("firewall").jc, balanced.jc);
        assert_ne!(from_profile("gfw").jc, balanced.jc);
    }

    #[test]
    fn a_profile_name_is_matched_regardless_of_case_or_padding() {
        assert_eq!(from_profile("  GFW  ").jc, AetherNoizeConfig::gfw().jc);
    }

    #[test]
    fn the_counter_tag_advances_instead_of_repeating_the_clock() {
        let first = parse_cps("<c>");
        let second = parse_cps("<c>");
        assert_eq!(first.len(), 4);
        assert_ne!(first, second);
    }

    #[test]
    fn the_counter_tag_is_not_the_timestamp_tag() {
        let counter = parse_cps("<c>");
        let stamp = parse_cps("<t>");
        assert_ne!(counter, stamp);
    }
}

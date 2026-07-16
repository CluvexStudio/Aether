use std::net::Ipv4Addr;

use octets::{Octets, OctetsMut};
use quiche::h3;
use rand::Rng;

use crate::consts;
use crate::error::{AetherError, Result};

pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;
pub const CAPSULE_DATAGRAM: u64 = 0x00;

#[derive(Debug, Clone)]
pub struct AssignedAddress {
    pub request_id: u64,
    pub ip_version: u8,
    pub address: Vec<u8>,
    pub prefix_len: u8,
}

#[derive(Debug, Clone)]
pub struct RouteAdvertisement {
    pub ip_version: u8,
    pub start: Vec<u8>,
    pub end: Vec<u8>,
    pub protocol: u8,
}

#[derive(Debug, Clone)]
pub enum Capsule {
    AddressAssign(Vec<AssignedAddress>),
    AddressRequest,
    Datagram(Vec<u8>),
    RouteAdvertisement(Vec<RouteAdvertisement>),
    Unknown { kind: u64, payload: Vec<u8> },
}

pub fn connect_ip_request(authority: &str, path: &str) -> Vec<h3::Header> {
    vec![
        h3::Header::new(b":method", b"CONNECT"),
        h3::Header::new(b":protocol", consts::CF_CONNECT_PROTOCOL.as_bytes()),
        h3::Header::new(b":scheme", b"https"),
        h3::Header::new(b":authority", authority.as_bytes()),
        h3::Header::new(b":path", path.as_bytes()),
        h3::Header::new(b"user-agent", b""),
        h3::Header::new(b"capsule-protocol", b"?1"),
    ]
}

pub fn quarter_stream_id(stream_id: u64) -> u64 {
    stream_id / 4
}

pub fn encode_ip_datagram(stream_id: u64, ip_packet: &[u8]) -> Result<Vec<u8>> {
    let qsid = quarter_stream_id(stream_id);
    let ctx = consts::CONNECT_IP_CONTEXT_ID;

    let cap = varint_len(qsid) + varint_len(ctx) + ip_packet.len();
    let mut out = vec![0u8; cap];

    {
        let mut b = OctetsMut::with_slice(&mut out);
        b.put_varint(qsid).map_err(oct)?;
        b.put_varint(ctx).map_err(oct)?;
        b.put_bytes(ip_packet).map_err(oct)?;
    }

    Ok(out)
}

pub fn decode_ip_datagram(datagram: &[u8], expect_stream_id: u64) -> Result<Option<Vec<u8>>> {
    let mut b = Octets::with_slice(datagram);

    let qsid = b.get_varint().map_err(oct)?;
    if qsid != quarter_stream_id(expect_stream_id) {
        return Ok(None);
    }

    let ctx = b.get_varint().map_err(oct)?;
    if ctx != consts::CONNECT_IP_CONTEXT_ID {
        return Ok(None);
    }

    let rest = b.cap();
    let payload = b.get_bytes(rest).map_err(oct)?;
    Ok(Some(payload.to_vec()))
}

pub fn encode_capsule(kind: u64, value: &[u8]) -> Vec<u8> {
    let cap = varint_len(kind) + varint_len(value.len() as u64) + value.len();
    let mut out = vec![0u8; cap];
    {
        let mut b = OctetsMut::with_slice(&mut out);
        let _ = b.put_varint(kind);
        let _ = b.put_varint(value.len() as u64);
        let _ = b.put_bytes(value);
    }
    out
}

pub fn encode_address_request(request_id: u64, ip_version: u8, prefix_len: u8) -> Vec<u8> {
    let value_len = varint_len(request_id) + 1 + 1;
    let mut value = vec![0u8; value_len];
    {
        let mut b = OctetsMut::with_slice(&mut value);
        let _ = b.put_varint(request_id);
        let _ = b.put_u8(ip_version);
        let _ = b.put_u8(prefix_len);
    }
    encode_capsule(CAPSULE_ADDRESS_REQUEST, &value)
}

pub fn encode_datagram_capsule(ip_packet: &[u8]) -> Vec<u8> {
    encode_capsule(CAPSULE_DATAGRAM, ip_packet)
}

pub struct CapsuleParser {
    buf: Vec<u8>,
}

impl CapsuleParser {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn next(&mut self) -> Result<Option<Capsule>> {
        let mut b = Octets::with_slice(&self.buf);

        let kind = match b.get_varint() {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let len = match b.get_varint() {
            Ok(v) => v as usize,
            Err(_) => return Ok(None),
        };
        if b.cap() < len {
            return Ok(None);
        }

        let value = b.get_bytes(len).map_err(oct)?.to_vec();
        let consumed = b.off();
        self.buf.drain(0..consumed);

        let capsule = match kind {
            CAPSULE_ADDRESS_ASSIGN => Capsule::AddressAssign(parse_address_assign(&value)?),
            CAPSULE_ADDRESS_REQUEST => Capsule::AddressRequest,
            CAPSULE_ROUTE_ADVERTISEMENT => {
                Capsule::RouteAdvertisement(parse_route_advertisement(&value)?)
            },
            CAPSULE_DATAGRAM => Capsule::Datagram(value),
            other => Capsule::Unknown {
                kind: other,
                payload: value,
            },
        };

        Ok(Some(capsule))
    }
}

impl Default for CapsuleParser {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_address_assign(value: &[u8]) -> Result<Vec<AssignedAddress>> {
    let mut b = Octets::with_slice(value);
    let mut out = Vec::new();

    while b.cap() > 0 {
        let request_id = b.get_varint().map_err(oct)?;
        let ip_version = b.get_u8().map_err(oct)?;
        let addr_len = match ip_version {
            4 => 4,
            6 => 16,
            _ => return Err(AetherError::Capsule(format!("bad ip version {ip_version}"))),
        };
        let address = b.get_bytes(addr_len).map_err(oct)?.to_vec();
        let prefix_len = b.get_u8().map_err(oct)?;

        out.push(AssignedAddress {
            request_id,
            ip_version,
            address,
            prefix_len,
        });
    }

    Ok(out)
}

fn parse_route_advertisement(value: &[u8]) -> Result<Vec<RouteAdvertisement>> {
    let mut b = Octets::with_slice(value);
    let mut out = Vec::new();

    while b.cap() > 0 {
        let ip_version = b.get_u8().map_err(oct)?;
        let addr_len = match ip_version {
            4 => 4,
            6 => 16,
            _ => return Err(AetherError::Capsule(format!("bad ip version {ip_version}"))),
        };
        let start = b.get_bytes(addr_len).map_err(oct)?.to_vec();
        let end = b.get_bytes(addr_len).map_err(oct)?.to_vec();
        let protocol = b.get_u8().map_err(oct)?;

        out.push(RouteAdvertisement {
            ip_version,
            start,
            end,
            protocol,
        });
    }

    Ok(out)
}

fn varint_len(v: u64) -> usize {
    if v < 64 {
        1
    } else if v < 16384 {
        2
    } else if v < 1_073_741_824 {
        4
    } else {
        8
    }
}

fn oct(e: octets::BufferTooShortError) -> AetherError {
    AetherError::Capsule(e.to_string())
}

pub fn build_dns_probe_packet(src: Ipv4Addr) -> Vec<u8> {
    let dns = probe_dns_query();
    let udp_len = 8 + dns.len();
    let total_len = 20 + udp_len;

    let mut pkt = Vec::with_capacity(total_len);

    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    let id: u16 = rand::random();
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(64);
    pkt.push(17);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&Ipv4Addr::new(8, 8, 8, 8).octets());
    let csum = ipv4_header_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());

    let sport: u16 = rand::thread_rng().gen_range(20000..60000);
    pkt.extend_from_slice(&sport.to_be_bytes());
    pkt.extend_from_slice(&53u16.to_be_bytes());
    pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);

    pkt.extend_from_slice(&dns);
    pkt
}

fn probe_dns_query() -> Vec<u8> {
    let id: u16 = rand::random();
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in ["cloudflare", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x01]);
    q
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

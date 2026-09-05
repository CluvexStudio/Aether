use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use crate::aethernoize::AetherNoizeConfig;
use crate::error::{AetherError, Result};

#[derive(Debug, Clone)]
pub struct CustomWgConfig {
    pub interface: InterfaceSection,
    pub peer: PeerSection,
    pub client_id: [u8; 3],
}

#[derive(Debug, Clone, Default)]
pub struct InterfaceSection {
    pub private_key: [u8; 32],
    pub addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, Default)]
pub struct PeerSection {
    pub public_key: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    // AllowedIPs are parsed for config completeness but route setup is not
    // yet wired into run_wireguard_tunnel. Kept for future use.
    pub allowed_ips: Vec<ipnet::IpNet>,
}

impl CustomWgConfig {
    pub fn from_file(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| AetherError::Other(format!("custom wg config: read {path}: {e}")))?;

        let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut current: Option<(String, HashMap<String, String>)> = None;

        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                if let Some((name, map)) = current.take() {
                    sections.insert(name.to_lowercase(), map);
                }
                let name = line[1..line.len() - 1].trim().to_lowercase();
                current = Some((name, HashMap::new()));
                continue;
            }

            let Some((name, rest)) = line.split_once('=') else {
                continue;
            };
            let key = name.trim().to_lowercase();
            let value = rest.trim().trim_start_matches('=').trim();

            if let Some((_section, map)) = current.as_mut() {
                map.insert(key, value.to_string());
            }
        }

        if let Some((name, map)) = current.take() {
            sections.insert(name.to_lowercase(), map);
        }

        let interface = sections
            .get("interface")
            .ok_or_else(|| AetherError::Other("custom wg config: missing [Interface]".into()))?;
        let peer = sections
            .get("peer")
            .ok_or_else(|| AetherError::Other("custom wg config: missing [Peer]".into()))?;

        let private_key = decode_key("Interface.PrivateKey", interface.get("privatekey").ok_or_else(|| {
            AetherError::Other("custom wg config: Interface.PrivateKey is required".into())
        })?)?;

        let addresses = interface
            .get("address")
            .or_else(|| interface.get("allowedips"))
            .map(|v| parse_address_list(v))
            .transpose()
            .map_err(|e| AetherError::Other(format!("custom wg config: bad Interface.Address: {e}")))?
            .unwrap_or_default();

        let public_key = decode_key("Peer.PublicKey", peer.get("publickey").ok_or_else(|| {
            AetherError::Other("custom wg config: Peer.PublicKey is required".into())
        })?)?;

        let endpoint = peer
            .get("endpoint")
            .map(|v| {
                v.parse::<SocketAddr>()
                    .map_err(|e| AetherError::Other(format!("custom wg config: bad Peer.Endpoint: {e}")))
            })
            .transpose()?;

        let allowed_ips = peer
            .get("allowedips")
            .map(|v| parse_allowedips(v))
            .transpose()
            .map_err(|e| AetherError::Other(format!("custom wg config: bad Peer.AllowedIPs: {e}")))?
            .unwrap_or_default();

        Ok(Self {
            interface: InterfaceSection {
                private_key,
                addresses,
            },
            peer: PeerSection {
                public_key,
                endpoint,
                allowed_ips,
            },
            client_id: [0u8; 3],
        })
    }

    pub fn local_ipv4(&self) -> Result<Ipv4Addr> {
        self.interface
            .addresses
            .iter()
            .find_map(|ip| match ip {
                IpAddr::V4(v4) => Some(*v4),
                _ => None,
            })
            .ok_or_else(|| AetherError::Other("custom wg config: no IPv4 address in Interface.Address".into()))
    }

    pub fn local_ipv6(&self) -> Result<Ipv6Addr> {
        self.interface
            .addresses
            .iter()
            .find_map(|ip| match ip {
                IpAddr::V6(v6) => Some(*v6),
                _ => None,
            })
            .ok_or_else(|| AetherError::Other("custom wg config: no IPv6 address in Interface.Address".into()))
    }

    pub fn aethernoize(&self) -> AetherNoizeConfig {
        crate::aethernoize::from_profile("off")
    }
}

fn decode_key(label: &str, value: &str) -> Result<[u8; 32]> {
    let decoded = BASE64
        .decode(value)
        .map_err(|e| AetherError::Other(format!("custom wg config: {label} is not valid base64: {e}")))?;

    if decoded.len() != 32 {
        return Err(AetherError::Other(format!(
            "custom wg config: {label} must decode to 32 bytes, found {}",
            decoded.len()
        )));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn parse_address_list(value: &str) -> Result<Vec<IpAddr>> {
    value
        .split(',')
        .map(|part| {
            let addr = part.trim();
            if addr.is_empty() {
                return Err(AetherError::Other("empty address entry".into()));
            }
            let had_cidr = addr.contains('/');
            let bare = addr.split('/').next().unwrap_or(addr).trim();
            if had_cidr {
                log::warn!("[customwg] stripping CIDR from Interface.Address entry '{addr}', using '{}'", bare);
            }
            bare.parse::<IpAddr>()
                .map_err(|e| AetherError::Other(format!("bad address {addr}: {e}")))
        })
        .collect()
}

fn parse_allowedips(value: &str) -> Result<Vec<ipnet::IpNet>> {
    value
        .split(',')
        .map(|part| {
            let entry = part.trim();
            if entry.is_empty() {
                return Err(AetherError::Other("empty AllowedIPs entry".into()));
            }
            entry
                .parse::<ipnet::IpNet>()
                .map_err(|e| AetherError::Other(format!("bad AllowedIPs {entry}: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_standard_wg_config() {
        let dir = std::env::temp_dir().join(format!("aether-customwg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let path = dir.join("custom.conf");
        std::fs::write(
            &path,
            "[Interface]\n\
             PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
             Address = 10.0.0.2/32, fd00::2/128\n\
             \n\
             [Peer]\n\
             PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
             Endpoint = 162.159.192.1:2408\n\
             AllowedIPs = 0.0.0.0/0, ::/0\n",
        )
        .unwrap();

        let cfg = CustomWgConfig::from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.interface.private_key.len(), 32);
        assert_eq!(cfg.peer.public_key.len(), 32);
        assert_eq!(cfg.interface.addresses.len(), 2);
        assert_eq!(cfg.peer.endpoint, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(cfg.peer.allowed_ips.len(), 2);
    }

    #[test]
    fn rejects_a_config_without_private_key() {
        let dir = std::env::temp_dir().join(format!("aether-customwg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let path = dir.join("bad.conf");
        std::fs::write(&path, "[Interface]\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n").unwrap();

        let err = CustomWgConfig::from_file(path.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("PrivateKey"));
    }
}

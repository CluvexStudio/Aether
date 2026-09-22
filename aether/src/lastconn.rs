use std::collections::HashSet;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

pub const RECENT_CAP: usize = 8;

pub const CARRIER_MASQUE_H3: &str = "masque-h3";
pub const CARRIER_MASQUE_H2: &str = "masque-h2";
pub const CARRIER_WIREGUARD: &str = "wireguard";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LastConnection {
    pub peer: String,
    #[serde(default)]
    pub profile: String,
    #[serde(default)]
    pub carrier: String,
    #[serde(default)]
    pub recent: Vec<String>,
}

pub fn load(path: &str) -> Option<LastConnection> {
    let text = std::fs::read_to_string(path).ok()?;
    toml::from_str(&text).ok()
}

pub fn save(path: &str, peer: &str, profile: &str, carrier: &str) {
    let previous = load(path);
    let carried_over = previous
        .as_ref()
        .filter(|c| c.carrier.is_empty() || c.carrier == carrier)
        .map(|c| c.recent.clone())
        .unwrap_or_default();

    let mut recent: Vec<String> = vec![peer.to_string()];
    for entry in carried_over {
        if entry != peer && recent.len() < RECENT_CAP {
            recent.push(entry);
        }
    }

    let conn = LastConnection {
        peer: peer.to_string(),
        profile: profile.to_string(),
        carrier: carrier.to_string(),
        recent,
    };

    match toml::to_string_pretty(&conn) {
        Ok(text) => {
            if let Err(e) = std::fs::write(path, text) {
                log::debug!("[lastconn] failed to save {path}: {e}");
            }
        }
        Err(e) => log::debug!("[lastconn] failed to encode: {e}"),
    }
}

pub fn usable_peers(cached: &LastConnection, carrier: &str) -> Vec<SocketAddr> {
    if !cached.carrier.is_empty() && cached.carrier != carrier {
        log::debug!(
            "[lastconn] ignoring gateways saved for {} while running {carrier}",
            cached.carrier
        );
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in std::iter::once(&cached.peer).chain(cached.recent.iter()) {
        if let Ok(addr) = raw.parse::<SocketAddr>() {
            if seen.insert(addr) {
                out.push(addr);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> String {
        let mut path = std::env::temp_dir();
        path.push(format!("aether-lastconn-{tag}-{}.toml", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path.to_string_lossy().to_string()
    }

    #[test]
    fn the_newest_gateway_leads_the_ring() {
        let path = scratch("ring");
        save(&path, "1.1.1.1:443", "gfw", CARRIER_MASQUE_H3);
        save(&path, "1.0.0.1:443", "gfw", CARRIER_MASQUE_H3);
        save(&path, "1.1.1.1:443", "gfw", CARRIER_MASQUE_H3);
        let loaded = load(&path).expect("it was just written");
        assert_eq!(loaded.peer, "1.1.1.1:443");
        assert_eq!(loaded.recent, vec!["1.1.1.1:443", "1.0.0.1:443"]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_ring_never_grows_past_its_cap() {
        let path = scratch("cap");
        for n in 0..20u8 {
            save(
                &path,
                &format!("10.0.0.{n}:443"),
                "balanced",
                CARRIER_WIREGUARD,
            );
        }
        let loaded = load(&path).expect("it was just written");
        assert_eq!(loaded.recent.len(), RECENT_CAP);
        assert_eq!(loaded.recent[0], "10.0.0.19:443");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_file_written_by_an_older_build_still_loads() {
        let path = scratch("legacy");
        std::fs::write(&path, "peer = \"1.1.1.1:443\"\nprofile = \"gfw\"\n").expect("write");
        let loaded = load(&path).expect("it was just written");
        assert_eq!(loaded.peer, "1.1.1.1:443");
        assert!(loaded.recent.is_empty());
        assert!(loaded.carrier.is_empty());
        assert_eq!(
            usable_peers(&loaded, CARRIER_MASQUE_H2),
            vec!["1.1.1.1:443".parse::<SocketAddr>().expect("an address")]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn gateways_proved_on_one_carrier_are_not_reused_on_another() {
        let cached = LastConnection {
            peer: "1.1.1.1:1701".to_string(),
            profile: String::new(),
            carrier: CARRIER_MASQUE_H3.to_string(),
            recent: vec!["1.1.1.1:1701".to_string()],
        };
        assert!(usable_peers(&cached, CARRIER_MASQUE_H2).is_empty());
        assert_eq!(usable_peers(&cached, CARRIER_MASQUE_H3).len(), 1);
    }

    #[test]
    fn unparsable_and_repeated_entries_are_dropped() {
        let cached = LastConnection {
            peer: "not-an-address".to_string(),
            profile: String::new(),
            carrier: String::new(),
            recent: vec!["1.1.1.1:443".to_string(), "1.1.1.1:443".to_string()],
        };
        assert_eq!(
            usable_peers(&cached, CARRIER_MASQUE_H3),
            vec!["1.1.1.1:443".parse::<SocketAddr>().expect("an address")]
        );
    }
}

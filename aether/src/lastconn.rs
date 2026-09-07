use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// How many recently-working endpoints are remembered for the fast path.
pub const RECENT_CAP: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LastConnection {
    pub peer: String,
    #[serde(default)]
    pub profile: String,
    /// Most-recent-first ring of working `ip:port`s. Old files simply lack
    /// it and load as empty, so this stays backward compatible.
    #[serde(default)]
    pub recent: Vec<String>,
}

pub fn load(path: &str) -> Option<LastConnection> {
    let text = std::fs::read_to_string(path).ok()?;
    toml::from_str(&text).ok()
}

pub fn save(path: &str, peer: &str, profile: &str) {
    let mut recent = load(path).map(|c| c.recent).unwrap_or_default();
    recent.retain(|p| p != peer);
    recent.insert(0, peer.to_string());
    recent.truncate(RECENT_CAP);
    let conn = LastConnection {
        peer: peer.to_string(),
        profile: profile.to_string(),
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

/// Parsed, most-recent-first candidates for the reconnect fast path.
pub fn recent_peers(cached: &LastConnection) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
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

    fn tmp_path(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("aether-lastconn-test-{tag}-{}.toml", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().to_string()
    }

    #[test]
    fn save_builds_a_most_recent_first_ring() {
        let path = tmp_path("ring");
        save(&path, "1.1.1.1:443", "gfw");
        save(&path, "1.0.0.1:443", "gfw");
        save(&path, "1.1.1.1:443", "gfw");
        let loaded = load(&path).expect("saved file must load");
        assert_eq!(loaded.peer, "1.1.1.1:443", "peer stays the latest");
        assert_eq!(loaded.recent, vec!["1.1.1.1:443", "1.0.0.1:443"]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ring_is_capped_and_deduped() {
        let path = tmp_path("cap");
        for i in 0..20u8 {
            save(&path, &format!("10.0.0.{i}:443"), "balanced");
        }
        let loaded = load(&path).expect("saved file must load");
        assert_eq!(loaded.recent.len(), RECENT_CAP);
        assert_eq!(loaded.recent[0], "10.0.0.19:443");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn old_files_without_recent_still_load() {
        let path = tmp_path("legacy");
        std::fs::write(&path, "peer = \"1.1.1.1:443\"\nprofile = \"gfw\"\n").unwrap();
        let loaded = load(&path).expect("legacy file must load");
        assert_eq!(loaded.peer, "1.1.1.1:443");
        assert!(loaded.recent.is_empty());
        assert_eq!(recent_peers(&loaded), vec!["1.1.1.1:443".parse().unwrap()]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn recent_peers_skips_garbage_and_dupes() {
        let cached = LastConnection {
            peer: "not-an-addr".to_string(),
            profile: String::new(),
            recent: vec!["1.1.1.1:443".to_string(), "1.1.1.1:443".to_string()],
        };
        assert_eq!(recent_peers(&cached), vec!["1.1.1.1:443".parse().unwrap()]);
    }
}

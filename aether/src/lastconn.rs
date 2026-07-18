use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LastConnection {
    pub peer: String,
    #[serde(default)]
    pub profile: String,
}

pub fn load(path: &str) -> Option<LastConnection> {
    let text = std::fs::read_to_string(path).ok()?;
    toml::from_str(&text).ok()
}

pub fn save(path: &str, peer: &str, profile: &str) {
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let conn = LastConnection {
        peer: peer.to_string(),
        profile: profile.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lastconn_save_creates_parent_dir() {
        let dir = std::env::temp_dir().join(format!("aether_test_lc_{}", rand::random::<u64>()));
        let nested_path = dir.join("nested").join("dir").join("lastconn.toml");
        let path_str = nested_path.to_str().unwrap();

        save(path_str, "127.0.0.1:443", "firewall");
        assert!(nested_path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}


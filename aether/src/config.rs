use std::path::Path;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::account::Identity;
use crate::error::{AetherError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedIdentity {
    pub device_id: String,
    pub access_token: String,
    #[serde(default)]
    pub cert_pem: String,
    #[serde(default)]
    pub key_pem: String,
    pub ipv4: String,
    pub ipv6: String,
    pub wg_private_key: String,
    pub wg_peer_public_key: String,
    #[serde(default)]
    pub client_id: String,
}

impl From<&Identity> for PersistedIdentity {
    fn from(id: &Identity) -> Self {
        Self {
            device_id: id.device_id.clone(),
            access_token: id.access_token.clone(),
            cert_pem: String::from_utf8_lossy(&id.cert_pem).to_string(),
            key_pem: String::from_utf8_lossy(&id.key_pem).to_string(),
            ipv4: id.ipv4.clone(),
            ipv6: id.ipv6.clone(),
            wg_private_key: base64::engine::general_purpose::STANDARD.encode(id.wg_private_key),
            wg_peer_public_key: base64::engine::general_purpose::STANDARD
                .encode(id.wg_peer_public_key),
            client_id: base64::engine::general_purpose::STANDARD.encode(id.client_id),
        }
    }
}

impl From<PersistedIdentity> for Identity {
    fn from(p: PersistedIdentity) -> Self {
        let wg_priv = base64::engine::general_purpose::STANDARD
            .decode(&p.wg_private_key)
            .expect("decode wg private key");

        let wg_peer = base64::engine::general_purpose::STANDARD
            .decode(&p.wg_peer_public_key)
            .expect("decode wg peer public key");

        let mut wg_private_key = [0u8; 32];
        let mut wg_peer_public_key = [0u8; 32];
        let mut client_id_arr = [0u8; 3];
        wg_private_key.copy_from_slice(&wg_priv);
        wg_peer_public_key.copy_from_slice(&wg_peer);
        
        if !p.client_id.is_empty() {
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&p.client_id) {
                if decoded.len() == 3 {
                    client_id_arr.copy_from_slice(&decoded);
                }
            }
        }

        Identity {
            device_id: p.device_id,
            access_token: p.access_token,
            cert_pem: p.cert_pem.into_bytes(),
            key_pem: p.key_pem.into_bytes(),
            ipv4: p.ipv4,
            ipv6: p.ipv6,
            wg_private_key,
            wg_peer_public_key,
            client_id: client_id_arr,
        }
    }
}

pub fn load(path: &str) -> Result<Option<Identity>> {
    if !Path::new(path).exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path)?;
    let persisted: PersistedIdentity =
        toml::from_str(&text).map_err(|e| AetherError::Other(format!("config parse: {e}")))?;
    Ok(Some(persisted.into()))
}

pub fn save(path: &str, identity: &Identity) -> Result<()> {
    if let Some(parent) = Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| AetherError::Other(format!("config dir create {}: {e}", parent.display())))?;
    }
    let persisted = PersistedIdentity::from(identity);
    let text = toml::to_string_pretty(&persisted)
        .map_err(|e| AetherError::Other(format!("config encode: {e}")))?;
    std::fs::write(path, text)?;
    Ok(())
}

pub fn save_masque_creds(path: &str, cert_pem: &[u8], key_pem: &[u8]) -> Result<()> {
    if !Path::new(path).exists() {
        return Ok(());
    }
    let text = std::fs::read_to_string(path)?;
    let mut persisted: PersistedIdentity =
        toml::from_str(&text).map_err(|e| AetherError::Other(format!("config parse: {e}")))?;
    persisted.cert_pem = String::from_utf8_lossy(cert_pem).to_string();
    persisted.key_pem = String::from_utf8_lossy(key_pem).to_string();
    let updated = toml::to_string_pretty(&persisted)
        .map_err(|e| AetherError::Other(format!("config encode: {e}")))?;
    std::fs::write(path, updated)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_creates_parent_dir() {
        let dir = std::env::temp_dir().join(format!("aether_test_cfg_{}", rand::random::<u64>()));
        let nested_path = dir.join("nested").join("dir").join("aether.toml");
        let path_str = nested_path.to_str().unwrap();

        let identity = Identity {
            device_id: "dev123".into(),
            access_token: "tok123".into(),
            cert_pem: vec![],
            key_pem: vec![],
            ipv4: "192.0.2.1".into(),
            ipv6: "2001:db8::1".into(),
            wg_private_key: [1u8; 32],
            wg_peer_public_key: [2u8; 32],
            client_id: [0u8; 3],
        };

        let res = save(path_str, &identity);
        assert!(res.is_ok());
        assert!(nested_path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}


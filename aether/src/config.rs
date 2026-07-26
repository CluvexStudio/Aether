use std::path::Path;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::account::Identity;
use crate::error::{AetherError, Result};

/// Decode a base64 field into a fixed-size key, reporting the field name on
/// failure instead of panicking. A truncated or hand-edited config must be a
/// recoverable error: the caller can re-register, but it cannot catch a panic.
fn decode_key<const N: usize>(field: &str, value: &str) -> Result<[u8; N]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|e| AetherError::Other(format!("config: {field} is not valid base64: {e}")))?;
    <[u8; N]>::try_from(raw.as_slice()).map_err(|_| {
        AetherError::Other(format!(
            "config: {field} decodes to {} bytes, expected {N}",
            raw.len()
        ))
    })
}

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

impl TryFrom<PersistedIdentity> for Identity {
    type Error = AetherError;

    fn try_from(p: PersistedIdentity) -> Result<Self> {
        let wg_private_key = decode_key::<32>("wg_private_key", &p.wg_private_key)?;
        let wg_peer_public_key = decode_key::<32>("wg_peer_public_key", &p.wg_peer_public_key)?;

        // client_id predates the current format, so an absent or unreadable
        // value stays a zeroed default rather than an error.
        let mut client_id = [0u8; 3];
        if !p.client_id.is_empty() {
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&p.client_id) {
                if decoded.len() == client_id.len() {
                    client_id.copy_from_slice(&decoded);
                }
            }
        }

        Ok(Identity {
            device_id: p.device_id,
            access_token: p.access_token,
            cert_pem: p.cert_pem.into_bytes(),
            key_pem: p.key_pem.into_bytes(),
            ipv4: p.ipv4,
            ipv6: p.ipv6,
            wg_private_key,
            wg_peer_public_key,
            client_id,
        })
    }
}

/// Write a file that holds private keys: atomically, and readable only by the
/// current user. `std::fs::write` truncates in place — a crash mid-write leaves
/// a half-written config — and it creates the file with the process umask,
/// which is world-readable on a typical Linux box.
fn write_private(path: &str, contents: &str) -> Result<()> {
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, contents)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }

    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn load(path: &str) -> Result<Option<Identity>> {
    if !Path::new(path).exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path)?;
    let persisted: PersistedIdentity =
        toml::from_str(&text).map_err(|e| AetherError::Other(format!("config parse: {e}")))?;
    Ok(Some(Identity::try_from(persisted)?))
}

pub fn save(path: &str, identity: &Identity) -> Result<()> {
    let persisted = PersistedIdentity::from(identity);
    let text = toml::to_string_pretty(&persisted)
        .map_err(|e| AetherError::Other(format!("config encode: {e}")))?;
    write_private(path, &text)
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
    write_private(path, &updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn persisted(wg_private_key: &str, wg_peer_public_key: &str) -> PersistedIdentity {
        PersistedIdentity {
            device_id: "d".into(),
            access_token: "t".into(),
            cert_pem: String::new(),
            key_pem: String::new(),
            ipv4: "10.0.0.2".into(),
            ipv6: "::1".into(),
            wg_private_key: wg_private_key.into(),
            wg_peer_public_key: wg_peer_public_key.into(),
            client_id: String::new(),
        }
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn reads_a_well_formed_identity() {
        let id = Identity::try_from(persisted(&b64(&[1u8; 32]), &b64(&[2u8; 32]))).unwrap();
        assert_eq!(id.wg_private_key, [1u8; 32]);
        assert_eq!(id.wg_peer_public_key, [2u8; 32]);
    }

    #[test]
    fn a_truncated_key_is_an_error_not_a_panic() {
        // What a config left half-written by a killed process looks like.
        let err = Identity::try_from(persisted(&b64(&[1u8; 20]), &b64(&[2u8; 32]))).unwrap_err();
        assert!(err.to_string().contains("wg_private_key"), "{err}");
        assert!(err.to_string().contains("expected 32"), "{err}");
    }

    #[test]
    fn a_key_that_is_not_base64_is_an_error_not_a_panic() {
        let err =
            Identity::try_from(persisted("!!! not base64 !!!", &b64(&[2u8; 32]))).unwrap_err();
        assert!(err.to_string().contains("not valid base64"), "{err}");
    }

    #[test]
    fn an_oversized_key_is_rejected_too() {
        let err = Identity::try_from(persisted(&b64(&[1u8; 33]), &b64(&[2u8; 32]))).unwrap_err();
        assert!(err.to_string().contains("expected 32"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn the_saved_config_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("aether-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("aether.toml");
        let path = path.to_str().unwrap();

        write_private(path, "device_id = \"d\"\n").unwrap();

        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "config holds private keys, mode was {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

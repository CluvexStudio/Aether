use std::path::{Path, PathBuf};

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
    #[serde(default)]
    pub cert_issued_at: u64,
    pub ipv4: String,
    pub ipv6: String,
    pub wg_private_key: String,
    pub wg_peer_public_key: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub gateway_proxy: String,
    #[serde(default)]
    pub assigned_endpoint: String,
}

impl From<&Identity> for PersistedIdentity {
    fn from(id: &Identity) -> Self {
        Self {
            device_id: id.device_id.clone(),
            access_token: id.access_token.clone(),
            cert_pem: String::from_utf8_lossy(&id.cert_pem).to_string(),
            key_pem: String::from_utf8_lossy(&id.key_pem).to_string(),
            cert_issued_at: id.cert_issued_at,
            ipv4: id.ipv4.clone(),
            ipv6: id.ipv6.clone(),
            wg_private_key: base64::engine::general_purpose::STANDARD.encode(id.wg_private_key),
            wg_peer_public_key: base64::engine::general_purpose::STANDARD
                .encode(id.wg_peer_public_key),
            client_id: base64::engine::general_purpose::STANDARD.encode(id.client_id),
            organization: id.organization.clone(),
            gateway_proxy: id.gateway_proxy.clone(),
            assigned_endpoint: id.assigned_endpoint.clone(),
        }
    }
}

fn decode_fixed<const N: usize>(field: &str, value: &str) -> Result<[u8; N]> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| AetherError::Other(format!("config field {field} is not valid base64: {e}")))?;

    if decoded.len() != N {
        return Err(AetherError::Other(format!(
            "config field {field} must decode to {N} bytes, found {}",
            decoded.len()
        )));
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&decoded);
    Ok(out)
}

impl TryFrom<PersistedIdentity> for Identity {
    type Error = AetherError;

    fn try_from(p: PersistedIdentity) -> Result<Self> {
        let wg_private_key = decode_fixed::<32>("wg_private_key", &p.wg_private_key)?;
        let wg_peer_public_key = decode_fixed::<32>("wg_peer_public_key", &p.wg_peer_public_key)?;

        let client_id = if p.client_id.is_empty() {
            [0u8; 3]
        } else {
            decode_fixed::<3>("client_id", &p.client_id).unwrap_or([0u8; 3])
        };

        Ok(Identity {
            device_id: p.device_id,
            access_token: p.access_token,
            cert_pem: p.cert_pem.into_bytes(),
            key_pem: p.key_pem.into_bytes(),
            cert_issued_at: p.cert_issued_at,
            ipv4: p.ipv4,
            ipv6: p.ipv6,
            wg_private_key,
            wg_peer_public_key,
            client_id,
            organization: p.organization,
            gateway_proxy: p.gateway_proxy,
            assigned_endpoint: p.assigned_endpoint,
        })
    }
}

fn quarantine_path(path: &str) -> PathBuf {
    let mut target = PathBuf::from(path);
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "aether.toml".to_string());
    target.set_file_name(format!("{name}.corrupt"));
    target
}

fn quarantine(path: &str) -> Option<PathBuf> {
    let target = quarantine_path(path);
    match std::fs::rename(path, &target) {
        Ok(()) => Some(target),
        Err(_) => None,
    }
}

pub fn load(path: &str) -> Result<Option<Identity>> {
    if !Path::new(path).exists() {
        return Ok(None);
    }

    let text = std::fs::read_to_string(path)?;

    let persisted: PersistedIdentity = match toml::from_str(&text) {
        Ok(value) => value,
        Err(e) => {
            let moved = quarantine(path);
            return Err(AetherError::Other(match moved {
                Some(target) => format!(
                    "config parse: {e}; the damaged file was moved to {} so a fresh identity can be provisioned",
                    target.display()
                ),
                None => format!("config parse: {e}; delete {path} to provision a fresh identity"),
            }));
        }
    };

    match Identity::try_from(persisted) {
        Ok(identity) => Ok(Some(identity)),
        Err(e) => {
            let moved = quarantine(path);
            Err(AetherError::Other(match moved {
                Some(target) => format!(
                    "{e}; the damaged file was moved to {} so a fresh identity can be provisioned",
                    target.display()
                ),
                None => format!("{e}; delete {path} to provision a fresh identity"),
            }))
        }
    }
}

fn write_private(path: &str, contents: &str) -> Result<()> {
    let target = Path::new(path);
    let directory = target.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = directory {
        std::fs::create_dir_all(dir)?;
    }

    let mut temporary = PathBuf::from(path);
    let name = temporary
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "aether.toml".to_string());
    temporary.set_file_name(format!(".{name}.{}.tmp", std::process::id()));

    let outcome = (|| -> Result<()> {
        {
            use std::io::Write;

            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);

            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }

            let mut file = options.open(&temporary)?;
            file.write_all(contents.as_bytes())?;
            file.flush()?;
            file.sync_all()?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
        }

        std::fs::rename(&temporary, target)?;
        Ok(())
    })();

    if outcome.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }

    outcome
}

pub fn save(path: &str, identity: &Identity) -> Result<()> {
    let persisted = PersistedIdentity::from(identity);
    let text = toml::to_string_pretty(&persisted)
        .map_err(|e| AetherError::Other(format!("config encode: {e}")))?;
    write_private(path, &text)
}

pub fn save_masque_creds(
    path: &str,
    cert_pem: &[u8],
    key_pem: &[u8],
    issued_at: u64,
) -> Result<()> {
    if !Path::new(path).exists() {
        return Ok(());
    }

    let text = std::fs::read_to_string(path)?;
    let mut persisted: PersistedIdentity =
        toml::from_str(&text).map_err(|e| AetherError::Other(format!("config parse: {e}")))?;

    persisted.cert_pem = String::from_utf8_lossy(cert_pem).to_string();
    persisted.key_pem = String::from_utf8_lossy(key_pem).to_string();
    persisted.cert_issued_at = issued_at;

    let updated = toml::to_string_pretty(&persisted)
        .map_err(|e| AetherError::Other(format!("config encode: {e}")))?;
    write_private(path, &updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Identity;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aether-config-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        dir
    }

    fn sample() -> Identity {
        Identity {
            device_id: "device-1".to_string(),
            access_token: "token-1".to_string(),
            cert_pem: b"-----BEGIN CERTIFICATE-----".to_vec(),
            key_pem: b"-----BEGIN PRIVATE KEY-----".to_vec(),
            cert_issued_at: 1_700_000_000,
            ipv4: "172.16.0.2".to_string(),
            ipv6: "2606:4700::2".to_string(),
            wg_private_key: [7u8; 32],
            wg_peer_public_key: [9u8; 32],
            client_id: [1, 2, 3],
            organization: "example-team".to_string(),
            gateway_proxy: "172.16.0.1:2480".to_string(),
            assigned_endpoint: "162.159.197.2".to_string(),
        }
    }

    #[test]
    fn saves_and_loads_every_field_including_the_issue_time() {
        let dir = scratch("roundtrip");
        let path = dir.join("aether.toml");
        let path_str = path.to_str().unwrap();

        save(path_str, &sample()).expect("save should succeed");
        let loaded = load(path_str).expect("load should succeed").expect("identity");

        assert_eq!(loaded.device_id, "device-1");
        assert_eq!(loaded.access_token, "token-1");
        assert_eq!(loaded.cert_issued_at, 1_700_000_000);
        assert_eq!(loaded.wg_private_key, [7u8; 32]);
        assert_eq!(loaded.wg_peer_public_key, [9u8; 32]);
        assert_eq!(loaded.client_id, [1, 2, 3]);
    }

    #[cfg(unix)]
    #[test]
    fn the_secret_file_is_only_readable_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("perms");
        let path = dir.join("aether.toml");
        let path_str = path.to_str().unwrap();

        save(path_str, &sample()).expect("save should succeed");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "found mode {mode:o}, expected 600");
    }

    #[test]
    fn saving_leaves_no_temporary_file_behind() {
        let dir = scratch("atomic");
        let path = dir.join("aether.toml");

        save(path.to_str().unwrap(), &sample()).expect("save should succeed");

        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .expect("read dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.ends_with(".tmp"))
            .collect();

        assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");
    }

    #[test]
    fn overwriting_an_existing_config_keeps_it_readable() {
        let dir = scratch("overwrite");
        let path = dir.join("aether.toml");
        let path_str = path.to_str().unwrap();

        save(path_str, &sample()).expect("first save");
        let mut second = sample();
        second.device_id = "device-2".to_string();
        save(path_str, &second).expect("second save");

        let loaded = load(path_str).expect("load").expect("identity");
        assert_eq!(loaded.device_id, "device-2");
    }

    #[test]
    fn a_corrupt_config_is_reported_and_set_aside_instead_of_panicking() {
        let dir = scratch("corrupt");
        let path = dir.join("aether.toml");
        let path_str = path.to_str().unwrap();

        std::fs::write(&path, "this is not = valid toml [[[").expect("write");

        let outcome = load(path_str);
        assert!(outcome.is_err(), "a corrupt config must be an error");
        assert!(
            !path.exists(),
            "the corrupt file should have been moved aside"
        );
        assert!(
            dir.join("aether.toml.corrupt").exists(),
            "the quarantined copy should exist"
        );
    }

    #[test]
    fn a_truncated_key_is_an_error_not_a_panic() {
        let dir = scratch("shortkey");
        let path = dir.join("aether.toml");
        let path_str = path.to_str().unwrap();

        let body = "\
device_id = \"d\"
access_token = \"t\"
cert_pem = \"\"
key_pem = \"\"
cert_issued_at = 0
ipv4 = \"172.16.0.2\"
ipv6 = \"::1\"
wg_private_key = \"AAAA\"
wg_peer_public_key = \"AAAA\"
client_id = \"\"
";
        std::fs::write(&path, body).expect("write");

        let outcome = load(path_str);
        assert!(outcome.is_err(), "a short key must be rejected");
        let message = format!("{}", outcome.err().unwrap());
        assert!(
            message.contains("wg_private_key"),
            "the error should name the bad field, got: {message}"
        );
    }

    #[test]
    fn a_key_that_is_not_base64_is_an_error_not_a_panic() {
        let dir = scratch("badbase64");
        let path = dir.join("aether.toml");
        let path_str = path.to_str().unwrap();

        let body = "\
device_id = \"d\"
access_token = \"t\"
ipv4 = \"172.16.0.2\"
ipv6 = \"::1\"
wg_private_key = \"!!!not base64!!!\"
wg_peer_public_key = \"AAAA\"
";
        std::fs::write(&path, body).expect("write");

        assert!(load(path_str).is_err());
    }

    #[test]
    fn a_missing_config_is_simply_absent() {
        let dir = scratch("missing");
        let path = dir.join("aether.toml");
        assert!(load(path.to_str().unwrap()).expect("load").is_none());
    }

    #[test]
    fn refreshing_the_masque_credentials_records_the_new_issue_time() {
        let dir = scratch("creds");
        let path = dir.join("aether.toml");
        let path_str = path.to_str().unwrap();

        save(path_str, &sample()).expect("save");
        save_masque_creds(path_str, b"new-cert", b"new-key", 1_800_000_000).expect("update");

        let loaded = load(path_str).expect("load").expect("identity");
        assert_eq!(loaded.cert_pem, b"new-cert".to_vec());
        assert_eq!(loaded.key_pem, b"new-key".to_vec());
        assert_eq!(loaded.cert_issued_at, 1_800_000_000);
    }

    #[cfg(unix)]
    #[test]
    fn refreshing_the_credentials_keeps_the_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("credperms");
        let path = dir.join("aether.toml");
        let path_str = path.to_str().unwrap();

        save(path_str, &sample()).expect("save");
        save_masque_creds(path_str, b"c", b"k", 42).expect("update");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

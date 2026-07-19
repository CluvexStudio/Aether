use base64::Engine;
use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::PKey;
use boring::x509::{X509Builder, X509NameBuilder};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::consts;
use crate::error::{AetherError, Result};

#[derive(Debug, Clone, Serialize)]
struct Registration {
    key: String,
    install_id: String,
    fcm_token: String,
    tos: String,
    model: String,
    serial_number: String,
    os_version: String,
    key_type: String,
    tunnel_type: String,
    locale: String,
}

#[derive(Debug, Clone, Serialize)]
struct DeviceUpdate {
    key: String,
    key_type: String,
    tunnel_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountData {
    pub id: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub config: Config,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub interface: Interface,
    #[serde(default)]
    pub peers: Vec<Peer>,
    #[serde(default)]
    pub client_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Peer {
    pub public_key: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Interface {
    #[serde(default)]
    pub addresses: Addresses,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Addresses {
    #[serde(default)]
    pub v4: String,
    #[serde(default)]
    pub v6: String,
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub device_id: String,
    pub access_token: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ipv4: String,
    pub ipv6: String,
    pub wg_private_key: [u8; 32],
    pub wg_peer_public_key: [u8; 32],
    pub client_id: [u8; 3],
}

pub struct MasqueKeyPair {
    pub key_pem: Vec<u8>,
    pub cert_pem: Vec<u8>,
    pub spki_der: Vec<u8>,
}

pub fn generate_masque_keypair() -> Result<MasqueKeyPair> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    let ec = EcKey::generate(&group).map_err(|e| AetherError::Tls(e.to_string()))?;
    let pkey = PKey::from_ec_key(ec).map_err(|e| AetherError::Tls(e.to_string()))?;

    let key_pem = pkey
        .private_key_to_pem_pkcs8()
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    let spki_der = pkey
        .public_key_to_der()
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let mut builder = X509Builder::new().map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_version(2)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let serial = BigNum::from_u32(0)
        .and_then(|bn| bn.to_asn1_integer())
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_serial_number(&serial)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let name = X509NameBuilder::new()
        .map_err(|e| AetherError::Tls(e.to_string()))?
        .build();
    builder
        .set_subject_name(&name)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_issuer_name(&name)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let not_before = Asn1Time::days_from_now(0).map_err(|e| AetherError::Tls(e.to_string()))?;
    // ponytail: 365-day validity avoids expired-cert reconnect loops after 24h;
    // upgrade to cert-expiry check + auto-renew if Cloudflare tightens validity
    let not_after = Asn1Time::days_from_now(365).map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_not_before(&not_before)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_not_after(&not_after)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder
        .set_pubkey(&pkey)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .sign(&pkey, MessageDigest::sha256())
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let cert_pem = builder
        .build()
        .to_pem()
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    Ok(MasqueKeyPair {
        key_pem,
        cert_pem,
        spki_der,
    })
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(consts::UA_REGISTER)
        .build()
        .map_err(|e| AetherError::Api(e.to_string()))
}

fn base_headers() -> reqwest::header::HeaderMap {
    use reqwest::header::{HeaderMap, HeaderValue, CONNECTION, CONTENT_TYPE};
    let mut h = HeaderMap::new();
    h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json; charset=UTF-8"));
    h.insert(CONNECTION, HeaderValue::from_static("Keep-Alive"));
    h.insert(
        "CF-Client-Version",
        HeaderValue::from_static(consts::CF_CLIENT_VERSION),
    );
    h
}

fn generate_x25519_keypair() -> ([u8; 32], String) {
    let mut private = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut private);

    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;

    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
    let public_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());

    (private, public_b64)
}

fn random_android_serial() -> String {
    let mut s = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut s);
    hex::encode(s)
}

fn tos_timestamp() -> String {
    chrono::Local::now()
        .format("%Y-%m-%dT%H:%M:%S%.3f%:z")
        .to_string()
}

pub async fn register(model: &str, locale: &str, jwt: Option<&str>) -> Result<(AccountData, [u8; 32])> {
    let (wg_private, wg_public) = generate_x25519_keypair();

    let body = Registration {
        key: wg_public,
        install_id: String::new(),
        fcm_token: String::new(),
        tos: tos_timestamp(),
        model: model.to_string(),
        serial_number: random_android_serial(),
        os_version: String::new(),
        key_type: "curve25519".to_string(),
        tunnel_type: "wireguard".to_string(),
        locale: locale.to_string(),
    };

    let url = format!("{}/{}/reg", consts::API_URL, consts::API_VERSION);
    let mut req = http_client()?
        .post(url)
        .headers(base_headers())
        .json(&body);

    if let Some(jwt) = jwt {
        req = req.header("CF-Access-Jwt-Assertion", jwt);
    }

    let resp = req.send().await.map_err(|e| AetherError::Api(e.to_string()))?;
    let account = parse_account(resp).await?;
    Ok((account, wg_private))
}

pub async fn enroll_key(
    device_id: &str,
    token: &str,
    spki_der: &[u8],
    name: Option<&str>,
) -> Result<AccountData> {
    let body = DeviceUpdate {
        key: base64::engine::general_purpose::STANDARD.encode(spki_der),
        key_type: consts::KEY_TYPE_MASQUE.to_string(),
        tunnel_type: consts::TUN_TYPE_MASQUE.to_string(),
        name: name.map(|s| s.to_string()),
    };

    let url = format!("{}/{}/reg/{}", consts::API_URL, consts::API_VERSION, device_id);
    let resp = http_client()?
        .patch(url)
        .headers(base_headers())
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|e| AetherError::Api(e.to_string()))?;

    parse_account(resp).await
}

pub async fn update_license(device_id: &str, token: &str, license_key: &str) -> Result<()> {
    let url = format!(
        "{}/{}/reg/{}/account",
        consts::API_URL,
        consts::API_VERSION,
        device_id
    );

    let body = serde_json::json!({ "license": license_key });

    let resp = http_client()?
        .put(url)
        .headers(base_headers())
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|e| AetherError::Api(e.to_string()))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| AetherError::Api(e.to_string()))?;

    if !status.is_success() {
        return Err(AetherError::Api(format!(
            "license update failed (status {status}): {text}"
        )));
    }

    // Check if WARP+ activated
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
        if v.get("warp_plus").and_then(|w| w.as_bool()) == Some(true) {
            log::info!("[+] WARP+ license activated successfully");
        } else {
            log::warn!("[-] license applied but warp_plus not confirmed in response");
        }
        if let Some(quota) = v.get("premium_data").and_then(|p| p.as_u64()) {
            log::info!("[+] premium data quota: {} bytes", quota);
        }
    }

    Ok(())
}

async fn parse_account(resp: reqwest::Response) -> Result<AccountData> {
    let status = resp.status();
    let text = resp.text().await.map_err(|e| AetherError::Api(e.to_string()))?;

    if !status.is_success() {
        return Err(AetherError::Api(format!("status {status}: {text}")));
    }

    serde_json::from_str::<AccountData>(&text)
        .map_err(|e| AetherError::Api(format!("decode: {e}; body={text}")))
}

fn extract_wg_peer(reg: &AccountData) -> Result<[u8; 32]> {
    if reg.config.peers.is_empty() {
        return Err(AetherError::Api("no peers in registration response".into()));
    }
    let peer_b64 = &reg.config.peers[0].public_key;
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, peer_b64)
        .map_err(|e| AetherError::Api(format!("decode peer pubkey: {e}")))?;
    if decoded.len() != 32 {
        return Err(AetherError::Api("invalid peer pubkey length".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&decoded);
    Ok(arr)
}

pub async fn provision_wg(model: &str, locale: &str, jwt: Option<&str>) -> Result<Identity> {
    let (reg, wg_private) = register(model, locale, jwt).await?;
    if reg.token.is_empty() {
        return Err(AetherError::Api("registration returned empty token".into()));
    }

    let wg_peer_public = extract_wg_peer(&reg)?;

    let mut client_id_arr = [0u8; 3];
    if !reg.config.client_id.is_empty() {
        log::debug!("[account] received client_id from API: {:?}", reg.config.client_id);
        if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &reg.config.client_id) {
            if decoded.len() == 3 {
                client_id_arr.copy_from_slice(&decoded);
                log::debug!("[account] decoded client_id: {:02x?}", client_id_arr);
            } else {
                log::warn!("[account] client_id decoded but wrong length: {}", decoded.len());
            }
        } else {
            log::warn!("[account] failed to decode client_id base64");
        }
    } else {
        log::warn!("[account] API response has empty client_id, using zeros");
    }

    Ok(Identity {
        device_id: reg.id,
        access_token: reg.token,
        cert_pem: Vec::new(),
        key_pem: Vec::new(),
        ipv4: reg.config.interface.addresses.v4,
        ipv6: reg.config.interface.addresses.v6,
        wg_private_key: wg_private,
        wg_peer_public_key: wg_peer_public,
        client_id: client_id_arr,
    })
}

pub async fn ensure_masque_enrolled(identity: &Identity) -> Result<(Vec<u8>, Vec<u8>)> {
    if !identity.cert_pem.is_empty() && !identity.key_pem.is_empty() {
        return Ok((identity.cert_pem.clone(), identity.key_pem.clone()));
    }

    log::info!("[+] enrolling MASQUE key for device {}", identity.device_id);
    let keypair = generate_masque_keypair()?;
    enroll_key(&identity.device_id, &identity.access_token, &keypair.spki_der, None).await?;
    log::info!("[+] MASQUE key enrolled");
    Ok((keypair.cert_pem, keypair.key_pem))
}

impl Identity {
    pub fn private_key_bytes(&self) -> Result<[u8; 32]> {
        Ok(self.wg_private_key)
    }

    pub fn peer_public_key_bytes(&self) -> Result<[u8; 32]> {
        Ok(self.wg_peer_public_key)
    }

    pub fn has_masque_credentials(&self) -> bool {
        !self.cert_pem.is_empty() && !self.key_pem.is_empty()
    }

    /// Returns true if masque credentials exist AND the cert is not expired.
    pub fn has_valid_masque_credentials(&self) -> bool {
        if !self.has_masque_credentials() {
            return false;
        }
        // ponytail: parse cert to check expiry; if parsing fails, treat as expired
        // so we re-enroll rather than loop with a broken cert
        match boring::x509::X509::from_pem(&self.cert_pem) {
            Ok(cert) => {
                match Asn1Time::days_from_now(0) {
                    Ok(now) => cert.not_after() >= now,
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }
}

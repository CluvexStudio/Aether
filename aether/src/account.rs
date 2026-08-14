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

use crate::apifront;
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
struct TeamRegistration {
    key: String,
    install_id: String,
    fcm_token: String,
    tos: String,
    model: String,
    name: String,
    serial_number: String,
    locale: String,
}

fn team_registration_body(public_key: String, model: &str, locale: &str) -> TeamRegistration {
    let install_id = crate::zerotrust::generate_install_id();
    let fcm_token = crate::zerotrust::generate_fcm_token(&install_id);

    TeamRegistration {
        key: public_key,
        tos: tos_timestamp(),
        model: model.to_string(),
        name: install_id.clone(),
        serial_number: install_id.clone(),
        locale: locale.to_string(),
        install_id,
        fcm_token,
    }
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
    #[serde(default)]
    pub account: AccountInfo,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub interface: Interface,
    #[serde(default)]
    pub peers: Vec<Peer>,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub services: Services,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Services {
    #[serde(default)]
    pub http_proxy: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Peer {
    pub public_key: String,
    #[serde(default)]
    pub endpoint: PeerEndpoint,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PeerEndpoint {
    #[serde(default)]
    pub v4: String,
    #[serde(default)]
    pub v6: String,
    #[serde(default)]
    pub host: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AccountInfo {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub account_type: String,
    #[serde(default)]
    pub organization: String,
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
    pub cert_issued_at: u64,
    pub ipv4: String,
    pub ipv6: String,
    pub wg_private_key: [u8; 32],
    pub wg_peer_public_key: [u8; 32],
    pub client_id: [u8; 3],
    pub organization: String,
    pub gateway_proxy: String,
    pub assigned_endpoint: String,
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
    let not_after = Asn1Time::days_from_now(MASQUE_CERT_LIFETIME_DAYS)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
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
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| AetherError::Api(e.to_string()))
}

const API_ATTEMPTS: u32 = 5;
const API_BACKOFF_BASE_MS: u64 = 900;
const API_BACKOFF_CAP_MS: u64 = 15_000;
const API_RETRY_AFTER_CAP_SECS: u64 = 30;

fn backoff_delay(attempt: u32) -> std::time::Duration {
    let exponential = API_BACKOFF_BASE_MS.saturating_mul(1u64 << attempt.min(5));
    let capped = exponential.min(API_BACKOFF_CAP_MS);
    let jitter = rand::thread_rng().next_u32() as u64 % (capped / 3 + 1);
    std::time::Duration::from_millis(capped / 2 + jitter)
}

fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<std::time::Duration> {
    let raw = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    let seconds = raw.trim().parse::<u64>().ok()?;
    Some(std::time::Duration::from_secs(
        seconds.min(API_RETRY_AFTER_CAP_SECS),
    ))
}

fn worth_retrying(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status.is_server_error()
}

fn api_host() -> &'static str {
    consts::API_URL
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("api.cloudflareclient.com")
}

fn front_headers(bearer: Option<&str>, jwt: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![
        (
            "Content-Type".to_string(),
            "application/json; charset=UTF-8".to_string(),
        ),
        ("User-Agent".to_string(), consts::UA_REGISTER.to_string()),
        (
            "CF-Client-Version".to_string(),
            consts::CF_CLIENT_VERSION.to_string(),
        ),
        ("Accept".to_string(), "application/json".to_string()),
    ];
    if let Some(token) = bearer {
        headers.push(("Authorization".to_string(), format!("Bearer {token}")));
    }
    if let Some(token) = jwt {
        headers.push(("CF-Access-Jwt-Assertion".to_string(), token.to_string()));
    }
    headers
}

async fn fallback_call(
    label: &str,
    method: &str,
    path: &str,
    body: Option<Vec<u8>>,
    bearer: Option<&str>,
    jwt: Option<&str>,
) -> Result<AccountData> {
    log::info!(
        "[*] {label} retrying over a camouflaged route: random cloudflare edge address, \
         no dns lookup, split client hello, alternate tls fingerprints"
    );

    let request = apifront::ApiRequest {
        method: method.to_string(),
        host: api_host().to_string(),
        path: path.to_string(),
        headers: front_headers(bearer, jwt),
        body,
    };

    let response = apifront::fetch(&request).await?;

    if (200..300).contains(&response.status) {
        log::info!("[+] {label} went through the camouflaged route ({})", response.route);
        return serde_json::from_str::<AccountData>(&response.body).map_err(|e| {
            AetherError::Api(format!(
                "{label} decode over {}: {e}; body={}",
                response.route, response.body
            ))
        });
    }

    Err(AetherError::Api(format!(
        "{label} over {}: {}",
        response.route,
        describe_status(response.status, &response.body)
    )))
}

fn describe_status(status: u16, body: &str) -> String {
    match reqwest::StatusCode::from_u16(status) {
        Ok(code) => describe_rejection(code, body),
        Err(_) => format!("status {status}: {body}"),
    }
}

fn describe_rejection(status: reqwest::StatusCode, body: &str) -> String {
    let detail = extract_api_error(body).unwrap_or_else(|| {
        let trimmed = body.trim();
        if trimmed.is_empty() {
            "no details returned".to_string()
        } else if trimmed.len() > 220 {
            format!("{}…", &trimmed[..220])
        } else {
            trimmed.to_string()
        }
    });

    let hint = match status.as_u16() {
        403 => " (cloudflare refused this network; the address looks flagged, \
                try again later, switch network, or import an existing identity)",
        429 => " (too many registrations from this address; wait a few minutes \
                before trying again)",
        _ => "",
    };

    format!("status {status}: {detail}{hint}")
}

fn extract_api_error(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let errors = value.get("errors")?.as_array()?;
    let parts: Vec<String> = errors
        .iter()
        .filter_map(|entry| {
            let message = entry
                .get("message")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            let code = entry.get("code").and_then(|value| value.as_i64());
            Some(match code {
                Some(code) => format!("{message} (code {code})"),
                None => message.to_string(),
            })
        })
        .collect();

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

async fn send_with_retry<F>(label: &str, build: F) -> Result<AccountData>
where
    F: Fn() -> Result<reqwest::RequestBuilder>,
{
    let mut last_error = AetherError::Api(format!("{label}: no attempt was made"));

    for attempt in 0..API_ATTEMPTS {
        if attempt > 0 {
            let wait = backoff_delay(attempt - 1);
            log::warn!(
                "[!] {label} retry {}/{} in {:.1}s: {last_error}",
                attempt,
                API_ATTEMPTS - 1,
                wait.as_secs_f32()
            );
            tokio::time::sleep(wait).await;
        }

        let response = match build()?.send().await {
            Ok(response) => response,
            Err(error) => {
                last_error = AetherError::Api(format!("{label}: {error}"));
                continue;
            }
        };

        let status = response.status();
        let cooldown = retry_after(response.headers());
        let body = response
            .text()
            .await
            .map_err(|e| AetherError::Api(format!("{label}: {e}")))?;

        if status.is_success() {
            return serde_json::from_str::<AccountData>(&body)
                .map_err(|e| AetherError::Api(format!("{label} decode: {e}; body={body}")));
        }

        last_error = AetherError::Api(format!("{label}: {}", describe_rejection(status, &body)));

        if !worth_retrying(status) {
            return Err(last_error);
        }

        if let Some(wait) = cooldown {
            log::warn!(
                "[!] {label} asked us to wait {}s before retrying",
                wait.as_secs()
            );
            tokio::time::sleep(wait).await;
        }
    }

    Err(last_error)
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

    let path = format!("/{}/reg", consts::API_VERSION);
    let url = format!("{}{}", consts::API_URL, path);
    let encoded =
        serde_json::to_vec(&body).map_err(|e| AetherError::Api(format!("encode: {e}")))?;

    let direct = send_with_retry("registration", || {
        let mut req = http_client()?
            .post(&url)
            .headers(base_headers())
            .json(&body);
        if let Some(jwt) = jwt {
            req = req.header("CF-Access-Jwt-Assertion", jwt);
        }
        Ok(req)
    })
    .await;

    let account = match direct {
        Ok(account) => account,
        Err(primary) => {
            log::warn!("[!] registration failed over the direct route: {primary}");
            match fallback_call(
                "registration",
                "POST",
                &path,
                Some(encoded),
                None,
                jwt,
            )
            .await
            {
                Ok(account) => account,
                Err(secondary) => {
                    return Err(AetherError::Api(format!(
                        "registration: direct route -> {primary}; camouflaged route -> {secondary}"
                    )));
                }
            }
        }
    };

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

    let path = format!("/{}/reg/{}", consts::API_VERSION, device_id);
    let url = format!("{}{}", consts::API_URL, path);
    let encoded =
        serde_json::to_vec(&body).map_err(|e| AetherError::Api(format!("encode: {e}")))?;

    let direct = send_with_retry("key enrollment", || {
        Ok(http_client()?
            .patch(&url)
            .headers(base_headers())
            .bearer_auth(token)
            .json(&body))
    })
    .await;

    match direct {
        Ok(account) => Ok(account),
        Err(primary) => {
            log::warn!("[!] key enrollment failed over the direct route: {primary}");
            match fallback_call(
                "key enrollment",
                "PATCH",
                &path,
                Some(encoded),
                Some(token),
                None,
            )
            .await
            {
                Ok(account) => Ok(account),
                Err(secondary) => Err(AetherError::Api(format!(
                    "key enrollment: direct route -> {primary}; camouflaged route -> {secondary}"
                ))),
            }
        }
    }
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

pub async fn register_with_team(
    model: &str,
    locale: &str,
    token: &str,
) -> Result<(AccountData, [u8; 32])> {
    let (wg_private, wg_public) = generate_x25519_keypair();
    let body = team_registration_body(wg_public, model, locale);

    let path = format!("/{}/reg", consts::API_VERSION);
    let url = format!("{}{}", consts::API_URL, path);
    let encoded =
        serde_json::to_vec(&body).map_err(|e| AetherError::Api(format!("encode: {e}")))?;

    let direct = send_with_retry("team registration", || {
        Ok(http_client()?
            .post(&url)
            .headers(base_headers())
            .header("CF-Access-Jwt-Assertion", token)
            .json(&body))
    })
    .await;

    let account = match direct {
        Ok(account) => account,
        Err(primary) => {
            log::warn!("[!] team registration failed over the direct route: {primary}");
            match fallback_call(
                "team registration",
                "POST",
                &path,
                Some(encoded),
                None,
                Some(token),
            )
            .await
            {
                Ok(account) => account,
                Err(secondary) => {
                    return Err(AetherError::Api(format!(
                        "team registration: direct route -> {primary}; \
                         camouflaged route -> {secondary}"
                    )));
                }
            }
        }
    };

    Ok((account, wg_private))
}

pub async fn provision_team(
    model: &str,
    locale: &str,
    settings: &crate::zerotrust::TeamSettings,
) -> Result<Identity> {
    let token = crate::zerotrust::resolve_token(settings).await?;
    let (reg, wg_private) = register_with_team(model, locale, &token).await?;
    finish_provision(reg, wg_private)
}

pub async fn provision_wg(model: &str, locale: &str, jwt: Option<&str>) -> Result<Identity> {
    let (reg, wg_private) = register(model, locale, jwt).await?;
    finish_provision(reg, wg_private)
}

pub async fn fetch_device(device_id: &str, token: &str) -> Result<AccountData> {
    let path = format!("/{}/reg/{}", consts::API_VERSION, device_id);
    let url = format!("{}{}", consts::API_URL, path);

    let direct = send_with_retry("device refresh", || {
        Ok(http_client()?
            .get(&url)
            .headers(base_headers())
            .bearer_auth(token))
    })
    .await;

    match direct {
        Ok(account) => Ok(account),
        Err(primary) => {
            log::debug!("[!] device refresh failed over the direct route: {primary}");
            fallback_call("device refresh", "GET", &path, None, Some(token), None).await
        }
    }
}

pub fn endpoint_from(reg: &AccountData) -> String {
    let raw = reg
        .config
        .peers
        .first()
        .map(|peer| peer.endpoint.v4.trim())
        .unwrap_or_default();

    match raw.rsplit_once(':') {
        Some((host, _)) if !host.is_empty() => host.to_string(),
        _ => raw.to_string(),
    }
}

pub async fn refresh_profile(identity: Identity) -> Identity {
    let reg = match fetch_device(&identity.device_id, &identity.access_token).await {
        Ok(reg) => reg,
        Err(error) => {
            log::debug!("[!] could not refresh the device profile: {error}");
            return identity;
        }
    };

    let ipv4 = reg.config.interface.addresses.v4.trim().to_string();
    let ipv6 = reg.config.interface.addresses.v6.trim().to_string();
    let organization = reg.account.organization.trim().to_string();
    let gateway_proxy = reg.config.services.http_proxy.trim().to_string();
    let assigned_endpoint = endpoint_from(&reg);

    if !ipv4.is_empty() && ipv4 != identity.ipv4 {
        log::info!(
            "[+] the account moved this device from {} to {ipv4}; using the assigned address",
            identity.ipv4
        );
    }
    if !organization.is_empty() {
        log::info!(
            "[+] confirmed membership of organization {organization} (account type {})",
            reg.account.account_type
        );
    }
    if !gateway_proxy.is_empty() {
        log::debug!("[zerotrust] the organization publishes a gateway http proxy at {gateway_proxy}");
    }

    Identity {
        ipv4: if ipv4.is_empty() { identity.ipv4 } else { ipv4 },
        ipv6: if ipv6.is_empty() { identity.ipv6 } else { ipv6 },
        organization,
        gateway_proxy,
        assigned_endpoint,
        ..identity
    }
}

fn finish_provision(reg: AccountData, wg_private: [u8; 32]) -> Result<Identity> {
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

    let organization = reg.account.organization.trim().to_string();
    let gateway_proxy = reg.config.services.http_proxy.trim().to_string();
    let assigned_endpoint = endpoint_from(&reg);

    Ok(Identity {
        device_id: reg.id,
        access_token: reg.token,
        cert_pem: Vec::new(),
        key_pem: Vec::new(),
        cert_issued_at: 0,
        ipv4: reg.config.interface.addresses.v4,
        ipv6: reg.config.interface.addresses.v6,
        wg_private_key: wg_private,
        wg_peer_public_key: wg_peer_public,
        client_id: client_id_arr,
        organization,
        gateway_proxy,
        assigned_endpoint,
    })
}

pub const MASQUE_CERT_LIFETIME_DAYS: u32 = 365;
pub const MASQUE_CERT_LIFETIME_SECS: u64 = MASQUE_CERT_LIFETIME_DAYS as u64 * 86_400;
pub const MASQUE_CERT_RENEW_BEFORE_SECS: u64 = 7 * 86_400;

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn masque_cert_expiring(issued_at: u64) -> bool {
    if issued_at == 0 {
        return true;
    }
    let now = now_unix();
    if now < issued_at {
        return true;
    }
    let age = now - issued_at;
    age + MASQUE_CERT_RENEW_BEFORE_SECS >= MASQUE_CERT_LIFETIME_SECS
}

pub struct MasqueEnrollment {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub issued_at: u64,
    pub renewed: bool,
}

pub async fn ensure_masque_enrolled(identity: &Identity) -> Result<MasqueEnrollment> {
    let usable = !identity.cert_pem.is_empty() && !identity.key_pem.is_empty();

    if usable && !masque_cert_expiring(identity.cert_issued_at) {
        return Ok(MasqueEnrollment {
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            issued_at: identity.cert_issued_at,
            renewed: false,
        });
    }

    if usable {
        log::info!("[*] masque certificate is expiring, enrolling a fresh key");
    } else {
        log::info!("[+] enrolling MASQUE key for device {}", identity.device_id);
    }

    let keypair = generate_masque_keypair()?;
    match enroll_key(&identity.device_id, &identity.access_token, &keypair.spki_der, None).await {
        Ok(_) => {
            log::info!("[+] MASQUE key enrolled");
            Ok(MasqueEnrollment {
                cert_pem: keypair.cert_pem,
                key_pem: keypair.key_pem,
                issued_at: now_unix(),
                renewed: true,
            })
        }
        Err(error) if cert_still_usable(identity) => {
            log::warn!(
                "[!] key enrollment failed ({error}); keeping the certificate already on disk"
            );
            Ok(MasqueEnrollment {
                cert_pem: identity.cert_pem.clone(),
                key_pem: identity.key_pem.clone(),
                issued_at: identity.cert_issued_at,
                renewed: false,
            })
        }
        Err(error) => Err(error),
    }
}

pub fn cert_still_usable(identity: &Identity) -> bool {
    if identity.cert_pem.is_empty() || identity.key_pem.is_empty() {
        return false;
    }
    if identity.cert_issued_at == 0 {
        return false;
    }
    let now = now_unix();
    if now < identity.cert_issued_at {
        return false;
    }
    now - identity.cert_issued_at < MASQUE_CERT_LIFETIME_SECS
}

impl Identity {
    pub fn private_key_bytes(&self) -> Result<[u8; 32]> {
        Ok(self.wg_private_key)
    }

    pub fn peer_public_key_bytes(&self) -> Result<[u8; 32]> {
        Ok(self.wg_peer_public_key)
    }

    pub fn has_masque_credentials(&self) -> bool {
        !self.cert_pem.is_empty()
            && !self.key_pem.is_empty()
            && !masque_cert_expiring(self.cert_issued_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_certificate_lives_far_longer_than_a_day() {
        assert!(MASQUE_CERT_LIFETIME_DAYS >= 365);
        assert!(MASQUE_CERT_LIFETIME_SECS > 86_400 * 300);
    }

    #[test]
    fn a_missing_issue_time_counts_as_expiring() {
        assert!(masque_cert_expiring(0));
    }

    #[test]
    fn a_fresh_certificate_is_not_expiring() {
        assert!(!masque_cert_expiring(now_unix()));
    }

    #[test]
    fn a_certificate_older_than_a_day_is_still_valid() {
        assert!(!masque_cert_expiring(now_unix() - 86_400 * 2));
    }

    #[test]
    fn a_certificate_inside_the_renewal_window_is_expiring() {
        let issued = now_unix() - (MASQUE_CERT_LIFETIME_SECS - MASQUE_CERT_RENEW_BEFORE_SECS / 2);
        assert!(masque_cert_expiring(issued));
    }

    #[test]
    fn a_certificate_issued_in_the_future_counts_as_expiring() {
        assert!(masque_cert_expiring(now_unix() + 86_400));
    }

    fn sample_identity(cert_issued_at: u64, with_cert: bool) -> Identity {
        Identity {
            device_id: "device".to_string(),
            access_token: "token".to_string(),
            cert_pem: if with_cert { b"cert".to_vec() } else { Vec::new() },
            key_pem: if with_cert { b"key".to_vec() } else { Vec::new() },
            cert_issued_at,
            ipv4: "172.16.0.2".to_string(),
            ipv6: String::new(),
            wg_private_key: [0u8; 32],
            wg_peer_public_key: [0u8; 32],
            client_id: [0u8; 3],
            organization: String::new(),
            gateway_proxy: String::new(),
            assigned_endpoint: String::new(),
        }
    }

    #[test]
    fn a_certificate_inside_its_lifetime_is_still_usable_offline() {
        let identity = sample_identity(now_unix() - 86_400 * 360, true);
        assert!(cert_still_usable(&identity));
    }

    #[test]
    fn a_certificate_past_its_lifetime_is_not_usable() {
        let identity = sample_identity(now_unix() - MASQUE_CERT_LIFETIME_SECS - 10, true);
        assert!(!cert_still_usable(&identity));
    }

    #[test]
    fn a_missing_certificate_is_never_usable() {
        let identity = sample_identity(now_unix(), false);
        assert!(!cert_still_usable(&identity));
    }

    #[test]
    fn a_rate_limited_rejection_explains_the_wait() {
        let message = describe_rejection(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            "{\"success\":false,\"errors\":[{\"code\":1015,\"message\":\"rate limited\"}]}",
        );
        assert!(message.contains("rate limited"));
        assert!(message.contains("code 1015"));
        assert!(message.contains("wait a few minutes"));
    }

    #[test]
    fn a_forbidden_rejection_mentions_the_flagged_address() {
        let message = describe_rejection(reqwest::StatusCode::FORBIDDEN, "");
        assert!(message.contains("flagged"));
    }

    #[test]
    fn only_transient_statuses_are_retried() {
        assert!(worth_retrying(reqwest::StatusCode::TOO_MANY_REQUESTS));
        assert!(worth_retrying(reqwest::StatusCode::BAD_GATEWAY));
        assert!(!worth_retrying(reqwest::StatusCode::FORBIDDEN));
        assert!(!worth_retrying(reqwest::StatusCode::BAD_REQUEST));
    }

    #[test]
    fn the_backoff_grows_and_stays_bounded() {
        let first = backoff_delay(0);
        let late = backoff_delay(6);
        assert!(first >= std::time::Duration::from_millis(API_BACKOFF_BASE_MS / 2));
        assert!(late <= std::time::Duration::from_millis(API_BACKOFF_CAP_MS * 2));
        assert!(late >= first);
    }

    #[test]
    fn a_retry_after_header_is_honoured_but_capped() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("120"),
        );
        assert_eq!(
            retry_after(&headers),
            Some(std::time::Duration::from_secs(API_RETRY_AFTER_CAP_SECS))
        );
    }

    #[test]
    fn a_missing_retry_after_header_is_ignored() {
        let headers = reqwest::header::HeaderMap::new();
        assert!(retry_after(&headers).is_none());
    }

    #[tokio::test]
    #[ignore = "registers a real warp device over the camouflaged route"]
    async fn the_camouflaged_route_can_register_a_real_device() {
        let (_, public) = generate_x25519_keypair();
        let body = Registration {
            key: public,
            install_id: String::new(),
            fcm_token: String::new(),
            tos: tos_timestamp(),
            model: "PC".to_string(),
            serial_number: random_android_serial(),
            os_version: String::new(),
            key_type: "curve25519".to_string(),
            tunnel_type: "wireguard".to_string(),
            locale: "en_US".to_string(),
        };

        let encoded = serde_json::to_vec(&body).expect("encode");
        let path = format!("/{}/reg", consts::API_VERSION);

        let account = fallback_call("registration", "POST", &path, Some(encoded), None, None)
            .await
            .expect("the camouflaged route should register a device");

        println!("device={} ipv4={}", account.id, account.config.interface.addresses.v4);
        assert!(!account.id.is_empty());
        assert!(!account.token.is_empty());
        assert!(!account.config.peers.is_empty());
    }

    #[test]
    fn a_generated_certificate_is_not_immediately_stale() {
        let pair = generate_masque_keypair().expect("keypair should be generated");
        assert!(!pair.cert_pem.is_empty());
        assert!(!pair.key_pem.is_empty());
        assert!(!masque_cert_expiring(now_unix()));
    }
}

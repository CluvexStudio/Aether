use std::time::Duration;

use base64::Engine;
use rand::Rng;

use crate::error::{AetherError, Result};

const TEAM_SUFFIX: &str = "cloudflareaccess.com";
const ENROLL_PATH: &str = "/warp";
const AUTH_TIMEOUT: Duration = Duration::from_secs(20);
const CODE_WAIT: Duration = Duration::from_secs(300);
const CODE_ATTEMPTS: u32 = 3;
const INSTALL_ID_LEN: usize = 22;
const FCM_SUFFIX_LEN: usize = 134;
const ALPHANUM: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[derive(Debug, Clone, Default)]
pub struct TeamSettings {
    pub team: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub token: Option<String>,
    pub email: Option<String>,
}

impl TeamSettings {
    pub fn from_env() -> Option<Self> {
        let team = normalize_team(&std::env::var("AETHER_TEAM").unwrap_or_default())?;

        let non_empty = |key: &str| {
            std::env::var(key)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };

        Some(Self {
            team,
            client_id: non_empty("AETHER_ACCESS_CLIENT_ID"),
            client_secret: non_empty("AETHER_ACCESS_CLIENT_SECRET"),
            token: non_empty("AETHER_ACCESS_TOKEN"),
            email: non_empty("AETHER_ACCESS_EMAIL"),
        })
    }

    pub fn has_service_token(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some()
    }

    pub fn team_domain(&self) -> String {
        team_domain(&self.team)
    }

    pub fn login_url(&self) -> String {
        format!("{}{ENROLL_PATH}", self.team_domain())
    }
}

pub fn normalize_team(raw: &str) -> Option<String> {
    let mut value = raw.trim().to_lowercase();
    if value.is_empty() {
        return None;
    }

    for prefix in ["https://", "http://"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            value = rest.to_string();
        }
    }

    value = value.trim_end_matches('/').to_string();
    if let Some(head) = value.split('/').next() {
        value = head.to_string();
    }
    if let Some(head) = value.strip_suffix(TEAM_SUFFIX) {
        value = head.trim_end_matches('.').to_string();
    }

    if value.is_empty() {
        return None;
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return None;
    }
    Some(value)
}

pub fn team_domain(team: &str) -> String {
    format!("https://{team}.{TEAM_SUFFIX}")
}

pub fn extract_jwt_from_html(html: &str) -> Option<String> {
    let marker = "token=";
    let start = html.find(marker)? + marker.len();
    let rest = &html[start..];
    let end = rest
        .find(|c: char| c == '"' || c == '\'' || c == '&' || c == '<' || c.is_whitespace())
        .unwrap_or(rest.len());
    let candidate = rest[..end].trim();
    if looks_like_jwt(candidate) {
        Some(candidate.to_string())
    } else {
        None
    }
}

pub fn extract_jwt_from_cookie(header: &str) -> Option<String> {
    for part in header.split(';') {
        let entry = part.trim();
        let value = entry
            .strip_prefix("CF_Authorization=")
            .or_else(|| entry.strip_prefix("cf_authorization="))?;
        if looks_like_jwt(value) {
            return Some(value.to_string());
        }
    }
    None
}

pub fn looks_like_jwt(token: &str) -> bool {
    let token = token.trim();
    if token.len() < 32 {
        return false;
    }
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() != 3 {
        return false;
    }
    if segments.iter().any(|segment| segment.is_empty()) {
        return false;
    }
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return false;
    }
    decode_segment(segments[0]).is_some()
}

fn decode_segment(segment: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .ok()
}

pub fn jwt_expiry(token: &str) -> Option<u64> {
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() != 3 {
        return None;
    }
    let payload = decode_segment(segments[1])?;
    let value: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    value.get("exp")?.as_u64()
}

pub fn jwt_expired(token: &str, now: u64) -> bool {
    match jwt_expiry(token) {
        Some(exp) => exp <= now,
        None => false,
    }
}

pub fn generate_install_id() -> String {
    random_alphanumeric(INSTALL_ID_LEN)
}

pub fn generate_fcm_token(install_id: &str) -> String {
    format!("{install_id}:APA91b{}", random_alphanumeric(FCM_SUFFIX_LEN))
}

fn random_alphanumeric(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| ALPHANUM[rng.gen_range(0..ALPHANUM.len())] as char)
        .collect()
}

pub fn extract_totp_form_action(html: &str) -> Option<String> {
    let anchor = html.find("id=\"totp-form\"")?;
    let head = &html[..anchor];
    let form_start = head.rfind("<form")?;
    let tag_end = html[form_start..].find('>')? + form_start;
    let tag = &html[form_start..tag_end];

    let key = "action=";
    let key_at = tag.find(key)? + key.len();
    let rest = tag[key_at..].trim_start();
    let quote = rest.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let body = &rest[1..];
    let end = body.find(quote)?;
    let action = decode_entities(&body[..end]);

    if action.starts_with("https://") {
        Some(action)
    } else {
        None
    }
}

pub fn decode_entities(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;

    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];

        let end = match rest.find(';') {
            Some(index) if index <= 8 => index,
            _ => {
                out.push('&');
                rest = &rest[1..];
                continue;
            }
        };

        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" | "#39" => Some('\''),
            other => other
                .strip_prefix("#x")
                .or_else(|| other.strip_prefix("#X"))
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| other.strip_prefix('#').and_then(|dec| dec.parse().ok()))
                .and_then(char::from_u32),
        };

        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }

    out.push_str(rest);
    out
}

pub fn query_value(url: &str, key: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=')?;
        if name == key {
            return Some(percent_decode(value));
        }
    }
    None
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&out).to_string()
}

static TOKEN_CACHE: tokio::sync::Mutex<Option<String>> = tokio::sync::Mutex::const_new(None);

pub async fn resolve_token(settings: &TeamSettings) -> Result<String> {
    let mut cache = TOKEN_CACHE.lock().await;

    if let Some(cached) = cache.as_ref() {
        if !jwt_expired(cached, crate::account::now_unix()) {
            log::debug!("[zerotrust] reusing the enrolment token from this session");
            return Ok(cached.clone());
        }
        log::debug!("[zerotrust] the cached enrolment token expired; signing in again");
        *cache = None;
    }

    let token = sign_in(settings).await?;
    *cache = Some(token.clone());
    Ok(token)
}

pub async fn store_token(token: &str) -> Result<()> {
    let token = token.trim();
    if !looks_like_jwt(token) {
        return Err(AetherError::Api(
            "that value is not a jwt; copy the value that follows token= on the enrolment page"
                .into(),
        ));
    }
    if jwt_expired(token, crate::account::now_unix()) {
        return Err(AetherError::Api(
            "that token has already expired; sign in again to get a fresh one".into(),
        ));
    }
    *TOKEN_CACHE.lock().await = Some(token.to_string());
    Ok(())
}

pub async fn cached_token() -> Option<String> {
    TOKEN_CACHE
        .lock()
        .await
        .clone()
        .filter(|token| !jwt_expired(token, crate::account::now_unix()))
}

pub async fn clear_token() {
    *TOKEN_CACHE.lock().await = None;
}

async fn sign_in(settings: &TeamSettings) -> Result<String> {
    if let Some(token) = &settings.token {
        if !looks_like_jwt(token) {
            return Err(AetherError::Api(
                "the supplied access token is not a jwt; copy the value that follows token= \
                 on the enrolment page"
                    .into(),
            ));
        }
        if jwt_expired(token, crate::account::now_unix()) {
            return Err(AetherError::Api(
                "the supplied access token has expired; sign in again to get a fresh one".into(),
            ));
        }
        log::info!("[+] using the access token supplied for team {}", settings.team);
        return Ok(token.clone());
    }

    if settings.has_service_token() {
        return fetch_token_with_service_token(settings).await;
    }

    if let Some(email) = &settings.email {
        return fetch_token_with_email_code(settings, email).await;
    }

    Err(AetherError::Api(format!(
        "team {} needs a way to sign in. pick one: a service token via \
         AETHER_ACCESS_CLIENT_ID and AETHER_ACCESS_CLIENT_SECRET, an email one-time code via \
         AETHER_ACCESS_EMAIL, or a token you already hold via AETHER_ACCESS_TOKEN \
         (sign in at {})",
        settings.team,
        settings.login_url()
    )))
}

fn access_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(crate::consts::UA_REGISTER)
        .timeout(AUTH_TIMEOUT)
        .cookie_store(true)
        .build()
        .map_err(|e| AetherError::Api(format!("access client: {e}")))
}

#[derive(Debug, Clone)]
pub enum CodeOutcome {
    Token(String),
    Rejected(u16),
}

pub struct EmailSignIn {
    client: reqwest::Client,
    team: String,
    email: String,
    nonce: String,
    verify_url: String,
}

impl EmailSignIn {
    pub fn team(&self) -> &str {
        &self.team
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn verify_url(&self) -> &str {
        &self.verify_url
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub async fn resend_code(&mut self) -> Result<()> {
        if let Some(nonce) = request_email_code(&self.client, &self.verify_url, &self.email, None).await? {
            self.nonce = nonce;
        }
        Ok(())
    }

    pub async fn submit_code(&self, code: &str) -> Result<CodeOutcome> {
        let code = code.trim();
        if code.is_empty() {
            return Err(AetherError::Api("no login code was entered".into()));
        }

        let callback = format!("{}/cdn-cgi/access/callback", team_domain(&self.team));
        let confirmed = self
            .client
            .post(&callback)
            .form(&[("code", code), ("nonce", self.nonce.as_str())])
            .send()
            .await
            .map_err(|e| AetherError::Api(format!("confirming the login code: {e}")))?;

        let status = confirmed.status();
        let body = confirmed
            .text()
            .await
            .map_err(|e| AetherError::Api(format!("callback body: {e}")))?;

        match extract_jwt_from_html(&body) {
            Some(token) => {
                log::info!("[+] signed in to team {} with the email code", self.team);
                Ok(CodeOutcome::Token(token))
            }
            None => Ok(CodeOutcome::Rejected(status.as_u16())),
        }
    }
}

pub async fn begin_email_signin(settings: &TeamSettings, email: &str) -> Result<EmailSignIn> {
    let email = email.trim();
    if email.is_empty() {
        return Err(AetherError::Api(
            "an email address is needed to request a login code".into(),
        ));
    }

    let client = access_client()?;

    log::info!(
        "[*] opening the device enrolment page for team {}",
        settings.team
    );
    let landing = client
        .get(settings.login_url())
        .send()
        .await
        .map_err(|e| AetherError::Api(format!("enrolment page: {e}")))?;

    let login_url = landing.url().to_string();
    let landing_body = landing
        .text()
        .await
        .map_err(|e| AetherError::Api(format!("enrolment page body: {e}")))?;

    let verify_url = extract_totp_form_action(&landing_body).ok_or_else(|| {
        AetherError::Api(format!(
            "team {} does not offer an email one-time code on its enrolment page; \
             use a service token or sign in at {}",
            settings.team,
            settings.login_url()
        ))
    })?;

    let nonce = request_email_code(&client, &verify_url, email, Some(&login_url))
        .await?
        .ok_or_else(|| {
            AetherError::Api(
                "cloudflare did not return a nonce for the login code; the enrolment flow \
                 may have changed"
                    .into(),
            )
        })?;

    Ok(EmailSignIn {
        client,
        team: settings.team.clone(),
        email: email.to_string(),
        nonce,
        verify_url,
    })
}

async fn request_email_code(
    client: &reqwest::Client,
    verify_url: &str,
    email: &str,
    fallback_url: Option<&str>,
) -> Result<Option<String>> {
    log::info!("[*] asking cloudflare to email a login code to {email}");
    let sent = client
        .post(verify_url)
        .form(&[
            ("email", email),
            ("client_id", ""),
            ("connector_id", ""),
            ("connector_type", ""),
            ("redirect_url", ""),
        ])
        .send()
        .await
        .map_err(|e| AetherError::Api(format!("requesting a login code: {e}")))?;

    let sent_url = sent.url().to_string();
    let status = sent.status();
    let _ = sent.text().await;

    if !status.is_success() {
        return Err(AetherError::Api(format!(
            "cloudflare refused to send a login code (status {status})"
        )));
    }

    Ok(query_value(&sent_url, "nonce")
        .or_else(|| fallback_url.and_then(|url| query_value(url, "nonce"))))
}

async fn fetch_token_with_email_code(settings: &TeamSettings, email: &str) -> Result<String> {
    let session = begin_email_signin(settings, email).await?;
    let mut last_status: Option<u16> = None;

    for attempt in 1..=CODE_ATTEMPTS {
        let code = prompt_login_code(session.email(), attempt).await?;

        match session.submit_code(&code).await? {
            CodeOutcome::Token(token) => return Ok(token),
            CodeOutcome::Rejected(status) => {
                last_status = Some(status);
                let left = CODE_ATTEMPTS - attempt;
                if left > 0 {
                    log::warn!("[-] that code was not accepted; {left} attempt(s) left");
                }
            }
        }
    }

    Err(AetherError::Api(format!(
        "the login code was not accepted after {CODE_ATTEMPTS} attempts (last status {}); \
         request a fresh code and try again",
        last_status
            .map(|status| status.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    )))
}

pub const CODE_PROMPT_MARKER: &str = "[zerotrust] login-code-needed";

pub fn code_prompt_line(email: &str, attempt: u32) -> String {
    format!("{CODE_PROMPT_MARKER} attempt={attempt} email={email}")
}

async fn prompt_login_code(email: &str, attempt: u32) -> Result<String> {
    use std::io::IsTerminal;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let interactive = std::io::stdin().is_terminal();

    let banner = match (interactive, attempt) {
        (true, 1) => format!("\nA login code was emailed to {email}.\nEnter the code: "),
        (true, _) => {
            format!("\nThat code was not accepted. Enter the code emailed to {email} again: ")
        }
        (false, _) => format!("{}\n", code_prompt_line(email, attempt)),
    };

    let mut stdout = tokio::io::stdout();
    let _ = stdout.write_all(banner.as_bytes()).await;
    let _ = stdout.flush().await;

    if !interactive {
        log::info!("[*] waiting for the login code emailed to {email}");
    }

    let mut line = String::new();
    let mut reader = BufReader::new(tokio::io::stdin());
    let read = reader.read_line(&mut line);

    let outcome = match interactive {
        true => read.await.map_err(|_| ()),
        false => match tokio::time::timeout(CODE_WAIT, read).await {
            Ok(result) => result.map_err(|_| ()),
            Err(_) => {
                return Err(AetherError::Api(format!(
                    "no login code arrived within {}s; request a fresh code and try again",
                    CODE_WAIT.as_secs()
                )))
            }
        },
    };

    match outcome {
        Ok(0) | Err(()) => Err(AetherError::Api(match interactive {
            true => "no login code was entered".to_string(),
            false => format!(
                "a login code was emailed to {email} but nothing was sent back to answer it"
            ),
        })),
        Ok(_) => {
            let code = line.trim().to_string();
            if code.is_empty() {
                Err(AetherError::Api("no login code was entered".into()))
            } else {
                Ok(code)
            }
        }
    }
}

async fn fetch_token_with_service_token(settings: &TeamSettings) -> Result<String> {
    let client_id = settings
        .client_id
        .as_deref()
        .ok_or_else(|| AetherError::Api("missing access client id".into()))?;
    let client_secret = settings
        .client_secret
        .as_deref()
        .ok_or_else(|| AetherError::Api("missing access client secret".into()))?;

    let url = settings.login_url();
    log::info!(
        "[*] asking {} for a device enrolment token using the service token",
        settings.team_domain()
    );

    let client = reqwest::Client::builder()
        .user_agent(crate::consts::UA_REGISTER)
        .timeout(AUTH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| AetherError::Api(format!("access client: {e}")))?;

    let response = client
        .get(&url)
        .header("CF-Access-Client-Id", client_id)
        .header("CF-Access-Client-Secret", client_secret)
        .send()
        .await
        .map_err(|e| AetherError::Api(format!("access request: {e}")))?;

    let status = response.status();

    for header in response.headers().get_all(reqwest::header::SET_COOKIE) {
        if let Ok(text) = header.to_str() {
            if let Some(token) = extract_jwt_from_cookie(text) {
                log::info!("[+] access issued a device enrolment token");
                return Ok(token);
            }
        }
    }

    let body = response.text().await.unwrap_or_default();
    if let Some(token) = extract_jwt_from_html(&body) {
        log::info!("[+] access issued a device enrolment token");
        return Ok(token);
    }

    Err(AetherError::Api(format!(
        "access did not return a device enrolment token (status {status}); confirm the service \
         token has Service Auth device enrolment permission for team {}",
        settings.team
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(payload: &str) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.{}",
            engine.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}"),
            engine.encode(payload.as_bytes()),
            engine.encode(b"signature-bytes-that-are-long-enough")
        )
    }

    #[test]
    fn a_bare_team_name_is_kept_as_is() {
        assert_eq!(normalize_team("my-org"), Some("my-org".to_string()));
    }

    #[test]
    fn a_full_team_domain_is_reduced_to_the_name() {
        assert_eq!(
            normalize_team("https://My-Org.cloudflareaccess.com/"),
            Some("my-org".to_string())
        );
        assert_eq!(
            normalize_team("my-org.cloudflareaccess.com"),
            Some("my-org".to_string())
        );
    }

    #[test]
    fn an_enrolment_url_is_reduced_to_the_name() {
        assert_eq!(
            normalize_team("https://my-org.cloudflareaccess.com/warp"),
            Some("my-org".to_string())
        );
    }

    #[test]
    fn an_empty_or_malformed_team_is_rejected() {
        assert_eq!(normalize_team("   "), None);
        assert_eq!(normalize_team("bad name!"), None);
        assert_eq!(normalize_team("https://cloudflareaccess.com"), None);
    }

    #[test]
    fn the_team_domain_and_login_url_follow_cloudflares_shape() {
        let settings = TeamSettings {
            team: "acme".to_string(),
            ..Default::default()
        };
        assert_eq!(settings.team_domain(), "https://acme.cloudflareaccess.com");
        assert_eq!(
            settings.login_url(),
            "https://acme.cloudflareaccess.com/warp"
        );
    }

    #[test]
    fn a_token_is_pulled_out_of_the_meta_refresh() {
        let token = jwt("{\"exp\":9999999999}");
        let html = format!(
            "<html><head><meta http-equiv=\"refresh\" \
             content=\"0;url=com.cloudflare.warp://acme.cloudflareaccess.com/auth?token={token}\" \
             /></head></html>"
        );
        assert_eq!(extract_jwt_from_html(&html), Some(token));
    }

    #[test]
    fn a_page_without_a_token_yields_nothing() {
        assert_eq!(extract_jwt_from_html("<html>please sign in</html>"), None);
        assert_eq!(extract_jwt_from_html("token=not-a-jwt"), None);
    }

    #[test]
    fn a_token_is_pulled_out_of_the_authorization_cookie() {
        let token = jwt("{\"exp\":9999999999}");
        let header = format!("CF_Authorization={token}; Path=/; HttpOnly; Secure");
        assert_eq!(extract_jwt_from_cookie(&header), Some(token));
    }

    #[test]
    fn an_unrelated_cookie_is_ignored() {
        assert_eq!(
            extract_jwt_from_cookie("session=abc; Path=/; HttpOnly"),
            None
        );
    }

    #[test]
    fn only_three_segment_base64_tokens_look_like_jwts() {
        assert!(looks_like_jwt(&jwt("{\"exp\":1}")));
        assert!(!looks_like_jwt("short"));
        assert!(!looks_like_jwt("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(!looks_like_jwt("one.two"));
        assert!(!looks_like_jwt("one..three"));
        assert!(!looks_like_jwt(
            "aaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb.cc cc dddddddddddd"
        ));
    }

    #[test]
    fn the_expiry_claim_is_read_from_the_payload() {
        assert_eq!(jwt_expiry(&jwt("{\"exp\":1750000000}")), Some(1750000000));
        assert_eq!(jwt_expiry(&jwt("{\"sub\":\"nobody\"}")), None);
        assert_eq!(jwt_expiry("not-a-jwt"), None);
    }

    #[test]
    fn an_expired_token_is_reported_and_a_live_one_is_not() {
        let token = jwt("{\"exp\":1000}");
        assert!(jwt_expired(&token, 1001));
        assert!(!jwt_expired(&token, 999));
    }

    #[test]
    fn a_token_without_an_expiry_claim_is_not_treated_as_expired() {
        assert!(!jwt_expired(&jwt("{\"sub\":\"nobody\"}"), 999_999_999));
    }

    #[test]
    fn the_install_id_has_the_length_the_api_expects() {
        let id = generate_install_id();
        assert_eq!(id.len(), INSTALL_ID_LEN);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn two_install_ids_are_not_the_same() {
        assert_ne!(generate_install_id(), generate_install_id());
    }

    #[test]
    fn the_fcm_token_embeds_the_install_id_and_the_expected_prefix() {
        let id = generate_install_id();
        let fcm = generate_fcm_token(&id);
        assert!(fcm.starts_with(&format!("{id}:APA91b")));
        assert_eq!(fcm.len(), id.len() + 1 + 6 + FCM_SUFFIX_LEN);
    }

    #[test]
    fn the_verify_code_action_is_read_off_the_real_enrolment_page() {
        let page = "<html><body><form class=\"AuthFormLogin\" \
            action='https:&#x2F;&#x2F;example-team.cloudflareaccess.com&#x2F;cdn-cgi&#x2F;access\
            &#x2F;verify-code&#x2F;example-team.cloudflareaccess.com?kid&#x3D;abc&amp;meta&#x3D;xyz\
            &amp;redirect_url&#x3D;%2Fwarp' method=\"post\" id=\"totp-form\">\
            <input name=\"email\"></form></body></html>";

        let action = extract_totp_form_action(page).expect("action");
        assert_eq!(
            action,
            "https://example-team.cloudflareaccess.com/cdn-cgi/access/verify-code/\
             example-team.cloudflareaccess.com?kid=abc&meta=xyz&redirect_url=%2Fwarp"
        );
    }

    #[test]
    fn a_page_without_the_email_form_has_no_action() {
        assert_eq!(extract_totp_form_action("<html>pick an idp</html>"), None);
        assert_eq!(
            extract_totp_form_action("<form action='/relative' id=\"totp-form\">"),
            None
        );
    }

    #[test]
    fn html_entities_are_decoded_including_hex_escapes() {
        assert_eq!(decode_entities("a&#x2F;b"), "a/b");
        assert_eq!(decode_entities("x&amp;y"), "x&y");
        assert_eq!(decode_entities("k&#x3D;v"), "k=v");
        assert_eq!(decode_entities("plain"), "plain");
        assert_eq!(decode_entities("a & b"), "a & b");
    }

    #[test]
    fn a_query_parameter_is_read_and_percent_decoded() {
        let url = "https://team.cloudflareaccess.com/x?nonce=abc123&redirect_url=%2Fwarp";
        assert_eq!(query_value(url, "nonce"), Some("abc123".to_string()));
        assert_eq!(query_value(url, "redirect_url"), Some("/warp".to_string()));
        assert_eq!(query_value(url, "missing"), None);
        assert_eq!(query_value("https://team/x", "nonce"), None);
    }

    #[test]
    fn an_email_address_alone_is_enough_to_start_the_code_flow() {
        let settings = TeamSettings {
            team: "example-team".to_string(),
            email: Some("me@example.com".to_string()),
            ..Default::default()
        };
        assert!(!settings.has_service_token());
        assert!(settings.email.is_some());
    }

    #[tokio::test]
    async fn a_token_supplied_up_front_is_reused_without_signing_in_again() {
        let token = jwt("{\"exp\":9999999999}");
        let settings = TeamSettings {
            team: "acme".to_string(),
            token: Some(token.clone()),
            ..Default::default()
        };

        let first = resolve_token(&settings).await.expect("first");
        assert_eq!(first, token);

        let bare = TeamSettings {
            team: "acme".to_string(),
            ..Default::default()
        };
        let second = resolve_token(&bare).await.expect("cached");
        assert_eq!(second, token);
    }

    #[test]
    fn the_code_prompt_line_carries_the_attempt_and_the_address() {
        let line = code_prompt_line("me@example.com", 1);
        assert!(line.starts_with(CODE_PROMPT_MARKER));
        assert!(line.contains("attempt=1"));
        assert!(line.contains("email=me@example.com"));
        assert!(!line.contains('\n'));

        let retry = code_prompt_line("me@example.com", 3);
        assert!(retry.contains("attempt=3"));
    }

    #[test]
    fn a_service_token_is_only_complete_with_both_halves() {
        let mut settings = TeamSettings {
            team: "acme".to_string(),
            ..Default::default()
        };
        assert!(!settings.has_service_token());
        settings.client_id = Some("id.access".to_string());
        assert!(!settings.has_service_token());
        settings.client_secret = Some("secret".to_string());
        assert!(settings.has_service_token());
    }
}

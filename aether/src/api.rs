use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::account::{self, Identity};
use crate::error::{AetherError, Result};
use crate::{aethernoize, config, consts, dns, noize, prober, quic, wg_prober, wireguard, zerotrust};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Masque,
    WireGuard,
}

impl Transport {
    pub fn parse(raw: &str) -> Transport {
        match raw.trim().to_lowercase().as_str() {
            "wg" | "wireguard" | "warp" => Transport::WireGuard,
            _ => Transport::Masque,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Transport::Masque => "masque",
            Transport::WireGuard => "wireguard",
        }
    }

    pub fn assigned_port(&self) -> u16 {
        match self {
            Transport::Masque => 443,
            Transport::WireGuard => 2408,
        }
    }

    pub fn default_ports(&self) -> Vec<u16> {
        match self {
            Transport::Masque => prober::MASQUE_PORTS.to_vec(),
            Transport::WireGuard => wireguard::WG_PORTS.to_vec(),
        }
    }
}

#[derive(Clone)]
pub struct Cancel {
    sender: Arc<tokio::sync::watch::Sender<bool>>,
}

impl Default for Cancel {
    fn default() -> Self {
        Self::new()
    }
}

impl Cancel {
    pub fn new() -> Self {
        let (sender, _) = tokio::sync::watch::channel(false);
        Self {
            sender: Arc::new(sender),
        }
    }

    pub fn cancel(&self) {
        self.sender.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }

    pub async fn wait(&self) {
        let mut receiver = self.sender.subscribe();
        if *receiver.borrow_and_update() {
            return;
        }
        while receiver.changed().await.is_ok() {
            if *receiver.borrow_and_update() {
                return;
            }
        }
        std::future::pending::<()>().await
    }
}

async fn guard<T, F>(cancel: &Cancel, work: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    tokio::select! {
        biased;
        _ = cancel.wait() => Err(AetherError::Cancelled),
        outcome = work => outcome,
    }
}

#[derive(Debug, Clone, Default)]
pub struct TeamCredentials {
    pub team: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub token: Option<String>,
    pub email: Option<String>,
}

impl TeamCredentials {
    pub fn new(team: &str) -> Result<Self> {
        let team = zerotrust::normalize_team(team).ok_or_else(|| {
            AetherError::Api(format!("'{team}' is not a usable zero trust team name"))
        })?;
        Ok(Self {
            team,
            ..Default::default()
        })
    }

    pub fn with_service_token(mut self, client_id: &str, client_secret: &str) -> Self {
        self.client_id = Some(client_id.to_string());
        self.client_secret = Some(client_secret.to_string());
        self
    }

    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self
    }

    pub fn with_email(mut self, email: &str) -> Self {
        self.email = Some(email.to_string());
        self
    }

    pub fn settings(&self) -> zerotrust::TeamSettings {
        zerotrust::TeamSettings {
            team: self.team.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            token: self.token.clone(),
            email: self.email.clone(),
        }
    }

    pub fn login_url(&self) -> String {
        self.settings().login_url()
    }
}

pub async fn team_sign_in(credentials: &TeamCredentials) -> Result<String> {
    zerotrust::resolve_token(&credentials.settings()).await
}

pub async fn team_email_code_request(
    credentials: &TeamCredentials,
    email: &str,
) -> Result<zerotrust::EmailSignIn> {
    zerotrust::begin_email_signin(&credentials.settings(), email).await
}

pub async fn team_email_code_resend(session: &mut zerotrust::EmailSignIn) -> Result<()> {
    session.resend_code().await
}

pub async fn team_email_code_submit(
    session: &zerotrust::EmailSignIn,
    code: &str,
) -> Result<Option<String>> {
    match session.submit_code(code).await? {
        zerotrust::CodeOutcome::Token(token) => {
            zerotrust::store_token(&token).await?;
            Ok(Some(token))
        }
        zerotrust::CodeOutcome::Rejected(status) => {
            log::warn!("[-] the login code was not accepted (status {status})");
            Ok(None)
        }
    }
}

pub async fn team_use_token(token: &str) -> Result<()> {
    zerotrust::store_token(token).await
}

pub async fn team_current_token() -> Option<String> {
    zerotrust::cached_token().await
}

pub async fn team_forget_token() {
    zerotrust::clear_token().await
}

#[derive(Debug, Clone)]
pub struct ProvisionRequest {
    pub model: String,
    pub locale: String,
    pub team: Option<TeamCredentials>,
    pub masque_cert: bool,
}

impl Default for ProvisionRequest {
    fn default() -> Self {
        Self {
            model: consts::DEFAULT_MODEL.to_string(),
            locale: consts::DEFAULT_LOCALE.to_string(),
            team: None,
            masque_cert: false,
        }
    }
}

impl ProvisionRequest {
    pub fn for_transport(transport: Transport) -> Self {
        Self {
            masque_cert: matches!(transport, Transport::Masque),
            ..Default::default()
        }
    }

    pub fn in_team(mut self, credentials: TeamCredentials) -> Self {
        self.team = Some(credentials);
        self
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IdentitySummary {
    pub device_id: String,
    pub ipv4: String,
    pub ipv6: String,
    pub organization: String,
    pub gateway_proxy: String,
    pub assigned_endpoint: String,
    pub has_masque_cert: bool,
    pub cert_issued_at: u64,
    pub cert_usable: bool,
}

impl IdentitySummary {
    pub fn of(identity: &Identity) -> Self {
        Self {
            device_id: identity.device_id.clone(),
            ipv4: identity.ipv4.clone(),
            ipv6: identity.ipv6.clone(),
            organization: identity.organization.clone(),
            gateway_proxy: identity.gateway_proxy.clone(),
            assigned_endpoint: identity.assigned_endpoint.clone(),
            has_masque_cert: identity.has_masque_credentials(),
            cert_issued_at: identity.cert_issued_at,
            cert_usable: account::cert_still_usable(identity),
        }
    }
}

pub fn identity_path(base: &str, transport: Transport, team: Option<&str>) -> String {
    match team {
        Some(team) => crate::derive_sibling_path(base, &format!("team-{team}")),
        None => match transport {
            Transport::Masque => crate::derive_sibling_path(base, "masque"),
            Transport::WireGuard => base.to_string(),
        },
    }
}

pub fn lastconn_path(identity_path: &str) -> String {
    crate::lastconn_path(identity_path)
}

pub fn load_identity(path: &str) -> Result<Option<Identity>> {
    config::load(path)
}

pub fn save_identity(path: &str, identity: &Identity) -> Result<()> {
    config::save(path, identity)
}

pub async fn provision_identity(request: &ProvisionRequest) -> Result<Identity> {
    let identity = match &request.team {
        Some(team) => {
            let settings = team.settings();
            log::info!(
                "[*] enrolling this device into the zero trust organization {} ({})",
                settings.team,
                settings.team_domain()
            );
            let identity =
                account::provision_team(&request.model, &request.locale, &settings).await?;
            account::refresh_profile(identity).await
        }
        None => account::provision_wg(&request.model, &request.locale, None).await?,
    };

    if request.masque_cert {
        return attach_masque_cert(identity).await;
    }
    Ok(identity)
}

pub async fn refresh_identity(identity: Identity) -> Identity {
    account::refresh_profile(identity).await
}

pub async fn attach_masque_cert(identity: Identity) -> Result<Identity> {
    if identity.has_masque_credentials() && !account::masque_cert_expiring(identity.cert_issued_at) {
        return Ok(identity);
    }

    let enrollment = account::ensure_masque_enrolled(&identity).await?;
    Ok(Identity {
        cert_pem: enrollment.cert_pem,
        key_pem: enrollment.key_pem,
        cert_issued_at: enrollment.issued_at,
        ..identity
    })
}

pub async fn open_identity(path: &str, request: &ProvisionRequest) -> Result<Identity> {
    if let Some(identity) = load_identity(path)? {
        log::info!("[+] loaded an existing identity from {path}");
        let identity = match request.team.is_some() {
            true => refresh_identity(identity).await,
            false => identity,
        };
        let identity = match request.masque_cert {
            true => attach_masque_cert(identity).await?,
            false => identity,
        };
        save_identity(path, &identity)?;
        return Ok(identity);
    }

    log::info!("[+] no identity at {path}; provisioning a new one");
    let identity = provision_identity(request).await?;
    save_identity(path, &identity)?;
    Ok(identity)
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
    pub rtt_ms: u64,
}

impl Endpoint {
    pub fn socket(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }
}

#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub transport: Transport,
    pub mode: String,
    pub ip: prober::IpScan,
    pub ports: Vec<u16>,
    pub excluded: HashSet<SocketAddr>,
    pub ech_config_list: Option<Vec<u8>>,
    pub noize: noize::NoizeConfig,
    pub aethernoize: aethernoize::AetherNoizeConfig,
}

impl ScanRequest {
    pub fn for_transport(transport: Transport) -> Self {
        Self {
            transport,
            mode: "balanced".to_string(),
            ip: prober::IpScan::V4,
            ports: transport.default_ports(),
            excluded: HashSet::new(),
            ech_config_list: None,
            noize: noize::from_profile("firewall"),
            aethernoize: aethernoize::from_profile("balanced"),
        }
    }

    pub fn with_mode(mut self, mode: &str) -> Self {
        self.mode = mode.to_string();
        self
    }

    pub fn with_ip(mut self, ip: prober::IpScan) -> Self {
        self.ip = ip;
        self
    }

    pub fn with_profile(mut self, profile: &str) -> Self {
        self.noize = noize::from_profile(profile);
        self.aethernoize = aethernoize::from_profile(profile);
        self
    }
}

pub async fn scan(
    identity: &Identity,
    request: &ScanRequest,
    cancel: &Cancel,
) -> Result<Endpoint> {
    match request.transport {
        Transport::Masque => {
            let probe = prober::MasqueProbe {
                sni: consts::CONNECT_SNI.to_string(),
                authority: quic::default_authority().to_string(),
                path: quic::default_path().to_string(),
                cert_pem: Arc::from(identity.cert_pem.clone()),
                key_pem: Arc::from(identity.key_pem.clone()),
                ech_config_list: request.ech_config_list.clone().map(Arc::from),
                noize: request.noize.clone(),
                ports: request.ports.clone(),
                ip: request.ip,
                local_ipv4: crate::parse_local_v4(&identity.ipv4),
            };
            let mode = prober::ScanMode::parse(&request.mode);
            let best = guard(cancel, prober::hunt_best_gateway(&probe, mode)).await?;
            Ok(Endpoint {
                ip: best.ip,
                port: best.port,
                rtt_ms: best.rtt.as_millis() as u64,
            })
        }
        Transport::WireGuard => {
            let probe = wg_prober::WgProbe {
                private_key: Arc::new(identity.private_key_bytes()?),
                peer_public_key: Arc::new(identity.peer_public_key_bytes()?),
                client_id: identity.client_id,
                local_ipv4: wg_local_v4(identity)?,
                aethernoize: request.aethernoize.clone(),
                ports: request.ports.clone(),
                ip: request.ip,
                excluded: request.excluded.clone(),
            };
            let mode = wg_prober::WgScanMode::parse(&request.mode);
            let best = guard(cancel, wg_prober::hunt_best_wg_endpoint(&probe, mode)).await?;
            Ok(Endpoint {
                ip: best.ip,
                port: best.port,
                rtt_ms: best.rtt.as_millis() as u64,
            })
        }
    }
}

fn wg_local_v4(identity: &Identity) -> Result<Ipv4Addr> {
    identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other(format!("identity has an unusable ipv4 {}", identity.ipv4)))
}

#[derive(Debug, Clone)]
pub struct TunnelSpec {
    pub transport: Transport,
    pub socks: SocketAddr,
    pub http: Option<SocketAddr>,
    pub ech: Option<Vec<u8>>,
    pub aethernoize: aethernoize::AetherNoizeConfig,
    pub keepalive: u16,
    pub verify_timeout: Duration,
}

impl TunnelSpec {
    pub fn for_transport(transport: Transport) -> Self {
        Self {
            transport,
            socks: SocketAddr::from(([127, 0, 0, 1], 1819)),
            http: None,
            ech: None,
            aethernoize: aethernoize::from_profile("balanced"),
            keepalive: 5,
            verify_timeout: Duration::from_secs(10),
        }
    }

    pub fn with_socks(mut self, listen: SocketAddr) -> Self {
        self.socks = listen;
        self
    }

    pub fn with_http(mut self, listen: SocketAddr) -> Self {
        self.http = Some(listen);
        self
    }

    pub fn with_profile(mut self, profile: &str) -> Self {
        self.aethernoize = aethernoize::from_profile(profile);
        self
    }
}

pub async fn fetch_ech_config() -> Option<Vec<u8>> {
    match dns::fetch_ech_config().await {
        Ok(raw) => {
            log::info!("[+] fetched an ECHConfigList ({} bytes)", raw.len());
            Some(raw)
        }
        Err(e) => {
            log::warn!("[-] could not fetch an ECHConfigList ({e}); continuing without ECH");
            None
        }
    }
}

pub async fn verify_endpoint(
    identity: &Identity,
    peer: SocketAddr,
    spec: &TunnelSpec,
    cancel: &Cancel,
) -> Result<bool> {
    match spec.transport {
        Transport::Masque => {
            let attempt = async { Ok(crate::quick_verify_masque_peer(identity, peer).await) };
            guard(cancel, attempt).await
        }
        Transport::WireGuard => {
            let private_key = identity.private_key_bytes()?;
            let peer_public = identity.peer_public_key_bytes()?;
            let local_ipv4 = wg_local_v4(identity)?;
            let attempt = wireguard::verify_endpoint(
                peer,
                private_key,
                peer_public,
                identity.client_id,
                local_ipv4,
                &spec.aethernoize,
                spec.verify_timeout,
                Some(spec.keepalive),
            );
            match guard(cancel, attempt).await {
                Ok(_) => Ok(true),
                Err(AetherError::Cancelled) => Err(AetherError::Cancelled),
                Err(e) => {
                    log::debug!("[-] {peer} did not verify: {e}");
                    Ok(false)
                }
            }
        }
    }
}

pub async fn connect(
    identity: &Identity,
    peer: SocketAddr,
    spec: &TunnelSpec,
    cancel: &Cancel,
) -> Result<()> {
    match spec.http {
        Some(listen) => std::env::set_var("AETHER_HTTP_PROXY", listen.to_string()),
        None => std::env::remove_var("AETHER_HTTP_PROXY"),
    }

    match spec.transport {
        Transport::Masque => {
            let attempt = crate::run_masque_tunnel(identity, peer, spec.ech.clone(), spec.socks);
            guard(cancel, attempt).await
        }
        Transport::WireGuard => {
            let attempt = crate::run_wireguard_tunnel(
                identity.clone(),
                peer,
                spec.aethernoize.clone(),
                spec.socks,
            );
            guard(cancel, attempt).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transport_is_read_from_the_names_the_cli_accepts() {
        assert_eq!(Transport::parse("wg"), Transport::WireGuard);
        assert_eq!(Transport::parse("WireGuard"), Transport::WireGuard);
        assert_eq!(Transport::parse("warp"), Transport::WireGuard);
        assert_eq!(Transport::parse("masque"), Transport::Masque);
        assert_eq!(Transport::parse("anything else"), Transport::Masque);
    }

    #[test]
    fn each_transport_carries_the_port_the_edge_assigns() {
        assert_eq!(Transport::Masque.assigned_port(), 443);
        assert_eq!(Transport::WireGuard.assigned_port(), 2408);
        assert!(!Transport::Masque.default_ports().is_empty());
        assert!(!Transport::WireGuard.default_ports().is_empty());
    }

    #[test]
    fn a_team_name_is_normalized_before_it_is_kept() {
        let credentials = TeamCredentials::new("https://My-Org.cloudflareaccess.com/warp")
            .expect("a full url is usable");
        assert_eq!(credentials.team, "my-org");
        assert_eq!(
            credentials.login_url(),
            "https://my-org.cloudflareaccess.com/warp"
        );
        assert!(TeamCredentials::new("bad name!").is_err());
    }

    #[test]
    fn credentials_carry_whichever_sign_in_method_was_given() {
        let service = TeamCredentials::new("acme")
            .expect("team")
            .with_service_token("id.access", "secret");
        assert!(service.settings().has_service_token());

        let by_email = TeamCredentials::new("acme")
            .expect("team")
            .with_email("me@example.com");
        assert!(!by_email.settings().has_service_token());
        assert_eq!(by_email.email.as_deref(), Some("me@example.com"));
    }

    #[test]
    fn identity_paths_follow_the_same_shape_the_cli_writes() {
        assert_eq!(
            identity_path("aether.toml", Transport::Masque, None),
            "aether-masque.toml"
        );
        assert_eq!(
            identity_path("aether.toml", Transport::WireGuard, None),
            "aether.toml"
        );
        assert_eq!(
            identity_path("aether.toml", Transport::Masque, Some("acme")),
            "aether-team-acme.toml"
        );
        assert_eq!(
            identity_path("/var/lib/aether/aether.toml", Transport::WireGuard, Some("acme")),
            "/var/lib/aether/aether-team-acme.toml"
        );
    }

    #[test]
    fn a_scan_request_starts_from_the_defaults_the_cli_uses() {
        let masque = ScanRequest::for_transport(Transport::Masque);
        assert_eq!(masque.mode, "balanced");
        assert_eq!(masque.ip, prober::IpScan::V4);
        assert_eq!(masque.ports, prober::MASQUE_PORTS.to_vec());

        let wg = ScanRequest::for_transport(Transport::WireGuard).with_mode("turbo");
        assert_eq!(wg.mode, "turbo");
        assert_eq!(wg.ports, wireguard::WG_PORTS.to_vec());
    }

    #[test]
    fn a_tunnel_spec_defaults_to_the_loopback_socks_port() {
        let spec = TunnelSpec::for_transport(Transport::Masque);
        assert_eq!(spec.socks.port(), 1819);
        assert!(spec.socks.ip().is_loopback());
        assert!(spec.http.is_none());

        let with_http = spec.with_http(SocketAddr::from(([127, 0, 0, 1], 8086)));
        assert_eq!(with_http.http.map(|addr| addr.port()), Some(8086));
    }

    #[tokio::test]
    async fn a_cancel_token_is_seen_by_everyone_holding_a_copy() {
        let cancel = Cancel::new();
        let copy = cancel.clone();
        assert!(!cancel.is_cancelled());

        copy.cancel();
        assert!(cancel.is_cancelled());
        cancel.wait().await;
    }

    #[tokio::test]
    async fn cancelling_stops_the_work_it_guards() {
        let cancel = Cancel::new();
        cancel.cancel();

        let outcome: Result<u8> = guard(&cancel, async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(1)
        })
        .await;

        assert!(matches!(outcome, Err(AetherError::Cancelled)));
    }

    #[tokio::test]
    async fn work_that_finishes_first_is_not_treated_as_cancelled() {
        let cancel = Cancel::new();
        let outcome: Result<u8> = guard(&cancel, async { Ok(7) }).await;
        assert!(matches!(outcome, Ok(7)));
    }

    #[tokio::test]
    async fn cancelling_part_way_through_stops_the_work() {
        let cancel = Cancel::new();
        let trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            trigger.cancel();
        });

        let outcome: Result<u8> = guard(&cancel, async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(1)
        })
        .await;

        assert!(matches!(outcome, Err(AetherError::Cancelled)));
    }
}

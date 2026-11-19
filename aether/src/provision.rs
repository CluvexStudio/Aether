use std::net::SocketAddr;

use crate::carrier::carrier_upstream;
use crate::error::{AetherError, Result};
use crate::modes::env_value;
use crate::prompt::prompt_line;
use crate::relay::TaskGuard;
use crate::{account, config, consts, psiphon, socks, tor, zerotrust};

pub(crate) fn team_scope() -> Option<String> {
    zerotrust::TeamSettings::from_env().map(|settings| settings.team)
}

fn enrolled_teams(base: &str) -> Vec<String> {
    let dir_end = base.rfind(['/', '\\']).map(|i| i + 1).unwrap_or(0);
    let dir = if dir_end == 0 { "." } else { &base[..dir_end] };
    let stem = match base[dir_end..].rfind('.') {
        Some(rel) => &base[dir_end..dir_end + rel],
        None => &base[dir_end..],
    };
    let prefix = format!("{stem}-team-");

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut teams: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        let Some(team) = rest.strip_suffix(".toml") else {
            continue;
        };
        if team.is_empty() || team.ends_with("-secondary") || team.ends_with("-lastconn") {
            continue;
        }
        if !teams.iter().any(|known| known == team) {
            teams.push(team.to_string());
        }
    }
    teams.sort();
    teams
}

pub(crate) async fn enrol_zero_trust(base: &str) {
    let known = enrolled_teams(base);

    let prompt = match known.first() {
        Some(team) => format!(
            "\nZero Trust organization.\n  already enrolled: {}\nTeam name from \
             <team>.cloudflareaccess.com, or blank to reuse '{}': ",
            known.join(", "),
            team
        ),
        None => "\nZero Trust organization.\nTeam name from <team>.cloudflareaccess.com \
                 (blank to cancel): "
            .to_string(),
    };

    let answer = prompt_line(&prompt).await.unwrap_or_default();
    let answer = answer.trim().to_string();

    let team = if answer.is_empty() {
        match known.first() {
            Some(team) => team.clone(),
            None => {
                log::info!("[*] Zero Trust skipped; staying on personal WARP");
                return;
            }
        }
    } else {
        match zerotrust::normalize_team(&answer) {
            Some(team) => team,
            None => {
                log::warn!("[-] '{answer}' is not a usable team name");
                return;
            }
        }
    };

    crate::settings::set("AETHER_TEAM", &team);

    if known.contains(&team) {
        log::info!("[+] reusing the saved enrolment for team {team}; no sign-in needed");
        return;
    }

    let needs_method = match zerotrust::TeamSettings::from_env() {
        Some(settings) => {
            !(settings.token.is_some() || settings.has_service_token() || settings.email.is_some())
        }
        None => {
            crate::settings::remove("AETHER_TEAM");
            return;
        }
    };

    if needs_method {
        let email = prompt_line("Email address for the one-time login code (blank to cancel): ")
            .await
            .unwrap_or_default();
        let email = email.trim().to_string();

        if email.is_empty() {
            log::warn!("[-] no email given; staying on personal WARP");
            crate::settings::remove("AETHER_TEAM");
            return;
        }

        crate::settings::set("AETHER_ACCESS_EMAIL", &email);
    }

    let settings = match zerotrust::TeamSettings::from_env() {
        Some(settings) => settings,
        None => {
            crate::settings::remove("AETHER_TEAM");
            return;
        }
    };

    match zerotrust::resolve_token(&settings).await {
        Ok(_) => log::info!("[+] signed in to team {team}; now pick the transport to use"),
        Err(error) => {
            log::error!("[-] Zero Trust sign-in failed: {error}");
            log::warn!("[-] staying on personal WARP");
            crate::settings::remove("AETHER_TEAM");
            crate::settings::remove("AETHER_ACCESS_EMAIL");
        }
    }
}

async fn provision_account() -> Result<account::Identity> {
    match zerotrust::TeamSettings::from_env() {
        Some(settings) => {
            log::info!(
                "[*] enrolling this device into the Zero Trust organization {} ({})",
                settings.team,
                settings.team_domain()
            );
            let identity =
                account::provision_team(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, &settings)
                    .await?;
            Ok(account::refresh_profile(identity).await)
        }
        None => account::provision_wg(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, None).await,
    }
}

async fn adopt_team_profile(identity: account::Identity) -> account::Identity {
    if team_scope().is_none() {
        return identity;
    }

    let identity = account::refresh_profile(identity).await;

    if !identity.gateway_proxy.is_empty() {
        if crate::settings::var("AETHER_GATEWAY").is_ok() {
            socks::set_gateway_proxy(&identity.gateway_proxy);
        } else {
            log::debug!(
                "[zerotrust] the organization offers a gateway proxy at {}; pass --gateway to route http through it",
                identity.gateway_proxy
            );
        }
    }

    if !identity.assigned_endpoint.is_empty() && crate::settings::var("AETHER_PEER").is_err() {
        let port = if crate::settings::var("AETHER_PROTOCOL")
            .map(|value| value == "wg" || value == "gool")
            .unwrap_or(false)
        {
            2408
        } else {
            443
        };
        let peer = format!("{}:{port}", identity.assigned_endpoint);
        if peer.parse::<SocketAddr>().is_ok() {
            log::info!("[+] the organization assigned endpoint {peer}; trying it before scanning");
            crate::settings::set("AETHER_TEAM_ENDPOINT", &peer);
        }
    }

    identity
}

pub(crate) fn warp_config_path(base: &str) -> String {
    if let Ok(p) = crate::settings::var("AETHER_WG_CONFIG") {
        return p;
    }
    match team_scope() {
        Some(team) => derive_sibling_path(base, &format!("team-{team}")),
        None => base.to_string(),
    }
}

pub(crate) fn masque_config_path(base: &str) -> String {
    if let Ok(p) = crate::settings::var("AETHER_MASQUE_CONFIG") {
        return p;
    }
    match team_scope() {
        Some(team) => derive_sibling_path(base, &format!("team-{team}")),
        None => derive_sibling_path(base, "masque"),
    }
}

pub(crate) fn gool_identity_path(masque_config: &str) -> String {
    derive_sibling_path(masque_config, "gool")
}

pub(crate) fn derive_sibling_path(base: &str, suffix: &str) -> String {
    let dir_end = base.rfind(['/', '\\']).map(|i| i + 1).unwrap_or(0);
    match base[dir_end..].rfind('.') {
        Some(rel) => {
            let dot = dir_end + rel;
            format!("{}-{}{}", &base[..dot], suffix, &base[dot..])
        }
        None => format!("{base}-{suffix}"),
    }
}

fn keep_saved_identity() -> bool {
    !matches!(
        crate::settings::var("AETHER_REPROVISION").as_deref(),
        Ok("0") | Ok("off") | Ok("false")
    )
}

pub(crate) async fn load_or_provision_warp(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing warp identity from {config_path}");
        let identity = adopt_team_profile(identity).await;
        if !identity.refused {
            config::save(config_path, &identity)?;
            return Ok(identity);
        }
        if !keep_saved_identity() {
            return Ok(identity);
        }
        log::warn!("[*] registering a fresh wireguard account to replace the refused identity");
    }

    log::info!("[+] no warp identity found; provisioning dedicated wireguard account");
    let identity = provision_account().await?;
    let identity = adopt_team_profile(identity).await;
    enable_warp_on(&identity).await?;
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new warp identity to {config_path}");
    Ok(identity)
}

pub(crate) async fn enable_warp_on(identity: &account::Identity) -> Result<()> {
    account::enable_warp(&identity.device_id, &identity.access_token).await?;
    log::info!("[+] warp enabled for device {}", identity.device_id);
    Ok(())
}

pub(crate) async fn load_or_provision_masque(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing masque identity from {config_path}");
        let refused = if identity.has_masque_credentials() {
            let identity = adopt_team_profile(identity).await;
            if !identity.refused {
                config::save(config_path, &identity)?;
                return Ok(identity);
            }
            identity
        } else {
            log::info!("[+] masque identity needs a certificate; enrolling masque key");
            match account::ensure_masque_enrolled(&identity).await {
                Ok(enrollment) => {
                    let identity = account::Identity {
                        cert_pem: enrollment.cert_pem,
                        key_pem: enrollment.key_pem,
                        cert_issued_at: enrollment.issued_at,
                        ..identity
                    };
                    config::save(config_path, &identity)?;
                    return Ok(identity);
                }
                Err(AetherError::IdentityRefused(reason)) => {
                    log::warn!("[-] the saved masque identity was refused: {reason}");
                    account::Identity {
                        refused: true,
                        ..identity
                    }
                }
                Err(error) => return Err(error),
            }
        };

        if !keep_saved_identity() {
            return Ok(refused);
        }
        log::warn!("[*] registering a fresh masque account to replace the refused identity");
    }

    log::info!("[+] no masque identity found; provisioning dedicated masque account");
    let identity = provision_account().await?;
    let enrollment = account::ensure_masque_enrolled(&identity).await?;
    let identity = account::Identity {
        cert_pem: enrollment.cert_pem,
        key_pem: enrollment.key_pem,
        cert_issued_at: enrollment.issued_at,
        ..identity
    };
    let identity = adopt_team_profile(identity).await;
    enable_warp_on(&identity).await?;
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new masque identity to {config_path}");
    Ok(identity)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RegisterSet {
    wireguard: bool,
    wireguard_inner: bool,
    masque: bool,
    masque_inner: bool,
    gool: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provision {
    Warp,
    Masque,
    Gool,
}

impl RegisterSet {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let none = RegisterSet {
            wireguard: false,
            wireguard_inner: false,
            masque: false,
            masque_inner: false,
            gool: false,
        };
        match value.trim().to_lowercase().as_str() {
            "all" => Ok(RegisterSet {
                wireguard: true,
                wireguard_inner: true,
                masque: true,
                masque_inner: true,
                gool: true,
            }),
            "masque" => Ok(RegisterSet {
                masque: true,
                ..none
            }),
            "wg" | "wireguard" | "warp" => Ok(RegisterSet {
                wireguard: true,
                ..none
            }),
            "gool" | "wg-over-masque" => Ok(RegisterSet {
                masque: true,
                gool: true,
                ..none
            }),
            "gool-classic" | "wiw" | "warp-in-warp" => Ok(RegisterSet {
                wireguard: true,
                wireguard_inner: true,
                ..none
            }),
            "mim" | "masque-in-masque" => Ok(RegisterSet {
                masque: true,
                masque_inner: true,
                ..none
            }),
            other => Err(AetherError::Other(format!(
                "--register takes masque, wg, gool, gool-classic, mim or all, not '{other}'"
            ))),
        }
    }
}

pub(crate) fn register_request() -> Result<Option<RegisterSet>> {
    env_value("AETHER_REGISTER")
        .map(|value| RegisterSet::parse(&value))
        .transpose()
}

pub(crate) async fn register_identities(wanted: RegisterSet, base_config: &str) -> Result<()> {
    let carrier = match (tor::mode(), psiphon::mode()) {
        (tor::Mode::Reverse, psiphon::Mode::Reverse) => {
            return Err(AetherError::Other(
                "--tor-reverse and --psiphon-reverse both want to carry the registration; \
                 pick one"
                    .into(),
            ));
        }
        (tor::Mode::Reverse, _) => Some((
            "tor",
            tor::start_reverse(tor::state_dir(base_config)).await?,
        )),
        (_, psiphon::Mode::Reverse) => Some((
            "psiphon",
            psiphon::start_reverse(psiphon::state_dir(base_config)).await?,
        )),
        _ => None,
    };
    let mut carried = TaskGuard::new();
    if let Some((name, (socks, carrier))) = carrier {
        carried.push(carrier);
        crate::settings::set("AETHER_UPSTREAM", carrier_upstream(name, socks)?);
        log::info!("[+] the identities are registered through {name}");
    }

    let wireguard = warp_config_path(base_config);
    let masque = masque_config_path(base_config);
    let identities = [
        (
            wanted.wireguard,
            "wireguard",
            wireguard.clone(),
            Provision::Warp,
        ),
        (
            wanted.wireguard_inner,
            "wireguard inner",
            derive_sibling_path(&wireguard, "secondary"),
            Provision::Warp,
        ),
        (wanted.masque, "masque", masque.clone(), Provision::Masque),
        (
            wanted.masque_inner,
            "masque inner",
            derive_sibling_path(&masque, "secondary"),
            Provision::Masque,
        ),
        (
            wanted.gool,
            "gool",
            gool_identity_path(&masque),
            Provision::Gool,
        ),
    ];

    let mut ready = Vec::new();
    for (asked, label, path, provision) in identities {
        if !asked {
            continue;
        }
        let identity = match provision {
            Provision::Warp => load_or_provision_warp(&path).await?,
            Provision::Masque => load_or_provision_masque(&path).await?,
            Provision::Gool => load_or_provision_gool(&path).await?,
        };
        log::info!(
            "[+] {label} identity ready: device={} ipv4={} ipv6={}",
            identity.device_id,
            identity.ipv4,
            identity.ipv6
        );
        ready.push(label);
    }

    log::info!("[+] identities ready: {}", ready.join(", "));
    Ok(())
}

pub(crate) fn lastconn_path(config_path: &str) -> String {
    derive_sibling_path(config_path, "lastconn")
}

async fn load_or_provision_gool(path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(path)? {
        log::info!("[+] loaded the gool wireguard identity from {path}");
        return Ok(identity);
    }
    let identity = provision_gool(path).await?;
    log::info!(
        "[+] gool wireguard identity registered and saved to {path}: device={} ipv4={}",
        identity.device_id,
        identity.ipv4
    );
    Ok(identity)
}

pub(crate) async fn provision_gool(path: &str) -> Result<account::Identity> {
    let kept = GOOL_NOT_ENABLED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    let registered = match kept {
        Some(identity) => identity,
        None => account::provision_wg(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, None).await?,
    };
    if let Err(error) = enable_warp_on(&registered).await {
        if worth_enabling_again(&error) {
            *GOOL_NOT_ENABLED.lock().unwrap_or_else(|e| e.into_inner()) = Some(registered);
        }
        return Err(error);
    }
    config::save(path, &registered)?;
    Ok(registered)
}

static GOOL_NOT_ENABLED: std::sync::Mutex<Option<account::Identity>> = std::sync::Mutex::new(None);

fn worth_enabling_again(error: &AetherError) -> bool {
    !matches!(error, AetherError::IdentityRefused(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gool_device_is_enabled_again_unless_the_api_refused_it() {
        assert!(worth_enabling_again(&AetherError::Api(
            "enabling warp: timed out".into()
        )));
        assert!(!worth_enabling_again(&AetherError::IdentityRefused(
            "enabling warp: 401".into()
        )));
    }

    #[test]
    fn register_names_the_identities_of_one_protocol_or_all_five() {
        let all = RegisterSet::parse("all").expect("all");
        assert!(all.wireguard && all.wireguard_inner && all.masque && all.masque_inner && all.gool);

        let masque = RegisterSet::parse(" MASQUE ").expect("masque");
        assert!(masque.masque && !masque.masque_inner && !masque.gool);
        assert!(!masque.wireguard && !masque.wireguard_inner);

        let wireguard = RegisterSet::parse("wg").expect("wg");
        assert!(wireguard.wireguard && !wireguard.wireguard_inner);
        assert!(!wireguard.masque && !wireguard.masque_inner && !wireguard.gool);

        for word in ["gool", "GOOL", "wg-over-masque"] {
            let gool = RegisterSet::parse(word).expect(word);
            assert!(gool.masque && gool.gool, "{word}");
            assert!(
                !gool.masque_inner && !gool.wireguard && !gool.wireguard_inner,
                "{word}"
            );
        }

        for word in ["gool-classic", "wiw", "warp-in-warp"] {
            let classic = RegisterSet::parse(word).expect(word);
            assert!(classic.wireguard && classic.wireguard_inner, "{word}");
            assert!(
                !classic.masque && !classic.masque_inner && !classic.gool,
                "{word}"
            );
        }

        let mim = RegisterSet::parse("mim").expect("mim");
        assert!(mim.masque && mim.masque_inner && !mim.gool);
        assert!(!mim.wireguard && !mim.wireguard_inner);

        assert!(RegisterSet::parse("everything").is_err());
    }

    #[test]
    fn gool_keeps_its_wireguard_identity_beside_the_masque_one() {
        assert_eq!(
            gool_identity_path("/data/files/aether/aether-masque.toml"),
            "/data/files/aether/aether-masque-gool.toml"
        );
        assert_eq!(
            gool_identity_path(r"C:\keys\aether-masque.toml"),
            r"C:\keys\aether-masque-gool.toml"
        );
    }
}

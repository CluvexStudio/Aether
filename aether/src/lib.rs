pub mod account;
pub mod aethernoize;
pub mod api;
pub mod bridges;
mod carrier;
pub mod cli;
pub mod config;
pub mod consts;
pub mod dns;
pub mod egress;
pub mod error;
pub mod exitloc;
pub mod ffi;
pub mod fragment;
pub mod https;
pub mod lastconn;
pub mod masque;
pub mod masque_h2;
mod modes;
pub mod netstack;
pub mod noize;
pub mod prober;
mod prompt;
mod provision;
pub mod psiphon;
pub mod quic;
mod relay;
pub mod routing;
pub mod settings;
pub mod sniff;
pub mod socks;
pub mod stats;
pub mod sysprofile;
pub mod tls;
pub mod tor;
pub mod tunnelping;
pub mod upstream;
pub mod wg_prober;
pub mod wireguard;
pub mod zerotrust;

use std::net::SocketAddr;

use crate::carrier::{carrier_upstream, until_core_end, watch_chain};
use crate::error::{AetherError, Result};
use crate::modes::endpoints::{mim_endpoints_from_env, wiw_endpoints_from_env};
use crate::modes::gool::{gool_classic, run_gool};
use crate::modes::masque::{resolve_ech, run_masque};
use crate::modes::mim::run_mim;
use crate::modes::wireguard::run_wireguard;
use crate::modes::{install_netstack_panic_guard, Listeners};
use crate::prompt::{needs_udp_to_warp, select_masque_transport, select_protocol, Protocol};
use crate::provision::{
    derive_sibling_path, gool_identity_path, lastconn_path, load_or_provision_masque,
    load_or_provision_warp, masque_config_path, register_identities, register_request,
    warp_config_path,
};
use crate::relay::TaskGuard;

const DEFAULT_CONFIG: &str = "aether.toml";

pub async fn run() -> Result<()> {
    run_with(std::env::args().skip(1).collect()).await
}

pub async fn run_with(args: Vec<String>) -> Result<()> {
    if cli::parse_args(args)? == cli::Parsed::Done {
        return Ok(());
    }

    let level = crate::settings::var("AETHER_LOG_LEVEL")
        .ok()
        .map(|v| v.trim().to_lowercase())
        .filter(|v| matches!(v.as_str(), "error" | "warn" | "info" | "debug" | "trace"))
        .unwrap_or_else(|| "info".to_string());
    let default_filter = format!("info,aether={level}");
    let _ =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
            .format_timestamp_millis()
            .try_init();

    log::info!("Aether v{}", env!("CARGO_PKG_VERSION"));
    sysprofile::log_summary();
    sysprofile::raise_fd_limit();
    egress::init()?;
    stats::init();
    stats::spawn_reporter();

    install_netstack_panic_guard();
    tls::check_tls_options()?;
    quic::masque_sni()?;
    account::check_api_settings()?;
    upstream::check_setting()?;
    account::forget_api_ech();
    account::forget_answered_api_host();

    let base_config =
        crate::settings::var("AETHER_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string());

    if let Some(wanted) = register_request()? {
        return register_identities(wanted, &base_config).await;
    }

    let listen: SocketAddr = crate::settings::var("AETHER_SOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:1819".parse().unwrap());

    let (core_end, core_ended) = tokio::sync::mpsc::unbounded_channel::<AetherError>();
    let listeners = Listeners::bind(listen, core_end.clone()).await?;

    if tor::mode() == tor::Mode::Only {
        let state = tor::state_dir(&base_config);
        return tor::run_only(listeners.into_socks(), listen, state).await;
    }

    if psiphon::mode() == psiphon::Mode::Only {
        let state = psiphon::state_dir(&base_config);
        return psiphon::run_only(listeners.into_socks(), listen, state).await;
    }

    if tor::mode() == tor::Mode::Reverse && psiphon::mode() == psiphon::Mode::Reverse {
        return Err(AetherError::from(crate::cli::CliError::TwoTunnelCarriers));
    }

    let pinned_wiw = wiw_endpoints_from_env()?;
    let pinned_mim = mim_endpoints_from_env()?;

    let protocol = match crate::settings::var("AETHER_PROTOCOL") {
        Ok(v) => Protocol::parse(&v),
        Err(_) if !pinned_wiw.is_empty() => Protocol::WarpInWarp,
        Err(_) if !pinned_mim.is_empty() => Protocol::MasqueInMasque,
        Err(_)
            if crate::settings::var("AETHER_PEER").is_ok()
                || crate::settings::var("AETHER_WG_PEER").is_ok() =>
        {
            Protocol::Masque
        }
        Err(_) => select_protocol(&base_config).await,
    };

    if tor::mode() == tor::Mode::Only {
        let state = tor::state_dir(&base_config);
        return tor::run_only(listeners.into_socks(), listen, state).await;
    }

    if psiphon::mode() == psiphon::Mode::Only {
        let state = psiphon::state_dir(&base_config);
        return psiphon::run_only(listeners.into_socks(), listen, state).await;
    }

    if protocol != Protocol::WarpInWarp && !pinned_wiw.is_empty() {
        log::warn!(
            "[-] the warp-in-warp endpoints you set are ignored on {}; they only apply to --gool",
            protocol.label()
        );
    }

    if protocol != Protocol::MasqueInMasque && !pinned_mim.is_empty() {
        log::warn!(
            "[-] the masque-in-masque endpoints you set are ignored on {}; they only apply to --mim",
            protocol.label()
        );
    }

    let mut tor_and_psiphon = TaskGuard::new();
    let held = crate::socks::dialable(listeners.socks.local_addr().unwrap_or(listen));
    match tor::mode() {
        tor::Mode::Chain => {
            let through = held;
            let state = tor::state_dir(&base_config);
            let chain = tokio::spawn(tor::run_chain(through, state));
            watch_chain("tor", chain, core_end.clone(), &mut tor_and_psiphon);
        }
        tor::Mode::Reverse => {
            if needs_udp_to_warp(protocol, gool_classic()) {
                return Err(AetherError::from(crate::cli::CliError::UdpOverTor(
                    protocol.label().to_string(),
                )));
            }

            let (socks, carrier) = tor::start_reverse(tor::state_dir(&base_config)).await?;
            tor_and_psiphon.push(carrier);
            crate::settings::set("AETHER_UPSTREAM", carrier_upstream("tor", socks)?);
            crate::settings::set("AETHER_MASQUE_HTTP2", "1");
            log::info!("[+] the tunnel is dialled through tor on the http/2 carrier");
        }
        tor::Mode::Only | tor::Mode::Off => {}
    }

    match psiphon::mode() {
        psiphon::Mode::Chain => {
            let through = held;
            let state = psiphon::state_dir(&base_config);
            let chain = tokio::spawn(psiphon::run_chain(through, state));
            watch_chain("psiphon", chain, core_end.clone(), &mut tor_and_psiphon);
        }
        psiphon::Mode::Reverse => {
            if needs_udp_to_warp(protocol, gool_classic()) {
                return Err(AetherError::from(crate::cli::CliError::UdpOverPsiphon(
                    protocol.label().to_string(),
                )));
            }

            let (socks, carrier) = psiphon::start_reverse(psiphon::state_dir(&base_config)).await?;
            tor_and_psiphon.push(carrier);
            crate::settings::set("AETHER_UPSTREAM", carrier_upstream("psiphon", socks)?);
            crate::settings::set("AETHER_MASQUE_HTTP2", "1");
            log::info!("[+] the tunnel is dialled through psiphon on the http/2 carrier");
        }
        psiphon::Mode::Only | psiphon::Mode::Off => {}
    }
    drop(core_end);

    let session = async {
        match protocol {
            Protocol::Masque => {
                select_masque_transport().await;
                let config_path = masque_config_path(&base_config);
                let identity = load_or_provision_masque(&config_path).await?;
                log::info!(
                    "[+] identity ready: device={} ipv4={} ipv6={}",
                    identity.device_id,
                    identity.ipv4,
                    identity.ipv6
                );
                let _ech = tls::EchSession::start(resolve_ech().await?);
                let lastconn_path = lastconn_path(&config_path);
                run_masque(identity, listeners, lastconn_path, None).await
            }
            Protocol::WireGuard => {
                let config_path = warp_config_path(&base_config);
                let identity = load_or_provision_warp(&config_path).await?;
                log::info!(
                    "[+] identity ready: device={} ipv4={} ipv6={}",
                    identity.device_id,
                    identity.ipv4,
                    identity.ipv6
                );

                let lastconn_path = lastconn_path(&config_path);
                run_wireguard(identity, listeners, lastconn_path).await
            }
            Protocol::WarpInWarp if !gool_classic() => {
                select_masque_transport().await;
                let config_path = masque_config_path(&base_config);
                let identity = load_or_provision_masque(&config_path).await?;
                let inner_path = gool_identity_path(&config_path);
                log::info!(
                    "[+] gool: masque device={} carries the wireguard identity in {inner_path}",
                    identity.device_id
                );
                let _ech = tls::EchSession::start(resolve_ech().await?);
                let lastconn_path = lastconn_path(&config_path);
                run_masque(identity, listeners, lastconn_path, Some(inner_path)).await
            }
            Protocol::WarpInWarp => {
                let primary_path = warp_config_path(&base_config);
                let secondary_path = derive_sibling_path(&primary_path, "secondary");
                let primary = load_or_provision_warp(&primary_path).await?;
                let secondary = load_or_provision_warp(&secondary_path).await?;
                log::info!(
                    "[+] outer device={} ipv4={} | inner device={} ipv4={}",
                    primary.device_id,
                    primary.ipv4,
                    secondary.device_id,
                    secondary.ipv4
                );
                run_gool(primary, secondary, listeners).await
            }
            Protocol::MasqueInMasque => {
                select_masque_transport().await;
                let primary_path = masque_config_path(&base_config);
                let secondary_path = derive_sibling_path(&primary_path, "secondary");
                let primary = load_or_provision_masque(&primary_path).await?;
                let secondary = load_or_provision_masque(&secondary_path).await?;
                log::info!(
                    "[+] outer device={} ipv4={} | inner device={} ipv4={}",
                    primary.device_id,
                    primary.ipv4,
                    secondary.device_id,
                    secondary.ipv4
                );
                let _ech = tls::EchSession::start(resolve_ech().await?);
                run_mim(primary, secondary, listeners).await
            }
        }
    };
    until_core_end(session, core_ended).await
}

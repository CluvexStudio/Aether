use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use crate::aethernoize::AetherNoizeConfig;
use crate::error::{AetherError, Result};
use crate::masque_h2;
use crate::netstack;
use crate::noize::NoizeConfig;
use crate::quic;
use crate::socks;
use crate::wireguard;

const PING_MTU: usize = 1280;
const HTTP_PROBE_HOST: &str = "www.gstatic.com";
const HTTP_PROBE_PATH: &str = "/generate_204";

struct AbortGuard<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortGuard<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn http_probe_port() -> u16 {
    std::env::var("AETHER_IRONCLAD_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(80)
}

pub async fn http_probe(stack: &netstack::StackHandle) -> Result<()> {
    let target = parse_probe_url("");
    http_probe_target(stack, &target).await.map(|_| ())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    pub host: String,
    pub port: u16,
    pub path: String,
}

pub fn parse_probe_url(url: &str) -> ProbeTarget {
    let default_port = http_probe_port();
    let default_target = ProbeTarget {
        host: HTTP_PROBE_HOST.to_string(),
        port: default_port,
        path: HTTP_PROBE_PATH.to_string(),
    };

    let s = url.trim();
    if s.is_empty() {
        return default_target;
    }

    let s = if let Some(stripped) = s.strip_prefix("http://") {
        stripped
    } else if let Some(stripped) = s.strip_prefix("https://") {
        stripped
    } else {
        s
    };

    let (host_port, path) = match s.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (s, "/".to_string()),
    };

    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(parsed_port) => (h.to_string(), parsed_port),
            Err(_) => (host_port.to_string(), default_port),
        },
        None => (host_port.to_string(), default_port),
    };

    if host.is_empty() {
        return default_target;
    }

    ProbeTarget { host, port, path }
}

pub async fn http_probe_target(
    stack: &netstack::StackHandle,
    target: &ProbeTarget,
) -> Result<Duration> {
    let start = Instant::now();
    let ip = socks::dns_resolve(stack, &target.host).await?;
    let dst = SocketAddr::new(ip, target.port);

    let conn = stack.open_tcp(dst).await?;
    let (sender, mut from_stack) = conn.into_split();

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: aether-ironclad\r\n\r\n",
        target.path, target.host
    );
    sender.send(request.into_bytes()).await?;

    let mut buf = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(6), from_stack.recv()).await {
            Ok(Some(chunk)) => {
                buf.extend_from_slice(&chunk);
                if buf.len() >= 12 {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => return Err(AetherError::Other("http probe response timeout".into())),
        }
    }

    sender.close().await;

    let status_line = String::from_utf8_lossy(&buf);
    if status_line.contains("204") || status_line.contains("200") {
        Ok(start.elapsed())
    } else {
        let first_line = status_line.lines().next().unwrap_or("").trim();
        Err(AetherError::Other(format!(
            "unexpected http probe response: {first_line}"
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthConfig {
    pub interval: Duration,
    pub max_fails: u32,
    pub timeout: Duration,
    pub probe_url: String,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl HealthConfig {
    pub fn from_env() -> Self {
        let interval_secs = std::env::var("AETHER_HEALTH_INTERVAL")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(20);

        let max_fails = std::env::var("AETHER_HEALTH_MAX_FAILS")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(2);

        let timeout_secs = std::env::var("AETHER_HEALTH_TIMEOUT")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(5);

        let probe_url = std::env::var("AETHER_HEALTH_PROBE_URL")
            .unwrap_or_else(|_| format!("http://{HTTP_PROBE_HOST}{HTTP_PROBE_PATH}"));

        Self {
            interval: Duration::from_secs(interval_secs),
            max_fails,
            timeout: Duration::from_secs(timeout_secs),
            probe_url,
        }
    }
}

pub async fn check_health(
    stack: &netstack::StackHandle,
    target: &ProbeTarget,
    timeout: Duration,
) -> Result<Duration> {
    match tokio::time::timeout(timeout, http_probe_target(stack, target)).await {
        Ok(res) => res,
        Err(_) => Err(AetherError::Other("tunnel health check timeout".into())),
    }
}

pub fn spawn_health_monitor(
    stack: netstack::StackHandle,
    config: HealthConfig,
) -> Option<tokio::task::JoinHandle<Result<()>>> {
    if config.interval.is_zero() {
        log::info!("[*] continuous tunnel health monitoring disabled (interval=0)");
        return None;
    }

    let target = parse_probe_url(&config.probe_url);

    log::info!(
        "[+] starting background tunnel health monitoring (url='http://{}:{}{}', interval={:?}, max_fails={}, timeout={:?})",
        target.host,
        target.port,
        target.path,
        config.interval,
        config.max_fails,
        config.timeout
    );

    Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(config.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;

        let mut consecutive_fails: u32 = 0;

        loop {
            interval.tick().await;
            match check_health(&stack, &target, config.timeout).await {
                Ok(rtt) => {
                    log::debug!("[+] tunnel health check passed (rtt {:?})", rtt);
                    if consecutive_fails > 0 {
                        log::info!(
                            "[+] tunnel health check passed (rtt {:?}); consecutive failure count reset to 0",
                            rtt
                        );
                    }
                    consecutive_fails = 0;
                }
                Err(e) => {
                    consecutive_fails += 1;
                    log::warn!(
                        "[-] tunnel health check failed ({consecutive_fails}/{}): {e}",
                        config.max_fails
                    );
                    if consecutive_fails >= config.max_fails {
                        log::error!(
                            "[-] tunnel health check failed {} consecutive times; declaring tunnel dead",
                            consecutive_fails
                        );
                        return Err(AetherError::Other(format!(
                            "tunnel health check failed {} consecutive times",
                            consecutive_fails
                        )));
                    }
                }
            }
        }
    }))
}



pub struct MasquePingParams {
    pub peer: SocketAddr,
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub noize: NoizeConfig,
    pub local_ipv4: Ipv4Addr,
    pub local_ipv4_str: String,
    pub local_ipv6_str: String,
}

pub async fn masque_http_ping(p: &MasquePingParams, timeout: Duration) -> Result<Duration> {
    let attempt = async {
        let (chans, internals) = quic::channels();
        let quic::Channels {
            outbound_tx,
            inbound_rx,
            ctrl_tx,
        } = chans;

        let stack = netstack::spawn(
            &p.local_ipv4_str,
            &p.local_ipv6_str,
            PING_MTU,
            inbound_rx,
            outbound_tx,
        )?;

        let (ready_tx, ready_rx) = oneshot::channel();

        let tunnel_task = if masque_h2::enabled() {
            let h2cfg = masque_h2::H2TunnelConfig {
                peer: masque_h2::h2_peer(p.peer),
                sni: p.sni.clone(),
                authority: p.authority.clone(),
                path: p.path.clone(),
                cert_pem: p.cert_pem.clone(),
                key_pem: p.key_pem.clone(),
                local_ipv4: p.local_ipv4,
                quiet: true,
            };
            AbortGuard(tokio::spawn(masque_h2::run(h2cfg, internals, None, Some(ready_tx))))
        } else {
            let cfg = quic::TunnelConfig {
                peer: p.peer,
                sni: p.sni.clone(),
                authority: p.authority.clone(),
                path: p.path.clone(),
                cert_pem: p.cert_pem.clone(),
                key_pem: p.key_pem.clone(),
                ech_config_list: None,
                noize: p.noize.clone(),
                local_ipv4: p.local_ipv4,
                quiet: true,
            };
            AbortGuard(tokio::spawn(quic::run(cfg, internals, None, Some(ready_tx))))
        };

        if ready_rx.await.is_err() {
            return Err(AetherError::Other(
                "tunnel exited before data-plane validation".into(),
            ));
        }

        let start = Instant::now();
        let result = http_probe(&stack).await.map(|()| start.elapsed());

        drop(ctrl_tx);
        drop(tunnel_task);
        result
    };

    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(rtt)) => Ok(rtt),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(AetherError::Other("ironclad http probe timeout".into())),
    }
}

pub struct WgPingParams {
    pub local_ipv4: Ipv4Addr,
    pub local_ipv6: Ipv6Addr,
    pub aethernoize: AetherNoizeConfig,
}

pub async fn wg_http_ping_established(
    session: wireguard::EstablishedSession,
    p: &WgPingParams,
    timeout: Duration,
) -> Result<Duration> {
    let attempt = async {
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(1024);
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(1024);

        let tunnel = wireguard::WgTunnel::from_established(
            session,
            std::sync::Arc::new(p.aethernoize.clone()),
            inbound_tx,
        );

        let local_ipv4_str = p.local_ipv4.to_string();
        let local_ipv6_str = p.local_ipv6.to_string();
        let stack = netstack::spawn(
            &local_ipv4_str,
            &local_ipv6_str,
            PING_MTU,
            inbound_rx,
            outbound_tx,
        )?;

        let tunnel_task = AbortGuard(tokio::spawn(tunnel.run(outbound_rx)));

        let start = Instant::now();
        let result = http_probe(&stack).await.map(|()| start.elapsed());

        drop(tunnel_task);
        result
    };

    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(rtt)) => Ok(rtt),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(AetherError::Other("ironclad http probe timeout".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_config_from_env() {
        let _guard = crate::cli::ENV_MUTEX.lock().unwrap();
        std::env::set_var("AETHER_HEALTH_INTERVAL", "15");
        std::env::set_var("AETHER_HEALTH_MAX_FAILS", "5");
        std::env::set_var("AETHER_HEALTH_TIMEOUT", "10");

        let cfg = HealthConfig::from_env();
        assert_eq!(cfg.interval, Duration::from_secs(15));
        assert_eq!(cfg.max_fails, 5);
        assert_eq!(cfg.timeout, Duration::from_secs(10));

        std::env::remove_var("AETHER_HEALTH_INTERVAL");
        std::env::remove_var("AETHER_HEALTH_MAX_FAILS");
        std::env::remove_var("AETHER_HEALTH_TIMEOUT");

        let default_cfg = HealthConfig::from_env();
        assert_eq!(default_cfg.interval, Duration::from_secs(20));
        assert_eq!(default_cfg.max_fails, 2);
        assert_eq!(default_cfg.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_parse_probe_url() {
        let t1 = parse_probe_url("http://cp.cloudflare.com/generate_204");
        assert_eq!(t1.host, "cp.cloudflare.com");
        assert_eq!(t1.port, 80);
        assert_eq!(t1.path, "/generate_204");

        let t2 = parse_probe_url("http://1.1.1.1:8080/check");
        assert_eq!(t2.host, "1.1.1.1");
        assert_eq!(t2.port, 8080);
        assert_eq!(t2.path, "/check");

        let t3 = parse_probe_url("");
        assert_eq!(t3.host, HTTP_PROBE_HOST);
        assert_eq!(t3.port, 80);
        assert_eq!(t3.path, HTTP_PROBE_PATH);
    }

    #[tokio::test]
    async fn test_spawn_health_monitor_failure_trigger() {
        let (outbound_tx, _outbound_rx) = tokio::sync::mpsc::channel(128);
        let (_inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(128);

        let stack = netstack::spawn("172.16.0.2", "fd00::2", 1500, inbound_rx, outbound_tx)
            .expect("spawn netstack");

        let config = HealthConfig {
            interval: Duration::from_millis(20),
            max_fails: 2,
            timeout: Duration::from_millis(50),
            probe_url: "http://1.1.1.1/generate_204".to_string(),
        };

        let handle = spawn_health_monitor(stack, config).expect("spawn health monitor");
        let result = handle.await.expect("join handle");

        assert!(result.is_err(), "expected health monitor to fail");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("failed 2 consecutive times"),
            "unexpected error message: {err_msg}"
        );
    }
}






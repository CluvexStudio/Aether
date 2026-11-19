use crate::provision::{enrol_zero_trust, team_scope};
use crate::{lastconn, prober};

pub(crate) async fn want_quick_reconnect(cached: &lastconn::LastConnection) -> bool {
    match crate::settings::var("AETHER_QUICK_RECONNECT").as_deref() {
        Ok("1") | Ok("true") | Ok("yes") | Ok("on") => return true,
        Ok("0") | Ok("false") | Ok("no") | Ok("off") => return false,
        _ => {}
    }

    let answer = prompt_line(&format!(
        "\nLast working gateway: {} (profile '{}')\nReconnect to it now without rescanning? [Y/n]: ",
        cached.peer, cached.profile
    ))
    .await;

    !matches!(answer.as_deref(), Some(a) if a.eq_ignore_ascii_case("n") || a.eq_ignore_ascii_case("no"))
}

pub(crate) fn needs_udp_to_warp(protocol: Protocol, classic_gool: bool) -> bool {
    match protocol {
        Protocol::WireGuard => true,
        Protocol::WarpInWarp => classic_gool,
        Protocol::Masque | Protocol::MasqueInMasque => false,
    }
}

pub(crate) async fn prompt_line(prompt: &str) -> Option<String> {
    use std::io::IsTerminal;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    if !std::io::stdin().is_terminal() {
        return None;
    }

    let mut stdout = tokio::io::stdout();
    let _ = stdout.write_all(prompt.as_bytes()).await;
    let _ = stdout.flush().await;

    let mut line = String::new();
    let mut reader = BufReader::new(tokio::io::stdin());
    match reader.read_line(&mut line).await {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

const SCAN_MODE_PROMPT: &str = "\nScan mode:\n  [1] turbo     (fast, first hit)\n  [2] balanced  (default)\n  [3] thorough  (deep, best ping)\n  [4] verified  (measured edges only, never a guessed neighbour; on gool and\n                 mim it keeps the two hops in different ranges, which is what\n                 moves the exit address)\n  [5] ironclad  (real tunnel + real HTTP check per candidate, guaranteed working)\nChoose [1-5] (default 2): ";

pub(crate) const MIM_MANUAL_TIP: &str = "\n(tip: you can skip this scan and give the two masque hops yourself:\n        aether --mim --mim-outer <ip:port> --mim-inner <ip:port>\n      the port is required, and naming just the outer one lets aether pick\n      the inner edge for you)\n";

pub(crate) const WIW_MANUAL_TIP: &str = "\n(tip: you can skip this scan and give the two gool hops yourself:\n        aether --gool --wiw-outer <ip:port> --wiw-inner <ip:port>\n      the port is required, and naming just one of the two lets the scan\n      find the other)\n";

pub(crate) async fn select_scan_mode_str(tip: &str) -> String {
    if let Ok(v) = crate::settings::var("AETHER_SCAN") {
        return v;
    }

    let answer = prompt_line(&format!("{tip}{SCAN_MODE_PROMPT}")).await;

    match answer.as_deref() {
        Some("1") => "turbo".to_string(),
        Some("3") => "thorough".to_string(),
        Some("4") => "verified".to_string(),
        Some("5") => "ironclad".to_string(),
        _ => "balanced".to_string(),
    }
}

pub(crate) async fn select_protocol(base: &str) -> Protocol {
    if let Ok(v) = crate::settings::var("AETHER_PROTOCOL") {
        return Protocol::parse(&v);
    }

    loop {
        let mut extra = String::new();
        let mut next = 5u8;
        let take = |line: &str, extra: &mut String, next: &mut u8| -> String {
            let key = next.to_string();
            extra.push_str(&format!("  [{key}] {line}\n"));
            *next += 1;
            key
        };

        let (tor_alone, tor_chain) = if cfg!(feature = "tor") {
            (
                take("Tor alone, with no warp under it", &mut extra, &mut next),
                take(
                    "Tor and warp chained, either way round",
                    &mut extra,
                    &mut next,
                ),
            )
        } else {
            (String::new(), String::new())
        };

        let psiphon_alone = take(
            "Psiphon alone, with no warp under it",
            &mut extra,
            &mut next,
        );
        let psiphon_chain = take(
            "Psiphon and warp chained, either way round",
            &mut extra,
            &mut next,
        );

        let last = next;
        let zero_trust_key = last.to_string();
        let zero_trust = match team_scope() {
            Some(team) => {
                format!("  [{last}] Zero Trust: signed in to {team}, pick another team\n")
            }
            None => {
                format!("  [{last}] Zero Trust: sign in to an organization (WARP for teams)\n")
            }
        };

        let answer = prompt_line(&format!(
            "\nProtocol:\n  [1] MASQUE (modern, QUIC/H3, default)\n  \
             [2] WireGuard (classic, faster)\n  [3] WARP-in-WARP / gool\n  \
             [4] MASQUE-in-MASQUE (two masque hops, for a different exit address)\n\
             {extra}{zero_trust}Choose [1-{last}] (default 1): "
        ))
        .await;

        let choice = answer.as_deref().unwrap_or_default();

        match choice {
            "2" => return Protocol::WireGuard,
            "3" => return select_gool().await,
            "4" => return Protocol::MasqueInMasque,
            _ if choice == zero_trust_key => {
                enrol_zero_trust(base).await;
                continue;
            }
            _ if !tor_alone.is_empty() && choice == tor_alone => {
                crate::settings::set("AETHER_TOR", "only");
                return Protocol::Masque;
            }
            _ if !tor_chain.is_empty() && choice == tor_chain => return select_tor_chain().await,
            _ if choice == psiphon_alone => {
                crate::settings::set("AETHER_PSIPHON", "only");
                return Protocol::Masque;
            }
            _ if choice == psiphon_chain => return select_psiphon_chain().await,
            _ => return Protocol::Masque,
        }
    }
}

async fn select_gool() -> Protocol {
    let answer = prompt_line(
        "\nWhich gool?\n  \
         [1] gool over masque: wireguard carried inside a masque tunnel, for a foreign exit \
         address (default)\n  \
         [2] classic gool: wireguard carried inside wireguard, a plain warp exit\n\
         Choose [1-2] (default 1): ",
    )
    .await;

    if matches!(answer.as_deref(), Some("2")) {
        crate::settings::set("AETHER_GOOL_MODE", "classic");
    }
    Protocol::WarpInWarp
}

async fn select_psiphon_chain() -> Protocol {
    let answer = prompt_line(
        "\nWhich way round?\n  \
         [1] psiphon inside warp: you, warp, psiphon, the internet. The exit is a psiphon \
         exit, and a network that blocks psiphon never sees it (default)\n  \
         [2] warp inside psiphon: you, psiphon, warp, the internet. The exit is a warp exit \
         reached from a psiphon exit, and your network never sees warp\n\
         Choose [1-2] (default 1): ",
    )
    .await;

    if matches!(answer.as_deref(), Some("2")) {
        crate::settings::set("AETHER_PSIPHON", "reverse");
        log::info!("[*] the tunnel will be dialled through psiphon, on the http/2 carrier");
        return Protocol::Masque;
    }

    crate::settings::set("AETHER_PSIPHON", "chain");
    log::info!("[*] psiphon will be carried inside the tunnel");
    select_chain_carrier("psiphon").await
}

async fn select_tor_chain() -> Protocol {
    let answer = prompt_line(
        "\nWhich way round?\n  \
         [1] tor inside warp: you, warp, tor, the internet. The exit is a tor exit, and a \
         network that blocks tor never sees it (default)\n  \
         [2] warp inside tor: you, tor, warp, the internet. The exit is a warp exit reached \
         from a tor exit, and your network never sees warp\n\
         Choose [1-2] (default 1): ",
    )
    .await;

    if matches!(answer.as_deref(), Some("2")) {
        crate::settings::set("AETHER_TOR", "reverse");
        log::info!("[*] the tunnel will be dialled through tor, on the http/2 carrier");
        return Protocol::Masque;
    }

    crate::settings::set("AETHER_TOR", "chain");
    log::info!("[*] tor will be carried inside the tunnel");
    select_chain_carrier("tor").await
}

async fn select_chain_carrier(what: &str) -> Protocol {
    let answer = prompt_line(&format!(
        "\nWhat carries {what}?\n  \
         [1] MASQUE, over quic/h3 or http/2, asked next (default)\n  \
         [2] WireGuard, warp over udp\n  \
         [3] WARP-in-WARP / gool\n  \
         [4] MASQUE-in-MASQUE\n\
         Choose [1-4] (default 1): "
    ))
    .await;

    match answer.as_deref() {
        Some("2") => Protocol::WireGuard,
        Some("3") => select_gool().await,
        Some("4") => Protocol::MasqueInMasque,
        _ => Protocol::Masque,
    }
}

pub(crate) fn protocol_without_asking(
    lookup: &dyn Fn(&str) -> Option<String>,
    pinned_wiw: bool,
    pinned_mim: bool,
) -> Option<Protocol> {
    if let Some(name) = lookup("AETHER_PROTOCOL") {
        return Some(Protocol::parse(&name));
    }
    if pinned_wiw {
        return Some(Protocol::WarpInWarp);
    }
    if pinned_mim {
        return Some(Protocol::MasqueInMasque);
    }
    if lookup("AETHER_WG_PEER").is_some() {
        return Some(Protocol::WireGuard);
    }
    lookup("AETHER_PEER").map(|_| Protocol::Masque)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    Masque,
    WireGuard,
    WarpInWarp,
    MasqueInMasque,
}

impl Protocol {
    pub(crate) fn parse(s: &str) -> Protocol {
        match s.trim().to_lowercase().as_str() {
            "wg" | "wireguard" => Protocol::WireGuard,
            "gool" | "wiw" | "warp-in-warp" | "warpinwarp" => Protocol::WarpInWarp,
            "mim" | "m2" | "masque-in-masque" | "masqueinmasque" => Protocol::MasqueInMasque,
            _ => Protocol::Masque,
        }
    }

    pub(crate) fn label(&self) -> &'static str {
        match self {
            Protocol::Masque => "MASQUE",
            Protocol::WireGuard => "WireGuard",
            Protocol::WarpInWarp => "WARP-in-WARP (gool)",
            Protocol::MasqueInMasque => "MASQUE-in-MASQUE",
        }
    }
}

pub(crate) async fn select_masque_transport() {
    if crate::settings::var("AETHER_MASQUE_HTTP2").is_ok()
        || crate::settings::var("AETHER_PEER").is_ok()
    {
        return;
    }

    let answer = prompt_line(
        "\nMASQUE transport:\n  [1] HTTP/3 (QUIC)  (default; fastest handshake, best on healthy UDP networks)\n  [2] HTTP/2 (TCP)   (looks like ordinary HTTPS; use if UDP/QUIC is blocked or throttled)\nChoose [1-2] (default 1): ",
    )
    .await;

    if matches!(answer.as_deref(), Some("2")) {
        crate::settings::set("AETHER_MASQUE_HTTP2", "1");
    }
}

pub(crate) async fn select_ip_version() -> prober::IpScan {
    if let Ok(v) = crate::settings::var("AETHER_IP") {
        return prober::IpScan::parse(&v);
    }

    let answer = prompt_line(
        "\nIP version to scan:\n  [1] IPv4 (default)\n  [2] IPv6\n  [3] Both\nChoose [1-3] (default 1): ",
    )
    .await;

    match answer.as_deref() {
        Some("2") => prober::IpScan::V6,
        Some("3") => prober::IpScan::Both,
        _ => prober::IpScan::V4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |key| {
            pairs
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| value.to_string())
        }
    }

    #[test]
    fn a_pinned_wireguard_peer_runs_wireguard_unless_a_protocol_is_named() {
        let wg = settings(&[("AETHER_WG_PEER", "162.159.192.1:2408")]);
        assert_eq!(
            protocol_without_asking(&wg, false, false),
            Some(Protocol::WireGuard)
        );

        let masque = settings(&[("AETHER_PEER", "162.159.198.1:443")]);
        assert_eq!(
            protocol_without_asking(&masque, false, false),
            Some(Protocol::Masque)
        );

        let named = settings(&[
            ("AETHER_PROTOCOL", "masque"),
            ("AETHER_WG_PEER", "162.159.192.1:2408"),
        ]);
        assert_eq!(
            protocol_without_asking(&named, false, false),
            Some(Protocol::Masque)
        );
    }

    #[test]
    fn pinned_hops_pick_their_two_hop_mode_and_nothing_pinned_asks() {
        let empty = settings(&[]);
        assert_eq!(
            protocol_without_asking(&empty, true, false),
            Some(Protocol::WarpInWarp)
        );
        assert_eq!(
            protocol_without_asking(&empty, false, true),
            Some(Protocol::MasqueInMasque)
        );
        assert_eq!(protocol_without_asking(&empty, false, false), None);
    }

    #[test]
    fn tor_and_psiphon_around_the_tunnel_refuse_only_what_needs_udp() {
        assert!(needs_udp_to_warp(Protocol::WireGuard, false));
        assert!(needs_udp_to_warp(Protocol::WarpInWarp, true));
        assert!(!needs_udp_to_warp(Protocol::WarpInWarp, false));
        assert!(!needs_udp_to_warp(Protocol::Masque, true));
        assert!(!needs_udp_to_warp(Protocol::MasqueInMasque, false));
    }

    #[test]
    fn masque_in_masque_is_selected_by_name() {
        for written in ["mim", "m2", "masque-in-masque", "MIM", "MasqueInMasque"] {
            assert_eq!(
                Protocol::parse(written),
                Protocol::MasqueInMasque,
                "{written}"
            );
        }
    }
}

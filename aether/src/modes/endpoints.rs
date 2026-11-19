use std::net::{IpAddr, SocketAddr};

use super::env_value;
use crate::error::{AetherError, Result};

pub(crate) const WG_EXAMPLE_PORT: u16 = 2408;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WiwEndpoints {
    pub(crate) outer: Option<SocketAddr>,
    pub(crate) inner: Option<SocketAddr>,
}

impl WiwEndpoints {
    pub(crate) fn is_empty(&self) -> bool {
        self.outer.is_none() && self.inner.is_none()
    }

    fn checked(self) -> Result<Self> {
        match (self.outer, self.inner) {
            (Some(outer), Some(inner)) if outer.ip() == inner.ip() => {
                Err(AetherError::Other(format!(
                    "the two hops need separate edges, but both point at {}",
                    outer.ip()
                )))
            }
            _ => Ok(self),
        }
    }
}

pub(crate) fn parse_endpoint(raw: &str) -> Result<SocketAddr> {
    let text = raw.trim();

    if let Ok(peer) = text.parse::<SocketAddr>() {
        return Ok(peer);
    }

    let portless = text.parse::<IpAddr>().ok().or_else(|| {
        text.strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .and_then(|inner| inner.parse::<IpAddr>().ok())
    });

    if let Some(address) = portless {
        return Err(AetherError::Other(format!(
            "{text} carries no port, and the port is required; write it out, as in {}",
            SocketAddr::new(address, WG_EXAMPLE_PORT)
        )));
    }

    Err(AetherError::Other(format!(
        "'{text}' is not an endpoint; write an address and a port together, \
         such as 162.159.192.1:{WG_EXAMPLE_PORT}"
    )))
}

fn parse_endpoint_list(raw: &str) -> Result<Vec<SocketAddr>> {
    let mut peers = Vec::new();

    for part in raw.split([',', ';', ' ']) {
        if part.trim().is_empty() {
            continue;
        }
        peers.push(parse_endpoint(part)?);
    }

    match peers.len() {
        0 => Err(AetherError::Other(
            "no endpoint was given; expected one or two addresses".to_string(),
        )),
        1 | 2 => Ok(peers),
        found => Err(AetherError::Other(format!(
            "warp-in-warp has two hops, but {found} addresses were given"
        ))),
    }
}

fn scan_keyword(value: &str) -> bool {
    matches!(
        value.to_lowercase().as_str(),
        "auto" | "scan" | "none" | "off" | "0"
    )
}

fn nested_endpoints_of(
    lookup: &dyn Fn(&str) -> Option<String>,
    list_key: &str,
    outer_key: &str,
    inner_key: &str,
) -> Result<WiwEndpoints> {
    let mut chosen = WiwEndpoints::default();

    if let Some(list) = lookup(list_key) {
        if !scan_keyword(&list) {
            let peers = parse_endpoint_list(&list)?;
            chosen.outer = peers.first().copied();
            chosen.inner = peers.get(1).copied();
        }
    }

    if let Some(value) = lookup(outer_key) {
        chosen.outer = Some(parse_endpoint(&value)?);
    }

    if let Some(value) = lookup(inner_key) {
        chosen.inner = Some(parse_endpoint(&value)?);
    }

    chosen.checked()
}

fn wiw_endpoints_of(lookup: &dyn Fn(&str) -> Option<String>) -> Result<WiwEndpoints> {
    nested_endpoints_of(
        lookup,
        "AETHER_WIW_PEERS",
        "AETHER_WIW_OUTER_PEER",
        "AETHER_WIW_INNER_PEER",
    )
}

pub(crate) fn wiw_endpoints_from_env() -> Result<WiwEndpoints> {
    wiw_endpoints_of(&env_value)
}

fn mim_endpoints_of(lookup: &dyn Fn(&str) -> Option<String>) -> Result<WiwEndpoints> {
    nested_endpoints_of(
        lookup,
        "AETHER_MIM_PEERS",
        "AETHER_MIM_OUTER_PEER",
        "AETHER_MIM_INNER_PEER",
    )
}

pub(crate) fn mim_endpoints_from_env() -> Result<WiwEndpoints> {
    mim_endpoints_of(&env_value)
}

pub(crate) fn wiw_endpoints_with_fallback(
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<WiwEndpoints> {
    let mut chosen = wiw_endpoints_of(lookup)?;

    if chosen.outer.is_some() {
        return Ok(chosen);
    }

    let forced = lookup("AETHER_WG_PEER").or_else(|| lookup("AETHER_PEER"));
    let Some(forced) = forced else {
        return Ok(chosen);
    };

    let peers = parse_endpoint_list(&forced)?;
    chosen.outer = peers.first().copied();
    if chosen.inner.is_none() {
        chosen.inner = peers.get(1).copied();
    }

    chosen.checked()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let values: BTreeMap<String, String> = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        move |key: &str| values.get(key).cloned()
    }

    #[test]
    fn the_masque_hops_can_be_named_by_hand() {
        let chosen = mim_endpoints_of(&env(&[
            ("AETHER_MIM_OUTER_PEER", "162.159.192.1:443"),
            ("AETHER_MIM_INNER_PEER", "188.114.96.1:443"),
        ]))
        .expect("both hops");

        assert_eq!(chosen.outer, Some("162.159.192.1:443".parse().unwrap()));
        assert_eq!(chosen.inner, Some("188.114.96.1:443".parse().unwrap()));
    }

    #[test]
    fn the_same_masque_edge_cannot_serve_as_both_hops() {
        assert!(mim_endpoints_of(&env(&[(
            "AETHER_MIM_PEERS",
            "162.159.192.1:443,162.159.192.1:8443"
        )]))
        .is_err());
    }

    #[test]
    fn an_address_and_a_port_are_read_together() {
        let peer = parse_endpoint("162.159.192.1:894").expect("address and port");
        assert_eq!(peer, "162.159.192.1:894".parse().unwrap());
    }

    #[test]
    fn an_address_without_a_port_is_refused_rather_than_guessed_at() {
        let message = parse_endpoint("162.159.192.1")
            .expect_err("the port carries too much meaning to be assumed")
            .to_string();
        assert!(
            message.contains("162.159.192.1:2408"),
            "the error should spell out the shape wanted, got: {message}"
        );
    }

    #[test]
    fn an_ipv6_address_without_a_port_is_refused_the_same_way() {
        for written in ["2606:4700:d0::a29f:c001", "[2606:4700:d0::a29f:c001]"] {
            let message = parse_endpoint(written).expect_err(written).to_string();
            assert!(
                message.contains("[2606:4700:d0::a29f:c001]:2408"),
                "the error should bracket the address it suggests, got: {message}"
            );
        }
    }

    #[test]
    fn surrounding_whitespace_is_forgiven() {
        let peer = parse_endpoint("  162.159.192.1:2408  ").expect("padded");
        assert_eq!(peer, "162.159.192.1:2408".parse().unwrap());
    }

    #[test]
    fn ipv6_is_read_when_it_is_bracketed_and_carries_its_port() {
        let peer = parse_endpoint("[2606:4700:d0::a29f:c001]:2408").expect("ipv6 endpoint");
        assert_eq!(peer, "[2606:4700:d0::a29f:c001]:2408".parse().unwrap());
    }

    #[test]
    fn nonsense_is_reported_with_an_example_to_copy() {
        let message = parse_endpoint("not-an-address")
            .expect_err("a hostname is not an address")
            .to_string();
        assert!(
            message.contains("162.159.192.1:2408"),
            "the error should show the shape expected, got: {message}"
        );
    }

    #[test]
    fn an_impossible_port_is_rejected_rather_than_wrapped() {
        assert!(parse_endpoint("162.159.192.1:70000").is_err());
    }

    #[test]
    fn a_pair_may_be_written_with_a_comma_or_a_space() {
        for written in [
            "162.159.192.1:2408,162.159.195.1:500",
            "162.159.192.1:2408, 162.159.195.1:500",
            "162.159.192.1:2408 162.159.195.1:500",
        ] {
            let peers = parse_endpoint_list(written).expect(written);
            assert_eq!(peers.len(), 2, "{written} names two hops");
            assert_eq!(peers[0], "162.159.192.1:2408".parse().unwrap());
            assert_eq!(peers[1], "162.159.195.1:500".parse().unwrap());
        }
    }

    #[test]
    fn a_third_address_is_refused_because_there_are_only_two_hops() {
        let outcome = parse_endpoint_list("1.1.1.1:2408,2.2.2.2:2408,3.3.3.3:2408");
        assert!(outcome.is_err());
    }

    #[test]
    fn the_pair_setting_fills_the_outer_hop_first() {
        let chosen = wiw_endpoints_of(&env(&[(
            "AETHER_WIW_PEERS",
            "162.159.192.1:2408,162.159.195.1:500",
        )]))
        .expect("a usable pair");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("162.159.195.1:500".parse().unwrap()));
    }

    #[test]
    fn one_address_pins_the_outer_hop_and_leaves_the_inner_one_to_the_scan() {
        let chosen = wiw_endpoints_of(&env(&[("AETHER_WIW_PEERS", "162.159.192.1:894")]))
            .expect("a single hop");
        assert_eq!(chosen.outer, Some("162.159.192.1:894".parse().unwrap()));
        assert_eq!(chosen.inner, None);
    }

    #[test]
    fn a_hop_named_on_its_own_wins_over_the_pair() {
        let chosen = wiw_endpoints_of(&env(&[
            ("AETHER_WIW_PEERS", "162.159.192.1:2408,162.159.195.1:500"),
            ("AETHER_WIW_INNER_PEER", "188.114.96.1:1701"),
        ]))
        .expect("the inner override");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("188.114.96.1:1701".parse().unwrap()));
    }

    #[test]
    fn only_the_inner_hop_may_be_pinned() {
        let chosen = wiw_endpoints_of(&env(&[("AETHER_WIW_INNER_PEER", "188.114.96.1:2408")]))
            .expect("the inner hop");
        assert_eq!(chosen.outer, None);
        assert_eq!(chosen.inner, Some("188.114.96.1:2408".parse().unwrap()));
    }

    #[test]
    fn one_address_cannot_serve_as_both_hops() {
        let outcome = wiw_endpoints_of(&env(&[
            ("AETHER_WIW_OUTER_PEER", "162.159.192.1:2408"),
            ("AETHER_WIW_INNER_PEER", "162.159.192.1:894"),
        ]));

        let message = outcome
            .expect_err("the same edge twice is not warp-in-warp")
            .to_string();
        assert!(
            message.contains("162.159.192.1"),
            "the error should name the address, got: {message}"
        );
    }

    #[test]
    fn asking_for_a_scan_leaves_both_hops_open() {
        for written in ["auto", "scan", "off", "none", "0"] {
            let lookup = env(&[("AETHER_WIW_PEERS", written)]);
            assert!(scan_keyword(written), "{written} means scan");
            assert!(
                wiw_endpoints_of(&lookup).expect(written).is_empty(),
                "{written} should pin nothing"
            );
        }
    }

    #[test]
    fn nothing_set_pins_nothing() {
        assert!(wiw_endpoints_of(&env(&[])).expect("empty").is_empty());
    }

    #[test]
    fn a_malformed_address_is_an_error_rather_than_a_silent_scan() {
        assert!(wiw_endpoints_of(&env(&[("AETHER_WIW_OUTER_PEER", "162.159.192")])).is_err());
    }

    #[test]
    fn a_hop_set_without_a_port_is_an_error_rather_than_a_silent_scan() {
        assert!(wiw_endpoints_of(&env(&[("AETHER_WIW_OUTER_PEER", "162.159.192.1")])).is_err());
    }

    #[test]
    fn the_older_wg_peer_setting_still_names_the_outer_hop() {
        let chosen = wiw_endpoints_with_fallback(&env(&[("AETHER_WG_PEER", "162.159.192.1:2408")]))
            .expect("the documented --gool --wg-peer pairing");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, None);
    }

    #[test]
    fn the_generic_peer_setting_is_the_last_fallback() {
        let chosen = wiw_endpoints_with_fallback(&env(&[("AETHER_PEER", "162.159.192.1:2408")]))
            .expect("--peer names the outer hop too");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
    }

    #[test]
    fn a_hop_chosen_for_warp_in_warp_beats_the_older_setting() {
        let chosen = wiw_endpoints_with_fallback(&env(&[
            ("AETHER_WG_PEER", "162.159.192.1:2408"),
            ("AETHER_WIW_OUTER_PEER", "188.114.96.1:2408"),
        ]))
        .expect("the warp-in-warp setting is the specific one");
        assert_eq!(chosen.outer, Some("188.114.96.1:2408".parse().unwrap()));
    }

    #[test]
    fn the_older_setting_may_carry_both_hops_at_once() {
        let chosen = wiw_endpoints_with_fallback(&env(&[(
            "AETHER_WG_PEER",
            "162.159.192.1:2408,188.114.96.1:2408",
        )]))
        .expect("a pair");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("188.114.96.1:2408".parse().unwrap()));
    }

    #[test]
    fn the_older_setting_does_not_overwrite_a_pinned_inner_hop() {
        let chosen = wiw_endpoints_with_fallback(&env(&[
            ("AETHER_WG_PEER", "162.159.192.1:2408,188.114.96.1:2408"),
            ("AETHER_WIW_INNER_PEER", "162.159.195.1:2408"),
        ]))
        .expect("the inner hop stays where it was put");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("162.159.195.1:2408".parse().unwrap()));
    }
}

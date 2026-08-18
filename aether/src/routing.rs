use std::net::IpAddr;

use ipnet::IpNet;
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Proxy,
    Direct,
    Block,
}

impl Action {
    pub fn label(self) -> &'static str {
        match self {
            Action::Proxy => "proxy",
            Action::Direct => "direct",
            Action::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Host<'a> {
    Domain(&'a str),
    Ip(IpAddr),
}

#[derive(Debug)]
enum Matcher {
    DomainSuffix(String),
    DomainFull(String),
    DomainKeyword(String),
    DomainRegex(Regex),
    Net(IpNet),
    Ports(u16, u16),
    Private,
}

impl Matcher {
    fn parse(entry: &str) -> Option<Self> {
        let entry = entry.trim();
        if entry.is_empty() || entry.starts_with('#') {
            return None;
        }

        let (kind, value) = match entry.split_once(':') {
            Some((kind, value)) if !kind.contains('.') && !kind.contains('/') => {
                (kind.trim().to_lowercase(), value.trim())
            }
            _ => (String::new(), entry),
        };

        match kind.as_str() {
            "domain" | "suffix" => Some(Matcher::DomainSuffix(normalize_domain(value)?)),
            "full" | "exact" => Some(Matcher::DomainFull(normalize_domain(value)?)),
            "keyword" => {
                let needle = value.trim().to_lowercase();
                if needle.is_empty() {
                    None
                } else {
                    Some(Matcher::DomainKeyword(needle))
                }
            }
            "regexp" | "regex" => Regex::new(value).ok().map(Matcher::DomainRegex),
            "ip" | "cidr" => parse_net(value).map(Matcher::Net),
            "port" => parse_ports(value).map(|(lo, hi)| Matcher::Ports(lo, hi)),
            "geoip" | "geosite" => {
                if value.eq_ignore_ascii_case("private") {
                    Some(Matcher::Private)
                } else {
                    None
                }
            }
            "" => {
                if value.eq_ignore_ascii_case("private") {
                    return Some(Matcher::Private);
                }
                if let Some(net) = parse_net(value) {
                    return Some(Matcher::Net(net));
                }
                normalize_domain(value).map(Matcher::DomainSuffix)
            }
            _ => None,
        }
    }

    fn matches(&self, host: Host<'_>, port: u16) -> bool {
        match self {
            Matcher::Ports(lo, hi) => port >= *lo && port <= *hi,
            Matcher::Private => match host {
                Host::Ip(ip) => is_private(ip),
                Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
            },
            Matcher::Net(net) => match host {
                Host::Ip(ip) => net.contains(&ip),
                Host::Domain(_) => false,
            },
            Matcher::DomainSuffix(suffix) => match host {
                Host::Domain(name) => {
                    let name = name.to_lowercase();
                    name == *suffix || name.ends_with(&format!(".{suffix}"))
                }
                Host::Ip(_) => false,
            },
            Matcher::DomainFull(full) => match host {
                Host::Domain(name) => name.eq_ignore_ascii_case(full),
                Host::Ip(_) => false,
            },
            Matcher::DomainKeyword(needle) => match host {
                Host::Domain(name) => name.to_lowercase().contains(needle),
                Host::Ip(_) => false,
            },
            Matcher::DomainRegex(pattern) => match host {
                Host::Domain(name) => pattern.is_match(name),
                Host::Ip(_) => false,
            },
        }
    }
}

fn normalize_domain(value: &str) -> Option<String> {
    let cleaned = value
        .trim()
        .trim_start_matches('*')
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_lowercase();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn parse_net(value: &str) -> Option<IpNet> {
    let value = value.trim();
    if let Ok(net) = value.parse::<IpNet>() {
        return Some(net);
    }
    value.parse::<IpAddr>().ok().map(IpNet::from)
}

fn parse_ports(value: &str) -> Option<(u16, u16)> {
    let value = value.trim();
    match value.split_once('-') {
        Some((lo, hi)) => {
            let lo = lo.trim().parse::<u16>().ok()?;
            let hi = hi.trim().parse::<u16>().ok()?;
            Some(if hi < lo { (hi, lo) } else { (lo, hi) })
        }
        None => {
            let single = value.parse::<u16>().ok()?;
            Some((single, single))
        }
    }
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[derive(Debug, Default)]
pub struct RuleSet {
    block: Vec<Matcher>,
    direct: Vec<Matcher>,
}

impl RuleSet {
    pub fn from_env() -> Self {
        let mut block = std::env::var("AETHER_ROUTE_BLOCK").unwrap_or_default();
        let mut direct = std::env::var("AETHER_ROUTE_DIRECT").unwrap_or_default();

        if let Ok(path) = std::env::var("AETHER_ROUTES_FILE") {
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let (file_block, file_direct) = split_sections(&text);
                    push_list(&mut block, &file_block);
                    push_list(&mut direct, &file_direct);
                }
                Err(error) => {
                    log::warn!("[-] could not read the routing file {path}: {error}");
                }
            }
        }

        Self::parse(&block, &direct)
    }

    pub fn parse(block: &str, direct: &str) -> Self {
        let set = Self {
            block: parse_list(block),
            direct: parse_list(direct),
        };

        if !set.is_empty() {
            log::info!(
                "[+] routing rules loaded: {} block, {} direct",
                set.block.len(),
                set.direct.len()
            );
        }
        set
    }

    pub fn is_empty(&self) -> bool {
        self.block.is_empty() && self.direct.is_empty()
    }

    pub fn has_domain_rules(&self) -> bool {
        self.block.iter().chain(self.direct.iter()).any(|rule| {
            matches!(
                rule,
                Matcher::DomainSuffix(_)
                    | Matcher::DomainFull(_)
                    | Matcher::DomainKeyword(_)
                    | Matcher::DomainRegex(_)
            )
        })
    }

    pub fn decide(&self, host: Host<'_>, port: u16) -> Action {
        if self.block.iter().any(|rule| rule.matches(host, port)) {
            return Action::Block;
        }
        if self.direct.iter().any(|rule| rule.matches(host, port)) {
            return Action::Direct;
        }
        Action::Proxy
    }
}

fn parse_list(raw: &str) -> Vec<Matcher> {
    raw.split(['\n', ',', ';'])
        .filter_map(Matcher::parse)
        .collect()
}

fn push_list(target: &mut String, extra: &str) {
    if extra.trim().is_empty() {
        return;
    }
    if !target.trim().is_empty() {
        target.push('\n');
    }
    target.push_str(extra);
}

fn split_sections(text: &str) -> (String, String) {
    let mut block = String::new();
    let mut direct = String::new();
    let mut current: Option<&mut String> = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let lowered = trimmed.to_lowercase();
        if lowered == "[block]" {
            current = Some(&mut block);
            continue;
        }
        if lowered == "[direct]" {
            current = Some(&mut direct);
            continue;
        }
        if lowered.starts_with('[') {
            current = None;
            continue;
        }

        if let Some(target) = current.as_deref_mut() {
            target.push_str(trimmed);
            target.push('\n');
        }
    }

    (block, direct)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(block: &str, direct: &str) -> RuleSet {
        RuleSet {
            block: parse_list(block),
            direct: parse_list(direct),
        }
    }

    #[test]
    fn an_empty_rule_set_sends_everything_through_the_proxy() {
        let set = rules("", "");
        assert!(set.is_empty());
        assert_eq!(set.decide(Host::Domain("example.com"), 443), Action::Proxy);
        assert_eq!(
            set.decide(Host::Ip("1.1.1.1".parse().unwrap()), 443),
            Action::Proxy
        );
    }

    #[test]
    fn a_bare_domain_matches_itself_and_its_subdomains() {
        let set = rules("ads.example", "");
        assert_eq!(set.decide(Host::Domain("ads.example"), 443), Action::Block);
        assert_eq!(
            set.decide(Host::Domain("tracker.ads.example"), 443),
            Action::Block
        );
        assert_eq!(
            set.decide(Host::Domain("notads.example"), 443),
            Action::Proxy
        );
        assert_eq!(set.decide(Host::Domain("ads.example.org"), 443), Action::Proxy);
    }

    #[test]
    fn a_full_rule_matches_only_the_exact_name() {
        let set = rules("full:example.com", "");
        assert_eq!(set.decide(Host::Domain("example.com"), 443), Action::Block);
        assert_eq!(set.decide(Host::Domain("www.example.com"), 443), Action::Proxy);
    }

    #[test]
    fn a_keyword_rule_matches_anywhere_in_the_name() {
        let set = rules("keyword:doubleclick", "");
        assert_eq!(
            set.decide(Host::Domain("stats.doubleclick.net"), 443),
            Action::Block
        );
        assert_eq!(set.decide(Host::Domain("example.com"), 443), Action::Proxy);
    }

    #[test]
    fn a_regex_rule_is_honoured() {
        let set = rules(r"regexp:^ad[0-9]+\.", "");
        assert_eq!(set.decide(Host::Domain("ad42.example.com"), 443), Action::Block);
        assert_eq!(set.decide(Host::Domain("ads.example.com"), 443), Action::Proxy);
    }

    #[test]
    fn a_cidr_rule_matches_addresses_inside_it() {
        let set = rules("", "10.0.0.0/8");
        assert_eq!(
            set.decide(Host::Ip("10.1.2.3".parse().unwrap()), 22),
            Action::Direct
        );
        assert_eq!(
            set.decide(Host::Ip("11.1.2.3".parse().unwrap()), 22),
            Action::Proxy
        );
    }

    #[test]
    fn a_bare_address_is_treated_as_a_single_host_rule() {
        let set = rules("1.2.3.4", "");
        assert_eq!(
            set.decide(Host::Ip("1.2.3.4".parse().unwrap()), 80),
            Action::Block
        );
        assert_eq!(
            set.decide(Host::Ip("1.2.3.5".parse().unwrap()), 80),
            Action::Proxy
        );
    }

    #[test]
    fn a_port_rule_can_carve_out_a_range() {
        let set = rules("port:25", "port:3000-3010");
        assert_eq!(set.decide(Host::Domain("mail.example"), 25), Action::Block);
        assert_eq!(set.decide(Host::Domain("dev.example"), 3005), Action::Direct);
        assert_eq!(set.decide(Host::Domain("dev.example"), 3011), Action::Proxy);
    }

    #[test]
    fn the_private_keyword_covers_lan_and_loopback_and_cgnat() {
        let set = rules("", "private");
        for address in ["10.1.1.1", "192.168.1.5", "172.16.9.9", "127.0.0.1", "100.96.0.2"] {
            assert_eq!(
                set.decide(Host::Ip(address.parse().unwrap()), 80),
                Action::Direct,
                "{address} should be direct"
            );
        }
        assert_eq!(
            set.decide(Host::Ip("8.8.8.8".parse().unwrap()), 80),
            Action::Proxy
        );
        assert_eq!(set.decide(Host::Domain("localhost"), 80), Action::Direct);
    }

    #[test]
    fn ipv6_private_ranges_are_recognised() {
        assert!(is_private("::1".parse().unwrap()));
        assert!(is_private("fd00::1".parse().unwrap()));
        assert!(is_private("fe80::1".parse().unwrap()));
        assert!(!is_private("2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn domain_rules_are_reported_so_a_tunnel_can_recover_the_name() {
        assert!(!rules("", "").has_domain_rules());
        assert!(!rules("10.0.0.0/8, port:25", "private").has_domain_rules());
        assert!(rules("ads.example", "").has_domain_rules());
        assert!(rules("", "keyword:internal").has_domain_rules());
        assert!(rules("", r"regexp:^ad[0-9]+\.").has_domain_rules());
        assert!(rules("full:example.com", "").has_domain_rules());
    }

    #[test]
    fn block_wins_over_direct_when_both_match() {
        let set = rules("example.com", "example.com");
        assert_eq!(set.decide(Host::Domain("example.com"), 443), Action::Block);
    }

    #[test]
    fn lists_accept_commas_newlines_and_comments() {
        let set = rules("a.example, b.example\n# a comment\nc.example", "");
        for name in ["a.example", "b.example", "c.example"] {
            assert_eq!(set.decide(Host::Domain(name), 443), Action::Block, "{name}");
        }
        assert_eq!(set.decide(Host::Domain("comment"), 443), Action::Proxy);
    }

    #[test]
    fn a_leading_wildcard_is_tolerated() {
        let set = rules("*.example.com", "");
        assert_eq!(set.decide(Host::Domain("a.example.com"), 443), Action::Block);
        assert_eq!(set.decide(Host::Domain("example.com"), 443), Action::Block);
    }

    #[test]
    fn a_rules_file_is_split_into_its_two_sections() {
        let text = "# routing\n[block]\nads.example\nkeyword:tracker\n\n[direct]\nprivate\n10.0.0.0/8\n";
        let (block, direct) = split_sections(text);
        assert!(block.contains("ads.example"));
        assert!(block.contains("keyword:tracker"));
        assert!(direct.contains("private"));
        assert!(direct.contains("10.0.0.0/8"));
        assert!(!block.contains("private"));
    }

    #[test]
    fn an_unknown_section_is_ignored_rather_than_misfiled() {
        let (block, direct) = split_sections("[proxy]\nexample.com\n[block]\nads.example\n");
        assert!(!block.contains("example.com"));
        assert!(block.contains("ads.example"));
        assert!(direct.trim().is_empty());
    }

    #[test]
    fn malformed_entries_are_dropped_without_panicking() {
        let set = rules("regexp:[unclosed, port:abc, ip:not-an-ip, geoip:cn, :", "");
        assert!(set.is_empty() || set.decide(Host::Domain("example.com"), 443) == Action::Proxy);
    }
}

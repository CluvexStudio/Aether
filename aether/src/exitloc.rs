use std::net::SocketAddr;
use std::time::Duration;

use crate::error::{AetherError, Result};
use crate::netstack::StackHandle;

const TRACE_HOST: &str = "www.cloudflare.com";
const TRACE_PATH: &str = "/cdn-cgi/trace";
const TRACE_PORT: u16 = 80;
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Clone)]
pub struct Policy {
    allow: Vec<String>,
    deny: Vec<String>,
    interval: Duration,
}

impl Policy {
    pub fn from_env() -> Option<Self> {
        Self::parse(&std::env::var("AETHER_EXIT_LOC").unwrap_or_default())
    }

    pub fn parse(raw: &str) -> Option<Self> {
        let spec = raw.trim();
        if spec.is_empty() || spec.eq_ignore_ascii_case("any") || spec.eq_ignore_ascii_case("off") {
            return None;
        }

        let negated = spec.starts_with('!');
        let body = spec
            .trim_start_matches('!')
            .trim_start_matches('=')
            .trim_start_matches('!');

        let codes: Vec<String> = body
            .split(',')
            .map(|c| c.trim().to_ascii_uppercase())
            .filter(|c| c.len() == 2 && c.chars().all(|ch| ch.is_ascii_alphabetic()))
            .collect();

        if codes.is_empty() {
            return None;
        }

        let (allow, deny) = if negated {
            (Vec::new(), codes)
        } else {
            (codes, Vec::new())
        };

        Some(Self {
            allow,
            deny,
            interval: interval_from_env(),
        })
    }

    pub fn accepts(&self, loc: &str) -> bool {
        let code = loc.trim().to_ascii_uppercase();
        if self.deny.contains(&code) {
            return false;
        }
        self.allow.is_empty() || self.allow.contains(&code)
    }

    pub fn describe(&self) -> String {
        if self.deny.is_empty() {
            format!("exit must be in {}", self.allow.join(", "))
        } else {
            format!("exit must not be in {}", self.deny.join(", "))
        }
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }
}

fn interval_from_env() -> Duration {
    let secs = std::env::var("AETHER_EXIT_LOC_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    Duration::from_secs(secs)
}

pub fn parse_trace(body: &str) -> Option<String> {
    field(body, "loc")
        .map(|code| code.to_ascii_uppercase())
        .filter(|code| code.len() == 2)
}

fn field(body: &str, name: &str) -> Option<String> {
    let head = format!("{name}=");
    body.lines()
        .find_map(|line| line.strip_prefix(head.as_str()))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Clone)]
pub struct Exit {
    pub address: Option<String>,
    pub country: Option<String>,
    pub colo: Option<String>,
    pub warp: bool,
    pub rtt: Duration,
}

impl Exit {
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();

        if let Some(address) = &self.address {
            parts.push(address.clone());
        }
        match (&self.country, &self.colo) {
            (Some(country), Some(colo)) => parts.push(format!("{country} via {colo}")),
            (Some(country), None) => parts.push(country.clone()),
            (None, Some(colo)) => parts.push(colo.clone()),
            (None, None) => {}
        }
        parts.push(format!("{}ms to cloudflare", self.rtt.as_millis()));
        if self.warp {
            parts.push("warp on".to_string());
        }

        parts.join(", ")
    }
}

pub fn parse_exit(body: &str, rtt: Duration) -> Exit {
    Exit {
        address: field(body, "ip"),
        country: parse_trace(body),
        colo: field(body, "colo"),
        warp: field(body, "warp").as_deref() == Some("on"),
        rtt,
    }
}

pub async fn trace_through(stack: &StackHandle) -> Result<(String, Duration)> {
    let started = std::time::Instant::now();
    let body = read_trace(stack).await?;
    Ok((body, started.elapsed()))
}

pub async fn report(stack: &StackHandle, what: &str) -> Option<Exit> {
    match trace_through(stack).await {
        Ok((body, rtt)) => {
            let exit = parse_exit(&body, rtt);
            log::info!("[+] {what} exit: {}", exit.describe());
            Some(exit)
        }
        Err(e) => {
            log::debug!("could not read the exit of {what}: {e}");
            None
        }
    }
}

pub async fn report_through_socks(proxy: SocketAddr, what: &str) -> Option<Exit> {
    let client = reqwest::Client::builder()
        .timeout(LOOKUP_TIMEOUT)
        .proxy(reqwest::Proxy::all(format!("socks5h://{proxy}")).ok()?)
        .build()
        .ok()?;

    let started = std::time::Instant::now();
    let body = client
        .get(format!("http://{TRACE_HOST}{TRACE_PATH}"))
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;

    let exit = parse_exit(&body, started.elapsed());
    log::info!("[+] {what} exit: {}", exit.describe());
    Some(exit)
}

async fn read_trace(stack: &StackHandle) -> Result<String> {
    let attempt = async {
        let ip = crate::socks::dns_resolve(stack, TRACE_HOST).await?;
        let conn = stack.open_tcp(SocketAddr::new(ip, TRACE_PORT)).await?;
        let (sender, mut from_stack) = conn.into_split();

        let request = format!(
            "GET {TRACE_PATH} HTTP/1.1\r\nHost: {TRACE_HOST}\r\nConnection: close\r\nUser-Agent: aether\r\n\r\n"
        );
        sender.send(request.into_bytes()).await?;

        let mut buf = Vec::new();
        while let Some(chunk) = from_stack.recv().await {
            buf.extend_from_slice(&chunk);
            if buf.len() > 8192 || parse_trace(&String::from_utf8_lossy(&buf)).is_some() {
                break;
            }
        }
        sender.close().await;

        Ok(String::from_utf8_lossy(&buf).to_string())
    };

    match tokio::time::timeout(LOOKUP_TIMEOUT, attempt).await {
        Ok(result) => result,
        Err(_) => Err(AetherError::Other(
            "looking up the exit location timed out".into(),
        )),
    }
}

pub async fn lookup(stack: &StackHandle) -> Result<String> {
    let body = read_trace(stack).await?;
    parse_trace(&body)
        .ok_or_else(|| AetherError::Other("the trace answer carried no location".into()))
}

pub async fn settle(stack: &StackHandle, policy: &Option<Policy>, what: &str) -> Result<()> {
    let Some(policy) = policy else {
        let stack = stack.clone();
        let what = what.to_string();
        tokio::spawn(async move {
            report(&stack, &what).await;
        });
        return Ok(());
    };

    let Some(exit) = report(stack, what).await else {
        return Err(AetherError::Other(
            "the exit location could not be read, so the policy cannot be honoured".into(),
        ));
    };

    let loc = exit.country.unwrap_or_default();
    if policy.accepts(&loc) {
        log::info!("[+] exit location {loc} accepted ({})", policy.describe());
        return Ok(());
    }

    log::warn!("[-] exit location {loc} rejected ({})", policy.describe());
    Err(AetherError::Other(format!(
        "exit location {loc} does not satisfy the requested policy"
    )))
}

pub async fn watch(stack: &StackHandle, policy: &Policy) -> AetherError {
    loop {
        tokio::time::sleep(policy.interval()).await;

        match lookup(stack).await {
            Ok(loc) if policy.accepts(&loc) => log::debug!("exit location is still {loc}"),
            Ok(loc) => {
                log::warn!("[-] exit location changed to {loc}; reconnecting");
                return AetherError::Other(format!("exit location changed to {loc}"));
            }
            Err(e) => log::debug!("exit location check did not answer: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deny_list_keeps_everything_else() {
        let policy = Policy::parse("!IR,AZ,RU").expect("a policy");
        assert!(!policy.accepts("IR"));
        assert!(!policy.accepts("az"));
        assert!(!policy.accepts("RU"));
        assert!(policy.accepts("DE"));
        assert!(policy.accepts("SE"));
    }

    #[test]
    fn an_allow_list_admits_only_what_it_names() {
        let policy = Policy::parse("DE,SE").expect("a policy");
        assert!(policy.accepts("DE"));
        assert!(policy.accepts("se"));
        assert!(!policy.accepts("IR"));
        assert!(!policy.accepts("US"));
    }

    #[test]
    fn the_shapes_the_issue_asked_for_all_parse() {
        assert!(Policy::parse("!=IR").expect("a policy").accepts("DE"));
        assert!(!Policy::parse("!=IR").expect("a policy").accepts("IR"));
        assert!(Policy::parse("=DE").expect("a policy").accepts("DE"));
    }

    #[test]
    fn an_unset_variable_reads_the_same_as_no_policy_at_all() {
        assert!(Policy::parse("").is_none());
    }

    #[test]
    fn nothing_worth_enforcing_turns_the_policy_off() {
        assert!(Policy::parse("").is_none());
        assert!(Policy::parse("   ").is_none());
        assert!(Policy::parse("any").is_none());
        assert!(Policy::parse("off").is_none());
        assert!(Policy::parse("!").is_none());
        assert!(Policy::parse("germany").is_none());
    }

    #[test]
    fn the_location_is_read_out_of_a_trace_body() {
        let body = "fl=117f35\nh=www.cloudflare.com\nip=1.2.3.4\ncolo=FRA\nloc=DE\nwarp=off\n";
        assert_eq!(parse_trace(body).as_deref(), Some("DE"));
        assert!(parse_trace("colo=FRA\nwarp=off\n").is_none());
    }
}

#[cfg(test)]
mod exit_tests {
    use super::*;

    const BODY: &str = "fl=117f35\nh=www.cloudflare.com\nip=104.28.246.167\nts=1\nvisit_scheme=http\ncolo=FRA\nloc=DE\nwarp=on\ngateway=off\n";

    #[test]
    fn every_field_worth_showing_is_read() {
        let exit = parse_exit(BODY, Duration::from_millis(42));
        assert_eq!(exit.address.as_deref(), Some("104.28.246.167"));
        assert_eq!(exit.country.as_deref(), Some("DE"));
        assert_eq!(exit.colo.as_deref(), Some("FRA"));
        assert!(exit.warp);
        assert_eq!(exit.rtt, Duration::from_millis(42));
    }

    #[test]
    fn the_line_reads_the_way_it_will_be_logged() {
        let exit = parse_exit(BODY, Duration::from_millis(42));
        assert_eq!(
            exit.describe(),
            "104.28.246.167, DE via FRA, 42ms to cloudflare, warp on"
        );
    }

    #[test]
    fn a_plain_exit_says_so_without_the_warp_note() {
        let body = "ip=1.2.3.4\ncolo=AMS\nloc=NL\nwarp=off\n";
        let exit = parse_exit(body, Duration::from_millis(7));
        assert!(!exit.warp);
        assert_eq!(exit.describe(), "1.2.3.4, NL via AMS, 7ms to cloudflare");
    }

    #[test]
    fn a_half_answer_still_makes_a_line() {
        let exit = parse_exit("loc=SE\n", Duration::from_millis(5));
        assert_eq!(exit.describe(), "SE, 5ms to cloudflare");
        let empty = parse_exit("", Duration::from_millis(1));
        assert_eq!(empty.describe(), "1ms to cloudflare");
    }
}

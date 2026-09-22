use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::Result;

const MOAT: &str = "https://bridges.torproject.org/moat/circumvention";
const ONIONOO: &str = "https://onionoo.torproject.org/details";
const TRACE: &str = "https://www.cloudflare.com/cdn-cgi/trace";
const CACHE_FILE: &str = "bridges.json";
const CACHE_MAX_AGE: Duration = Duration::from_secs(6 * 60 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(25);

const PREFERENCE: &[&str] = &["obfs4", "webtunnel", "snowflake", "meek_lite", "meek"];
const WORKED_FILE: &str = "bridges-worked.txt";

const EMBEDDED: &[&str] = &[
    "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn",
    "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn",
    "obfs4 146.57.248.225:22 10A6CD36A537FCE513A322361547444B393989F0 cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq/mtAjp1BIC9vHKJ2FAEpGssTPw iat-mode=0",
    "obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw iat-mode=0",
    "obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw iat-mode=0",
    "obfs4 212.83.43.74:443 39562501228A4D5E27FCA4C0C81A01EE23AE3EE4 cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw iat-mode=1",
    "obfs4 51.222.13.177:80 5EDAC3B810E12B01F6FD8050D2FD3E277B289A08 cert=2uplIpLQ0q9+0qMFrK5pkaYRDOe460LL9WHBvatgkuRr/SL31wBOEupaMMJ6koRE6Ld0ew iat-mode=0",
    "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
    "obfs4 212.83.43.95:443 BFE712113A72899AD685764B211FACD30FF52C31 cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg iat-mode=1",
    "meek_lite 192.0.2.20:80 url=https://1603026938.rsc.cdn77.org front=www.phpmyadmin.net utls=HelloRandomizedALPN",
];

const PT_BINARIES: &[(&str, &[&str])] = &[
    ("snowflake-client", &["snowflake"]),
    ("webtunnel-client", &["webtunnel"]),
    ("conjure-client", &["conjure"]),
    ("meek-client", &["meek", "meek_lite"]),
    (
        "lyrebird",
        &[
            "obfs4",
            "snowflake",
            "webtunnel",
            "meek_lite",
            "obfs3",
            "scramblesuit",
        ],
    ),
    (
        "obfs4proxy",
        &["obfs4", "obfs3", "obfs2", "scramblesuit", "meek_lite"],
    ),
];

const ASKABLE: &[&str] = &[
    "obfs4",
    "snowflake",
    "webtunnel",
    "conjure",
    "meek_lite",
    "meek",
    "obfs3",
    "obfs2",
    "scramblesuit",
];

const PROBE_TIMEOUT: Duration = Duration::from_secs(8);
const REACH_TIMEOUT: Duration = Duration::from_secs(6);
const KEEP_PER_TRANSPORT: usize = 6;
const UNTESTABLE: &[&str] = &["snowflake", "meek", "meek_lite", "conjure"];
const TOR_DESIGNATED_PORTS: &[u16] = &[9001, 9030, 9040, 9050, 9051, 9150];
const WEB_PORTS: &[u16] = &[80, 443];
const RELAYS_DEFAULT: usize = 40;

const SYSTEM_DIRS: &[&str] = &[
    "/usr/lib/tor/pluggable-transports",
    "/usr/lib64/tor/pluggable-transports",
    "/usr/libexec/tor/pluggable-transports",
    "/usr/local/lib/tor/pluggable-transports",
    "/usr/lib/tor-browser",
    "/opt/tor-browser/Browser/TorBrowser/Tor/PluggableTransports",
    "/usr/share/tor-browser/Browser/TorBrowser/Tor/PluggableTransports",
    "/Applications/Tor Browser.app/Contents/MacOS/Tor/PluggableTransports",
];

const HOME_DIRS: &[&str] = &[
    ".local/share/aether/pt",
    ".local/share/torbrowser/tbb/x86_64/tor-browser/Browser/TorBrowser/Tor/PluggableTransports",
    ".local/share/torbrowser/tbb/i686/tor-browser/Browser/TorBrowser/Tor/PluggableTransports",
    ".var/app/org.torproject.torbrowser-launcher/data/torbrowser/tbb/x86_64/tor-browser/Browser/TorBrowser/Tor/PluggableTransports",
    "tor-browser/Browser/TorBrowser/Tor/PluggableTransports",
    "Desktop/tor-browser/Browser/TorBrowser/Tor/PluggableTransports",
    "Downloads/tor-browser/Browser/TorBrowser/Tor/PluggableTransports",
    "Applications/Tor Browser.app/Contents/MacOS/Tor/PluggableTransports",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transport {
    pub protocols: Vec<String>,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub lines: Vec<String>,
    pub transports: Vec<Transport>,
    pub missing: Vec<String>,
    pub source: &'static str,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

#[derive(Serialize, Deserialize)]
struct Cached {
    fetched: u64,
    country: String,
    lines: Vec<String>,
}

#[derive(Deserialize)]
struct OnionooReply {
    #[serde(default)]
    relays: Vec<OnionooRelay>,
}

#[derive(Deserialize)]
struct OnionooRelay {
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    or_addresses: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct MoatReply {
    #[serde(default)]
    settings: Vec<MoatSetting>,
    #[serde(default)]
    country: String,
}

#[derive(Deserialize)]
struct MoatSetting {
    bridges: MoatBridges,
}

#[derive(Deserialize)]
struct MoatBridges {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    bridge_strings: Vec<String>,
}

pub fn transport_of(line: &str) -> Option<String> {
    let mut words = line.split_whitespace();
    let mut first = words.next()?;
    if first.eq_ignore_ascii_case("bridge") {
        first = words.next()?;
    }

    let head = first.chars().next()?;
    if head.is_ascii_digit() || head == '[' || first.contains('=') {
        return None;
    }

    Some(first.to_ascii_lowercase())
}

fn home() -> Option<PathBuf> {
    for name in ["HOME", "USERPROFILE"] {
        if let Some(value) = std::env::var(name).ok().filter(|v| !v.trim().is_empty()) {
            return Some(PathBuf::from(value));
        }
    }
    None
}

fn search_dirs() -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut dirs = Vec::new();
    let push = |dir: PathBuf, dirs: &mut Vec<PathBuf>, seen: &mut BTreeSet<PathBuf>| {
        if seen.insert(dir.clone()) {
            dirs.push(dir);
        }
    };

    if let Ok(extra) = std::env::var("AETHER_TOR_PT_DIR") {
        for part in extra.split(';') {
            for entry in std::env::split_paths(part) {
                if !entry.as_os_str().is_empty() {
                    push(entry, &mut dirs, &mut seen);
                }
            }
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(beside) = exe.parent() {
            push(beside.join("pt"), &mut dirs, &mut seen);
            push(beside.to_path_buf(), &mut dirs, &mut seen);
        }
    }

    if let Ok(path) = std::env::var("PATH") {
        for entry in std::env::split_paths(&path) {
            if !entry.as_os_str().is_empty() {
                push(entry, &mut dirs, &mut seen);
            }
        }
    }

    for entry in SYSTEM_DIRS {
        push(PathBuf::from(entry), &mut dirs, &mut seen);
    }

    if let Some(base) = home() {
        for entry in HOME_DIRS {
            push(base.join(entry), &mut dirs, &mut seen);
        }
    }

    if let Some(local) = std::env::var("LOCALAPPDATA").ok().filter(|v| !v.is_empty()) {
        let base = PathBuf::from(local);
        push(
            base.join("Programs/Tor Browser/Browser/TorBrowser/Tor/PluggableTransports"),
            &mut dirs,
            &mut seen,
        );
    }

    dirs
}

fn runnable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }

    #[cfg(not(unix))]
    {
        true
    }
}

fn locate(name: &str) -> Option<PathBuf> {
    let filenames: Vec<String> = if cfg!(windows) {
        vec![format!("{name}.exe"), name.to_string()]
    } else {
        vec![name.to_string()]
    };

    for dir in search_dirs() {
        for filename in &filenames {
            let candidate = dir.join(filename);
            if runnable(&candidate) {
                return Some(candidate);
            }
        }
    }

    None
}

fn methods_in(output: &str) -> Vec<String> {
    let mut found = Vec::new();

    for line in output.lines() {
        if let Some(rest) = line.trim().strip_prefix("CMETHOD ") {
            if let Some(name) = rest.split_whitespace().next() {
                let name = name.to_ascii_lowercase();
                if !found.contains(&name) {
                    found.push(name);
                }
            }
        }
    }

    found
}

fn ask(path: &Path) -> Option<Vec<String>> {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let state = std::env::temp_dir().join("aether-pt-probe");
    std::fs::create_dir_all(&state).ok()?;

    let mut child = Command::new(path)
        .env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
        .env("TOR_PT_STATE_LOCATION", &state)
        .env("TOR_PT_EXIT_ON_STDIN_CLOSE", "1")
        .env("TOR_PT_CLIENT_TRANSPORTS", ASKABLE.join(","))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let stdout = child.stdout.take()?;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut said = String::new();
        for line in BufReader::new(stdout).lines().map_while(|line| line.ok()) {
            let done = line.starts_with("CMETHODS DONE");
            said.push_str(&line);
            said.push('\n');
            if done {
                break;
            }
        }
        let _ = sender.send(said);
    });

    let said = receiver.recv_timeout(PROBE_TIMEOUT).ok();
    let _ = child.kill();
    let _ = child.wait();

    said.map(|said| methods_in(&said))
        .filter(|found| !found.is_empty())
}

pub fn discover_transports() -> Vec<Transport> {
    let mut claimed: BTreeSet<String> = BTreeSet::new();
    let mut found = Vec::new();

    for (binary, assumed) in PT_BINARIES {
        let Some(path) = locate(binary) else {
            continue;
        };

        let speaks = ask(&path).unwrap_or_else(|| {
            log::debug!("[*] {} did not answer, going by its name", path.display());
            assumed
                .iter()
                .map(|protocol| (*protocol).to_string())
                .collect()
        });

        let mine: Vec<String> = speaks
            .into_iter()
            .filter(|protocol| claimed.insert(protocol.clone()))
            .collect();

        if mine.is_empty() {
            continue;
        }

        found.push(Transport {
            protocols: mine,
            path,
        });
    }

    found
}

pub fn install_hint() -> &'static str {
    if cfg!(target_os = "windows") {
        "tor browser ships all of them and aether finds them there on its own; otherwise set \
         AETHER_TOR_PT_DIR to the folder holding lyrebird.exe and snowflake-client.exe"
    } else if cfg!(target_os = "macos") {
        "install one with `brew install lyrebird`, or install tor browser, which ships all of \
         them where aether looks"
    } else {
        "install one with `dnf install obfs4` on fedora, `apt install lyrebird \
         snowflake-client` on debian or ubuntu, `pacman -S obfs4proxy` on arch; tor browser \
         ships all of them and aether finds them there on its own"
    }
}

fn http_client(through: Option<std::net::SocketAddr>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent(crate::consts::UA_REGISTER)
        .timeout(REQUEST_TIMEOUT);

    match through {
        Some(proxy) => {
            log::info!("[*] fetching bridges through the tunnel on {proxy}");
            builder = builder.proxy(reqwest::Proxy::all(format!("socks5h://{proxy}")).map_err(
                |e| crate::error::AetherError::Other(format!("bridge fetch through {proxy}: {e}")),
            )?);
        }
        None => {
            if let Some(upstream) = crate::upstream::configured() {
                builder = builder.proxy(upstream.as_reqwest_proxy()?);
            }
        }
    }

    builder
        .build()
        .map_err(|e| crate::error::AetherError::Other(format!("bridge fetch: {e}")))
}

async fn detect_country(client: &reqwest::Client) -> Option<String> {
    if let Some(told) = std::env::var("AETHER_TOR_COUNTRY")
        .ok()
        .map(|code| code.trim().to_lowercase())
        .filter(|code| code.len() == 2)
    {
        return Some(told);
    }

    let body = client.get(TRACE).send().await.ok()?.text().await.ok()?;
    body.lines()
        .find_map(|line| line.strip_prefix("loc="))
        .map(|code| code.trim().to_lowercase())
        .filter(|code| code.len() == 2)
}

fn ordered(mut grouped: BTreeMap<String, Vec<String>>) -> Vec<String> {
    let mut lines = Vec::new();

    for wanted in PREFERENCE {
        if let Some(found) = grouped.remove(*wanted) {
            lines.extend(found);
        }
    }
    for (_, found) in grouped {
        lines.extend(found);
    }

    lines
}

async fn from_settings(client: &reqwest::Client, country: Option<&str>) -> Option<Vec<String>> {
    let body = match country {
        Some(code) => serde_json::json!({ "country": code }),
        None => serde_json::json!({}),
    };

    let reply: MoatReply = client
        .post(format!("{MOAT}/settings"))
        .header("Content-Type", "application/vnd.api+json")
        .json(&body)
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;

    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut order = Vec::new();
    for setting in reply.settings {
        if setting.bridges.bridge_strings.is_empty() {
            continue;
        }
        order.push(setting.bridges.kind.clone());
        grouped
            .entry(setting.bridges.kind)
            .or_default()
            .extend(setting.bridges.bridge_strings);
    }

    if grouped.is_empty() {
        return None;
    }

    log::info!(
        "[+] bridgedb answered for {} with {}",
        if reply.country.is_empty() {
            "this network"
        } else {
            &reply.country
        },
        order.join(", ")
    );

    let mut lines = Vec::new();
    for kind in order {
        if let Some(found) = grouped.remove(&kind) {
            lines.extend(found);
        }
    }

    Some(lines)
}

async fn from_builtin(client: &reqwest::Client) -> Option<Vec<String>> {
    let grouped: BTreeMap<String, Vec<String>> = client
        .get(format!("{MOAT}/builtin"))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;

    let lines = ordered(grouped);
    if lines.is_empty() {
        None
    } else {
        Some(lines)
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

fn read_cache(state: &Path) -> Option<Cached> {
    let raw = std::fs::read_to_string(state.join(CACHE_FILE)).ok()?;
    let cached: Cached = serde_json::from_str(&raw).ok()?;
    if cached.lines.is_empty() {
        None
    } else {
        Some(cached)
    }
}

fn write_cache(state: &Path, cached: &Cached) {
    let Ok(body) = serde_json::to_string_pretty(cached) else {
        return;
    };

    let path = state.join(CACHE_FILE);
    let temporary = state.join(format!("{CACHE_FILE}.new"));
    if std::fs::write(&temporary, body).is_err() {
        return;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600));
    }

    let _ = std::fs::rename(&temporary, &path);
}

fn dedup(lines: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    lines
        .into_iter()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .filter(|line| seen.insert(line.clone()))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relays {
    Off,
    Also(usize),
    Only(usize),
}

pub fn relay_policy() -> Relays {
    let raw = std::env::var("AETHER_TOR_RELAYS").unwrap_or_default();
    let spec = raw.trim().to_ascii_lowercase();

    match spec.as_str() {
        "off" | "no" | "0" | "false" | "none" => Relays::Off,
        "" | "auto" | "on" | "yes" | "true" => Relays::Also(RELAYS_DEFAULT),
        "only" | "relays" => Relays::Only(RELAYS_DEFAULT),
        _ => match spec.strip_prefix("only:").unwrap_or(&spec).parse::<usize>() {
            Ok(count) if count > 0 => {
                let count = count.min(400);
                if spec.starts_with("only") {
                    Relays::Only(count)
                } else {
                    Relays::Also(count)
                }
            }
            _ => Relays::Also(RELAYS_DEFAULT),
        },
    }
}

fn relay_ports_are_open() -> bool {
    std::env::var("AETHER_TOR_RELAY_PORTS")
        .map(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "any" | "all"))
        .unwrap_or(false)
}

pub fn relay_line(fingerprint: &str, address: &str, web_only: bool) -> Option<String> {
    let parsed: std::net::SocketAddr = address.parse().ok()?;
    let port = parsed.port();

    if TOR_DESIGNATED_PORTS.contains(&port) {
        return None;
    }
    if web_only && !WEB_PORTS.contains(&port) {
        return None;
    }

    let id = fingerprint.trim().to_ascii_uppercase();
    if id.len() != 40 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    Some(format!("{address} {id}"))
}

async fn from_relays(client: &reqwest::Client, want: usize) -> Option<Vec<String>> {
    let web_only = !relay_ports_are_open();

    log::info!(
        "[*] asking onionoo for running relays to use as plain bridges{}",
        if web_only { " on ports 80 and 443" } else { "" }
    );

    let answer = match client
        .get(ONIONOO)
        .query(&[
            ("type", "relay"),
            ("running", "true"),
            ("fields", "fingerprint,or_addresses"),
        ])
        .send()
        .await
    {
        Ok(answer) => answer,
        Err(e) => {
            log::warn!("[-] onionoo did not answer: {e}");
            return None;
        }
    };

    let reply = match answer.json::<OnionooReply>().await {
        Ok(reply) => reply,
        Err(e) => {
            log::warn!("[-] onionoo sent something unreadable: {e}");
            return None;
        }
    };

    let mut lines: Vec<String> = Vec::new();
    for relay in &reply.relays {
        let fingerprint = match &relay.fingerprint {
            Some(id) => id,
            None => continue,
        };
        for address in relay.or_addresses.iter().flatten() {
            if let Some(line) = relay_line(fingerprint, address, web_only) {
                lines.push(line);
            }
        }
    }

    if lines.is_empty() {
        log::warn!("[-] onionoo listed no relay that clears the port filter");
        return None;
    }

    let total = lines.len();
    shuffle(&mut lines);
    lines.truncate(want);

    log::info!(
        "[+] onionoo gave {total} usable relay address(es); trying {} of them",
        lines.len()
    );

    Some(lines)
}

pub async fn fetch(
    state: &Path,
    through: Option<std::net::SocketAddr>,
) -> (Vec<String>, &'static str) {
    log::info!(
        "[*] looking for bridges: bridgedb {}, onionoo relays {:?}",
        if matches!(relay_policy(), Relays::Only(_)) {
            "skipped"
        } else {
            "asked"
        },
        relay_policy()
    );

    let cached = read_cache(state);
    if let Some(fresh) = cached
        .as_ref()
        .filter(|entry| now().saturating_sub(entry.fetched) < CACHE_MAX_AGE.as_secs())
    {
        log::info!(
            "[*] reusing {} bridge(s) fetched earlier",
            fresh.lines.len()
        );
        return (fresh.lines.clone(), "cache");
    }

    let client = match http_client(through) {
        Ok(client) => client,
        Err(e) => {
            log::warn!("[-] cannot build a client to fetch bridges: {e}");
            return fallback(cached);
        }
    };

    let relays = relay_policy();
    let mut country = None;
    let mut lines = Vec::new();
    let mut source = "bridgedb";

    if let Relays::Only(_) = relays {
        source = "onionoo relays";
    } else {
        log::info!("[*] asking bridgedb for bridges");
        country = detect_country(&client).await;
        if let Some(code) = country.as_deref() {
            log::info!("[*] this network looks like it is in {code}");
        }

        if let Some(found) = from_settings(&client, country.as_deref()).await {
            lines.extend(found);
        }
        if let Some(found) = from_builtin(&client).await {
            lines.extend(found);
        }

        if lines.is_empty() {
            log::warn!("[-] bridgedb gave nothing back");
        }
    }

    match relays {
        Relays::Off => {}
        Relays::Also(want) | Relays::Only(want) => {
            if let Some(found) = from_relays(&client, want).await {
                if !lines.is_empty() {
                    source = "bridgedb and onionoo relays";
                } else {
                    source = "onionoo relays";
                }
                lines.extend(found);
            }
        }
    }

    let lines = dedup(lines);
    if lines.is_empty() {
        if through.is_none() {
            log::warn!(
                "[-] every bridge source is unreachable from here, which is what a network that \
                 blocks tor looks like. two ways past it: run --tor instead of --tor-only, which \
                 brings the tunnel up first and fetches bridges through it, or pass bridges you \
                 already have with --tor-bridge-file"
            );
        }
        return fallback(cached);
    }

    write_cache(
        state,
        &Cached {
            fetched: now(),
            country: country.unwrap_or_default(),
            lines: lines.clone(),
        },
    );

    log::info!("[+] {source} gave {} bridge(s)", lines.len());
    (lines, source)
}

fn fallback(cached: Option<Cached>) -> (Vec<String>, &'static str) {
    if let Some(stale) = cached {
        log::info!(
            "[*] falling back on {} bridge(s) from an earlier fetch",
            stale.lines.len()
        );
        return (stale.lines, "stale cache");
    }

    log::info!("[*] falling back on the bridges built into this binary");
    (
        EMBEDDED.iter().map(|line| (*line).to_string()).collect(),
        "built in",
    )
}

pub fn address_of(line: &str) -> Option<std::net::SocketAddr> {
    let mut words = line.split_whitespace();
    let mut first = words.next()?;
    if first.eq_ignore_ascii_case("bridge") {
        first = words.next()?;
    }

    let written = match transport_of(line) {
        None => first,
        Some(_) => words.next()?,
    };

    written.parse().ok()
}

async fn answers(address: std::net::SocketAddr) -> bool {
    matches!(
        tokio::time::timeout(REACH_TIMEOUT, crate::egress::tcp_connect(address)).await,
        Ok(Ok(_))
    )
}

pub async fn keep_reachable(
    lines: Vec<String>,
    through: Option<std::net::SocketAddr>,
) -> Vec<String> {
    if through.is_some() {
        log::info!(
            "[*] tor will dial its bridges through the tunnel, so they are not probed from here"
        );
        return lines;
    }

    let mut checks = Vec::new();

    for line in &lines {
        let skip =
            transport_of(line).is_some_and(|protocol| UNTESTABLE.contains(&protocol.as_str()));

        match address_of(line).filter(|_| !skip) {
            Some(address) => checks.push(Some(answers(address))),
            None => checks.push(None),
        }
    }

    let verdicts = futures::future::join_all(checks.into_iter().map(|check| async move {
        match check {
            Some(running) => running.await,
            None => true,
        }
    }))
    .await;

    let mut answered: BTreeMap<String, usize> = BTreeMap::new();
    let mut counted: BTreeMap<String, usize> = BTreeMap::new();
    for (line, alive) in lines.iter().zip(&verdicts) {
        let kind = transport_of(line).unwrap_or_else(|| "vanilla".to_string());
        *counted.entry(kind.clone()).or_default() += 1;
        if *alive {
            *answered.entry(kind).or_default() += 1;
        }
    }

    for (kind, total) in &counted {
        if answered.get(kind).copied().unwrap_or(0) == 0 {
            log::warn!(
                "[-] not one of the {total} {kind} bridge(s) answered a probe; keeping them all, \
                 since the probe may be the thing at fault"
            );
        }
    }

    let mut held: BTreeMap<String, usize> = BTreeMap::new();
    let mut kept = Vec::new();
    let mut dropped = 0usize;

    for (line, alive) in lines.into_iter().zip(verdicts) {
        let kind = transport_of(&line).unwrap_or_else(|| "vanilla".to_string());
        let all_quiet = answered.get(&kind).copied().unwrap_or(0) == 0;

        if !alive && !all_quiet {
            dropped += 1;
            continue;
        }

        let seen = held.entry(kind).or_default();
        if *seen >= KEEP_PER_TRANSPORT {
            continue;
        }
        *seen += 1;
        kept.push(line);
    }

    if dropped > 0 {
        log::info!("[*] {dropped} bridge(s) did not answer and were dropped");
    }

    kept
}

pub fn recall(state: &Path) -> Option<String> {
    std::fs::read_to_string(state.join(WORKED_FILE))
        .ok()
        .map(|name| name.trim().to_lowercase())
        .filter(|name| !name.is_empty())
}

pub fn remember(state: &Path, transport: &str) {
    let _ = std::fs::write(state.join(WORKED_FILE), transport);
}

pub fn shuffle(lines: &mut [String]) {
    use rand::RngExt;

    let mut rng = rand::rng();
    for place in (1..lines.len()).rev() {
        lines.swap(place, rng.random_range(0..=place));
    }
}

pub fn waves(plan: &Plan, first: Option<&str>) -> Vec<(String, Plan)> {
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in &plan.lines {
        let kind = transport_of(line).unwrap_or_else(|| "vanilla".to_string());
        grouped.entry(kind).or_default().push(line.clone());
    }

    if grouped.len() < 2 {
        return Vec::new();
    }

    let mut names: Vec<String> = grouped.keys().cloned().collect();
    names.sort_by_key(|name| {
        let known = PREFERENCE
            .iter()
            .position(|entry| entry == name)
            .unwrap_or(PREFERENCE.len());
        let tried = usize::from(!first.is_some_and(|worked| worked == name));
        (tried, known)
    });

    names
        .into_iter()
        .filter_map(|name| {
            let lines = grouped.remove(&name)?;
            let wanted: BTreeSet<String> = std::iter::once(name.clone()).collect();

            let mut transports: Vec<Transport> = plan
                .transports
                .iter()
                .filter(|held| {
                    held.protocols
                        .iter()
                        .any(|protocol| wanted.contains(protocol))
                })
                .cloned()
                .collect();
            for transport in &mut transports {
                transport
                    .protocols
                    .retain(|protocol| wanted.contains(protocol));
            }

            Some((
                name,
                Plan {
                    lines,
                    transports,
                    missing: Vec::new(),
                    source: plan.source,
                },
            ))
        })
        .collect()
}

pub fn plan(lines: Vec<String>, source: &'static str, extra: Vec<Transport>) -> Plan {
    plan_with(lines, source, extra, discover_transports())
}

pub fn plan_with(
    lines: Vec<String>,
    source: &'static str,
    extra: Vec<Transport>,
    found: Vec<Transport>,
) -> Plan {
    let mut transports = extra;
    let mut claimed: BTreeSet<String> = transports
        .iter()
        .flat_map(|transport| transport.protocols.iter().cloned())
        .collect();

    for one in found {
        let mine: Vec<String> = one
            .protocols
            .into_iter()
            .filter(|protocol| claimed.insert(protocol.clone()))
            .collect();
        if !mine.is_empty() {
            transports.push(Transport {
                protocols: mine,
                path: one.path,
            });
        }
    }

    let mut kept = Vec::new();
    let mut missing = BTreeSet::new();
    for line in lines {
        match transport_of(&line) {
            None => kept.push(line),
            Some(protocol) if claimed.contains(&protocol) => kept.push(line),
            Some(protocol) => {
                missing.insert(protocol);
            }
        }
    }

    let used: BTreeSet<String> = kept.iter().filter_map(|line| transport_of(line)).collect();
    transports.retain(|transport| transport.protocols.iter().any(|p| used.contains(p)));
    for transport in &mut transports {
        transport
            .protocols
            .retain(|protocol| used.contains(protocol));
    }

    Plan {
        lines: kept,
        transports,
        missing: missing.into_iter().collect(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bridge_line_names_the_transport_it_needs() {
        assert_eq!(
            transport_of("obfs4 1.2.3.4:443 ABCD cert=x"),
            Some("obfs4".to_string())
        );
        assert_eq!(
            transport_of("Bridge snowflake 192.0.2.3:80 2B28 url=https://example.test/"),
            Some("snowflake".to_string())
        );
        assert_eq!(
            transport_of("webtunnel [2001:db8::1]:443 ABCD"),
            Some("webtunnel".to_string())
        );
        assert_eq!(transport_of("1.2.3.4:443 ABCD"), None);
        assert_eq!(transport_of("Bridge 1.2.3.4:443 ABCD"), None);
        assert_eq!(transport_of("[2001:db8::1]:443 ABCD"), None);
        assert_eq!(transport_of(""), None);
    }

    #[test]
    fn a_bridge_is_dropped_when_nothing_can_speak_its_transport() {
        let lines = vec![
            "obfs4 1.2.3.4:443 AAAA cert=x".to_string(),
            "snowflake 192.0.2.3:80 BBBB url=https://example.test/".to_string(),
            "5.6.7.8:9001 CCCC".to_string(),
        ];
        let have = vec![Transport {
            protocols: vec!["obfs4".to_string()],
            path: PathBuf::from("/nowhere/lyrebird"),
        }];

        let plan = plan_with(lines, "test", have, Vec::new());
        assert_eq!(plan.lines.len(), 2);
        assert!(plan.lines.iter().any(|line| line.starts_with("obfs4")));
        assert!(plan.lines.iter().any(|line| line.starts_with("5.6.7.8")));
        assert_eq!(plan.missing, vec!["snowflake".to_string()]);
        assert_eq!(plan.transports.len(), 1);
        assert_eq!(plan.transports[0].protocols, vec!["obfs4".to_string()]);
    }

    #[test]
    fn a_transport_nobody_asked_for_is_not_launched() {
        let lines = vec!["5.6.7.8:9001 CCCC".to_string()];
        let have = vec![Transport {
            protocols: vec!["obfs4".to_string()],
            path: PathBuf::from("/nowhere/lyrebird"),
        }];

        let plan = plan_with(lines, "test", have, Vec::new());
        assert_eq!(plan.lines.len(), 1);
        assert!(plan.transports.is_empty());
        assert!(plan.missing.is_empty());
    }

    #[test]
    fn the_bridges_baked_into_the_binary_are_usable_lines() {
        assert!(!EMBEDDED.is_empty());
        for line in EMBEDDED {
            let protocol = transport_of(line).unwrap_or_else(|| panic!("{line}"));
            assert!(PREFERENCE.contains(&protocol.as_str()), "{protocol}");
        }
    }

    #[test]
    fn a_transport_binary_is_believed_when_it_lists_its_methods() {
        let said = "VERSION 1\n\
                    STATUS TYPE=version IMPLEMENTATION=\"lyrebird\" VERSION=\"devel\"\n\
                    CMETHOD obfs4 socks5 127.0.0.1:32927\n\
                    CMETHOD snowflake socks5 127.0.0.1:44461\n\
                    CMETHOD webtunnel socks5 127.0.0.1:42291\n\
                    CMETHODS DONE\n";

        assert_eq!(
            methods_in(said),
            vec![
                "obfs4".to_string(),
                "snowflake".to_string(),
                "webtunnel".to_string()
            ]
        );
        assert!(methods_in("VERSION 1\nCMETHODS DONE\n").is_empty());
    }

    #[test]
    fn the_preferred_transport_comes_first() {
        let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
        grouped.insert("obfs4".to_string(), vec!["obfs4 a".to_string()]);
        grouped.insert("snowflake".to_string(), vec!["snowflake b".to_string()]);
        grouped.insert("zzz".to_string(), vec!["zzz c".to_string()]);

        assert_eq!(
            ordered(grouped),
            vec![
                "obfs4 a".to_string(),
                "snowflake b".to_string(),
                "zzz c".to_string()
            ]
        );
    }
}

#[cfg(test)]
mod relay_tests {
    use super::*;

    #[test]
    fn the_obvious_tor_ports_are_left_out() {
        for port in TOR_DESIGNATED_PORTS {
            let address = format!("1.2.3.4:{port}");
            assert!(
                relay_line("A".repeat(40).as_str(), &address, false).is_none(),
                "port {port} is the first thing a censor blocks"
            );
        }
    }

    #[test]
    fn a_relay_that_looks_like_a_web_server_is_kept() {
        let id = "0".repeat(40);
        assert_eq!(
            relay_line(&id, "1.2.3.4:443", true),
            Some(format!("1.2.3.4:443 {id}"))
        );
        assert_eq!(
            relay_line(&id, "1.2.3.4:80", true),
            Some(format!("1.2.3.4:80 {id}"))
        );
    }

    #[test]
    fn an_odd_port_is_only_kept_when_the_filter_is_widened() {
        let id = "0".repeat(40);
        assert!(relay_line(&id, "1.2.3.4:8443", true).is_none());
        assert!(relay_line(&id, "1.2.3.4:8443", false).is_some());
    }

    #[test]
    fn an_ipv6_relay_parses_the_same_way() {
        let id = "a".repeat(40);
        let line = relay_line(&id, "[2001:db8::1]:443", true).expect("a line");
        assert!(line.starts_with("[2001:db8::1]:443 "));
        assert!(line.ends_with(&id.to_ascii_uppercase()));
    }

    #[test]
    fn a_relay_line_reads_back_as_a_plain_bridge() {
        let id = "b".repeat(40);
        let line = relay_line(&id, "1.2.3.4:443", true).expect("a line");
        assert_eq!(transport_of(&line), None);
        assert_eq!(address_of(&line), "1.2.3.4:443".parse().ok());
    }

    #[test]
    fn a_broken_fingerprint_is_refused() {
        assert!(relay_line("short", "1.2.3.4:443", true).is_none());
        assert!(relay_line(&"z".repeat(40), "1.2.3.4:443", true).is_none());
    }

    #[test]
    fn a_malformed_address_is_refused() {
        let id = "0".repeat(40);
        assert!(relay_line(&id, "not-an-address", true).is_none());
        assert!(relay_line(&id, "1.2.3.4", true).is_none());
    }
}

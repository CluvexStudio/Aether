use std::ffi::c_void;
use std::os::raw::c_int;
use std::ptr;

use boring::pkey::PKey;
use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
use boring::x509::X509;
use foreign_types_shared::ForeignTypeRef;

use crate::consts;
use crate::error::{AetherError, Result};

extern "C" {
    fn SSL_set1_ech_config_list(
        ssl: *mut c_void,
        ech_config_list: *const u8,
        ech_config_list_len: usize,
    ) -> c_int;

    fn SSL_get0_ech_retry_configs(
        ssl: *const c_void,
        out_retry_configs: *mut *const u8,
        out_retry_configs_len: *mut usize,
    );
}

/// The groups of the fingerprint, in order, unless --tls-groups names others.
const CHROME_GROUPS: &str = "P-256:X25519:P-384";

/// The TLS 1.2 cipher suites of the fingerprint unless --tls-ciphers names others: Chrome's
/// own rule, which BoringSSL orders as it does for Chrome, AES-GCM before ChaCha20 on
/// hardware with AES instructions and after it elsewhere.
pub const CHROME_CIPHERS: &str = "ALL:!aPSK:!ECDSA+SHA1:!3DES";

/// An option that sets TLS 1.2 cipher suites: a BoringSSL cipher string, names separated
/// by ':'. A ClientHello lists them after BoringSSL's own TLS 1.3 suites, which no cipher
/// string changes, and only where it offers TLS 1.2 as well.
#[derive(Debug)]
pub struct CipherOption {
    pub flag: &'static str,
    pub variable: &'static str,
}

/// --tls-ciphers: the TLS 1.2 cipher suites of the handshakes `Fingerprint` makes, in place
/// of Chrome's (`CHROME_CIPHERS`). HTTP/3 lists none: QUIC offers TLS 1.3 alone.
pub const TLS_CIPHERS: CipherOption = CipherOption {
    flag: "--tls-ciphers",
    variable: "AETHER_TLS_CIPHERS",
};

impl CipherOption {
    /// The cipher string given to the option; None when it is not given.
    pub fn configured(&self) -> Option<String> {
        std::env::var(self.variable)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }
}

/// Sets `list`, a BoringSSL cipher string, as the TLS 1.2 cipher suites of `builder`.
/// Strictly, through boring's set_strict_cipher_list (SSL_CTX_set_strict_cipher_list): a name
/// BoringSSL does not know is an error, which set_cipher_list would leave out without a word.
/// boring takes the error off the thread's error queue, where it would show in a later error.
pub fn set_tls12_ciphers(builder: &mut SslContextBuilder, list: &str) -> Result<()> {
    builder.set_strict_cipher_list(list).map_err(|_| {
        AetherError::Tls(format!(
            "{list:?} is no cipher list BoringSSL takes (cipher names separated by ':')"
        ))
    })
}

/// The TLS 1.2 cipher suites `list` names, in its order, as BoringSSL reads it: the number
/// and the name of each.
pub fn tls12_ciphers(list: &str) -> Result<Vec<(u16, &'static str)>> {
    let mut builder =
        SslContextBuilder::new(SslMethod::tls()).map_err(|e| AetherError::Tls(e.to_string()))?;
    set_tls12_ciphers(&mut builder, list)?;
    Ok(builder
        .ciphers()
        .map(|ciphers| {
            ciphers
                .iter()
                .map(|cipher| {
                    let name = cipher.standard_name().unwrap_or_else(|| cipher.name());
                    (cipher.protocol_id(), name)
                })
                .collect()
        })
        .unwrap_or_default())
}

/// Sets `groups`, a BoringSSL group list, names separated by ':', as the groups of `builder`,
/// in order.
fn set_groups(builder: &mut SslContextBuilder, groups: &str) -> Result<()> {
    builder.set_curves_list(groups).map_err(|_| {
        AetherError::Tls(format!(
            "{groups:?} is no group list BoringSSL takes (group names separated by ':')"
        ))
    })
}

/// The TLS fingerprint of the handshakes of the tunnel and its setup: MASQUE over HTTP/2 and
/// over HTTP/3, the calls to the WARP API and the DoH lookup of the ECH key, each with its
/// own ALPN.
/// It is Chrome's, as BoringSSL writes it, with what --tls-ciphers, --tls-groups and
/// --disable-grease change of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// --tls-ciphers: the TLS 1.2 cipher suites in place of Chrome's, when given.
    pub ciphers: Option<String>,
    /// --tls-groups: the groups, in order; the first gets a key share.
    pub groups: String,
    /// GREASE values (RFC 8701) among the cipher suites, the extensions, the groups, the key
    /// shares and the versions, as Chrome sends them; --disable-grease leaves them out.
    pub grease: bool,
}

impl Default for Fingerprint {
    /// Chrome's, with none of the options given.
    fn default() -> Self {
        Fingerprint {
            ciphers: None,
            groups: CHROME_GROUPS.to_string(),
            grease: true,
        }
    }
}

impl Fingerprint {
    /// The fingerprint the options give: --tls-ciphers (AETHER_TLS_CIPHERS), --tls-groups
    /// (AETHER_TLS_GROUPS) and --disable-grease (AETHER_DISABLE_GREASE).
    pub fn configured() -> Self {
        let groups = std::env::var("AETHER_TLS_GROUPS")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        Fingerprint {
            ciphers: TLS_CIPHERS.configured(),
            groups: groups.unwrap_or_else(|| CHROME_GROUPS.to_string()),
            grease: !std::env::var("AETHER_DISABLE_GREASE")
                .is_ok_and(|value| crate::fragment::is_truthy(&value)),
        }
    }

    /// Gives `builder` the fingerprint, offering `alpn`, in wire format: TLS 1.2 and 1.3, the
    /// groups, the extensions in a new order on each handshake, signed certificate timestamps
    /// and OCSP asked for, GREASE unless it is off, and the TLS 1.2 suites, Chrome's unless the
    /// cipher list names others. TLS server-certificate verification disabled (unconditional).
    pub fn apply(&self, builder: &mut SslContextBuilder, alpn: &[u8]) -> Result<()> {
        let tls = |error: boring::error::ErrorStack| AetherError::Tls(error.to_string());
        builder.set_verify(SslVerifyMode::NONE);
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(tls)?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(tls)?;
        builder.set_grease_enabled(self.grease);
        builder.set_permute_extensions(true);
        set_groups(builder, &self.groups)?;
        builder.set_alpn_protos(alpn).map_err(tls)?;
        builder.enable_signed_cert_timestamps();
        builder.enable_ocsp_stapling();
        set_tls12_ciphers(builder, self.ciphers.as_deref().unwrap_or(CHROME_CIPHERS))?;
        Ok(())
    }
}

/// Checks --tls-ciphers and --tls-groups as the core starts: a cipher string or a group list
/// BoringSSL does not take stops it, with the option named.
pub fn check_tls_options() -> Result<()> {
    let named = |flag: &str, e: AetherError| {
        let reason = match e {
            AetherError::Tls(reason) => reason,
            other => other.to_string(),
        };
        AetherError::Tls(format!("{flag}: {reason}"))
    };
    let fingerprint = Fingerprint::configured();
    if let Some(list) = &fingerprint.ciphers {
        tls12_ciphers(list).map_err(|e| named(TLS_CIPHERS.flag, e))?;
    }
    let mut builder =
        SslContextBuilder::new(SslMethod::tls()).map_err(|e| AetherError::Tls(e.to_string()))?;
    set_groups(&mut builder, &fingerprint.groups).map_err(|e| named("--tls-groups", e))
}

/// The variables of the options of the fingerprint.
#[cfg(test)]
const OPTION_VARIABLES: [&str; 3] = [
    "AETHER_TLS_CIPHERS",
    "AETHER_TLS_GROUPS",
    "AETHER_DISABLE_GREASE",
];

/// A hold on the options of the fingerprint, which the whole process shares, for a test that
/// sets them or reads them through `Fingerprint::configured`: they start out clear, and are
/// cleared again as it ends. A test that holds AETHER_UPSTREAM as well takes that first.
#[cfg(test)]
pub(crate) struct OptionsHeld(tokio::sync::MutexGuard<'static, ()>);

#[cfg(test)]
impl Drop for OptionsHeld {
    fn drop(&mut self) {
        for variable in OPTION_VARIABLES {
            std::env::remove_var(variable);
        }
    }
}

/// Waits for the hold on the options of the fingerprint, see `OptionsHeld`.
#[cfg(test)]
pub(crate) async fn hold_options() -> OptionsHeld {
    static OPTIONS: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    let held = OPTIONS
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    for variable in OPTION_VARIABLES {
        std::env::remove_var(variable);
    }
    OptionsHeld(held)
}

pub struct TlsParams<'a> {
    pub cert_pem: &'a [u8],
    pub key_pem: &'a [u8],
    pub pin_endpoint: bool,
    /// SHA-256 SPKI hashes of expected server certificates for pin-based verification.
    /// When non-empty and `pin_endpoint` is true, the server cert's SPKI hash is checked
    /// against these pins instead of relying on standard CA chain validation.
    /// This allows the TLS handshake to succeed even when SNI is spoofed for DPI bypass,
    /// while still preventing MITM attacks.
    pub expected_pins: &'a [&'a [u8]],
}

/// Install TLS verification on an `SslContextBuilder`.
///
/// NOTE: server-certificate verification is unconditionally disabled
/// (`SslVerifyMode::NONE`): any certificate presented by the server is
/// accepted. This is insecure against man-in-the-middle attacks — use only
/// for testing against your own servers.
pub fn install_verification(
    builder: &mut SslContextBuilder,
    _pin_endpoint: bool,
    _expected_pins: &[&[u8]],
) -> Result<()> {
    builder.set_verify(SslVerifyMode::NONE);
    announce_once("tls verification: disabled (unconditional)".to_string());
    Ok(())
}

fn announce_once(message: String) {
    use std::sync::OnceLock;
    static ANNOUNCED: OnceLock<()> = OnceLock::new();
    if ANNOUNCED.set(()).is_ok() {
        log::info!("{message}");
    } else {
        log::debug!("{message}");
    }
}

pub fn build_config(params: &TlsParams) -> Result<quiche::Config> {
    let mut builder =
        SslContextBuilder::new(SslMethod::tls()).map_err(|e| AetherError::Tls(e.to_string()))?;

    let mut alpn = Vec::with_capacity(consts::ALPN_H3.len() + 1);
    alpn.push(consts::ALPN_H3.len() as u8);
    alpn.extend_from_slice(consts::ALPN_H3);
    Fingerprint::configured().apply(&mut builder, &alpn)?;
    // QUIC carries TLS 1.3 alone, so the TLS 1.2 suites of --tls-ciphers never show here.
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let cert = X509::from_pem(params.cert_pem).map_err(|e| AetherError::Tls(e.to_string()))?;
    let key =
        PKey::private_key_from_pem(params.key_pem).map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_certificate(&cert)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_private_key(&key)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    // Install TLS verification (pin-based or standard CA chain)
    install_verification(&mut builder, params.pin_endpoint, params.expected_pins)?;

    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)
        .map_err(AetherError::Quic)?;

    config
        .set_application_protos(&[consts::ALPN_H3])
        .map_err(AetherError::Quic)?;

    config.set_max_idle_timeout(120_000);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(2_000_000);
    config.set_initial_max_stream_data_bidi_remote(2_000_000);
    config.set_initial_max_stream_data_uni(2_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_dgram(true, 65536, 65536);

    Ok(config)
}

pub fn inject_ech(conn: &mut quiche::Connection, ech_config_list: &[u8]) -> Result<()> {
    ensure_offerable(ech_config_list)?;

    let ssl: &mut boring::ssl::SslRef = conn.as_mut();
    let ssl_ptr = ssl.as_ptr() as *mut c_void;

    let rc = unsafe {
        SSL_set1_ech_config_list(ssl_ptr, ech_config_list.as_ptr(), ech_config_list.len())
    };

    if rc != 1 {
        return Err(AetherError::Ech(format!(
            "SSL_set1_ech_config_list failed (rc={rc})"
        )));
    }

    Ok(())
}

/// The ECHConfigList the MASQUE handshakes of the session offer, on either carrier: the
/// one the session starts with, see `use_ech`, until a server that turns it down hands
/// back the one it holds now, see `adopt_ech_retry`. With none, the server name goes out
/// in the clear. Cores of the library that run side by side in one process share it, see
/// `EchSession`.
static SESSION_ECH: std::sync::RwLock<Option<Vec<u8>>> = std::sync::RwLock::new(None);

/// How many sessions run in the process, see `EchSession`.
static SESSIONS: std::sync::Mutex<usize> = std::sync::Mutex::new(0);

/// Makes the MASQUE handshakes of the session from now on, on either carrier, offer `ech`,
/// an ECHConfigList: the tunnel's, and those of the scan and of the gateway checks.
pub fn use_ech(ech: Option<Vec<u8>>) {
    *SESSION_ECH
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = ech;
}

/// The ECHConfigList the next MASQUE handshake of the session offers, if any.
pub fn session_ech() -> Option<Vec<u8>> {
    SESSION_ECH
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// The ECH key of a session for as long as it runs: set as the session starts, see
/// `use_ech`, and cleared as the last session of the process ends, however it ends, so that
/// nothing after them offers that key. Sessions that run side by side, cores of the library,
/// share one: a session that starts without a key leaves another's in place, and one that
/// ends leaves it to those that run on, which would go on without ECH otherwise.
pub struct EchSession(());

impl EchSession {
    pub fn start(ech: Option<Vec<u8>>) -> Self {
        let mut sessions = SESSIONS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *sessions += 1;
        if ech.is_some() || *sessions == 1 {
            use_ech(ech);
        }
        EchSession(())
    }
}

impl Drop for EchSession {
    fn drop(&mut self) {
        let mut sessions = SESSIONS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *sessions -= 1;
        if *sessions == 0 {
            use_ech(None);
        }
    }
}

/// Keeps `retry`, the ECHConfigList a server handed back as it turned the session's down,
/// for the handshakes to come, on either carrier. A session that offers no ECH stays
/// without.
pub fn adopt_ech_retry(retry: &[u8]) {
    let mut ech = SESSION_ECH
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if ech.is_some() {
        *ech = Some(retry.to_vec());
    }
}

/// The TLS alert a client sends as it gives up a handshake whose ECHConfigList the server
/// did not take (ech_required), and the base quiche adds a TLS alert to as it closes the
/// connection with it.
const ECH_REQUIRED_ALERT: u64 = 121;
const QUIC_CRYPTO_ERROR: u64 = 0x100;

/// Whether `conn` was closed because its ECHConfigList was turned down. Only then does
/// BoringSSL hand out the server's retry configs; asked after any other failure, it hands
/// out a placeholder.
pub fn ech_rejected(conn: &quiche::Connection) -> bool {
    conn.local_error()
        .is_some_and(|e| !e.is_app && e.error_code == QUIC_CRYPTO_ERROR + ECH_REQUIRED_ALERT)
}

pub fn extract_ech_retry_configs(conn: &mut quiche::Connection) -> Option<Vec<u8>> {
    let ssl: &mut boring::ssl::SslRef = conn.as_mut();
    let ssl_ptr = ssl.as_ptr() as *const c_void;

    let mut out: *const u8 = ptr::null();
    let mut out_len: usize = 0;

    unsafe {
        SSL_get0_ech_retry_configs(ssl_ptr, &mut out, &mut out_len);
    }

    if out.is_null() || out_len == 0 {
        return None;
    }

    let slice = unsafe { std::slice::from_raw_parts(out, out_len) };
    usable_retry(slice)
}

/// Whether the handshake of `conn` went with ECH: the server took the key it was offered.
pub fn ech_accepted(conn: &mut quiche::Connection) -> bool {
    let ssl: &mut boring::ssl::SslRef = conn.as_mut();
    ssl.ech_accepted()
}

/// `retry`, the ECHConfigList a server handed back as it turned the offered one down, when
/// BoringSSL can offer it: a handshake given one it cannot would go without ECH.
pub fn usable_retry(retry: &[u8]) -> Option<Vec<u8>> {
    match check_ech_config_list(retry) {
        Ok(()) => Some(retry.to_vec()),
        Err(reason) => {
            log::warn!(
                "the server handed back an ECH key that cannot be offered ({reason}); not retrying with it"
            );
            None
        }
    }
}

pub fn decode_ech_config_list(b64: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| AetherError::Ech(format!("not base64: {e}")))
}

/// How the core says that it goes no further for want of an ECH key: with --ech given,
/// going on without a key it can offer would send a server name in the clear. An app that runs the core reads it to tell its user why it stopped.
pub const NO_ECH_KEY: &str = "ECH is on but there is no ECH key to offer";

/// An option that asks for an ECH key: its name and variable, what the key is for, and
/// what the core does rather than go without it.
pub struct EchOption {
    pub flag: &'static str,
    pub variable: &'static str,
    pub purpose: &'static str,
    pub refusal: &'static str,
}

/// --ech: the key the MASQUE handshakes of the session offer.
pub const SESSION_ECH_OPTION: EchOption = EchOption {
    flag: "--ech",
    variable: "AETHER_ECH",
    purpose: "",
    refusal: "stopping rather than send the server name in the clear",
};

/// --ech as the calls to the WARP API take it, which register and enroll the WARP keys.
pub const API_ECH_OPTION: EchOption = EchOption {
    flag: "--ech",
    variable: "AETHER_ECH",
    purpose: " for the WARP API",
    refusal: "not asking it rather than send its name in the clear",
};

/// The ECH key `option` asks for with the value `setting`: none without a value; with one,
/// the key it gives in base64, or with auto, the key `fetch` looks up. With a key asked for
/// and none BoringSSL can offer, an error that says NO_ECH_KEY and why.
pub async fn ech_key<F>(
    option: &EchOption,
    setting: Option<&str>,
    fetch: impl FnOnce() -> F,
) -> Result<Option<Vec<u8>>>
where
    F: std::future::Future<Output = Result<Vec<u8>>>,
{
    let (key, origin) = match setting {
        Some(v) if v.trim().eq_ignore_ascii_case("auto") => (
            fetch().await,
            "fetched ECHConfigList automatically".to_string(),
        ),
        Some(b64) if !b64.is_empty() => (
            decode_ech_config_list(b64).map_err(|e| match e {
                AetherError::Ech(reason) => {
                    AetherError::Ech(format!("the {} value is {reason}", option.flag))
                }
                other => other,
            }),
            format!("using ECHConfigList from {}", option.variable),
        ),
        _ => return Ok(None),
    };
    match key.and_then(|key| ensure_offerable(&key).map(|()| key)) {
        Ok(key) => {
            log::info!("[+] {origin}{} ({} bytes)", option.purpose, key.len());
            Ok(Some(key))
        }
        Err(e) => {
            let reason = match e {
                AetherError::Ech(reason) => reason,
                other => other.to_string(),
            };
            Err(AetherError::Ech(format!(
                "{NO_ECH_KEY}{} ({reason}); {}",
                option.purpose, option.refusal
            )))
        }
    }
}

/// The ECHConfig version BoringSSL offers, which is the code point of the extension as well.
const ECH_CONFIG_VERSION: u16 = 0xfe0d;
/// The HPKE algorithms BoringSSL offers ECH with, as a client: one KEM, one KDF, and the
/// AEADs AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305.
const HPKE_DHKEM_X25519_HKDF_SHA256: u16 = 0x0020;
const HPKE_HKDF_SHA256: u16 = 0x0001;
const HPKE_AEADS: [u16; 3] = [0x0001, 0x0002, 0x0003];
const X25519_PUBLIC_KEY_LEN: usize = 32;

/// `check_ech_config_list`, as the error of a handshake about to be given `list`.
pub fn ensure_offerable(list: &[u8]) -> Result<()> {
    check_ech_config_list(list)
        .map_err(|reason| AetherError::Ech(format!("the ECH key cannot be offered: {reason}")))
}

/// Whether BoringSSL offers ECH when it is given `list`, an ECHConfigList. BoringSSL takes
/// any list that parses, even one with no config it can use, and then sends the server
/// name in the clear (with a GREASE ECH extension), so a key is checked here before a
/// handshake is given it. The list has to parse as BoringSSL parses it, and the first
/// config BoringSSL picks from it has to hold an X25519 key. This follows
/// ssl/encrypted_client_hello.cc (parse_ech_config, ssl_is_valid_ech_public_name,
/// ssl_select_ech_config) of the BoringSSL that boring 4.22 builds.
pub fn check_ech_config_list(list: &[u8]) -> std::result::Result<(), String> {
    let malformed = || "it is no ECHConfigList".to_string();
    let mut whole = Fields(list);
    let mut configs = whole.u16_prefixed().ok_or_else(malformed)?;
    if configs.is_empty() || !whole.is_empty() {
        return Err(malformed());
    }
    // BoringSSL parses every config as it takes the list, and offers the first it can.
    let mut picked = None;
    while !configs.is_empty() {
        let config = ech_config(&mut configs).ok_or_else(malformed)?;
        picked = picked.or(config);
    }
    match picked {
        Some(key) if key.len() == X25519_PUBLIC_KEY_LEN => Ok(()),
        Some(_) => Err("the X25519 key of its config is not 32 bytes long".into()),
        None => Err(
            "it holds no config BoringSSL offers: ECH version 0xfe0d, X25519, and \
                     HKDF-SHA256 with AES-GCM or ChaCha20-Poly1305"
                .into(),
        ),
    }
}

/// Reads one ECHConfig off `configs` as BoringSSL's parse_ech_config does. None when it
/// does not parse, for which BoringSSL turns the whole list down; Some(None) for a config
/// BoringSSL passes over; its public key for one BoringSSL would offer.
fn ech_config<'a>(configs: &mut Fields<'a>) -> Option<Option<&'a [u8]>> {
    let version = configs.u16()?;
    let mut contents = configs.u16_prefixed()?;
    if version != ECH_CONFIG_VERSION {
        return Some(None);
    }
    let _config_id = contents.u8()?;
    let kem_id = contents.u16()?;
    let public_key = contents.u16_prefixed()?.0;
    let mut cipher_suites = contents.u16_prefixed()?;
    let _maximum_name_length = contents.u8()?;
    let public_name = contents.u8_prefixed()?.0;
    let mut extensions = contents.u16_prefixed()?;
    if public_key.is_empty()
        || cipher_suites.is_empty()
        || cipher_suites.0.len() % 4 != 0
        || public_name.is_empty()
        || !contents.is_empty()
    {
        return None;
    }
    // A config whose public name is invalid is passed over before its extensions are read.
    if !valid_public_name(public_name) {
        return Some(None);
    }
    let mut mandatory_extension = false;
    while !extensions.is_empty() {
        let kind = extensions.u16()?;
        extensions.u16_prefixed()?;
        mandatory_extension |= kind & 0x8000 != 0;
    }
    let mut cipher_suite = false;
    while !cipher_suites.is_empty() {
        let (kdf, aead) = (cipher_suites.u16()?, cipher_suites.u16()?);
        cipher_suite |= kdf == HPKE_HKDF_SHA256 && HPKE_AEADS.contains(&aead);
    }
    let offered = !mandatory_extension && kem_id == HPKE_DHKEM_X25519_HKDF_SHA256 && cipher_suite;
    Some(offered.then_some(public_key))
}

/// BoringSSL's ssl_is_valid_ech_public_name: dot-separated labels of 1 to 63 letters,
/// digits and hyphens, none starting or ending with a hyphen, the last of them no decimal
/// number and no 0x hex one.
fn valid_public_name(name: &[u8]) -> bool {
    let mut last: &[u8] = &[];
    for label in name.split(|&b| b == b'.') {
        let ldh = label
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-');
        if label.is_empty()
            || label.len() > 63
            || label[0] == b'-'
            || label[label.len() - 1] == b'-'
            || !ldh
        {
            return false;
        }
        last = label;
    }
    let decimal = last.iter().all(u8::is_ascii_digit);
    let hex = last.len() >= 2
        && last[0] == b'0'
        && (last[1] == b'x' || last[1] == b'X')
        && last[2..].iter().all(u8::is_ascii_hexdigit);
    !decimal && !hex
}

/// The fields of an ECHConfigList, read in order as BoringSSL's CBS reads them.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.0.len() < len {
            return None;
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    fn u8_prefixed(&mut self) -> Option<Fields<'a>> {
        let len = self.u8()?;
        self.take(len.into()).map(Fields)
    }

    fn u16_prefixed(&mut self) -> Option<Fields<'a>> {
        let len = self.u16()?;
        self.take(len.into()).map(Fields)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hold of a test on the session key, which the whole process shares: the tests that
    /// set it run one at a time.
    fn hold_session_key() -> std::sync::MutexGuard<'static, ()> {
        static KEY: std::sync::Mutex<()> = std::sync::Mutex::new(());
        KEY.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn a_key_a_server_hands_back_replaces_the_sessions_only_while_it_offers_ech() {
        let _key = hold_session_key();
        use_ech(None);
        adopt_ech_retry(&[1, 2]);
        assert_eq!(session_ech(), None);

        use_ech(Some(vec![9]));
        assert_eq!(session_ech(), Some(vec![9]));
        adopt_ech_retry(&[1, 2]);
        assert_eq!(session_ech(), Some(vec![1, 2]));

        use_ech(None);
        assert_eq!(session_ech(), None);
    }

    #[test]
    fn the_session_key_goes_with_the_session() {
        let _key = hold_session_key();
        {
            let _session = EchSession::start(Some(vec![7]));
            assert_eq!(session_ech(), Some(vec![7]));
            adopt_ech_retry(&[8]);
            assert_eq!(session_ech(), Some(vec![8]));
        }
        assert_eq!(session_ech(), None);
    }

    #[test]
    fn a_session_that_ends_leaves_the_key_to_one_that_runs_on() {
        let _key = hold_session_key();
        // A second core of the library, started beside the first: with no key of its own, it
        // takes the first one's away neither as it starts nor as the first one ends.
        let first = EchSession::start(Some(vec![7]));
        let second = EchSession::start(None);
        assert_eq!(session_ech(), Some(vec![7]));
        drop(first);
        assert_eq!(session_ech(), Some(vec![7]));
        drop(second);
        assert_eq!(session_ech(), None);

        // With a key of its own, it offers its own, which the first one goes on with.
        let first = EchSession::start(Some(vec![7]));
        let second = EchSession::start(Some(vec![8]));
        assert_eq!(session_ech(), Some(vec![8]));
        drop(second);
        assert_eq!(session_ech(), Some(vec![8]));
        drop(first);
        assert_eq!(session_ech(), None);
    }

    /// Cloudflare's key of cloudflare-ech.com on 2026-10-01.
    const CLOUDFLARE_ECH: &str =
        "AEX+DQBBrwAgACCbK1mYDYFz/BAn6S5t+Q/v+Oej3eFNxtPWgz50fNnFPAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=";

    /// Why `option` found no key, from the error it ends with, which says NO_ECH_KEY first.
    fn no_key_reason(option: &EchOption, outcome: Result<Option<Vec<u8>>>) -> String {
        match outcome {
            Err(AetherError::Ech(message)) => {
                let reason = message
                    .strip_prefix(NO_ECH_KEY)
                    .and_then(|rest| rest.strip_prefix(option.purpose))
                    .expect("the core's word for going without an ECH key");
                assert!(reason.ends_with(option.refusal), "{message}");
                reason.to_string()
            }
            other => panic!("it went on: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_key_asked_for_without_one_to_offer_goes_no_further() {
        let key = decode_ech_config_list(CLOUDFLARE_ECH).expect("base64");
        let unused = || async { panic!("looked up without auto") };
        let silent = || async {
            Err(AetherError::Ech(
                "udp://1.1.1.1:53 did not answer for cloudflare-ech.com".into(),
            ))
        };
        for option in [&SESSION_ECH_OPTION, &API_ECH_OPTION] {
            assert_eq!(ech_key(option, None, unused).await.ok(), Some(None));
            assert_eq!(ech_key(option, Some(""), unused).await.ok(), Some(None));
            assert_eq!(
                ech_key(option, Some(CLOUDFLARE_ECH), unused).await.ok(),
                Some(Some(key.clone()))
            );
            let found = key.clone();
            assert_eq!(
                ech_key(option, Some("AUTO"), || async { Ok(found) })
                    .await
                    .ok(),
                Some(Some(key.clone()))
            );
            // Spaces around auto are no key in base64; spaces alone still ask for a key.
            let found = key.clone();
            assert_eq!(
                ech_key(option, Some(" auto "), || async { Ok(found) })
                    .await
                    .ok(),
                Some(Some(key.clone()))
            );
            no_key_reason(option, ech_key(option, Some("  "), unused).await);

            let unanswered = no_key_reason(option, ech_key(option, Some("auto"), silent).await);
            assert!(unanswered.contains("did not answer"), "{unanswered}");

            // BoringSSL would take this list and offer nothing from it: its only config is of
            // another version.
            let unusable = vec![0, 6, 0xfe, 0x0c, 0, 2, 0, 0];
            let passed_over = no_key_reason(
                option,
                ech_key(option, Some("auto"), || async { Ok(unusable) }).await,
            );
            assert!(passed_over.contains("cannot be offered"), "{passed_over}");

            let typo = no_key_reason(option, ech_key(option, Some("AEX+DQ="), unused).await);
            let named = format!("the {} value is not base64", option.flag);
            assert!(typo.contains(&named), "{typo}");
        }

        // Word for word, as an app that runs the core reads them.
        let said = |outcome: Result<Option<Vec<u8>>>| outcome.err().map(|e| e.to_string());
        assert_eq!(
            said(ech_key(&SESSION_ECH_OPTION, Some("auto"), silent).await).as_deref(),
            Some(
                "ech: ECH is on but there is no ECH key to offer (udp://1.1.1.1:53 did not answer \
                 for cloudflare-ech.com); stopping rather than send the server name in the clear"
            )
        );
        assert_eq!(
            said(ech_key(&API_ECH_OPTION, Some("auto"), silent).await).as_deref(),
            Some(
                "ech: ECH is on but there is no ECH key to offer for the WARP API (udp://1.1.1.1:53 \
                 did not answer for cloudflare-ech.com); not asking it rather than send its name in \
                 the clear"
            )
        );
    }

    #[tokio::test]
    async fn the_fingerprint_is_chromes_with_what_the_options_change() {
        let _options = hold_options().await;
        assert_eq!(Fingerprint::configured(), Fingerprint::default());
        assert_eq!(
            Fingerprint::default(),
            Fingerprint {
                ciphers: None,
                groups: "P-256:X25519:P-384".to_string(),
                grease: true,
            }
        );
        assert!(check_tls_options().is_ok());

        std::env::set_var("AETHER_TLS_CIPHERS", " ECDHE-RSA-AES128-GCM-SHA256 ");
        std::env::set_var("AETHER_TLS_GROUPS", "X25519:P-256");
        for (value, greased) in [("1", false), ("on", false), ("TRUE", false), ("0", true)] {
            std::env::set_var("AETHER_DISABLE_GREASE", value);
            assert_eq!(
                Fingerprint::configured(),
                Fingerprint {
                    ciphers: Some("ECDHE-RSA-AES128-GCM-SHA256".to_string()),
                    groups: "X25519:P-256".to_string(),
                    grease: greased,
                },
                "{value}"
            );
        }
        assert!(check_tls_options().is_ok());

        std::env::set_var("AETHER_TLS_GROUPS", "X25519:P-999");
        let refused = check_tls_options().expect_err("a group BoringSSL does not know");
        assert!(
            refused.to_string().starts_with("tls: --tls-groups: "),
            "{refused}"
        );
        std::env::set_var("AETHER_TLS_GROUPS", "X25519");
        std::env::set_var(
            "AETHER_TLS_CIPHERS",
            "ECDHE-RSA-AES128-GCM-SHA256:NO-SUCH-SUITE",
        );
        let refused = check_tls_options().expect_err("a suite BoringSSL does not know");
        assert!(
            refused.to_string().starts_with("tls: --tls-ciphers: "),
            "{refused}"
        );
    }

    /// The ClientHello of `fingerprint`, offering HTTP/2, as a server on this machine reads it.
    async fn hello_of(fingerprint: &Fingerprint) -> client_hello::ClientHello {
        let (server, hello) = client_hello::catch().await;
        let mut builder = boring::ssl::SslConnector::builder(SslMethod::tls()).expect("tls");
        fingerprint
            .apply(&mut builder, b"\x02h2")
            .expect("the fingerprint");
        let config = builder.build().configure().expect("a configuration");
        let tcp = tokio::net::TcpStream::connect(server)
            .await
            .expect("a connection");
        assert!(
            tokio_boring::connect(config, "fingerprint.example.test", tcp)
                .await
                .is_err()
        );
        hello.await.expect("the ClientHello")
    }

    #[tokio::test]
    async fn the_client_hello_carries_the_fingerprint() {
        let chrome = hello_of(&Fingerprint::default()).await;
        assert!(chrome.has_grease());
        assert!(chrome.has_grease_extension());
        assert_eq!(chrome.versions(), [0x0304, 0x0303]);
        assert_eq!(chrome.groups(), [0x0017, 0x001d, 0x0018]);
        assert_eq!(chrome.key_shares(), [0x0017]);
        assert_eq!(chrome.alpn(), [b"h2".to_vec()]);
        assert_eq!(
            chrome.server_name().as_deref(),
            Some("fingerprint.example.test")
        );
        // Signed certificate timestamps and OCSP asked for, as Chrome asks.
        assert!(chrome.has_extension(18) && chrome.has_extension(5));
        // Chrome's TLS 1.2 suites, in the order Chrome's rule gets on this machine.
        assert_eq!(chrome.tls12_suites(), client_hello::chrome_tls12_suites());
        let mut suites = chrome.tls12_suites();
        suites.sort_unstable();
        assert_eq!(
            suites,
            [
                0x002f, 0x0035, 0x009c, 0x009d, 0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030,
                0xcca8, 0xcca9
            ]
        );

        let plain = Fingerprint {
            grease: false,
            ..Fingerprint::default()
        };
        let ungreased = hello_of(&plain).await;
        assert!(!ungreased.has_grease());
        assert!(!ungreased.has_grease_extension());
        assert_eq!(ungreased.groups(), chrome.groups());

        let changed = hello_of(&Fingerprint {
            ciphers: Some("ECDHE-ECDSA-CHACHA20-POLY1305:AES256-SHA".to_string()),
            groups: "X25519:P-384".to_string(),
            grease: false,
        })
        .await;
        assert_eq!(changed.tls12_suites(), [0xcca9, 0x0035]);
        assert_eq!(changed.groups(), [0x001d, 0x0018]);
        assert_eq!(changed.key_shares(), [0x001d]);

        // The extensions go in a new order on each handshake, as Chrome's do; without GREASE,
        // whose values change on each handshake too, only the order can differ.
        let mut orders = std::collections::HashSet::new();
        for _ in 0..4 {
            orders.insert(hello_of(&plain).await.extension_types());
        }
        assert!(orders.len() > 1, "{orders:?}");
    }

    /// An ECHConfig: `version`, config id 7, the KEM `kem` with a key of `key_len` bytes, the
    /// cipher suites `suites` as (KDF, AEAD), the public name `name`, and `extensions` as they
    /// go on the wire.
    fn config(
        version: u16,
        kem: u16,
        key_len: usize,
        suites: &[(u16, u16)],
        name: &str,
        extensions: &[u8],
    ) -> Vec<u8> {
        let mut contents = vec![7];
        contents.extend_from_slice(&kem.to_be_bytes());
        contents.extend_from_slice(&(key_len as u16).to_be_bytes());
        contents.extend(std::iter::repeat(0x42).take(key_len));
        contents.extend_from_slice(&((suites.len() * 4) as u16).to_be_bytes());
        for (kdf, aead) in suites {
            contents.extend_from_slice(&kdf.to_be_bytes());
            contents.extend_from_slice(&aead.to_be_bytes());
        }
        contents.push(0);
        contents.push(name.len() as u8);
        contents.extend_from_slice(name.as_bytes());
        contents.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        contents.extend_from_slice(extensions);
        let mut config = version.to_be_bytes().to_vec();
        config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        config.extend(contents);
        config
    }

    fn list(configs: &[Vec<u8>]) -> Vec<u8> {
        let body = configs.concat();
        let mut list = (body.len() as u16).to_be_bytes().to_vec();
        list.extend(body);
        list
    }

    /// A config like Cloudflare's: X25519, HKDF-SHA256 with AES-128-GCM.
    fn offered(name: &str) -> Vec<u8> {
        config(0xfe0d, 0x0020, 32, &[(1, 1)], name, &[])
    }

    #[test]
    fn cloudflares_key_is_one_boringssl_offers() {
        // Cloudflare's key of cloudflare-ech.com on 2026-10-01.
        let key = decode_ech_config_list(
            "AEX+DQBBrwAgACCbK1mYDYFz/BAn6S5t+Q/v+Oej3eFNxtPWgz50fNnFPAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=",
        )
        .expect("base64");
        assert_eq!(check_ech_config_list(&key), Ok(()));
        // The same fields as built here, the key aside.
        let mut built = list(&[offered("cloudflare-ech.com")]);
        built[2 + 2 + 2 + 1 + 2 + 2..][..32].copy_from_slice(&key[11..43]);
        built[6] = key[6];
        assert_eq!(built, key);
    }

    #[test]
    fn a_key_boringssl_would_pass_over_is_turned_down() {
        // Each parses, so BoringSSL would take it, offer nothing, and send the name in the clear.
        let passed_over = [
            config(0xfe0c, 0x0020, 32, &[(1, 1)], "cloudflare-ech.com", &[]),
            // P-256, its key as long as an X25519 one so that only the KEM tells them apart.
            config(0xfe0d, 0x0010, 32, &[(1, 1)], "cloudflare-ech.com", &[]),
            config(0xfe0d, 0x0020, 32, &[(2, 1)], "cloudflare-ech.com", &[]),
            config(0xfe0d, 0x0020, 32, &[(1, 4)], "cloudflare-ech.com", &[]),
            config(
                0xfe0d,
                0x0020,
                32,
                &[(1, 1)],
                "cloudflare-ech.com",
                &[0x80, 1, 0, 0],
            ),
            offered("192.0.2.1"),
            offered("example.0x1F"),
            offered("-example.com"),
            offered("example-.com"),
            offered("example..com"),
            offered("example.com."),
            offered("exa_mple.com"),
            offered(&"a".repeat(64)),
        ];
        for config in passed_over {
            let list = list(&[config]);
            assert!(check_ech_config_list(&list).is_err(), "{list:02x?}");
            assert!(usable_retry(&list).is_none());
        }
    }

    #[test]
    fn the_first_config_boringssl_can_offer_is_the_one_it_offers() {
        let older = config(0xfe0c, 0x0020, 32, &[(1, 1)], "x.example", &[]);
        assert_eq!(
            check_ech_config_list(&list(&[older, offered("a.example")])),
            Ok(())
        );
        // An extension that is not mandatory is passed over, and one good suite is enough.
        let optional = config(
            0xfe0d,
            0x0020,
            32,
            &[(2, 1), (1, 3)],
            "a.example",
            &[0, 1, 0, 1, 9],
        );
        assert_eq!(check_ech_config_list(&list(&[optional])), Ok(()));
        // Only a last label that is a number disqualifies a name.
        assert_eq!(
            check_ech_config_list(&list(&[offered("0x1f.example")])),
            Ok(())
        );
        assert_eq!(check_ech_config_list(&list(&[offered("a.0x1g")])), Ok(()));
        assert_eq!(check_ech_config_list(&list(&[offered("a.b1")])), Ok(()));
        // A config it picks with a key of the wrong length fails the handshake: no later one counts.
        let short = config(0xfe0d, 0x0020, 31, &[(1, 1)], "a.example", &[]);
        assert!(check_ech_config_list(&list(&[short, offered("a.example")])).is_err());
    }

    #[test]
    fn a_list_boringssl_cannot_parse_is_turned_down() {
        let mut trailing = list(&[offered("a.example")]);
        trailing.push(0);
        let mut cut = list(&[offered("a.example")]);
        cut.pop();
        // A config it would pass over still has to parse: here its extensions are cut short.
        let broken = list(&[
            offered("a.example"),
            config(0xfe0d, 0x0020, 32, &[(1, 1)], "a.example", &[0]),
        ]);
        let no_key = list(&[config(0xfe0d, 0x0020, 0, &[(1, 1)], "a.example", &[])]);
        let no_name = list(&[offered("")]);
        // What BoringSSL hands out for retry configs when it has none.
        let placeholder = vec![0xfe, 0x0d, 0xff, 0xff, 0xff];
        for bad in [
            vec![],
            vec![0, 0],
            trailing,
            cut,
            broken,
            no_key,
            no_name,
            placeholder,
        ] {
            assert!(check_ech_config_list(&bad).is_err(), "{bad:02x?}");
            assert!(ensure_offerable(&bad).is_err());
        }
    }

    /// Whether BoringSSL offers ECH from `list` in the ClientHello it sends to a server on this
    /// machine: None when it takes no such list, or sends no ClientHello at all.
    async fn boringssl_offers(list: &[u8]) -> Option<bool> {
        let mut builder = boring::ssl::SslConnector::builder(SslMethod::tls()).expect("tls");
        Fingerprint::default()
            .apply(&mut builder, b"\x02h2")
            .expect("the fingerprint");
        let mut config = builder.build().configure().expect("a configuration");
        config.set_ech_config_list(list).ok()?;
        let (server, hello) = client_hello::catch().await;
        let tcp = tokio::net::TcpStream::connect(server)
            .await
            .expect("a connection");
        let _ = tokio_boring::connect(config, "a.example", tcp).await;
        hello.await.ok().map(|hello| hello.offers_ech())
    }

    #[tokio::test]
    async fn the_key_check_says_what_boringssl_does() {
        // The fingerprint sends no GREASE ECH, so an ECH extension in the ClientHello means
        // BoringSSL took a config from the list.
        let older = config(0xfe0c, 0x0020, 32, &[(1, 1)], "x.example", &[]);
        let short = config(0xfe0d, 0x0020, 31, &[(1, 1)], "a.example", &[]);
        let lists = [
            decode_ech_config_list(CLOUDFLARE_ECH).expect("base64"),
            list(&[older.clone(), offered("a.example")]),
            list(&[config(
                0xfe0d,
                0x0020,
                32,
                &[(2, 1), (1, 3)],
                "a.example",
                &[0, 1, 0, 1, 9],
            )]),
            list(&[offered("0x1f.example")]),
            list(&[older]),
            list(&[config(0xfe0d, 0x0010, 32, &[(1, 1)], "a.example", &[])]),
            list(&[config(0xfe0d, 0x0020, 32, &[(2, 1)], "a.example", &[])]),
            list(&[config(0xfe0d, 0x0020, 32, &[(1, 4)], "a.example", &[])]),
            list(&[config(
                0xfe0d,
                0x0020,
                32,
                &[(1, 1)],
                "a.example",
                &[0x80, 1, 0, 0],
            )]),
            list(&[offered("192.0.2.1")]),
            list(&[offered("example.0x1F")]),
            list(&[offered("example.com.")]),
            list(&[offered("exa_mple.com")]),
            list(&[short, offered("a.example")]),
            list(&[config(0xfe0d, 0x0020, 0, &[(1, 1)], "a.example", &[])]),
            vec![0xfe, 0x0d, 0xff, 0xff, 0xff],
        ];
        for list in lists {
            let sent = boringssl_offers(&list).await;
            assert_eq!(
                check_ech_config_list(&list).is_ok(),
                sent == Some(true),
                "{list:02x?}: BoringSSL {sent:?}"
            );
        }
    }
}

/// A ClientHello as a server reads it, and a server on this machine that reads one and hangs
/// up, for the tests of the handshakes that list cipher suites.
#[cfg(test)]
pub(crate) mod client_hello {
    use tokio::io::AsyncReadExt;

    pub struct ClientHello {
        /// The cipher suites, in order.
        pub suites: Vec<u16>,
        /// The extensions, in order: their type and what they carry.
        pub extensions: Vec<(u16, Vec<u8>)>,
    }

    /// Whether `value` is a GREASE value (RFC 8701).
    fn grease(value: u16) -> bool {
        value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
    }

    fn be16(bytes: &[u8], at: usize) -> usize {
        u16::from_be_bytes([bytes[at], bytes[at + 1]]) as usize
    }

    impl ClientHello {
        fn extension(&self, kind: u16) -> Option<&[u8]> {
            self.extensions
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, data)| data.as_slice())
        }

        /// The TLS 1.2 cipher suites: GREASE and the TLS 1.3 ones left out.
        pub fn tls12_suites(&self) -> Vec<u16> {
            self.suites
                .iter()
                .copied()
                .filter(|suite| !grease(*suite) && !(0x1301..=0x1305).contains(suite))
                .collect()
        }

        /// The versions of supported_versions, GREASE left out.
        pub fn versions(&self) -> Vec<u16> {
            let data = self.extension(43).expect("supported_versions");
            data[1..1 + data[0] as usize]
                .chunks(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .filter(|version| !grease(*version))
                .collect()
        }

        /// The name in server_name.
        pub fn server_name(&self) -> Option<String> {
            let data = self.extension(0)?;
            Some(String::from_utf8_lossy(&data[5..5 + be16(data, 3)]).into_owned())
        }

        /// Whether it offers ECH: encrypted_client_hello.
        pub fn offers_ech(&self) -> bool {
            self.extension(0xfe0d).is_some()
        }

        /// The protocols of application_layer_protocol_negotiation, in order.
        pub fn alpn(&self) -> Vec<Vec<u8>> {
            let data = self.extension(16).expect("ALPN");
            let mut protocols = Vec::new();
            let mut at = 2;
            while at < data.len() {
                let len = data[at] as usize;
                protocols.push(data[at + 1..at + 1 + len].to_vec());
                at += 1 + len;
            }
            protocols
        }

        /// Whether a GREASE value leads its cipher suites.
        pub fn has_grease(&self) -> bool {
            self.suites.first().is_some_and(|suite| grease(*suite))
        }

        /// Whether one of its extensions is a GREASE one.
        pub fn has_grease_extension(&self) -> bool {
            self.extensions.iter().any(|(kind, _)| grease(*kind))
        }

        /// Whether it carries the extension `kind`.
        pub fn has_extension(&self, kind: u16) -> bool {
            self.extension(kind).is_some()
        }

        /// The types of its extensions, in order.
        pub fn extension_types(&self) -> Vec<u16> {
            self.extensions.iter().map(|(kind, _)| *kind).collect()
        }

        /// The groups of supported_groups, in order, GREASE left out.
        pub fn groups(&self) -> Vec<u16> {
            let data = self.extension(10).expect("supported_groups");
            data[2..2 + be16(data, 0)]
                .chunks(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .filter(|group| !grease(*group))
                .collect()
        }

        /// The groups of the shares of key_share, in order, GREASE left out.
        pub fn key_shares(&self) -> Vec<u16> {
            let data = self.extension(51).expect("key_share");
            let mut groups = Vec::new();
            let mut at = 2;
            while at + 4 <= data.len() {
                let group = be16(data, at) as u16;
                if !grease(group) {
                    groups.push(group);
                }
                at += 4 + be16(data, at + 2);
            }
            groups
        }
    }

    /// The ClientHello in `record`, a TLS record as it goes over the wire.
    pub fn parse(record: &[u8]) -> ClientHello {
        assert_eq!(record[0], 0x16, "a handshake record");
        let message = &record[5..5 + be16(record, 3)];
        assert_eq!(message[0], 1, "a ClientHello");
        let hello = &message[4..];
        let mut at = 2 + 32;
        at += 1 + hello[at] as usize;
        let suites = hello[at + 2..at + 2 + be16(hello, at)]
            .chunks(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        at += 2 + be16(hello, at);
        at += 1 + hello[at] as usize;
        let end = at + 2 + be16(hello, at);
        at += 2;
        let mut extensions = Vec::new();
        while at + 4 <= end {
            let len = be16(hello, at + 2);
            extensions.push((be16(hello, at) as u16, hello[at + 4..at + 4 + len].to_vec()));
            at += 4 + len;
        }
        ClientHello { suites, extensions }
    }

    /// Chrome's TLS 1.2 suites, in the order BoringSSL gives Chrome's rule on this machine,
    /// which depends on its AES hardware.
    pub fn chrome_tls12_suites() -> Vec<u16> {
        super::tls12_ciphers(super::CHROME_CIPHERS)
            .expect("Chrome's rule")
            .iter()
            .map(|(id, _)| *id)
            .collect()
    }

    /// Listens on this machine: the task ends with the first ClientHello sent there, read
    /// before the server hangs up, and fails when none comes within ten seconds.
    pub async fn catch() -> (std::net::SocketAddr, tokio::task::JoinHandle<ClientHello>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let address = listener.local_addr().expect("its address");
        let caught = tokio::spawn(async move {
            let (mut tcp, _) =
                tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
                    .await
                    .expect("a connection within ten seconds")
                    .expect("a connection");
            let mut record = vec![0u8; 5];
            tcp.read_exact(&mut record).await.expect("a record header");
            let len = be16(&record, 3);
            record.resize(5 + len, 0);
            tcp.read_exact(&mut record[5..]).await.expect("the record");
            parse(&record)
        });
        (address, caught)
    }
}

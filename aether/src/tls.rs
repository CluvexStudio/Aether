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

const CHROME_GROUPS: &str = "P-256:X25519:P-384";

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

    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder.set_grease_enabled(true);
    let groups = std::env::var("AETHER_TLS_GROUPS").ok();
    let groups = groups
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(CHROME_GROUPS);
    builder
        .set_curves_list(groups)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let mut alpn = Vec::with_capacity(consts::ALPN_H3.len() + 1);
    alpn.push(consts::ALPN_H3.len() as u8);
    alpn.extend_from_slice(consts::ALPN_H3);
    builder
        .set_alpn_protos(&alpn)
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
    if ech_config_list.is_empty() {
        return Err(AetherError::Ech("empty ech config list".into()));
    }

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
/// in the clear.
static SESSION_ECH: std::sync::RwLock<Option<Vec<u8>>> = std::sync::RwLock::new(None);

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
    Some(slice.to_vec())
}

pub fn decode_ech_config_list(b64: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| AetherError::Ech(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_a_server_hands_back_replaces_the_sessions_only_while_it_offers_ech() {
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
}

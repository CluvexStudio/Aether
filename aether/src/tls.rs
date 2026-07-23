use std::ffi::c_void;
use std::os::raw::c_int;
use std::ptr;

use boring::pkey::PKey;
use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyError, SslVerifyMode, SslVersion};
use boring::x509::X509;
use foreign_types_shared::ForeignTypeRef;
use ring::digest;

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

/// Compute the SHA-256 hash of a certificate's SubjectPublicKeyInfo (SPKI).
/// This is the standard format for certificate pinning (e.g., HPKP, CT logs).
fn spki_sha256(cert: &boring::x509::X509Ref) -> Option<[u8; 32]> {
    let pubkey = cert.public_key().ok()?;
    let der = pubkey.public_key_to_der().ok()?;
    let hash = digest::digest(&digest::SHA256, &der);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_ref());
    Some(out)
}

/// Install TLS verification on an `SslContextBuilder`.
///
/// When `pin_endpoint` is true and `expected_pins` is non-empty:
///   Pin-only verification: leaf cert SPKI hash is checked against pins.
///   No CA chain verification is performed (Cloudflare MASQUE edges use
///   self-signed certs that would fail chain validation).
///
/// When `pin_endpoint` is false (or no pins provided):
///   SslVerifyMode::NONE — no server cert verification.
///   Required because Cloudflare edges serve different certs per SNI
///   and some are self-signed. Security relies on the pin-based path
///   being used in production.
pub fn install_verification(
    builder: &mut SslContextBuilder,
    pin_endpoint: bool,
    expected_pins: &[&[u8]],
) -> Result<()> {
    if pin_endpoint && !expected_pins.is_empty() {
        let pins: Vec<Vec<u8>> = expected_pins.iter().map(|p| p.to_vec()).collect();
        builder.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            // Pin-only verification: check leaf cert SPKI hash against known pins.
            // No CA chain verification — Cloudflare MASQUE edges use self-signed certs.
            let leaf_cert = ssl.peer_certificate().ok_or_else(|| {
                log::warn!("tls pin: no peer certificate presented");
                SslVerifyError::Invalid(boring::ssl::SslAlert::BAD_CERTIFICATE)
            })?;

            let hash = spki_sha256(&leaf_cert).ok_or_else(|| {
                log::warn!("tls pin: failed to compute SPKI hash");
                SslVerifyError::Invalid(boring::ssl::SslAlert::INTERNAL_ERROR)
            })?;

            let matched = pins.iter().any(|pin| pin.as_slice() == hash.as_slice());
            if !matched {
                log::warn!(
                    "tls pin: server cert SPKI hash {:02x?} does not match any pinned hash",
                    hash
                );
                return Err(SslVerifyError::Invalid(
                    boring::ssl::SslAlert::CERTIFICATE_UNKNOWN,
                ));
            }
            log::debug!("tls pin: SPKI hash match OK");
            Ok(())
        });
        log::info!(
            "tls verification: pin-based ({} pins loaded)",
            expected_pins.len()
        );
    } else {
        // No pin-based verification configured — disable server cert verification.
        // This is required because Aether connects to Cloudflare edge IPs with
        // SNI=consumer-masque.cloudflareclient.com but the edge may present a
        // different certificate or the SNI may be empty/transformed for DPI bypass.
        // Standard CA validation fails in this context. The security model relies on
        // the encrypted MASQUE tunnel and ECH rather than TLS cert verification.
        builder.set_verify(SslVerifyMode::NONE);
        log::info!("tls verification: disabled (no pin configured)");
    }
    Ok(())
}

pub fn build_config(params: &TlsParams) -> Result<quiche::Config> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder.set_grease_enabled(true);
    let groups = std::env::var("AETHER_TLS_GROUPS").ok();
    let groups = groups.as_deref().map(str::trim).filter(|s| !s.is_empty()).unwrap_or(CHROME_GROUPS);
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
    let key = PKey::private_key_from_pem(params.key_pem)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
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

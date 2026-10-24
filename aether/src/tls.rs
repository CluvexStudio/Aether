use std::ffi::{c_char, c_void, CStr, CString};
use std::io::Read;
use std::os::raw::c_int;
use std::ptr;

use boring::pkey::PKey;
use boring::ssl::{
    Ssl, SslCipher, SslContextBuilder, SslMethod, SslOptions, SslRef, SslVerifyError,
    SslVerifyMode, SslVersion,
};
use boring::x509::X509;
use ring::digest;
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

    // Calls of the BoringSSL of boring 5.3 that the boring crate does not wrap.
    fn SSL_CTX_set1_tls13_ciphers(
        ctx: *mut c_void,
        cipher_ids: *const u16,
        flags: *const u32,
        num_cipher_ids: usize,
    ) -> c_int;

    fn SSL_CTX_set_grease_sigalgs_enabled(ctx: *mut c_void, enabled: c_int);

    fn SSL_set1_client_key_shares(
        ssl: *mut c_void,
        group_ids: *const u16,
        num_group_ids: usize,
    ) -> c_int;

    fn SSL_set1_groups_list(ssl: *mut c_void, groups: *const c_char) -> c_int;

    fn SSL_get_group_name(group_id: u16) -> *const c_char;

    // boring wraps this one only with its own type of signature algorithm, which takes none
    // it has no constant for, as ML-DSA.
    fn SSL_CTX_set_verify_algorithm_prefs(
        ctx: *mut c_void,
        prefs: *const u16,
        num_prefs: usize,
    ) -> c_int;

    fn SSL_get_signature_algorithm_name(sigalg: u16, include_curve: c_int) -> *const c_char;

    // boring wraps this one only for zlib and brotli.
    fn SSL_CTX_add_cert_compression_alg(
        ctx: *mut c_void,
        alg_id: u16,
        compress: Option<CertCompressFn>,
        decompress: Option<CertDecompressFn>,
    ) -> c_int;

    fn CRYPTO_BUFFER_alloc(out_data: *mut *mut u8, len: usize) -> *mut c_void;

    fn CRYPTO_BUFFER_free(buffer: *mut c_void);

    fn SSL_add_application_settings(
        ssl: *mut c_void,
        proto: *const u8,
        proto_len: usize,
        settings: *const u8,
        settings_len: usize,
    ) -> c_int;

    fn SSL_set_alps_use_new_codepoint(ssl: *mut c_void, use_new: c_int);

    fn SSL_CTX_set1_requested_trust_anchors(
        ctx: *mut c_void,
        ids: *const u8,
        ids_len: usize,
    ) -> c_int;

    fn SSL_set_server_padding_request(ssl: *mut c_void, num_bytes: u16);
}

/// BoringSSL's ssl_cert_compression_func_t: (ssl, out, in, in_len).
type CertCompressFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const u8, usize) -> c_int;

/// BoringSSL's ssl_cert_decompression_func_t: (ssl, out, uncompressed_len, in, in_len).
type CertDecompressFn =
    unsafe extern "C" fn(*mut c_void, *mut *mut c_void, usize, *const u8, usize) -> c_int;

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
/// It is Chrome's, as BoringSSL writes it, with what the TLS options change of it: the cipher
/// suites, groups, key shares, signature algorithms and extensions the ClientHello carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// --tls-ciphers: the TLS 1.2 cipher suites in place of Chrome's, when given.
    pub ciphers: Option<String>,
    /// --tls13-ciphers: the TLS 1.3 cipher suites, in order, by their standard names, when
    /// given. Otherwise BoringSSL's order, as Chrome's: AES-GCM first on hardware with AES
    /// instructions, ChaCha20 first elsewhere.
    pub tls13_ciphers: Option<String>,
    /// --tls-groups: the groups, in order.
    pub groups: String,
    /// --tls-key-shares: the groups that get a key share, in order, when given; each is one of
    /// the groups, in their order. Otherwise BoringSSL's choice, as Chrome's: the first group,
    /// and the first one of the other kind, post-quantum or not.
    pub key_shares: Option<String>,
    /// GREASE values (RFC 8701) among the cipher suites, the extensions, the groups, the key
    /// shares and the versions, as Chrome sends them; --disable-grease leaves them out.
    pub grease: bool,
    /// --enable-grease-sigalgs: a GREASE value first among the signature algorithms as well, as
    /// Chrome sends it, which BoringSSL turns on apart from the rest and leaves off by default.
    pub grease_sigalgs: bool,
    /// --tls-sigalgs: the signature algorithms, in order, by the names BoringSSL gives them
    /// (ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, mldsa65...), when given: those the
    /// ClientHello lists, and the only ones a server may sign the handshake with. Otherwise
    /// BoringSSL's: Chrome's eight, then rsa_pkcs1_sha1.
    pub sigalgs: Option<String>,
    /// --tls-cert-compression: the certificate compression algorithms (RFC 8879) offered, in
    /// order, of zlib, brotli and zstd, when given; a certificate the server sends compressed
    /// with one of them is decompressed. Otherwise none.
    pub cert_compression: Option<String>,
    /// --tls-alps: application settings (ALPS) offered for HTTP/2 and HTTP/3, with no settings
    /// of the client's, under the codepoint "new" (0x44cd), Chrome's now, or "old" (0x4469),
    /// Chrome's before, as Chrome 120 sends it, when given. Otherwise none.
    pub alps: Option<String>,
    /// --tls-trust-anchors: the trust anchor IDs (draft-ietf-tls-trust-anchor-ids) asked for, in
    /// order, as relative OIDs in dotted decimal separated by ':', when given. Otherwise none.
    pub trust_anchors: Option<String>,
    /// --tls-server-padding: the bytes of padding asked of the server, in BoringSSL's
    /// server_padding extension (0x12e0), when given. Otherwise none.
    pub server_padding: Option<String>,
    /// --enable-ech-grease: a GREASE encrypted_client_hello when no ECH key is offered, as
    /// Chrome and Firefox send it. Off by default.
    pub ech_grease: bool,
    /// OCSP asked for (status_request), as Chrome asks; --disable-ocsp-stapling leaves it out.
    pub ocsp_stapling: bool,
    /// Signed certificate timestamps asked for, as Chrome asks; --disable-sct leaves them out.
    pub sct: bool,
    /// The session_ticket extension, as Chrome sends it; --disable-session-ticket leaves it out.
    pub session_ticket: bool,
    /// The extensions in a new order on each handshake, as Chrome's;
    /// --disable-extension-permutation keeps BoringSSL's one order.
    pub permute_extensions: bool,
}

impl Default for Fingerprint {
    /// Chrome's, with none of the options given.
    fn default() -> Self {
        Fingerprint {
            ciphers: None,
            tls13_ciphers: None,
            groups: CHROME_GROUPS.to_string(),
            key_shares: None,
            grease: true,
            grease_sigalgs: false,
            sigalgs: None,
            cert_compression: None,
            alps: None,
            trust_anchors: None,
            server_padding: None,
            ech_grease: false,
            ocsp_stapling: true,
            sct: true,
            session_ticket: true,
            permute_extensions: true,
        }
    }
}

/// The value of the environment variable `variable`, trimmed, unless it is not set or blank.
fn listed(variable: &str) -> Option<String> {
    std::env::var(variable)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

impl Fingerprint {
    /// The fingerprint the options give: --tls-ciphers (AETHER_TLS_CIPHERS), --tls13-ciphers
    /// (AETHER_TLS13_CIPHERS), --tls-groups (AETHER_TLS_GROUPS), --tls-key-shares
    /// (AETHER_TLS_KEY_SHARES), --disable-grease (AETHER_DISABLE_GREASE),
    /// --enable-grease-sigalgs (AETHER_ENABLE_GREASE_SIGALGS), --tls-sigalgs
    /// (AETHER_TLS_SIGALGS), --tls-cert-compression (AETHER_TLS_CERT_COMPRESSION), --tls-alps
    /// (AETHER_TLS_ALPS), --tls-trust-anchors (AETHER_TLS_TRUST_ANCHORS), --tls-server-padding
    /// (AETHER_TLS_SERVER_PADDING), --enable-ech-grease (AETHER_ENABLE_ECH_GREASE),
    /// --disable-ocsp-stapling (AETHER_DISABLE_OCSP_STAPLING), --disable-sct
    /// (AETHER_DISABLE_SCT), --disable-session-ticket (AETHER_DISABLE_SESSION_TICKET) and
    /// --disable-extension-permutation (AETHER_DISABLE_EXTENSION_PERMUTATION).
    pub fn configured() -> Self {
        let on = |variable: &str| {
            std::env::var(variable).is_ok_and(|value| crate::fragment::is_truthy(&value))
        };
        Fingerprint {
            ciphers: TLS_CIPHERS.configured(),
            tls13_ciphers: listed("AETHER_TLS13_CIPHERS"),
            groups: listed("AETHER_TLS_GROUPS").unwrap_or_else(|| CHROME_GROUPS.to_string()),
            key_shares: listed("AETHER_TLS_KEY_SHARES"),
            grease: !on("AETHER_DISABLE_GREASE"),
            grease_sigalgs: on("AETHER_ENABLE_GREASE_SIGALGS"),
            sigalgs: listed("AETHER_TLS_SIGALGS"),
            cert_compression: listed("AETHER_TLS_CERT_COMPRESSION"),
            alps: listed("AETHER_TLS_ALPS"),
            trust_anchors: listed("AETHER_TLS_TRUST_ANCHORS"),
            server_padding: listed("AETHER_TLS_SERVER_PADDING"),
            ech_grease: on("AETHER_ENABLE_ECH_GREASE"),
            ocsp_stapling: !on("AETHER_DISABLE_OCSP_STAPLING"),
            sct: !on("AETHER_DISABLE_SCT"),
            session_ticket: !on("AETHER_DISABLE_SESSION_TICKET"),
            permute_extensions: !on("AETHER_DISABLE_EXTENSION_PERMUTATION"),
        }
    }

    /// Gives `builder` the fingerprint, offering `alpn`, in wire format: TLS 1.2 and 1.3, the
    /// groups, the extensions in a new order on each handshake unless that is off, signed
    /// certificate timestamps, OCSP and the session_ticket extension unless each is off, GREASE
    /// unless it is off, GREASE among the signature algorithms when it is on, the TLS 1.2 suites,
    /// Chrome's unless the cipher list names others, the TLS 1.3 suites in their order when it is
    /// given, and the signature algorithms, the certificate compression and the trust anchors
    /// of the options that give them. TLS server-certificate verification disabled
    /// (unconditional). What BoringSSL takes from a connection only goes on each one, see
    /// `prepare`.
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
        unsafe {
            SSL_CTX_set_grease_sigalgs_enabled(
                builder.as_ptr().cast(),
                c_int::from(self.grease_sigalgs),
            )
        };
        builder.set_permute_extensions(self.permute_extensions);
        set_groups(builder, &self.groups)?;
        builder.set_alpn_protos(alpn).map_err(tls)?;
        if self.sct {
            builder.enable_signed_cert_timestamps();
        }
        if self.ocsp_stapling {
            builder.enable_ocsp_stapling();
        }
        if !self.session_ticket {
            builder.set_options(SslOptions::NO_TICKET);
        }
        set_tls12_ciphers(builder, self.ciphers.as_deref().unwrap_or(CHROME_CIPHERS))?;
        if let Some(list) = &self.tls13_ciphers {
            set_tls13_ciphers(builder, list)?;
        }
        if let Some(list) = &self.sigalgs {
            set_sigalgs(builder, list)?;
        }
        if let Some(list) = &self.cert_compression {
            offer_cert_compression(builder, list)?;
        }
        if let Some(list) = &self.trust_anchors {
            ask_trust_anchors(builder, list)?;
        }
        Ok(())
    }

    /// Gives `ssl`, one connection of a context `apply` set up offering `alpn`, before its
    /// ClientHello, what BoringSSL takes from a connection only: the key shares of
    /// --tls-key-shares, ALPS of --tls-alps for HTTP/2 and HTTP/3 among `alpn`, GREASE ECH of
    /// --enable-ech-grease and the padding --tls-server-padding asks of the server.
    pub fn prepare(&self, ssl: &mut SslRef, alpn: &[u8]) -> Result<()> {
        if let Some(list) = &self.key_shares {
            set_key_shares(ssl, list)?;
        }
        if let Some(codepoint) = &self.alps {
            offer_alps(ssl, codepoint, alpn)?;
        }
        if self.ech_grease {
            ssl.set_enable_ech_grease(true);
        }
        if let Some(bytes) = &self.server_padding {
            ask_server_padding(ssl, bytes)?;
        }
        Ok(())
    }
}

/// The first number of a TLS 1.3 cipher suite, and the last one: 0x13 is their first byte.
const TLS13_CIPHER_IDS: std::ops::RangeInclusive<u16> = 0x1300..=0x13ff;

/// The numbers of the TLS 1.3 cipher suites `list` names, standard names separated by ':', in
/// order, as BoringSSL names them.
fn tls13_cipher_ids(list: &str) -> Result<Vec<u16>> {
    list.split(':')
        .map(|name| {
            TLS13_CIPHER_IDS
                .into_iter()
                .find(|&id| {
                    SslCipher::from_value(id).and_then(|cipher| cipher.standard_name())
                        == Some(name)
                })
                .ok_or_else(|| {
                    AetherError::Tls(format!(
                        "{name:?} is no TLS 1.3 cipher suite BoringSSL has (it has \
                         TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 and \
                         TLS_CHACHA20_POLY1305_SHA256)"
                    ))
                })
        })
        .collect()
}

/// Sets `list`, TLS 1.3 cipher suites by their standard names separated by ':', as the TLS 1.3
/// suites of `builder`, in order, in place of BoringSSL's own.
fn set_tls13_ciphers(builder: &mut SslContextBuilder, list: &str) -> Result<()> {
    let ids = tls13_cipher_ids(list)?;
    let set = unsafe {
        SSL_CTX_set1_tls13_ciphers(
            builder.as_ptr().cast(),
            ids.as_ptr(),
            ptr::null(),
            ids.len(),
        )
    };
    if set != 1 {
        // Off the thread's error queue, where it would show in a later error.
        let _ = boring::error::ErrorStack::get();
        return Err(AetherError::Tls(format!(
            "{list:?} names a TLS 1.3 cipher suite more than once"
        )));
    }
    Ok(())
}

/// Every group BoringSSL has, by number: each number it has a name for.
fn known_group_ids() -> &'static [u16] {
    static IDS: std::sync::OnceLock<Vec<u16>> = std::sync::OnceLock::new();
    IDS.get_or_init(|| {
        (0..=u16::MAX)
            .filter(|&id| !unsafe { SSL_get_group_name(id) }.is_null())
            .collect()
    })
}

/// The numbers of the groups `list` names, names separated by ':', in order, each read as
/// --tls-groups reads it. BoringSSL has no call that turns a group's name into its number, so
/// each name alone is set as the groups of a connection, and its number is the one group of
/// BoringSSL's that this connection then takes as a key share.
fn group_ids(list: &str) -> Result<Vec<u16>> {
    let tls = |error: boring::error::ErrorStack| AetherError::Tls(error.to_string());
    let context = SslContextBuilder::new(SslMethod::tls())
        .map_err(tls)?
        .build();
    let ids = list
        .split(':')
        .map(|name| {
            let unknown = || AetherError::Tls(format!("{name:?} is no group BoringSSL takes"));
            let text = CString::new(name).map_err(|_| unknown())?;
            let ssl = Ssl::new(&context).map_err(tls)?;
            let alone = unsafe { SSL_set1_groups_list(ssl.as_ptr().cast(), text.as_ptr()) };
            if name.is_empty() || alone != 1 {
                return Err(unknown());
            }
            known_group_ids()
                .iter()
                .copied()
                .find(|id| unsafe { SSL_set1_client_key_shares(ssl.as_ptr().cast(), id, 1) } == 1)
                .ok_or_else(unknown)
        })
        .collect();
    // The groups each name was not, and a name BoringSSL did not take, left errors on the
    // thread's queue, where they would show in a later error.
    let _ = boring::error::ErrorStack::get();
    ids
}

/// Sets `list`, group names separated by ':', as the groups `ssl` sends key shares for, in
/// order: each one of the groups of `ssl`, in their order, and named once.
fn set_key_shares(ssl: &mut SslRef, list: &str) -> Result<()> {
    let ids = group_ids(list)?;
    let set = unsafe { SSL_set1_client_key_shares(ssl.as_ptr().cast(), ids.as_ptr(), ids.len()) };
    if set != 1 {
        let _ = boring::error::ErrorStack::get();
        return Err(AetherError::Tls(format!(
            "{list:?} names no key shares BoringSSL sends: each must be one of the groups, in \
             their order, and named once"
        )));
    }
    Ok(())
}

/// The number of rsa_pkcs1_md5_sha1, which only TLS 1.1 and older sign with: BoringSSL drops
/// it from a list of signature algorithms without a word, so --tls-sigalgs does not take it.
const SIGN_RSA_PKCS1_MD5_SHA1: u16 = 0xff01;

/// Every signature algorithm BoringSSL has, by name and number: each number it has a name for,
/// with the curve in the name, as SSL_get_signature_algorithm_name gives it.
fn known_sigalgs() -> &'static [(String, u16)] {
    static KNOWN: std::sync::OnceLock<Vec<(String, u16)>> = std::sync::OnceLock::new();
    KNOWN.get_or_init(|| {
        (0..=u16::MAX)
            .filter(|&id| id != SIGN_RSA_PKCS1_MD5_SHA1)
            .filter_map(|id| {
                let name = unsafe { SSL_get_signature_algorithm_name(id, 1) };
                (!name.is_null()).then(|| {
                    let name = unsafe { CStr::from_ptr(name) };
                    (name.to_string_lossy().into_owned(), id)
                })
            })
            .collect()
    })
}

/// The numbers of the signature algorithms `list` names, names separated by ':', in order.
fn sigalg_ids(list: &str) -> Result<Vec<u16>> {
    list.split(':')
        .map(|name| {
            known_sigalgs()
                .iter()
                .find(|(known, _)| known == name)
                .map(|(_, id)| *id)
                .ok_or_else(|| {
                    let names: Vec<&str> =
                        known_sigalgs().iter().map(|(n, _)| n.as_str()).collect();
                    AetherError::Tls(format!(
                        "{name:?} is no signature algorithm BoringSSL has (it has {})",
                        names.join(", ")
                    ))
                })
        })
        .collect()
}

/// Sets `list`, signature algorithms by name separated by ':', in order, as those `builder`
/// lists in its ClientHello and takes the server's signature in, in place of BoringSSL's own.
/// The handshake's own key signs as before: the client certificate of MASQUE is apart.
fn set_sigalgs(builder: &mut SslContextBuilder, list: &str) -> Result<()> {
    let ids = sigalg_ids(list)?;
    let set = unsafe {
        SSL_CTX_set_verify_algorithm_prefs(builder.as_ptr().cast(), ids.as_ptr(), ids.len())
    };
    if set != 1 {
        let _ = boring::error::ErrorStack::get();
        return Err(AetherError::Tls(format!(
            "{list:?} names a signature algorithm more than once"
        )));
    }
    Ok(())
}

/// A certificate compression algorithm (RFC 8879) --tls-cert-compression offers: its name, its
/// number, and the call BoringSSL decompresses a certificate with.
struct CertCompression {
    name: &'static str,
    id: u16,
    decompress: CertDecompressFn,
}

/// The algorithms --tls-cert-compression takes: zlib (RFC 1950), brotli (RFC 7932) and zstd
/// (RFC 8878), as Firefox offers them.
const CERT_COMPRESSIONS: [CertCompression; 3] = [
    CertCompression {
        name: "zlib",
        id: 1,
        decompress: decompress_zlib,
    },
    CertCompression {
        name: "brotli",
        id: 2,
        decompress: decompress_brotli,
    },
    CertCompression {
        name: "zstd",
        id: 3,
        decompress: decompress_zstd,
    },
];

/// The largest window, as a power of two, a certificate compressed with zstd may ask for: 8
/// MiB, which zstd uses up to its level 19. A certificate chain is never more than 100 KiB here
/// (BoringSSL's limit), so a larger window only spends memory a server asks for.
const ZSTD_WINDOW_LOG_MAX: u32 = 23;

/// Fills `out`, all of it, with what `decoder` gives, which must be no more: the certificate
/// is exactly as long as the server said.
fn fill_exactly(mut decoder: impl Read, out: &mut [u8]) -> bool {
    if decoder.read_exact(out).is_err() {
        return false;
    }
    let mut more = [0u8; 1];
    matches!(decoder.read(&mut more), Ok(0))
}

fn zlib_into(input: &[u8], out: &mut [u8]) -> bool {
    fill_exactly(flate2::read::ZlibDecoder::new(input), out)
}

fn brotli_into(input: &[u8], out: &mut [u8]) -> bool {
    fill_exactly(brotli_decompressor::Decompressor::new(input, 4096), out)
}

fn zstd_into(input: &[u8], out: &mut [u8]) -> bool {
    let Ok(mut decoder) = zstd::stream::read::Decoder::with_buffer(input) else {
        return false;
    };
    decoder.window_log_max(ZSTD_WINDOW_LOG_MAX).is_ok() && fill_exactly(decoder, out)
}

/// Gives BoringSSL, in `out`, the certificate `decompress` makes of the `input_len` bytes at
/// `input`, exactly `len` bytes long; 0 when it cannot, which fails the handshake.
///
/// # Safety
/// As BoringSSL calls a certificate decompression function: `out` takes the result, and
/// `input` holds `input_len` bytes.
unsafe fn decompressed(
    out: *mut *mut c_void,
    len: usize,
    input: *const u8,
    input_len: usize,
    decompress: fn(&[u8], &mut [u8]) -> bool,
) -> c_int {
    let mut data: *mut u8 = ptr::null_mut();
    let buffer = unsafe { CRYPTO_BUFFER_alloc(&mut data, len) };
    if buffer.is_null() || (len > 0 && data.is_null()) {
        return 0;
    }
    let input = if input_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(input, input_len) }
    };
    let output = if len == 0 {
        &mut [][..]
    } else {
        unsafe {
            ptr::write_bytes(data, 0, len);
            std::slice::from_raw_parts_mut(data, len)
        }
    };
    // No panic may unwind into BoringSSL.
    let done = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decompress(input, output)))
        .unwrap_or(false);
    if !done {
        unsafe { CRYPTO_BUFFER_free(buffer) };
        return 0;
    }
    unsafe { *out = buffer };
    1
}

unsafe extern "C" fn decompress_zlib(
    _ssl: *mut c_void,
    out: *mut *mut c_void,
    len: usize,
    input: *const u8,
    input_len: usize,
) -> c_int {
    unsafe { decompressed(out, len, input, input_len, zlib_into) }
}

unsafe extern "C" fn decompress_brotli(
    _ssl: *mut c_void,
    out: *mut *mut c_void,
    len: usize,
    input: *const u8,
    input_len: usize,
) -> c_int {
    unsafe { decompressed(out, len, input, input_len, brotli_into) }
}

unsafe extern "C" fn decompress_zstd(
    _ssl: *mut c_void,
    out: *mut *mut c_void,
    len: usize,
    input: *const u8,
    input_len: usize,
) -> c_int {
    unsafe { decompressed(out, len, input, input_len, zstd_into) }
}

/// Offers `list`, certificate compression algorithms by name separated by ':', in order, on
/// `builder`, each with the call that decompresses what it compressed.
fn offer_cert_compression(builder: &mut SslContextBuilder, list: &str) -> Result<()> {
    for name in list.split(':') {
        let algorithm = CERT_COMPRESSIONS
            .iter()
            .find(|algorithm| algorithm.name == name)
            .ok_or_else(|| {
                AetherError::Tls(format!(
                    "{name:?} is no certificate compression Aether has (zlib, brotli and zstd)"
                ))
            })?;
        let added = unsafe {
            SSL_CTX_add_cert_compression_alg(
                builder.as_ptr().cast(),
                algorithm.id,
                None,
                Some(algorithm.decompress),
            )
        };
        if added != 1 {
            let _ = boring::error::ErrorStack::get();
            return Err(AetherError::Tls(format!(
                "{list:?} names {name} more than once"
            )));
        }
    }
    Ok(())
}

/// The trust anchor IDs `list` names, relative OIDs in dotted decimal separated by ':', in the
/// wire format BoringSSL takes: each ID's bytes, its arcs in base 128, after their length.
fn trust_anchor_ids(list: &str) -> Result<Vec<u8>> {
    let mut wire = Vec::new();
    for id in list.split(':') {
        let bad = || {
            AetherError::Tls(format!(
                "{id:?} is no trust anchor ID (a relative OID in dotted decimal, such as \
                 11129.9.1)"
            ))
        };
        let mut encoded = Vec::new();
        for arc in id.split('.') {
            if arc.is_empty()
                || !arc.bytes().all(|byte| byte.is_ascii_digit())
                || (arc.len() > 1 && arc.starts_with('0'))
            {
                return Err(bad());
            }
            let mut value: u64 = arc.parse().map_err(|_| bad())?;
            let mut base128 = vec![(value & 0x7f) as u8];
            value >>= 7;
            while value > 0 {
                base128.push(0x80 | (value & 0x7f) as u8);
                value >>= 7;
            }
            base128.reverse();
            encoded.extend(base128);
        }
        wire.push(u8::try_from(encoded.len()).map_err(|_| bad())?);
        wire.extend(encoded);
    }
    Ok(wire)
}

/// Asks, on `builder`, for the trust anchors `list` names (see `trust_anchor_ids`), in order.
fn ask_trust_anchors(builder: &mut SslContextBuilder, list: &str) -> Result<()> {
    let ids = trust_anchor_ids(list)?;
    let set = unsafe {
        SSL_CTX_set1_requested_trust_anchors(builder.as_ptr().cast(), ids.as_ptr(), ids.len())
    };
    if set != 1 {
        let _ = boring::error::ErrorStack::get();
        return Err(AetherError::Tls(format!(
            "{list:?} is no list of trust anchor IDs BoringSSL takes"
        )));
    }
    Ok(())
}

/// The protocols ALPS is offered for: HTTP/2 and HTTP/3, as Chrome offers it; never HTTP/1.1.
const ALPS_PROTOCOLS: [&[u8]; 2] = [b"h2", b"h3"];

/// The protocols of `alpn`, an ALPN list in wire format, in order.
fn alpn_protocols(alpn: &[u8]) -> Vec<&[u8]> {
    let mut protocols = Vec::new();
    let mut at = 0;
    while at < alpn.len() {
        let end = (at + 1 + alpn[at] as usize).min(alpn.len());
        protocols.push(&alpn[at + 1..end]);
        at = end;
    }
    protocols
}

/// Whether --tls-alps `codepoint` is the new codepoint of ALPS: "new" (0x44cd) or "old" (0x4469).
fn alps_new_codepoint(codepoint: &str) -> Result<bool> {
    match codepoint {
        "new" => Ok(true),
        "old" => Ok(false),
        _ => Err(AetherError::Tls(format!(
            "{codepoint:?} is no ALPS codepoint: new (0x44cd, Chrome's now) or old (0x4469, \
             Chrome 120's)"
        ))),
    }
}

/// Offers ALPS on `ssl`, under `codepoint` (see `alps_new_codepoint`), for HTTP/2 and HTTP/3
/// among `alpn`, its ALPN list in wire format, with no settings of the client's, as Chrome
/// offers it: a server that takes ALPS gets them once the handshake is encrypted.
fn offer_alps(ssl: &mut SslRef, codepoint: &str, alpn: &[u8]) -> Result<()> {
    let new = alps_new_codepoint(codepoint)?;
    unsafe { SSL_set_alps_use_new_codepoint(ssl.as_ptr().cast(), c_int::from(new)) };
    for protocol in alpn_protocols(alpn)
        .into_iter()
        .filter(|protocol| ALPS_PROTOCOLS.contains(protocol))
    {
        let added = unsafe {
            SSL_add_application_settings(
                ssl.as_ptr().cast(),
                protocol.as_ptr(),
                protocol.len(),
                ptr::null(),
                0,
            )
        };
        if added != 1 {
            let _ = boring::error::ErrorStack::get();
            return Err(AetherError::Tls(format!(
                "ALPS for {} cannot be offered",
                String::from_utf8_lossy(protocol)
            )));
        }
    }
    Ok(())
}

/// The bytes of padding --tls-server-padding `value` asks of the server: 0 to 65535.
fn server_padding(value: &str) -> Result<u16> {
    value
        .parse()
        .map_err(|_| AetherError::Tls(format!("{value:?} is no number of bytes from 0 to 65535")))
}

/// Asks the server of `ssl` for the padding --tls-server-padding `value` gives.
fn ask_server_padding(ssl: &mut SslRef, value: &str) -> Result<()> {
    let bytes = server_padding(value)?;
    unsafe { SSL_set_server_padding_request(ssl.as_ptr().cast(), bytes) };
    Ok(())
}

/// The ALPN list in wire format of HTTP/2 then HTTP/1.1, as `check_tls_options` checks the
/// options with.
const ALPN_H2_HTTP1: &[u8] = b"\x02h2\x08http/1.1";

/// Checks the TLS options as the core starts: a cipher string, a TLS 1.3 suite list, a group
/// list, key shares, signature algorithms, certificate compression, an ALPS codepoint, trust
/// anchor IDs or a server padding BoringSSL does not take stop it, with the option named.
pub fn check_tls_options() -> Result<()> {
    let named = |flag: &str, e: AetherError| {
        let reason = match e {
            AetherError::Tls(reason) => reason,
            other => other.to_string(),
        };
        AetherError::Tls(format!("{flag}: {reason}"))
    };
    let tls = |error: boring::error::ErrorStack| AetherError::Tls(error.to_string());
    let fingerprint = Fingerprint::configured();
    if let Some(list) = &fingerprint.ciphers {
        tls12_ciphers(list).map_err(|e| named(TLS_CIPHERS.flag, e))?;
    }
    let mut builder = SslContextBuilder::new(SslMethod::tls()).map_err(tls)?;
    if let Some(list) = &fingerprint.tls13_ciphers {
        set_tls13_ciphers(&mut builder, list).map_err(|e| named("--tls13-ciphers", e))?;
    }
    set_groups(&mut builder, &fingerprint.groups).map_err(|e| named("--tls-groups", e))?;
    if let Some(list) = &fingerprint.sigalgs {
        set_sigalgs(&mut builder, list).map_err(|e| named("--tls-sigalgs", e))?;
    }
    if let Some(list) = &fingerprint.cert_compression {
        offer_cert_compression(&mut builder, list)
            .map_err(|e| named("--tls-cert-compression", e))?;
    }
    if let Some(list) = &fingerprint.trust_anchors {
        ask_trust_anchors(&mut builder, list).map_err(|e| named("--tls-trust-anchors", e))?;
    }
    let context = builder.build();
    let mut ssl = Ssl::new(&context).map_err(tls)?;
    if let Some(list) = &fingerprint.key_shares {
        set_key_shares(&mut ssl, list).map_err(|e| named("--tls-key-shares", e))?;
    }
    if let Some(codepoint) = &fingerprint.alps {
        offer_alps(&mut ssl, codepoint, ALPN_H2_HTTP1).map_err(|e| named("--tls-alps", e))?;
    }
    if let Some(bytes) = &fingerprint.server_padding {
        server_padding(bytes).map_err(|e| named("--tls-server-padding", e))?;
    }
    Ok(())
}

/// The ALPN list of HTTP/3 in wire format, as `build_config` offers it.
const ALPN_H3_WIRE: &[u8] = b"\x02h3";

/// Gives `conn`, a QUIC connection, before its first packet, what the fingerprint sets on each
/// connection, see `Fingerprint::prepare`; `build_config` set up the rest.
pub fn prepare_quic(conn: &mut quiche::Connection) -> Result<()> {
    let ssl: &mut SslRef = conn.as_mut();
    Fingerprint::configured().prepare(ssl, ALPN_H3_WIRE)
}

/// The variables of the options the handshakes are made with: those of the fingerprint, and
/// for MASQUE --masque-sni and the carrier.
#[cfg(test)]
const OPTION_VARIABLES: [&str; 18] = [
    "AETHER_TLS_CIPHERS",
    "AETHER_TLS13_CIPHERS",
    "AETHER_TLS_GROUPS",
    "AETHER_TLS_KEY_SHARES",
    "AETHER_DISABLE_GREASE",
    "AETHER_ENABLE_GREASE_SIGALGS",
    "AETHER_TLS_SIGALGS",
    "AETHER_TLS_CERT_COMPRESSION",
    "AETHER_TLS_ALPS",
    "AETHER_TLS_TRUST_ANCHORS",
    "AETHER_TLS_SERVER_PADDING",
    "AETHER_ENABLE_ECH_GREASE",
    "AETHER_DISABLE_OCSP_STAPLING",
    "AETHER_DISABLE_SCT",
    "AETHER_DISABLE_SESSION_TICKET",
    "AETHER_DISABLE_EXTENSION_PERMUTATION",
    "AETHER_MASQUE_SNI",
    "AETHER_MASQUE_HTTP2",
];

/// A hold on the options the handshakes are made with, which the whole process shares, for a
/// test that sets them, reads them through `Fingerprint::configured`, or makes a MASQUE
/// handshake: they start out clear, and are cleared again as it ends. A test that holds
/// AETHER_UPSTREAM as well takes that first.
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

/// Waits for the hold on the options of the handshakes, see `OptionsHeld`.
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
fn verify_enabled() -> bool {
    match std::env::var("AETHER_TLS_VERIFY") {
        Ok(value) => matches!(value.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => team_run(),
    }
}

fn team_run() -> bool {
    std::env::var("AETHER_TEAM").is_ok_and(|team| !team.trim().is_empty())
}

fn spki_sha256(cert: &boring::x509::X509Ref) -> Option<[u8; 32]> {
    let pubkey = cert.public_key().ok()?;
    let der = pubkey.public_key_to_der().ok()?;
    let hash = digest::digest(&digest::SHA256, &der);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_ref());
    Some(out)
}

pub fn install_verification(
    builder: &mut SslContextBuilder,
    pin_endpoint: bool,
    expected_pins: &[&[u8]],
) -> Result<()> {
    if !verify_enabled() {
        builder.set_verify(SslVerifyMode::NONE);
        announce_once(
            "tls verification: disabled (--tls-verify enables pinning; on by default with --team)"
                .to_string(),
        );
        return Ok(());
    }

    if pin_endpoint && !expected_pins.is_empty() {
        let pins: Vec<Vec<u8>> = expected_pins.iter().map(|p| p.to_vec()).collect();
        builder.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            let leaf_cert = ssl.peer_certificate().ok_or_else(|| {
                log::warn!("tls pin: no peer certificate presented");
                SslVerifyError::Invalid(boring::ssl::SslAlert::BAD_CERTIFICATE)
            })?;
            let hash = spki_sha256(&leaf_cert).ok_or_else(|| {
                log::warn!("tls pin: failed to compute SPKI hash");
                SslVerifyError::Invalid(boring::ssl::SslAlert::INTERNAL_ERROR)
            })?;
            if pins.iter().any(|pin| pin.as_slice() == hash.as_slice()) {
                Ok(())
            } else {
                Err(SslVerifyError::Invalid(
                    boring::ssl::SslAlert::CERTIFICATE_UNKNOWN,
                ))
            }
        });
        announce_once(format!(
            "tls verification: pin-based ({} pins loaded)",
            expected_pins.len()
        ));
    } else {
        builder.set_verify(SslVerifyMode::NONE);
        announce_once(
            "tls verification: none (--tls-verify set but no pins configured)".to_string(),
        );
    }
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

    #[test]
    fn a_zero_trust_run_verifies_the_gateway_unless_told_otherwise() {
        static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _held = ENV
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let clear = || {
            for key in ["AETHER_TEAM", "AETHER_TLS_VERIFY"] {
                std::env::remove_var(key);
            }
        };

        clear();
        assert!(!verify_enabled());

        std::env::set_var("AETHER_TEAM", "example");
        assert!(verify_enabled());

        std::env::set_var("AETHER_TLS_VERIFY", "false");
        assert!(!verify_enabled());

        std::env::remove_var("AETHER_TEAM");
        std::env::set_var("AETHER_TLS_VERIFY", "1");
        assert!(verify_enabled());

        clear();
    }

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
                tls13_ciphers: None,
                groups: "P-256:X25519:P-384".to_string(),
                key_shares: None,
                grease: true,
                grease_sigalgs: false,
                sigalgs: None,
                cert_compression: None,
                alps: None,
                trust_anchors: None,
                server_padding: None,
                ech_grease: false,
                ocsp_stapling: true,
                sct: true,
                session_ticket: true,
                permute_extensions: true,
            }
        );
        assert!(check_tls_options().is_ok());

        std::env::set_var("AETHER_TLS_CIPHERS", " ECDHE-RSA-AES128-GCM-SHA256 ");
        std::env::set_var(
            "AETHER_TLS13_CIPHERS",
            " TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256 ",
        );
        std::env::set_var("AETHER_TLS_GROUPS", "X25519:P-256");
        std::env::set_var("AETHER_TLS_KEY_SHARES", " X25519:P-256 ");
        for (value, greased) in [("1", false), ("on", false), ("TRUE", false), ("0", true)] {
            std::env::set_var("AETHER_DISABLE_GREASE", value);
            assert_eq!(
                Fingerprint::configured(),
                Fingerprint {
                    ciphers: Some("ECDHE-RSA-AES128-GCM-SHA256".to_string()),
                    tls13_ciphers: Some(
                        "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256".to_string()
                    ),
                    groups: "X25519:P-256".to_string(),
                    key_shares: Some("X25519:P-256".to_string()),
                    grease: greased,
                    ..Fingerprint::default()
                },
                "{value}"
            );
        }
        assert!(check_tls_options().is_ok());
        for (value, on) in [("1", true), ("yes", true), ("0", false), ("", false)] {
            std::env::set_var("AETHER_ENABLE_GREASE_SIGALGS", value);
            assert_eq!(Fingerprint::configured().grease_sigalgs, on, "{value}");
            std::env::set_var("AETHER_ENABLE_ECH_GREASE", value);
            assert_eq!(Fingerprint::configured().ech_grease, on, "{value}");
            std::env::set_var("AETHER_DISABLE_OCSP_STAPLING", value);
            assert_eq!(Fingerprint::configured().ocsp_stapling, !on, "{value}");
            std::env::set_var("AETHER_DISABLE_SCT", value);
            assert_eq!(Fingerprint::configured().sct, !on, "{value}");
            std::env::set_var("AETHER_DISABLE_SESSION_TICKET", value);
            assert_eq!(Fingerprint::configured().session_ticket, !on, "{value}");
            std::env::set_var("AETHER_DISABLE_EXTENSION_PERMUTATION", value);
            assert_eq!(Fingerprint::configured().permute_extensions, !on, "{value}");
        }
        for variable in [
            "AETHER_ENABLE_GREASE_SIGALGS",
            "AETHER_ENABLE_ECH_GREASE",
            "AETHER_DISABLE_OCSP_STAPLING",
            "AETHER_DISABLE_SCT",
            "AETHER_DISABLE_SESSION_TICKET",
            "AETHER_DISABLE_EXTENSION_PERMUTATION",
        ] {
            std::env::remove_var(variable);
        }

        // The options with a value: trimmed, and none when blank.
        std::env::set_var("AETHER_TLS_SIGALGS", " ecdsa_secp256r1_sha256:mldsa65 ");
        std::env::set_var("AETHER_TLS_CERT_COMPRESSION", " zlib:brotli:zstd ");
        std::env::set_var("AETHER_TLS_ALPS", " old ");
        std::env::set_var("AETHER_TLS_TRUST_ANCHORS", " 11129.9.1:44947.2.6 ");
        std::env::set_var("AETHER_TLS_SERVER_PADDING", " 6000 ");
        let given = Fingerprint::configured();
        assert_eq!(
            given.sigalgs.as_deref(),
            Some("ecdsa_secp256r1_sha256:mldsa65")
        );
        assert_eq!(given.cert_compression.as_deref(), Some("zlib:brotli:zstd"));
        assert_eq!(given.alps.as_deref(), Some("old"));
        assert_eq!(given.trust_anchors.as_deref(), Some("11129.9.1:44947.2.6"));
        assert_eq!(given.server_padding.as_deref(), Some("6000"));
        assert!(check_tls_options().is_ok());
        for refused in [
            (
                "AETHER_TLS_SIGALGS",
                "ecdsa_secp256r1_sha256:ed448",
                "--tls-sigalgs",
            ),
            (
                "AETHER_TLS_SIGALGS",
                "rsa_pkcs1_sha256:rsa_pkcs1_sha256",
                "--tls-sigalgs",
            ),
            ("AETHER_TLS_SIGALGS", "rsa_pkcs1_md5_sha1", "--tls-sigalgs"),
            (
                "AETHER_TLS_SIGALGS",
                "ecdsa_secp256r1_sha256:",
                "--tls-sigalgs",
            ),
            (
                "AETHER_TLS_CERT_COMPRESSION",
                "brotli:lzma",
                "--tls-cert-compression",
            ),
            (
                "AETHER_TLS_CERT_COMPRESSION",
                "zlib:zlib",
                "--tls-cert-compression",
            ),
            ("AETHER_TLS_ALPS", "h2", "--tls-alps"),
            (
                "AETHER_TLS_TRUST_ANCHORS",
                "11129.9.01",
                "--tls-trust-anchors",
            ),
            (
                "AETHER_TLS_TRUST_ANCHORS",
                "11129..9",
                "--tls-trust-anchors",
            ),
            (
                "AETHER_TLS_TRUST_ANCHORS",
                "11129.9.1:",
                "--tls-trust-anchors",
            ),
            ("AETHER_TLS_TRUST_ANCHORS", "0x2b.6", "--tls-trust-anchors"),
            ("AETHER_TLS_SERVER_PADDING", "65536", "--tls-server-padding"),
            ("AETHER_TLS_SERVER_PADDING", "-1", "--tls-server-padding"),
        ] {
            let (variable, value, flag) = refused;
            let kept = std::env::var(variable).expect("a value given above");
            std::env::set_var(variable, value);
            let error = check_tls_options().expect_err(value);
            assert!(
                error.to_string().starts_with(&format!("tls: {flag}: ")),
                "{value}: {error}"
            );
            std::env::set_var(variable, kept);
        }
        assert!(check_tls_options().is_ok());
        for variable in [
            "AETHER_TLS_SIGALGS",
            "AETHER_TLS_CERT_COMPRESSION",
            "AETHER_TLS_ALPS",
            "AETHER_TLS_TRUST_ANCHORS",
            "AETHER_TLS_SERVER_PADDING",
        ] {
            std::env::remove_var(variable);
        }

        // A TLS 1.3 suite list BoringSSL takes: standard names of TLS 1.3 suites, each once.
        for list in [
            "TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256",
            "TLS_AES_128_GCM_SHA256:TLS_AES_128_GCM_SHA256",
            "TLS_AES_128_GCM_SHA256:",
            "AES128-GCM-SHA256",
        ] {
            std::env::set_var("AETHER_TLS13_CIPHERS", list);
            let refused = check_tls_options().expect_err(list);
            assert!(
                refused.to_string().starts_with("tls: --tls13-ciphers: "),
                "{list}: {refused}"
            );
        }
        std::env::remove_var("AETHER_TLS13_CIPHERS");

        // Key shares: groups of the list, in its order, each once, as --tls-groups names them
        // (x25519 for X25519).
        std::env::set_var("AETHER_TLS_GROUPS", "X25519MLKEM768:X25519:P-256:P-384");
        for list in [
            "X25519MLKEM768",
            "X25519MLKEM768:x25519:prime256v1",
            "P-256:P-384",
        ] {
            std::env::set_var("AETHER_TLS_KEY_SHARES", list);
            assert!(check_tls_options().is_ok(), "{list}");
        }
        for list in [
            "P-521",
            "P-256:X25519",
            "X25519:X25519",
            "X25519:P-999",
            "X25519:",
        ] {
            std::env::set_var("AETHER_TLS_KEY_SHARES", list);
            let refused = check_tls_options().expect_err(list);
            assert!(
                refused.to_string().starts_with("tls: --tls-key-shares: "),
                "{list}: {refused}"
            );
        }
        std::env::remove_var("AETHER_TLS_KEY_SHARES");
        std::env::set_var("AETHER_TLS_GROUPS", "X25519:P-256");

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

    #[tokio::test]
    async fn the_command_line_sets_the_tls13_order_and_the_key_shares() {
        let _options = hold_options().await;
        let words = [
            "--tls13-ciphers",
            "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256",
            "--tls-groups",
            "X25519MLKEM768:X25519:P-256",
            "--tls-key-shares",
            "X25519:P-256",
            "--enable-grease-sigalgs",
            "--tls-sigalgs",
            "mldsa44:ecdsa_secp256r1_sha256:ed25519",
            "--tls-cert-compression",
            "brotli:zstd",
            "--tls-alps",
            "new",
            "--tls-trust-anchors",
            "11129.9.1",
            "--tls-server-padding",
            "6000",
            "--enable-ech-grease",
            "--disable-ocsp-stapling",
            "--disable-sct",
            "--disable-session-ticket",
            "--disable-extension-permutation",
        ];
        let parsed = crate::cli::parse_args(words.iter().map(|word| word.to_string()).collect())
            .expect("options the core takes");
        assert!(parsed == crate::cli::Parsed::Run);
        let fingerprint = Fingerprint::configured();
        assert_eq!(
            fingerprint.tls13_ciphers.as_deref(),
            Some("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256")
        );
        assert_eq!(fingerprint.key_shares.as_deref(), Some("X25519:P-256"));
        assert!(fingerprint.grease_sigalgs);
        assert!(fingerprint.grease);
        assert_eq!(
            fingerprint.sigalgs.as_deref(),
            Some("mldsa44:ecdsa_secp256r1_sha256:ed25519")
        );
        assert_eq!(fingerprint.cert_compression.as_deref(), Some("brotli:zstd"));
        assert_eq!(fingerprint.alps.as_deref(), Some("new"));
        assert_eq!(fingerprint.trust_anchors.as_deref(), Some("11129.9.1"));
        assert_eq!(fingerprint.server_padding.as_deref(), Some("6000"));
        assert!(fingerprint.ech_grease);
        assert!(!fingerprint.ocsp_stapling);
        assert!(!fingerprint.sct);
        assert!(!fingerprint.session_ticket);
        assert!(!fingerprint.permute_extensions);
        assert!(check_tls_options().is_ok());
    }

    /// The ClientHello of `fingerprint`, offering HTTP/2, as a server on this machine reads it.
    async fn hello_of(fingerprint: &Fingerprint) -> client_hello::ClientHello {
        hello_offering(fingerprint, b"\x02h2").await
    }

    /// The ClientHello of `fingerprint`, offering `alpn` in wire format, as a server on this
    /// machine reads it.
    async fn hello_offering(fingerprint: &Fingerprint, alpn: &[u8]) -> client_hello::ClientHello {
        let (server, hello) = client_hello::catch().await;
        let mut builder = boring::ssl::SslConnector::builder(SslMethod::tls()).expect("tls");
        fingerprint
            .apply(&mut builder, alpn)
            .expect("the fingerprint");
        let mut config = builder.build().configure().expect("a configuration");
        fingerprint
            .prepare(&mut config, alpn)
            .expect("what goes on the connection");
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
        // Not among the signature algorithms, which take --enable-grease-sigalgs.
        assert!(!chrome.has_grease_signature_algorithm());
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
        assert!(!ungreased.has_grease_signature_algorithm());
        assert_eq!(ungreased.groups(), chrome.groups());

        // --enable-grease-sigalgs puts a GREASE value first among the signature algorithms, as
        // Chrome does, with the rest of GREASE or without it.
        for grease in [true, false] {
            let sigalgs = hello_of(&Fingerprint {
                grease,
                grease_sigalgs: true,
                ..Fingerprint::default()
            })
            .await;
            assert!(sigalgs.has_grease_signature_algorithm(), "{grease}");
            assert_eq!(
                sigalgs.signature_algorithms()[1..],
                chrome.signature_algorithms(),
                "{grease}"
            );
            assert_eq!(sigalgs.has_grease(), grease);
            assert_eq!(sigalgs.has_grease_extension(), grease);
        }

        let changed = hello_of(&Fingerprint {
            ciphers: Some("ECDHE-ECDSA-CHACHA20-POLY1305:AES256-SHA".to_string()),
            groups: "X25519:P-384".to_string(),
            grease: false,
            ..Fingerprint::default()
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

    #[tokio::test]
    async fn the_client_hello_takes_the_tls13_order_and_the_key_shares_of_the_options() {
        // Firefox's, as its ClientHello of October 2026 has them: its TLS 1.3 order, and key
        // shares for three of its groups, where BoringSSL would send two.
        let firefox = hello_of(&Fingerprint {
            tls13_ciphers: Some(
                "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384"
                    .to_string(),
            ),
            groups: "X25519MLKEM768:X25519:P-256:P-384:P-521".to_string(),
            key_shares: Some("X25519MLKEM768:X25519:P-256".to_string()),
            grease: false,
            ..Fingerprint::default()
        })
        .await;
        assert_eq!(firefox.tls13_suites(), [0x1301, 0x1303, 0x1302]);
        assert_eq!(firefox.groups(), [0x11ec, 0x001d, 0x0017, 0x0018, 0x0019]);
        assert_eq!(firefox.key_shares(), [0x11ec, 0x001d, 0x0017]);
        assert!(!firefox.has_grease());

        // Without them, BoringSSL's choice: the first group, and the first of the other kind.
        let groups = Fingerprint {
            groups: "X25519MLKEM768:X25519:P-256".to_string(),
            ..Fingerprint::default()
        };
        assert_eq!(hello_of(&groups).await.key_shares(), [0x11ec, 0x001d]);

        // Python's TLS 1.3 order, and one key share named as --tls-groups names it.
        let python = hello_of(&Fingerprint {
            tls13_ciphers: Some(
                "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
                    .to_string(),
            ),
            key_shares: Some("x25519".to_string()),
            ..groups
        })
        .await;
        assert_eq!(python.tls13_suites(), [0x1302, 0x1303, 0x1301]);
        assert_eq!(python.key_shares(), [0x001d]);
        // GREASE stays where it was: before the suites and among the key shares.
        assert!(python.has_grease());
        assert!(python.has_grease_key_share());
    }

    /// Chrome's signature algorithms of October 2026, after the GREASE value it leads them with.
    const CHROME_SIGALGS: &str = "mldsa44:mldsa65:mldsa87:ecdsa_secp256r1_sha256:\
        rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:\
        rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";

    /// Chrome 120's signature algorithms: Chrome's eight.
    const CHROME_120_SIGALGS: &str = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:\
        rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:\
        rsa_pss_rsae_sha512:rsa_pkcs1_sha512";

    /// Firefox's signature algorithms of October 2026.
    const FIREFOX_SIGALGS: &str = "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:\
        ecdsa_secp521r1_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:\
        rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:ecdsa_sha1:rsa_pkcs1_sha1";

    /// The trust anchor IDs of Chrome's ClientHello of October 2026.
    const CHROME_TRUST_ANCHORS: &str = "44947.2.1:44947.2.6:44947.2.13:44947.2.14:44947.2.15:\
        44947.2.18:44947.2.19:44947.2.20:52580.200109.1.7:52580.200109.1.8:52580.200109.1.9:\
        52580.200109.1.10:52580.200109.1.11:52580.200109.1.12:52580.200109.1.13:\
        52580.200109.1.18:52580.200109.1.19:11129.9.1:11129.9.4:11129.9.5:11129.9.6:11129.9.7:\
        11129.9.8:11129.9.10:11129.9.11:11129.9.12:11129.9.13:11129.9.15";

    /// HTTP/2 then HTTP/1.1, as every client of the captures offers them over TCP.
    const H2_HTTP1: &[u8] = b"\x02h2\x08http/1.1";

    #[test]
    fn the_signature_algorithms_go_by_boringssls_names() {
        assert_eq!(
            sigalg_ids(
                "mldsa44:mldsa65:mldsa87:ed25519:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:\
                 rsa_pkcs1_sha1:ecdsa_sha1:ecdsa_secp521r1_sha512"
            )
            .expect("names BoringSSL has"),
            [0x0904, 0x0905, 0x0906, 0x0807, 0x0403, 0x0804, 0x0201, 0x0203, 0x0603]
        );
        // ECDSA's names go with their curve; MD5-SHA1 only signs TLS 1.1 and older.
        for refused in [
            "ecdsa_sha256",
            "rsa_pkcs1_md5_sha1",
            "ed448",
            "",
            "RSA+SHA256",
        ] {
            assert!(sigalg_ids(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn trust_anchor_ids_go_on_the_wire_in_base_128() {
        assert_eq!(
            trust_anchor_ids("11129.9.1").expect("an ID"),
            [4, 0xd6, 0x79, 0x09, 0x01]
        );
        assert_eq!(
            trust_anchor_ids("44947.2.6:0").expect("two IDs"),
            [5, 0x82, 0xdf, 0x13, 0x02, 0x06, 1, 0x00]
        );
        // Chrome's, as its ClientHello carries them: 184 bytes.
        let chrome = trust_anchor_ids(CHROME_TRUST_ANCHORS).expect("Chrome's");
        assert_eq!(chrome.len(), 184);
        assert_eq!(chrome[..6], [5, 0x82, 0xdf, 0x13, 0x02, 0x01]);
        let too_long = ["18446744073709551615"; 30].join(".");
        for refused in [
            "",
            "1..2",
            ".1",
            "1.",
            "01",
            "1.x",
            "1:",
            "18446744073709551616",
            too_long.as_str(),
        ] {
            assert!(trust_anchor_ids(refused).is_err(), "{refused}");
        }
    }

    #[tokio::test]
    async fn the_client_hello_carries_the_extensions_of_the_options() {
        // Chrome's of October 2026, from its ClientHello: GREASE then ML-DSA first among the
        // signature algorithms, brotli, ALPS for HTTP/2 under the new codepoint, ECH GREASE,
        // its trust anchors and 6000 bytes of padding asked of the server.
        let chrome = Fingerprint {
            groups: "X25519MLKEM768:X25519:P-256:P-384".to_string(),
            grease_sigalgs: true,
            sigalgs: Some(CHROME_SIGALGS.to_string()),
            cert_compression: Some("brotli".to_string()),
            alps: Some("new".to_string()),
            trust_anchors: Some(CHROME_TRUST_ANCHORS.to_string()),
            server_padding: Some("6000".to_string()),
            ech_grease: true,
            ..Fingerprint::default()
        };
        let hello = hello_offering(&chrome, H2_HTTP1).await;
        assert!(hello.has_grease_signature_algorithm());
        assert_eq!(
            hello.signature_algorithms()[1..],
            [
                0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
                0x0601
            ]
        );
        assert_eq!(hello.cert_compression(), [2]);
        // ALPS for HTTP/2 alone, not for HTTP/1.1, under the new codepoint alone.
        assert_eq!(hello.alps(0x44cd), Some(vec![b"h2".to_vec()]));
        assert_eq!(hello.alps(0x4469), None);
        assert!(hello.offers_ech());
        let anchors = trust_anchor_ids(CHROME_TRUST_ANCHORS).expect("Chrome's");
        let mut wire = (anchors.len() as u16).to_be_bytes().to_vec();
        wire.extend(&anchors);
        assert_eq!(hello.extension(0xca34), Some(wire.as_slice()));
        assert_eq!(hello.server_padding(), Some(6000));
        // OCSP, signed certificate timestamps and the session ticket, as Chrome's.
        assert!(hello.has_extension(5) && hello.has_extension(18) && hello.has_extension(35));

        // Chrome 120's: ALPS under the old codepoint, its eight signature algorithms without
        // GREASE or ML-DSA, and neither trust anchors nor server padding.
        let chrome_120 = Fingerprint {
            groups: "X25519:P-256:P-384".to_string(),
            sigalgs: Some(CHROME_120_SIGALGS.to_string()),
            cert_compression: Some("brotli".to_string()),
            alps: Some("old".to_string()),
            ech_grease: true,
            ..Fingerprint::default()
        };
        let hello = hello_offering(&chrome_120, H2_HTTP1).await;
        assert_eq!(
            hello.signature_algorithms(),
            [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
        );
        assert_eq!(hello.alps(0x4469), Some(vec![b"h2".to_vec()]));
        assert_eq!(hello.alps(0x44cd), None);
        assert_eq!(hello.cert_compression(), [2]);
        assert!(hello.offers_ech());
        assert!(!hello.has_extension(0xca34));
        assert_eq!(hello.server_padding(), None);

        // Firefox's: zlib, brotli and zstd, no session ticket, and the extensions in one order,
        // BoringSSL's, the same on every handshake.
        let firefox = Fingerprint {
            grease: false,
            sigalgs: Some(FIREFOX_SIGALGS.to_string()),
            cert_compression: Some("zlib:brotli:zstd".to_string()),
            ech_grease: true,
            session_ticket: false,
            permute_extensions: false,
            ..Fingerprint::default()
        };
        let first = hello_offering(&firefox, H2_HTTP1).await;
        assert_eq!(
            first.signature_algorithms(),
            [
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201
            ]
        );
        assert_eq!(first.cert_compression(), [1, 2, 3]);
        assert!(!first.has_extension(35));
        assert!(first.offers_ech());
        assert!(first.has_extension(5) && first.has_extension(18));
        assert_eq!(first.alps(0x44cd), None);
        assert_eq!(first.alps(0x4469), None);
        for _ in 0..3 {
            let again = hello_offering(&firefox, H2_HTTP1).await;
            assert_eq!(again.extension_types(), first.extension_types());
        }
        assert_eq!(
            first.extension_types(),
            [0, 0xfe0d, 23, 0xff01, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27]
        );

        // Python's: no OCSP, no signed certificate timestamps, one order, and so no padding
        // extension, which BoringSSL adds when a shuffled order ends on an empty extension.
        let python = Fingerprint {
            grease: false,
            ocsp_stapling: false,
            sct: false,
            permute_extensions: false,
            ..Fingerprint::default()
        };
        for _ in 0..3 {
            let hello = hello_offering(&python, H2_HTTP1).await;
            assert_eq!(
                hello.extension_types(),
                [0, 23, 0xff01, 10, 11, 35, 16, 13, 51, 45, 43]
            );
        }
    }

    extern "C" {
        fn CBB_add_bytes(cbb: *mut c_void, data: *const u8, len: usize) -> c_int;
        fn SSL_has_application_settings(ssl: *const c_void) -> c_int;
        fn SSL_get0_peer_application_settings(
            ssl: *const c_void,
            out_data: *mut *const u8,
            out_len: *mut usize,
        );
    }

    /// How many certificates the servers of the tests compressed.
    static COMPRESSED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    /// Hands BoringSSL, in `out`, what `compress` makes of the certificate at `input`, as a
    /// server compresses one.
    unsafe fn compressed(
        out: *mut c_void,
        input: *const u8,
        input_len: usize,
        compress: fn(&[u8]) -> Vec<u8>,
    ) -> c_int {
        let input = unsafe { std::slice::from_raw_parts(input, input_len) };
        let bytes = compress(input);
        COMPRESSED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        unsafe { CBB_add_bytes(out, bytes.as_ptr(), bytes.len()) }
    }

    fn zlib_of(input: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(input).expect("zlib");
        encoder.finish().expect("zlib")
    }

    fn zstd_of(input: &[u8]) -> Vec<u8> {
        zstd::bulk::compress(input, 3).expect("zstd")
    }

    /// Zstd whose frame asks for a window of 2^`window_log` bytes, whatever the input: without
    /// its length, which would make the window the input's.
    fn zstd_window_of(input: &[u8], window_log: u32) -> Vec<u8> {
        use std::io::Write;
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3).expect("zstd");
        encoder.include_contentsize(false).expect("no length");
        encoder.window_log(window_log).expect("the window");
        encoder.write_all(input).expect("zstd");
        encoder.finish().expect("zstd")
    }

    /// Brotli (RFC 7932) without compression, which the brotli crate the core decompresses with
    /// cannot make: a window of 2^16, the input in meta-blocks stored as they are, 65536 bytes
    /// at most each, then an empty last one.
    fn brotli_of(input: &[u8]) -> Vec<u8> {
        struct Bits {
            out: Vec<u8>,
            byte: u8,
            used: u32,
        }
        impl Bits {
            /// The `count` low bits of `value`, the lowest first.
            fn put(&mut self, value: u32, count: u32) {
                for bit in 0..count {
                    self.byte |= (((value >> bit) & 1) as u8) << self.used;
                    self.used += 1;
                    if self.used == 8 {
                        self.align();
                    }
                }
            }
            fn align(&mut self) {
                if self.used > 0 {
                    self.out.push(self.byte);
                    self.byte = 0;
                    self.used = 0;
                }
            }
        }
        let mut bits = Bits {
            out: Vec::new(),
            byte: 0,
            used: 0,
        };
        bits.put(0, 1); // WBITS: 16
        for block in input.chunks(65536) {
            bits.put(0, 1); // ISLAST
            bits.put(0, 2); // MNIBBLES: 4
            bits.put(block.len() as u32 - 1, 16); // MLEN - 1
            bits.put(1, 1); // ISUNCOMPRESSED
            bits.align();
            bits.out.extend_from_slice(block);
        }
        bits.put(1, 1); // ISLAST
        bits.put(1, 1); // ISLASTEMPTY
        bits.align();
        bits.out
    }

    #[test]
    fn the_test_brotli_is_brotli() {
        let input: Vec<u8> = (0..70000u32).map(|n| (n % 251) as u8).collect();
        let mut out = vec![0u8; input.len()];
        assert!(brotli_into(&brotli_of(&input), &mut out));
        assert_eq!(out, input);
    }

    /// Whether a handshake of `client`, offering HTTP/2, goes through with a server on this
    /// machine that compresses its certificate as algorithm `id` with `compress`.
    async fn handshake_with_compression(
        client: &Fingerprint,
        id: u16,
        compress: CertCompressFn,
    ) -> bool {
        let pair = crate::account::generate_masque_keypair().expect("a key and a certificate");
        let mut builder =
            boring::ssl::SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("tls");
        builder
            .set_certificate(&X509::from_pem(&pair.cert_pem).expect("a certificate"))
            .expect("the certificate");
        builder
            .set_private_key(&PKey::private_key_from_pem(&pair.key_pem).expect("a key"))
            .expect("the key");
        let added = unsafe {
            SSL_CTX_add_cert_compression_alg(builder.as_ptr().cast(), id, Some(compress), None)
        };
        assert_eq!(added, 1, "the server's compression");
        let acceptor = builder.build();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let address = listener.local_addr().expect("its address");
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("a connection");
            if let Ok(mut stream) = tokio_boring::accept(&acceptor, tcp).await {
                // Until the client hangs up.
                let mut byte = [0u8; 1];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut byte).await;
            }
        });
        let mut connector = boring::ssl::SslConnector::builder(SslMethod::tls()).expect("tls");
        client
            .apply(&mut connector, b"\x02h2")
            .expect("the fingerprint");
        let mut config = connector.build().configure().expect("a configuration");
        client
            .prepare(&mut config, b"\x02h2")
            .expect("what goes on the connection");
        let tcp = tokio::net::TcpStream::connect(address)
            .await
            .expect("a connection");
        let done = tokio_boring::connect(config, "localhost", tcp)
            .await
            .is_ok();
        server.await.expect("the server");
        done
    }

    #[tokio::test]
    async fn a_certificate_sent_compressed_is_decompressed() {
        unsafe extern "C" fn zlib_server(
            _: *mut c_void,
            out: *mut c_void,
            input: *const u8,
            len: usize,
        ) -> c_int {
            unsafe { compressed(out, input, len, zlib_of) }
        }
        unsafe extern "C" fn brotli_server(
            _: *mut c_void,
            out: *mut c_void,
            input: *const u8,
            len: usize,
        ) -> c_int {
            unsafe { compressed(out, input, len, brotli_of) }
        }
        unsafe extern "C" fn zstd_server(
            _: *mut c_void,
            out: *mut c_void,
            input: *const u8,
            len: usize,
        ) -> c_int {
            unsafe { compressed(out, input, len, zstd_of) }
        }
        // A certificate one byte short of the length the server gives, and one byte over it.
        unsafe extern "C" fn short_zlib_server(
            _: *mut c_void,
            out: *mut c_void,
            input: *const u8,
            len: usize,
        ) -> c_int {
            unsafe { compressed(out, input, len, |input| zlib_of(&input[..input.len() - 1])) }
        }
        unsafe extern "C" fn long_brotli_server(
            _: *mut c_void,
            out: *mut c_void,
            input: *const u8,
            len: usize,
        ) -> c_int {
            unsafe { compressed(out, input, len, |input| brotli_of(&[input, &[0]].concat())) }
        }
        unsafe extern "C" fn short_brotli_server(
            _: *mut c_void,
            out: *mut c_void,
            input: *const u8,
            len: usize,
        ) -> c_int {
            unsafe {
                compressed(out, input, len, |input| {
                    brotli_of(&input[..input.len() - 1])
                })
            }
        }
        unsafe extern "C" fn long_zstd_server(
            _: *mut c_void,
            out: *mut c_void,
            input: *const u8,
            len: usize,
        ) -> c_int {
            unsafe { compressed(out, input, len, |input| zstd_of(&[input, &[0]].concat())) }
        }
        // A frame that asks for the largest window the core takes, and one that asks for twice.
        unsafe extern "C" fn widest_zstd_server(
            _: *mut c_void,
            out: *mut c_void,
            input: *const u8,
            len: usize,
        ) -> c_int {
            unsafe {
                compressed(out, input, len, |input| {
                    zstd_window_of(input, ZSTD_WINDOW_LOG_MAX)
                })
            }
        }
        unsafe extern "C" fn too_wide_zstd_server(
            _: *mut c_void,
            out: *mut c_void,
            input: *const u8,
            len: usize,
        ) -> c_int {
            unsafe {
                compressed(out, input, len, |input| {
                    zstd_window_of(input, ZSTD_WINDOW_LOG_MAX + 1)
                })
            }
        }
        let offering = |list: &str| Fingerprint {
            cert_compression: Some(list.to_string()),
            ..Fingerprint::default()
        };
        let count = || COMPRESSED.load(std::sync::atomic::Ordering::SeqCst);

        for (name, id, server) in [
            ("zlib", 1, zlib_server as CertCompressFn),
            ("brotli", 2, brotli_server),
            ("zstd", 3, zstd_server),
        ] {
            let before = count();
            assert!(
                handshake_with_compression(&offering(name), id, server).await,
                "{name}"
            );
            assert_eq!(
                count(),
                before + 1,
                "{name}: the certificate went compressed"
            );
            // Offered among the others.
            assert!(
                handshake_with_compression(&offering("zlib:brotli:zstd"), id, server).await,
                "{name} among the three"
            );
        }
        // The decompressed certificate is exactly as long as the server said, or the
        // handshake fails.
        for (name, id, server) in [
            ("zlib", 1, short_zlib_server as CertCompressFn),
            ("brotli", 2, short_brotli_server),
            ("brotli", 2, long_brotli_server),
            ("zstd", 3, long_zstd_server),
        ] {
            let before = count();
            assert!(
                !handshake_with_compression(&offering(name), id, server).await,
                "{name}"
            );
            assert_eq!(count(), before + 1, "{name}: the server compressed");
        }
        // A zstd frame may ask for a window of 8 MiB at most: a server gets no more of the
        // client's memory than that.
        let zstd = offering("zstd");
        assert!(handshake_with_compression(&zstd, 3, widest_zstd_server).await);
        assert!(!handshake_with_compression(&zstd, 3, too_wide_zstd_server).await);
        // Without the option, the certificate goes as it is.
        let before = count();
        assert!(handshake_with_compression(&Fingerprint::default(), 2, brotli_server).await);
        assert_eq!(count(), before);
    }

    #[tokio::test]
    async fn alps_goes_through_with_a_server_that_takes_it() {
        for (codepoint, new) in [("new", true), ("old", false)] {
            let pair = crate::account::generate_masque_keypair().expect("a key and a certificate");
            let mut builder =
                boring::ssl::SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("tls");
            builder
                .set_certificate(&X509::from_pem(&pair.cert_pem).expect("a certificate"))
                .expect("the certificate");
            builder
                .set_private_key(&PKey::private_key_from_pem(&pair.key_pem).expect("a key"))
                .expect("the key");
            builder.set_alpn_select_callback(|_, offered| {
                boring::ssl::select_next_proto(b"\x02h2", offered)
                    .ok_or(boring::ssl::AlpnError::NOACK)
            });
            let acceptor = builder.build();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("a port");
            let address = listener.local_addr().expect("its address");
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.expect("a connection");
                let ssl = Ssl::new(acceptor.context()).expect("a connection");
                unsafe {
                    SSL_set_alps_use_new_codepoint(ssl.as_ptr().cast(), c_int::from(new));
                    let settings = b"the server's settings";
                    let added = SSL_add_application_settings(
                        ssl.as_ptr().cast(),
                        b"h2".as_ptr(),
                        2,
                        settings.as_ptr(),
                        settings.len(),
                    );
                    assert_eq!(added, 1);
                }
                if let Ok(mut stream) = tokio_boring::SslStreamBuilder::new(ssl, tcp).accept().await
                {
                    let mut byte = [0u8; 1];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut byte).await;
                }
            });
            let client = Fingerprint {
                alps: Some(codepoint.to_string()),
                ..Fingerprint::default()
            };
            let mut connector = boring::ssl::SslConnector::builder(SslMethod::tls()).expect("tls");
            client
                .apply(&mut connector, H2_HTTP1)
                .expect("the fingerprint");
            let mut config = connector.build().configure().expect("a configuration");
            client
                .prepare(&mut config, H2_HTTP1)
                .expect("what goes on the connection");
            let tcp = tokio::net::TcpStream::connect(address)
                .await
                .expect("a connection");
            let stream = tokio_boring::connect(config, "localhost", tcp)
                .await
                .expect("a handshake");
            let ssl = stream.ssl();
            assert_eq!(
                ssl.selected_alpn_protocol(),
                Some(&b"h2"[..]),
                "{codepoint}"
            );
            assert_eq!(
                unsafe { SSL_has_application_settings(ssl.as_ptr().cast()) },
                1,
                "{codepoint}"
            );
            let (mut data, mut len) = (ptr::null(), 0);
            unsafe { SSL_get0_peer_application_settings(ssl.as_ptr().cast(), &mut data, &mut len) };
            assert_eq!(
                unsafe { std::slice::from_raw_parts(data, len) },
                b"the server's settings",
                "{codepoint}"
            );
            drop(stream);
            server.await.expect("the server");
        }
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
        /// What the extension `kind` carries, when it is there.
        pub fn extension(&self, kind: u16) -> Option<&[u8]> {
            self.extensions
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, data)| data.as_slice())
        }

        /// The algorithms of compress_certificate, in order; empty without it.
        pub fn cert_compression(&self) -> Vec<u16> {
            self.extension(27)
                .map(|data| {
                    data[1..1 + data[0] as usize]
                        .chunks(2)
                        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                        .collect()
                })
                .unwrap_or_default()
        }

        /// The protocols of application_settings, under the codepoint `kind` (0x44cd or 0x4469),
        /// in order, when it is there.
        pub fn alps(&self, kind: u16) -> Option<Vec<Vec<u8>>> {
            let data = self.extension(kind)?;
            let mut protocols = Vec::new();
            let mut at = 2;
            while at < data.len() {
                let len = data[at] as usize;
                protocols.push(data[at + 1..at + 1 + len].to_vec());
                at += 1 + len;
            }
            Some(protocols)
        }

        /// The bytes of padding the server_padding extension (0x12e0) asks for, when it is there.
        pub fn server_padding(&self) -> Option<u16> {
            self.extension(0x12e0)
                .map(|data| u16::from_be_bytes([data[0], data[1]]))
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

        /// The groups of the shares of key_share, in order, GREASE among them.
        fn key_share_groups(&self) -> Vec<u16> {
            let data = self.extension(51).expect("key_share");
            let mut groups = Vec::new();
            let mut at = 2;
            while at + 4 <= data.len() {
                groups.push(be16(data, at) as u16);
                at += 4 + be16(data, at + 2);
            }
            groups
        }

        /// The groups of the shares of key_share, in order, GREASE left out.
        pub fn key_shares(&self) -> Vec<u16> {
            self.key_share_groups()
                .into_iter()
                .filter(|group| !grease(*group))
                .collect()
        }

        /// Whether one of the shares of key_share is a GREASE one.
        pub fn has_grease_key_share(&self) -> bool {
            self.key_share_groups().into_iter().any(grease)
        }

        /// The TLS 1.3 cipher suites, in order.
        pub fn tls13_suites(&self) -> Vec<u16> {
            self.suites
                .iter()
                .copied()
                .filter(|suite| (0x1301..=0x1305).contains(suite))
                .collect()
        }

        /// The signature algorithms of signature_algorithms, in order, GREASE among them.
        pub fn signature_algorithms(&self) -> Vec<u16> {
            let data = self.extension(13).expect("signature_algorithms");
            data[2..2 + be16(data, 0)]
                .chunks(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect()
        }

        /// Whether a GREASE value leads its signature algorithms.
        pub fn has_grease_signature_algorithm(&self) -> bool {
            self.signature_algorithms()
                .first()
                .is_some_and(|value| grease(*value))
        }
    }

    /// The ClientHello in `record`, a TLS record as it goes over the wire.
    pub fn parse(record: &[u8]) -> ClientHello {
        assert_eq!(record[0], 0x16, "a handshake record");
        let message = &record[5..5 + be16(record, 3)];
        assert_eq!(message[0], 1, "a ClientHello");
        parse_body(&message[4..])
    }

    /// The ClientHello whose body is `hello`: what follows its handshake header, as BoringSSL
    /// hands a server the ClientHello of a QUIC connection.
    pub fn parse_body(hello: &[u8]) -> ClientHello {
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

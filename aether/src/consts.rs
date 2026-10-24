/// The name the calls to the WARP API go by unless --api-host or --api-sni names another: the one
/// the Cloudflare One client calls since its 2026.6.0, on addresses of its own.
pub const API_HOST: &str = "api.devices.cloudflare.com";
/// The API's other name, on Cloudflare's shared addresses, which the WARP clients called before:
/// an attempt API_HOST does not serve, with no answer or with a refusal of another server than the
/// API, goes by this one next.
pub const API_FALLBACK_HOST: &str = "api.cloudflareclient.com";
pub const API_VERSION: &str = "v0a4471";

pub const API_FRONT_ADDRESSES: [&str; 2] = ["104.24.4.6", "104.18.0.6"];

pub const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
/// The server name the MASQUE handshakes send unless --masque-sni names another, in place of
/// CONNECT_SNI, the one the WARP client sends.
pub const DEFAULT_MASQUE_SNI: &str = "www.cloudflare.com";
pub const L4_CONNECT_SNI: &str = "consumer-masque-proxy.cloudflareclient.com";
pub const CONNECT_URI: &str = "https://cloudflareaccess.com";

pub const ECH_PUBLIC_NAME: &str = "cloudflare-ech.com";

pub const DEFAULT_MODEL: &str = "PC";
pub const DEFAULT_LOCALE: &str = "en_US";

pub const KEY_TYPE_MASQUE: &str = "secp256r1";
pub const TUN_TYPE_MASQUE: &str = "masque";

pub const UA_REGISTER: &str = "WARP for Android";
pub const CF_CLIENT_VERSION: &str = "a-6.35-4471";

pub const ALPN_H3: &[u8] = b"h3";

pub const CF_CONNECT_PROTOCOL: &str = "cf-connect-ip";

pub const H3_DATAGRAM_00: u64 = 0x276;

pub const CONNECT_IP_CONTEXT_ID: u64 = 0;

pub const CDN_ANYCAST_POOL: &[&str] = &[
    "104.16.0.0",
    "104.17.0.0",
    "104.18.0.0",
    "104.19.0.0",
    "104.20.0.0",
    "104.21.0.0",
    "104.22.0.0",
    "104.24.0.0",
    "104.25.0.0",
    "104.26.0.0",
    "104.27.0.0",
    "104.28.0.0",
    "172.64.0.0",
    "172.65.0.0",
    "172.66.0.0",
    "172.67.0.0",
    "188.114.96.0",
    "188.114.97.0",
    "188.114.98.0",
    "188.114.99.0",
];

pub const QUIC_PORT: u16 = 443;

/// SHA-256 SPKI hashes of Cloudflare MASQUE edge certificates.
/// Used for certificate pinning to prevent MITM attacks while allowing
/// SslVerifyMode::NONE at the library level (required because Cloudflare
/// edges serve different certs per SNI and some are self-signed).
///
/// Format: raw 32-byte hex (no base64, no colons).
pub const MASQUE_PINS: &[&[u8]] = &[
    // masque.cloudflareclient.com — self-signed by Cloudflare (2024-02-27 Self-Signed Root)
    // Returned when SNI is empty or unrecognized
    b"\xeb\x59\x1b\x36\xab\x26\xba\x61\x7e\x98\x37\x19\x18\xc1\x0b\xcd\xea\xe3\x74\x2d\xb6\xe7\x65\x43\xf9\x4b\xe5\x24\xdc\xe1\xd5\x55",
    b"\x2a\x38\xb6\x9b\x25\x66\x96\xc0\x9a\x11\xfb\xf1\x47\x4f\xe3\x90\x23\x63\x63\x3a\xb0\x0d\xd9\xc2\x97\xb2\xde\x64\x9b\x72\xd7\x2e",
    // cloudflareaccess.com — signed by Google Trust Services WE1
    // Returned when SNI=cloudflareaccess.com
    b"\x3f\xbb\x1d\x74\x52\xd3\x2b\x38\x81\xeb\x4b\x5d\x48\x42\x14\x45\xb6\xb9\xd8\xf5\x22\x59\x59\xf0\x33\x53\x2d\x50\x26\x37\xb0\x40",
];

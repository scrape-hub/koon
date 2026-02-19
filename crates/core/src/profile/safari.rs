use std::borrow::Cow;

use crate::http2::config::{
    Http2Config, PseudoHeader, SettingId,
};
use crate::tls::config::{
    AlpnProtocol, CertCompression, TlsConfig, TlsVersion,
};

use super::BrowserProfile;

/// Safari browser profile factory.
///
/// Supports Safari 15.6, 16.0, 17.0, 18.0, and 18.3.
/// Safari is macOS-only. Profile data sourced from tls-client (bogdanfinn)
/// and public fingerprint databases, cross-referenced for accuracy.
///
/// Key evolution:
/// - Safari 15.x-16.x: H2 initial_window=4MB, pseudo m/sc/p/a
/// - Safari 17.x: H2 initial_window drops to 2MB
/// - Safari 18.0+: pseudo order changes to m/sc/a/p, adds no_rfc7540_priorities
/// - Safari 18.3+: removes ecdsa_sha1 from sigalgs
pub struct Safari;

impl Safari {
    // ========== Safari 15.6 (macOS Monterey 12.5) ==========
    pub fn v15_6_macos() -> BrowserProfile {
        BrowserProfile {
            tls: safari_tls_legacy(),
            http2: safari_http2_v15(),
            quic: None,
            headers: safari_headers("15.6"),
        }
    }

    // ========== Safari 16.0 (macOS Ventura 13.0) ==========
    pub fn v16_0_macos() -> BrowserProfile {
        BrowserProfile {
            tls: safari_tls_legacy(),
            http2: safari_http2_v15(),
            quic: None,
            headers: safari_headers("16.0"),
        }
    }

    // ========== Safari 17.0 (macOS Sonoma 14.0) ==========
    pub fn v17_0_macos() -> BrowserProfile {
        BrowserProfile {
            tls: safari_tls_legacy(),
            http2: safari_http2_v17(),
            quic: None,
            headers: safari_headers("17.0"),
        }
    }

    // ========== Safari 18.0 (macOS Sequoia 15.0) ==========
    pub fn v18_0_macos() -> BrowserProfile {
        BrowserProfile {
            tls: safari_tls_legacy(),
            http2: safari_http2_v18(),
            quic: None,
            headers: safari_headers("18.0"),
        }
    }

    // ========== Safari 18.3 (macOS Sequoia 15.3) ==========
    pub fn v18_3_macos() -> BrowserProfile {
        BrowserProfile {
            tls: safari_tls_v18_3(),
            http2: safari_http2_v18(),
            quic: None,
            headers: safari_headers("18.3"),
        }
    }

    /// Latest Safari profile (currently v18.3 on macOS).
    pub fn latest() -> BrowserProfile {
        Self::v18_3_macos()
    }
}

// ========== Cipher list ==========
// Same across Safari 15.x through 18.x — includes legacy 3DES.
const SAFARI_CIPHER_LIST: &str = "\
TLS_AES_128_GCM_SHA256:\
TLS_AES_256_GCM_SHA384:\
TLS_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:\
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:\
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:\
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:\
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:\
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:\
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:\
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:\
TLS_RSA_WITH_AES_256_GCM_SHA384:\
TLS_RSA_WITH_AES_128_GCM_SHA256:\
TLS_RSA_WITH_AES_256_CBC_SHA:\
TLS_RSA_WITH_AES_128_CBC_SHA:\
TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:\
TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:\
TLS_RSA_WITH_3DES_EDE_CBC_SHA";

const SAFARI_CURVES: &str = "X25519:P-256:P-384:P-521";

// Safari 15.x–18.0: includes ecdsa_sha1
const SAFARI_SIGALGS_LEGACY: &str = "\
ecdsa_secp256r1_sha256:\
rsa_pss_rsae_sha256:\
rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:\
ecdsa_sha1:\
rsa_pss_rsae_sha384:\
rsa_pkcs1_sha384:\
rsa_pss_rsae_sha512:\
rsa_pkcs1_sha512:\
rsa_pkcs1_sha1";

// Safari 18.3+: ecdsa_sha1 removed, ecdsa_secp521r1_sha512 added
const SAFARI_SIGALGS_V18_3: &str = "\
ecdsa_secp256r1_sha256:\
rsa_pss_rsae_sha256:\
rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:\
rsa_pss_rsae_sha384:\
ecdsa_secp521r1_sha512:\
rsa_pss_rsae_sha512:\
rsa_pkcs1_sha384:\
rsa_pkcs1_sha512:\
rsa_pkcs1_sha1";

// ========== TLS configs ==========

// Safari 15.x through 18.0 — includes ecdsa_sha1
fn safari_tls_legacy() -> TlsConfig {
    TlsConfig {
        cipher_list: Cow::Borrowed(SAFARI_CIPHER_LIST),
        curves: Cow::Borrowed(SAFARI_CURVES),
        sigalgs: Cow::Borrowed(SAFARI_SIGALGS_LEGACY),
        alpn: vec![AlpnProtocol::Http2, AlpnProtocol::Http11],
        alps: None,
        alps_use_new_codepoint: false,
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
        grease: true,
        ech_grease: false,
        permute_extensions: false,
        ocsp_stapling: true,
        signed_cert_timestamps: true,
        cert_compression: vec![CertCompression::Zlib],
        pre_shared_key: false,
        session_ticket: false,
        key_shares_limit: None,
        delegated_credentials: None,
        danger_accept_invalid_certs: false,
    }
}

// Safari 18.3+ — ecdsa_sha1 removed, ecdsa_secp521r1_sha512 added
fn safari_tls_v18_3() -> TlsConfig {
    TlsConfig {
        sigalgs: Cow::Borrowed(SAFARI_SIGALGS_V18_3),
        ..safari_tls_legacy()
    }
}

// ========== HTTP/2 configs ==========

// Safari 15.x–16.x: 4MB initial window, old pseudo order, basic settings
fn safari_http2_v15() -> Http2Config {
    Http2Config {
        header_table_size: None,
        enable_push: Some(false),
        max_concurrent_streams: Some(100),
        initial_window_size: 4194304,
        max_frame_size: None,
        max_header_list_size: None,
        initial_conn_window_size: 10485760,
        pseudo_header_order: vec![
            PseudoHeader::Method,
            PseudoHeader::Scheme,
            PseudoHeader::Path,
            PseudoHeader::Authority,
        ],
        settings_order: vec![
            SettingId::InitialWindowSize,
            SettingId::MaxConcurrentStreams,
        ],
        headers_stream_dependency: None,
        priorities: Vec::new(),
        no_rfc7540_priorities: None,
        enable_connect_protocol: None,
    }
}

// Safari 17.x: 2MB initial window (reduced), still old pseudo order
fn safari_http2_v17() -> Http2Config {
    Http2Config {
        initial_window_size: 2097152,
        ..safari_http2_v15()
    }
}

// Safari 18.0+: 2MB window, NEW pseudo order (a before p), NoRFC7540+ConnectProtocol
fn safari_http2_v18() -> Http2Config {
    Http2Config {
        header_table_size: None,
        enable_push: Some(false),
        max_concurrent_streams: Some(100),
        initial_window_size: 2097152,
        max_frame_size: None,
        max_header_list_size: None,
        initial_conn_window_size: 10485760,
        pseudo_header_order: vec![
            PseudoHeader::Method,
            PseudoHeader::Scheme,
            PseudoHeader::Authority,
            PseudoHeader::Path,
        ],
        settings_order: vec![
            SettingId::HeaderTableSize,
            SettingId::EnablePush,
            SettingId::MaxConcurrentStreams,
            SettingId::InitialWindowSize,
            SettingId::MaxFrameSize,
            SettingId::MaxHeaderListSize,
            SettingId::EnableConnectProtocol,
            SettingId::NoRfc7540Priorities,
        ],
        headers_stream_dependency: None,
        priorities: Vec::new(),
        no_rfc7540_priorities: Some(true),
        enable_connect_protocol: Some(true),
    }
}

// ========== Headers ==========

fn safari_headers(version: &str) -> Vec<(String, String)> {
    let ua = format!(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version} Safari/605.1.15"
    );
    vec![
        ("sec-fetch-dest".into(), "document".into()),
        ("user-agent".into(), ua),
        ("accept".into(), "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into()),
        ("sec-fetch-site".into(), "none".into()),
        ("sec-fetch-mode".into(), "navigate".into()),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        ("priority".into(), "u=0, i".into()),
        ("accept-encoding".into(), "gzip, deflate, br".into()),
    ]
}

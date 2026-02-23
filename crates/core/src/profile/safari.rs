use std::borrow::Cow;

use crate::http2::config::{Http2Config, PseudoHeader, SettingId};
use crate::tls::config::{AlpnProtocol, CertCompression, TlsConfig, TlsVersion};

use super::BrowserProfile;

/// Safari browser profile factory.
///
/// Supports Safari 15.6, 16.0, 17.0, 18.0, and 18.3.
/// Safari is macOS-only. Profile data verified against real Safari 18.2 captures
/// (curl_cffi#460) and tls-client (bogdanfinn) for older versions.
///
/// Key evolution:
/// - Safari 15.x–16.x: H2 initial_window=4MB
/// - Safari 17.x: H2 initial_window drops to 2MB
/// - Safari 18.0+: H2 initial_window back to 4MB (verified via real capture)
/// - All versions share the same TLS sigalgs (verified against real Safari 18.2)
pub struct Safari;

impl Safari {
    // ========== Safari 15.6 (macOS Monterey 12.5) ==========
    pub fn v15_6_macos() -> BrowserProfile {
        BrowserProfile {
            tls: safari_tls(),
            http2: safari_http2_4mb(),
            quic: None,
            headers: safari_headers_pre_sec_fetch("15.6"),
        }
    }

    // ========== Safari 16.0 (macOS Ventura 13.0) ==========
    pub fn v16_0_macos() -> BrowserProfile {
        BrowserProfile {
            tls: safari_tls(),
            http2: safari_http2_4mb(),
            quic: None,
            headers: safari_headers_pre_sec_fetch("16.0"),
        }
    }

    // ========== Safari 17.0 (macOS Sonoma 14.0) ==========
    pub fn v17_0_macos() -> BrowserProfile {
        BrowserProfile {
            tls: safari_tls(),
            http2: safari_http2_2mb(),
            quic: None,
            headers: safari_headers_v17("17.0"),
        }
    }

    // ========== Safari 18.0 (macOS Sequoia 15.0) ==========
    pub fn v18_0_macos() -> BrowserProfile {
        BrowserProfile {
            tls: safari_tls(),
            http2: safari_http2_4mb(),
            quic: None,
            headers: safari_headers_v18("18.0"),
        }
    }

    // ========== Safari 18.3 (macOS Sequoia 15.3) ==========
    pub fn v18_3_macos() -> BrowserProfile {
        BrowserProfile {
            tls: safari_tls(),
            http2: safari_http2_4mb(),
            quic: None,
            headers: safari_headers_v18("18.3"),
        }
    }

    // ========== Safari iOS ==========
    pub fn v16_0_ios() -> BrowserProfile {
        BrowserProfile {
            tls: safari_tls(),
            http2: safari_http2_ios(),
            quic: None,
            headers: safari_headers_ios_pre_sec_fetch("16.0", "16_0"),
        }
    }

    pub fn v17_0_ios() -> BrowserProfile {
        BrowserProfile {
            tls: safari_tls(),
            http2: safari_http2_ios(),
            quic: None,
            headers: safari_headers_ios_v17("17.0", "17_0"),
        }
    }

    pub fn v18_0_ios() -> BrowserProfile {
        BrowserProfile {
            tls: safari_tls(),
            http2: safari_http2_ios(),
            quic: None,
            headers: safari_headers_ios_v18("18.0", "18_0"),
        }
    }

    pub fn v18_3_ios() -> BrowserProfile {
        BrowserProfile {
            tls: safari_tls(),
            http2: safari_http2_ios(),
            quic: None,
            headers: safari_headers_ios_v18("18.3", "18_3"),
        }
    }

    /// Latest Safari profile (currently v18.3 on macOS).
    pub fn latest() -> BrowserProfile {
        Self::v18_3_macos()
    }

    /// Latest Safari Mobile profile (currently v18.3 on iOS).
    pub fn latest_ios() -> BrowserProfile {
        Self::v18_3_ios()
    }

    /// Resolve a Safari profile by version string and optional OS.
    /// Version can be "156", "15.6", "183", "18.3", etc.
    pub(super) fn resolve(version: &str, os: Option<&str>) -> Result<BrowserProfile, String> {
        if matches!(os, Some("windows") | Some("linux") | Some("android")) {
            return Err("Safari is only available on macOS and iOS".to_string());
        }
        let ios = matches!(os, Some("ios"));
        match (version, ios) {
            ("", false) => Ok(Self::latest()),
            ("", true) => Ok(Self::latest_ios()),
            ("156" | "15.6", false) => Ok(Self::v15_6_macos()),
            ("160" | "16.0", false) => Ok(Self::v16_0_macos()),
            ("160" | "16.0", true) => Ok(Self::v16_0_ios()),
            ("170" | "17.0", false) => Ok(Self::v17_0_macos()),
            ("170" | "17.0", true) => Ok(Self::v17_0_ios()),
            ("180" | "18.0", false) => Ok(Self::v18_0_macos()),
            ("180" | "18.0", true) => Ok(Self::v18_0_ios()),
            ("183" | "18.3", false) => Ok(Self::v18_3_macos()),
            ("183" | "18.3", true) => Ok(Self::v18_3_ios()),
            ("156" | "15.6", true) => Err(
                "Safari 15.6 iOS is not available. Supported iOS: 16.0, 17.0, 18.0, 18.3"
                    .to_string(),
            ),
            _ => Err(format!(
                "Unsupported Safari version: '{version}'. Supported: 15.6, 16.0, 17.0, 18.0, 18.3"
            )),
        }
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

// Safari 15.x–18.3: includes ecdsa_sha1, duplicate rsa_pss_rsae_sha384.
// Verified against real Safari 18.2 capture (curl_cffi#460) and wreq-util.
// Real Safari (Apple SecureTransport) sends rsa_pss_rsae_sha384 twice — boring2's
// patched BoringSSL allows this (uniqueness check removed).
const SAFARI_SIGALGS: &str = "\
ecdsa_secp256r1_sha256:\
rsa_pss_rsae_sha256:\
rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:\
ecdsa_sha1:\
rsa_pss_rsae_sha384:\
rsa_pss_rsae_sha384:\
rsa_pkcs1_sha384:\
rsa_pss_rsae_sha512:\
rsa_pkcs1_sha512:\
rsa_pkcs1_sha1";

// ========== TLS configs ==========

// Safari 15.x through 18.3 — all versions share the same TLS config.
// Verified against real Safari 18.2 capture (curl_cffi#460).
fn safari_tls() -> TlsConfig {
    TlsConfig {
        cipher_list: Cow::Borrowed(SAFARI_CIPHER_LIST),
        curves: Cow::Borrowed(SAFARI_CURVES),
        sigalgs: Cow::Borrowed(SAFARI_SIGALGS),
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
        // Safari sends psk_key_exchange_modes (0x002d) even without offering PSK.
        pre_shared_key: true,
        session_ticket: false,
        key_shares_limit: None,
        delegated_credentials: None,
        record_size_limit: None,
        preserve_tls13_cipher_order: false,
        danger_accept_invalid_certs: false,
    }
}

// ========== HTTP/2 configs ==========

// Safari 15.x–16.x, 18.0+: 4MB initial window.
// Settings order verified against real Safari 18.2 capture: 2,4,3 (EnablePush, InitialWindowSize, MaxConcurrentStreams).
// Connection window: WINDOW_UPDATE=10485760 → configured=10551295 (10485760+65535).
fn safari_http2_4mb() -> Http2Config {
    Http2Config {
        header_table_size: None,
        enable_push: Some(false),
        max_concurrent_streams: Some(100),
        initial_window_size: 4194304,
        max_frame_size: None,
        max_header_list_size: None,
        initial_conn_window_size: 10551295,
        pseudo_header_order: vec![
            PseudoHeader::Method,
            PseudoHeader::Scheme,
            PseudoHeader::Path,
            PseudoHeader::Authority,
        ],
        settings_order: vec![
            SettingId::EnablePush,
            SettingId::InitialWindowSize,
            SettingId::MaxConcurrentStreams,
        ],
        headers_stream_dependency: None,
        priorities: Vec::new(),
        no_rfc7540_priorities: None,
        enable_connect_protocol: None,
    }
}

// Safari 17.x: 2MB initial window (reduced from 4MB).
fn safari_http2_2mb() -> Http2Config {
    Http2Config {
        initial_window_size: 2097152,
        ..safari_http2_4mb()
    }
}

// iOS Safari: 2MB initial window on all iOS versions.
// Verified via wreq-util safari_ios_16_5, safari_ios_17_2, safari_ios_18_1_1.
fn safari_http2_ios() -> Http2Config {
    Http2Config {
        initial_window_size: 2097152,
        ..safari_http2_4mb()
    }
}

// ========== Headers ==========

fn safari_ua(version: &str) -> String {
    format!(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version} Safari/605.1.15"
    )
}

/// iOS Safari User-Agent. `os_version` uses underscore format (e.g. "18_3").
fn safari_ua_ios(version: &str, os_version: &str) -> String {
    format!(
        "Mozilla/5.0 (iPhone; CPU iPhone OS {os_version} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version} Mobile/15E148 Safari/604.1"
    )
}

/// Safari 15.6–16.0: No Sec-Fetch headers (added in Safari 16.4), no Priority header.
fn safari_headers_pre_sec_fetch(version: &str) -> Vec<(String, String)> {
    vec![
        ("user-agent".into(), safari_ua(version)),
        (
            "accept".into(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into(),
        ),
        ("upgrade-insecure-requests".into(), "1".into()),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        ("accept-encoding".into(), "gzip, deflate, br".into()),
    ]
}

/// Safari 17.0: Has Sec-Fetch headers (16.4+), but no Priority header yet.
fn safari_headers_v17(version: &str) -> Vec<(String, String)> {
    vec![
        ("sec-fetch-dest".into(), "document".into()),
        ("user-agent".into(), safari_ua(version)),
        ("upgrade-insecure-requests".into(), "1".into()),
        (
            "accept".into(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into(),
        ),
        ("sec-fetch-site".into(), "none".into()),
        ("sec-fetch-mode".into(), "navigate".into()),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        ("accept-encoding".into(), "gzip, deflate, br".into()),
    ]
}

/// Safari 18.0+: Sec-Fetch + Priority + Upgrade-Insecure-Requests.
/// Order verified against real Safari 18.2 capture (Apple DTS Engineer, macOS 15.2).
fn safari_headers_v18(version: &str) -> Vec<(String, String)> {
    vec![
        ("sec-fetch-dest".into(), "document".into()),
        ("user-agent".into(), safari_ua(version)),
        ("upgrade-insecure-requests".into(), "1".into()),
        (
            "accept".into(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into(),
        ),
        ("sec-fetch-site".into(), "none".into()),
        ("sec-fetch-mode".into(), "navigate".into()),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        ("priority".into(), "u=0, i".into()),
        ("accept-encoding".into(), "gzip, deflate, br".into()),
    ]
}

// ========== iOS Safari headers ==========

/// iOS Safari 16.0: No Sec-Fetch headers, no Priority header.
fn safari_headers_ios_pre_sec_fetch(version: &str, os_version: &str) -> Vec<(String, String)> {
    vec![
        ("user-agent".into(), safari_ua_ios(version, os_version)),
        (
            "accept".into(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into(),
        ),
        ("upgrade-insecure-requests".into(), "1".into()),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        ("accept-encoding".into(), "gzip, deflate, br".into()),
    ]
}

/// iOS Safari 17.0: Sec-Fetch headers, no Priority.
fn safari_headers_ios_v17(version: &str, os_version: &str) -> Vec<(String, String)> {
    vec![
        ("sec-fetch-dest".into(), "document".into()),
        ("user-agent".into(), safari_ua_ios(version, os_version)),
        ("upgrade-insecure-requests".into(), "1".into()),
        (
            "accept".into(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into(),
        ),
        ("sec-fetch-site".into(), "none".into()),
        ("sec-fetch-mode".into(), "navigate".into()),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        ("accept-encoding".into(), "gzip, deflate, br".into()),
    ]
}

/// iOS Safari 18.0+: Sec-Fetch + Priority.
fn safari_headers_ios_v18(version: &str, os_version: &str) -> Vec<(String, String)> {
    vec![
        ("sec-fetch-dest".into(), "document".into()),
        ("user-agent".into(), safari_ua_ios(version, os_version)),
        ("upgrade-insecure-requests".into(), "1".into()),
        (
            "accept".into(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into(),
        ),
        ("sec-fetch-site".into(), "none".into()),
        ("sec-fetch-mode".into(), "navigate".into()),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        ("priority".into(), "u=0, i".into()),
        ("accept-encoding".into(), "gzip, deflate, br".into()),
    ]
}

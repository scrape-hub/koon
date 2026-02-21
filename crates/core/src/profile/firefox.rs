use std::borrow::Cow;

use crate::http2::config::{
    Http2Config, PseudoHeader, SettingId,
};
use crate::quic::QuicConfig;
use crate::tls::config::{
    AlpnProtocol, CertCompression, TlsConfig, TlsVersion,
};

use super::BrowserProfile;

/// Firefox browser profile factory.
///
/// Supports Firefox 135–147. TLS/H2/QUIC fingerprint is identical across all
/// versions (verified via capture tool). Only User-Agent differs per version.
pub struct Firefox;

impl Firefox {
    // ========== Firefox 135 ==========
    pub fn v135_windows() -> BrowserProfile { firefox_profile(135, Os::Windows) }
    pub fn v135_macos() -> BrowserProfile { firefox_profile(135, Os::MacOS) }
    pub fn v135_linux() -> BrowserProfile { firefox_profile(135, Os::Linux) }

    // ========== Firefox 136 ==========
    pub fn v136_windows() -> BrowserProfile { firefox_profile(136, Os::Windows) }
    pub fn v136_macos() -> BrowserProfile { firefox_profile(136, Os::MacOS) }
    pub fn v136_linux() -> BrowserProfile { firefox_profile(136, Os::Linux) }

    // ========== Firefox 137 ==========
    pub fn v137_windows() -> BrowserProfile { firefox_profile(137, Os::Windows) }
    pub fn v137_macos() -> BrowserProfile { firefox_profile(137, Os::MacOS) }
    pub fn v137_linux() -> BrowserProfile { firefox_profile(137, Os::Linux) }

    // ========== Firefox 138 ==========
    pub fn v138_windows() -> BrowserProfile { firefox_profile(138, Os::Windows) }
    pub fn v138_macos() -> BrowserProfile { firefox_profile(138, Os::MacOS) }
    pub fn v138_linux() -> BrowserProfile { firefox_profile(138, Os::Linux) }

    // ========== Firefox 139 ==========
    pub fn v139_windows() -> BrowserProfile { firefox_profile(139, Os::Windows) }
    pub fn v139_macos() -> BrowserProfile { firefox_profile(139, Os::MacOS) }
    pub fn v139_linux() -> BrowserProfile { firefox_profile(139, Os::Linux) }

    // ========== Firefox 140 ==========
    pub fn v140_windows() -> BrowserProfile { firefox_profile(140, Os::Windows) }
    pub fn v140_macos() -> BrowserProfile { firefox_profile(140, Os::MacOS) }
    pub fn v140_linux() -> BrowserProfile { firefox_profile(140, Os::Linux) }

    // ========== Firefox 141 ==========
    pub fn v141_windows() -> BrowserProfile { firefox_profile(141, Os::Windows) }
    pub fn v141_macos() -> BrowserProfile { firefox_profile(141, Os::MacOS) }
    pub fn v141_linux() -> BrowserProfile { firefox_profile(141, Os::Linux) }

    // ========== Firefox 142 ==========
    pub fn v142_windows() -> BrowserProfile { firefox_profile(142, Os::Windows) }
    pub fn v142_macos() -> BrowserProfile { firefox_profile(142, Os::MacOS) }
    pub fn v142_linux() -> BrowserProfile { firefox_profile(142, Os::Linux) }

    // ========== Firefox 143 ==========
    pub fn v143_windows() -> BrowserProfile { firefox_profile(143, Os::Windows) }
    pub fn v143_macos() -> BrowserProfile { firefox_profile(143, Os::MacOS) }
    pub fn v143_linux() -> BrowserProfile { firefox_profile(143, Os::Linux) }

    // ========== Firefox 144 ==========
    pub fn v144_windows() -> BrowserProfile { firefox_profile(144, Os::Windows) }
    pub fn v144_macos() -> BrowserProfile { firefox_profile(144, Os::MacOS) }
    pub fn v144_linux() -> BrowserProfile { firefox_profile(144, Os::Linux) }

    // ========== Firefox 145 ==========
    pub fn v145_windows() -> BrowserProfile { firefox_profile(145, Os::Windows) }
    pub fn v145_macos() -> BrowserProfile { firefox_profile(145, Os::MacOS) }
    pub fn v145_linux() -> BrowserProfile { firefox_profile(145, Os::Linux) }

    // ========== Firefox 146 ==========
    pub fn v146_windows() -> BrowserProfile { firefox_profile(146, Os::Windows) }
    pub fn v146_macos() -> BrowserProfile { firefox_profile(146, Os::MacOS) }
    pub fn v146_linux() -> BrowserProfile { firefox_profile(146, Os::Linux) }

    // ========== Firefox 147 ==========
    pub fn v147_windows() -> BrowserProfile { firefox_profile(147, Os::Windows) }
    pub fn v147_macos() -> BrowserProfile { firefox_profile(147, Os::MacOS) }
    pub fn v147_linux() -> BrowserProfile { firefox_profile(147, Os::Linux) }

    /// Latest Firefox profile (currently v147 on Windows).
    pub fn latest() -> BrowserProfile {
        Self::v147_windows()
    }

    /// Resolve a Firefox profile by version number and optional OS.
    pub(super) fn resolve(major: u32, os: Option<&str>) -> Result<BrowserProfile, String> {
        if !(135..=147).contains(&major) {
            return Err(format!(
                "Unsupported Firefox version: {major}. Supported: 135-147"
            ));
        }
        let os = match os {
            Some("macos") => Os::MacOS,
            Some("linux") => Os::Linux,
            _ => Os::Windows,
        };
        Ok(firefox_profile(major, os))
    }

    pub(super) const LATEST_VERSION: u32 = 147;
}

// ========== Internal: OS enum ==========

#[derive(Clone, Copy)]
enum Os {
    Windows,
    MacOS,
    Linux,
}

// ========== Internal: Profile generator ==========

fn firefox_profile(major: u32, os: Os) -> BrowserProfile {
    BrowserProfile {
        tls: firefox_tls(),
        http2: firefox_http2(),
        quic: Some(firefox_quic()),
        headers: firefox_headers(major, os),
    }
}

// ========== TLS ==========
// Identical across Firefox 135–147 (verified via capture tool).

// TLS 1.3 order: AES_128(4865) → CHACHA20(4867) → AES_256(4866)
// Matches real Firefox/NSS. Requires preserve_tls13_cipher_order = true.
const FIREFOX_CIPHER_LIST: &str = "\
TLS_AES_128_GCM_SHA256:\
TLS_CHACHA20_POLY1305_SHA256:\
TLS_AES_256_GCM_SHA384:\
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:\
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:\
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:\
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:\
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:\
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:\
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:\
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:\
TLS_RSA_WITH_AES_128_GCM_SHA256:\
TLS_RSA_WITH_AES_256_GCM_SHA384:\
TLS_RSA_WITH_AES_128_CBC_SHA:\
TLS_RSA_WITH_AES_256_CBC_SHA";

const FIREFOX_SIGALGS: &str = "\
ecdsa_secp256r1_sha256:\
ecdsa_secp384r1_sha384:\
ecdsa_secp521r1_sha512:\
rsa_pss_rsae_sha256:\
rsa_pss_rsae_sha384:\
rsa_pss_rsae_sha512:\
rsa_pkcs1_sha256:\
rsa_pkcs1_sha384:\
rsa_pkcs1_sha512:\
ecdsa_sha1:\
rsa_pkcs1_sha1";

const FIREFOX_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384:P-521:ffdhe2048:ffdhe3072";

const FIREFOX_DC_SIGALGS: &str = "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:ecdsa_sha1";

fn firefox_tls() -> TlsConfig {
    TlsConfig {
        cipher_list: Cow::Borrowed(FIREFOX_CIPHER_LIST),
        curves: Cow::Borrowed(FIREFOX_CURVES),
        sigalgs: Cow::Borrowed(FIREFOX_SIGALGS),
        alpn: vec![AlpnProtocol::Http2, AlpnProtocol::Http11],
        alps: None,
        alps_use_new_codepoint: false,
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
        grease: false,
        ech_grease: true,
        permute_extensions: false,
        ocsp_stapling: true,
        signed_cert_timestamps: true,
        cert_compression: vec![
            CertCompression::Zlib,
            CertCompression::Brotli,
            CertCompression::Zstd,
        ],
        pre_shared_key: true,
        session_ticket: true,
        key_shares_limit: Some(3),
        delegated_credentials: Some(Cow::Borrowed(FIREFOX_DC_SIGALGS)),
        record_size_limit: Some(16385),
        // Firefox/NSS uses AES_128 → AES_256 → CHACHA20 (differs from BoringSSL default).
        preserve_tls13_cipher_order: true,
        danger_accept_invalid_certs: false,
    }
}

// ========== HTTP/2 ==========

fn firefox_http2() -> Http2Config {
    Http2Config {
        header_table_size: Some(65536),
        enable_push: Some(false),
        max_concurrent_streams: None,
        initial_window_size: 131072,
        max_frame_size: Some(16384),
        max_header_list_size: None,
        initial_conn_window_size: 12582912,
        pseudo_header_order: vec![
            PseudoHeader::Method,
            PseudoHeader::Path,
            PseudoHeader::Authority,
            PseudoHeader::Scheme,
        ],
        settings_order: vec![
            SettingId::HeaderTableSize,
            SettingId::EnablePush,
            SettingId::InitialWindowSize,
            SettingId::MaxFrameSize,
        ],
        headers_stream_dependency: None,
        // Firefox 135+ does not send RFC 7540 PRIORITY frames (deprecated since ~FF100).
        // Verified via capture: akamai_text PRIORITY segment is "0".
        priorities: Vec::new(),
        no_rfc7540_priorities: None,
        enable_connect_protocol: None,
    }
}

// ========== QUIC ==========

fn firefox_quic() -> QuicConfig {
    QuicConfig {
        initial_max_data: 12582912,
        initial_max_stream_data_bidi_local: 1048576,
        initial_max_stream_data_bidi_remote: 1048576,
        initial_max_stream_data_uni: 1048576,
        initial_max_streams_bidi: 16,
        initial_max_streams_uni: 16,
        max_idle_timeout_ms: 30000,
        max_udp_payload_size: 1472,
        ack_delay_exponent: 3,
        max_ack_delay_ms: 25,
        active_connection_id_limit: 2,
        disable_active_migration: false,
        grease_quic_bit: false,
        qpack_max_table_capacity: 0,
        qpack_blocked_streams: 0,
        max_field_section_size: None,
    }
}

// ========== Headers ==========

fn firefox_headers(major: u32, os: Os) -> Vec<(String, String)> {
    let ver = major.to_string();

    let user_agent = match os {
        Os::Windows => format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{ver}.0) Gecko/20100101 Firefox/{ver}.0"
        ),
        Os::MacOS => format!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{ver}.0) Gecko/20100101 Firefox/{ver}.0"
        ),
        Os::Linux => format!(
            "Mozilla/5.0 (X11; Linux x86_64; rv:{ver}.0) Gecko/20100101 Firefox/{ver}.0"
        ),
    };

    vec![
        ("te".into(), "trailers".into()),
        ("user-agent".into(), user_agent),
        ("accept".into(), "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into()),
        ("accept-language".into(), "en-US,en;q=0.5".into()),
        ("accept-encoding".into(), "gzip, deflate, br, zstd".into()),
        ("upgrade-insecure-requests".into(), "1".into()),
        ("sec-fetch-dest".into(), "document".into()),
        ("sec-fetch-mode".into(), "navigate".into()),
        ("sec-fetch-site".into(), "none".into()),
        ("sec-fetch-user".into(), "?1".into()),
        ("priority".into(), "u=0, i".into()),
    ]
}

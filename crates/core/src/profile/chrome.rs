use std::borrow::Cow;

use crate::http2::config::{
    Http2Config, PseudoHeader, SettingId, StreamDep,
};
use crate::quic::QuicConfig;
use crate::tls::config::{
    AlpnProtocol, AlpsProtocol, CertCompression, TlsConfig, TlsVersion,
};

use super::BrowserProfile;

/// Chrome browser profile factory.
///
/// Supports Chrome 131–145. TLS/H2/QUIC fingerprint is identical across all
/// versions except for the ALPS codepoint (old for ≤134, new for ≥135).
/// Only User-Agent and sec-ch-ua headers differ per version.
pub struct Chrome;

impl Chrome {
    // ========== Chrome 131 ==========
    pub fn v131_windows() -> BrowserProfile { chrome_profile(131, Os::Windows) }
    pub fn v131_macos() -> BrowserProfile { chrome_profile(131, Os::MacOS) }
    pub fn v131_linux() -> BrowserProfile { chrome_profile(131, Os::Linux) }

    // ========== Chrome 132 ==========
    pub fn v132_windows() -> BrowserProfile { chrome_profile(132, Os::Windows) }
    pub fn v132_macos() -> BrowserProfile { chrome_profile(132, Os::MacOS) }
    pub fn v132_linux() -> BrowserProfile { chrome_profile(132, Os::Linux) }

    // ========== Chrome 133 ==========
    pub fn v133_windows() -> BrowserProfile { chrome_profile(133, Os::Windows) }
    pub fn v133_macos() -> BrowserProfile { chrome_profile(133, Os::MacOS) }
    pub fn v133_linux() -> BrowserProfile { chrome_profile(133, Os::Linux) }

    // ========== Chrome 134 ==========
    pub fn v134_windows() -> BrowserProfile { chrome_profile(134, Os::Windows) }
    pub fn v134_macos() -> BrowserProfile { chrome_profile(134, Os::MacOS) }
    pub fn v134_linux() -> BrowserProfile { chrome_profile(134, Os::Linux) }

    // ========== Chrome 135 ==========
    pub fn v135_windows() -> BrowserProfile { chrome_profile(135, Os::Windows) }
    pub fn v135_macos() -> BrowserProfile { chrome_profile(135, Os::MacOS) }
    pub fn v135_linux() -> BrowserProfile { chrome_profile(135, Os::Linux) }

    // ========== Chrome 136 ==========
    pub fn v136_windows() -> BrowserProfile { chrome_profile(136, Os::Windows) }
    pub fn v136_macos() -> BrowserProfile { chrome_profile(136, Os::MacOS) }
    pub fn v136_linux() -> BrowserProfile { chrome_profile(136, Os::Linux) }

    // ========== Chrome 137 ==========
    pub fn v137_windows() -> BrowserProfile { chrome_profile(137, Os::Windows) }
    pub fn v137_macos() -> BrowserProfile { chrome_profile(137, Os::MacOS) }
    pub fn v137_linux() -> BrowserProfile { chrome_profile(137, Os::Linux) }

    // ========== Chrome 138 ==========
    pub fn v138_windows() -> BrowserProfile { chrome_profile(138, Os::Windows) }
    pub fn v138_macos() -> BrowserProfile { chrome_profile(138, Os::MacOS) }
    pub fn v138_linux() -> BrowserProfile { chrome_profile(138, Os::Linux) }

    // ========== Chrome 139 ==========
    pub fn v139_windows() -> BrowserProfile { chrome_profile(139, Os::Windows) }
    pub fn v139_macos() -> BrowserProfile { chrome_profile(139, Os::MacOS) }
    pub fn v139_linux() -> BrowserProfile { chrome_profile(139, Os::Linux) }

    // ========== Chrome 140 ==========
    pub fn v140_windows() -> BrowserProfile { chrome_profile(140, Os::Windows) }
    pub fn v140_macos() -> BrowserProfile { chrome_profile(140, Os::MacOS) }
    pub fn v140_linux() -> BrowserProfile { chrome_profile(140, Os::Linux) }

    // ========== Chrome 141 ==========
    pub fn v141_windows() -> BrowserProfile { chrome_profile(141, Os::Windows) }
    pub fn v141_macos() -> BrowserProfile { chrome_profile(141, Os::MacOS) }
    pub fn v141_linux() -> BrowserProfile { chrome_profile(141, Os::Linux) }

    // ========== Chrome 142 ==========
    pub fn v142_windows() -> BrowserProfile { chrome_profile(142, Os::Windows) }
    pub fn v142_macos() -> BrowserProfile { chrome_profile(142, Os::MacOS) }
    pub fn v142_linux() -> BrowserProfile { chrome_profile(142, Os::Linux) }

    // ========== Chrome 143 ==========
    pub fn v143_windows() -> BrowserProfile { chrome_profile(143, Os::Windows) }
    pub fn v143_macos() -> BrowserProfile { chrome_profile(143, Os::MacOS) }
    pub fn v143_linux() -> BrowserProfile { chrome_profile(143, Os::Linux) }

    // ========== Chrome 144 ==========
    pub fn v144_windows() -> BrowserProfile { chrome_profile(144, Os::Windows) }
    pub fn v144_macos() -> BrowserProfile { chrome_profile(144, Os::MacOS) }
    pub fn v144_linux() -> BrowserProfile { chrome_profile(144, Os::Linux) }

    // ========== Chrome 145 ==========
    pub fn v145_windows() -> BrowserProfile { chrome_profile(145, Os::Windows) }
    pub fn v145_macos() -> BrowserProfile { chrome_profile(145, Os::MacOS) }
    pub fn v145_linux() -> BrowserProfile { chrome_profile(145, Os::Linux) }

    /// Latest Chrome profile (currently v145 on Windows).
    pub fn latest() -> BrowserProfile {
        Self::v145_windows()
    }
}

// ========== Internal: OS enum ==========

#[derive(Clone, Copy)]
enum Os {
    Windows,
    MacOS,
    Linux,
}

// ========== Internal: Profile generator ==========

fn chrome_profile(major: u32, os: Os) -> BrowserProfile {
    BrowserProfile {
        tls: chrome_tls(major),
        http2: chrome_http2(),
        quic: Some(chrome_quic()),
        headers: chrome_headers(major, os),
    }
}

// ========== TLS ==========

const CHROME_CIPHER_LIST: &str = "\
TLS_AES_128_GCM_SHA256:\
TLS_AES_256_GCM_SHA384:\
TLS_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:\
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:\
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:\
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:\
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:\
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:\
TLS_RSA_WITH_AES_128_GCM_SHA256:\
TLS_RSA_WITH_AES_256_GCM_SHA384:\
TLS_RSA_WITH_AES_128_CBC_SHA:\
TLS_RSA_WITH_AES_256_CBC_SHA";

const CHROME_SIGALGS: &str = "\
ecdsa_secp256r1_sha256:\
rsa_pss_rsae_sha256:\
rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:\
rsa_pss_rsae_sha384:\
rsa_pkcs1_sha384:\
rsa_pss_rsae_sha512:\
rsa_pkcs1_sha512";

const CHROME_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384";

// Shared TLS config — only ALPS codepoint differs between Chrome ≤134 and ≥135.
fn chrome_tls(major: u32) -> TlsConfig {
    TlsConfig {
        cipher_list: Cow::Borrowed(CHROME_CIPHER_LIST),
        curves: Cow::Borrowed(CHROME_CURVES),
        sigalgs: Cow::Borrowed(CHROME_SIGALGS),
        alpn: vec![AlpnProtocol::Http2, AlpnProtocol::Http11],
        alps: Some(AlpsProtocol::Http2),
        alps_use_new_codepoint: major >= 135, // Old 0x4469 for ≤134, new 0x44CD for ≥135
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
        grease: true,
        ech_grease: true,
        permute_extensions: true,
        ocsp_stapling: true,
        signed_cert_timestamps: true,
        cert_compression: vec![CertCompression::Brotli],
        pre_shared_key: true,
        session_ticket: true,
        key_shares_limit: None,
        delegated_credentials: None,
        danger_accept_invalid_certs: false,
    }
}

// Also export for Edge which shares the same TLS config.
pub(super) fn chrome_tls_for_edge(major: u32) -> TlsConfig {
    chrome_tls(major)
}

// ========== HTTP/2 ==========
// Identical across Chrome 131–145 (verified via Akamai fingerprint hash).

pub(super) fn chrome_http2() -> Http2Config {
    Http2Config {
        header_table_size: Some(65536),
        enable_push: Some(false),
        max_concurrent_streams: None,
        initial_window_size: 6291456,
        max_frame_size: None,
        max_header_list_size: Some(262144),
        initial_conn_window_size: 15728640,
        pseudo_header_order: vec![
            PseudoHeader::Method,
            PseudoHeader::Authority,
            PseudoHeader::Scheme,
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
        headers_stream_dependency: Some(StreamDep {
            stream_id: 0,
            weight: 219,
            exclusive: true,
        }),
        priorities: Vec::new(),
        no_rfc7540_priorities: Some(true),
        enable_connect_protocol: None,
    }
}

// ========== QUIC ==========

pub(super) fn chrome_quic() -> QuicConfig {
    QuicConfig {
        initial_max_data: 15728640,
        initial_max_stream_data_bidi_local: 6291456,
        initial_max_stream_data_bidi_remote: 6291456,
        initial_max_stream_data_uni: 6291456,
        initial_max_streams_bidi: 100,
        initial_max_streams_uni: 100,
        max_idle_timeout_ms: 30000,
        max_udp_payload_size: 1350,
        ack_delay_exponent: 3,
        max_ack_delay_ms: 25,
        active_connection_id_limit: 4,
        disable_active_migration: true,
        grease_quic_bit: true,
        qpack_max_table_capacity: 0,
        qpack_blocked_streams: 0,
        max_field_section_size: None,
    }
}

// ========== Headers ==========

/// sec-ch-ua "Not A Brand" string per Chrome version.
/// Verified from real browser captures against tls.browserleaks.com.
fn chrome_brand(major: u32) -> &'static str {
    match major {
        136 | 145 => "Not/A)Brand",
        _ => "Not_A Brand",
    }
}

fn chrome_headers(major: u32, os: Os) -> Vec<(String, String)> {
    let brand = chrome_brand(major);
    let ver = major.to_string();

    let sec_ch_ua = format!(
        "\"Chromium\";v=\"{ver}\", \"{brand}\";v=\"24\", \"Google Chrome\";v=\"{ver}\""
    );

    let (platform, user_agent) = match os {
        Os::Windows => (
            "\"Windows\"",
            format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36"),
        ),
        Os::MacOS => (
            "\"macOS\"",
            format!("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36"),
        ),
        Os::Linux => (
            "\"Linux\"",
            format!("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36"),
        ),
    };

    vec![
        ("sec-ch-ua".into(), sec_ch_ua),
        ("sec-ch-ua-mobile".into(), "?0".into()),
        ("sec-ch-ua-platform".into(), platform.into()),
        ("upgrade-insecure-requests".into(), "1".into()),
        ("user-agent".into(), user_agent),
        ("accept".into(), "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".into()),
        ("sec-fetch-site".into(), "none".into()),
        ("sec-fetch-mode".into(), "navigate".into()),
        ("sec-fetch-user".into(), "?1".into()),
        ("sec-fetch-dest".into(), "document".into()),
        ("accept-encoding".into(), "gzip, deflate, br, zstd".into()),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        ("priority".into(), "u=0, i".into()),
    ]
}

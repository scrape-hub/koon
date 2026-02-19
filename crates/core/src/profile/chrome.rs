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
pub struct Chrome;

impl Chrome {
    /// Chrome 131 on Windows 10.
    pub fn v131_windows() -> BrowserProfile {
        BrowserProfile {
            tls: chrome_tls_v131(),
            http2: chrome_http2_v131(),
            quic: Some(chrome_quic()),
            headers: chrome_headers_v131_windows(),
        }
    }

    /// Chrome 131 on macOS.
    pub fn v131_macos() -> BrowserProfile {
        BrowserProfile {
            tls: chrome_tls_v131(),
            http2: chrome_http2_v131(),
            quic: Some(chrome_quic()),
            headers: chrome_headers_v131_macos(),
        }
    }

    /// Chrome 131 on Linux.
    pub fn v131_linux() -> BrowserProfile {
        BrowserProfile {
            tls: chrome_tls_v131(),
            http2: chrome_http2_v131(),
            quic: Some(chrome_quic()),
            headers: chrome_headers_v131_linux(),
        }
    }

    /// Chrome 145 on Windows 10.
    pub fn v145_windows() -> BrowserProfile {
        BrowserProfile {
            tls: chrome_tls_v145(),
            http2: chrome_http2_v145(),
            quic: Some(chrome_quic()),
            headers: chrome_headers_v145_windows(),
        }
    }

    /// Chrome 145 on macOS.
    pub fn v145_macos() -> BrowserProfile {
        BrowserProfile {
            tls: chrome_tls_v145(),
            http2: chrome_http2_v145(),
            quic: Some(chrome_quic()),
            headers: chrome_headers_v145_macos(),
        }
    }

    /// Chrome 145 on Linux.
    pub fn v145_linux() -> BrowserProfile {
        BrowserProfile {
            tls: chrome_tls_v145(),
            http2: chrome_http2_v145(),
            quic: Some(chrome_quic()),
            headers: chrome_headers_v145_linux(),
        }
    }

    /// Latest Chrome profile (currently v145 on Windows).
    pub fn latest() -> BrowserProfile {
        Self::v145_windows()
    }
}

// ========== Common TLS Constants ==========

/// Chrome cipher suites in the exact order Chrome sends them.
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

/// Chrome 131+ uses X25519MLKEM768 (post-quantum) + X25519 + P-256 + P-384.
const CHROME_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384";

// ========== Chrome 131 TLS ==========

pub(super) fn chrome_tls_v131() -> TlsConfig {
    TlsConfig {
        cipher_list: Cow::Borrowed(CHROME_CIPHER_LIST),
        curves: Cow::Borrowed(CHROME_CURVES),
        sigalgs: Cow::Borrowed(CHROME_SIGALGS),
        alpn: vec![AlpnProtocol::Http2, AlpnProtocol::Http11],
        alps: Some(AlpsProtocol::Http2),
        alps_use_new_codepoint: true,
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

// ========== Chrome 145 TLS ==========
// TLS config is identical to v131 (cipher suites rarely change between versions).

fn chrome_tls_v145() -> TlsConfig {
    chrome_tls_v131()
}

// ========== Chrome 131 HTTP/2 ==========

fn chrome_http2_v131() -> Http2Config {
    chrome_http2_base()
}

// ========== Chrome 145 HTTP/2 ==========
// HTTP/2 settings are identical to v131.

fn chrome_http2_v145() -> Http2Config {
    chrome_http2_base()
}

pub(super) fn chrome_http2_base() -> Http2Config {
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

// ========== Chrome QUIC ==========

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

// ========== Chrome 131 Headers ==========

fn chrome_headers_v131_windows() -> Vec<(String, String)> {
    let sec_ch_ua = r#""Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131""#;
    chrome_headers_base(sec_ch_ua, "\"Windows\"", "?0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
}

fn chrome_headers_v131_macos() -> Vec<(String, String)> {
    let sec_ch_ua = r#""Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131""#;
    chrome_headers_base(sec_ch_ua, "\"macOS\"", "?0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
}

fn chrome_headers_v131_linux() -> Vec<(String, String)> {
    let sec_ch_ua = r#""Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131""#;
    chrome_headers_base(sec_ch_ua, "\"Linux\"", "?0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
}

// ========== Chrome 145 Headers ==========

fn chrome_headers_v145_windows() -> Vec<(String, String)> {
    let sec_ch_ua = r#""Chromium";v="145", "Not/A)Brand";v="24", "Google Chrome";v="145""#;
    chrome_headers_base(sec_ch_ua, "\"Windows\"", "?0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36")
}

fn chrome_headers_v145_macos() -> Vec<(String, String)> {
    let sec_ch_ua = r#""Chromium";v="145", "Not/A)Brand";v="24", "Google Chrome";v="145""#;
    chrome_headers_base(sec_ch_ua, "\"macOS\"", "?0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36")
}

fn chrome_headers_v145_linux() -> Vec<(String, String)> {
    let sec_ch_ua = r#""Chromium";v="145", "Not/A)Brand";v="24", "Google Chrome";v="145""#;
    chrome_headers_base(sec_ch_ua, "\"Linux\"", "?0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36")
}

// ========== Shared Header Builder ==========

fn chrome_headers_base(
    sec_ch_ua: &str,
    platform: &str,
    mobile: &str,
    user_agent: &str,
) -> Vec<(String, String)> {
    vec![
        ("sec-ch-ua".into(), sec_ch_ua.into()),
        ("sec-ch-ua-mobile".into(), mobile.into()),
        ("sec-ch-ua-platform".into(), platform.into()),
        ("upgrade-insecure-requests".into(), "1".into()),
        ("user-agent".into(), user_agent.into()),
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

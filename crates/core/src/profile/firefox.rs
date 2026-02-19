use std::borrow::Cow;

use crate::http2::config::{
    Http2Config, PseudoHeader, SettingId, StreamDep,
};
use crate::quic::QuicConfig;
use crate::tls::config::{
    AlpnProtocol, CertCompression, TlsConfig, TlsVersion,
};

use super::BrowserProfile;

/// Firefox browser profile factory.
pub struct Firefox;

impl Firefox {
    /// Firefox 135 on Windows.
    pub fn v135_windows() -> BrowserProfile {
        BrowserProfile {
            tls: firefox_tls_v135(),
            http2: firefox_http2_v135(),
            quic: Some(firefox_quic()),
            headers: firefox_headers_v135(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
            ),
        }
    }

    /// Firefox 135 on macOS.
    pub fn v135_macos() -> BrowserProfile {
        BrowserProfile {
            tls: firefox_tls_v135(),
            http2: firefox_http2_v135(),
            quic: Some(firefox_quic()),
            headers: firefox_headers_v135(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
            ),
        }
    }

    /// Firefox 135 on Linux.
    pub fn v135_linux() -> BrowserProfile {
        BrowserProfile {
            tls: firefox_tls_v135(),
            http2: firefox_http2_v135(),
            quic: Some(firefox_quic()),
            headers: firefox_headers_v135(
                "Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
            ),
        }
    }

    /// Latest Firefox profile (currently v135 on Windows).
    pub fn latest() -> BrowserProfile {
        Self::v135_windows()
    }
}

// Firefox cipher list: AES128 > ChaCha > AES256, plus CBC fallbacks
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

// Firefox includes more curves + ffdhe groups
const FIREFOX_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384:P-521:ffdhe2048:ffdhe3072";

const FIREFOX_DC_SIGALGS: &str = "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:ecdsa_sha1";

fn firefox_tls_v135() -> TlsConfig {
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
        danger_accept_invalid_certs: false,
    }
}

fn firefox_http2_v135() -> Http2Config {
    Http2Config {
        header_table_size: Some(65536),
        enable_push: Some(false),
        max_concurrent_streams: None,
        initial_window_size: 131072,
        max_frame_size: None,
        max_header_list_size: Some(65536),
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
            SettingId::MaxConcurrentStreams,
            SettingId::InitialWindowSize,
            SettingId::MaxFrameSize,
            SettingId::MaxHeaderListSize,
        ],
        headers_stream_dependency: Some(StreamDep {
            stream_id: 0,
            weight: 41,
            exclusive: false,
        }),
        priorities: Vec::new(),
        no_rfc7540_priorities: None,
        enable_connect_protocol: None,
    }
}

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

fn firefox_headers_v135(user_agent: &str) -> Vec<(String, String)> {
    vec![
        ("te".into(), "trailers".into()),
        ("user-agent".into(), user_agent.into()),
        ("accept".into(), "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into()),
        ("accept-language".into(), "en-US,en;q=0.5".into()),
        ("accept-encoding".into(), "gzip, deflate, br, zstd".into()),
        ("sec-fetch-dest".into(), "document".into()),
        ("sec-fetch-mode".into(), "navigate".into()),
        ("sec-fetch-site".into(), "none".into()),
        ("priority".into(), "u=0, i".into()),
    ]
}

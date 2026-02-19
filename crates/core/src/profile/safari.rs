use std::borrow::Cow;

use crate::http2::config::{
    Http2Config, PseudoHeader, SettingId,
};
use crate::tls::config::{
    AlpnProtocol, CertCompression, TlsConfig, TlsVersion,
};

use super::BrowserProfile;

/// Safari browser profile factory.
pub struct Safari;

impl Safari {
    /// Safari 18.3 on macOS.
    pub fn v18_3_macos() -> BrowserProfile {
        BrowserProfile {
            tls: safari_tls_v18_3(),
            http2: safari_http2_v18_3(),
            quic: None, // Safari does not use HTTP/3 with custom QUIC params yet
            headers: safari_headers_v18_3(),
        }
    }

    /// Latest Safari profile (currently v18.3 on macOS).
    pub fn latest() -> BrowserProfile {
        Self::v18_3_macos()
    }
}

// Safari cipher list: includes legacy 3DES cipher
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

const SAFARI_SIGALGS: &str = "\
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

// Safari: no MLKEM, no ffdhe
const SAFARI_CURVES: &str = "X25519:P-256:P-384:P-521";

fn safari_tls_v18_3() -> TlsConfig {
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
        pre_shared_key: false,
        session_ticket: false,
        key_shares_limit: None,
        delegated_credentials: None,
        danger_accept_invalid_certs: false,
    }
}

fn safari_http2_v18_3() -> Http2Config {
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

fn safari_headers_v18_3() -> Vec<(String, String)> {
    vec![
        ("sec-fetch-dest".into(), "document".into()),
        ("user-agent".into(), "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15".into()),
        ("accept".into(), "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into()),
        ("sec-fetch-site".into(), "none".into()),
        ("sec-fetch-mode".into(), "navigate".into()),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        ("priority".into(), "u=0, i".into()),
        ("accept-encoding".into(), "gzip, deflate, br".into()),
    ]
}

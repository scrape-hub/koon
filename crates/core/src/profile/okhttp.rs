use std::borrow::Cow;

use crate::http2::config::{Http2Config, PseudoHeader, SettingId, StreamDep};
use crate::tls::config::{AlpnProtocol, TlsConfig, TlsVersion};

use super::BrowserProfile;

/// OkHttp profile factory (Android app HTTP client).
///
/// OkHttp is the default HTTP client for Android apps (used by Retrofit, Ktor, etc.).
/// Its TLS fingerprint differs significantly from browsers: no GREASE, no ALPS,
/// no ECH, no extension permutation, no cert compression.
///
/// Profile data sourced from wreq-util (0x676e67) and real OkHttp captures.
/// Supports OkHttp 4.x (most common) and 5.x (latest).
pub struct OkHttp;

impl OkHttp {
    /// OkHttp 4.12 (most common in current Android apps).
    pub fn v4() -> BrowserProfile {
        okhttp_profile(OkHttpVersion::V4)
    }

    /// OkHttp 5.0 (latest alpha, emerging in new apps).
    pub fn v5() -> BrowserProfile {
        okhttp_profile(OkHttpVersion::V5)
    }

    /// Latest OkHttp profile (currently v5).
    pub fn latest() -> BrowserProfile {
        Self::v5()
    }

    /// Resolve an OkHttp profile by version string.
    pub(super) fn resolve(version: &str) -> Result<BrowserProfile, String> {
        match version {
            "" | "5" => Ok(Self::v5()),
            "4" => Ok(Self::v4()),
            _ => Err(format!(
                "Unsupported OkHttp version: '{version}'. Supported: 4, 5"
            )),
        }
    }
}

#[derive(Clone, Copy)]
enum OkHttpVersion {
    V4,
    V5,
}

fn okhttp_profile(version: OkHttpVersion) -> BrowserProfile {
    BrowserProfile {
        tls: okhttp_tls(),
        http2: okhttp_http2(),
        quic: None,
        headers: okhttp_headers(version),
    }
}

// ========== TLS ==========
// OkHttp uses Android's Conscrypt (BoringSSL-based) TLS stack.
// No GREASE, no ALPS, no ECH, no extension permutation, no cert compression.
// Data from wreq-util okhttp.rs (verified against real captures).

const OKHTTP_CIPHER_LIST: &str = "\
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
TLS_RSA_WITH_AES_256_CBC_SHA:\
TLS_RSA_WITH_3DES_EDE_CBC_SHA";

const OKHTTP_SIGALGS: &str = "\
ecdsa_secp256r1_sha256:\
rsa_pss_rsae_sha256:\
rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:\
rsa_pss_rsae_sha384:\
rsa_pkcs1_sha384:\
rsa_pss_rsae_sha512:\
rsa_pkcs1_sha512:\
rsa_pkcs1_sha1";

// OkHttp/Conscrypt: X25519, P-256, P-384 (no ML-KEM, no P-521, no ffdhe).
const OKHTTP_CURVES: &str = "X25519:P-256:P-384";

fn okhttp_tls() -> TlsConfig {
    TlsConfig {
        cipher_list: Cow::Borrowed(OKHTTP_CIPHER_LIST),
        curves: Cow::Borrowed(OKHTTP_CURVES),
        sigalgs: Cow::Borrowed(OKHTTP_SIGALGS),
        alpn: vec![AlpnProtocol::Http2, AlpnProtocol::Http11],
        alps: None,
        alps_use_new_codepoint: false,
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
        grease: false,
        ech_grease: false,
        permute_extensions: false,
        ocsp_stapling: true,
        signed_cert_timestamps: false,
        cert_compression: vec![],
        pre_shared_key: false,
        session_ticket: true,
        key_shares_limit: None,
        delegated_credentials: None,
        record_size_limit: None,
        preserve_tls13_cipher_order: false,
        danger_accept_invalid_certs: false,
    }
}

// ========== HTTP/2 ==========
// Data from wreq-util okhttp.rs.
// OkHttp H2: pseudo order m,p,a,s, settings include EnableConnectProtocol and NoRfc7540Priorities.

fn okhttp_http2() -> Http2Config {
    Http2Config {
        header_table_size: Some(65536),
        enable_push: Some(false),
        max_concurrent_streams: Some(1000),
        initial_window_size: 6291456,
        max_frame_size: None,
        max_header_list_size: Some(262144),
        initial_conn_window_size: 15728640,
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
            SettingId::EnableConnectProtocol,
            SettingId::NoRfc7540Priorities,
        ],
        headers_stream_dependency: Some(StreamDep {
            stream_id: 0,
            weight: 255,
            exclusive: true,
        }),
        priorities: Vec::new(),
        no_rfc7540_priorities: None,
        enable_connect_protocol: None,
    }
}

// ========== Headers ==========
// OkHttp sends minimal headers: Accept, Accept-Language, User-Agent, Accept-Encoding.
// No sec-ch-ua, no sec-fetch-*, no upgrade-insecure-requests.

fn okhttp_headers(version: OkHttpVersion) -> Vec<(String, String)> {
    let ua = match version {
        OkHttpVersion::V4 => "okhttp/4.12.0",
        OkHttpVersion::V5 => "okhttp/5.0.0-alpha2",
    };

    vec![
        ("accept".into(), "*/*".into()),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        ("user-agent".into(), ua.into()),
        ("accept-encoding".into(), "gzip, deflate, br".into()),
    ]
}

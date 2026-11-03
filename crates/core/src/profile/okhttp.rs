use std::borrow::Cow;

use crate::Error;
use crate::http2::config::{Http2Config, PseudoHeader, SettingId};
use crate::tls::config::{
    AlpnProtocol, EchGrease, ExtensionOrder, TlsConfig, TlsVersion, TrustAnchorOrder,
};

use super::{BrowserProfile, HeaderFamily, Os};

/// `OkHttp` profile factory (Android app HTTP client).
///
/// On Android it does TLS through the platform's Conscrypt (`BoringSSL`), so its `ClientHello` is
/// that of the device's Conscrypt with `OkHttp`'s cipher suites: no GREASE, no ALPS, no ECH, no
/// extension permutation, no cert compression. The profiles are `OkHttp` 4 (4.12.0) and 5 (5.5.0)
/// on Android 14 and later, whose Conscrypt is a Mainline module.
pub struct OkHttp;

impl OkHttp {
    /// Oldest supported `OkHttp` major version.
    pub const MIN_VERSION: u32 = super::releases::OKHTTP_VERSIONS.0;

    /// Newest supported `OkHttp` major version.
    pub const LATEST_VERSION: u32 = super::releases::OKHTTP_VERSIONS.1;

    /// Operating systems `OkHttp` profiles exist for: `OkHttp` impersonates Android apps.
    pub const PLATFORMS: &'static [Os] = &[Os::Android];

    /// `OkHttp` `major` (the latest release of that major version).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for an unsupported version.
    pub fn version(major: u32) -> Result<BrowserProfile, Error> {
        match major {
            4 | 5 => Ok(okhttp_profile(major)),
            _ => Err(Error::InvalidArgument(
                format!("Unsupported OkHttp version: {major}. Supported: 4, 5"),
                None,
            )),
        }
    }

    /// Latest `OkHttp` profile.
    #[must_use]
    pub fn latest() -> BrowserProfile {
        okhttp_profile(Self::LATEST_VERSION)
    }
}

fn okhttp_profile(major: u32) -> BrowserProfile {
    let release = if major == 4 { "4.12.0" } else { "5.5.0" };
    BrowserProfile {
        farble_accept_language: false,
        language_source: None,
        multipart: Some(if major == 4 {
            crate::BoundaryStyle::OkHttp4
        } else {
            crate::BoundaryStyle::OkHttp5
        }),
        header_family: Some(HeaderFamily::OkHttp),
        ua_client_hints: None,
        tls: okhttp_tls(major),
        http2: okhttp_http2(),
        quic: None,
        headers: okhttp_headers(release),
    }
}

const OKHTTP4_CIPHER_LIST: &str = "\
TLS_AES_128_GCM_SHA256:\
TLS_AES_256_GCM_SHA384:\
TLS_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:\
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:\
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:\
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:\
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:\
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:\
TLS_RSA_WITH_AES_128_GCM_SHA256:\
TLS_RSA_WITH_AES_256_GCM_SHA384:\
TLS_RSA_WITH_AES_128_CBC_SHA:\
TLS_RSA_WITH_AES_256_CBC_SHA";

const OKHTTP5_CIPHER_LIST: &str = "\
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

const OKHTTP_CURVES: &str = "X25519:P-256:P-384";

fn okhttp_tls(major: u32) -> TlsConfig {
    let cipher_list = if major == 4 {
        OKHTTP4_CIPHER_LIST
    } else {
        OKHTTP5_CIPHER_LIST
    };
    TlsConfig {
        cipher_list: Cow::Borrowed(cipher_list),
        curves: Cow::Borrowed(OKHTTP_CURVES),
        sigalgs: Cow::Borrowed(OKHTTP_SIGALGS),
        alpn: vec![AlpnProtocol::Http2, AlpnProtocol::Http11],
        alps: None,
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
        grease: false,
        grease_sigalgs: false,
        ech_grease: EchGrease::Off,
        extension_order: ExtensionOrder::Default,
        trust_anchor_ids: None,
        trust_anchor_order: TrustAnchorOrder::Listed,
        omit_session_ticket_on_resumption: false,
        legacy_extensions_in_tls13: false,
        ocsp_stapling: true,
        signed_cert_timestamps: false,
        cert_compression: vec![],
        psk_key_exchange_modes: true,
        session_ticket: true,
        key_shares_limit: None,
        delegated_credentials: None,
        record_size_limit: None,
        server_padding: None,
        server_padding_trial: None,
        preserve_tls13_cipher_order: false,
        danger_accept_invalid_certs: false,
    }
}

fn okhttp_http2() -> Http2Config {
    Http2Config {
        header_table_size: None,
        enable_push: None,
        max_concurrent_streams: None,
        initial_window_size: 16_777_216,
        max_frame_size: None,
        max_header_list_size: None,
        initial_conn_window_size: 16_777_216,
        pseudo_header_order: vec![
            PseudoHeader::Method,
            PseudoHeader::Path,
            PseudoHeader::Authority,
            PseudoHeader::Scheme,
        ],
        settings_order: vec![SettingId::InitialWindowSize],
        headers_stream_dependency: None,
        priorities: Vec::new(),
        no_rfc7540_priorities: None,
        enable_connect_protocol: None,
        initial_stream_id: Some(3),
        write_frames_individually: true,
        write_preface_alone: true,
        write_data_with_headers: true,
        goaway_on_close: false,
        close_notify: true,
        ..Http2Config::default()
    }
}

fn okhttp_headers(release: &str) -> Vec<(String, String)> {
    vec![
        ("accept-encoding".into(), "gzip".into()),
        ("user-agent".into(), format!("okhttp/{release}")),
    ]
}

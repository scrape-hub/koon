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
    pub const MIN_VERSION: u32 = 4;

    /// Newest supported `OkHttp` major version.
    pub const LATEST_VERSION: u32 = 5;

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
        header_family: Some(HeaderFamily::OkHttp),
        ua_client_hints: None,
        tls: okhttp_tls(major),
        http2: okhttp_http2(),
        quic: None,
        headers: okhttp_headers(release),
    }
}

// ========== TLS ==========
// Conscrypt's ClientHello: BoringSSL's extension order, X25519/P-256/P-384 without ML-KEM, one key
// share, padding to 512 bytes, TLS 1.3 PSK resumption with session_ticket kept. OkHttp only chooses
// the cipher suites: those of its connection spec that the socket enables, no 3DES.

/// `OkHttp` 4 keeps the socket's order of the enabled suites, Conscrypt's: the ECDSA suites before
/// the RSA ones.
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

/// `OkHttp` 5 sends them in the order of its connection spec.
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

// Conscrypt: X25519, P-256, P-384 (no ML-KEM, no P-521, no ffdhe).
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
        // Conscrypt keeps BoringSSL's own order.
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

// ========== HTTP/2 ==========
// OkHttp's client SETTINGS carry only INITIAL_WINDOW_SIZE = 16 MiB, followed by a connection
// WINDOW_UPDATE raising the connection window to 16 MiB too (`Http2Connection.okHttpSettings` and
// `start()`). HEADERS frames carry no priority (`Http2Writer.headers`). Pseudo-headers go :method,
// :path, :authority, :scheme (`Http2ExchangeCodec.http2HeadersList`).

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
        // `Http2Connection.nextStreamId` starts a client at 3 (stream 1 is reserved for an HTTP/1.1
        // upgrade): streams 3, 5, 7, ...
        initial_stream_id: Some(3),
        // `Http2Writer` flushes the preface, the SETTINGS, the connection WINDOW_UPDATE and every
        // frame after them one by one, and Conscrypt writes a TLS record per flush; the HEADERS of
        // a request with a body go out with its first DATA frame.
        write_frames_individually: true,
        write_preface_alone: true,
        write_data_with_headers: true,
        // The connection pool closes an idle connection by closing its socket: Conscrypt sends
        // close_notify, OkHttp no GOAWAY.
        goaway_on_close: false,
        close_notify: true,
        ..Http2Config::default()
    }
}

// ========== Headers ==========
// `BridgeInterceptor` adds Accept-Encoding: gzip, Cookie and User-Agent `okhttp/<version>`, plus
// Host and Connection: Keep-Alive on HTTP/1.1 only; no Accept or Accept-Language. The default
// `OkHttpClient()` has no cookie jar; koon's jar stands in for one an app installs, one Cookie
// header joined with "; " between Accept-Encoding and User-Agent.

fn okhttp_headers(release: &str) -> Vec<(String, String)> {
    vec![
        ("accept-encoding".into(), "gzip".into()),
        ("user-agent".into(), format!("okhttp/{release}")),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cipher suites of the captured ClientHellos, TLS 1.2 part: OkHttp 4 in Conscrypt's order,
    /// 5 in its spec's, neither with 3DES.
    #[test]
    fn cipher_order_follows_the_okhttp_version() {
        let tls12 = |major| {
            OkHttp::version(major)
                .unwrap()
                .tls
                .cipher_list
                .split(':')
                .skip(3)
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        let ecdhe = |list: &[String]| list[..6].join(",");
        assert_eq!(
            ecdhe(&tls12(4)),
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,\
             TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,\
             TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        );
        assert_eq!(
            ecdhe(&tls12(5)),
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,\
             TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,\
             TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        );
        for major in [4, 5] {
            assert_eq!(tls12(major).len(), 12);
            assert!(!tls12(major).iter().any(|c| c.contains("3DES")));
            let profile = OkHttp::version(major).unwrap();
            assert!(profile.tls.psk_key_exchange_modes);
            assert_eq!(profile.http2.initial_stream_id, Some(3));
        }
    }
}

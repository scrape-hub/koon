use std::borrow::Cow;

use crate::Error;
use crate::http2::config::{
    ConnectionPing, HeaderCompression, HeadersPriority, Http2Config, PseudoHeader, SettingId,
    WindowUpdateRule,
};
use crate::quic::{QuicConfig, QuicStack};
use crate::tls::config::{
    AlpnProtocol, CertCompression, EchGrease, ExtensionOrder, TlsConfig, TlsVersion,
    TrustAnchorOrder,
};

use super::{BrowserProfile, HeaderFamily, Os, check_platform, check_version};

/// Firefox browser profile factory.
///
/// The H2 fingerprint is identical across
/// [`MIN_VERSION`](Self::MIN_VERSION)-[`LATEST_VERSION`](Self::LATEST_VERSION); the TLS and QUIC
/// `ClientHello` and the Accept-Language weighting are version-dependent (see the version constants
/// below).
pub struct Firefox;

impl Firefox {
    /// Oldest supported Firefox major version.
    pub const MIN_VERSION: u32 = 135;

    /// Newest supported Firefox major version.
    pub const LATEST_VERSION: u32 = 157;

    /// Operating systems Firefox profiles exist for.
    pub const PLATFORMS: &'static [Os] = &[Os::Windows, Os::MacOS, Os::Linux, Os::Android];

    /// Firefox `major` on `os`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for an unsupported version or OS.
    pub fn version(major: u32, os: Os) -> Result<BrowserProfile, Error> {
        check_version("Firefox", major, Self::MIN_VERSION, Self::LATEST_VERSION)?;
        check_platform("Firefox", os, Self::PLATFORMS)?;
        Ok(firefox_profile(major, os))
    }

    /// Latest Firefox on the default OS (Windows): the profile the name `firefox` resolves to.
    #[must_use]
    pub fn latest() -> BrowserProfile {
        firefox_profile(Self::LATEST_VERSION, super::DEFAULT_OS)
    }
}

fn firefox_profile(major: u32, os: Os) -> BrowserProfile {
    if os == Os::Android {
        let tls = firefox_tls_android(major);
        return BrowserProfile {
            farble_accept_language: false,
            header_family: Some(HeaderFamily::Firefox),
            ua_client_hints: None,
            quic: Some(firefox_quic(&tls, major)),
            tls,
            http2: firefox_http2_android(),
            headers: firefox_headers(major, os),
        };
    }
    let tls = firefox_tls(major);
    let mut quic = firefox_quic(&tls, major);
    // `network.dns.native_https_query` is false on macOS up to 150 (`StaticPrefList.yaml`), so the
    // record there comes through TRR (DoH) alone; 151 dropped the macOS gate. Other OSes always ask
    // natively.
    quic.https_rr_doh_only = os == Os::MacOS && major <= 150;
    BrowserProfile {
        farble_accept_language: false,
        header_family: Some(HeaderFamily::Firefox),
        ua_client_hints: None,
        quic: Some(quic),
        tls,
        http2: firefox_http2(),
        headers: firefox_headers(major, os),
    }
}

// ========== TLS ==========
// Identical across Firefox 135–150; later versions drop ciphers and groups, see the version
// constants below.

// TLS 1.3 order: AES_128(4865) → CHACHA20(4867) → AES_256(4866), as real Firefox/NSS sends it.
// Requires preserve_tls13_cipher_order = true.
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

// Firefox 151 drops TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009).
const FIREFOX_CIPHER_LIST_151: &str = "\
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
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:\
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:\
TLS_RSA_WITH_AES_128_GCM_SHA256:\
TLS_RSA_WITH_AES_256_GCM_SHA384:\
TLS_RSA_WITH_AES_128_CBC_SHA:\
TLS_RSA_WITH_AES_256_CBC_SHA";

/// First Firefox version without the ECDSA AES-128-CBC cipher.
const FIREFOX_SLIM_CIPHERS_VERSION: u32 = 151;

// Firefox 154 also drops TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a).
const FIREFOX_CIPHER_LIST_154: &str = "\
TLS_AES_128_GCM_SHA256:\
TLS_CHACHA20_POLY1305_SHA256:\
TLS_AES_256_GCM_SHA384:\
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:\
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:\
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:\
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:\
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:\
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:\
TLS_RSA_WITH_AES_128_GCM_SHA256:\
TLS_RSA_WITH_AES_256_GCM_SHA384:\
TLS_RSA_WITH_AES_128_CBC_SHA:\
TLS_RSA_WITH_AES_256_CBC_SHA";

/// First Firefox version without the ECDSA AES-256-CBC cipher.
const FIREFOX_SLIMMER_CIPHERS_VERSION: u32 = 154;

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

// Firefox 156 drops the finite-field groups.
const FIREFOX_CURVES_156: &str = "X25519MLKEM768:X25519:P-256:P-384:P-521";

/// First Firefox version without ffdhe2048/ffdhe3072.
const FIREFOX_NO_FFDHE_VERSION: u32 = 156;

// Firefox does not permute extensions — it emits this fixed order (the same in every captured
// version), which differs from BoringSSL's internal one and is visible in JA3 (but not JA4, which
// sorts). The list must name every extension the profile sends: BoringSSL appends unlisted ones in
// random order. pre_shared_key is always written last by BoringSSL and is deliberately absent.
const FIREFOX_EXTENSION_ORDER: &[u16] = &[
    0x0000, // server_name
    0x0017, // extended_master_secret
    0xff01, // renegotiation_info
    0x000a, // supported_groups
    0x000b, // ec_point_formats
    0x0023, // session_ticket
    0x0010, // application_layer_protocol_negotiation
    0x0005, // status_request
    0x0022, // delegated_credentials
    0x0012, // signed_certificate_timestamp
    0x0033, // key_share
    0x002b, // supported_versions
    0x000d, // signature_algorithms
    0x002d, // psk_key_exchange_modes
    0x001c, // record_size_limit
    0x001b, // compress_certificate
    0xfe0d, // encrypted_client_hello
];

const FIREFOX_DC_SIGALGS: &str =
    "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:ecdsa_sha1";

/// NSS's ECH GREASE (`tls13_MaybeGreaseEch`, same for TCP and QUIC): AES-128-GCM or
/// ChaCha20-Poly1305 on one random bit, and a payload as long as a real encrypted inner
/// `ClientHello` with the server name padded to `security.tls.ech.grease_size` (100). Up to Firefox
/// 154 NSS padded to one byte short of a multiple of 32.
fn firefox_ech_grease(major: u32) -> EchGrease {
    EchGrease::Nss {
        name_len: 100,
        legacy_padding: major < FIREFOX_ECH_PADDING_FIX_VERSION,
    }
}

/// First Firefox version whose NSS rounds the ECH padding to a multiple of 32.
const FIREFOX_ECH_PADDING_FIX_VERSION: u32 = 155;

fn firefox_tls(major: u32) -> TlsConfig {
    let cipher_list = if major >= FIREFOX_SLIMMER_CIPHERS_VERSION {
        FIREFOX_CIPHER_LIST_154
    } else if major >= FIREFOX_SLIM_CIPHERS_VERSION {
        FIREFOX_CIPHER_LIST_151
    } else {
        FIREFOX_CIPHER_LIST
    };
    let curves = if major >= FIREFOX_NO_FFDHE_VERSION {
        FIREFOX_CURVES_156
    } else {
        FIREFOX_CURVES
    };
    TlsConfig {
        cipher_list: Cow::Borrowed(cipher_list),
        curves: Cow::Borrowed(curves),
        sigalgs: Cow::Borrowed(FIREFOX_SIGALGS),
        alpn: vec![AlpnProtocol::Http2, AlpnProtocol::Http11],
        alps: None,
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
        grease: false,
        grease_sigalgs: false,
        ech_grease: firefox_ech_grease(major),
        extension_order: ExtensionOrder::Fixed(FIREFOX_EXTENSION_ORDER.to_vec()),
        trust_anchor_ids: None,
        trust_anchor_order: TrustAnchorOrder::Listed,
        omit_session_ticket_on_resumption: true,
        legacy_extensions_in_tls13: false,
        ocsp_stapling: true,
        signed_cert_timestamps: true,
        cert_compression: vec![
            CertCompression::Zlib,
            CertCompression::Brotli,
            CertCompression::Zstd,
        ],
        psk_key_exchange_modes: true,
        session_ticket: true,
        key_shares_limit: Some(3),
        delegated_credentials: Some(Cow::Borrowed(FIREFOX_DC_SIGALGS)),
        record_size_limit: Some(16385),
        server_padding: None,
        server_padding_trial: None,
        // Firefox/NSS uses AES_128 → CHACHA20 → AES_256 (differs from BoringSSL default).
        preserve_tls13_cipher_order: true,
        danger_accept_invalid_certs: false,
    }
}

/// First Firefox version that sends `signed_certificate_timestamp` on Android; desktop Firefox
/// sends it in every supported version.
const FIREFOX_ANDROID_SCT_VERSION: u32 = 155;

// Firefox Android TLS: desktop's, without signed_certificate_timestamp up to 154; from 155 on the
// same ClientHello as desktop.
fn firefox_tls_android(major: u32) -> TlsConfig {
    TlsConfig {
        signed_cert_timestamps: major >= FIREFOX_ANDROID_SCT_VERSION,
        ..firefox_tls(major)
    }
}

// ========== HTTP/2 ==========
// Frame-level behaviour: netwerk/protocol/http/Http2Session.cpp, Http2StreamBase.cpp and
// Http2Compression.cpp.

/// Receive window a stream is raised to right after its HEADERS
/// (`network.http.http2.pull-allowance`, 12 MB; `AdjustInitialWindow`).
const FIREFOX_PULL_ALLOWANCE: u32 = 12 * 1024 * 1024;

/// Firefox returns consumed data in steps of at least `kMinimumToAck` (4 MB), or at once when a
/// window is down to `kEmergencyWindowThreshold` (96 KB) (`Http2Session::UpdateLocalStreamWindow`,
/// `UpdateLocalSessionWindow`).
const FIREFOX_WINDOW_UPDATE: WindowUpdateRule = WindowUpdateRule {
    threshold: 4 * 1024 * 1024,
    low_window: Some(96 * 1024),
    interval_ms: None,
};

fn firefox_http2() -> Http2Config {
    Http2Config {
        header_table_size: Some(65536),
        enable_push: Some(false),
        max_concurrent_streams: None,
        initial_window_size: 131_072,
        max_frame_size: Some(16384),
        max_header_list_size: None,
        initial_conn_window_size: 12_582_912,
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
        // No RFC 7540 PRIORITY frames (the Akamai PRIORITY segment is "0").
        priorities: Vec::new(),
        no_rfc7540_priorities: None,
        enable_connect_protocol: None,
        // `mNextStreamID(3)`: streams 3, 5, 7, ...
        initial_stream_id: Some(3),
        // Every HEADERS carries a priority block.
        headers_priority: Some(HeadersPriority::Firefox),
        initial_stream_window_size: Some(FIREFOX_PULL_ALLOWANCE),
        stream_window_update: Some(FIREFOX_WINDOW_UPDATE),
        connection_window_update: Some(FIREFOX_WINDOW_UPDATE),
        header_compression: Some(HeaderCompression::Firefox),
        // [preface, SETTINGS, WINDOW_UPDATE], then one record per request (HEADERS + its
        // WINDOW_UPDATE) or frame.
        write_frames_individually: true,
        write_preface_alone: false,
        write_data_with_headers: false,
        // `kMaxFrameData` (16 KB) per HEADERS/CONTINUATION frame, whatever the server allows.
        max_header_frame_size: Some(16_384),
        // `network.http.http2.ping-threshold` (58 s) without reads, then `ping-timeout` (8 s) for
        // the answer.
        ping: Some(ConnectionPing::Idle {
            idle_ms: 58_000,
            timeout_ms: 8_000,
        }),
        // Close with GOAWAY(NO_ERROR), close_notify, FIN.
        goaway_on_close: true,
        close_notify: true,
    }
}

// Firefox Android H2: smaller header_table_size (4096) and initial_window_size (32768) than
// desktop.
fn firefox_http2_android() -> Http2Config {
    Http2Config {
        header_table_size: Some(4096),
        initial_window_size: 32768,
        ..firefox_http2()
    }
}

// ========== QUIC ==========
// neqo's ClientHello and transport parameters; earlier versions assumed from the same source where
// uncaptured.

/// Signature algorithms of the QUIC `ClientHello`, which NSS configures apart from the TCP one:
/// NSS's defaults without DSA, SHA-1 last per family.
const FIREFOX_QUIC_SIGALGS: &str = "\
ecdsa_secp256r1_sha256:\
ecdsa_secp384r1_sha384:\
ecdsa_secp521r1_sha512:\
ecdsa_sha1:\
rsa_pss_rsae_sha256:\
rsa_pss_rsae_sha384:\
rsa_pss_rsae_sha512:\
rsa_pkcs1_sha256:\
rsa_pkcs1_sha384:\
rsa_pkcs1_sha512:\
rsa_pkcs1_sha1";

/// Firefox 156's QUIC signature algorithms, with ML-DSA.
const FIREFOX_QUIC_SIGALGS_MLDSA: &str = "\
ecdsa_secp256r1_sha256:\
ecdsa_secp384r1_sha384:\
ecdsa_secp521r1_sha512:\
ecdsa_sha1:\
rsa_pss_rsae_sha256:\
rsa_pss_rsae_sha384:\
rsa_pss_rsae_sha512:\
mldsa44:\
mldsa65:\
mldsa87:\
rsa_pkcs1_sha256:\
rsa_pkcs1_sha384:\
rsa_pkcs1_sha512:\
rsa_pkcs1_sha1";

/// `delegated_credentials` of the QUIC `ClientHello`.
const FIREFOX_QUIC_DC_SIGALGS: &str = "\
ecdsa_secp256r1_sha256:\
ecdsa_secp384r1_sha384:\
ecdsa_secp521r1_sha512:\
ecdsa_sha1";

/// `delegated_credentials` of Firefox 156's QUIC `ClientHello`, with ML-DSA.
const FIREFOX_QUIC_DC_SIGALGS_MLDSA: &str = "\
ecdsa_secp256r1_sha256:\
ecdsa_secp384r1_sha384:\
ecdsa_secp521r1_sha512:\
ecdsa_sha1:\
mldsa44:\
mldsa65:\
mldsa87";

/// The only Firefox version whose QUIC `ClientHello` offers ML-DSA: NSS 156 added the schemes to
/// its defaults, 157 turns them off again by policy (`security.tls.enable_mldsa`, `SetKyberPolicy`
/// in nsNSSComponent.cpp). The TCP hello sets its own list and never had them.
const FIREFOX_QUIC_MLDSA_VERSION: u32 = 156;

/// Groups of the QUIC `ClientHello`: `neqo_glue` sets them itself (`set_groups`), without the
/// finite-field groups of the TCP hello up to Firefox 155 (captured from Firefox 155).
const FIREFOX_QUIC_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384:P-521";

/// Extensions of the QUIC `ClientHello` that NSS permutes on every handshake.
/// `quic_transport_parameters` and `encrypted_client_hello` follow them in this order,
/// `pre_shared_key` comes last.
const FIREFOX_QUIC_PERMUTED_EXTENSIONS: &[u16] = &[
    0x0000, // server_name
    0x0005, // status_request
    0x000a, // supported_groups
    0x000d, // signature_algorithms
    0x0010, // application_layer_protocol_negotiation
    0x0017, // extended_master_secret
    0x001b, // compress_certificate
    0x001c, // record_size_limit
    0x0022, // delegated_credentials
    0x002a, // early_data (resumption)
    0x002b, // supported_versions
    0x002d, // psk_key_exchange_modes
    0x0033, // key_share
    0xff01, // renegotiation_info
];

/// First Firefox version that offers QUIC version 2 in `version_information` (`GREASE, v2, v1`); up
/// to 154 it offers `GREASE, v1` only.
const FIREFOX_QUIC_V2_VERSION: u32 = 155;

/// First Firefox version that sends the `reset_stream_at` transport parameter (0x1d,
/// `ConnectionParameters::reliable_stream_reset`, on by default in neqo from 155).
const FIREFOX_RESET_STREAM_AT_VERSION: u32 = 155;

const FIREFOX_QUIC_EXTENSION_TAIL: &[u16] = &[
    0x0039, // quic_transport_parameters
    0xfe0d, // encrypted_client_hello
];

/// QUIC and HTTP/3 of Firefox `major` whose TCP `ClientHello` is `tls`.
///
/// The QUIC `ClientHello` differs from the TCP one: no `signed_certificate_timestamp`, no
/// finite-field groups, other signature algorithms and delegated credentials, and a permuted
/// extension order with `quic_transport_parameters`/`encrypted_client_hello` pinned at the end.
fn firefox_quic(tls: &TlsConfig, major: u32) -> QuicConfig {
    let (sigalgs, dc_sigalgs) = if major == FIREFOX_QUIC_MLDSA_VERSION {
        (FIREFOX_QUIC_SIGALGS_MLDSA, FIREFOX_QUIC_DC_SIGALGS_MLDSA)
    } else {
        (FIREFOX_QUIC_SIGALGS, FIREFOX_QUIC_DC_SIGALGS)
    };
    QuicConfig {
        stack: QuicStack::Neqo,
        quic_v2: major >= FIREFOX_QUIC_V2_VERSION,
        reset_stream_at: major >= FIREFOX_RESET_STREAM_AT_VERSION,
        tls: Some(TlsConfig {
            curves: Cow::Borrowed(FIREFOX_QUIC_CURVES),
            sigalgs: Cow::Borrowed(sigalgs),
            signed_cert_timestamps: false,
            extension_order: ExtensionOrder::PermutedWithTail {
                permuted: FIREFOX_QUIC_PERMUTED_EXTENSIONS.to_vec(),
                tail: FIREFOX_QUIC_EXTENSION_TAIL.to_vec(),
            },
            cert_compression: vec![
                CertCompression::Zlib,
                CertCompression::Zstd,
                CertCompression::Brotli,
            ],
            delegated_credentials: Some(Cow::Borrowed(dc_sigalgs)),
            legacy_extensions_in_tls13: true,
            ..tls.clone()
        }),
        max_idle_timeout_ms: 30_000,
        max_udp_payload_size: None,
        initial_max_data: 25_165_824,
        initial_max_stream_data_bidi_local: 12_582_912,
        initial_max_stream_data_bidi_remote: 1_048_576,
        initial_max_stream_data_uni: 1_048_576,
        initial_max_streams_bidi: 100,
        initial_max_streams_uni: 100,
        max_ack_delay_ms: Some(20),
        active_connection_id_limit: Some(8),
        max_datagram_frame_size: Some(65_535),
        max_datagram_size: 1252,
        keep_alive_ms: Some(15_000),
        qpack_max_table_capacity: 65_536,
        qpack_blocked_streams: 20,
        max_field_section_size: None,
        extra_transport_parameters: Vec::new(),
        session_resumption: true,
        alt_svc: true,
        // `network.dns.use_https_rr_as_altsvc` is on by default; whether the system resolver asks
        // for the record is per OS (`firefox_profile`).
        https_rr: true,
        https_rr_doh_only: false,
    }
}

// ========== Headers ==========

/// First Firefox version that weights Accept-Language in Chrome's 0.1 steps (`en-US,en;q=0.9`)
/// instead of splitting 1.0 evenly (`en-US,en;q=0.5`).
pub(crate) const FIREFOX_WEIGHTED_ACCEPT_LANGUAGE_VERSION: u32 = 147;

/// The Android release in the User-Agent of the Android profiles: Firefox reports the device's real
/// one, as the Chrome Android profiles do.
const ANDROID_RELEASE: &str = "17";

fn firefox_headers(major: u32, os: Os) -> Vec<(String, String)> {
    let ver = major.to_string();

    let user_agent = match os {
        Os::Windows => format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{ver}.0) Gecko/20100101 Firefox/{ver}.0"
        ),
        Os::MacOS => format!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{ver}.0) Gecko/20100101 Firefox/{ver}.0"
        ),
        Os::Linux => {
            format!("Mozilla/5.0 (X11; Linux x86_64; rv:{ver}.0) Gecko/20100101 Firefox/{ver}.0")
        }
        Os::Android => format!(
            "Mozilla/5.0 (Android {ANDROID_RELEASE}; Mobile; rv:{ver}.0) Gecko/{ver}.0 Firefox/{ver}.0"
        ),
        Os::Ios => unreachable!("no Firefox profile for iOS"),
    };

    let accept_language = if major >= FIREFOX_WEIGHTED_ACCEPT_LANGUAGE_VERSION {
        "en-US,en;q=0.9"
    } else {
        "en-US,en;q=0.5"
    };

    // HTTP/2 order of a navigation, captured from Firefox 156: `te` comes after `priority`.
    vec![
        ("user-agent".into(), user_agent),
        (
            "accept".into(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into(),
        ),
        ("accept-language".into(), accept_language.into()),
        ("accept-encoding".into(), "gzip, deflate, br, zstd".into()),
        ("upgrade-insecure-requests".into(), "1".into()),
        ("sec-fetch-dest".into(), "document".into()),
        ("sec-fetch-mode".into(), "navigate".into()),
        ("sec-fetch-site".into(), "none".into()),
        ("sec-fetch-user".into(), "?1".into()),
        ("priority".into(), "u=0, i".into()),
        ("te".into(), "trailers".into()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> &'a str {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("no {name} header"))
    }

    #[test]
    fn cipher_list_drops_at_151_and_154() {
        let ciphers = |major| firefox_tls(major).cipher_list.into_owned();
        assert!(ciphers(150).contains("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"));
        assert!(!ciphers(151).contains("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"));
        assert!(ciphers(151).contains("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"));
        assert!(!ciphers(154).contains("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"));
        // Both drops apply from their version on, not just at it.
        assert!(!ciphers(157).contains("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"));
        assert!(!ciphers(157).contains("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"));
    }

    #[test]
    fn curves_drop_the_ffdhe_groups_at_156() {
        let curves = |major| firefox_tls(major).curves.into_owned();
        assert!(curves(155).contains("ffdhe2048"));
        assert!(curves(155).contains("ffdhe3072"));
        assert!(!curves(156).contains("ffdhe2048"));
        assert!(!curves(156).contains("ffdhe3072"));
    }

    #[test]
    fn ech_padding_fix_at_155() {
        let legacy_padding = |major| match firefox_tls(major).ech_grease {
            EchGrease::Nss { legacy_padding, .. } => legacy_padding,
            other => panic!("expected EchGrease::Nss, got {other:?}"),
        };
        assert!(legacy_padding(154));
        assert!(!legacy_padding(155));
    }

    #[test]
    fn quic_mldsa_only_at_156() {
        let sigalgs = |major| {
            firefox_quic(&firefox_tls(major), major)
                .tls
                .unwrap()
                .sigalgs
                .into_owned()
        };
        assert!(!sigalgs(155).contains("mldsa"));
        assert!(sigalgs(156).contains("mldsa44"));
        // 157 turns ML-DSA off by policy again.
        assert!(!sigalgs(157).contains("mldsa"));
    }

    #[test]
    fn quic_v2_and_reset_stream_at_from_155() {
        let quic = |major| firefox_quic(&firefox_tls(major), major);
        assert!(!quic(154).quic_v2);
        assert!(!quic(154).reset_stream_at);
        assert!(quic(155).quic_v2);
        assert!(quic(155).reset_stream_at);
    }

    #[test]
    fn android_sends_no_sct_before_155() {
        let sct = |major| firefox_tls_android(major).signed_cert_timestamps;
        assert!(!sct(154));
        assert!(sct(155));
        // Desktop always sends it.
        assert!(firefox_tls(154).signed_cert_timestamps);
    }

    #[test]
    fn accept_language_weighting_changes_at_147() {
        assert_eq!(
            header(&firefox_headers(146, Os::Windows), "accept-language"),
            "en-US,en;q=0.5"
        );
        assert_eq!(
            header(&firefox_headers(147, Os::Windows), "accept-language"),
            "en-US,en;q=0.9"
        );
    }

    #[test]
    fn every_version_builds_on_every_platform() {
        for major in Firefox::MIN_VERSION..=Firefox::LATEST_VERSION {
            for &os in Firefox::PLATFORMS {
                Firefox::version(major, os).unwrap();
            }
        }
    }
}

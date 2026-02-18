use std::borrow::Cow;

use serde::{Deserialize, Serialize};

/// TLS fingerprint configuration.
///
/// Controls every aspect of the TLS ClientHello that anti-bot systems
/// like Akamai use for fingerprinting (JA3/JA4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// BoringSSL cipher list string (colon-separated).
    /// Controls cipher suite order in the ClientHello.
    pub cipher_list: Cow<'static, str>,

    /// Supported elliptic curves (colon-separated).
    pub curves: Cow<'static, str>,

    /// Signature algorithms (colon-separated).
    pub sigalgs: Cow<'static, str>,

    /// ALPN protocols to advertise.
    pub alpn: Vec<AlpnProtocol>,

    /// ALPS protocols.
    pub alps: Option<AlpsProtocol>,

    /// Whether to use the new ALPS codepoint.
    pub alps_use_new_codepoint: bool,

    /// Minimum TLS version.
    pub min_version: TlsVersion,

    /// Maximum TLS version.
    pub max_version: TlsVersion,

    /// Enable GREASE (Generate Random Extensions And Sustain Extensibility).
    pub grease: bool,

    /// Enable ECH (Encrypted Client Hello) GREASE.
    pub ech_grease: bool,

    /// Permute TLS extensions (Chrome 110+ behavior).
    pub permute_extensions: bool,

    /// Enable OCSP stapling.
    pub ocsp_stapling: bool,

    /// Enable Signed Certificate Timestamps.
    pub signed_cert_timestamps: bool,

    /// Certificate compression algorithms.
    pub cert_compression: Vec<CertCompression>,

    /// Pre-shared key support.
    pub pre_shared_key: bool,

    /// Enable session tickets.
    pub session_ticket: bool,

    /// Key shares limit.
    pub key_shares_limit: Option<u8>,

    /// Delegated credentials sigalgs.
    pub delegated_credentials: Option<Cow<'static, str>>,

    /// Whether to disable certificate verification (for testing only).
    pub danger_accept_invalid_certs: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlpnProtocol {
    #[serde(rename = "h2")]
    Http2,
    #[serde(rename = "http/1.1")]
    Http11,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlpsProtocol {
    #[serde(rename = "h2")]
    Http2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertCompression {
    Brotli,
    Zlib,
    Zstd,
}

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig {
            cipher_list: Cow::Borrowed("DEFAULT"),
            curves: Cow::Borrowed("X25519:P-256:P-384"),
            sigalgs: Cow::Borrowed(
                "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
                 ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:\
                 rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
            ),
            alpn: vec![AlpnProtocol::Http2, AlpnProtocol::Http11],
            alps: None,
            alps_use_new_codepoint: false,
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            grease: false,
            ech_grease: false,
            permute_extensions: false,
            ocsp_stapling: false,
            signed_cert_timestamps: false,
            cert_compression: Vec::new(),
            pre_shared_key: false,
            session_ticket: true,
            key_shares_limit: None,
            delegated_credentials: None,
            danger_accept_invalid_certs: false,
        }
    }
}

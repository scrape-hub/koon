//! Safari's TLS `ClientHello`.

use std::borrow::Cow;

use crate::tls::config::{
    AlpnProtocol, CertCompression, EchGrease, ExtensionOrder, TlsConfig, TlsVersion,
    TrustAnchorOrder,
};

use super::Stack;

// Every release: the 3DES suites still at the end.
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

// macOS and iOS 26 on: the TLS 1.3 suites AES-256, ChaCha20, AES-128.
const SAFARI_TAHOE_CIPHER_LIST: &str = "\
TLS_AES_256_GCM_SHA384:\
TLS_CHACHA20_POLY1305_SHA256:\
TLS_AES_128_GCM_SHA256:\
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

const SAFARI_CURVES: &str = "X25519:P-256:P-384:P-521";
const SAFARI_TAHOE_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384:P-521";

// With ecdsa_sha1 and rsa_pss_rsae_sha384 twice, as every capture has it; the btls fork's BoringSSL
// patch removes the uniqueness check that would reject the duplicate.
const SAFARI_SONOMA_SIGALGS: &str = "\
ecdsa_secp256r1_sha256:\
rsa_pss_rsae_sha256:\
rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:\
ecdsa_sha1:\
rsa_pss_rsae_sha384:\
rsa_pss_rsae_sha384:\
rsa_pkcs1_sha384:\
rsa_pss_rsae_sha512:\
rsa_pkcs1_sha512:\
rsa_pkcs1_sha1";

// From macOS 15.2 and iOS 18.2 on: without ecdsa_sha1.
const SAFARI_SIGALGS: &str = "\
ecdsa_secp256r1_sha256:\
rsa_pss_rsae_sha256:\
rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:\
rsa_pss_rsae_sha384:\
rsa_pss_rsae_sha384:\
rsa_pkcs1_sha384:\
rsa_pss_rsae_sha512:\
rsa_pkcs1_sha512:\
rsa_pkcs1_sha1";

pub(super) fn safari_tls(stack: Stack) -> TlsConfig {
    let (cipher_list, curves, sigalgs) = match stack {
        Stack::Sonoma => (SAFARI_CIPHER_LIST, SAFARI_CURVES, SAFARI_SONOMA_SIGALGS),
        Stack::Sequoia => (SAFARI_CIPHER_LIST, SAFARI_CURVES, SAFARI_SIGALGS),
        Stack::Tahoe => (
            SAFARI_TAHOE_CIPHER_LIST,
            SAFARI_TAHOE_CURVES,
            SAFARI_SIGALGS,
        ),
    };
    TlsConfig {
        cipher_list: Cow::Borrowed(cipher_list),
        curves: Cow::Borrowed(curves),
        sigalgs: Cow::Borrowed(sigalgs),
        alpn: vec![AlpnProtocol::Http2, AlpnProtocol::Http11],
        alps: None,
        // Up to macOS 15 and iOS 18, supported_versions still lists TLS 1.1 and 1.0.
        min_version: if stack == Stack::Tahoe {
            TlsVersion::Tls12
        } else {
            TlsVersion::Tls10
        },
        max_version: TlsVersion::Tls13,
        grease: true,
        grease_sigalgs: false,
        ech_grease: EchGrease::Off,
        // BoringSSL's order is Safari's, in every release.
        extension_order: ExtensionOrder::Default,
        trust_anchor_ids: None,
        trust_anchor_order: TrustAnchorOrder::Listed,
        omit_session_ticket_on_resumption: false,
        legacy_extensions_in_tls13: false,
        ocsp_stapling: true,
        signed_cert_timestamps: true,
        cert_compression: vec![CertCompression::Zlib],
        // Sent although Safari never offers a PSK over TCP.
        psk_key_exchange_modes: true,
        session_ticket: false,
        // BoringSSL's choice is Safari's: X25519, from 26 on X25519MLKEM768 and X25519.
        key_shares_limit: None,
        delegated_credentials: None,
        record_size_limit: None,
        server_padding: None,
        server_padding_trial: None,
        // Safari's TLS 1.3 order on every machine, not BoringSSL's hardware-dependent one.
        preserve_tls13_cipher_order: true,
        danger_accept_invalid_certs: false,
    }
}

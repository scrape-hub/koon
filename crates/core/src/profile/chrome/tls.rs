use std::borrow::Cow;

use crate::Error;
use crate::tls::config::{
    AlpnProtocol, AlpsCodepoint, CertCompression, EchGrease, ExtensionOrder, ServerPaddingGroup,
    ServerPaddingTrial, TlsConfig, TlsVersion, TrustAnchorId, TrustAnchorOrder,
};

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

const CHROME_SIGALGS_MLDSA: &str = "\
mldsa44:\
mldsa65:\
mldsa87:\
ecdsa_secp256r1_sha256:\
rsa_pss_rsae_sha256:\
rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:\
rsa_pss_rsae_sha384:\
rsa_pkcs1_sha384:\
rsa_pss_rsae_sha512:\
rsa_pkcs1_sha512";

const CHROMIUM_MLDSA_VERSION: u32 = 150;

const CHROME_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384";

pub(super) const CHROME_TRUST_ANCHORS_VERSION: u32 = 152;

const CHROMIUM_SIGALGS_GREASE_VERSION: u32 = 152;

const CHROMIUM_NEW_ALPS_VERSION: u32 = 135;

const CHROMIUM_SORTED_TRUST_ANCHORS_VERSION: u32 = 154;

pub(super) const CHROME_PQC_BANDWIDTH_VERSION: u32 = 151;

const PQC_BANDWIDTH_BYTES: [u16; 6] = [6000, 9000, 12000, 14000, 16000, 0];

const PQC_BANDWIDTH_ENDS_AT: u64 = 1_793_318_400;

pub(super) fn pqc_bandwidth_experiment() -> ServerPaddingTrial {
    ServerPaddingTrial {
        enrolled_slots: 6,
        slots: 100,
        groups: PQC_BANDWIDTH_BYTES
            .iter()
            .map(|&bytes| ServerPaddingGroup { weight: 1, bytes })
            .collect(),
        ends_at: Some(PQC_BANDWIDTH_ENDS_AT),
    }
}

pub fn chromium_trust_anchor_ids(
    chromium_major: u32,
    trust_anchors: bool,
) -> Result<Option<Vec<TrustAnchorId>>, Error> {
    if !trust_anchors {
        return Ok(None);
    }
    crate::tls::root_store::chrome_trust_anchor_ids(chromium_major)
        .map(Some)
        .ok_or_else(|| {
            Error::InvalidArgument(
                format!("The Chrome Root Store of Chromium {chromium_major} is not embedded"),
                None,
            )
        })
}

pub(super) const CHROME_152_MACOS_TRUST_ANCHOR_ORDER: [&[u8]; 32] = [
    b"\xd6\x79\x09\x06",
    b"\x83\x9a\x64\x8c\x9b\x2d\x01\x07",
    b"\xd6\x79\x09\x0c",
    b"\x82\xdf\x13\x02\x06",
    b"\x82\xdf\x13\x02\x13",
    b"\x83\x9a\x64\x8c\x9b\x2d\x01\x0d",
    b"\xd6\x79\x09\x01",
    b"\x82\xdf\x13\x02\x0d",
    b"\xd6\x79\x09\x0d",
    b"\x82\xdf\x13\x02\x0f",
    b"\x83\x9a\x64\x8c\x9b\x2d\x01\x08",
    b"\x82\xdf\x13\x02\x12",
    b"\x83\x9a\x64\x8c\x9b\x2d\x01\x09",
    b"\xd6\x79\x09\x02",
    b"\x82\xdf\x13\x02\x01",
    b"\xd6\x79\x09\x0e",
    b"\xd6\x79\x09\x09",
    b"\x83\x9a\x64\x8c\x9b\x2d\x01\x0a",
    b"\xd6\x79\x09\x03",
    b"\xd6\x79\x09\x0f",
    b"\x83\x9a\x64\x8c\x9b\x2d\x01\x0b",
    b"\xd6\x79\x09\x04",
    b"\x82\xdf\x13\x02\x14",
    b"\xd6\x79\x09\x0a",
    b"\x83\x9a\x64\x8c\x9b\x2d\x01\x13",
    b"\x83\x9a\x64\x8c\x9b\x2d\x01\x12",
    b"\xd6\x79\x09\x07",
    b"\xd6\x79\x09\x08",
    b"\x83\x9a\x64\x8c\x9b\x2d\x01\x0c",
    b"\xd6\x79\x09\x05",
    b"\x82\xdf\x13\x02\x0e",
    b"\xd6\x79\x09\x0b",
];

pub fn chromium_tls(
    chromium_major: u32,
    trust_anchor_ids: Option<Vec<TrustAnchorId>>,
) -> TlsConfig {
    let sigalgs = if chromium_major >= CHROMIUM_MLDSA_VERSION {
        CHROME_SIGALGS_MLDSA
    } else {
        CHROME_SIGALGS
    };
    let trust_anchor_order =
        if trust_anchor_ids.is_some() && chromium_major < CHROMIUM_SORTED_TRUST_ANCHORS_VERSION {
            TrustAnchorOrder::ShuffledPerClient
        } else {
            TrustAnchorOrder::Listed
        };
    TlsConfig {
        cipher_list: Cow::Borrowed(CHROME_CIPHER_LIST),
        curves: Cow::Borrowed(CHROME_CURVES),
        sigalgs: Cow::Borrowed(sigalgs),
        alpn: vec![AlpnProtocol::Http2, AlpnProtocol::Http11],
        alps: Some(if chromium_major >= CHROMIUM_NEW_ALPS_VERSION {
            AlpsCodepoint::New
        } else {
            AlpsCodepoint::Old
        }),
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
        grease: true,
        grease_sigalgs: chromium_major >= CHROMIUM_SIGALGS_GREASE_VERSION,
        ech_grease: EchGrease::BoringSsl,
        extension_order: ExtensionOrder::Permuted,
        trust_anchor_ids,
        trust_anchor_order,
        omit_session_ticket_on_resumption: false,
        legacy_extensions_in_tls13: false,
        ocsp_stapling: true,
        signed_cert_timestamps: true,
        cert_compression: vec![CertCompression::Brotli],
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

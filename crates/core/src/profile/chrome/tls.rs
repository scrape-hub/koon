//! Chromium-family TLS `ClientHello` (Chrome, Edge, Opera and derived browsers).

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

// From Chromium 150 on, the post-quantum ML-DSA schemes (FIPS 204) come first in
// signature_algorithms.
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

/// First Chromium version that advertises ML-DSA signature algorithms.
const CHROMIUM_MLDSA_VERSION: u32 = 150;

const CHROME_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384";

/// First Chrome version that sends the `trust_anchors` extension (0xCA34, feature
/// `TLSTrustAnchorIDs`), filled with the trust anchor IDs of its Chrome Root Store, over TCP and
/// QUIC. Chrome for Testing sends it empty from 141 on (its field trial testing configuration turns
/// the feature on early).
pub(super) const CHROME_TRUST_ANCHORS_VERSION: u32 = 152;

/// First Chromium version that puts a GREASE value first in `signature_algorithms`.
const CHROMIUM_SIGALGS_GREASE_VERSION: u32 = 152;

/// ALPS moved from codepoint 0x4469 to 0x44CD in Chromium 135.
const CHROMIUM_NEW_ALPS_VERSION: u32 = 135;

/// First Chromium version that sorts its trust anchor IDs; earlier versions send them in
/// `absl::flat_hash_set` iteration order.
const CHROMIUM_SORTED_TRUST_ANCHORS_VERSION: u32 = 154;

/// First Chrome version in the Finch study `PqcBandwidthExperiment`: a client drawn into it asks
/// servers for padding via the `server_padding` extension (0x12E0,
/// `SSLContextConfig::RequestServerPadding`), same on TCP and QUIC, split over
/// [`PQC_BANDWIDTH_BYTES`]. Chrome for Testing sends the extension always.
pub(super) const CHROME_PQC_BANDWIDTH_VERSION: u32 = 151;

/// The padding of the six groups of `PqcBandwidthExperiment` (`Enabled_06000` to `Enabled_16000`
/// and `Enabled_00000`, each weight 1). 0 still sends the extension.
const PQC_BANDWIDTH_BYTES: [u16; 6] = [6000, 9000, 12000, 14000, 16000, 0];

/// `PqcBandwidthExperiment` as a [`ServerPaddingTrial`]: 6 of 100 slots, the groups of
/// [`PQC_BANDWIDTH_BYTES`] with equal weight.
pub(super) fn pqc_bandwidth_experiment() -> ServerPaddingTrial {
    ServerPaddingTrial {
        enrolled_slots: 6,
        slots: 100,
        groups: PQC_BANDWIDTH_BYTES
            .iter()
            .map(|&bytes| ServerPaddingGroup { weight: 1, bytes })
            .collect(),
    }
}

/// The trust anchor IDs a Chromium profile of `chromium_major` sends, if `trust_anchors`: those of
/// the Chrome Root Store compiled into that release (`tests/chrome_root_store.rs` embeds the store
/// of every release from 152 on). The one lookup [`chromium_tls`]'s caller validates the version
/// with and builds the profile from, so a release whose store is not embedded is an error, not a
/// panic building the profile.
///
/// # Errors
///
/// [`Error::InvalidArgument`] if `trust_anchors` but `chromium_major`'s store is not embedded.
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

/// The trust anchor IDs of Chrome 152 on macOS over TCP, in the fixed order it sends them (Chrome
/// 152/153 on Windows pick a new order per browser start instead; over QUIC the order changes per
/// session on both OSes).
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

/// TLS config of Chromium-based browsers. Version-dependent: the ALPS codepoint (≥135), ML-DSA
/// signature algorithms (≥150), the GREASE signature algorithm (≥152), and the `trust_anchors`
/// extension, which each browser adopts on its own (Chrome from 152, Opera from 136, Edge never).
///
/// `trust_anchor_ids`, from [`chromium_trust_anchor_ids`], carries the IDs of the Chrome Root Store
/// compiled into the release, letting a server pick or shorten its chain for an anchor Chrome
/// trusts; koon's root store verifies such a chain by holding every embedded Chrome anchor
/// alongside Mozilla's. Chromium 152–153 list the IDs in hash-set order
/// ([`CHROME_152_MACOS_TRUST_ANCHOR_ORDER`] is macOS's fixed exception); 154 sorts them.
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
        // Chrome shuffles its extension order on every handshake, so there is no fixed order to
        // reproduce.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{Chrome, Opera, Os};

    #[test]
    fn trust_anchors_by_version() {
        let tls = |major| Chrome::version(major, Os::Windows).unwrap().tls;
        let ids = |major| tls(major).trust_anchor_ids.map(|ids| ids.len());
        assert_eq!(ids(140), None);
        assert_eq!(ids(151), None);
        assert_eq!(ids(152), Some(32));
        assert_eq!(ids(153), Some(28));
        assert_eq!(ids(154), Some(28));
        // Chrome 155 ships store version 39 unchanged.
        assert_eq!(ids(155), Some(28));
        assert_eq!(tls(155).trust_anchor_ids, tls(154).trust_anchor_ids);
        assert_eq!(
            tls(153).trust_anchor_order,
            TrustAnchorOrder::ShuffledPerClient
        );
        assert_eq!(tls(154).trust_anchor_order, TrustAnchorOrder::Listed);
        let sorted = tls(154).trust_anchor_ids.unwrap();
        assert!(sorted.is_sorted());
    }

    /// Chrome sends trust_anchors from 152 on only, on every OS, over TCP and QUIC.
    #[test]
    fn trust_anchors_from_152_on_every_os() {
        for &os in Chrome::PLATFORMS {
            for major in [141, 149, 150, 151, 152, 155] {
                let profile = Chrome::version(major, os).unwrap();
                let quic = profile.quic.unwrap().tls.unwrap();
                assert_eq!(profile.tls.trust_anchor_ids.is_some(), major >= 152);
                assert_eq!(quic.trust_anchor_ids.is_some(), major >= 152);
            }
        }
    }

    /// `PqcBandwidthExperiment` from 151 on, on every OS and over TCP and QUIC; no fixed padding in
    /// the profile.
    #[test]
    fn pqc_bandwidth_experiment_from_151() {
        for &os in Chrome::PLATFORMS {
            for major in [150, 151, 155] {
                let profile = Chrome::version(major, os).unwrap();
                let quic = profile.quic.unwrap().tls.unwrap();
                let trial = (major >= 151).then(pqc_bandwidth_experiment);
                assert_eq!(profile.tls.server_padding_trial, trial);
                assert_eq!(quic.server_padding_trial, trial);
                assert_eq!(profile.tls.server_padding, None);
            }
        }
    }

    /// 6 % of clients take part, spread evenly over the six groups.
    #[test]
    fn pqc_bandwidth_experiment_draws_the_seed_weights() {
        use rand::SeedableRng;

        let trial = pqc_bandwidth_experiment();
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let draws = 600_000;
        let mut counts = std::collections::HashMap::new();
        for _ in 0..draws {
            *counts.entry(trial.draw(&mut rng)).or_insert(0u32) += 1;
        }
        let share = |value| f64::from(counts[&value]) / f64::from(draws);
        assert!((share(None) - 0.94).abs() < 0.002, "{counts:?}");
        for bytes in PQC_BANDWIDTH_BYTES {
            assert!((share(Some(bytes)) - 0.01).abs() < 0.001, "{counts:?}");
        }
        assert_eq!(counts.len(), 7);
    }

    /// Chrome 152 on macOS sends its IDs in one captured order over TCP; a new order per QUIC
    /// session, as on Windows.
    #[test]
    fn chrome_152_macos_sends_the_captured_order() {
        let profile = Chrome::version(152, Os::MacOS).unwrap();
        assert_eq!(profile.tls.trust_anchor_order, TrustAnchorOrder::Listed);
        let mut ids = profile.tls.trust_anchor_ids.clone().unwrap();
        assert_eq!(ids[0].as_bytes(), b"\xd6\x79\x09\x06");
        ids.sort();
        assert_eq!(
            Some(ids),
            crate::tls::root_store::chrome_trust_anchor_ids(152)
        );
        let quic = profile.quic.unwrap().tls.unwrap();
        assert_eq!(
            quic.trust_anchor_order,
            TrustAnchorOrder::ShuffledPerConnection
        );
        let windows = Chrome::version(152, Os::Windows).unwrap().tls;
        assert_eq!(
            windows.trust_anchor_order,
            TrustAnchorOrder::ShuffledPerClient
        );
    }

    /// Every Chromium release that sends trust anchor IDs has its store embedded (add its branch to
    /// tests/chrome_root_store.rs), and every profile builds a connector.
    #[test]
    fn every_version_builds_with_the_ids_of_its_store() {
        for major in CHROME_TRUST_ANCHORS_VERSION..=Chrome::LATEST_VERSION {
            assert!(
                crate::tls::root_store::chrome_trust_anchor_ids(major).is_some(),
                "the Chrome Root Store of Chrome {major} is not embedded"
            );
        }
        let profiles = (Chrome::MIN_VERSION..=Chrome::LATEST_VERSION)
            .map(|major| Chrome::version(major, Os::Windows).unwrap())
            .chain(
                (Opera::MIN_VERSION..=Opera::LATEST_VERSION)
                    .map(|major| Opera::version(major, Os::Windows).unwrap()),
            );
        for profile in profiles {
            crate::tls::TlsConnector::build_connector(&profile.tls, None).unwrap();
            let quic = profile.quic.unwrap().tls.unwrap();
            crate::tls::TlsConnector::build_connector(&quic, None).unwrap();
        }
    }
}

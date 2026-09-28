//! The payload length NSS (Firefox) gives an ECH GREASE extension. NSS sizes the fake payload like
//! the encrypted ClientHelloInner it would send (`tls13_MaybeGreaseEch`): the inner hello repeats
//! the outer one's version, random, cipher suites and compression methods with an empty session ID,
//! drops pre-TLS-1.3 extensions, writes server_name, supported_versions and pre_shared_key in full
//! and compresses the rest into one outer_extensions extension. The server name is padded to
//! `security.tls.ech.grease_size` bytes, the whole rounded up to a multiple of 32 (RFC 9849
//! §6.1.3), plus the AEAD tag. NSS before bug 2060720 (Firefox up to 154) padded one byte short of
//! that multiple.

use super::config::{ExtensionOrder, TlsConfig, TlsVersion};

/// A session offered for resumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferedPsk {
    /// Length of the ticket, the PSK identity.
    pub ticket_len: usize,
    /// Length of the binder: the hash length of the session's cipher suite.
    pub binder_len: usize,
    /// The ClientHello also carries early_data.
    pub early_data: bool,
}

/// Extensions NSS knows only before TLS 1.3, left out of the inner hello: extended_master_secret,
/// renegotiation_info, ec_point_formats and session_ticket.
const PRE_TLS13_ONLY: &[u16] = &[0x0017, 0xff01, 0x000b, 0x0023];

/// AEAD tag of the HPKE ciphers ECH uses.
const AEAD_TAG_LEN: usize = 16;

/// TLS 1.3 cipher suites BoringSSL offers.
const TLS13_CIPHER_SUITES: usize = 3;

/// How NSS pads the inner hello (see [`EchGrease::Nss`](super::config::EchGrease::Nss)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Padding {
    /// Length the server name is padded to.
    pub name_len: u8,
    /// NSS before bug 2060720: one byte short of a multiple of 32.
    pub legacy: bool,
}

/// The GREASE payload length, AEAD tag included, of a ClientHello with the extensions `config`
/// lists in its extension order. `None` when the order does not list them (`Default` or
/// `Permuted`).
pub fn padded_inner_hello_len(
    config: &TlsConfig,
    host: &str,
    quic: bool,
    psk: Option<OfferedPsk>,
    padding: Padding,
) -> Option<u16> {
    let listed: Vec<u16> = match &config.extension_order {
        ExtensionOrder::Fixed(order) => order.clone(),
        ExtensionOrder::PermutedWithTail { permuted, tail } => {
            permuted.iter().chain(tail).copied().collect()
        }
        ExtensionOrder::Default | ExtensionOrder::Permuted => return None,
    };
    let has_sni = host.parse::<std::net::IpAddr>().is_err();

    // The inner encrypted_client_hello: type, length, one byte.
    let mut extensions = 4 + 1;
    let mut compressed = 0;
    for ext in listed {
        if PRE_TLS13_ONLY.contains(&ext) || !sent(config, ext, quic, psk) {
            continue;
        }
        match ext {
            // server_name: list length, name type, name length, name.
            0x0000 => extensions += 4 + 2 + 1 + 2 + host.len(),
            // supported_versions: TLS 1.3, plus GREASE when enabled.
            0x002b => extensions += 4 + 1 + 2 + if config.grease { 2 } else { 0 },
            _ => compressed += 1,
        }
    }
    if compressed > 0 {
        // outer_extensions: a one-byte list length and two bytes per type.
        extensions += 4 + 1 + 2 * compressed;
    }
    if let Some(psk) = psk {
        // identities (identity, obfuscated age) and binders.
        extensions += 4 + (2 + 2 + psk.ticket_len + 4) + (2 + 1 + psk.binder_len);
    }

    let cipher_suites = cipher_suite_count(config, quic);
    let encoded = 2 + 32 + 1 + (2 + 2 * cipher_suites) + (1 + 1) + (2 + extensions);
    let name_padding = if has_sni {
        usize::from(padding.name_len).saturating_sub(host.len())
    } else {
        0
    };
    let unpadded = encoded + name_padding;
    let padded = if padding.legacy {
        // `31 - (L % 32)` bytes of rounding.
        unpadded / 32 * 32 + 31
    } else {
        unpadded.div_ceil(32) * 32
    };
    u16::try_from(padded + AEAD_TAG_LEN).ok()
}

/// Whether the ClientHello carries extension `ext`.
fn sent(config: &TlsConfig, ext: u16, quic: bool, psk: Option<OfferedPsk>) -> bool {
    match ext {
        0x0005 => config.ocsp_stapling,
        0x0012 => config.signed_cert_timestamps,
        0x001b => !config.cert_compression.is_empty(),
        0x001c => config.record_size_limit.is_some(),
        0x0022 => config.delegated_credentials.is_some(),
        0x002a => psk.is_some_and(|p| p.early_data),
        0x002d => config.psk_key_exchange_modes,
        0x0039 => quic,
        0x4469 | 0x44cd => config.alps.is_some(),
        0xca34 => config.trust_anchor_ids.is_some(),
        // The ECH extension itself and the PSK, counted apart.
        0xfe0d | 0x0029 => false,
        _ => true,
    }
}

/// Cipher suites of the ClientHello: BoringSSL's TLS 1.3 ones, the TLS 1.2 ones of the list unless
/// only TLS 1.3 is offered, and GREASE.
fn cipher_suite_count(config: &TlsConfig, quic: bool) -> usize {
    let tls12 = if quic || config.min_version == TlsVersion::Tls13 {
        0
    } else {
        config
            .cipher_list
            .split(':')
            .map(str::trim)
            .filter(|c| {
                !c.is_empty() && !c.starts_with("TLS_AES_") && !c.starts_with("TLS_CHACHA20_")
            })
            .count()
    };
    TLS13_CIPHER_SUITES + tls12 + usize::from(config.grease)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Firefox;

    fn firefox_quic_tls() -> TlsConfig {
        firefox_quic_tls_of(156)
    }

    fn firefox_quic_tls_of(major: u32) -> TlsConfig {
        Firefox::version(major, crate::Os::Windows)
            .unwrap()
            .quic
            .unwrap()
            .tls
            .unwrap()
    }

    const PADDING: Padding = Padding {
        name_len: 100,
        legacy: false,
    };

    /// The padding of a profile's own ECH GREASE.
    fn padding_of(tls: &TlsConfig) -> Padding {
        match tls.ech_grease {
            crate::tls::config::EchGrease::Nss {
                name_len,
                legacy_padding,
            } => Padding {
                name_len,
                legacy: legacy_padding,
            },
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn matches_firefox_156_full_handshakes() {
        let tls = firefox_quic_tls();
        for host in ["www.google.com", "update.googleapis.com", "dl.google.com"] {
            assert_eq!(
                padded_inner_hello_len(&tls, host, true, None, PADDING),
                Some(240),
                "{host}"
            );
        }
    }

    #[test]
    fn matches_firefox_android_before_and_after_the_padding_fix() {
        let tcp = |major| Firefox::version(major, crate::Os::Android).unwrap().tls;
        for (major, expected) in [(146, 239), (151, 239), (154, 239), (155, 240), (157, 240)] {
            let tls = tcp(major);
            assert_eq!(
                padded_inner_hello_len(&tls, "www.cloudflare.com", false, None, padding_of(&tls)),
                Some(expected),
                "Firefox {major}"
            );
        }
        let quic = Firefox::version(154, crate::Os::Android)
            .unwrap()
            .quic
            .unwrap()
            .tls
            .unwrap();
        assert_eq!(
            padded_inner_hello_len(
                &quic,
                "quic.browserleaks.com",
                true,
                None,
                padding_of(&quic)
            ),
            Some(239)
        );
    }

    #[test]
    fn matches_firefox_157_full_handshake() {
        assert_eq!(
            padded_inner_hello_len(
                &firefox_quic_tls_of(157),
                "www.cloudflare.com",
                true,
                None,
                PADDING
            ),
            Some(240)
        );
    }

    #[test]
    fn matches_firefox_156_resumption() {
        let psk = OfferedPsk {
            ticket_len: 266,
            binder_len: 32,
            early_data: true,
        };
        assert_eq!(
            padded_inner_hello_len(
                &firefox_quic_tls(),
                "www.google.com",
                true,
                Some(psk),
                PADDING
            ),
            Some(528)
        );
    }

    #[test]
    fn needs_a_listed_extension_order() {
        let tls = TlsConfig {
            extension_order: ExtensionOrder::Permuted,
            ..firefox_quic_tls()
        };
        assert_eq!(
            padded_inner_hello_len(&tls, "example.com", true, None, PADDING),
            None
        );
    }

    #[test]
    fn long_names_grow_the_payload() {
        let tls = firefox_quic_tls();
        let long = format!("{}.example.com", "a".repeat(120));
        let len = padded_inner_hello_len(&tls, &long, true, None, PADDING).unwrap();
        assert!(len > 240 && (len - 16) % 32 == 0, "{len}");
    }
}

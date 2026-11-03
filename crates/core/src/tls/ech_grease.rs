use super::config::{ExtensionOrder, TlsConfig, TlsVersion};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferedPsk {
    pub ticket_len: usize,
    pub binder_len: usize,
    pub early_data: bool,
}

const PRE_TLS13_ONLY: &[u16] = &[0x0017, 0xff01, 0x000b, 0x0023];

const AEAD_TAG_LEN: usize = 16;

const TLS13_CIPHER_SUITES: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Padding {
    pub name_len: u8,
    pub legacy: bool,
}

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

    let mut extensions = 4 + 1;
    let mut compressed = 0;
    for ext in listed {
        if PRE_TLS13_ONLY.contains(&ext) || !sent(config, ext, quic, psk) {
            continue;
        }
        match ext {
            0x0000 => extensions += 4 + 2 + 1 + 2 + host.len(),
            0x002b => extensions += 4 + 1 + 2 + if config.grease { 2 } else { 0 },
            _ => compressed += 1,
        }
    }
    if compressed > 0 {
        extensions += 4 + 1 + 2 * compressed;
    }
    if let Some(psk) = psk {
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
        unpadded / 32 * 32 + 31
    } else {
        unpadded.div_ceil(32) * 32
    };
    u16::try_from(padded + AEAD_TAG_LEN).ok()
}

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
        0xfe0d | 0x0029 => false,
        _ => true,
    }
}

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

use btls::ssl::SslSignatureAlgorithm;

use crate::Error;

const SIGALG_NAMES: &[(&str, u16)] = &[
    ("rsa_pkcs1_sha1", 0x0201),
    ("ecdsa_sha1", 0x0203),
    ("rsa_pkcs1_sha256", 0x0401),
    ("ecdsa_secp256r1_sha256", 0x0403),
    ("rsa_pkcs1_sha384", 0x0501),
    ("ecdsa_secp384r1_sha384", 0x0503),
    ("rsa_pkcs1_sha512", 0x0601),
    ("ecdsa_secp521r1_sha512", 0x0603),
    ("rsa_pss_rsae_sha256", 0x0804),
    ("rsa_pss_rsae_sha384", 0x0805),
    ("rsa_pss_rsae_sha512", 0x0806),
    ("ed25519", 0x0807),
    ("ed448", 0x0808),
    ("rsa_pss_pss_sha256", 0x0809),
    ("rsa_pss_pss_sha384", 0x080a),
    ("rsa_pss_pss_sha512", 0x080b),
    ("mldsa44", 0x0904),
    ("mldsa65", 0x0905),
    ("mldsa87", 0x0906),
];

pub fn parse(list: &str) -> Result<Vec<SslSignatureAlgorithm>, Error> {
    list.split(':')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| {
            code_point(name)
                .map(SslSignatureAlgorithm::from)
                .ok_or_else(|| {
                    Error::Config(format!("Unknown signature algorithm: '{name}'"), None)
                })
        })
        .collect()
}

fn code_point(name: &str) -> Option<u16> {
    if let Some(hex) = name.strip_prefix("0x").or_else(|| name.strip_prefix("0X")) {
        return u16::from_str_radix(hex, 16).ok();
    }
    SIGALG_NAMES
        .iter()
        .find(|(known, _)| known.eq_ignore_ascii_case(name))
        .map(|(_, code)| *code)
}

pub fn signable_subset(list: &str) -> String {
    const BORINGSSL_KNOWS: &[&str] = &[
        "rsa_pkcs1_sha1",
        "ecdsa_sha1",
        "rsa_pkcs1_sha256",
        "ecdsa_secp256r1_sha256",
        "rsa_pkcs1_sha384",
        "ecdsa_secp384r1_sha384",
        "rsa_pkcs1_sha512",
        "ecdsa_secp521r1_sha512",
        "rsa_pss_rsae_sha256",
        "rsa_pss_rsae_sha384",
        "rsa_pss_rsae_sha512",
        "ed25519",
    ];

    list.split(':')
        .map(str::trim)
        .filter(|name| {
            BORINGSSL_KNOWS
                .iter()
                .any(|known| known.eq_ignore_ascii_case(name))
        })
        .collect::<Vec<_>>()
        .join(":")
}

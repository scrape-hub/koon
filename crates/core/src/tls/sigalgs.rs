//! Signature algorithm list parsing.
//!
//! BoringSSL's `SSL_CTX_set1_sigalgs_list` only accepts names it can also sign
//! with, which excludes the post-quantum ML-DSA schemes that Chromium 150+
//! advertises in its ClientHello. Since the advertised list is a fingerprint
//! input, we translate names to raw code points ourselves and hand those to
//! `SSL_CTX_set_verify_algorithm_prefs`, which writes them out verbatim.

use btls::ssl::SslSignatureAlgorithm;

use crate::Error;

/// Signature algorithm names accepted in a profile's `sigalgs` list, mapped to
/// their TLS `SignatureScheme` code points.
///
/// Covers everything BoringSSL knows plus the ML-DSA schemes from FIPS 204
/// (draft-ietf-tls-mldsa), which browsers advertise but no public web server
/// currently selects.
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

/// Parse a colon-separated signature algorithm list into TLS code points.
///
/// Also accepts raw hex code points (`"0x0904"`) so a custom profile can
/// advertise a scheme this build has no name for.
pub fn parse(list: &str) -> Result<Vec<SslSignatureAlgorithm>, Error> {
    list.split(':')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| {
            code_point(name)
                .map(SslSignatureAlgorithm::from)
                .ok_or_else(|| Error::Config(format!("Unknown signature algorithm: '{name}'")))
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

/// The subset of `list` that BoringSSL can parse by name, for the signing
/// preferences. Client certificates can only be signed with algorithms the
/// library implements, so ML-DSA and unknown code points are dropped here.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_chrome_150_list() {
        let list = "mldsa44:mldsa65:mldsa87:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256";
        let parsed = parse(list).expect("valid list");
        assert_eq!(parsed.len(), 5);
        assert_eq!(parsed[0], SslSignatureAlgorithm::from(0x0904));
        assert_eq!(parsed[2], SslSignatureAlgorithm::from(0x0906));
    }

    #[test]
    fn parses_raw_code_points() {
        let parsed = parse("0x0904:ecdsa_secp256r1_sha256").expect("valid list");
        assert_eq!(parsed[0], SslSignatureAlgorithm::from(0x0904));
    }

    #[test]
    fn rejects_unknown_names() {
        assert!(parse("ecdsa_secp256r1_sha256:not_a_real_algorithm").is_err());
    }

    #[test]
    fn signable_subset_drops_mldsa() {
        let subset = signable_subset("mldsa44:mldsa65:mldsa87:ecdsa_secp256r1_sha256:0x1234");
        assert_eq!(subset, "ecdsa_secp256r1_sha256");
    }
}

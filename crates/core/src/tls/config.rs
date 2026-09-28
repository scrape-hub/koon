use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Error;

/// TLS ClientHello settings of a profile: what JA3, JA4 and similar fingerprints see. Unknown
/// cipher, group or signature algorithm names make
/// [`ClientBuilder::build`](crate::ClientBuilder::build) fail. Certificates are verified against
/// the same roots for every profile, whatever it advertises: Mozilla's roots plus every trust
/// anchor of the embedded Chrome Root Store versions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Cipher suites in ClientHello order, as a BoringSSL cipher list (colon-separated names).
    pub cipher_list: Cow<'static, str>,

    /// Supported groups in ClientHello order (colon-separated names).
    pub curves: Cow<'static, str>,

    /// Signature algorithms in ClientHello order (colon-separated names).
    pub sigalgs: Cow<'static, str>,

    /// Protocols offered in the ALPN extension, in order.
    pub alpn: Vec<AlpnProtocol>,

    /// Codepoint of the ALPS (application_settings) extension; `None` omits the extension.
    pub alps: Option<AlpsCodepoint>,

    /// Lowest TLS version offered.
    pub min_version: TlsVersion,

    /// Highest TLS version offered.
    pub max_version: TlsVersion,

    /// Adds BoringSSL's GREASE values (RFC 8701) to the ClientHello.
    pub grease: bool,

    /// Puts a GREASE value first in `signature_algorithms`. Independent of
    /// [`grease`](Self::grease).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub grease_sigalgs: bool,

    /// ECH GREASE, sent when there is no real ECH configuration for the server.
    pub ech_grease: EchGrease,

    /// Order of the ClientHello extensions.
    pub extension_order: ExtensionOrder,

    /// IDs of the `trust_anchors` extension (0xCA34, draft-ietf-tls-trust-anchor-ids); `None` omits
    /// it, empty sends it without IDs. A custom ID naming an anchor outside the embedded Chrome
    /// Root Store can make verification fail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_anchor_ids: Option<Vec<TrustAnchorId>>,

    /// Order of [`trust_anchor_ids`](Self::trust_anchor_ids) on the wire.
    #[serde(default, skip_serializing_if = "TrustAnchorOrder::is_listed")]
    pub trust_anchor_order: TrustAnchorOrder,

    /// Omits `session_ticket` from a ClientHello that offers a TLS 1.3 session; otherwise an empty
    /// one goes next to the PSK.
    pub omit_session_ticket_on_resumption: bool,

    /// Sends `extended_master_secret` and `renegotiation_info` also when only TLS 1.3 is offered,
    /// where BoringSSL otherwise drops them.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub legacy_extensions_in_tls13: bool,

    /// Sends the `status_request` extension (OCSP stapling).
    pub ocsp_stapling: bool,

    /// Sends the `signed_certificate_timestamp` extension.
    pub signed_cert_timestamps: bool,

    /// Algorithms offered in the `compress_certificate` extension (RFC 8879), in order; empty omits
    /// it.
    pub cert_compression: Vec<CertCompression>,

    /// Sends the `psk_key_exchange_modes` extension (psk_dhe_ke) when TLS 1.3 is offered.
    /// Resumption PSKs are offered either way.
    pub psk_key_exchange_modes: bool,

    /// Sends the `session_ticket` extension (TLS 1.2 session tickets).
    pub session_ticket: bool,

    /// Number of key shares, for the first groups of [`curves`](Self::curves) that can carry one.
    /// `None`: BoringSSL's choice, the first group plus the first later one of the other kind
    /// (post-quantum or classical).
    pub key_shares_limit: Option<u8>,

    /// Signature algorithms of the `delegated_credential` extension (colon-separated names); `None`
    /// omits it.
    pub delegated_credentials: Option<Cow<'static, str>>,

    /// Value of the `record_size_limit` extension (RFC 8449); `None` omits it.
    pub record_size_limit: Option<u16>,

    /// Bytes of padding the `server_padding` extension (0x12E0, BoringSSL's) asks the server to add
    /// to its EncryptedExtensions in TLS 1.3; `None` omits it. Chrome sends it (TCP and QUIC) while
    /// its Finch feature `AddTLSServerHandshakePadding` is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_padding: Option<u16>,

    /// Decides [`server_padding`](Self::server_padding) per client: building a
    /// [`Client`](crate::Client) draws the group once for all its connections (Chrome from 151 on,
    /// Finch study `PqcBandwidthExperiment`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_padding_trial: Option<ServerPaddingTrial>,

    /// Sends the TLS 1.3 cipher suites in [`cipher_list`](Self::cipher_list) order instead of
    /// BoringSSL's, which depends on AES hardware support.
    pub preserve_tls13_cipher_order: bool,

    /// Disables certificate verification of origins; for testing only. Never read from or written
    /// to profile JSON, so a shared profile cannot turn it off. HTTPS proxies are verified
    /// separately (see [`ClientBuilder::proxy_ca_certs`](crate::ClientBuilder::proxy_ca_certs)).
    #[serde(skip)]
    pub danger_accept_invalid_certs: bool,
}

/// TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    /// TLS 1.0 (Safari up to macOS 15 and iOS 18 still offers it).
    Tls10,
    /// TLS 1.1.
    Tls11,
    /// TLS 1.2.
    Tls12,
    /// TLS 1.3.
    Tls13,
}

/// ALPN (Application-Layer Protocol Negotiation) protocol identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlpnProtocol {
    /// HTTP/2 (`"h2"`).
    #[serde(rename = "h2")]
    Http2,
    /// HTTP/1.1 (`"http/1.1"`).
    #[serde(rename = "http/1.1")]
    Http11,
}

/// Codepoint of the ALPS (application_settings) extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlpsCodepoint {
    /// 0x4469, used up to Chromium 134.
    Old,
    /// 0x44CD, used from Chromium 135 on.
    New,
}

/// Order of the ClientHello extensions.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionOrder {
    /// BoringSSL's built-in order.
    #[default]
    Default,
    /// A new random order on every handshake.
    Permuted,
    /// This order, as extension code points. It must list every extension the profile sends:
    /// unlisted ones follow in random order. `pre_shared_key` needs no entry; it always comes last.
    Fixed(Vec<u16>),
    /// A new random order on every handshake, followed by `tail` and then `pre_shared_key`.
    PermutedWithTail {
        /// The permuted extensions. BoringSSL permutes everything it sends except `tail`; the list
        /// names that set for sizing [`EchGrease::Nss`] payloads.
        permuted: Vec<u16>,
        /// Extensions after the permuted ones, in this order.
        tail: Vec<u16>,
    },
}

/// Order of the IDs in the `trust_anchors` extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustAnchorOrder {
    /// As listed.
    #[default]
    Listed,
    /// Shuffled once per [`Client`](crate::Client), for all its connections.
    ShuffledPerClient,
    /// Shuffled for every connection.
    ShuffledPerConnection,
}

impl TrustAnchorOrder {
    fn is_listed(&self) -> bool {
        *self == Self::Listed
    }
}

/// Trust anchor ID (draft-ietf-tls-trust-anchor-ids): the 1 to 255 bytes of a relative OID below
/// 1.3.6.1.4.1, written in hex in profile JSON (`"d6790901"`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustAnchorId(Cow<'static, [u8]>);

impl TrustAnchorId {
    /// Creates an ID from its wire bytes. Errors ([`Error::Config`]) unless there are 1 to 255
    /// bytes.
    pub fn new(bytes: impl Into<Cow<'static, [u8]>>) -> Result<Self, Error> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > 255 {
            return Err(Error::Config(
                format!("a trust anchor ID has 1 to 255 bytes, not {}", bytes.len()),
                None,
            ));
        }
        Ok(Self(bytes))
    }

    /// An embedded ID, whose length the tests check.
    pub(crate) const fn from_static(bytes: &'static [u8]) -> Self {
        Self(Cow::Borrowed(bytes))
    }

    /// Returns the bytes as they go on the wire.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for TrustAnchorId {
    /// Formats the ID as lowercase hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl FromStr for TrustAnchorId {
    type Err = Error;

    /// Parses hex digits of either case; [`Error::Config`] unless they encode 1 to 255 bytes.
    fn from_str(hex: &str) -> Result<Self, Error> {
        let invalid = || Error::Config(format!("invalid trust anchor ID: '{hex}'"), None);
        if hex.len() % 2 != 0 {
            return Err(invalid());
        }
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| {
                hex.get(i..i + 2)
                    .and_then(|b| u8::from_str_radix(b, 16).ok())
            })
            .collect::<Option<Vec<u8>>>()
            .ok_or_else(invalid)?;
        Self::new(bytes)
    }
}

impl Serialize for TrustAnchorId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for TrustAnchorId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex = <Cow<'de, str>>::deserialize(deserializer)?;
        hex.parse().map_err(serde::de::Error::custom)
    }
}

/// ECH GREASE: a fake `encrypted_client_hello` extension, sent when there is no real ECH
/// configuration for the server. Both kinds use HKDF-SHA256, a 32-byte `enc` and a random config
/// ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EchGrease {
    /// No ECH GREASE.
    #[default]
    Off,
    /// BoringSSL's: AES-128-GCM on hardware with AES instructions, else ChaCha20-Poly1305, and a
    /// random payload of 144, 176, 208 or 240 bytes.
    BoringSsl,
    /// NSS's: AES-128-GCM or ChaCha20-Poly1305 at random, with a payload as long as a real
    /// encrypted ClientHelloInner (compressed extensions, name padded to `name_len` bytes per RFC
    /// 9849 §6.1.3, plus the AEAD tag). Needs an [`ExtensionOrder`] that lists the extensions
    /// (`Fixed` or `PermutedWithTail`); with another order the payload length is BoringSSL's.
    Nss {
        /// Length the server name is padded to.
        name_len: u8,
        /// NSS before bug 2060720 (Firefox ≤154) pads to one byte short of a multiple of 32 (`31 -
        /// (L % 32)` instead of `31 - ((L - 1) % 32)`).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        legacy_padding: bool,
    },
}

/// Certificate compression algorithm (RFC 8879).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertCompression {
    /// Brotli.
    Brotli,
    /// Zlib.
    Zlib,
    /// Zstandard.
    Zstd,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cipher_list: Cow::Borrowed("DEFAULT"),
            curves: Cow::Borrowed("X25519:P-256:P-384"),
            sigalgs: Cow::Borrowed(
                "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
                 ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:\
                 rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
            ),
            alpn: vec![AlpnProtocol::Http2, AlpnProtocol::Http11],
            alps: None,
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            grease: false,
            grease_sigalgs: false,
            ech_grease: EchGrease::Off,
            extension_order: ExtensionOrder::Default,
            trust_anchor_ids: None,
            trust_anchor_order: TrustAnchorOrder::Listed,
            omit_session_ticket_on_resumption: false,
            legacy_extensions_in_tls13: false,
            ocsp_stapling: false,
            signed_cert_timestamps: false,
            cert_compression: Vec::new(),
            psk_key_exchange_modes: false,
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
}

/// A field trial on the `server_padding` extension, as a Finch study of Chrome runs it: a client
/// enters with chance `enrolled_slots / slots`, then draws a group with a chance proportional to
/// its weight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerPaddingTrial {
    /// Slots of the layer assigned to the trial.
    pub enrolled_slots: u32,
    /// Slots of the layer.
    pub slots: u32,
    /// The groups a client in the trial is assigned to.
    pub groups: Vec<ServerPaddingGroup>,
}

/// A group of a [`ServerPaddingTrial`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerPaddingGroup {
    /// Relative chance of the group (the study's `probability_weight`).
    pub weight: u32,
    /// Bytes of padding the group's clients ask for; 0 still sends the extension.
    pub bytes: u16,
}

impl ServerPaddingTrial {
    /// The padding one client asks for: `None` outside the trial.
    pub fn draw<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Option<u16> {
        if self.slots == 0 || rng.random_range(0..self.slots) >= self.enrolled_slots {
            return None;
        }
        let total: u64 = self.groups.iter().map(|g| u64::from(g.weight)).sum();
        if total == 0 {
            return None;
        }
        let mut pick = rng.random_range(0..total);
        for group in &self.groups {
            let weight = u64::from(group.weight);
            if pick < weight {
                return Some(group.bytes);
            }
            pick -= weight;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TlsConfig in JSON without the optional fields, `extra` (starting with a comma) appended.
    fn json(extra: &str) -> String {
        format!(
            r#"{{"cipher_list":"DEFAULT","curves":"X25519","sigalgs":"rsa_pkcs1_sha256",
            "alpn":["h2","http/1.1"],"min_version":"tls12","max_version":"tls13",
            "grease":true,"ech_grease":"boring_ssl","extension_order":"permuted",
            "omit_session_ticket_on_resumption":false,"ocsp_stapling":true,
            "signed_cert_timestamps":true,"cert_compression":["brotli"],
            "psk_key_exchange_modes":true,"session_ticket":true,
            "preserve_tls13_cipher_order":false{extra}}}"#
        )
    }

    #[test]
    fn optional_fields_default() {
        let c: TlsConfig = serde_json::from_str(&json("")).unwrap();
        assert_eq!(c.alps, None);
        assert!(!c.grease_sigalgs && !c.legacy_extensions_in_tls13);
        assert_eq!(c.trust_anchor_ids, None);
        assert_eq!(c.trust_anchor_order, TrustAnchorOrder::Listed);
        assert_eq!(c.key_shares_limit, None);
        assert_eq!(c.delegated_credentials, None);
        assert_eq!(c.record_size_limit, None);
        let json = serde_json::to_string(&TlsConfig {
            min_version: TlsVersion::Tls10,
            ..TlsConfig::default()
        })
        .unwrap();
        assert!(json.contains(r#""min_version":"tls10""#), "{json}");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let err =
            serde_json::from_str::<TlsConfig>(&json(r#","pre_shared_key":true"#)).unwrap_err();
        assert!(
            err.to_string().contains("unknown field `pre_shared_key`"),
            "{err}"
        );
    }

    #[test]
    fn current_fields_roundtrip() {
        for (alps, order) in [
            (Some(AlpsCodepoint::New), ExtensionOrder::Permuted),
            (Some(AlpsCodepoint::Old), ExtensionOrder::Default),
            (None, ExtensionOrder::Fixed(vec![0, 23, 65281])),
        ] {
            let config = TlsConfig {
                alps,
                extension_order: order,
                psk_key_exchange_modes: true,
                ..TlsConfig::default()
            };
            let json = serde_json::to_string(&config).unwrap();
            let back: TlsConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(serde_json::to_string(&back).unwrap(), json);
            assert_eq!(back.alps, config.alps);
            assert_eq!(back.extension_order, config.extension_order);
        }
        let json = serde_json::to_string(&TlsConfig {
            extension_order: ExtensionOrder::Fixed(vec![0, 23]),
            ..TlsConfig::default()
        })
        .unwrap();
        assert!(
            json.contains(r#""extension_order":{"fixed":[0,23]}"#),
            "{json}"
        );
    }

    #[test]
    fn trust_anchors_roundtrip() {
        let config = TlsConfig {
            trust_anchor_ids: Some(vec![TrustAnchorId::from_static(&[0xd6, 0x79, 0x09, 0x01])]),
            trust_anchor_order: TrustAnchorOrder::ShuffledPerConnection,
            ..TlsConfig::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(
            json.contains(r#""trust_anchor_ids":["d6790901"]"#),
            "{json}"
        );
        assert!(
            json.contains(r#""trust_anchor_order":"shuffled_per_connection""#),
            "{json}"
        );
        let back: TlsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);

        let json = serde_json::to_string(&TlsConfig::default()).unwrap();
        assert!(!json.contains("trust_anchor"), "{json}");
    }

    #[test]
    fn trust_anchor_ids_parse_from_hex() {
        let id: TrustAnchorId = "D679090A".parse().unwrap();
        assert_eq!(id.as_bytes(), [0xd6, 0x79, 0x09, 0x0a]);
        assert_eq!(id.to_string(), "d679090a");
        for bad in ["", "d67", "zz", "é1", &"00".repeat(256)] {
            assert!(bad.parse::<TrustAnchorId>().is_err(), "{bad}");
        }
        assert!(TrustAnchorId::new(vec![0u8; 255]).is_ok());
        let json = json(r#","trust_anchor_ids":["d6x9"]"#);
        assert!(serde_json::from_str::<TlsConfig>(&json).is_err());
    }

    #[test]
    fn ech_grease_roundtrips() {
        for kind in [
            EchGrease::Off,
            EchGrease::BoringSsl,
            EchGrease::Nss {
                name_len: 100,
                legacy_padding: false,
            },
            EchGrease::Nss {
                name_len: 100,
                legacy_padding: true,
            },
        ] {
            let config = TlsConfig {
                ech_grease: kind,
                ..TlsConfig::default()
            };
            let json = serde_json::to_string(&config).unwrap();
            let back: TlsConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(back.ech_grease, kind, "{json}");
        }
        let json = serde_json::to_string(&TlsConfig {
            ech_grease: EchGrease::Nss {
                name_len: 100,
                legacy_padding: false,
            },
            ..TlsConfig::default()
        })
        .unwrap();
        assert!(
            json.contains(r#""ech_grease":{"nss":{"name_len":100}}"#),
            "{json}"
        );
    }
}

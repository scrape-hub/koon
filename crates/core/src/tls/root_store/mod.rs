use std::collections::HashSet;
use std::sync::OnceLock;

use base64::Engine;
use btls::hash::{MessageDigest, hash};
use btls::ssl::SslContextBuilder;
use btls::x509::X509;
use btls::x509::store::{X509Store, X509StoreBuilder};
use btls::x509::verify::X509VerifyFlags;

use super::config::TrustAnchorId;
use crate::Error;

#[rustfmt::skip]
mod chrome_root_store;

struct ChromeAnchor {
    sha256: &'static str,
    trust_anchor_id: &'static [u8],
    stores: u32,
    der: &'static str,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn certs() -> &'static [X509] {
    static CERTS: OnceLock<Vec<X509>> = OnceLock::new();
    CERTS.get_or_init(|| {
        let mozilla = webpki_root_certs::TLS_SERVER_ROOT_CERTS;
        let mozilla_digests: HashSet<String> = mozilla
            .iter()
            .map(|der| {
                let digest =
                    hash(MessageDigest::sha256(), der.as_ref()).expect("SHA-256 of a certificate");
                hex(&digest)
            })
            .collect();
        let chrome_only = chrome_root_store::ANCHORS
            .iter()
            .filter(|anchor| !mozilla_digests.contains(anchor.sha256))
            .map(|anchor| {
                let der = base64::engine::general_purpose::STANDARD
                    .decode(anchor.der)
                    .expect("embedded Chrome Root Store certificate is base64");
                X509::from_der(&der).expect("embedded Chrome Root Store certificate parses")
            });
        mozilla
            .iter()
            .filter_map(|der| X509::from_der(der.as_ref()).ok())
            .chain(chrome_only)
            .collect()
    })
}

fn build(extra: &[X509]) -> Result<X509Store, Error> {
    let mut builder = X509StoreBuilder::new()?;
    for cert in certs().iter().chain(extra) {
        builder.add_cert(cert)?;
    }
    builder.set_flags(X509VerifyFlags::PARTIAL_CHAIN);
    Ok(builder.build())
}

pub fn load(builder: &mut SslContextBuilder) -> Result<(), Error> {
    static SHARED: OnceLock<X509Store> = OnceLock::new();
    let shared = match SHARED.get() {
        Some(shared) => shared.clone(),
        None => {
            let built = build(&[])?;
            SHARED.get_or_init(|| built).clone()
        }
    };
    builder.set_verify_cert_store(shared)?;
    Ok(())
}

pub fn with_extra(extra: &[X509]) -> Result<X509Store, Error> {
    build(extra)
}

pub fn chrome_trust_anchor_ids(major: u32) -> Option<Vec<TrustAnchorId>> {
    let index = chrome_root_store::RELEASES
        .iter()
        .position(|&(chrome, _)| chrome == major)?;
    let mut ids: Vec<TrustAnchorId> = chrome_root_store::ANCHORS
        .iter()
        .filter(|anchor| anchor.stores & (1 << index) != 0 && !anchor.trust_anchor_id.is_empty())
        .map(|anchor| TrustAnchorId::from_static(anchor.trust_anchor_id))
        .collect();
    ids.sort_unstable();
    Some(ids)
}

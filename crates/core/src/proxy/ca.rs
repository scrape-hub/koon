use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use btls::asn1::{Asn1Time, Asn1TimeRef};
use btls::bn::{BigNum, MsbOption};
use btls::ec::{EcGroup, EcKey};
use btls::error::ErrorStack;
use btls::hash::MessageDigest;
use btls::nid::Nid;
use btls::pkey::{PKey, Private};
use btls::rsa::Rsa;
use btls::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use btls::x509::{X509, X509Builder, X509Name, X509NameRef};
use lru::LruCache;

use crate::error::Error;

/// Most leaf certificates kept in memory; beyond this the least-recently-used entry is evicted
/// to make room for a new host.
const MAX_CACHED_HOSTS: usize = 10_000;

/// Longest Common Name X.509 allows (`ub-common-name`, RFC 5280).
const MAX_COMMON_NAME_LEN: usize = 64;

/// Write the CA private key to `key_path`: to a temp file in the same directory, then an atomic
/// rename, so a reader never sees a partial write. Owner-only (`0600`) on Unix from creation;
/// Windows has no mode bit and relies on the inherited NTFS ACL.
fn write_ca_key_pem(key_path: &Path, key_pem: &[u8]) -> Result<(), Error> {
    let dir = key_path
        .parent()
        .ok_or_else(|| Error::Proxy("CA key path has no parent directory".into(), None))?;
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp_path = dir.join(format!(
        "koon-ca-key.pem.tmp.{}.{unique}",
        std::process::id()
    ));

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(Error::Io)?;
        file.write_all(key_pem).map_err(Error::Io)?;
        file.sync_all().map_err(Error::Io)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp_path, key_pem).map_err(Error::Io)?;
    }

    std::fs::rename(&tmp_path, key_path).map_err(Error::Io)?;
    Ok(())
}

/// Certificate authority for MITM proxy.
///
/// Generates or loads a CA certificate from disk, and signs leaf certificates per host on demand.
/// Leaf certs are cached in memory (case-insensitively, at most 10 000, least-recently-used
/// evicted first).
pub struct CertAuthority {
    ca_key: PKey<Private>,
    ca_cert: X509,
    storage_dir: PathBuf,
    leaf_cache: Mutex<LruCache<String, (X509, PKey<Private>)>>,
}

impl CertAuthority {
    /// Load an existing CA from disk, or generate a new one and save it.
    ///
    /// Files: `koon-ca.pem` (certificate) and `koon-ca-key.pem` (private key). Blocking (file I/O,
    /// RSA key generation on first use). A CA certificate without a subjectKeyIdentifier fails:
    /// strict verifiers (e.g. Python 3.13+'s `VERIFY_X509_STRICT`) reject it.
    ///
    /// # Errors
    /// Returns [`Error::Io`] if `storage_dir` cannot be created or the CA files cannot be read or
    /// written, or [`Error::Proxy`] if an existing CA certificate or key is malformed or lacks a
    /// subjectKeyIdentifier.
    pub fn load_or_generate(storage_dir: PathBuf) -> Result<Self, Error> {
        std::fs::create_dir_all(&storage_dir).map_err(Error::Io)?;

        let cert_path = storage_dir.join("koon-ca.pem");
        let key_path = storage_dir.join("koon-ca-key.pem");

        let (ca_cert, ca_key) = if cert_path.exists() && key_path.exists() {
            let cert_pem = std::fs::read(&cert_path).map_err(Error::Io)?;
            let key_pem = std::fs::read(&key_path).map_err(Error::Io)?;

            let cert = X509::from_pem(&cert_pem).map_err(|e| {
                let message = format!("Failed to load CA cert: {e}");
                Error::Proxy(message, crate::error::boxed(e))
            })?;
            let key = PKey::private_key_from_pem(&key_pem).map_err(|e| {
                let message = format!("Failed to load CA key: {e}");
                Error::Proxy(message, crate::error::boxed(e))
            })?;

            if cert.subject_key_id().is_none() {
                return Err(Error::Proxy(
                    format!(
                        "The CA certificate {} has no subjectKeyIdentifier, which strict TLS \
                         clients require. Delete {} and {}; koon will generate a new CA next \
                         time, and it will need reinstalling in your clients.",
                        cert_path.display(),
                        cert_path.display(),
                        key_path.display()
                    ),
                    None,
                ));
            }

            (cert, key)
        } else {
            let (cert, key) = generate_ca().map_err(|e| {
                let message = format!("CA certificate generation failed: {e}");
                Error::Proxy(message, crate::error::boxed(e))
            })?;

            let cert_pem = cert.to_pem().map_err(|e| {
                let message = format!("Failed to encode CA cert: {e}");
                Error::Proxy(message, crate::error::boxed(e))
            })?;
            let key_pem = key.private_key_to_pem_pkcs8().map_err(|e| {
                let message = format!("Failed to encode CA key: {e}");
                Error::Proxy(message, crate::error::boxed(e))
            })?;

            std::fs::write(&cert_path, &cert_pem).map_err(Error::Io)?;
            write_ca_key_pem(&key_path, &key_pem)?;

            (cert, key)
        };

        Ok(Self {
            ca_key,
            ca_cert,
            storage_dir,
            leaf_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(MAX_CACHED_HOSTS).expect("MAX_CACHED_HOSTS is non-zero"),
            )),
        })
    }

    /// A CA whose leaf cache holds at most `capacity` hosts instead of [`MAX_CACHED_HOSTS`], to
    /// test eviction without generating thousands of certificates.
    #[cfg(test)]
    fn with_leaf_cache_capacity(storage_dir: PathBuf, capacity: usize) -> Result<Self, Error> {
        let mut ca = Self::load_or_generate(storage_dir)?;
        ca.leaf_cache = Mutex::new(LruCache::new(
            NonZeroUsize::new(capacity).expect("test capacity is non-zero"),
        ));
        Ok(ca)
    }

    /// Path to the CA certificate PEM file.
    pub fn ca_cert_path(&self) -> PathBuf {
        self.storage_dir.join("koon-ca.pem")
    }

    /// CA certificate as PEM bytes (for installing in browsers/tools).
    ///
    /// # Errors
    /// Returns [`Error::Proxy`] if the certificate cannot be PEM-encoded.
    pub fn ca_cert_pem(&self) -> Result<Vec<u8>, Error> {
        self.ca_cert.to_pem().map_err(|e| {
            let message = format!("Failed to encode CA cert: {e}");
            Error::Proxy(message, crate::error::boxed(e))
        })
    }

    /// Get or create a leaf certificate for a host name or IP literal (IPv6 with or without
    /// brackets, matched case-insensitively).
    ///
    /// Synchronous and CPU-bound: async callers run it via `spawn_blocking`. Signing runs without
    /// the cache lock, so other hosts' CONNECTs don't wait behind it; if two callers race on the
    /// same new host, the first cached wins (certificates for a host are interchangeable).
    ///
    /// # Errors
    /// Returns [`Error::Proxy`] if key generation or signing fails.
    pub fn get_or_create_leaf(&self, host: &str) -> Result<(X509, PKey<Private>), Error> {
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        if let Some(entry) = crate::util::lock_recover(&self.leaf_cache).get(&host) {
            return Ok(entry.clone());
        }

        let (cert, key) = self.sign_leaf(&host).map_err(|e| {
            let message = format!("Leaf certificate for {host} failed: {e}");
            Error::Proxy(message, crate::error::boxed(e))
        })?;

        let mut cache = crate::util::lock_recover(&self.leaf_cache);
        // If two callers raced on this host, keep whichever is already cached (certificates for
        // a host are interchangeable) instead of the one just signed here.
        if let Some(existing) = cache.get(&host) {
            return Ok(existing.clone());
        }
        cache.put(host, (cert.clone(), key.clone()));
        Ok((cert, key))
    }

    /// Sign a leaf certificate for `host` (lowercase, no brackets).
    ///
    /// ECDSA P-256, not RSA-2048: this runs once per distinct host on the request path, and P-256
    /// keygen is ~100x faster (the CA's own RSA key still signs it, an ordinary mixed-algorithm
    /// chain). The subjectAltName is an iPAddress or dNSName entry; the Common Name is dropped
    /// (with a critical SAN, per RFC 5280) past 64 characters. `serverAuth` is required by Apple's
    /// TLS clients, the authorityKeyIdentifier (key identifier only) by strict verifiers.
    fn sign_leaf(&self, host: &str) -> Result<(X509, PKey<Private>), ErrorStack> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = PKey::from_ec_key(EcKey::generate(&group)?)?;

        let mut name = X509Name::builder()?;
        let has_common_name = host.len() <= MAX_COMMON_NAME_LEN;
        if has_common_name {
            name.append_entry_by_text("CN", host)?;
        }
        let name = name.build();

        let (not_before, not_after) = validity(365)?;
        let mut builder = new_cert_builder(
            &name,
            self.ca_cert.subject_name(),
            &key,
            &not_before,
            &not_after,
        )?;
        let basic_constraints = BasicConstraints::new().build()?;
        builder.append_extension(&basic_constraints)?;
        let server_auth = ExtendedKeyUsage::new().server_auth().build()?;
        builder.append_extension(&server_auth)?;
        let authority_key_id = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&builder.x509v3_context(Some(&self.ca_cert), None))?;
        builder.append_extension(&authority_key_id)?;

        let mut san = SubjectAlternativeName::new();
        if !has_common_name {
            san.critical();
        }
        if host.parse::<IpAddr>().is_ok() {
            san.ip(host);
        } else {
            san.dns(host);
        }
        let san = san.build(&builder.x509v3_context(Some(&self.ca_cert), None))?;
        builder.append_extension(&san)?;

        builder.sign(&self.ca_key, MessageDigest::sha256())?;
        Ok((builder.build(), key))
    }
}

/// Generate a new self-signed CA certificate (RSA-2048, 10 years).
fn generate_ca() -> Result<(X509, PKey<Private>), ErrorStack> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;

    let mut name = X509Name::builder()?;
    name.append_entry_by_text("CN", "Koon MITM Proxy CA")?;
    name.append_entry_by_text("O", "Koon")?;
    let name = name.build();

    let (not_before, not_after) = validity(3650)?;
    let cert = sign_ca(&name, &key, &not_before, &not_after)?;
    Ok((cert, key))
}

/// A self-signed CA certificate: a critical basicConstraints (CA), a critical keyUsage
/// (keyCertSign, cRLSign) and a subjectKeyIdentifier, which RFC 5280 requires of a CA and strict
/// verifiers check.
fn sign_ca(
    name: &X509NameRef,
    key: &PKey<Private>,
    not_before: &Asn1TimeRef,
    not_after: &Asn1TimeRef,
) -> Result<X509, ErrorStack> {
    let mut builder = new_cert_builder(name, name, key, not_before, not_after)?;
    let basic_constraints = BasicConstraints::new().critical().ca().build()?;
    builder.append_extension(&basic_constraints)?;
    let key_usage = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()?;
    builder.append_extension(&key_usage)?;
    let subject_key_id = SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
    builder.append_extension(&subject_key_id)?;

    builder.sign(key, MessageDigest::sha256())?;
    Ok(builder.build())
}

/// From now until `days` from now.
fn validity(days: u32) -> Result<(Asn1Time, Asn1Time), ErrorStack> {
    Ok((Asn1Time::days_from_now(0)?, Asn1Time::days_from_now(days)?))
}

/// An X.509 v3 certificate builder with a random serial, the given subject, issuer, public key and
/// validity.
fn new_cert_builder(
    subject: &X509NameRef,
    issuer: &X509NameRef,
    key: &PKey<Private>,
    not_before: &Asn1TimeRef,
    not_after: &Asn1TimeRef,
) -> Result<X509Builder, ErrorStack> {
    let mut builder = X509::builder()?;
    builder.set_version(2)?;

    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;

    builder.set_subject_name(subject)?;
    builder.set_issuer_name(issuer)?;
    builder.set_pubkey(key)?;
    builder.set_not_before(not_before)?;
    builder.set_not_after(not_after)?;
    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A fresh scratch directory under the OS temp dir with a unique name, so parallel and
    /// repeat test runs never collide. Removed when the guard is dropped, also on a panic.
    fn temp_ca_dir(name: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(&format!("koon-ca-test-{name}-"))
            .tempdir()
            .expect("temp dir")
    }

    #[test]
    #[cfg(unix)]
    fn ca_key_file_is_written_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_ca_dir("perms");
        let _ca = CertAuthority::load_or_generate(dir.path().to_path_buf())
            .expect("CA generation failed");

        let key_path = dir.path().join("koon-ca-key.pem");
        let mode = std::fs::metadata(&key_path)
            .expect("CA key file should exist after generation")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "CA private key file should be owner-read/write only, got mode {:o}",
            mode & 0o777
        );
    }

    #[test]
    fn leaf_certificates_use_ecdsa_p256_not_rsa() {
        let dir = temp_ca_dir("ecdsa");
        let ca = CertAuthority::load_or_generate(dir.path().to_path_buf())
            .expect("CA generation failed");

        let (_cert, key) = ca
            .get_or_create_leaf("example.com")
            .expect("leaf generation failed");
        assert_eq!(key.id(), btls::pkey::Id::EC);
    }

    #[test]
    fn leaf_certificates_are_cached_by_host_case_insensitively() {
        let dir = temp_ca_dir("cache");
        let ca = CertAuthority::load_or_generate(dir.path().to_path_buf())
            .expect("CA generation failed");

        let (cert_a, _) = ca.get_or_create_leaf("example.com").unwrap();
        let (cert_b, _) = ca.get_or_create_leaf("Example.COM").unwrap();

        assert_eq!(
            cert_a.to_pem().unwrap(),
            cert_b.to_pem().unwrap(),
            "repeated lookups for the same host should return the cached cert, not sign a new one"
        );
    }

    #[test]
    fn leaf_cache_evicts_the_least_recently_used_entry_not_an_arbitrary_one() {
        let dir = temp_ca_dir("lru");
        let ca = CertAuthority::with_leaf_cache_capacity(dir.path().to_path_buf(), 3)
            .expect("CA generation failed");

        let (cert_a, _) = ca.get_or_create_leaf("a.example.com").unwrap();
        let (cert_b, _) = ca.get_or_create_leaf("b.example.com").unwrap();
        ca.get_or_create_leaf("c.example.com").unwrap();
        // Touch "a" again so it is no longer the least recently used entry: "b" is, since it
        // was inserted but never looked up again.
        ca.get_or_create_leaf("a.example.com").unwrap();

        // A 4th distinct host, over capacity: evicts "b", not "a" (just touched) or "c"
        // (inserted after "b").
        ca.get_or_create_leaf("d.example.com").unwrap();

        let (cert_a_again, _) = ca.get_or_create_leaf("a.example.com").unwrap();
        assert_eq!(
            cert_a_again.to_pem().unwrap(),
            cert_a.to_pem().unwrap(),
            "a should still be cached"
        );
        let (cert_b_again, _) = ca.get_or_create_leaf("b.example.com").unwrap();
        assert_ne!(
            cert_b_again.to_der().unwrap(),
            cert_b.to_der().unwrap(),
            "b should have been evicted and re-signed with a new serial number"
        );
    }

    #[test]
    fn leaf_certificates_for_long_hosts_and_ip_literals() {
        let dir = temp_ca_dir("names");
        let ca = CertAuthority::load_or_generate(dir.path().to_path_buf())
            .expect("CA generation failed");

        // Longer than the 64-character Common Name limit: SAN only.
        let long = format!("{}.s3.example.com", "a".repeat(70));
        let (cert, _) = ca.get_or_create_leaf(&long).unwrap();
        let sans = cert.subject_alt_names().unwrap();
        assert_eq!(sans.iter().next().unwrap().dnsname(), Some(long.as_str()));
        assert!(
            cert.subject_name()
                .entries_by_nid(Nid::COMMONNAME)
                .next()
                .is_none()
        );

        // IP literals get an iPAddress SAN, never a dNSName.
        for (host, octets) in [
            ("127.0.0.1", vec![127, 0, 0, 1]),
            ("[::1]", [0u8; 15].into_iter().chain([1]).collect()),
        ] {
            let (cert, _) = ca.get_or_create_leaf(host).unwrap();
            let sans = cert.subject_alt_names().unwrap();
            let san = sans.iter().next().unwrap();
            assert_eq!(san.ipaddress(), Some(octets.as_slice()), "{host}");
            assert_eq!(san.dnsname(), None, "{host}");
        }
    }

    #[test]
    fn concurrent_leaf_generation_converges_on_one_cached_cert_per_domain() {
        use std::thread;

        let dir = temp_ca_dir("concurrent");
        let ca = Arc::new(
            CertAuthority::load_or_generate(dir.path().to_path_buf())
                .expect("CA generation failed"),
        );

        // Several threads race to generate leaf certs for two domains at once. Signing must not
        // happen while the cache lock is held, so two threads can genuinely race on the same new
        // domain, but whichever result loses that race must still agree with what ended up
        // cached.
        let domains = ["a.example.com", "b.example.com"];
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let ca = ca.clone();
                let domain = domains[i % domains.len()];
                thread::spawn(move || {
                    let (cert, _) = ca.get_or_create_leaf(domain).unwrap();
                    (domain, cert.to_pem().unwrap())
                })
            })
            .collect();

        let results: Vec<(&str, Vec<u8>)> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();

        for domain in domains {
            let pems: Vec<&Vec<u8>> = results
                .iter()
                .filter(|(d, _)| *d == domain)
                .map(|(_, pem)| pem)
                .collect();
            assert!(pems.len() >= 2, "expected multiple results for {domain}");
            assert!(
                pems.windows(2).all(|w| w[0] == w[1]),
                "all threads should agree on the single cached cert for {domain}"
            );
        }
    }

    /// The extendedKeyUsage OID id-kp-serverAuth (1.3.6.1.5.5.7.3.1), DER.
    const SERVER_AUTH_OID: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

    fn der_contains(cert: &X509, needle: &[u8]) -> bool {
        let der = cert.to_der().unwrap();
        der.windows(needle.len()).any(|w| w == needle)
    }

    /// Whether `leaf` verifies against the trust anchor `anchor`.
    fn verifies(leaf: &X509, anchor: &X509) -> bool {
        let mut store = btls::x509::store::X509StoreBuilder::new().unwrap();
        store.add_cert(anchor.clone()).unwrap();
        let store = store.build();
        let chain = btls::stack::Stack::new().unwrap();
        let mut context = btls::x509::X509StoreContext::new().unwrap();
        context
            .init(&store, leaf, &chain, |context| context.verify_cert())
            .unwrap()
    }

    #[test]
    fn certificates_carry_what_strict_verifiers_require() {
        let dir = temp_ca_dir("extensions");
        let ca = CertAuthority::load_or_generate(dir.path().to_path_buf())
            .expect("CA generation failed");
        let ca_cert = X509::from_pem(&ca.ca_cert_pem().unwrap()).unwrap();
        let ca_key_id = ca_cert
            .subject_key_id()
            .expect("the CA has a subjectKeyIdentifier")
            .as_slice()
            .to_vec();

        for host in ["example.com", "127.0.0.1"] {
            let (leaf, _) = ca.get_or_create_leaf(host).unwrap();
            let authority_key_id = leaf
                .authority_key_id()
                .expect("the leaf has an authorityKeyIdentifier");
            assert_eq!(authority_key_id.as_slice(), &ca_key_id[..], "{host}");
            assert!(
                der_contains(&leaf, SERVER_AUTH_OID),
                "{host}: serverAuth EKU"
            );
            assert!(verifies(&leaf, &ca_cert), "{host}");
        }
    }

    #[test]
    fn ca_without_subject_key_id_is_rejected() {
        // A CA as koon generated it up to 0.8: no subjectKeyIdentifier.
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_text("CN", "Koon MITM Proxy CA")
            .unwrap();
        name.append_entry_by_text("O", "Koon").unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(1000).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();
        let constraints = BasicConstraints::new().critical().ca().build().unwrap();
        builder.append_extension(&constraints).unwrap();
        let usage = KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap();
        builder.append_extension(&usage).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        let old = builder.build();
        assert!(old.subject_key_id().is_none());

        let dir = temp_ca_dir("no-subject-key-id");
        let cert_pem = old.to_pem().unwrap();
        let key_pem = key.private_key_to_pem_pkcs8().unwrap();
        std::fs::write(dir.path().join("koon-ca.pem"), &cert_pem).unwrap();
        std::fs::write(dir.path().join("koon-ca-key.pem"), &key_pem).unwrap();

        let Err(err) = CertAuthority::load_or_generate(dir.path().to_path_buf()) else {
            panic!("a CA without subjectKeyIdentifier must be rejected");
        };
        let message = err.to_string();
        assert!(message.contains("subjectKeyIdentifier"), "{message}");
        assert!(message.contains("koon-ca-key.pem"), "{message}");
        // The files stay as they were.
        assert_eq!(
            std::fs::read(dir.path().join("koon-ca.pem")).unwrap(),
            cert_pem
        );
        assert_eq!(
            std::fs::read(dir.path().join("koon-ca-key.pem")).unwrap(),
            key_pem
        );
    }
}
